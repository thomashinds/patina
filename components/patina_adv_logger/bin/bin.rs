//! Executable for parsing advanced logger buffers.
//!
//! Supports two modes:
//! - **Direct parse**: Parse a raw advanced logger buffer from a file.
//! - **Scan mode** (`--scan`): Scan a full memory dump (potentially multi-GB) for
//!   advanced logger instances, attempting to parse each candidate found.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use clap::Parser;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Instant,
};

/// ALOG signature bytes (little-endian representation of 0x474F4C41).
const ALOG_SIGNATURE_BYTES: [u8; 4] = [0x41, 0x4C, 0x4F, 0x47];

/// Report scanning progress every 100 MB.
const PROGRESS_INTERVAL: u64 = 100 * 1024 * 1024;

/// Maximum log size we will attempt to read from a candidate (256 MB).
const MAX_LOG_READ_SIZE: u64 = 256 * 1024 * 1024;

// Field byte-offsets within the repr(C) AdvLoggerInfoV5 structure.
const FIELD_OFFSET_VERSION: usize = 4;
const FIELD_OFFSET_LOG_BUFFER_OFFSET: usize = 12;
const FIELD_OFFSET_LOG_CURRENT_OFFSET: usize = 20;
const FIELD_OFFSET_LOG_BUFFER_SIZE: usize = 28;

/// Minimum bytes to peek at in order to inspect all header fields we need.
const HEADER_PEEK_SIZE: usize = 128;

#[derive(Parser, Debug)]
struct Args {
    /// Path for the input file containing the raw advanced logger buffer or memory dump.
    input_path: PathBuf,
    /// Optional path for the output file. If not specified, the output will be printed to stdout.
    #[arg(short, long)]
    output_path: Option<PathBuf>,
    /// Flag to include entry metadata (level, phase, timestamp) in the output.
    #[arg(short, long, default_value_t = false)]
    entry_metadata: bool,
    /// Flag to include the header in the output.
    #[arg(long, default_value_t = false)]
    header: bool,
    /// Scan a full memory dump for advanced logger instances instead of parsing a raw log buffer.
    #[arg(long)]
    scan: bool,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.scan {
        return scan_memory_dump(&args);
    }

    // Original direct-parse path.
    let mut file = File::open(Path::new(&args.input_path))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut parser = patina_adv_logger::parser::Parser::open(&buffer).map_err(|e| {
        eprintln!("Error opening log data: {e}");
        io::Error::new(io::ErrorKind::InvalidData, e)
    })?;

    parser.configure_print_entry_metadata(args.entry_metadata);

    match args.output_path {
        Some(path) => {
            let mut out = File::create(path)?;
            parse_log(args.header, &parser, &mut out)?;
        }
        None => parse_log(args.header, &parser, &mut io::stdout())?,
    };

    Ok(())
}

fn parse_log<W: Write>(header: bool, parser: &patina_adv_logger::parser::Parser, out: &mut W) -> io::Result<()> {
    if header {
        parser.write_header(out).map_err(|e| {
            eprintln!("Error writing log: {e}");
            io::Error::other(e)
        })?;
    }

    parser.write_log(out).map_err(|e| {
        eprintln!("Error writing log: {e}");
        io::Error::other(e)
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Memory dump scanning
// ---------------------------------------------------------------------------

/// Size of each read chunk during the signature scan (256 MB).
const SCAN_CHUNK_SIZE: usize = 256 * 1024 * 1024;

/// Scan a full memory dump for advanced logger buffers using chunked I/O.
fn scan_memory_dump(args: &Args) -> io::Result<()> {
    let mut file = File::open(&args.input_path)?;
    let file_size = file.metadata()?.len();

    eprintln!(
        "Scanning memory dump: {} ({:.2} GB)",
        args.input_path.display(),
        file_size as f64 / (1024.0 * 1024.0 * 1024.0)
    );

    let t_start = Instant::now();

    // Phase 1: find all candidate offsets by reading in chunks.
    let candidates = find_alog_candidates_chunked(&mut file, file_size)?;

    let t_scan = Instant::now();
    eprintln!(
        "\nScan complete in {:.2}s. Found {} ALOG signature candidate(s).\n",
        (t_scan - t_start).as_secs_f64(),
        candidates.len()
    );

    if candidates.is_empty() {
        eprintln!("No advanced logger signatures found in dump.");
        return Ok(());
    }

    // Phase 2: attempt to parse each candidate by seeking and reading.
    let mut out: Box<dyn Write> = match &args.output_path {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout()),
    };

    let mut successful = 0u64;
    for (i, &offset) in candidates.iter().enumerate() {
        eprintln!(
            "--- Candidate {} of {} at offset 0x{:X} ({:.2} MB) ---",
            i + 1,
            candidates.len(),
            offset,
            offset as f64 / (1024.0 * 1024.0)
        );

        match try_parse_log_at_file(&mut file, file_size, offset, args, &mut out) {
            Ok(()) => {
                successful += 1;
                eprintln!("--- Candidate {} parsed successfully ---\n", i + 1);
            }
            Err(e) => {
                eprintln!("--- Candidate {} failed: {} ---\n", i + 1, e);
            }
        }
    }

    let t_end = Instant::now();
    eprintln!(
        "Done. Successfully parsed {} of {} candidate(s). Total time: {:.2}s",
        successful,
        candidates.len(),
        (t_end - t_start).as_secs_f64()
    );
    Ok(())
}

/// Find all 4-byte-aligned ALOG signatures by reading the file in chunks.
fn find_alog_candidates_chunked(file: &mut File, file_size: u64) -> io::Result<Vec<u64>> {
    let mut candidates = Vec::new();
    let signature = u32::from_le_bytes(ALOG_SIGNATURE_BYTES);
    let mut buf = vec![0u8; SCAN_CHUNK_SIZE];
    let mut file_offset: u64 = 0;
    let mut next_progress: u64 = PROGRESS_INTERVAL;

    loop {
        let bytes_read = read_full_or_eof(file, &mut buf)?;
        if bytes_read == 0 {
            break;
        }

        let aligned_len = bytes_read & !3;
        let mut i = 0usize;
        while i < aligned_len {
            let abs = file_offset + i as u64;

            while next_progress <= abs {
                eprintln!(
                    "  Scanned: {:.0} MB / {:.0} MB ({:.1}%)",
                    next_progress as f64 / (1024.0 * 1024.0),
                    file_size as f64 / (1024.0 * 1024.0),
                    next_progress as f64 / file_size as f64 * 100.0
                );
                next_progress += PROGRESS_INTERVAL;
            }

            let val = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
            if val == signature {
                eprintln!(
                    "  Found ALOG signature at offset 0x{:X} ({:.2} MB)",
                    abs,
                    abs as f64 / (1024.0 * 1024.0)
                );
                candidates.push(abs);
            }

            i += 4;
        }

        file_offset += bytes_read as u64;
        if bytes_read < buf.len() {
            break;
        }
    }

    // Print any remaining progress milestones.
    while next_progress <= file_size {
        eprintln!(
            "  Scanned: {:.0} MB / {:.0} MB ({:.1}%)",
            next_progress as f64 / (1024.0 * 1024.0),
            file_size as f64 / (1024.0 * 1024.0),
            next_progress as f64 / file_size as f64 * 100.0
        );
        next_progress += PROGRESS_INTERVAL;
    }

    Ok(candidates)
}

/// Read until `buf` is full or EOF, handling partial reads.
fn read_full_or_eof(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match file.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Parse a candidate log by seeking to the offset in the file and reading the
/// necessary region.
fn try_parse_log_at_file<W: Write>(
    file: &mut File,
    file_size: u64,
    offset: u64,
    args: &Args,
    out: &mut W,
) -> io::Result<()> {
    let available = file_size.saturating_sub(offset) as usize;
    if available < HEADER_PEEK_SIZE {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Not enough data remaining for a log header"));
    }

    // Seek and read the header peek.
    file.seek(SeekFrom::Start(offset))?;
    let mut peek = [0u8; HEADER_PEEK_SIZE];
    file.read_exact(&mut peek)?;

    let version = u16::from_le_bytes([peek[FIELD_OFFSET_VERSION], peek[FIELD_OFFSET_VERSION + 1]]);
    let log_buffer_offset = u32::from_le_bytes(
        peek[FIELD_OFFSET_LOG_BUFFER_OFFSET..FIELD_OFFSET_LOG_BUFFER_OFFSET + 4].try_into().unwrap(),
    );
    let log_current_offset = u32::from_le_bytes(
        peek[FIELD_OFFSET_LOG_CURRENT_OFFSET..FIELD_OFFSET_LOG_CURRENT_OFFSET + 4].try_into().unwrap(),
    );
    let log_buffer_size = u32::from_le_bytes(
        peek[FIELD_OFFSET_LOG_BUFFER_SIZE..FIELD_OFFSET_LOG_BUFFER_SIZE + 4].try_into().unwrap(),
    );

    eprintln!(
        "  Version: {version}, LogBufferOffset: 0x{log_buffer_offset:X}, \
         LogCurrentOffset: 0x{log_current_offset:X}, LogBufferSize: 0x{log_buffer_size:X}"
    );

    let min_header_size: u32 = match version {
        5 => 80,
        6 => 88,
        v => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Unsupported log version: {v}"))),
    };

    if log_buffer_offset < min_header_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("log_buffer_offset (0x{log_buffer_offset:X}) < min header size (0x{min_header_size:X})"),
        ));
    }
    let full_size = log_buffer_offset as u64 + log_buffer_size as u64;
    if (log_current_offset) < log_buffer_offset || (log_current_offset as u64) > full_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "log_current_offset is outside the log buffer range",
        ));
    }
    if full_size > MAX_LOG_READ_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Claimed log size ({:.2} MB) exceeds limit", full_size as f64 / (1024.0 * 1024.0)),
        ));
    }

    let read_size = (log_current_offset as usize).min(available);
    eprintln!("  Reading {:.2} MB of log data...", read_size as f64 / (1024.0 * 1024.0));

    // Seek back to start of the candidate and read the full log region.
    file.seek(SeekFrom::Start(offset))?;
    let mut log_buf = vec![0u8; read_size];
    file.read_exact(&mut log_buf)?;

    let mut parser = patina_adv_logger::parser::Parser::open(&log_buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    parser.configure_print_entry_metadata(args.entry_metadata);

    writeln!(out, "\n========== Log at offset 0x{:X} ==========", offset)?;
    parse_log(args.header, &parser, out)?;
    writeln!(out, "========== End of log at offset 0x{:X} ==========\n", offset)?;

    Ok(())
}
