//! Parsing logic for the Advanced Logger to be used in the standard environment.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use crate::memory_log::{self, AdvLoggerInfoV5, AdvLoggerInfoV6, LogEntry};
use alloc::format;
use core::{mem::{offset_of, size_of}, str};
use patina::error::EfiError;

use crate::reader::AdvancedLogReader;

// Advanced logger header layout constants (for memory-dump scanning)

/// The ALOG signature value.
pub const ALOG_SIGNATURE: u32 = memory_log::AdvLoggerInfo::SIGNATURE;

/// Byte offset of the `version` field within the AdvLoggerInfo header.
pub const FIELD_OFFSET_VERSION: usize = offset_of!(AdvLoggerInfoV5, version);
/// Byte offset of the `log_buffer_offset` field within the AdvLoggerInfo header.
pub const FIELD_OFFSET_LOG_BUFFER_OFFSET: usize = offset_of!(AdvLoggerInfoV5, log_buffer_offset);
/// Byte offset of the `log_current_offset` field within the AdvLoggerInfo header.
pub const FIELD_OFFSET_LOG_CURRENT_OFFSET: usize = offset_of!(AdvLoggerInfoV5, log_current_offset);
/// Byte offset of the `log_buffer_size` field within the AdvLoggerInfo header.
pub const FIELD_OFFSET_LOG_BUFFER_SIZE: usize = offset_of!(AdvLoggerInfoV5, log_buffer_size);

/// Size of the V5 header in bytes.
pub const HEADER_SIZE_V5: usize = size_of::<AdvLoggerInfoV5>();
/// Size of the V6 header in bytes.
pub const HEADER_SIZE_V6: usize = size_of::<AdvLoggerInfoV6>();

/// Version number for the V5 log format.
pub const VERSION_V5: u16 = memory_log::ADV_LOGGER_INFO_VERSION_V5;
/// Version number for the V6 log format.
pub const VERSION_V6: u16 = memory_log::ADV_LOGGER_INFO_VERSION_V6;

/// Parser for the Advanced Logger buffer.
pub struct Parser<'a> {
    log: AdvancedLogReader<'a>,
    entry_meta: bool,
}

impl<'a> Parser<'a> {
    /// Creates a new `Parser` instance with the provided data slice from an advanced
    /// logger buffer.
    pub fn open(data: &'a [u8]) -> Result<Self, &'static str> {
        let log = AdvancedLogReader::open_log(data).map_err(|err| match err {
            EfiError::InvalidParameter => "Invalid log data provided.",
            EfiError::BufferTooSmall => "Incomplete log buffer.",
            EfiError::Unsupported => "Log data format not supported.",
            _ => "Failed to open log data.",
        })?;

        Ok(Parser { log, entry_meta: true })
    }

    /// Sets whether to print entry metadata (level, phase, timestamp) in the log output.
    pub const fn configure_print_entry_metadata(&mut self, with_meta: bool) {
        self.entry_meta = with_meta;
    }

    /// Writes the log header information to the provided output stream.
    pub fn write_header<W: std::io::Write>(&self, out: &mut W) -> Result<(), &'static str> {
        let header = &format!("{:#x?}\n", self.log.header);
        out.write(header.as_bytes()).map_err(|_| "Failed to write to output.")?;
        Ok(())
    }

    /// Writes the log entries to the provided output stream.
    pub fn write_log<W: std::io::Write>(&self, out: &mut W) -> Result<(), &'static str> {
        let frequency = self.log.get_frequency();

        let mut carry_entry: Option<LogEntry> = None;
        for entry in self.log.iter() {
            if let Some(carry) = carry_entry {
                // If the carry entry is not the same boot phase, drop it. This
                // means messages from different environments are interleaved.
                if carry.phase != entry.phase {
                    carry_entry = None;
                }
            }

            if self.entry_meta && carry_entry.is_none() {
                let timestamp = entry.timestamp;
                let meta_data = &format!(
                    "{:<5}|{:<8}|{}| ",
                    level_name(entry.level),
                    phase_name(entry.phase),
                    get_time_str(timestamp, frequency)
                );
                out.write(meta_data.as_bytes()).map_err(|_| "Failed to write to output.")?;
            }

            let msg = entry.get_message();
            out.write(msg).map_err(|_| "Failed to write to output.")?;
            carry_entry = if !msg.is_empty() && msg[msg.len() - 1] == b'\n' { None } else { Some(entry) };
        }

        Ok(())
    }
}

fn get_time_str(timestamp: u64, frequency: u64) -> String {
    // If there is no frequency, return the raw timestamp.
    if frequency == 0 {
        return format!("{timestamp}");
    }

    // Convert the timestamp to a human-readable format
    let mut time_ms = timestamp / (frequency / 1000);

    let milliseconds = time_ms % 1000;
    time_ms /= 1000;
    let seconds = time_ms % 60;
    time_ms /= 60;
    let minutes = time_ms % 60;
    time_ms /= 60;
    let hours = time_ms % 24;
    format!("{hours:02}:{minutes:02}:{seconds:02}.{milliseconds:03}")
}

fn phase_name(phase: u16) -> &'static str {
    match phase {
        0 => "UNSPEC",
        1 => "SEC",
        2 => "PEI",
        3 => "PEI64",
        4 => "DXE",
        5 => "RUNTIME",
        6 => "MM_CORE",
        7 => "MM",
        8 => "SMM_CORE",
        9 => "SMM",
        10 => "TFA",
        11 => "CNT",
        _ => "UNKNOWN",
    }
}

fn level_name(level: u32) -> &'static str {
    if level & crate::memory_log::DEBUG_LEVEL_ERROR != 0 {
        "ERR"
    } else if level & crate::memory_log::DEBUG_LEVEL_WARNING != 0 {
        "WARN"
    } else if level & crate::memory_log::DEBUG_LEVEL_INFO != 0 {
        "INFO"
    } else if level & crate::memory_log::DEBUG_LEVEL_VERBOSE != 0 {
        "VERB"
    } else {
        "UNKN"
    }
}
