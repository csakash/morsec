//! Reading receipts files.

use std::fs;
use std::path::{Path, PathBuf};

use ms_core::{Error, Result};
use serde::Serialize;

use crate::record::{RawLine, Rec, hash_rec, parse_file_name};

/// A receipts file and the first seq its name claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptsFile {
    /// First seq, from the name.
    pub first_seq: u64,
    /// Path.
    pub path: PathBuf,
}

/// Receipts files in `dir`, in seq order. A missing directory has none.
pub fn list_files(dir: &Path) -> Result<Vec<ReceiptsFile>> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(Error::io(
                format!("reading receipts directory {}", dir.display()),
                e,
            ));
        }
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::io("reading receipts directory", e))?;
        let name = entry.file_name();
        if let Some(first_seq) = name.to_str().and_then(parse_file_name) {
            files.push(ReceiptsFile {
                first_seq,
                path: entry.path(),
            });
        }
    }
    files.sort_by_key(|f| f.first_seq);
    Ok(files)
}

/// A record read back, with its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoredRecord {
    /// Sequence number.
    pub seq: u64,
    /// Hex hash of its `rec` bytes (the next record's `prev`).
    pub hash: String,
    /// The record.
    pub rec: Rec,
}

/// One parsed line, borrowing the raw bytes.
pub(crate) struct ParsedLine<'a> {
    pub raw: &'a [u8],
    pub mac: String,
    pub rec: Rec,
}

/// Parses one line (without its `\n`).
pub(crate) fn parse_line(line: &[u8]) -> std::result::Result<ParsedLine<'_>, String> {
    let raw: RawLine<'_> = serde_json::from_slice(line).map_err(|e| e.to_string())?;
    let rec_bytes = raw.rec.get().as_bytes();
    let rec: Rec = serde_json::from_slice(rec_bytes).map_err(|e| e.to_string())?;
    Ok(ParsedLine {
        raw: rec_bytes,
        mac: raw.mac,
        rec,
    })
}

/// Splits file contents into lines. Returns the lines and whether the last one is torn (no
/// trailing newline).
pub(crate) fn split_lines(bytes: &[u8]) -> (Vec<&[u8]>, bool) {
    if bytes.is_empty() {
        return (Vec::new(), false);
    }
    let torn = !bytes.ends_with(b"\n");
    let body = if torn {
        bytes
    } else {
        &bytes[..bytes.len() - 1]
    };
    (body.split(|b| *b == b'\n').collect(), torn)
}

/// Every record in `dir`, in file and line order. It does not check MACs or links (that is
/// [`crate::verify`]); it fails on a line it can't parse, saying to run `ms log --verify`.
pub fn read_all(dir: &Path) -> Result<Vec<StoredRecord>> {
    let mut out = Vec::new();
    for f in list_files(dir)? {
        let bytes =
            fs::read(&f.path).map_err(|e| Error::io(format!("reading {}", f.path.display()), e))?;
        let (lines, _torn) = split_lines(&bytes);
        for (i, line) in lines.iter().enumerate() {
            let p = parse_line(line).map_err(|why| {
                Error::io(
                    format!(
                        "{} line {} is not a receipt ({why}); run: ms log --verify",
                        f.path.display(),
                        i + 1
                    ),
                    std::io::Error::from(std::io::ErrorKind::InvalidData),
                )
            })?;
            out.push(StoredRecord {
                seq: p.rec.seq,
                hash: hex::encode(hash_rec(p.raw)),
                rec: p.rec,
            });
        }
    }
    Ok(out)
}
