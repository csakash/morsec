//! Chain and MAC verification (`ms log --verify`).

use std::fmt;
use std::path::{Path, PathBuf};

use ms_core::{KeyName, Result};
use ms_vault::Vault;
use serde::Serialize;

use crate::read::{list_files, parse_line, split_lines};
use crate::record::{
    Entry, FORMAT_VERSION, GENESIS_PREV, HMAC_KEY_NAME, MIN_KEY_LEN, hash_rec, mac_ok,
};

/// What went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProblemKind {
    /// A line is not a valid record.
    Malformed,
    /// The last line has no newline: a write was cut short, or bytes were removed.
    TornLine,
    /// An unknown format version.
    UnknownVersion,
    /// The first record is not seq 1 with a zero `prev`: earlier records are missing.
    BadGenesis,
    /// `seq` jumped forward: records are missing, or were moved later.
    MissingRecords,
    /// `seq` went backwards or repeated: records were reordered or duplicated.
    OutOfOrder,
    /// `prev` does not match the previous record's hash: a record was changed or replaced.
    BrokenLink,
    /// The MAC does not match: the record was changed or forged without the key.
    BadMac,
    /// A checkpoint names the wrong head.
    BadCheckpoint,
    /// A file's name does not match the first record in it.
    FileNameMismatch,
    /// An empty receipts file that is not the newest one.
    EmptyFile,
}

impl ProblemKind {
    fn describe(self) -> &'static str {
        match self {
            ProblemKind::Malformed => "the line is not a valid receipt",
            ProblemKind::TornLine => "the last line is incomplete (cut short or bytes removed)",
            ProblemKind::UnknownVersion => "unknown record format version",
            ProblemKind::BadGenesis => {
                "the log does not start at record 1 (earlier records are missing)"
            }
            ProblemKind::MissingRecords => "a record is missing or out of place before this one",
            ProblemKind::OutOfOrder => "records are out of order or duplicated",
            ProblemKind::BrokenLink => {
                "the hash chain is broken (this or the previous record was changed or replaced)"
            }
            ProblemKind::BadMac => "the record's MAC is wrong (changed or forged without the key)",
            ProblemKind::BadCheckpoint => "a checkpoint names the wrong chain head",
            ProblemKind::FileNameMismatch => "the file name does not match its first record",
            ProblemKind::EmptyFile => "an empty receipts file sits before newer ones",
        }
    }
}

/// The first failure found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    /// What.
    pub kind: ProblemKind,
    /// File.
    pub file: PathBuf,
    /// Line, from 1 (0 for a whole-file problem).
    pub line: usize,
    /// The seq the verifier expected at that point.
    pub expected_seq: u64,
    /// Extra detail.
    pub detail: String,
}

/// Result of [`verify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyReport {
    /// Files read.
    pub files: usize,
    /// Records that passed before the first problem (all of them when there is none).
    pub records: u64,
    /// Whether every record's MAC was checked (needs the vault key).
    pub macs_checked: bool,
    /// The first problem, if any.
    pub problem: Option<Problem>,
}

impl VerifyReport {
    /// True when nothing is wrong.
    pub fn ok(&self) -> bool {
        self.problem.is_none()
    }
}

impl fmt::Display for VerifyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.problem {
            None => write!(
                f,
                "receipts intact: {} records in {} files; hash chain ok; MACs {}",
                self.records,
                self.files,
                if self.macs_checked {
                    "ok"
                } else {
                    "not checked"
                }
            ),
            Some(p) => write!(
                f,
                "receipts verification FAILED: {} ({}, line {}, expected record {}{}{}). {} earlier records passed",
                p.kind.describe(),
                p.file.display(),
                p.line,
                p.expected_seq,
                if p.detail.is_empty() { "" } else { "; " },
                p.detail,
                self.records
            ),
        }
    }
}

/// Verifies the chain in `dir`; with `vault`, also every record's MAC (key
/// [`HMAC_KEY_NAME`]). The key is used inside `with_secret` only.
pub fn verify(dir: &Path, vault: Option<&dyn Vault>) -> Result<VerifyReport> {
    let Some(vault) = vault else {
        return verify_with_key(dir, None);
    };
    let name = KeyName::new(HMAC_KEY_NAME)?;
    let mut out = None;
    vault.with_secret(&name, &mut |key| {
        out = Some(if key.len() < MIN_KEY_LEN {
            Err(short_key())
        } else {
            verify_with_key(dir, Some(key))
        });
    })?;
    out.unwrap_or_else(|| Err(ms_core::Error::NoSuchKey(HMAC_KEY_NAME.into())))
}

pub(crate) fn short_key() -> ms_core::Error {
    ms_core::Error::io(
        format!("the receipts key {HMAC_KEY_NAME} is shorter than {MIN_KEY_LEN} bytes"),
        std::io::Error::other("recreate it with: ms init"),
    )
}

fn verify_with_key(dir: &Path, key: Option<&[u8]>) -> Result<VerifyReport> {
    let files = list_files(dir)?;
    let mut report = VerifyReport {
        files: files.len(),
        records: 0,
        macs_checked: key.is_some(),
        problem: None,
    };
    let mut expected = 1u64;
    let mut prev = GENESIS_PREV;
    let n_files = files.len();
    for (fi, f) in files.iter().enumerate() {
        // Details can quote file contents (serde errors name fields): keep them inert.
        let fail = |kind, line, expected_seq, detail: String| Problem {
            kind,
            file: f.path.clone(),
            line,
            expected_seq,
            detail: crate::export::inert(&detail),
        };
        let bytes = crate::read::read_file(&f.path)?;
        let (lines, torn) = split_lines(&bytes);
        if lines.is_empty() {
            if fi + 1 != n_files {
                report.problem = Some(fail(ProblemKind::EmptyFile, 0, expected, String::new()));
                return Ok(report);
            }
            if f.first_seq != expected {
                report.problem = Some(fail(
                    ProblemKind::FileNameMismatch,
                    0,
                    expected,
                    format!("empty file named for record {}", f.first_seq),
                ));
            }
            return Ok(report);
        }
        if f.first_seq != expected {
            let kind = if expected == 1 {
                ProblemKind::BadGenesis
            } else if f.first_seq > expected {
                ProblemKind::MissingRecords
            } else {
                ProblemKind::FileNameMismatch
            };
            report.problem = Some(fail(
                kind,
                0,
                expected,
                format!("file is named for record {}", f.first_seq),
            ));
            return Ok(report);
        }
        for (li, line) in lines.iter().enumerate() {
            let line_no = li + 1;
            if torn && li + 1 == lines.len() {
                report.problem = Some(fail(
                    ProblemKind::TornLine,
                    line_no,
                    expected,
                    String::new(),
                ));
                return Ok(report);
            }
            let p = match parse_line(line) {
                Ok(p) => p,
                Err(why) => {
                    report.problem = Some(fail(ProblemKind::Malformed, line_no, expected, why));
                    return Ok(report);
                }
            };
            if let Some(k) = key {
                // MAC first: a forged record must not be described by its own claims.
                if !mac_ok(k, p.raw, &p.mac) {
                    report.problem =
                        Some(fail(ProblemKind::BadMac, line_no, expected, String::new()));
                    return Ok(report);
                }
            }
            if p.rec.v != FORMAT_VERSION {
                report.problem = Some(fail(
                    ProblemKind::UnknownVersion,
                    line_no,
                    expected,
                    format!("version {}", p.rec.v),
                ));
                return Ok(report);
            }
            if p.rec.seq != expected {
                let kind = if expected == 1 {
                    ProblemKind::BadGenesis
                } else if p.rec.seq > expected {
                    ProblemKind::MissingRecords
                } else {
                    ProblemKind::OutOfOrder
                };
                report.problem = Some(fail(
                    kind,
                    line_no,
                    expected,
                    format!("found record {}", p.rec.seq),
                ));
                return Ok(report);
            }
            if p.rec.prev != hex::encode(prev) {
                let kind = if expected == 1 {
                    ProblemKind::BadGenesis
                } else {
                    ProblemKind::BrokenLink
                };
                report.problem = Some(fail(kind, line_no, expected, String::new()));
                return Ok(report);
            }
            if let Entry::Checkpoint(c) = &p.rec.entry
                && (c.through_seq.checked_add(1) != Some(p.rec.seq) || c.head != p.rec.prev)
            {
                report.problem = Some(fail(
                    ProblemKind::BadCheckpoint,
                    line_no,
                    expected,
                    String::new(),
                ));
                return Ok(report);
            }
            prev = hash_rec(p.raw);
            expected += 1;
            report.records += 1;
        }
    }
    Ok(report)
}
