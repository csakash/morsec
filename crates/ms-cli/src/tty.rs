//! Terminal input for secrets: echo off, and Ctrl-C delivered as a byte so the terminal is always
//! restored (a SIGINT would kill the process with echo still off).

use std::io::{self, IsTerminal, Write};
use std::os::fd::AsFd;

use rustix::io::Errno;
use rustix::termios::{
    LocalModes, OptionalActions, SpecialCodeIndex, Termios, tcgetattr, tcsetattr,
};
use zeroize::{Zeroize, Zeroizing};

/// Largest value accepted from a terminal or `--stdin`.
pub(crate) const MAX_VALUE_BYTES: usize = 64 * 1024;

/// True when stdin is a terminal.
pub(crate) fn stdin_is_tty() -> bool {
    io::stdin().is_terminal()
}

/// Puts the terminal back as it was, however the read ends.
struct Restore {
    stdin: io::Stdin,
    orig: Termios,
}

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = tcsetattr(self.stdin.as_fd(), OptionalActions::Now, &self.orig);
    }
}

/// Reads one line from the terminal without echo. `Ok(None)` when the user cancels (Ctrl-C, or
/// Ctrl-D on an empty line). Bytes go straight from the fd into a zeroizing buffer, without std's
/// stdin buffer.
pub(crate) fn read_hidden(prompt: &str) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let stdin = io::stdin();
    let orig = tcgetattr(stdin.as_fd())?;
    let mut raw = orig.clone();
    raw.local_modes
        .remove(LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG | LocalModes::IEXTEN);
    raw.special_codes[SpecialCodeIndex::VMIN] = 1;
    raw.special_codes[SpecialCodeIndex::VTIME] = 0;
    // Flush: drop anything typed before the prompt, so it can't become part of the value.
    tcsetattr(stdin.as_fd(), OptionalActions::Flush, &raw)?;
    let guard = Restore { stdin, orig };

    let mut err = io::stderr();
    let _ = write!(err, "{prompt}");
    let _ = err.flush();
    // Full capacity up front: growing the Vec would leave unwiped copies of the value behind.
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_VALUE_BYTES));
    let mut byte = [0u8; 1];
    let result = loop {
        let n = match rustix::io::read(guard.stdin.as_fd(), &mut byte) {
            Ok(n) => n,
            Err(Errno::INTR) => continue,
            Err(e) => break Err(io::Error::from(e)),
        };
        if n == 0 {
            break Ok(if buf.is_empty() { None } else { Some(()) });
        }
        match byte[0] {
            b'\r' | b'\n' => break Ok(Some(())),
            0x03 => break Ok(None),
            0x04 if buf.is_empty() => break Ok(None),
            0x04 => {}
            0x7f | 0x08 => {
                buf.pop();
            }
            0x15 => buf.clear(),
            // Arrow keys, Ctrl-Z and other control bytes are not part of a value; refuse rather
            // than store them silently.
            c if c < 0x20 => {
                break Err(io::Error::other(
                    "a control key was typed (arrows, Ctrl-Z, ...). Nothing was stored; try again",
                ));
            }
            c => {
                if buf.len() >= MAX_VALUE_BYTES {
                    break Err(io::Error::other("the value is longer than 64 KiB"));
                }
                buf.push(c);
            }
        }
    };
    byte.zeroize();
    drop(guard);
    let _ = writeln!(err);
    result.map(|r| r.map(|()| buf))
}

/// Reads all of stdin (a pipe or file) up to [`MAX_VALUE_BYTES`], without std's stdin buffer, and
/// strips one trailing newline.
pub(crate) fn read_stdin_value() -> io::Result<Zeroizing<Vec<u8>>> {
    let stdin = io::stdin();
    let mut buf = Zeroizing::new(vec![0u8; MAX_VALUE_BYTES + 1]);
    let mut len = 0;
    loop {
        if len == buf.len() {
            return Err(io::Error::other("the value is longer than 64 KiB"));
        }
        match rustix::io::read(stdin.as_fd(), &mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(Errno::INTR) => {}
            Err(e) => return Err(io::Error::from(e)),
        }
    }
    let mut end = len;
    if end > 0 && buf[end - 1] == b'\n' {
        end -= 1;
        if end > 0 && buf[end - 1] == b'\r' {
            end -= 1;
        }
    }
    let mut out = Zeroizing::new(Vec::with_capacity(end));
    out.extend_from_slice(&buf[..end]);
    Ok(out)
}

/// Asks a yes/no question on the controlling terminal (`/dev/tty`), not stdin, so a pipe can't
/// answer it. Used for the pre-L11 terminal path (L07 SPEC D-A). True only for a typed `yes`.
pub(crate) fn confirm_at_terminal(question: &str) -> io::Result<bool> {
    use std::io::{BufRead, BufReader, Read};
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    write!(tty, "{question} Type yes to confirm: ")?;
    tty.flush()?;
    let mut line = String::new();
    BufReader::new((&tty).take(64)).read_line(&mut line)?;
    Ok(line.trim() == "yes")
}
