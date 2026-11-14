//! SSH wire encoding (RFC 4251 §5): `uint32`, `string`, `byte`, `boolean`.
//!
//! Everything read here comes from a process msd doesn't trust, so every read is bounds-checked
//! and a short or malformed message is an error, never a panic.

/// Reads SSH wire values from a byte slice.
#[derive(Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.buf.split_first()?;
        self.buf = rest;
        Some(b)
    }

    pub(crate) fn bool(&mut self) -> Option<bool> {
        self.u8().map(|b| b != 0)
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        let (head, rest) = self.buf.split_first_chunk::<4>()?;
        self.buf = rest;
        Some(u32::from_be_bytes(*head))
    }

    pub(crate) fn string(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.u32()?).ok()?;
        if n > self.buf.len() {
            return None;
        }
        let (s, rest) = self.buf.split_at(n);
        self.buf = rest;
        Some(s)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Appends SSH wire values to a buffer.
pub(crate) fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    // Every string msd writes is far below 4 GiB (keys, signatures, comments).
    put_u32(out, u32::try_from(s.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(s);
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=short or lying lengths are errors, never panics or over-reads; fails_when=a
    // string longer than the buffer is returned; no_claim=-
    #[test]
    fn bounds() {
        let mut out = Vec::new();
        put_string(&mut out, b"abc");
        put_u32(&mut out, 7);
        let mut r = Reader::new(&out);
        assert_eq!(r.string(), Some(&b"abc"[..]));
        assert_eq!(r.u32(), Some(7));
        assert!(r.is_empty());
        assert_eq!(r.u8(), None);
        let mut r = Reader::new(&[0, 0, 0, 9, 1, 2]);
        assert_eq!(r.string(), None);
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(r.string(), None);
        let mut r = Reader::new(&[0, 0]);
        assert_eq!(r.u32(), None);
    }
}
