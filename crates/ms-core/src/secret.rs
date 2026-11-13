//! Secret values.

use std::fmt;

use zeroize::Zeroizing;

/// A secret value held by the broker.
///
/// The buffer is zeroized on drop. On purpose this type has no `Clone`, `Serialize`,
/// `Deserialize`, `Display` or `PartialEq`, so it cannot be copied around, sent in an IPC message,
/// printed or compared in non-constant time by accident. `Debug` shows only the length.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Takes ownership of `bytes`. The caller's buffer moves in; nothing is copied.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the value. Broker-internal: call it only at the point the value is used
    /// (substituted into a request, handed to a child), never to log or return it.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when the value is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

impl From<String> for SecretBytes {
    fn from(s: String) -> Self {
        Self::new(s.into_bytes())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([redacted; {} bytes])", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=Debug output never contains the value; fails_when=any byte run of the canary is
    // printed; no_claim=does not prove memory is wiped (see ms-vault zeroize test)
    #[test]
    fn debug_is_redacted() {
        let canary = "sk_test_CANARY_7f3a9c";
        let s = SecretBytes::from(canary.to_owned());
        let dbg = format!("{s:?} {:#?}", s);
        assert!(!dbg.contains("CANARY"), "{dbg}");
        assert!(!dbg.contains(canary), "{dbg}");
        assert!(dbg.contains("redacted; 21 bytes"), "{dbg}");
        assert_eq!(s.expose(), canary.as_bytes());
        assert_eq!(s.len(), 21);
        assert!(!s.is_empty());
    }
}
