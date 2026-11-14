//! ed25519 keys: the user's private key (from the vault, OpenSSH format), signing, and checking
//! a server's host-key signature.
//!
//! The private key is parsed from the vault value inside the vault's closure into wiped buffers,
//! used for one operation and dropped. It is never written anywhere.

use base64::Engine as _;
#[cfg(test)]
use ring::signature::KeyPair as _;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use zeroize::Zeroizing;

use super::wire::{Reader, put_string};

/// The key type name in SSH.
pub(crate) const ED25519_NAME: &[u8] = b"ssh-ed25519";
const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";
const MAGIC: &[u8] = b"openssh-key-v1\0";
/// Largest vault value parsed as a key.
const MAX_KEY_TEXT: usize = 16 * 1024;

/// Why a vault value is not a usable key. The text says what to do and never holds key bytes.
pub(crate) const NOT_A_KEY: &str = "the key's value is not an unencrypted OpenSSH ed25519 private key (-----BEGIN OPENSSH PRIVATE KEY-----, made with ssh-keygen -t ed25519 -N ''). Other key types and passphrase-protected keys are not supported yet";

/// A parsed private key, for one operation. Dropping it wipes the seed copy msd made (ring's own
/// key schedule is freed, not wiped: ARI42 GW-1 residual).
pub(crate) struct PrivateKey {
    pair: Ed25519KeyPair,
    public: [u8; 32],
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey").finish_non_exhaustive()
    }
}

impl PrivateKey {
    /// Parses an unencrypted OpenSSH ed25519 private key.
    pub(crate) fn from_openssh(text: &[u8]) -> Result<Self, &'static str> {
        if text.len() > MAX_KEY_TEXT {
            return Err(NOT_A_KEY);
        }
        let text = std::str::from_utf8(text).map_err(|_| NOT_A_KEY)?;
        let body = text
            .trim()
            .strip_prefix(PEM_BEGIN)
            .and_then(|b| b.strip_suffix(PEM_END))
            .ok_or(NOT_A_KEY)?;
        let b64: Zeroizing<String> =
            Zeroizing::new(body.chars().filter(|c| !c.is_ascii_whitespace()).collect());
        let raw = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|_| NOT_A_KEY)?,
        );
        let rest = raw.strip_prefix(MAGIC).ok_or(NOT_A_KEY)?;
        let mut r = Reader::new(rest);
        let cipher = r.string().ok_or(NOT_A_KEY)?;
        let kdf = r.string().ok_or(NOT_A_KEY)?;
        let _kdf_options = r.string().ok_or(NOT_A_KEY)?;
        if cipher != b"none" || kdf != b"none" || r.u32() != Some(1) {
            return Err(NOT_A_KEY);
        }
        let public_blob = r.string().ok_or(NOT_A_KEY)?;
        let private = r.string().ok_or(NOT_A_KEY)?;
        if !r.is_empty() {
            return Err(NOT_A_KEY);
        }
        let public = public_from_blob(public_blob).ok_or(NOT_A_KEY)?;
        let mut p = Reader::new(private);
        let (c1, c2) = (p.u32().ok_or(NOT_A_KEY)?, p.u32().ok_or(NOT_A_KEY)?);
        if c1 != c2 || p.string() != Some(ED25519_NAME) {
            return Err(NOT_A_KEY);
        }
        let pk = p.string().ok_or(NOT_A_KEY)?;
        let sk = p.string().ok_or(NOT_A_KEY)?;
        if pk != public || sk.len() != 64 || sk[32..] != public {
            return Err(NOT_A_KEY);
        }
        let seed = Zeroizing::new(<[u8; 32]>::try_from(&sk[..32]).map_err(|_| NOT_A_KEY)?);
        let pair =
            Ed25519KeyPair::from_seed_and_public_key(&seed[..], &public).map_err(|_| NOT_A_KEY)?;
        Ok(Self { pair, public })
    }

    /// The public key blob (`string "ssh-ed25519", string key`).
    pub(crate) fn public_blob(&self) -> Vec<u8> {
        public_blob(&self.public)
    }

    /// The public key.
    pub(crate) fn public(&self) -> [u8; 32] {
        self.public
    }

    /// An SSH signature blob over `data` (`string "ssh-ed25519", string sig`).
    pub(crate) fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sig = self.pair.sign(data);
        let mut out = Vec::with_capacity(83);
        put_string(&mut out, ED25519_NAME);
        put_string(&mut out, sig.as_ref());
        out
    }

    /// The public half matches what ring derived from the seed (tests).
    #[cfg(test)]
    pub(crate) fn consistent(&self) -> bool {
        self.pair.public_key().as_ref() == self.public
    }
}

/// The SSH public key blob for an ed25519 key.
pub(crate) fn public_blob(key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(51);
    put_string(&mut out, ED25519_NAME);
    put_string(&mut out, key);
    out
}

/// The 32-byte key in an `ssh-ed25519` public key blob, if `blob` is exactly one.
pub(crate) fn public_from_blob(blob: &[u8]) -> Option<[u8; 32]> {
    let mut r = Reader::new(blob);
    if r.string()? != ED25519_NAME {
        return None;
    }
    let k = r.string()?.try_into().ok()?;
    r.is_empty().then_some(k)
}

/// True when `sig_blob` is a valid `ssh-ed25519` signature by `key` over `data`.
pub(crate) fn verify(key: &[u8; 32], data: &[u8], sig_blob: &[u8]) -> bool {
    let mut r = Reader::new(sig_blob);
    if r.string() != Some(ED25519_NAME) {
        return false;
    }
    let Some(sig) = r.string() else { return false };
    if sig.len() != 64 || !r.is_empty() {
        return false;
    }
    UnparsedPublicKey::new(&ED25519, key)
        .verify(data, sig)
        .is_ok()
}

/// `SHA256:<base64>` as `ssh-keygen -l` prints it.
pub(crate) fn fingerprint(key: &[u8; 32]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, &public_blob(key));
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(d.as_ref())
    )
}

/// A one-line OpenSSH public key file body.
pub(crate) fn public_line(key: &[u8; 32], comment: &str) -> String {
    format!(
        "ssh-ed25519 {} {comment}\n",
        base64::engine::general_purpose::STANDARD.encode(public_blob(key))
    )
}

/// Test helpers: an OpenSSH private key text for a seed, as `ssh-keygen` writes it.
#[cfg(test)]
pub(crate) mod testkey {
    use super::*;
    use crate::adapters::ssh_git::wire::put_u32;

    pub(crate) fn public_of(seed: &[u8; 32]) -> [u8; 32] {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
        pair.public_key().as_ref().try_into().unwrap()
    }

    pub(crate) fn openssh(seed: &[u8; 32]) -> String {
        openssh_with(seed, b"none", &public_of(seed))
    }

    /// Like [`openssh`] with another cipher name and the public half of the private section
    /// replaced by `inner_public`.
    pub(crate) fn openssh_with(seed: &[u8; 32], cipher: &[u8], inner_public: &[u8; 32]) -> String {
        let public = public_of(seed);
        let blob = public_blob(&public);
        let mut private = Vec::new();
        put_u32(&mut private, 0x1234_5678);
        put_u32(&mut private, 0x1234_5678);
        put_string(&mut private, ED25519_NAME);
        put_string(&mut private, inner_public);
        let mut sk = seed.to_vec();
        sk.extend_from_slice(inner_public);
        put_string(&mut private, &sk);
        put_string(&mut private, b"test");
        let mut pad = 1u8;
        while private.len() % 8 != 0 {
            private.push(pad);
            pad += 1;
        }
        let mut raw = MAGIC.to_vec();
        put_string(&mut raw, cipher);
        put_string(&mut raw, b"none");
        put_string(&mut raw, b"");
        put_u32(&mut raw, 1);
        put_string(&mut raw, &blob);
        put_string(&mut raw, &private);
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let mut text = format!("{PEM_BEGIN}\n");
        for chunk in b64.as_bytes().chunks(70) {
            text.push_str(std::str::from_utf8(chunk).unwrap());
            text.push('\n');
        }
        text.push_str(PEM_END);
        text.push('\n');
        text
    }

    /// A raw ed25519 signature over `data` with `seed`, as an SSH blob (host-key side).
    pub(crate) fn sign_with(seed: &[u8; 32], data: &[u8]) -> Vec<u8> {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
        let mut out = Vec::new();
        put_string(&mut out, ED25519_NAME);
        put_string(&mut out, pair.sign(data).as_ref());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testkey::*;
    use super::*;

    // protects=only an unencrypted OpenSSH ed25519 key parses; its signatures verify; a
    // tampered, encrypted or other-type key is refused with a message that holds no key bytes;
    // fails_when=a malformed key parses or a bad signature verifies; no_claim=keys ssh-keygen
    // writes (the sshd integration test uses those)
    #[test]
    fn parse_sign_verify() {
        let seed = [7u8; 32];
        let k = PrivateKey::from_openssh(openssh(&seed).as_bytes()).unwrap();
        assert!(k.consistent());
        assert_eq!(k.public(), public_of(&seed));
        let sig = k.sign(b"data");
        assert!(verify(&k.public(), b"data", &sig));
        assert!(!verify(&k.public(), b"datx", &sig));
        assert!(!verify(&public_of(&[8u8; 32]), b"data", &sig));
        assert!(!format!("{k:?}").contains("pair"));
        assert_eq!(public_from_blob(&k.public_blob()), Some(k.public()));
        assert!(fingerprint(&k.public()).starts_with("SHA256:"));

        let good = openssh(&seed);
        let encrypted = openssh_with(&seed, b"aes256-ctr", &public_of(&seed));
        // A private section whose public half is another key's.
        let mismatched = openssh_with(&seed, b"none", &public_of(&[9u8; 32]));
        for bad in [
            "",
            "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
            &good.replace(PEM_END, ""),
            &encrypted,
            &mismatched,
            &good[..good.len() / 2],
        ] {
            let e = PrivateKey::from_openssh(bad.as_bytes()).unwrap_err();
            assert_eq!(e, NOT_A_KEY);
        }
    }
}
