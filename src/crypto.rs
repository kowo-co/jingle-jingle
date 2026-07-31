//! Vault encryption: versioned binary header + XChaCha20-Poly1305.
//!
//! Layout:
//! ```text
//! offset  len  field
//! 0       4    magic  b"JNGL"
//! 4       1    format version (1)
//! 5       1    kdf id   (1 = HKDF-SHA256)
//! 6       1    aead id  (1 = XChaCha20-Poly1305)
//! 7       32   salt     (random at init, fixed for the vault's lifetime)
//! 39      24   nonce    (fresh random on every write)
//! 63      ..   ciphertext || 16-byte Poly1305 tag
//! ```
//!
//! Bytes 0..39 (everything before the nonce) are bound as AEAD associated
//! data, so version/KDF/AEAD downgrades and salt swaps fail the tag check.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const MAGIC: [u8; 4] = *b"JNGL";
pub const FORMAT_VERSION: u8 = 1;
pub const KDF_HKDF_SHA256: u8 = 1;
pub const AEAD_XCHACHA20_POLY1305: u8 = 1;

pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// magic + version + kdf + aead + salt
pub const AAD_LEN: usize = 4 + 1 + 1 + 1 + SALT_LEN;
pub const MIN_FILE_LEN: usize = AAD_LEN + NONCE_LEN + TAG_LEN;

const HKDF_INFO: &[u8] = b"jingle/v1/enc";

fn derive_key(keyfile: &[u8; 32], salt: &[u8; SALT_LEN]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), keyfile);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    // Keep the derived XChaCha key off swap for its (short) lifetime.
    crate::harden::mlock(okm.as_ref());
    okm
}

pub fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|e| Error::Other(format!("failed to gather OS randomness: {e}")))?;
    Ok(salt)
}

/// Encrypt `plaintext` into a complete vault file image (header included).
pub fn seal(keyfile: &[u8; 32], salt: &[u8; SALT_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut aad = [0u8; AAD_LEN];
    aad[0..4].copy_from_slice(&MAGIC);
    aad[4] = FORMAT_VERSION;
    aad[5] = KDF_HKDF_SHA256;
    aad[6] = AEAD_XCHACHA20_POLY1305;
    aad[7..].copy_from_slice(salt);

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|e| Error::Other(format!("failed to gather OS randomness: {e}")))?;

    let key = derive_key(keyfile, salt);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Other("encryption failed".into()))?;

    let mut out = Vec::with_capacity(AAD_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a complete vault file image. Returns the salt (needed to re-seal)
/// and the zeroize-on-drop plaintext.
pub fn open(keyfile: &[u8; 32], data: &[u8]) -> Result<([u8; SALT_LEN], Zeroizing<Vec<u8>>)> {
    if data.len() < MIN_FILE_LEN {
        return Err(Error::Tamper("file is truncated".into()));
    }
    if data[0..4] != MAGIC {
        return Err(Error::Tamper("not a jingle vault (bad magic)".into()));
    }
    if data[4] != FORMAT_VERSION {
        return Err(Error::Tamper(format!(
            "unsupported vault format version {}",
            data[4]
        )));
    }
    if data[5] != KDF_HKDF_SHA256 || data[6] != AEAD_XCHACHA20_POLY1305 {
        return Err(Error::Tamper("unsupported KDF or AEAD identifier".into()));
    }

    let aad = &data[..AAD_LEN];
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&data[7..AAD_LEN]);
    let nonce = &data[AAD_LEN..AAD_LEN + NONCE_LEN];
    let ciphertext = &data[AAD_LEN + NONCE_LEN..];

    let key = derive_key(keyfile, &salt);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            Error::Tamper("decryption failed: wrong keyfile, or the vault has been modified".into())
        })?;
    Ok((salt, Zeroizing::new(plaintext)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn roundtrip() {
        let salt = random_salt().unwrap();
        let sealed = seal(&key(1), &salt, b"hello vault").unwrap();
        let (got_salt, plain) = open(&key(1), &sealed).unwrap();
        assert_eq!(got_salt, salt);
        assert_eq!(plain.as_slice(), b"hello vault");
    }

    #[test]
    fn wrong_key_fails() {
        let salt = random_salt().unwrap();
        let sealed = seal(&key(1), &salt, b"data").unwrap();
        assert!(matches!(open(&key(2), &sealed), Err(Error::Tamper(_))));
    }

    #[test]
    fn nonce_is_fresh_per_seal() {
        let salt = random_salt().unwrap();
        let a = seal(&key(1), &salt, b"data").unwrap();
        let b = seal(&key(1), &salt, b"data").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn any_flipped_byte_is_tamper() {
        let salt = random_salt().unwrap();
        let sealed = seal(&key(1), &salt, b"sensitive payload bytes").unwrap();
        for i in 0..sealed.len() {
            let mut corrupted = sealed.clone();
            corrupted[i] ^= 0x01;
            assert!(
                matches!(open(&key(1), &corrupted), Err(Error::Tamper(_))),
                "flipping byte {i} was not detected"
            );
        }
    }

    #[test]
    fn truncation_is_tamper() {
        let salt = random_salt().unwrap();
        let sealed = seal(&key(1), &salt, b"data").unwrap();
        for len in [0, 3, AAD_LEN, MIN_FILE_LEN - 1, sealed.len() - 1] {
            assert!(matches!(
                open(&key(1), &sealed[..len]),
                Err(Error::Tamper(_))
            ));
        }
    }

    #[test]
    fn header_downgrade_rejected() {
        let salt = random_salt().unwrap();
        let sealed = seal(&key(1), &salt, b"data").unwrap();
        // Even if a future parser accepted other ids, AAD binding must fail the tag.
        let mut swapped = sealed.clone();
        swapped[7] ^= 0xFF; // first salt byte
        assert!(matches!(open(&key(1), &swapped), Err(Error::Tamper(_))));
    }
}
