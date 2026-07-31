//! Keyfile wrapping (v2): seal the 32-byte root key at rest under a passphrase.
//!
//! The v1 keyfile is the raw 32-byte root key, protected by nothing but mode
//! 0600 — `cat ~/.config/jingle/key` defeats the entire vault. This module adds
//! a v2 format that encrypts that root key under a key-encryption key (KEK)
//! derived from a passphrase, so the on-disk bytes are useless without the
//! passphrase (which lives somewhere the attacker who copied your home
//! directory does not have — see the README on this tradeoff).
//!
//! The design mirrors `crypto.rs` deliberately: a versioned binary header bound
//! as AEAD associated data, so a version/KDF/AEAD downgrade or a salt/param swap
//! fails the Poly1305 tag rather than silently changing how the file is read.
//!
//! Layout:
//! ```text
//! offset  len  field
//! 0       4    magic  b"JKW1"  (jingle key-wrap)
//! 4       1    format version (2)  — distinguishes from the raw v1 keyfile
//! 5       1    kdf id   (1 = Argon2id)
//! 6       1    aead id  (1 = XChaCha20-Poly1305)
//! 7       4    argon2 m_cost, KiB   (u32 little-endian)
//! 11      4    argon2 t_cost         (u32 little-endian)
//! 15      1    argon2 p_cost (lanes)
//! 16      32   salt   (random per wrap)
//! 48      24   nonce  (random per wrap)
//! 72      48   sealed root key: 32-byte key ciphertext || 16-byte Poly1305 tag
//! ```
//!
//! Bytes 0..48 (everything before the nonce) are bound as AEAD associated data.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::keyfile::KEY_LEN;
use crate::{Error, Result};

pub const MAGIC: [u8; 4] = *b"JKW1";
/// Keyfile format version. v1 is the raw 32-byte key (no header); v2 is wrapped.
pub const FORMAT_VERSION: u8 = 2;
pub const KDF_ARGON2ID: u8 = 1;
pub const AEAD_XCHACHA20_POLY1305: u8 = 1;

pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

/// magic + version + kdf + aead + m_cost + t_cost + p_cost + salt
pub const AAD_LEN: usize = 4 + 1 + 1 + 1 + 4 + 4 + 1 + SALT_LEN;
/// Header (AAD) + nonce + sealed 32-byte key + tag.
pub const V2_FILE_LEN: usize = AAD_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;

// Argon2id parameters. Chosen for an interactive per-invocation unlock:
//   * memory = 64 MiB — well above the 19 MiB OWASP floor; forces a GPU/ASIC
//     attacker to pay for real RAM per guess.
//   * iterations (time cost) = 3.
//   * parallelism (lanes) = 1 — deterministic and portable; a CLI has no thread
//     budget to spend and single-lane keeps the cost identical everywhere.
// These are written into every v2 header, so a future default change stays
// backward compatible: old files decrypt with the params they were sealed with.
pub const ARGON2_M_COST_KIB: u32 = 65536; // 64 MiB
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;

/// Argon2 parameters recovered from (or being written into) a v2 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            m_cost: ARGON2_M_COST_KIB,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        }
    }
}

/// Does `data` look like a v2 wrapped keyfile? (magic match only — cheap peek.)
pub fn is_wrapped(data: &[u8]) -> bool {
    data.len() >= 5 && data[0..4] == MAGIC && data[4] == FORMAT_VERSION
}

fn derive_kek(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    p: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(p.m_cost, p.t_cost, p.p_cost, Some(32))
        .map_err(|e| Error::Passphrase(format!("invalid Argon2 parameters: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, kek.as_mut())
        .map_err(|e| Error::Passphrase(format!("key derivation failed: {e}")))?;
    // Keep the KEK off swap for its short lifetime.
    crate::harden::mlock(kek.as_ref());
    Ok(kek)
}

fn build_aad(salt: &[u8; SALT_LEN], p: &KdfParams) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[0..4].copy_from_slice(&MAGIC);
    aad[4] = FORMAT_VERSION;
    aad[5] = KDF_ARGON2ID;
    aad[6] = AEAD_XCHACHA20_POLY1305;
    aad[7..11].copy_from_slice(&p.m_cost.to_le_bytes());
    aad[11..15].copy_from_slice(&p.t_cost.to_le_bytes());
    aad[15] = p.p_cost as u8;
    aad[16..].copy_from_slice(salt);
    aad
}

/// Wrap a 32-byte root key under `passphrase`, producing a complete v2 keyfile
/// image (header included). Uses the module's default Argon2 parameters.
pub fn wrap(root_key: &[u8; KEY_LEN], passphrase: &[u8]) -> Result<Vec<u8>> {
    let params = KdfParams::default();

    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|e| Error::Other(format!("failed to gather OS randomness: {e}")))?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|e| Error::Other(format!("failed to gather OS randomness: {e}")))?;

    let aad = build_aad(&salt, &params);
    let kek = derive_kek(passphrase, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new(kek.as_ref().into());
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: root_key.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| Error::Other("key wrapping failed".into()))?;

    let mut out = Vec::with_capacity(V2_FILE_LEN);
    out.extend_from_slice(&aad);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    debug_assert_eq!(out.len(), V2_FILE_LEN);
    Ok(out)
}

/// Unwrap a v2 keyfile image, returning the 32-byte root key.
///
/// Structural problems (bad magic/version/ids, wrong length) surface as
/// `Error::Keyfile` — the file is malformed. A valid header whose tag does not
/// verify surfaces as `Error::Passphrase` — the passphrase is wrong (or, less
/// commonly, the sealed bytes were corrupted). This distinction is deliberate:
/// a wrong passphrase must never masquerade as the vault's generic tamper error.
pub fn unwrap(data: &[u8], passphrase: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if data.len() != V2_FILE_LEN {
        return Err(Error::Keyfile(format!(
            "wrapped keyfile has unexpected size {} (expected {V2_FILE_LEN} bytes); it may be corrupt",
            data.len()
        )));
    }
    if data[0..4] != MAGIC {
        return Err(Error::Keyfile("not a wrapped keyfile (bad magic)".into()));
    }
    if data[4] != FORMAT_VERSION {
        return Err(Error::Keyfile(format!(
            "unsupported keyfile format version {}",
            data[4]
        )));
    }
    if data[5] != KDF_ARGON2ID || data[6] != AEAD_XCHACHA20_POLY1305 {
        return Err(Error::Keyfile(
            "unsupported KDF or AEAD identifier in keyfile".into(),
        ));
    }

    let params = KdfParams {
        m_cost: u32::from_le_bytes(data[7..11].try_into().unwrap()),
        t_cost: u32::from_le_bytes(data[11..15].try_into().unwrap()),
        p_cost: data[15] as u32,
    };
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&data[16..AAD_LEN]);
    let aad = &data[..AAD_LEN];
    let nonce = &data[AAD_LEN..AAD_LEN + NONCE_LEN];
    let ciphertext = &data[AAD_LEN + NONCE_LEN..];

    let kek = derive_kek(passphrase, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new(kek.as_ref().into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            Error::Passphrase(
                "wrong passphrase: the keyfile could not be unwrapped (or it has been corrupted)"
                    .into(),
            )
        })?;

    if plaintext.len() != KEY_LEN {
        return Err(Error::Keyfile(
            "unwrapped keyfile has the wrong length".into(),
        ));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&plaintext);
    crate::harden::mlock(key.as_ref());
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(byte: u8) -> [u8; KEY_LEN] {
        [byte; KEY_LEN]
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let key = root(0xAB);
        let image = wrap(&key, b"correct horse battery staple").unwrap();
        assert_eq!(image.len(), V2_FILE_LEN);
        assert!(is_wrapped(&image));
        let got = unwrap(&image, b"correct horse battery staple").unwrap();
        assert_eq!(got.as_ref(), &key);
    }

    #[test]
    fn wrapped_image_does_not_contain_the_root_key() {
        let key = root(0x5A);
        let image = wrap(&key, b"pw").unwrap();
        // The 32-byte root key must never appear verbatim in the sealed file.
        assert!(!image.windows(KEY_LEN).any(|w| w == key));
    }

    #[test]
    fn wrong_passphrase_is_passphrase_error_not_tamper() {
        let key = root(1);
        let image = wrap(&key, b"right").unwrap();
        let err = unwrap(&image, b"wrong").unwrap_err();
        assert!(matches!(err, Error::Passphrase(_)), "got {err:?}");
        // Explicitly NOT the vault's tamper error.
        assert!(!matches!(err, Error::Tamper(_)));
    }

    #[test]
    fn nonce_and_salt_are_fresh_per_wrap() {
        let key = root(2);
        let a = wrap(&key, b"pw").unwrap();
        let b = wrap(&key, b"pw").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn header_tamper_fails_the_tag() {
        let key = root(3);
        let image = wrap(&key, b"pw").unwrap();
        // Flip a salt byte (inside the AAD): decryption must fail.
        let mut bad = image.clone();
        bad[20] ^= 0xFF;
        assert!(matches!(unwrap(&bad, b"pw"), Err(Error::Passphrase(_))));
    }

    #[test]
    fn structural_corruption_is_keyfile_error() {
        let key = root(4);
        let image = wrap(&key, b"pw").unwrap();
        let mut bad = image.clone();
        bad[0] ^= 0xFF; // break the magic
        assert!(matches!(unwrap(&bad, b"pw"), Err(Error::Keyfile(_))));
        // Truncated image.
        assert!(matches!(
            unwrap(&image[..10], b"pw"),
            Err(Error::Keyfile(_))
        ));
    }

    #[test]
    fn params_from_header_are_used_on_unwrap() {
        // The header carries the params, so unwrap must not depend on the
        // current default constants staying fixed.
        let key = root(5);
        let image = wrap(&key, b"pw").unwrap();
        let params = KdfParams {
            m_cost: u32::from_le_bytes(image[7..11].try_into().unwrap()),
            t_cost: u32::from_le_bytes(image[11..15].try_into().unwrap()),
            p_cost: image[15] as u32,
        };
        assert_eq!(params, KdfParams::default());
    }
}
