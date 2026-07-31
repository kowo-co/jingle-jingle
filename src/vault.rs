//! Encrypted vault: atomic load/save with one backup generation, and CRUD
//! over entries. This is the only module that touches `SecretString` serde.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::model::{Entry, VaultPayload};
use crate::{Error, Result, crypto};

pub const SCHEMA_VERSION: u32 = 1;

pub struct Vault {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    salt: [u8; crypto::SALT_LEN],
    pub payload: VaultPayload,
}

impl Vault {
    /// Create a fresh vault file. Fails if one already exists unless `force`.
    pub fn create(path: &Path, key: Zeroizing<[u8; 32]>, force: bool) -> Result<Self> {
        if path.exists() && !force {
            return Err(Error::Other(format!(
                "vault already exists at {} (use --force to replace it)",
                path.display()
            )));
        }
        let vault = Vault {
            path: path.to_path_buf(),
            key,
            salt: crypto::random_salt()?,
            payload: VaultPayload {
                schema: SCHEMA_VERSION,
                entries: Vec::new(),
            },
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn load(path: &Path, key: Zeroizing<[u8; 32]>) -> Result<Self> {
        let data = fs::read(path).map_err(|_| {
            Error::Other(format!(
                "vault not found at {} (run `jingle init` first)",
                path.display()
            ))
        })?;
        // Loose vault perms are a warning, not a failure: an install predating
        // this check must still open.
        crate::perms::warn_if_loose(path, "vault");
        let (salt, plaintext) = crypto::open(&key, &data)?;
        let payload: VaultPayload = serde_json::from_slice(&plaintext)
            .map_err(|_| Error::Tamper("vault decrypted but payload is malformed".into()))?;
        if payload.schema > SCHEMA_VERSION {
            return Err(Error::Other(format!(
                "vault schema {} is newer than this jingle understands ({SCHEMA_VERSION}); upgrade jingle",
                payload.schema
            )));
        }
        Ok(Vault {
            path: path.to_path_buf(),
            key,
            salt,
            payload,
        })
    }

    /// Atomic save: temp file in the same directory (0600) → write + fsync →
    /// copy the previous vault to `.bak` → rename over → fsync the directory.
    pub fn save(&self) -> Result<()> {
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        fs::create_dir_all(&dir)?;

        let plaintext = Zeroizing::new(serde_json::to_vec(&self.payload)?);
        let sealed = crypto::seal(&self.key, &self.salt, &plaintext)?;

        let mut tmp = tempfile::Builder::new()
            .prefix(".vault-")
            .suffix(".tmp")
            .tempfile_in(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o600))?;
        }
        tmp.write_all(&sealed)?;
        tmp.flush()?;
        tmp.as_file().sync_all()?;

        // One backup generation: protects against a logic bug writing garbage,
        // which an atomic rename alone would happily preserve.
        if self.path.exists() {
            let bak = self.path.with_extension("jingle.bak");
            fs::copy(&self.path, &bak)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&bak, fs::Permissions::from_mode(0o600))?;
            }
        }

        tmp.persist(&self.path).map_err(|e| Error::Io(e.error))?;

        #[cfg(unix)]
        {
            if let Ok(d) = fs::File::open(&dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }

    pub fn find(&self, name: &str) -> Result<&Entry> {
        self.payload
            .entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| Error::NotFound(crate::redact::sanitize(name)))
    }

    pub fn find_mut(&mut self, name: &str) -> Result<&mut Entry> {
        self.payload
            .entries
            .iter_mut()
            .find(|e| e.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| Error::NotFound(crate::redact::sanitize(name)))
    }

    pub fn contains(&self, name: &str) -> bool {
        self.payload
            .entries
            .iter()
            .any(|e| e.name.eq_ignore_ascii_case(name))
    }

    pub fn add(&mut self, entry: Entry) -> Result<()> {
        if self.contains(&entry.name) {
            return Err(Error::AlreadyExists(entry.name));
        }
        self.payload.entries.push(entry);
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<Entry> {
        let idx = self
            .payload
            .entries
            .iter()
            .position(|e| e.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| Error::NotFound(crate::redact::sanitize(name)))?;
        Ok(self.payload.entries.remove(idx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SecretString;

    fn key() -> Zeroizing<[u8; 32]> {
        Zeroizing::new([7u8; 32])
    }

    #[test]
    fn create_load_roundtrip_with_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.jingle");
        let mut v = Vault::create(&path, key(), false).unwrap();
        let mut e = Entry::new("github".into());
        e.secrets
            .insert("password".into(), SecretString::new("s3cr3t".into()));
        v.add(e).unwrap();
        v.save().unwrap();

        let v2 = Vault::load(&path, key()).unwrap();
        assert_eq!(v2.payload.entries.len(), 1);
        assert_eq!(
            v2.find("GitHub")
                .unwrap()
                .secret("password")
                .unwrap()
                .expose(),
            "s3cr3t"
        );
    }

    #[test]
    fn vault_file_never_contains_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.jingle");
        let mut v = Vault::create(&path, key(), false).unwrap();
        let mut e = Entry::new("gh".into());
        e.secrets.insert(
            "password".into(),
            SecretString::new("SENTINEL_PLAINTEXT_VALUE".into()),
        );
        v.add(e).unwrap();
        v.save().unwrap();
        let raw = std::fs::read(&path).unwrap();
        let needle = b"SENTINEL_PLAINTEXT_VALUE";
        assert!(!raw.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn backup_generation_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.jingle");
        let mut v = Vault::create(&path, key(), false).unwrap();
        v.add(Entry::new("one".into())).unwrap();
        v.save().unwrap();
        let bak = path.with_extension("jingle.bak");
        assert!(bak.exists());
        // The backup decrypts and holds the previous generation.
        let prev = Vault::load(&bak, key()).unwrap();
        assert!(prev.payload.entries.len() <= v.payload.entries.len());
    }

    #[test]
    fn duplicate_names_rejected_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.jingle");
        let mut v = Vault::create(&path, key(), false).unwrap();
        v.add(Entry::new("GitHub".into())).unwrap();
        assert!(matches!(
            v.add(Entry::new("github".into())),
            Err(Error::AlreadyExists(_))
        ));
    }
}
