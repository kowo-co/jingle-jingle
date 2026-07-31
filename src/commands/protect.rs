//! `jingle protect` / `jingle unprotect` — migrate the keyfile between the raw
//! v1 format and the passphrase-wrapped v2 format.
//!
//! Both directions are **verify-first and non-destructive**: the live keyfile
//! is replaced only by a final atomic rename, and only after the new keyfile
//! has been read back, unwrapped/loaded, and proven to open the *real* vault.
//! Any failure before that rename aborts with the original keyfile untouched —
//! this is the one operation that could otherwise destroy every credential the
//! user owns, so nothing is deleted until the replacement is known good.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::json;
use zeroize::Zeroizing;

use crate::commands::Ctx;
use crate::keyfile::{self, Format, KEY_LEN};
use crate::vault::Vault;
use crate::{Error, Result, keywrap, output, passphrase};

/// v1 → v2: wrap the root key under a passphrase.
pub fn protect(ctx: &Ctx) -> Result<()> {
    let kf = &ctx.paths.keyfile;
    match keyfile::detect(kf)? {
        Format::V2Wrapped => {
            return Err(Error::Usage(
                "keyfile is already protected (v2); use `jingle unprotect` to revert it to a raw key"
                    .into(),
            ));
        }
        Format::V1Raw => {}
    }

    // Load the current root key. This also runs the permission checks and
    // confirms the v1 keyfile is well-formed before we touch anything.
    let root_key = keyfile::load(kf)?;

    // A NEW passphrase: prompted twice on a TTY, or taken from
    // $JINGLE_PASSPHRASE_CMD's stdout. Never argv, never a plain env var.
    let pass = passphrase::acquire(true)?;

    // 1. Back up the live v1 keyfile (0600). Non-destructive: this only adds a
    //    file; the original stays in place.
    let bak = sibling(kf, ".v1.bak");
    backup_file(kf, &bak)?;

    // 2. Seal the root key and stage the v2 image in a temp file in the same
    //    directory. It is NOT yet the live keyfile.
    let image = keywrap::wrap(&root_key, &pass)?;
    let tmp = stage(kf, &image)?;

    // 3. Verify the staged file before it goes live: read it back, unwrap it,
    //    check it yields the same root key, and prove it opens the real vault.
    //    On any failure the temp is dropped (auto-removed) and the original v1
    //    keyfile is left exactly as it was.
    let staged = Zeroizing::new(fs::read(tmp.path())?);
    let unwrapped = keywrap::unwrap(&staged, &pass)?;
    if unwrapped.as_ref() != root_key.as_ref() {
        return Err(Error::Other(
            "internal error: wrapped keyfile did not round-trip; aborting, original keyfile untouched"
                .into(),
        ));
    }
    open_vault(ctx, &unwrapped)?;

    // 4. Only now replace the live keyfile, atomically.
    commit(tmp, kf)?;
    ctx.audit().append("protect", None, None, "ok", None)?;

    output::ok(
        ctx.json,
        ctx.quiet,
        &format!(
            "Keyfile protected (v1 → v2).\n  keyfile: {} (now passphrase-wrapped)\n  backup:  {} (the old raw key — delete it once you've confirmed the new keyfile works)\nA passphrase is now required to open the vault.",
            kf.display(),
            bak.display()
        ),
        json!({
            "keyfile": kf.display().to_string(),
            "format": "v2",
            "backup": bak.display().to_string(),
        }),
    );
    Ok(())
}

/// v2 → v1: unwrap the root key back to a raw keyfile.
pub fn unprotect(ctx: &Ctx) -> Result<()> {
    let kf = &ctx.paths.keyfile;
    match keyfile::detect(kf)? {
        Format::V1Raw => {
            return Err(Error::Usage(
                "keyfile is not protected (it is already a raw v1 key); nothing to unprotect"
                    .into(),
            ));
        }
        Format::V2Wrapped => {}
    }

    // Unwrap the current keyfile. A wrong passphrase surfaces its own error
    // here (never the vault's tamper error) and aborts before anything changes.
    let current = Zeroizing::new(fs::read(kf)?);
    let pass = passphrase::acquire(false)?;
    let root_key = keywrap::unwrap(&current, &pass)?;

    // Prove the recovered key actually opens the real vault before we commit to
    // writing it out in the clear.
    open_vault(ctx, &root_key)?;

    // 1. Back up the live v2 keyfile (0600) — same non-destructive discipline.
    let bak = sibling(kf, ".v2.bak");
    backup_file(kf, &bak)?;

    // 2. Stage the raw key in a temp file.
    let tmp = stage(kf, root_key.as_ref())?;

    // 3. Verify: read the staged raw key back, confirm it matches and opens the
    //    vault, before it goes live.
    let staged = Zeroizing::new(fs::read(tmp.path())?);
    if staged.len() != KEY_LEN || staged.as_slice() != root_key.as_ref() {
        return Err(Error::Other(
            "internal error: unwrapped keyfile did not round-trip; aborting, original keyfile untouched"
                .into(),
        ));
    }
    let mut check = Zeroizing::new([0u8; KEY_LEN]);
    check.copy_from_slice(&staged);
    open_vault(ctx, &check)?;

    // 4. Replace atomically.
    commit(tmp, kf)?;
    ctx.audit().append("unprotect", None, None, "ok", None)?;

    output::ok(
        ctx.json,
        ctx.quiet,
        &format!(
            "Keyfile unprotected (v2 → v1).\n  keyfile: {} (now a raw key — disk access alone opens the vault again)\n  backup:  {} (the old wrapped key)",
            kf.display(),
            bak.display()
        ),
        json!({
            "keyfile": kf.display().to_string(),
            "format": "v1",
            "backup": bak.display().to_string(),
        }),
    );
    Ok(())
}

/// Append `suffix` to the full path (so `.../key` → `.../key.v1.bak`).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Copy `src` to `dst` at 0600 and fsync it. Fails (aborting the migration)
/// if the backup cannot be written — we will not proceed without one.
fn backup_file(src: &Path, dst: &Path) -> Result<()> {
    fs::copy(src, dst)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dst, fs::Permissions::from_mode(0o600))?;
    }
    if let Ok(f) = fs::File::open(dst) {
        let _ = f.sync_all();
    }
    Ok(())
}

/// Write `bytes` into a fresh 0600 temp file in the keyfile's directory and
/// fsync it. The returned handle removes the file automatically if dropped
/// without [`commit`] — that is what makes every failure path clean up.
fn stage(keyfile: &Path, bytes: &[u8]) -> Result<tempfile::NamedTempFile> {
    let dir = keyfile
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&dir)?;

    let mut tmp = tempfile::Builder::new()
        .prefix(".key-")
        .suffix(".tmp")
        .tempfile_in(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(bytes)?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    Ok(tmp)
}

/// Atomically move the staged temp over the live keyfile and fsync the dir.
fn commit(tmp: tempfile::NamedTempFile, keyfile: &Path) -> Result<()> {
    tmp.persist(keyfile).map_err(|e| Error::Io(e.error))?;
    #[cfg(unix)]
    {
        if let Some(dir) = keyfile.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Ok(d) = fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
    }
    Ok(())
}

/// Prove `key` opens the real vault. Verification only: the loaded vault is
/// dropped immediately.
fn open_vault(ctx: &Ctx, key: &Zeroizing<[u8; KEY_LEN]>) -> Result<()> {
    let copy = Zeroizing::new(**key);
    match Vault::load(&ctx.paths.vault, copy) {
        Ok(_) => Ok(()),
        Err(Error::Tamper(_)) => Err(Error::Tamper(
            "the key does not open the vault (or the vault is corrupt); aborting, keyfile untouched"
                .into(),
        )),
        Err(e) => Err(e),
    }
}
