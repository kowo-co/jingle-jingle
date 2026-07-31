//! Encrypted export (backup) and import (merge). There is deliberately no
//! plaintext export: a "dump everything" command is exactly what a prompt-
//! injected agent would be steered toward.

use std::fs;
use std::io::Write;
use std::path::Path;

use serde_json::json;

use crate::commands::Ctx;
use crate::{Error, Result, crypto, output};

pub fn export(ctx: &Ctx, output_path: &Path) -> Result<()> {
    // Verify the vault decrypts with the current keyfile before copying, so
    // an export is never a blind copy of a corrupt file.
    let key = ctx.load_key()?;
    let data = fs::read(&ctx.paths.vault).map_err(|_| {
        Error::Other(format!(
            "vault not found at {} (run `jingle init` first)",
            ctx.paths.vault.display()
        ))
    })?;
    crypto::open(&key, &data)?;

    if let Some(parent) = output_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    // Create at 0600 up front (not write-then-chmod) so the backup is never
    // momentarily world-readable, whatever the ambient umask.
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut out = opts.open(output_path)?;
    out.write_all(&data)?;
    out.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // In case the file pre-existed with looser permissions.
        fs::set_permissions(output_path, fs::Permissions::from_mode(0o600))?;
    }
    ctx.audit().append("export", None, None, "ok", None)?;

    output::ok(
        ctx.json,
        ctx.quiet,
        &format!(
            "Exported encrypted vault to {} (opens only with the current keyfile)",
            output_path.display()
        ),
        json!({ "output": output_path.display().to_string() }),
    );
    Ok(())
}

pub fn import(ctx: &Ctx, file: &Path, overwrite: bool) -> Result<()> {
    let key = ctx.load_key()?;
    let incoming = crate::vault::Vault::load(file, key)?;

    let mut vault = ctx.load_vault()?;
    let mut added = 0usize;
    let mut replaced = 0usize;
    let mut skipped = 0usize;
    for entry in incoming.payload.entries {
        if vault.contains(&entry.name) {
            if overwrite {
                vault.remove(&entry.name)?;
                vault.add(entry)?;
                replaced += 1;
            } else {
                skipped += 1;
            }
        } else {
            vault.add(entry)?;
            added += 1;
        }
    }
    vault.save()?;
    ctx.audit().append("import", None, None, "ok", None)?;

    output::ok(
        ctx.json,
        ctx.quiet,
        &format!(
            "Imported from {}: {added} added, {replaced} replaced, {skipped} skipped{}",
            file.display(),
            if skipped > 0 && !overwrite {
                " (pass --overwrite to replace colliding entries)"
            } else {
                ""
            }
        ),
        json!({ "added": added, "replaced": replaced, "skipped": skipped }),
    );
    Ok(())
}
