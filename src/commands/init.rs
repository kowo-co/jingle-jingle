//! `jingle init` — create the keyfile and an empty vault.

use serde_json::json;

use crate::commands::Ctx;
use crate::vault::Vault;
use crate::{Result, keyfile, output};

pub fn run(ctx: &Ctx, force: bool) -> Result<()> {
    keyfile::create(&ctx.paths.keyfile, force)?;
    let key = keyfile::load(&ctx.paths.keyfile, None)?;
    Vault::create(&ctx.paths.vault, key, force)?;
    ctx.audit().append("init", None, None, "ok", None)?;

    output::ok(
        ctx.json,
        ctx.quiet,
        &format!(
            "Initialized jingle.\n  keyfile: {}\n  vault:   {}\n  audit:   {}\nKeep the keyfile safe: it is the only way to open this vault.",
            ctx.paths.keyfile.display(),
            ctx.paths.vault.display(),
            ctx.paths.audit.display()
        ),
        json!({
            "keyfile": ctx.paths.keyfile.display().to_string(),
            "vault": ctx.paths.vault.display().to_string(),
            "audit": ctx.paths.audit.display().to_string(),
        }),
    );
    Ok(())
}
