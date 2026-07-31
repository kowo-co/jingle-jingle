//! Command implementations and the dispatcher.

pub mod audit_cmd;
pub mod crud;
pub mod doctor;
pub mod egress;
pub mod init;
pub mod transfer;

use std::io::{BufRead, IsTerminal, Read, Write};

use zeroize::Zeroizing;

use crate::audit::AuditLog;
use crate::cli::{Cli, Cmd, SecretSource};
use crate::model::SecretString;
use crate::paths::Paths;
use crate::vault::Vault;
use crate::{Error, Result, genpass, keyfile};

pub const MAX_STDIN_SECRET: usize = 4096;

pub struct Ctx {
    pub json: bool,
    pub quiet: bool,
    pub paths: Paths,
    /// Command label used in audit records.
    pub cmd_label: &'static str,
}

impl Ctx {
    pub fn audit(&self) -> AuditLog {
        AuditLog::new(&self.paths.audit)
    }

    pub fn load_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        keyfile::load(&self.paths.keyfile)
    }

    /// Load the vault; integrity failures are recorded in the audit log
    /// before being reported.
    pub fn load_vault(&self) -> Result<Vault> {
        let key = self.load_key()?;
        match Vault::load(&self.paths.vault, key) {
            Ok(v) => Ok(v),
            Err(e @ Error::Tamper(_)) => {
                let _ = self
                    .audit()
                    .append(self.cmd_label, None, None, "tamper", None);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }
}

fn cmd_label(cmd: &Cmd) -> &'static str {
    match cmd {
        Cmd::Init { .. } => "init",
        Cmd::Add { .. } => "add",
        Cmd::Set { .. } => "set",
        Cmd::Unset { .. } => "unset",
        Cmd::Generate { .. } => "generate",
        Cmd::List { .. } => "list",
        Cmd::Show { .. } => "show",
        Cmd::Exec { .. } => "exec",
        Cmd::Copy { .. } => "copy",
        Cmd::Totp { .. } => "totp",
        Cmd::Rm { .. } => "rm",
        Cmd::Edit { .. } => "edit",
        Cmd::Lock { .. } => "lock",
        Cmd::Unlock { .. } => "unlock",
        Cmd::Export { .. } => "export",
        Cmd::Import { .. } => "import",
        Cmd::Audit { .. } => "audit",
        Cmd::Doctor => "doctor",
        Cmd::ClearClipboard { .. } => "__clear-clipboard",
    }
}

/// Dispatch a parsed CLI invocation. Returns the process exit code.
pub fn run(cli: Cli) -> Result<i32> {
    let paths = crate::paths::resolve(cli.vault, cli.keyfile)?;
    let ctx = Ctx {
        json: cli.json,
        quiet: cli.quiet,
        paths,
        cmd_label: cmd_label(&cli.cmd),
    };

    match cli.cmd {
        Cmd::Init { force } => init::run(&ctx, force),
        Cmd::Add {
            name,
            service,
            username,
            url,
            notes,
            tags,
            field,
            source,
        } => crud::add(
            &ctx, name, service, username, url, notes, tags, field, &source,
        ),
        Cmd::Set {
            name,
            field,
            source,
        } => crud::set(&ctx, &name, &field, &source),
        Cmd::Unset { name, field, yes } => crud::unset(&ctx, &name, &field, yes),
        Cmd::Generate {
            entry,
            field,
            print,
            length,
            charset,
        } => crud::generate(
            &ctx,
            entry.as_deref(),
            &field,
            print,
            length,
            charset.into(),
        ),
        Cmd::List { tag, service } => crud::list(&ctx, tag.as_deref(), service.as_deref()),
        Cmd::Show { name } => crud::show(&ctx, &name),
        Cmd::Exec {
            secrets,
            confirm_locked,
            no_inherit_env,
            allow_overwrite,
            no_leak_guard,
            command,
        } => {
            return egress::exec(
                &ctx,
                &secrets,
                &confirm_locked,
                no_inherit_env,
                allow_overwrite,
                no_leak_guard,
                &command,
            );
        }
        Cmd::Copy {
            name,
            field,
            clear_after,
            confirm_locked,
        } => egress::copy(&ctx, &name, &field, clear_after, &confirm_locked),
        Cmd::Totp {
            name,
            confirm_locked,
        } => egress::totp(&ctx, &name, &confirm_locked),
        Cmd::Rm { name, yes } => crud::rm(&ctx, &name, yes),
        Cmd::Edit {
            name,
            service,
            username,
            url,
            notes,
            tags,
            rename,
        } => crud::edit(&ctx, &name, service, username, url, notes, tags, rename),
        Cmd::Lock { name } => crud::set_locked(&ctx, &name, true, true),
        Cmd::Unlock { name, yes } => crud::set_locked(&ctx, &name, false, yes),
        Cmd::Export { output } => transfer::export(&ctx, &output),
        Cmd::Import { file, overwrite } => transfer::import(&ctx, &file, overwrite),
        Cmd::Audit { limit } => audit_cmd::run(&ctx, limit),
        Cmd::Doctor => doctor::run(&ctx),
        Cmd::ClearClipboard { after } => egress::clear_clipboard(after),
    }?;
    Ok(0)
}

/// Obtain the secret value from the chosen source. Returns the value and, if
/// generated, its entropy in bits (safe to print).
pub fn obtain_secret(source: &SecretSource) -> Result<(SecretString, Option<f64>)> {
    if !source.generate && (source.length.is_some() || source.charset.is_some()) {
        return Err(Error::Usage(
            "--length/--charset only apply with --generate".into(),
        ));
    }
    if source.generate {
        let charset: genpass::Charset = source
            .charset
            .unwrap_or(crate::cli::CharsetArg::Full)
            .into();
        let length = source.length.unwrap_or(24);
        let value = genpass::generate(length, charset)?;
        let bits = genpass::entropy_bits(length, charset);
        Ok((value, Some(bits)))
    } else {
        Ok((read_secret_stdin()?, None))
    }
}

/// Read a secret from stdin: bounded, UTF-8, one trailing newline trimmed.
/// Reading from stdin (rather than argv) keeps secrets out of process lists,
/// shell history, and agent transcripts.
pub fn read_secret_stdin() -> Result<SecretString> {
    let mut stdin = std::io::stdin().lock();
    if stdin.is_terminal() {
        eprintln!("(reading secret from stdin; end with Ctrl-D)");
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(256));
    let mut chunk = [0u8; 512];
    loop {
        let n = stdin.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if buf.len() + n > MAX_STDIN_SECRET + 2 {
            return Err(Error::Usage(format!(
                "stdin secret exceeds {MAX_STDIN_SECRET} bytes"
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    chunk.iter_mut().for_each(|b| *b = 0);

    let mut text = String::from_utf8(buf.to_vec())
        .map_err(|_| Error::Usage("stdin secret is not valid UTF-8".into()))?;
    // Trim exactly one trailing newline (what `echo`/heredocs append).
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    if text.is_empty() {
        return Err(Error::Usage("stdin secret is empty".into()));
    }
    if text.len() > MAX_STDIN_SECRET {
        return Err(Error::Usage(format!(
            "stdin secret exceeds {MAX_STDIN_SECRET} bytes"
        )));
    }
    Ok(SecretString::new(text))
}

/// Interactive confirmation. In non-interactive use (agents), `--yes` is
/// required — silently proceeding on a destructive action would be worse.
pub fn confirm(prompt: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Err(Error::Usage(
            "confirmation required: re-run with --yes (stdin is not a terminal)".into(),
        ));
    }
    eprint!("{prompt} [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    if answer == "y" || answer == "yes" {
        Ok(())
    } else {
        Err(Error::Usage("aborted".into()))
    }
}
