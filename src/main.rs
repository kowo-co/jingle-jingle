use clap::Parser;

use jingle::cli::Cli;

fn main() {
    // Disable core dumps and same-uid ptrace before any key material can be
    // read. Must stay first: everything below may touch the keyfile.
    jingle::harden::harden_process();

    let cli = Cli::parse();
    let json_mode = cli.json;
    let code = match jingle::commands::run(cli) {
        Ok(code) => code,
        Err(err) => {
            jingle::output::error(json_mode, &err);
            err.exit_code()
        }
    };
    std::process::exit(code);
}
