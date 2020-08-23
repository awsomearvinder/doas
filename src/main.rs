//!This program is a clone of doas.
//!It takes the user input, parses the config to see if they're allowed to run
//!whatever they're doing, and then does it accordingly.
//!The parser module contains the Parser & Lexer for the config,
//!doas contains the logic for the main program
//!persistent_logins will manage the state for the program in /var/lib/doas/persistent_logins
use structopt::StructOpt;

pub mod doas;
pub mod parser;

use once_cell::sync::OnceCell;
pub static SHOULD_LOG: OnceCell<bool> = OnceCell::new();

#[derive(Debug, StructOpt)]
pub struct Options {
    ///Use config file at this path, then exit.
    ///If command is supplied, doas will also perform command matching.
    ///In the latter case either 'permit', 'permit nopass', or 'deny' will be printed on standard
    ///output, depending on the command matching results. No command is executed.
    #[structopt(short = "C", long = "config-file")]
    config_file: Option<std::path::PathBuf>,

    ///Clear any persisted authorizations from previous invocations, then exit.
    ///No command is executed.
    #[structopt(short = "L", long = "clear-persisted-auth")]
    clear_persisted_auth: bool,

    ///Non interactive mode, fail if doas would prompt for password.
    #[structopt(short = "n", long = "non-interactive-mode")]
    non_interactive_mode: bool,

    ///Execute the shell from $shell or /etc/passwd
    #[structopt(parse(from_os_str), short = "s", long = "shell")]
    shell: Option<std::path::PathBuf>,

    ///Execute the command as supplied user. The default is root.
    #[structopt(short = "u", long = "user", default_value = "root")]
    user: String,

    ///The command to run under doas.
    #[structopt(
        min_values = 1,
        required_unless_one = &["shell","clear-persisted-auth", "config-file"],
    )]
    command: Vec<String>,
}

fn main() {
    let opts = Options::from_args();

    //If you pass the -L flag, clear the persistent logins and move on with your life.
    if opts.clear_persisted_auth {
        std::fs::remove_file("/var/lib/doas/persistent_logins")
            .expect("Couldn't delete the persistent logins file.");
        std::process::exit(0);
    }

    //We should only log if we *aren't* in non-interactive mode.
    //Note: this is read by the log! macro and logs accordingly.
    SHOULD_LOG.set(!opts.non_interactive_mode).unwrap();

    doas::exec_doas(&opts, &opts.command)
}
