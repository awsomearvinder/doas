use structopt::StructOpt;

pub mod doas;
pub mod parser;

#[derive(Debug, StructOpt)]
pub struct Options {
    ///Use config file at this path, then exit.
    ///If command is supplied, doas will also perform command matching.
    ///In the latter case either 'permit', 'permit nopass', or 'deny' will be printed on standard
    ///output, depending on the command matching results. No command is executed.
    #[structopt(short = "C", default_value = "/etc/doas.conf", long = "config-file")]
    config_file: std::path::PathBuf,

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
        required_unless_one = &["shell","L","C"],
    )]
    command: Vec<String>,
}

fn main() {
    let opts = Options::from_args();
    doas::exec_doas(&opts, &opts.command)
}
