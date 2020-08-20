use crate::parser::rules::Rule;
use crate::user::{Password, User};
use crate::Options;
use nix::unistd;

use std::collections::HashMap;
use std::env;
use std::os::unix::process::ExitStatusExt;

use crate::parser;

///Execute doas.
pub fn exec_doas(options: &Options, command: &[String]) {
    //TODO: do something with user
    let current_user = env::var("USER").unwrap();
    let current_user = User::from_name(current_user).unwrap(); //somehow handle these eventually?
    let target_user = User::from_name(options.user.clone()).unwrap_or_else(|_| {
        eprintln!("Couldn't find target user");
        std::process::exit(1);
    }); //somehow handle these eventually?
    let conf_contents = std::fs::read_to_string(&options.config_file).unwrap_or_else(|e| {
        eprintln!(
            "couldn't read config file {:?}, exiting. Error: {}",
            options.config_file, e
        );
        std::process::exit(1);
    });
    let mut cmd = command.iter();
    let cmd_name = cmd.next().unwrap_or_else(|| {
        eprintln!("Did you give a valid command?");
        std::process::exit(1);
    });
    let cmd_args: Vec<_> = cmd.map(|s| s.as_str()).collect();
    eprintln!("checking if allowed");
    if let (is_allowed, Some(rule)) = check_if_allowed_and_get_rule(
        &current_user,
        &cmd_name,
        &cmd_args,
        target_user.get_name(),
        &conf_contents,
    ) {
        if is_allowed {
            //If the config file is not at default path, -C must of been passed.
            //If that's true, we don't want to actually run the app. Only say if the
            //given config allows for the command.
            if options.config_file.as_os_str().to_str() != Some("/etc/doas.conf") {
                println!("Permitted due to config rule.");
                return;
            }

            //Check for password before execution.
            let user_input = rpassword::read_password_from_tty(Some(&format!(
                "[doas] password for {}: ",
                current_user.get_name()
            )))
            .unwrap();
            if check_pass(&user_input, &current_user.get_password()) != Ok(()) {
                eprintln!("doas: Authentication failure");
                return;
            }
            set_env_vars(
                &current_user,
                &target_user,
                command,
                &options.shell,
                rule.get_set_env(),
            );

            exec_command(cmd_name, &cmd_args, &target_user)
        } else {
            eprintln!("Denied due to config rule.");
        }
    }
}

fn exec_command(command_name: &str, args: &[&str], target_user: &User) {
    let mode = nix::sys::stat::Mode::from_bits(0o0022).unwrap(); //default umask for root.
    nix::sys::stat::umask(mode);
    unistd::setuid(target_user.get_uid()).unwrap_or_else(|_| panic!("Couldn't set UID"));
    match std::process::Command::new(command_name).args(args).spawn() {
        Ok(mut child) => {
            let exitcode = child.wait().unwrap();
            if let Some(code) = exitcode.code() {
                std::process::exit(code);
            }
            if exitcode.signal().is_some() {
                std::process::exit(0);
            }
        }
        Err(error) => eprintln!(
            "doas: got some error: {}\n while running {}",
            error, command_name
        ),
    }
    std::process::exit(1);
}

///Checks if the command is allowed, and returns a bool and Option<Rule>.
///If no matches were found in the config, it'll return (false, None)
fn check_if_allowed_and_get_rule(
    user: &User,
    cmd: &str,
    cmd_args: &[&str],
    target: &str,
    config_contents: &str,
) -> (bool, Option<Rule>) {
    let (mut is_last_match_allowed, mut last_active_rule) = (false, None);
    for (i, rule) in parser::parse_rules(config_contents).into_iter().enumerate() {
        eprintln!("{:?}", rule);
        let rule = match rule {
            Ok(rule) => rule,
            Err(e) => {
                eprintln!(
                    "Warning:\n Got error in config\n {}\n while working on rule: {}",
                    e, i
                );
                continue;
            }
        };
        if let Some(is_allowed) = rule.is_allowed(user.get_name(), cmd, cmd_args, target) {
            is_last_match_allowed = is_allowed;
            last_active_rule = Some(rule);
        }
    }
    dbg!((is_last_match_allowed, last_active_rule))
}

///Check if user input password and hashed password are same.
fn check_pass(unhashed: &str, maybe_hashed_pass: &Password) -> Result<(), ()> {
    let hashed_pass = match maybe_hashed_pass {
        Password::Unhashed(val) if val == unhashed => return Ok(()),
        Password::Hashed(val) => val,
        _ => return Err(()),
    };

    //Get the different values out of password field.
    let mut maybe_hashed_pass_parts = hashed_pass.split('$').skip(1);
    let pass_type = maybe_hashed_pass_parts
        .next()
        .expect("misconfigured /etc/shadow");
    let salt = maybe_hashed_pass_parts
        .next()
        .expect("misconfigured /etc/shadow");
    let hash = maybe_hashed_pass_parts
        .next()
        .expect("misconfigured /etc/shadow");

    let are_same = match pass_type {
        "6" => pwhash::sha512_crypt::verify(
            &unhashed,
            format!("${}${}${}", pass_type, salt, hash).as_str(),
        ),
        "5" => pwhash::sha256_crypt::verify(
            &unhashed,
            format!("${}${}${}", pass_type, salt, hash).as_str(),
        ),
        //These are both blowfish algos.
        "2y" | "2a" => pwhash::bcrypt::verify(
            &unhashed,
            format!("${}${}${}", pass_type, salt, hash).as_str(),
        ),
        "1" => pwhash::md5_crypt::verify(
            &unhashed,
            format!("${}${}${}", pass_type, salt, hash).as_str(),
        ),
        _ => unimplemented!(),
    };

    if are_same {
        Ok(())
    } else {
        Err(())
    }
}

fn clear_env_vars() {
    for var in env::vars() {
        env::remove_var(var.0);
    }
}

///Sets the env vars doas works with.
fn set_env_vars(
    current_user: &User,
    target_user: &User,
    command: &[String],
    shell: &Option<std::path::PathBuf>,
    set_env: Option<&HashMap<String, String>>,
) {
    let current_vars = [
        env::var("LANG"),
        env::var("COLORTERM"),
        env::var("DISPLAY"),
        env::var("TERM"),
    ];
    clear_env_vars();
    if let Ok(lang) = &current_vars[0] {
        env::set_var("LANG", lang);
    }
    if let Ok(color_term) = &current_vars[1] {
        env::set_var("COLORTERM", color_term);
    }
    if let Ok(display) = &current_vars[2] {
        env::set_var("DISPLAY", display);
    }
    if let Ok(term) = &current_vars[3] {
        env::set_var("TERM", term);
    }
    env::set_var("SUDO_USER", current_user.get_name());
    env::set_var("USERNAME", current_user.get_name());
    env::set_var("DOAS_USER", current_user.get_name()); //lol, why the heck not.
    env::set_var("SUDO_UID", current_user.get_uid().to_string());
    env::set_var("SUDO_GID", current_user.get_gid().to_string());
    env::set_var(
        "SUDO_COMMAND",
        &command
            .iter()
            .fold(String::new(), |acc, command| acc + command),
    );
    env::set_var(
        "HOME",
        &target_user
            .get_home()
            .to_owned()
            .into_os_string()
            .into_string()
            .unwrap(),
    );
    env::set_var("USER", target_user.get_name());
    env::set_var("LOGNAME", target_user.get_name());
    env::set_var(
        //lol this is hardcoded rn. Fite me.
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    let shell = if let Some(shell) = shell {
        shell
    } else {
        current_user.get_shell()
    };
    env::set_var("SHELL", shell);
    if let Some(map) = set_env {
        for (key, value) in map.iter() {
            env::set_var(key, value);
        }
    }
}
