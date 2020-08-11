use crate::user::{Password, User};
use crate::Options;
use std::env;

///Executes a doas command.
pub fn exec_command(options: &Options, command: &[String]) {
    //TODO: do something with user
    let current_user = env::var("USER").unwrap();
    let current_user = User::from_name(current_user).unwrap(); //somehow handle these eventually?
    let target_user = User::from_name(options.user.clone()).unwrap(); //somehow handle these eventually?
    set_env_vars(&current_user, &target_user, command, &options.shell);
    let user_input = rpassword::read_password_from_tty(Some("Password: ")).unwrap();
    if check_pass(&user_input, &current_user.get_password()) != Ok(()) {
        eprintln!("doas: Authentication failure");
        return;
    }
    let mut command = command.iter();
    let command_name = command.next().unwrap();
    let mut cmd = std::process::Command::new(command_name);
    for argument in command {
        cmd.arg(argument);
    }
    match cmd.spawn() {
        Ok(mut child) => child.wait().unwrap(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("doas: Couldn't find such command \"{}\", does it exist? \n If the programmer who made me is an idiot, consider opening a bug report on github." , command_name);
            std::process::exit(1);
        }
        Err(e) => panic!("got unexpected error {}", e),
    };
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
) {
    let term = env::var("TERM").unwrap();
    let lang = env::var("LANG").unwrap();
    let color_term = env::var("COLORTERM").unwrap();
    let display = env::var("DISPLAY").unwrap();
    clear_env_vars();
    env::set_var("LANG", lang);
    env::set_var("DISPLAY", display);
    env::set_var("COLORTERM", color_term);
    env::set_var("TERM", term);
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
}

