use nix::unistd;
use std::path::Path;
use std::path::PathBuf;

///This struct represents a user in /etc/passwd, (may get password from /etc/shadow also)
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub struct User {
    name: String,
    password: Password,
    uid: unistd::Uid,
    gid: u32,
    uid_info: String,
    home: PathBuf,
    shell: PathBuf,
}

impl User {
    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_password(&self) -> &Password {
        &self.password
    }

    pub fn get_uid(&self) -> unistd::Uid {
        self.uid
    }

    pub fn get_gid(&self) -> u32 {
        self.gid
    }

    pub fn get_uid_info(&self) -> &str {
        &self.uid_info
    }

    pub fn get_home(&self) -> &Path {
        &self.home
    }

    pub fn get_shell(&self) -> &Path {
        &self.shell
    }

    ///This function returns a User from /etc/passwd
    ///If user pass isn't present, it'll find it in /etc/shadow or be given NoPass depending.
    pub fn from_name(name: String) -> Result<User, ()> {
        let passwd_file_contents = std::fs::read_to_string("/etc/passwd")
            .unwrap_or_else(|e| panic!("got error while trying to read /etc/passwd file: {}", e));
        for line in passwd_file_contents.split('\n') {
            if line.starts_with(&name) {
                //The format for a line in /etc/passwd is:
                //name:password:uid:gid:uid_information:path_to_home:default_shell
                let mut user_info = line.split(':');
                let name = user_info.next().ok_or(())?.to_owned();

                //If this password is "x", it means it's stored in /etc/shadow.
                let password = user_info.next().ok_or(())?;
                let password = match password {
                    "x" => Self::read_from_shadow(&name)?,
                    "*" | "!" | "**" | "!!" => Password::NoPass,
                    pass => Password::Unhashed(pass.into()),
                };

                //Some beautiful boilerplate below.
                let uid = user_info.next().ok_or(())?.parse::<u32>().map_err(|_| ())?;
                let gid = user_info.next().ok_or(())?.parse::<u32>().map_err(|_| ())?;
                let uid_info = user_info.next().ok_or(())?.into();
                let home = user_info.next().ok_or(())?.into();
                let shell = user_info.next().ok_or(())?.into();
                return Ok(User {
                    name,
                    password,
                    uid: unistd::Uid::from_raw(uid),
                    gid,
                    uid_info,
                    home,
                    shell,
                });
            }
        }
        Err(())
    }

    //TODO: Switch out this result from returning Err(()) to an actual sensical error.
    ///This will parse and read the /etc/shadow and return a Result accordingly.
    fn read_from_shadow(name: &str) -> Result<Password, ()> {
        let shadow_contents = std::fs::read_to_string("/etc/shadow")
            .unwrap_or_else(|_| panic!("couldn't read /etc/shadow"));

        for line in shadow_contents.split('\n') {
            let mut segments = line.split(':');
            if let Some(segment_name) = segments.next() {
                if segment_name != name {
                    continue;
                }
                let pass = segments
                    .next()
                    .expect("/etc/shadow misconfigured maybe? had trouble reading it.");
                if pass == "!!" || pass == "!" || pass == "*" || pass == "**" {
                    return Ok(Password::NoPass);
                }
                return Ok(Password::Hashed(pass.into()));
            }
        }

        Err(())
    }
}

///Password will be NoPass if user has no password
///Password will be Hashed if it's stored in /etc/shadow
///Password will be plain text if it's stored in /etc/passwd
#[derive(Debug, PartialEq, Eq)]
pub enum Password {
    NoPass,
    Hashed(String),
    Unhashed(String),
}
