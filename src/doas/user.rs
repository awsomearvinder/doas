use nix::unistd;
use std::path::Path;
use std::path::PathBuf;

///This struct represents a linux user.
#[derive(Debug, PartialEq, Eq)]
pub struct User {
    name: String,
    password: Password,
    uid: unistd::Uid,
    primary_gid: u32, //TODO: primary_group
    groups: Vec<Group>,
    uid_info: String,
    home: PathBuf,
    shell: PathBuf,
}

///This struct is parsed only from /etc/passwd and /etc/shadow
#[derive(Debug, PartialEq, Eq)]
pub struct PartialUser {
    name: String,
    password: Password,
    uid: unistd::Uid,
    primary_gid: u32,
    uid_info: String,
    home: PathBuf,
    shell: PathBuf,
}

impl PartialUser {
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

    ///This function returns a User from /etc/passwd
    ///If user pass isn't present, it'll find it in /etc/shadow or be given NoPass depending.
    pub fn from_name(name: &str) -> Result<Self, ()> {
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
                let primary_gid = user_info.next().ok_or(())?.parse::<u32>().map_err(|_| ())?;
                let uid_info = user_info.next().ok_or(())?.into();
                let home = user_info.next().ok_or(())?.into();
                let shell = user_info.next().ok_or(())?.into();
                return Ok(Self {
                    name,
                    password,
                    uid: unistd::Uid::from_raw(uid),
                    primary_gid,
                    uid_info,
                    home,
                    shell,
                });
            }
        }
        Err(())
    }
    ///This function returns a User from /etc/passwd
    ///If user pass isn't present, it'll find it in /etc/shadow or be given NoPass depending.
    pub fn from_uid(target_uid: u32) -> Result<Self, ()> {
        let passwd_file_contents = std::fs::read_to_string("/etc/passwd")
            .unwrap_or_else(|e| panic!("got error while trying to read /etc/passwd file: {}", e));
        for line in passwd_file_contents.split('\n') {
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
            if target_uid != uid {
                continue;
            }
            let primary_gid = user_info.next().ok_or(())?.parse::<u32>().map_err(|_| ())?;
            let uid_info = user_info.next().ok_or(())?.into();
            let home = user_info.next().ok_or(())?.into();
            let shell = user_info.next().ok_or(())?.into();
            return Ok(Self {
                name,
                password,
                uid: unistd::Uid::from_raw(uid),
                primary_gid,
                uid_info,
                home,
                shell,
            });
        }
        Err(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Group {
    name: String,
    passwd: Password,
    gid: unistd::Gid,
}
impl Group {
    pub fn get_name(&self) -> &str {
        &self.name
    }
    //TODO: Switch out this result from returning Err(()) to an actual sensical error.
    ///This will parse and read the /etc/gshadow and return a Result accordingly.
    fn read_from_shadow(name: &str) -> Result<Password, ()> {
        let shadow_contents = std::fs::read_to_string("/etc/gshadow").map_err(|_| ())?;

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

    fn from_user_name(name: &str) -> Result<Vec<Self>, ()> {
        let mut valid_groups = Vec::new();
        let passwd_file_contents = std::fs::read_to_string("/etc/group")
            .unwrap_or_else(|e| panic!("got error while trying to read /etc/group file: {}", e));
        for line in passwd_file_contents.trim().split('\n') {
            //The format for a line in /etc/group is:
            //name:password:gid:list of users
            let mut group_info = line.split(':');
            let group_name = group_info.next().ok_or(())?.to_owned();

            //If this password is "x", it means it's stored in /etc/shadow.
            let password = group_info.next().ok_or(())?;
            let password = match password {
                "x" => Self::read_from_shadow(name).unwrap_or(Password::NoPass),
                "*" | "!" | "**" | "!!" => Password::NoPass,
                pass => Password::Unhashed(pass.into()),
            };

            //Some beautiful boilerplate below.
            let gid = group_info
                .next()
                .ok_or(())?
                .parse::<u32>()
                .map_err(|_| ())?;
            let mut users = group_info.next().ok_or(())?.split(',');
            if users.any(|word| word == name) {
                valid_groups.push(Self {
                    name: group_name,
                    passwd: password,
                    gid: unistd::Gid::from_raw(gid),
                });
            }
        }
        Ok(valid_groups)
    }
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

    pub fn get_primary_gid(&self) -> u32 {
        self.primary_gid
    }

    pub fn get_home(&self) -> &Path {
        &self.home
    }

    pub fn get_shell(&self) -> &Path {
        &self.shell
    }

    pub fn get_groups(&self) -> &[Group] {
        &self.groups
    }

    ///This function returns a User from /etc/passwd
    ///If user pass isn't present, it'll find it in /etc/shadow or be given NoPass depending.
    pub fn from_uid(uid: u32) -> Result<Self, ()> {
        let user = PartialUser::from_uid(uid)?;
        let groups = Group::from_user_name(&user.name)?;
        Ok(Self {
            name: user.name,
            password: user.password,
            uid: user.uid,
            uid_info: user.uid_info,
            primary_gid: user.primary_gid,
            groups,
            home: user.home,
            shell: user.shell,
        })
    }

    ///This function returns a User from /etc/passwd
    ///If user pass isn't present, it'll find it in /etc/shadow or be given NoPass depending.
    pub fn from_name(name: String) -> Result<Self, ()> {
        let user = PartialUser::from_name(&name)?;
        let groups = Group::from_user_name(&name)?;
        Ok(Self {
            name: user.name,
            password: user.password,
            uid: user.uid,
            uid_info: user.uid_info,
            primary_gid: user.primary_gid,
            groups,
            home: user.home,
            shell: user.shell,
        })
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
