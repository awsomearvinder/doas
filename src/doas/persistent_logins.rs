// yeah okay I'm too sleepy to code, I'll write my thoughts here I guess.
// So what should happen is that I check if the directory exists, and create the directory
// if not (ideally handled by a setup script though? which is probably a wise idea.)
// In it - check for a persistent logins file which can just have a simplified key value
// file of some sort. Easy to manage, can split via \n and = and make a hashmap and call it
// a day. key can be UID, value can be a timestamp. The timestamp should be set for when
// the persistent login *expires* not when it's activated ideally. It's as simple for code
// and it allows for more modularity - although atleast at this time we won't be working
// with the added potential ability.
// We also want to filter the hashmap of any persistent logins that are past the time when
// they expire. This is better for efficiency and leaves a cleaner file overall to read,
// work and debug overall. If user isn't in persistent login - add them with time limit and
// return true.

use chrono::offset::FixedOffset;
use chrono::{DateTime, Duration, Utc};

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

const NEXT_PERSISTENT_LOGIN_QUERY_MINUTES: i64 = 5;

#[allow(dead_code)]
///Return if the given user with UID
///Needs to enter the password. (Persistent Logins)
pub fn need_pass(user: i32) -> bool {
    let user = user.to_string();
    let (persistent_login_file, mut conf) = read_persistent_login_file();
    let current_time = Utc::now();
    let timestamp = conf.get(user.as_str());
    let next_timeout = current_time
        .checked_add_signed(Duration::minutes(NEXT_PERSISTENT_LOGIN_QUERY_MINUTES))
        .unwrap();
    if let Some(timestamp) = timestamp {
        if current_time < *timestamp {
            conf.insert(user, next_timeout.into());
            return false;
        }
    }
    conf.insert(user, next_timeout.into());
    insert_to_file(persistent_login_file, conf).unwrap();
    true
}

fn insert_to_file(
    mut file: fs::File,
    map: HashMap<String, DateTime<FixedOffset>>,
) -> io::Result<()> {
    let contents: String = dbg!(map)
        .iter()
        .filter(|(_, &v)| Utc::now() < v)
        .map(|(k, v)| format!("{}={}\n", k, v.to_rfc3339()))
        .collect();
    file.write_all(dbg!(contents).as_str().as_bytes())
}

fn read_persistent_login_file() -> (fs::File, HashMap<String, DateTime<FixedOffset>>) {
    let mut persistent_login_file = match fs::OpenOptions::new()
        .write(true)
        .read(true)
        .open("/var/lib/doas/persistent_logins")
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if !Path::new("/var/lib/doas").exists() {
                fs::create_dir("/var/lib/doas").expect("Couldn't create doas folder in /var/lib");
            }
            fs::OpenOptions::new()
                .write(true)
                .read(true)
                .create_new(true)
                .open("/var/lib/doas/persistent_logins")
                .unwrap()
        }
        Err(e) => {
            eprintln!("Got unexpected error: {}. Exiting.", e);
            std::process::exit(1);
        }
    };
    let mut contents = String::new();
    persistent_login_file.read_to_string(&mut contents).unwrap();
    (
        persistent_login_file,
        contents
            .split('\n')
            .filter_map(|s| {
                if s.trim().is_empty() {
                    return None;
                }
                let space_index = s.rfind('=').unwrap();
                let (k, v) = s.split_at(space_index);
                let v = &v[1..];
                Some((k.to_owned(), DateTime::parse_from_rfc3339(v).unwrap()))
            })
            .collect(),
    )
}
