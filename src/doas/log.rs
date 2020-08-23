//Your daily cup of black magic.
//This has two cases: One that is basically line for line just piping it into println!
//and another with the only difference being that it has a second argument that must
//start with should_print: (it'll only log if that's true.)

macro_rules! log {
    ($fmt: tt, $($args: expr),*) => {
        if *crate::SHOULD_LOG.get().unwrap() {
            println!($fmt, $($args),*);
        }
    };
    ($literal: tt) => {
        if *crate::SHOULD_LOG.get().unwrap() {
            println!($literal);
        }
    }
}

macro_rules! err_log {
    ($fmt: tt, $($args: expr),*) => {
        if *crate::SHOULD_LOG.get().unwrap() {
            eprintln!($fmt, $($args),*);
        }
    };
    ($literal: tt) => {
        if *crate::SHOULD_LOG.get().unwrap() {
            eprintln!($literal);
        }
    }
}
