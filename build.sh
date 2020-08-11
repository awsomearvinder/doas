#!/bin/sh 
cargo build
chown root target/debug/doas 
chmod u+s target/debug/doas
