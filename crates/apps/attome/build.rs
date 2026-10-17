//! `sqlx::migrate!` embeds the migrations at compile time but does not tell
//! cargo to rebuild when a migration file is added, so a new migration would
//! be missing from the binary until something else in this crate changed.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
