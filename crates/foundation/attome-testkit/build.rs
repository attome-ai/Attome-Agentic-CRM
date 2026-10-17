//! `sqlx::migrate!` embeds the migrations at compile time but does not tell
//! cargo to rebuild when a migration file is added, so a new migration would
//! leave the test template without it until something else changed here.

fn main() {
    println!("cargo:rerun-if-changed=../../apps/attome/migrations");
}
