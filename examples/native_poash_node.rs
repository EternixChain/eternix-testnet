//! Explicitly configured isolated C1 process trial, separate from the prototype and all M1 binaries.
fn main() {
    if let Err(e) = eternix_testnet::native_poash::trial::run(std::env::args_os().skip(1).collect())
    {
        eprintln!("C1 process stopped: {e}");
        std::process::exit(1);
    }
}
