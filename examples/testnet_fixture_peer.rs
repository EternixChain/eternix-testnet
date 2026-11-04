//! S3/S4 loopback fixture peer; selections and catch-up targets arrive only over local operator I/O.
#[allow(clippy::duplicate_mod)]
// Share the reviewed owner/pool/controller boundary, not a new ledger.
mod testnet_support;

fn main() {
    if let Err(error) = testnet_support::transport::run(std::env::args_os().skip(1).collect()) {
        eprintln!("fixture peer stopped: {error}");
        std::process::exit(1);
    }
}
