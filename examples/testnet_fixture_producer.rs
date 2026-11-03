//! S2 experimental local producer. Only a protected external key file supplies signing material;
//! private proposals go to the trusted controller, not to peers or a consensus network.
#[allow(clippy::duplicate_mod)]
// Both executables intentionally reuse the same example-only runtime.
mod testnet_support;

fn main() {
    if let Err(error) = testnet_support::run_producer(std::env::args_os().skip(1).collect()) {
        eprintln!("fixture producer stopped: {error}");
        std::process::exit(1);
    }
}
