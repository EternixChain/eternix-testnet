//! S1 local fixture worker. The trusted operator supplies initialization and exact selections;
//! this process has no signer, pool, sockets, scheduler or prototype-node state.
mod testnet_support;

fn main() {
    if let Err(error) = testnet_support::run(std::env::args_os().skip(1).collect()) {
        // Diagnostics never echo operator payloads or imply that a failed response undid SQL COMMIT.
        eprintln!("fixture worker stopped: {error}");
        std::process::exit(1);
    }
}
