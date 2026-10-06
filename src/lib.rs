//! Isolated protocol primitives, independent of the prototype node's admission and state engine.
//!
//! Exporting native authentication and offline application does not activate V2 in RPC, P2P,
//! or the live node's canonical execution.

pub mod native_transaction;
pub mod native_transfer;
