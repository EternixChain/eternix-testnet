use std::net::SocketAddr;

use anyhow::Result;

use crate::models::{Config, NodeMode};

pub fn parse_args() -> Result<Config> {
    let mut mode = NodeMode::Validator;
    let mut p2p_port = 30333_u16;
    let mut rpc_port = 8545_u16;
    let mut peers: Vec<SocketAddr> = vec![];
    let mut validator_id: Option<String> = None;
    let mut validator_account: Option<String> = None;
    let mut genesis_path = "genesis.json".to_string();

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--mode requires value: standard|validator");
                }
                mode = match args[i].as_str() {
                    "standard" => NodeMode::Standard,
                    "validator" => NodeMode::Validator,
                    _ => anyhow::bail!("invalid --mode, use standard or validator"),
                };
            }
            "--p2p-port" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--p2p-port requires a value");
                }
                p2p_port = args[i].parse()?;
            }
            "--peers" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--peers requires comma-separated host:port list");
                }
                for raw in args[i].split(',') {
                    if !raw.trim().is_empty() {
                        peers.push(raw.parse()?);
                    }
                }
            }
            "--rpc-port" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--rpc-port requires a value");
                }
                rpc_port = args[i].parse()?;
            }
            "--validator-account" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--validator-account requires an address");
                }
                validator_account = Some(args[i].clone());
            }
            "--validator-id" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--validator-id requires a validator id");
                }
                validator_id = Some(args[i].clone());
            }
            "--genesis" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--genesis requires a path");
                }
                genesis_path = args[i].clone();
            }
            _ => {}
        }
        i += 1;
    }

    if validator_id.is_some() && validator_account.is_none() {
        anyhow::bail!("--validator-id requires --validator-account");
    }

    Ok(Config {
        mode,
        p2p_port,
        peers,
        rpc_port,
        validator_id,
        validator_account,
        genesis_path,
    })
}
