use std::net::SocketAddr;

use anyhow::Result;

use crate::models::{Config, NodeMode};

pub fn parse_args() -> Result<Config> {
    let mut mode = NodeMode::Validator;
    let mut p2p_port = 30333_u16;
    let mut rpc_port = 8545_u16;
    let mut peers: Vec<SocketAddr> = vec![];

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
            _ => {}
        }
        i += 1;
    }

    Ok(Config {
        mode,
        p2p_port,
        peers,
        rpc_port,
    })
}
