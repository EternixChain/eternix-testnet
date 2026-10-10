//! Real-file release benchmark of experimental complete producer/receiver pipelines and history costs.
//! Provide an existing disk-backed parent, optional sample count, and optional matrix case index.
use eternix_testnet as chain;
#[path = "stage4_support/bench.rs"]
mod bench;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let parent =
        std::path::PathBuf::from(args.next().ok_or("existing disk-backed parent required")?);
    let samples = args
        .next()
        .map(|s| s.to_str().unwrap().parse())
        .transpose()?
        .unwrap_or(5);
    let case = args
        .next()
        .map(|s| s.to_str().unwrap().parse())
        .transpose()?;
    let body = args
        .next()
        .map(|s| s.to_str().unwrap().parse())
        .transpose()?;
    bench::run(&parent, samples, case, body, |_, _| Ok(false))
}
