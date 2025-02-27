use std::{sync::atomic::Ordering, time::Instant};

use gumdrop::Options;
use log::{error, info};
use vanity_4b::{generate_vanity_function_name, HASH_COUNTER, HEX_LOOKUP_TABLE};

// CLI Options
#[derive(Debug, Options, Clone)]
pub struct Opts {
    pub help: bool,
    #[options(help = "Desired pattern, e.g., \"0x01234\"", required, short = "x", meta = "")]
    pub pattern: String,
    #[options(
        help = "Function name, e.g., \"checkAddressInfo\"",
        required,
        short = "f",
        meta = ""
    )]
    pub fn_name: String,
    #[options(
        help = "Optional function parameters e.g., \"address,address,uint256\"",
        short = "p",
        meta = ""
    )]
    pub fn_parameters: Option<String>,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let opts = Opts::parse_args_default_or_exit();

    // Lower case and strip '0x' if pattern starts with it
    let pattern = opts.pattern.to_lowercase();
    let pattern_without_prefix = pattern.strip_prefix("0x").unwrap_or(&pattern);

    // Validate pattern (every char should be in 0123456789abcdef range)
    if !pattern_without_prefix.chars().all(|c| HEX_LOOKUP_TABLE[c as usize] != 0xFF) {
        error!("Pattern {} has invalid characters!", opts.pattern);
        std::process::exit(1);
    }

    let fn_name = &opts.fn_name;
    let fn_parameters = &opts.fn_parameters.unwrap_or_default();
    let full_name = format!("{}({})", fn_name, fn_parameters);
    info!("Start searching vanity function name for {}", full_name);
    let instant = Instant::now();

    generate_vanity_function_name(
        pattern_without_prefix.as_bytes(),
        fn_name.as_bytes(),
        fn_parameters.as_bytes(),
    );

    let elapsed = instant.elapsed().as_millis() as f64;
    let elapsed_seconds = elapsed / 1000.0;
    let total_hashes = HASH_COUNTER.load(Ordering::Relaxed);
    let mhps = (total_hashes as f64) / elapsed_seconds / 1_000_000.0;

    info!("Elapsed time {} seconds", elapsed_seconds);
    info!("Summary: {} hashes, average speed: {:.2} MH/s", total_hashes, mhps);
}
