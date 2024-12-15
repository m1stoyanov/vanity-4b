use std::time::Instant;

use gumdrop::Options;
use log::info;

mod utils;

// CLI Options
#[derive(Debug, Options, Clone)]
pub struct Opts {
    pub help: bool,
    #[options(
        help = "Desired pattern, e.g., \"0x01234\"",
        required,
        short = "x",
        meta = ""
    )]
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

    // Strip '0x' if pattern starts with it
    let pattern = opts.pattern.as_bytes();
    let pattern_without_prefix = if pattern.starts_with(b"0x") {
        &pattern[2..]
    } else {
        pattern
    };

    let fn_name = &opts.fn_name;
    let fn_parameters = &opts.fn_parameters.unwrap_or_default();
    let full_name = format!("{}({})", fn_name, fn_parameters);
    info!("Start searching vanity function name for {}", full_name);
    let instant = Instant::now();

    utils::generate_vanity_function_name(
        pattern_without_prefix,
        fn_name.as_bytes(),
        fn_parameters.as_bytes(),
    );

    let elapsed = instant.elapsed().as_millis() as f64;
    let elapsed_seconds = elapsed / 1000.0;
    info!("Elapsed time {} seconds", elapsed_seconds);
}
