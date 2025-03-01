use std::{sync::atomic::Ordering, time::Instant};

use gumdrop::Options;
use log::{error, info, warn};
use vanity_4b::{
    HASH_COUNTER, HEX_LOOKUP_TABLE, calculate_keccak_256, cli::Opts, generate_vanity_function_name,
};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let opts = Opts::parse_args_default_or_exit();

    // Configure thread pool
    let available_cores = num_cpus::get_physical();
    let threads_to_use = opts.num_threads.unwrap_or(available_cores);

    rayon::ThreadPoolBuilder::new()
        .num_threads(threads_to_use)
        .build_global()
        .expect("Failed to build thread pool");

    // Lower case and strip '0x' if pattern starts with it
    let pattern = opts.pattern.to_lowercase();
    let mut pattern_without_prefix = pattern.strip_prefix("0x").unwrap_or(&pattern);

    // Validate pattern
    // It should be <= 8 chars
    if pattern_without_prefix.len() > 8 {
        let truncated_pattern_without_prefix = &pattern_without_prefix[..8];
        warn!(
            "Pattern {} has invalid lenght. Truncating to 0x{}",
            opts.pattern, truncated_pattern_without_prefix
        );
        pattern_without_prefix = truncated_pattern_without_prefix;
    }
    // Every char should be in 0123456789abcdef range
    if !pattern_without_prefix.chars().all(|c| HEX_LOOKUP_TABLE[c as usize] != 0xFF) {
        error!("Pattern {} has invalid characters!", opts.pattern);
        std::process::exit(1);
    }
    // Done validating pattern

    let fn_name = &opts.fn_name;
    let fn_parameters = &opts.fn_parameters.unwrap_or_default();
    let full_name = format!("{}({})", fn_name, fn_parameters);
    info!("Start searching vanity function name for {}", full_name);
    info!("Using {} threads on {} physical cores for processing", threads_to_use, available_cores);

    let instant = Instant::now();

    let step = 1_000_000_000_u64;
    for starting_point in (0..u64::MAX).step_by(step as usize) {
        let ending_point = starting_point.saturating_add(step);
        info!("Range: [{}..{}]", starting_point, ending_point);
        match generate_vanity_function_name(
            pattern_without_prefix.as_bytes(),
            fn_name.as_bytes(),
            fn_parameters.as_bytes(),
            starting_point,
            Some(ending_point),
        ) {
            Some(solution_index) => {
                let vanity_function_name =
                    format!("{}{}({})", fn_name, solution_index, fn_parameters);
                let hash = calculate_keccak_256(vanity_function_name.as_bytes());
                let signature =
                    format!("0x{:02x}{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2], hash[3]);
                info!("Vanity function name found:");
                info!("Signature: {}", signature);
                info!("Function name: {}", vanity_function_name);
                break;
            }
            None => {
                warn!("Did not find solution");
            }
        }
    }

    let elapsed = instant.elapsed().as_millis() as f64;
    let elapsed_seconds = elapsed / 1000.0;
    let total_hashes = HASH_COUNTER.load(Ordering::Relaxed);
    let mhps = (total_hashes as f64) / elapsed_seconds / 1_000_000.0;

    info!("Elapsed time {} seconds", elapsed_seconds);
    info!("Summary: {} hashes, average speed: {:.2} MH/s", total_hashes, mhps);
}
