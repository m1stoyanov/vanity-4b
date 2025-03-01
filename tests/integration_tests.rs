use vanity_4b::{calculate_keccak_256, cli::Opts, generate_vanity_function_name};

#[test]
fn test_cli_argument_parsing() {
    use gumdrop::Options;

    // Test valid arguments
    let args = vec!["-x", "0x1234", "-f", "test", "-p", "uint256", "-t", "4"];

    let opts = Opts::parse_args_default(&args).unwrap();
    assert_eq!(opts.pattern, "0x1234");
    assert_eq!(opts.fn_name, "test");
    assert_eq!(opts.fn_parameters, Some("uint256".to_string()));
    assert_eq!(opts.num_threads, Some(4));

    // Test missing required arguments
    let incomplete_args = vec!["-f", "test"];
    assert!(Opts::parse_args_default(&incomplete_args).is_err());
}

#[test]
fn test_complete_workflow() {
    // This test simulates the complete command but with a small range
    let pattern = "0x1234";
    let fn_name = "simpleTest";
    let fn_params = "uint256";

    // Run the generator with a small range
    let solution = generate_vanity_function_name(
        pattern[2..].as_bytes(),
        fn_name.as_bytes(),
        fn_params.as_bytes(),
        0,
        Some(100000),
    );

    assert!(solution.is_some());

    let solution_index = solution.unwrap();
    let full_name = format!("{}{}({})", fn_name, solution_index, fn_params);
    let hash = calculate_keccak_256(full_name.as_bytes());

    assert_eq!(format!("0x{:02x}{:02x}", hash[0], hash[1]), pattern);
}
