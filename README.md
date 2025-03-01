# Vanity Solidity Function Name Generator

A high-performance tool for generating Solidity function names with specific function signatures (method IDs). In Ethereum smart contracts, function signatures are the first 4 bytes of the Keccak-256 hash of the function's signature string. This tool helps you find a function name that produces your desired signature by appending numeric values to your base function name.

For example, you can generate a function like `transfer123456(address,uint256)` that has the exact signature `0xbeefdead` you want for gas optimization, contract interface continuity, or creative purposes.

## Usage

```bash
# Basic syntax
cargo run --profile maxperf -- -x <DESIRED_SIGNATURE> -f <FUNCTION_NAME> [-p <FUNCTION_PARAMS>] [-t <NUM_THREADS>]
```

### Command Line Options

| Option | Description | Required | Default |
|--------|-------------|----------|---------|
| `-x`, `--pattern` | Desired signature pattern (e.g., "0x12345678") | Yes | - |
| `-f`, `--fn-name` | Base function name (e.g., "transfer") | Yes | - |
| `-p`, `--fn-parameters` | Function parameters (e.g., "address,uint256") | No | "" (empty string) |
| `-t`, `--num-threads` | Number of threads to use | No | Number of physical cores |
| `--help` | Display help information | No | - |

### Examples

Find a function with signature `0x12345678`:

```bash
$ cargo run --profile maxperf -- -x 0x12345678 -f doSomething -p address
[2025-03-01T16:10:26Z INFO  vanity_4b] Start searching vanity function name for doSomething(address)
[2025-03-01T16:10:26Z INFO  vanity_4b] Using 6 threads on 6 physical cores for processing
[2025-03-01T16:10:26Z INFO  vanity_4b] Range: [0..1000000000]
[2025-03-01T16:10:37Z INFO  vanity_4b] Vanity function name found:
[2025-03-01T16:10:37Z INFO  vanity_4b] Signature: 0x12345678
[2025-03-01T16:10:37Z INFO  vanity_4b] Function name: doSomething533813959(address)
[2025-03-01T16:10:37Z INFO  vanity_4b] Elapsed time 10.771 seconds
[2025-03-01T16:10:37Z INFO  vanity_4b] Summary: 192937800 hashes, average speed: 17.91 MH/s
```

Find a function with a very specific signature `0xffffffff`:

```bash
$ cargo run --profile maxperf -- -x 0xffffffff -f doSomethingOther
[2025-03-01T16:11:19Z INFO  vanity_4b] Start searching vanity function name for doSomethingOther()
[2025-03-01T16:11:19Z INFO  vanity_4b] Using 6 threads on 6 physical cores for processing
[2025-03-01T16:11:19Z INFO  vanity_4b] Range: [0..1000000000]
[2025-03-01T16:12:14Z WARN  vanity_4b] Did not find solution
[2025-03-01T16:12:14Z INFO  vanity_4b] Range: [1000000000..2000000000]
[2025-03-01T16:12:53Z INFO  vanity_4b] Vanity function name found:
[2025-03-01T16:12:53Z INFO  vanity_4b] Signature: 0xffffffff
[2025-03-01T16:12:53Z INFO  vanity_4b] Function name: doSomethingOther1496513840()
[2025-03-01T16:12:53Z INFO  vanity_4b] Elapsed time 94.458 seconds
[2025-03-01T16:12:53Z INFO  vanity_4b] Summary: 1727003025 hashes, average speed: 18.28 MH/s
```