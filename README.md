# Vanity solidity function name generator

A fast and simple app that can generate function name to match your desired signature.
For example, you have function doSomething(address) and need signature 0x12345678

```bash
$ cargo run --profile maxperf -- -x 0x12345678 -f doSomething -p address
[2024-12-15T19:45:36Z INFO  vanity_4b] Start searching vanity function name for doSomething(address)
[2024-12-15T19:50:38Z INFO  vanity_4b::utils] Vanity function name found:
[2024-12-15T19:50:38Z INFO  vanity_4b::utils] Signature: 0x12345678
[2024-12-15T19:50:38Z INFO  vanity_4b::utils] Function name: doSomething12682136551088022702(address)
[2024-12-15T19:50:38Z INFO  vanity_4b] Elapsed time 302.379 seconds
$ 
```

Or function doSomethingOther() and need signature 0xffffffff
```bash
$ cargo run --profile maxperf -- -x 0xffffffff -f doSomethingOther
[2024-12-15T19:43:59Z INFO  vanity_4b] Start searching vanity function name for doSomethingOther()
[2024-12-15T19:45:06Z INFO  vanity_4b::utils] Vanity function name found:
[2024-12-15T19:45:06Z INFO  vanity_4b::utils] Signature: 0xffffffff
[2024-12-15T19:45:06Z INFO  vanity_4b::utils] Function name: doSomethingOther4611686018518633616()
[2024-12-15T19:45:06Z INFO  vanity_4b] Elapsed time 66.722 seconds
$
```