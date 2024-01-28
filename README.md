# Vanity solidity function name generator

A fast and simple app that can generate function name to match your desired signature.
For example, you have function doSomething(address) and need signature 0x12345678

```bash
$ cargo run --release -- -x 0x12345678 -f doSomething -p address
[2024-01-28T10:25:33Z INFO  vanity_4b] Start searching vanity function name for doSomething(address)
[2024-01-28T10:35:59Z INFO  vanity_4b::utils] Vanity function name found:
[2024-01-28T10:35:59Z INFO  vanity_4b::utils] Signature: 0x12345678
[2024-01-28T10:35:59Z INFO  vanity_4b::utils] Function name: doSomething533813959(address)
[2024-01-28T10:35:59Z INFO  vanity_4b] Elapsed time 625 seconds
$ 
```

Or function doSomethingOther() and need signature 0xffffffff
```bash
$ cargo run --release -- -x 0xffffffff -f doSomethingOther
[2024-01-28T10:46:51Z INFO  vanity_4b] Start searching vanity function name for doSomethingOther()
[2024-01-28T10:48:40Z INFO  vanity_4b::utils] Vanity function name found:
[2024-01-28T10:48:40Z INFO  vanity_4b::utils] Signature: 0xffffffff
[2024-01-28T10:48:40Z INFO  vanity_4b::utils] Function name: doSomethingOther4611686018518633616()
[2024-01-28T10:48:40Z INFO  vanity_4b] Elapsed time 109 seconds
$
```