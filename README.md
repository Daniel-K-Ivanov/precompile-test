## Precompile Checker

A Foundry script to test which EVM precompiles are supported on various blockchain networks.

## Usage

### Build

```shell
$ forge build
```

### PrecompileChecker

Test which EVM precompiles are supported on a specific blockchain network:

```shell
$ forge script script/PrecompileChecker.s.sol --rpc-url <your_rpc_url>
```

This script tests support for all standard Ethereum precompiles (0x01-0x09) on the specified RPC endpoint and reports which ones are supported:

- ECRECOVER (0x01): Elliptic curve digital signature recovery
- SHA256 (0x02): SHA-256 hash function
- RIPEMD160 (0x03): RIPEMD-160 hash function
- IDENTITY (0x04): Identity function (data copy)
- MODEXP (0x05): Modular exponentiation
- ECADD (0x06): Elliptic curve addition
- ECMUL (0x07): Elliptic curve scalar multiplication
- ECPAIRING (0x08): Elliptic curve pairing check
- BLAKE2F (0x09): BLAKE2 compression function
