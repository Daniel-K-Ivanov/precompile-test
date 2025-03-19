// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

contract PrecompileChecker is Script {
    // Precompile addresses according to EVM specification
    address constant ECRECOVER = 0x0000000000000000000000000000000000000001;
    address constant SHA256 = 0x0000000000000000000000000000000000000002;
    address constant RIPEMD160 = 0x0000000000000000000000000000000000000003;
    address constant IDENTITY = 0x0000000000000000000000000000000000000004;
    address constant MODEXP = 0x0000000000000000000000000000000000000005;
    address constant ECADD = 0x0000000000000000000000000000000000000006;
    address constant ECMUL = 0x0000000000000000000000000000000000000007;
    address constant ECPAIRING = 0x0000000000000000000000000000000000000008;
    address constant BLAKE2F = 0x0000000000000000000000000000000000000009;

    // Keep track of supported precompiles
    bool[9] public precompileSupport;

    function setUp() public {}

    function run() public {
        // Note: This script should be run with a specific RPC URL
        // e.g. forge script script/PrecompileChecker.s.sol --rpc-url <YOUR_RPC_URL>
        console.log(
            "Testing precompile support on RPC endpoint:",
            block.chainid
        );

        // Test each precompile and catch any reverts
        try this.testEcrecover() {
            precompileSupport[0] = true;
        } catch {}
        try this.testSha256() {
            precompileSupport[1] = true;
        } catch {}
        try this.testRipemd160() {
            precompileSupport[2] = true;
        } catch {}
        try this.testIdentity() {
            precompileSupport[3] = true;
        } catch {}
        try this.testModexp() {
            precompileSupport[4] = true;
        } catch {}
        try this.testEcAdd() {
            precompileSupport[5] = true;
        } catch {}
        try this.testEcMul() {
            precompileSupport[6] = true;
        } catch {}
        try this.testEcPairing() {
            precompileSupport[7] = true;
        } catch {}
        try this.testBlake2f() {
            precompileSupport[8] = true;
        } catch {}

        // Summarize results
        console.log("\nPrecompile Support Summary:");
        console.log("ECRECOVER (0x01):", precompileSupport[0]);
        console.log("SHA256 (0x02):", precompileSupport[1]);
        console.log("RIPEMD160 (0x03):", precompileSupport[2]);
        console.log("IDENTITY (0x04):", precompileSupport[3]);
        console.log("MODEXP (0x05):", precompileSupport[4]);
        console.log("ECADD (0x06):", precompileSupport[5]);
        console.log("ECMUL (0x07):", precompileSupport[6]);
        console.log("ECPAIRING (0x08):", precompileSupport[7]);
        console.log("BLAKE2F (0x09):", precompileSupport[8]);

        console.log("\nPrecompile testing completed");
    }

    function testEcrecover() public {
        console.log("Testing ECRECOVER (0x01):");

        // Example values from documentation
        bytes32 hash = 0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3;
        bytes32 v = bytes32(uint256(28)); // v value padded to 32 bytes
        bytes32 r = 0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608;
        bytes32 s = 0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada;

        // Format input correctly: hash + v + r + s (each 32 bytes)
        bytes memory input = abi.encodePacked(hash, v, r, s);

        (bool success, bytes memory result) = ECRECOVER.staticcall(input);

        // Expected result from documentation
        address expected = 0x7156526fbD7a3C72969B54f64e42c10fbb768C8a;

        if (success) {
            // The ECRECOVER result is a raw address (20 bytes), right-aligned in 32 bytes
            address recovered;
            assembly {
                recovered := mload(add(result, 32))
            }
            console.log("  Success:", success);
            console.log("  Recovered address:", addressToString(recovered));
            console.log("  Expected address:", addressToString(expected));
            console.log("  Result matches expected:", recovered == expected);
        } else {
            console.log("  Failed to call ECRECOVER");
        }
    }

    function testSha256() public {
        console.log("Testing SHA256 (0x02):");
        bytes memory input = "test input for SHA256";

        (bool success, bytes memory result) = SHA256.staticcall(input);

        if (success) {
            // SHA256 returns a raw 32 bytes hash, not ABI-encoded
            bytes32 hash;
            assembly {
                hash := mload(add(result, 32))
            }
            console.log("  Success:", success);
            console.log("  Hash computed:", bytes32ToString(hash));
        } else {
            console.log("  Failed to call SHA256");
        }
    }

    function testRipemd160() public {
        console.log("Testing RIPEMD160 (0x03):");
        bytes memory input = "test input for RIPEMD160";

        (bool success, bytes memory result) = RIPEMD160.staticcall(input);

        if (success) {
            // RIPEMD160 returns a raw 20 bytes hash padded to 32 bytes, not ABI-encoded
            bytes20 hash;
            assembly {
                hash := mload(add(result, 32))
            }
            console.log("  Success:", success);
            console.log("  Hash computed:", bytes20ToString(hash));
        } else {
            console.log("  Failed to call RIPEMD160");
        }
    }

    function testIdentity() public {
        console.log("Testing IDENTITY (0x04):");
        bytes memory input = "test input for IDENTITY";

        (bool success, bytes memory result) = IDENTITY.staticcall(input);

        if (success) {
            console.log("  Success:", success);
            string memory resultStr = string(result);
            console.log("  Result:", resultStr);
            console.log(
                "  Result matches input:",
                keccak256(result) == keccak256(input)
            );
        } else {
            console.log("  Failed to call IDENTITY");
        }
    }

    function testModexp() public {
        console.log("Testing MODEXP (0x05):");

        // Test case: 3^7 mod 11
        uint256 base = 3;
        uint256 exponent = 7;
        uint256 modulus = 11;

        // MODEXP input format: baseLen, expLen, modLen, base, exponent, modulus
        bytes memory input = abi.encodePacked(
            uint256(32), // baseLen
            uint256(32), // expLen
            uint256(32), // modLen
            bytes32(base), // base
            bytes32(exponent), // exponent
            bytes32(modulus) // modulus
        );

        (bool success, bytes memory result) = MODEXP.staticcall(input);

        // 3^7 mod 11 = 9
        uint256 expected = 9;

        if (success) {
            // MODEXP returns a big-endian modulus-sized integer
            uint256 output;
            assembly {
                output := mload(add(result, 32))
            }
            console.log("  Success:", success);
            console.log("  Result:", output);
            console.log("  Expected:", expected);
            console.log("  Result matches expected:", output == expected);
        } else {
            console.log("  Failed to call MODEXP");
        }
    }

    function testEcAdd() public {
        console.log("Testing ECADD (0x06):");

        // Using valid curve points
        bytes memory input = abi.encodePacked(
            // First point (x, y)
            bytes32(
                0x0000000000000000000000000000000000000000000000000000000000000001
            ),
            bytes32(
                0x0000000000000000000000000000000000000000000000000000000000000002
            ),
            // Second point (x, y)
            bytes32(
                0x0000000000000000000000000000000000000000000000000000000000000001
            ),
            bytes32(
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
        );

        (bool success, bytes memory result) = ECADD.staticcall(input);
        console.log("  Success:", success);

        if (success && result.length >= 64) {
            bytes32 x;
            bytes32 y;
            assembly {
                x := mload(add(result, 32))
                y := mload(add(result, 64))
            }
            console.log("  Result point x:", bytes32ToString(x));
            console.log("  Result point y:", bytes32ToString(y));
        }
    }

    function testEcMul() public {
        console.log("Testing ECMUL (0x07):");

        // Using valid curve point and scalar
        bytes memory input = abi.encodePacked(
            // Point (x, y)
            bytes32(
                0x0000000000000000000000000000000000000000000000000000000000000001
            ),
            bytes32(
                0x0000000000000000000000000000000000000000000000000000000000000002
            ),
            // Scalar
            bytes32(
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
        );

        (bool success, bytes memory result) = ECMUL.staticcall(input);
        console.log("  Success:", success);

        if (success && result.length >= 64) {
            bytes32 x;
            bytes32 y;
            assembly {
                x := mload(add(result, 32))
                y := mload(add(result, 64))
            }
            console.log("  Result point x:", bytes32ToString(x));
            console.log("  Result point y:", bytes32ToString(y));
        }
    }

    function testEcPairing() public {
        console.log("Testing ECPAIRING (0x08):");

        // This is a valid test case for BN128 pairing check
        // Input consists of a sequence of points on G1 and G2
        bytes
            memory input = hex"1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";

        (bool success, bytes memory result) = ECPAIRING.staticcall(input);
        console.log("  Success:", success);

        if (success && result.length >= 32) {
            uint256 output;
            assembly {
                output := mload(add(result, 32))
            }
            console.log("  Result:", output);
            console.log(
                "  Expected (1 = valid pairing, 0 = invalid):",
                uint256(1)
            );
        }
    }

    function testBlake2f() public {
        console.log("Testing BLAKE2F (0x09):");

        // Real input for Blake2f
        // Format: rounds(4) + h(64) + m(128) + t(16) + f(1)
        bytes
            memory input = hex"0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001";

        (bool success, bytes memory result) = BLAKE2F.staticcall(input);
        console.log("  Success:", success);

        if (success && result.length >= 64) {
            bytes32 part1;
            bytes32 part2;
            assembly {
                part1 := mload(add(result, 32))
                part2 := mload(add(result, 64))
            }
            console.log("  Result part 1:", bytes32ToString(part1));
            console.log("  Result part 2:", bytes32ToString(part2));
        }
    }

    // Helper functions
    function bytes32ToString(
        bytes32 _bytes
    ) private pure returns (string memory) {
        bytes memory byteArray = new bytes(64);
        for (uint256 i; i < 32; i++) {
            byteArray[i * 2] = toHexChar(uint8(_bytes[i]) / 16);
            byteArray[i * 2 + 1] = toHexChar(uint8(_bytes[i]) % 16);
        }
        return string(abi.encodePacked("0x", byteArray));
    }

    function bytes20ToString(
        bytes20 _bytes
    ) private pure returns (string memory) {
        bytes memory byteArray = new bytes(40);
        for (uint256 i; i < 20; i++) {
            byteArray[i * 2] = toHexChar(uint8(_bytes[i]) / 16);
            byteArray[i * 2 + 1] = toHexChar(uint8(_bytes[i]) % 16);
        }
        return string(abi.encodePacked("0x", byteArray));
    }

    function addressToString(
        address _addr
    ) private pure returns (string memory) {
        bytes32 value = bytes32(uint256(uint160(_addr)));
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(42);
        str[0] = "0";
        str[1] = "x";

        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(value[i + 12] >> 4)];
            str[3 + i * 2] = alphabet[uint8(value[i + 12] & 0x0f)];
        }

        return string(str);
    }

    function toHexChar(uint8 _i) private pure returns (bytes1) {
        if (_i < 10) {
            return bytes1(uint8(_i) + 48);
        } else {
            return bytes1(uint8(_i) + 87);
        }
    }
}
