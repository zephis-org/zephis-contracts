// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/cryptography/HKDF.sol";

contract HKDFWrapper {
    function expandWrapper(
        bytes32 prk,
        bytes memory info,
        uint256 length
    ) external pure returns (bytes memory) {
        return HKDF.expand(prk, info, length);
    }
}

contract HKDFTest is Test {
    using HKDF for bytes32;

    HKDFWrapper wrapper;

    function setUp() public {
        wrapper = new HKDFWrapper();
    }

    function testExtract() public pure {
        bytes32 salt = keccak256("test salt");
        bytes memory ikm = "input keying material";
        
        bytes32 prk = HKDF.extract(salt, ikm);
        assertTrue(prk != bytes32(0));
    }

    function testExpand() public pure {
        bytes32 prk = keccak256("pseudo random key");
        bytes memory info = "info string";
        uint256 length = 32;
        
        bytes memory okm = HKDF.expand(prk, info, length);
        assertEq(okm.length, length);
    }

    function testExpandDifferentLengths() public pure {
        bytes32 prk = keccak256("pseudo random key");
        bytes memory info = "info string";
        
        bytes memory okm16 = HKDF.expand(prk, info, 16);
        bytes memory okm32 = HKDF.expand(prk, info, 32);
        bytes memory okm64 = HKDF.expand(prk, info, 64);
        
        assertEq(okm16.length, 16);
        assertEq(okm32.length, 32);
        assertEq(okm64.length, 64);
        
        // Results should be different for different lengths
        assertFalse(keccak256(okm16) == keccak256(okm32));
        assertFalse(keccak256(okm32) == keccak256(okm64));
    }

    function testExpandMaxLength() public pure {
        bytes32 prk = keccak256("pseudo random key");
        bytes memory info = "info string";
        uint256 maxLength = 255 * 32; // Max allowed length
        
        bytes memory okm = HKDF.expand(prk, info, maxLength);
        assertEq(okm.length, maxLength);
    }

    function testExpandInvalidLengthZero() public {
        bytes32 prk = keccak256("pseudo random key");
        bytes memory info = "info string";
        
        vm.expectRevert(HKDF.InvalidOutputLength.selector);
        wrapper.expandWrapper(prk, info, 0);
    }

    function testExpandInvalidLengthTooLong() public {
        bytes32 prk = keccak256("pseudo random key");
        bytes memory info = "info string";
        
        vm.expectRevert(HKDF.InvalidOutputLength.selector);
        wrapper.expandWrapper(prk, info, 255 * 32 + 1);
    }

    function testDeriveKey() public pure {
        bytes32 salt = keccak256("test salt");
        bytes memory ikm = "input keying material";
        bytes memory info = "application info";
        uint256 length = 32;
        
        bytes memory key = HKDF.deriveKey(salt, ikm, info, length);
        assertEq(key.length, length);
        assertTrue(keccak256(key) != keccak256(abi.encodePacked(bytes32(0))));
    }

    function testDeriveKeyConsistency() public pure {
        bytes32 salt = keccak256("test salt");
        bytes memory ikm = "input keying material";
        bytes memory info = "application info";
        uint256 length = 32;
        
        bytes memory key1 = HKDF.deriveKey(salt, ikm, info, length);
        bytes memory key2 = HKDF.deriveKey(salt, ikm, info, length);
        
        // Same inputs should produce same output
        assertEq(keccak256(key1), keccak256(key2));
    }

    function testDeriveKeyDifferentInputs() public pure {
        bytes32 salt1 = keccak256("salt 1");
        bytes32 salt2 = keccak256("salt 2");
        bytes memory ikm = "input keying material";
        bytes memory info = "application info";
        uint256 length = 32;
        
        bytes memory key1 = HKDF.deriveKey(salt1, ikm, info, length);
        bytes memory key2 = HKDF.deriveKey(salt2, ikm, info, length);
        
        // Different salts should produce different keys
        assertFalse(keccak256(key1) == keccak256(key2));
    }

    function testHmacSha256() public pure {
        bytes32 key = keccak256("test key");
        bytes memory data = "test data";
        
        bytes32 result = HKDF.hmacSha256(key, data);
        assertTrue(result != bytes32(0));
    }

    function testHmacSha256Consistency() public pure {
        bytes32 key = keccak256("test key");
        bytes memory data = "test data";
        
        bytes32 result1 = HKDF.hmacSha256(key, data);
        bytes32 result2 = HKDF.hmacSha256(key, data);
        
        assertEq(result1, result2);
    }

    function testHmacSha256DifferentKeys() public pure {
        bytes32 key1 = keccak256("key 1");
        bytes32 key2 = keccak256("key 2");
        bytes memory data = "test data";
        
        bytes32 result1 = HKDF.hmacSha256(key1, data);
        bytes32 result2 = HKDF.hmacSha256(key2, data);
        
        assertFalse(result1 == result2);
    }

    function testTlsKdf() public pure {
        bytes32 masterSecret = keccak256("master secret");
        bytes32 clientRandom = keccak256("client random");
        bytes32 serverRandom = keccak256("server random");
        bytes memory label = "key expansion";
        uint256 length = 48; // Typical for TLS
        
        bytes memory keyMaterial = HKDF.tlsKdf(masterSecret, clientRandom, serverRandom, label, length);
        assertEq(keyMaterial.length, length);
        assertTrue(keccak256(keyMaterial) != keccak256(abi.encodePacked(bytes32(0))));
    }

    function testTlsKdfConsistency() public pure {
        bytes32 masterSecret = keccak256("master secret");
        bytes32 clientRandom = keccak256("client random");
        bytes32 serverRandom = keccak256("server random");
        bytes memory label = "key expansion";
        uint256 length = 48;
        
        bytes memory keyMaterial1 = HKDF.tlsKdf(masterSecret, clientRandom, serverRandom, label, length);
        bytes memory keyMaterial2 = HKDF.tlsKdf(masterSecret, clientRandom, serverRandom, label, length);
        
        assertEq(keccak256(keyMaterial1), keccak256(keyMaterial2));
    }

    function testPrf() public pure {
        bytes32 secret = keccak256("secret");
        bytes memory seed = "seed data";
        uint256 length = 64;
        
        bytes memory result = HKDF.prf(secret, seed, length);
        assertEq(result.length, length);
        assertTrue(keccak256(result) != keccak256(abi.encodePacked(bytes32(0))));
    }

    function testPrfConsistency() public pure {
        bytes32 secret = keccak256("secret");
        bytes memory seed = "seed data";
        uint256 length = 64;
        
        bytes memory result1 = HKDF.prf(secret, seed, length);
        bytes memory result2 = HKDF.prf(secret, seed, length);
        
        assertEq(keccak256(result1), keccak256(result2));
    }

    function testPrfDifferentSeeds() public pure {
        bytes32 secret = keccak256("secret");
        bytes memory seed1 = "seed 1";
        bytes memory seed2 = "seed 2";
        uint256 length = 64;
        
        bytes memory result1 = HKDF.prf(secret, seed1, length);
        bytes memory result2 = HKDF.prf(secret, seed2, length);
        
        assertFalse(keccak256(result1) == keccak256(result2));
    }

    function testExpansionWithMultipleIterations() public pure {
        bytes32 prk = keccak256("pseudo random key");
        bytes memory info = "info string";
        uint256 longLength = 100; // Requires multiple iterations
        
        bytes memory okm = HKDF.expand(prk, info, longLength);
        assertEq(okm.length, longLength);
        
        // Should be different from single iteration result
        bytes memory shortOkm = HKDF.expand(prk, info, 32);
        assertFalse(keccak256(okm) == keccak256(shortOkm));
    }

    function testEmptyInfo() public pure {
        bytes32 prk = keccak256("pseudo random key");
        bytes memory emptyInfo = "";
        uint256 length = 32;
        
        bytes memory okm = HKDF.expand(prk, emptyInfo, length);
        assertEq(okm.length, length);
        assertTrue(keccak256(okm) != keccak256(abi.encodePacked(bytes32(0))));
    }

    function testZeroSalt() public pure {
        bytes32 zeroSalt = bytes32(0);
        bytes memory ikm = "input keying material";
        
        bytes32 prk = HKDF.extract(zeroSalt, ikm);
        assertTrue(prk != bytes32(0));
        
        // Should be different from non-zero salt
        bytes32 nonZeroSalt = keccak256("salt");
        bytes32 prk2 = HKDF.extract(nonZeroSalt, ikm);
        assertFalse(prk == prk2);
    }
}