// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/cryptography/ECDSA.sol";

contract ECDSAWrapper {
    using ECDSA for ECDSA.Point;

    function verifySecp256k1Wrapper(
        bytes32 messageHash,
        ECDSA.Signature memory signature,
        ECDSA.Point memory publicKey
    ) external pure returns (bool) {
        return ECDSA.verifySecp256k1(messageHash, signature, publicKey);
    }

    function verifySecp256r1Wrapper(
        bytes32 messageHash,
        ECDSA.Signature memory signature,
        ECDSA.Point memory publicKey
    ) external pure returns (bool) {
        return ECDSA.verifySecp256r1(messageHash, signature, publicKey);
    }

    function verifySignatureWrapper(
        bytes32 messageHash,
        ECDSA.Signature memory signature,
        ECDSA.Point memory publicKey,
        uint256 curveType
    ) external pure returns (bool) {
        return ECDSA.verifySignature(messageHash, signature, publicKey, curveType);
    }
}

contract ECDSATest is Test {
    using ECDSA for ECDSA.Point;

    ECDSAWrapper wrapper;

    // Test constants for secp256k1
    uint256 constant SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 constant SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    function setUp() public {
        wrapper = new ECDSAWrapper();
    }

    function testSecp256k1GeneratorIsOnCurve() public pure {
        ECDSA.Point memory g = ECDSA.Point(SECP256K1_GX, SECP256K1_GY);
        assertTrue(ECDSA.isOnCurveSecp256k1(g));
    }

    function testSecp256r1GeneratorIsOnCurve() public pure {
        ECDSA.Point memory g = ECDSA.Point(
            0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        );
        assertTrue(ECDSA.isOnCurveSecp256r1(g));
    }

    function testInvalidPointNotOnCurve() public pure {
        ECDSA.Point memory invalid = ECDSA.Point(1, 1);
        assertFalse(ECDSA.isOnCurveSecp256k1(invalid));
        assertFalse(ECDSA.isOnCurveSecp256r1(invalid));
    }

    function testPointAtInfinity() public pure {
        ECDSA.Point memory infinity = ECDSA.Point(0, 0);
        // Point at infinity is considered valid in our implementation
        assertTrue(ECDSA.isOnCurveSecp256k1(infinity));
        assertTrue(ECDSA.isOnCurveSecp256r1(infinity));
    }

    function testDoublePointSecp256k1() public pure {
        ECDSA.Point memory g = ECDSA.Point(SECP256K1_GX, SECP256K1_GY);
        ECDSA.Point memory doubled = ECDSA.doublePointSecp256k1(g);
        
        assertTrue(ECDSA.isOnCurveSecp256k1(doubled));
        assertFalse(doubled.x == g.x && doubled.y == g.y);
    }

    function testAddPointsSecp256k1() public pure {
        ECDSA.Point memory g = ECDSA.Point(SECP256K1_GX, SECP256K1_GY);
        ECDSA.Point memory doubled1 = ECDSA.doublePointSecp256k1(g);
        ECDSA.Point memory doubled2 = ECDSA.addPointsSecp256k1(g, g);
        
        // Doubling should equal addition of point to itself
        assertEq(doubled1.x, doubled2.x);
        assertEq(doubled1.y, doubled2.y);
    }

    function testAddPointsWithInfinity() public pure {
        ECDSA.Point memory g = ECDSA.Point(SECP256K1_GX, SECP256K1_GY);
        ECDSA.Point memory infinity = ECDSA.Point(0, 0);
        
        ECDSA.Point memory result1 = ECDSA.addPointsSecp256k1(g, infinity);
        ECDSA.Point memory result2 = ECDSA.addPointsSecp256k1(infinity, g);
        
        // Adding infinity should return the original point
        assertEq(result1.x, g.x);
        assertEq(result1.y, g.y);
        assertEq(result2.x, g.x);
        assertEq(result2.y, g.y);
    }

    function testScalarMultiplicationZero() public pure {
        ECDSA.Point memory g = ECDSA.Point(SECP256K1_GX, SECP256K1_GY);
        ECDSA.Point memory result = ECDSA.scalarMultSecp256k1(0, g);
        
        // 0 * G should equal point at infinity
        assertEq(result.x, 0);
        assertEq(result.y, 0);
    }

    function testScalarMultiplicationOne() public pure {
        ECDSA.Point memory g = ECDSA.Point(SECP256K1_GX, SECP256K1_GY);
        ECDSA.Point memory result = ECDSA.scalarMultSecp256k1(1, g);
        
        // 1 * G should equal G
        assertEq(result.x, g.x);
        assertEq(result.y, g.y);
    }

    function testScalarMultiplicationTwo() public pure {
        ECDSA.Point memory g = ECDSA.Point(SECP256K1_GX, SECP256K1_GY);
        ECDSA.Point memory doubled = ECDSA.doublePointSecp256k1(g);
        ECDSA.Point memory result = ECDSA.scalarMultSecp256k1(2, g);
        
        // 2 * G should equal doubled G
        assertEq(result.x, doubled.x);
        assertEq(result.y, doubled.y);
    }

    function testModInverse() public pure {
        uint256 a = 3;
        uint256 mod = 7;
        uint256 inv = ECDSA.modInverse(a, mod);
        
        // a * inv should equal 1 mod p
        assertEq(mulmod(a, inv, mod), 1);
    }

    function testModExp() public pure {
        uint256 base = 2;
        uint256 exp = 10;
        uint256 mod = 1000;
        uint256 result = ECDSA.modExp(base, exp, mod);
        
        // 2^10 = 1024, 1024 % 1000 = 24
        assertEq(result, 24);
    }

    function testSubmod() public pure {
        uint256 a = 5;
        uint256 b = 8;
        uint256 mod = 7;
        uint256 result = ECDSA.submod(a, b, mod);
        
        // (5 - 8) mod 7 = (-3) mod 7 = 4
        assertEq(result, 4);
    }

    function testVerifySignatureInvalidR() public {
        bytes32 messageHash = keccak256("test message");
        ECDSA.Signature memory invalidSig = ECDSA.Signature({
            r: 0, // Invalid
            s: 1,
            v: 27
        });
        ECDSA.Point memory pubKey = ECDSA.Point(SECP256K1_GX, SECP256K1_GY);
        
        vm.expectRevert(ECDSA.InvalidSignature.selector);
        wrapper.verifySecp256k1Wrapper(messageHash, invalidSig, pubKey);
    }

    function testVerifySignatureInvalidS() public {
        bytes32 messageHash = keccak256("test message");
        ECDSA.Signature memory invalidSig = ECDSA.Signature({
            r: 1,
            s: 0, // Invalid
            v: 27
        });
        ECDSA.Point memory pubKey = ECDSA.Point(SECP256K1_GX, SECP256K1_GY);
        
        vm.expectRevert(ECDSA.InvalidSignature.selector);
        wrapper.verifySecp256k1Wrapper(messageHash, invalidSig, pubKey);
    }

    function testVerifySignatureInvalidCurve() public {
        bytes32 messageHash = keccak256("test message");
        ECDSA.Signature memory sig = ECDSA.Signature({
            r: 1,
            s: 1,
            v: 27
        });
        ECDSA.Point memory pubKey = ECDSA.Point(SECP256K1_GX, SECP256K1_GY);
        
        vm.expectRevert(ECDSA.InvalidCurve.selector);
        wrapper.verifySignatureWrapper(messageHash, sig, pubKey, 99); // Invalid curve type
    }

    function testSecp256r1Operations() public pure {
        ECDSA.Point memory g = ECDSA.Point(
            0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        );
        
        // Test doubling
        ECDSA.Point memory doubled = ECDSA.doublePointSecp256r1(g);
        assertTrue(ECDSA.isOnCurveSecp256r1(doubled));
        
        // Test addition
        ECDSA.Point memory added = ECDSA.addPointsSecp256r1(g, g);
        assertEq(doubled.x, added.x);
        assertEq(doubled.y, added.y);
        
        // Test scalar multiplication
        ECDSA.Point memory result = ECDSA.scalarMultSecp256r1(2, g);
        assertEq(result.x, doubled.x);
        assertEq(result.y, doubled.y);
    }

    function testLargeScalarMultiplication() public pure {
        ECDSA.Point memory g = ECDSA.Point(SECP256K1_GX, SECP256K1_GY);
        uint256 largeScalar = 0x123456789ABCDEF;
        
        ECDSA.Point memory result = ECDSA.scalarMultSecp256k1(largeScalar, g);
        assertTrue(ECDSA.isOnCurveSecp256k1(result));
        assertTrue(result.x != 0 || result.y != 0); // Should not be point at infinity for this scalar
    }

    function testPointNegation() public pure {
        ECDSA.Point memory g = ECDSA.Point(SECP256K1_GX, SECP256K1_GY);
        
        // Create the negation of g (same x, negated y)
        uint256 p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
        ECDSA.Point memory negG = ECDSA.Point(g.x, p - g.y);
        
        assertTrue(ECDSA.isOnCurveSecp256k1(negG));
        
        // Adding g and -g should give point at infinity
        ECDSA.Point memory result = ECDSA.addPointsSecp256k1(g, negG);
        assertEq(result.x, 0);
        assertEq(result.y, 0);
    }

    function testEdgeCaseCoordinates() public pure {
        // Test with coordinates at the edge of the field
        uint256 p256k1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
        uint256 p256r1 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
        
        ECDSA.Point memory edgePoint = ECDSA.Point(p256k1 - 1, p256k1 - 1);
        assertFalse(ECDSA.isOnCurveSecp256k1(edgePoint));
        
        edgePoint = ECDSA.Point(p256r1 - 1, p256r1 - 1);
        assertFalse(ECDSA.isOnCurveSecp256r1(edgePoint));
    }

    function testVerifySecp256r1InvalidR() public {
        bytes32 messageHash = keccak256("test message");
        ECDSA.Signature memory invalidSig = ECDSA.Signature({
            r: 0, // Invalid
            s: 1,
            v: 27
        });
        ECDSA.Point memory pubKey = ECDSA.Point(
            0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        );
        
        vm.expectRevert(ECDSA.InvalidSignature.selector);
        wrapper.verifySecp256r1Wrapper(messageHash, invalidSig, pubKey);
    }

    function testVerifySecp256r1InvalidS() public {
        bytes32 messageHash = keccak256("test message");
        ECDSA.Signature memory invalidSig = ECDSA.Signature({
            r: 1,
            s: 0, // Invalid
            v: 27
        });
        ECDSA.Point memory pubKey = ECDSA.Point(
            0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        );
        
        vm.expectRevert(ECDSA.InvalidSignature.selector);
        wrapper.verifySecp256r1Wrapper(messageHash, invalidSig, pubKey);
    }

    function testVerifySecp256k1InvalidPublicKey() public {
        bytes32 messageHash = keccak256("test message");
        ECDSA.Signature memory sig = ECDSA.Signature({
            r: 1,
            s: 1,
            v: 27
        });
        ECDSA.Point memory invalidPubKey = ECDSA.Point(1, 1); // Not on curve
        
        vm.expectRevert(ECDSA.InvalidPublicKey.selector);
        wrapper.verifySecp256k1Wrapper(messageHash, sig, invalidPubKey);
    }

    function testVerifySecp256r1InvalidPublicKey() public {
        bytes32 messageHash = keccak256("test message");
        ECDSA.Signature memory sig = ECDSA.Signature({
            r: 1,
            s: 1,
            v: 27
        });
        ECDSA.Point memory invalidPubKey = ECDSA.Point(1, 1); // Not on curve
        
        vm.expectRevert(ECDSA.InvalidPublicKey.selector);
        wrapper.verifySecp256r1Wrapper(messageHash, sig, invalidPubKey);
    }

    function testSignatureRangeSecp256k1() public {
        bytes32 messageHash = keccak256("test message");
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        
        // Test r >= N
        ECDSA.Signature memory invalidSig = ECDSA.Signature({
            r: n, // Invalid - equal to N
            s: 1,
            v: 27
        });
        ECDSA.Point memory pubKey = ECDSA.Point(SECP256K1_GX, SECP256K1_GY);
        
        vm.expectRevert(ECDSA.InvalidSignature.selector);
        wrapper.verifySecp256k1Wrapper(messageHash, invalidSig, pubKey);
        
        // Test s >= N
        invalidSig = ECDSA.Signature({
            r: 1,
            s: n, // Invalid - equal to N
            v: 27
        });
        
        vm.expectRevert(ECDSA.InvalidSignature.selector);
        wrapper.verifySecp256k1Wrapper(messageHash, invalidSig, pubKey);
    }

    function testSignatureRangeSecp256r1() public {
        bytes32 messageHash = keccak256("test message");
        uint256 n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
        
        // Test r >= N
        ECDSA.Signature memory invalidSig = ECDSA.Signature({
            r: n, // Invalid - equal to N
            s: 1,
            v: 27
        });
        ECDSA.Point memory pubKey = ECDSA.Point(
            0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        );
        
        vm.expectRevert(ECDSA.InvalidSignature.selector);
        wrapper.verifySecp256r1Wrapper(messageHash, invalidSig, pubKey);
        
        // Test s >= N
        invalidSig = ECDSA.Signature({
            r: 1,
            s: n, // Invalid - equal to N
            v: 27
        });
        
        vm.expectRevert(ECDSA.InvalidSignature.selector);
        wrapper.verifySecp256r1Wrapper(messageHash, invalidSig, pubKey);
    }

    function testCoordinateAtFieldBoundary() public pure {
        uint256 p256k1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
        uint256 p256r1 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
        
        // Test coordinates equal to field modulus
        ECDSA.Point memory boundaryPoint = ECDSA.Point(p256k1, 1);
        assertFalse(ECDSA.isOnCurveSecp256k1(boundaryPoint));
        
        boundaryPoint = ECDSA.Point(1, p256k1);
        assertFalse(ECDSA.isOnCurveSecp256k1(boundaryPoint));
        
        boundaryPoint = ECDSA.Point(p256r1, 1);
        assertFalse(ECDSA.isOnCurveSecp256r1(boundaryPoint));
        
        boundaryPoint = ECDSA.Point(1, p256r1);
        assertFalse(ECDSA.isOnCurveSecp256r1(boundaryPoint));
    }

    function testScalarMultSecp256r1EdgeCases() public pure {
        ECDSA.Point memory g = ECDSA.Point(
            0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        );
        
        // Test 0 * G
        ECDSA.Point memory result = ECDSA.scalarMultSecp256r1(0, g);
        assertEq(result.x, 0);
        assertEq(result.y, 0);
        
        // Test 1 * G
        result = ECDSA.scalarMultSecp256r1(1, g);
        assertEq(result.x, g.x);
        assertEq(result.y, g.y);
        
        // Test large scalar
        uint256 largeScalar = 0xABCDEF123456789;
        result = ECDSA.scalarMultSecp256r1(largeScalar, g);
        assertTrue(ECDSA.isOnCurveSecp256r1(result));
    }

    function testDoublePointSecp256r1() public pure {
        ECDSA.Point memory g = ECDSA.Point(
            0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        );
        
        ECDSA.Point memory doubled = ECDSA.doublePointSecp256r1(g);
        assertTrue(ECDSA.isOnCurveSecp256r1(doubled));
        assertFalse(doubled.x == g.x && doubled.y == g.y);
    }

    function testAddPointsSecp256r1WithInfinity() public pure {
        ECDSA.Point memory g = ECDSA.Point(
            0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        );
        ECDSA.Point memory infinity = ECDSA.Point(0, 0);
        
        ECDSA.Point memory result1 = ECDSA.addPointsSecp256r1(g, infinity);
        ECDSA.Point memory result2 = ECDSA.addPointsSecp256r1(infinity, g);
        
        assertEq(result1.x, g.x);
        assertEq(result1.y, g.y);
        assertEq(result2.x, g.x);
        assertEq(result2.y, g.y);
    }

    function testAddPointsSecp256r1Negation() public pure {
        ECDSA.Point memory g = ECDSA.Point(
            0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        );
        
        uint256 p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
        ECDSA.Point memory negG = ECDSA.Point(g.x, p - g.y);
        
        assertTrue(ECDSA.isOnCurveSecp256r1(negG));
        
        ECDSA.Point memory result = ECDSA.addPointsSecp256r1(g, negG);
        assertEq(result.x, 0);
        assertEq(result.y, 0);
    }

    function testVerifySignatureCurveTypeBranches() public {
        bytes32 messageHash = keccak256("test message");
        ECDSA.Signature memory sig = ECDSA.Signature({
            r: 1,
            s: 1,
            v: 27
        });
        ECDSA.Point memory invalidPubKey = ECDSA.Point(1, 1); // Not on curve
        
        // Test curve type 1 branch - should hit verifySecp256k1 and fail with InvalidPublicKey  
        vm.expectRevert(ECDSA.InvalidPublicKey.selector);
        wrapper.verifySignatureWrapper(messageHash, sig, invalidPubKey, 1);
        
        // Test curve type 2 branch - should hit verifySecp256r1 and fail with InvalidPublicKey
        vm.expectRevert(ECDSA.InvalidPublicKey.selector);
        wrapper.verifySignatureWrapper(messageHash, sig, invalidPubKey, 2);
    }
}