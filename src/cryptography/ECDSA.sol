// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library ECDSA {
    struct Point {
        uint256 x;
        uint256 y;
    }

    struct Signature {
        uint256 r;
        uint256 s;
        uint8 v;
    }

    uint256 constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 constant SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 constant SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 constant SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    uint256 constant SECP256R1_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 constant SECP256R1_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 constant SECP256R1_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint256 constant SECP256R1_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;

    error InvalidSignature();
    error InvalidPublicKey();
    error InvalidCurve();

    function verifySignature(
        bytes32 messageHash,
        Signature memory signature,
        Point memory publicKey,
        uint256 curveType
    ) internal pure returns (bool) {
        if (curveType == 1) {
            return verifySecp256k1(messageHash, signature, publicKey);
        } else if (curveType == 2) {
            return verifySecp256r1(messageHash, signature, publicKey);
        } else {
            revert InvalidCurve();
        }
    }

    function verifySecp256k1(
        bytes32 messageHash,
        Signature memory signature,
        Point memory publicKey
    ) internal pure returns (bool) {
        if (signature.r == 0 || signature.r >= SECP256K1_N) revert InvalidSignature();
        if (signature.s == 0 || signature.s >= SECP256K1_N) revert InvalidSignature();
        if (!isOnCurveSecp256k1(publicKey)) revert InvalidPublicKey();

        uint256 w = modInverse(signature.s, SECP256K1_N);
        uint256 u1 = mulmod(uint256(messageHash), w, SECP256K1_N);
        uint256 u2 = mulmod(signature.r, w, SECP256K1_N);

        Point memory point1 = scalarMultSecp256k1(u1, Point(SECP256K1_GX, SECP256K1_GY));
        Point memory point2 = scalarMultSecp256k1(u2, publicKey);
        Point memory result = addPointsSecp256k1(point1, point2);

        return result.x == signature.r;
    }

    function verifySecp256r1(
        bytes32 messageHash,
        Signature memory signature,
        Point memory publicKey
    ) internal pure returns (bool) {
        if (signature.r == 0 || signature.r >= SECP256R1_N) revert InvalidSignature();
        if (signature.s == 0 || signature.s >= SECP256R1_N) revert InvalidSignature();
        if (!isOnCurveSecp256r1(publicKey)) revert InvalidPublicKey();

        uint256 w = modInverse(signature.s, SECP256R1_N);
        uint256 u1 = mulmod(uint256(messageHash), w, SECP256R1_N);
        uint256 u2 = mulmod(signature.r, w, SECP256R1_N);

        Point memory point1 = scalarMultSecp256r1(u1, Point(SECP256R1_GX, SECP256R1_GY));
        Point memory point2 = scalarMultSecp256r1(u2, publicKey);
        Point memory result = addPointsSecp256r1(point1, point2);

        return result.x == signature.r;
    }

    function isOnCurveSecp256k1(Point memory point) internal pure returns (bool) {
        // Point at infinity
        if (point.x == 0 && point.y == 0) return true;
        if (point.x >= SECP256K1_P || point.y >= SECP256K1_P) return false;
        
        uint256 left = mulmod(point.y, point.y, SECP256K1_P);
        uint256 right = addmod(
            mulmod(mulmod(point.x, point.x, SECP256K1_P), point.x, SECP256K1_P),
            7,
            SECP256K1_P
        );
        
        return left == right;
    }

    function isOnCurveSecp256r1(Point memory point) internal pure returns (bool) {
        // Point at infinity
        if (point.x == 0 && point.y == 0) return true;
        if (point.x >= SECP256R1_P || point.y >= SECP256R1_P) return false;
        
        uint256 left = mulmod(point.y, point.y, SECP256R1_P);
        uint256 right = addmod(
            addmod(
                mulmod(mulmod(point.x, point.x, SECP256R1_P), point.x, SECP256R1_P),
                mulmod(point.x, SECP256R1_P - 3, SECP256R1_P),
                SECP256R1_P
            ),
            0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
            SECP256R1_P
        );
        
        return left == right;
    }

    function addPointsSecp256k1(Point memory p1, Point memory p2) internal pure returns (Point memory) {
        if (p1.x == 0 && p1.y == 0) return p2;
        if (p2.x == 0 && p2.y == 0) return p1;
        if (p1.x == p2.x) {
            if (p1.y == p2.y) return doublePointSecp256k1(p1);
            else return Point(0, 0);
        }

        uint256 dx = submod(p2.x, p1.x, SECP256K1_P);
        uint256 dy = submod(p2.y, p1.y, SECP256K1_P);
        uint256 m = mulmod(dy, modInverse(dx, SECP256K1_P), SECP256K1_P);
        
        uint256 x3 = submod(submod(mulmod(m, m, SECP256K1_P), p1.x, SECP256K1_P), p2.x, SECP256K1_P);
        uint256 y3 = submod(mulmod(m, submod(p1.x, x3, SECP256K1_P), SECP256K1_P), p1.y, SECP256K1_P);
        
        return Point(x3, y3);
    }

    function addPointsSecp256r1(Point memory p1, Point memory p2) internal pure returns (Point memory) {
        if (p1.x == 0 && p1.y == 0) return p2;
        if (p2.x == 0 && p2.y == 0) return p1;
        if (p1.x == p2.x) {
            if (p1.y == p2.y) return doublePointSecp256r1(p1);
            else return Point(0, 0);
        }

        uint256 dx = submod(p2.x, p1.x, SECP256R1_P);
        uint256 dy = submod(p2.y, p1.y, SECP256R1_P);
        uint256 m = mulmod(dy, modInverse(dx, SECP256R1_P), SECP256R1_P);
        
        uint256 x3 = submod(submod(mulmod(m, m, SECP256R1_P), p1.x, SECP256R1_P), p2.x, SECP256R1_P);
        uint256 y3 = submod(mulmod(m, submod(p1.x, x3, SECP256R1_P), SECP256R1_P), p1.y, SECP256R1_P);
        
        return Point(x3, y3);
    }

    function doublePointSecp256k1(Point memory p) internal pure returns (Point memory) {
        uint256 m = mulmod(
            mulmod(3, mulmod(p.x, p.x, SECP256K1_P), SECP256K1_P),
            modInverse(mulmod(2, p.y, SECP256K1_P), SECP256K1_P),
            SECP256K1_P
        );
        
        uint256 x3 = submod(mulmod(m, m, SECP256K1_P), mulmod(2, p.x, SECP256K1_P), SECP256K1_P);
        uint256 y3 = submod(mulmod(m, submod(p.x, x3, SECP256K1_P), SECP256K1_P), p.y, SECP256K1_P);
        
        return Point(x3, y3);
    }

    function doublePointSecp256r1(Point memory p) internal pure returns (Point memory) {
        uint256 m = mulmod(
            addmod(mulmod(3, mulmod(p.x, p.x, SECP256R1_P), SECP256R1_P), SECP256R1_P - 3, SECP256R1_P),
            modInverse(mulmod(2, p.y, SECP256R1_P), SECP256R1_P),
            SECP256R1_P
        );
        
        uint256 x3 = submod(mulmod(m, m, SECP256R1_P), mulmod(2, p.x, SECP256R1_P), SECP256R1_P);
        uint256 y3 = submod(mulmod(m, submod(p.x, x3, SECP256R1_P), SECP256R1_P), p.y, SECP256R1_P);
        
        return Point(x3, y3);
    }

    function scalarMultSecp256k1(uint256 scalar, Point memory point) internal pure returns (Point memory) {
        if (scalar == 0) return Point(0, 0);
        if (scalar == 1) return point;

        Point memory result = Point(0, 0);
        Point memory addend = point;

        while (scalar > 0) {
            if (scalar & 1 == 1) {
                result = addPointsSecp256k1(result, addend);
            }
            addend = doublePointSecp256k1(addend);
            scalar >>= 1;
        }

        return result;
    }

    function scalarMultSecp256r1(uint256 scalar, Point memory point) internal pure returns (Point memory) {
        if (scalar == 0) return Point(0, 0);
        if (scalar == 1) return point;

        Point memory result = Point(0, 0);
        Point memory addend = point;

        while (scalar > 0) {
            if (scalar & 1 == 1) {
                result = addPointsSecp256r1(result, addend);
            }
            addend = doublePointSecp256r1(addend);
            scalar >>= 1;
        }

        return result;
    }

    function submod(uint256 a, uint256 b, uint256 mod) internal pure returns (uint256) {
        return addmod(a, mod - (b % mod), mod);
    }

    function modInverse(uint256 a, uint256 mod) internal pure returns (uint256) {
        return modExp(a, mod - 2, mod);
    }

    function modExp(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256 result) {
        result = 1;
        base = base % mod;
        
        while (exp > 0) {
            if (exp & 1 == 1) {
                result = mulmod(result, base, mod);
            }
            exp >>= 1;
            base = mulmod(base, base, mod);
        }
    }
}