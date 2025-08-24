// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library HKDF {
    error InvalidInputLength();
    error InvalidOutputLength();

    function extract(bytes32 salt, bytes memory ikm) internal pure returns (bytes32) {
        return hmacSha256(salt, ikm);
    }

    function expand(
        bytes32 prk,
        bytes memory info,
        uint256 length
    ) internal pure returns (bytes memory) {
        if (length == 0 || length > 255 * 32) revert InvalidOutputLength();

        bytes memory okm = new bytes(length);
        bytes32 t = bytes32(0);
        uint256 iterations = (length + 31) / 32;
        
        for (uint256 i = 1; i <= iterations; i++) {
            bytes memory input = abi.encodePacked(t, info, uint8(i));
            t = hmacSha256(prk, input);
            
            uint256 copyLength = (i == iterations) ? (length - (i - 1) * 32) : 32;
            for (uint256 j = 0; j < copyLength; j++) {
                okm[(i - 1) * 32 + j] = t[j];
            }
        }
        
        return okm;
    }

    function deriveKey(
        bytes32 salt,
        bytes memory ikm,
        bytes memory info,
        uint256 length
    ) internal pure returns (bytes memory) {
        bytes32 prk = extract(salt, ikm);
        return expand(prk, info, length);
    }

    function hmacSha256(bytes32 key, bytes memory data) internal pure returns (bytes32) {
        bytes32 ipad = bytes32(0x3636363636363636363636363636363636363636363636363636363636363636);
        bytes32 opad = bytes32(0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c);
        
        bytes32 innerKey = key ^ ipad;
        bytes32 outerKey = key ^ opad;
        
        bytes32 innerHash = keccak256(abi.encodePacked(innerKey, data));
        return keccak256(abi.encodePacked(outerKey, innerHash));
    }

    function tlsKdf(
        bytes32 masterSecret,
        bytes32 clientRandom,
        bytes32 serverRandom,
        bytes memory label,
        uint256 length
    ) internal pure returns (bytes memory) {
        bytes memory seed = abi.encodePacked(label, clientRandom, serverRandom);
        return prf(masterSecret, seed, length);
    }

    function prf(
        bytes32 secret,
        bytes memory seed,
        uint256 length
    ) internal pure returns (bytes memory) {
        bytes memory result = new bytes(length);
        bytes32 a = keccak256(seed);
        
        uint256 iterations = (length + 31) / 32;
        for (uint256 i = 0; i < iterations; i++) {
            bytes32 hmacResult = hmacSha256(secret, abi.encodePacked(a, seed));
            
            uint256 copyLength = (i == iterations - 1) ? (length - i * 32) : 32;
            for (uint256 j = 0; j < copyLength; j++) {
                result[i * 32 + j] = hmacResult[j];
            }
            
            a = hmacSha256(secret, abi.encodePacked(a));
        }
        
        return result;
    }
}