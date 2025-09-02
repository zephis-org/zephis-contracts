// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title SecurityUtils
 * @author Zephis Protocol
 * @notice Comprehensive security utilities for cryptographic operations and validation
 * @dev Provides signature verification, hashing, validation, and cryptographic utilities
 *
 * This library implements:
 * - ECDSA signature verification and recovery
 * - EIP-712 typed data signing support
 * - Merkle proof verification
 * - Various hashing utilities with nonce/timestamp
 * - Address and data validation
 * - Commitment scheme utilities
 */
library SecurityUtils {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when signature verification fails
    error InvalidSignature();

    /// @notice Thrown when an invalid address is provided
    error InvalidAddress();

    /// @notice Thrown when an invalid hash is provided
    error InvalidHash();

    /// @notice Thrown when a replay attack is detected
    error ReplayAttack();

    /// @notice Thrown when an invalid nonce is used
    error InvalidNonce();

    /// @notice Thrown when unauthorized access is attempted
    error UnauthorizedAccess();

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Components of an ECDSA signature
     * @param v Recovery identifier (27 or 28)
     * @param r First 32 bytes of signature
     * @param s Second 32 bytes of signature
     */
    struct SignatureComponents {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /*//////////////////////////////////////////////////////////////
                         SIGNATURE VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verifies an ECDSA signature against expected signer
     * @dev Uses ecrecover to extract signer from signature
     * @param messageHash Hash of the message that was signed
     * @param signature 65-byte signature (r + s + v)
     * @param expectedSigner Address that should have signed the message
     * @return True if signature is valid and from expected signer
     */
    function verifySignature(bytes32 messageHash, bytes memory signature, address expectedSigner)
        internal
        pure
        returns (bool)
    {
        if (signature.length != 65) {
            return false;
        }

        SignatureComponents memory sig = splitSignature(signature);
        address recoveredSigner = ecrecover(messageHash, sig.v, sig.r, sig.s);

        return recoveredSigner != address(0) && recoveredSigner == expectedSigner;
    }

    /**
     * @notice Verifies signature with Ethereum signed message prefix
     * @dev Adds "\x19Ethereum Signed Message:\n32" prefix before verification
     * @param messageHash Original message hash
     * @param signature 65-byte signature
     * @param expectedSigner Expected signer address
     * @return True if signature with prefix is valid
     */
    function verifySignatureWithPrefix(bytes32 messageHash, bytes memory signature, address expectedSigner)
        internal
        pure
        returns (bool)
    {
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);
        return verifySignature(ethSignedMessageHash, signature, expectedSigner);
    }

    /**
     * @notice Splits signature bytes into r, s, v components
     * @dev Handles both v=0/1 and v=27/28 formats
     * @param signature 65-byte signature to split
     * @return SignatureComponents struct with v, r, s values
     */
    function splitSignature(bytes memory signature) internal pure returns (SignatureComponents memory) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        // Extract r, s, v from signature bytes
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        // Normalize v value to 27/28 format
        if (v < 27) {
            v += 27;
        }

        return SignatureComponents(v, r, s);
    }

    /**
     * @notice Adds Ethereum signed message prefix to hash
     * @dev Required for personal_sign compatibility
     * @param messageHash Original message hash
     * @return Hash with Ethereum prefix applied
     */
    function getEthSignedMessageHash(bytes32 messageHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
    }

    /*//////////////////////////////////////////////////////////////
                           HASHING UTILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Hashes arbitrary message bytes
     * @param message Message to hash
     * @return Keccak256 hash of the message
     */
    function hashMessage(bytes memory message) internal pure returns (bytes32) {
        return keccak256(message);
    }

    /**
     * @notice Hashes message with nonce for replay protection
     * @param message Message to hash
     * @param nonce Unique nonce value
     * @return Hash of message concatenated with nonce
     */
    function hashMessageWithNonce(bytes memory message, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(message, nonce));
    }

    /**
     * @notice Hashes message with timestamp for time-bound validity
     * @param message Message to hash
     * @param timestamp Unix timestamp
     * @return Hash of message concatenated with timestamp
     */
    function hashMessageWithTimestamp(bytes memory message, uint256 timestamp) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(message, timestamp));
    }

    /**
     * @notice Hashes message with sender address
     * @param message Message to hash
     * @param sender Sender address to include
     * @return Hash of message concatenated with sender
     */
    function hashMessageWithSender(bytes memory message, address sender) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(message, sender));
    }

    /*//////////////////////////////////////////////////////////////
                          VALIDATION UTILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates that address is not zero address
     * @param addr Address to validate
     * @return True if address is valid (non-zero)
     */
    function validateAddress(address addr) internal pure returns (bool) {
        return addr != address(0);
    }

    /**
     * @notice Validates array of addresses
     * @param addresses Array of addresses to validate
     * @return True if all addresses are valid
     */
    function validateAddresses(address[] memory addresses) internal pure returns (bool) {
        for (uint256 i = 0; i < addresses.length; i++) {
            if (!validateAddress(addresses[i])) {
                return false;
            }
        }
        return true;
    }

    /**
     * @notice Validates that hash is not zero
     * @param hash Hash to validate
     * @return True if hash is non-zero
     */
    function validateHash(bytes32 hash) internal pure returns (bool) {
        return hash != bytes32(0);
    }

    /**
     * @notice Validates array of hashes
     * @param hashes Array of hashes to validate
     * @return True if all hashes are valid
     */
    function validateHashes(bytes32[] memory hashes) internal pure returns (bool) {
        for (uint256 i = 0; i < hashes.length; i++) {
            if (!validateHash(hashes[i])) {
                return false;
            }
        }
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                         ID AND SALT GENERATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Generates salt value from sender and block number
     * @param sender Address of the sender
     * @param blockNumber Block number for uniqueness
     * @return Salt value for cryptographic operations
     */
    function generateSalt(address sender, uint256 blockNumber) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(sender, blockNumber));
    }

    /**
     * @notice Generates unique identifier from multiple parameters
     * @param sender Address of the sender
     * @param timestamp Unix timestamp
     * @param nonce Unique nonce value
     * @return Unique identifier hash
     */
    function generateUniqueId(address sender, uint256 timestamp, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(sender, timestamp, nonce));
    }

    /*//////////////////////////////////////////////////////////////
                          MERKLE TREE UTILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verifies a Merkle tree proof
     * @dev Uses sorted pair hashing to prevent second preimage attacks
     * @param proof Array of sibling hashes in the Merkle path
     * @param root Expected Merkle root
     * @param leaf Leaf node to verify
     * @return True if the proof is valid
     */
    function verifyMerkleProof(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 computedHash = leaf;

        // Traverse up the tree computing hashes
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            // Sort pairs before hashing to maintain consistency
            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        return computedHash == root;
    }

    /*//////////////////////////////////////////////////////////////
                          DATA PACKING UTILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Packs address, uint256, and bytes32 into single bytes array
     * @param addr Address to pack
     * @param value Uint256 value to pack
     * @param data Bytes32 data to pack
     * @return Packed bytes representation
     */
    function packData(address addr, uint256 value, bytes32 data) internal pure returns (bytes memory) {
        return abi.encodePacked(addr, value, data);
    }

    /**
     * @notice Unpacks bytes into address, uint256, and bytes32
     * @dev Requires exactly 84 bytes (20 + 32 + 32)
     * @param packedData Packed bytes to unpack
     * @return addr Unpacked address
     * @return value Unpacked uint256
     * @return data Unpacked bytes32
     */
    function unpackData(bytes memory packedData) internal pure returns (address addr, uint256 value, bytes32 data) {
        require(packedData.length == 84, "Invalid packed data length");

        // Extract components using assembly for gas efficiency
        assembly {
            addr := mload(add(packedData, 20))
            value := mload(add(packedData, 52))
            data := mload(add(packedData, 84))
        }
    }

    /*//////////////////////////////////////////////////////////////
                          CONTRACT DETECTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Checks if an address is a contract
     * @dev Uses extcodesize to check for deployed code
     * @param account Address to check
     * @return True if address contains contract code
     */
    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    /*//////////////////////////////////////////////////////////////
                          STRING UTILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compares two strings for equality
     * @dev Uses keccak256 hash comparison
     * @param a First string
     * @param b Second string
     * @return True if strings are equal
     */
    function compareStrings(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    /*//////////////////////////////////////////////////////////////
                          TYPE CONVERSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Converts bytes to bytes32
     * @dev Takes first 32 bytes if data is longer
     * @param data Bytes to convert
     * @return result Bytes32 representation
     */
    function toBytes32(bytes memory data) internal pure returns (bytes32 result) {
        if (data.length == 0) {
            return 0x0;
        }

        assembly {
            result := mload(add(data, 32))
        }
    }

    /**
     * @notice Converts bytes to address
     * @dev Requires at least 20 bytes
     * @param data Bytes to convert
     * @return addr Address extracted from bytes
     */
    function toAddress(bytes memory data) internal pure returns (address addr) {
        require(data.length >= 20, "Invalid address data");

        assembly {
            addr := mload(add(data, 20))
        }
    }

    /*//////////////////////////////////////////////////////////////
                          EIP-712 UTILITIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Calculates EIP-712 domain separator
     * @dev Used for typed data signing
     * @param name Domain name
     * @param version Domain version
     * @param chainId Chain ID for replay protection
     * @param verifyingContract Contract address that will verify signatures
     * @return EIP-712 domain separator hash
     */
    function calculateDomainSeparator(
        string memory name,
        string memory version,
        uint256 chainId,
        address verifyingContract
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
    }

    /**
     * @notice Verifies EIP-712 typed data signature
     * @param domainSeparator EIP-712 domain separator
     * @param structHash Hash of the typed data struct
     * @param signature Signature to verify
     * @param expectedSigner Expected signer address
     * @return True if signature is valid
     */
    function verifyEip712(bytes32 domainSeparator, bytes32 structHash, bytes memory signature, address expectedSigner)
        internal
        pure
        returns (bool)
    {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        return verifySignature(digest, signature, expectedSigner);
    }

    /*//////////////////////////////////////////////////////////////
                          TIME VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates timestamp is within acceptable range
     * @dev Checks timestamp is not future and not too old
     * @param timestamp Timestamp to validate
     * @param maxAge Maximum age in seconds
     * @return True if timestamp is valid
     */
    function validateTimestamp(uint256 timestamp, uint256 maxAge) internal view returns (bool) {
        return timestamp > 0 && timestamp <= block.timestamp && block.timestamp - timestamp <= maxAge;
    }

    /*//////////////////////////////////////////////////////////////
                        COMMITMENT SCHEME
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Generates commitment hash from secret and data
     * @dev Used for commit-reveal schemes
     * @param secret Secret value known only to committer
     * @param data Data being committed to
     * @return Commitment hash
     */
    function generateCommitment(bytes32 secret, bytes32 data) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(secret, data));
    }

    /**
     * @notice Verifies a commitment against revealed values
     * @param commitment Original commitment hash
     * @param secret Revealed secret
     * @param data Revealed data
     * @return True if commitment matches revealed values
     */
    function verifyCommitment(bytes32 commitment, bytes32 secret, bytes32 data) internal pure returns (bool) {
        return commitment == generateCommitment(secret, data);
    }
}
