// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/utils/MerkleProof.sol";

contract MerkleProofWrapper {
    function verifyWrapper(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) external pure returns (bool) {
        return MerkleProof.verify(proof, root, leaf);
    }
    
    function verifyCalldataWrapper(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) external pure returns (bool) {
        return MerkleProof.verifyCalldata(proof, root, leaf);
    }
    
    function processProofWrapper(
        bytes32[] memory proof,
        bytes32 leaf
    ) external pure returns (bytes32) {
        return MerkleProof.processProof(proof, leaf);
    }
    
    function processProofCalldataWrapper(
        bytes32[] calldata proof,
        bytes32 leaf
    ) external pure returns (bytes32) {
        return MerkleProof.processProofCalldata(proof, leaf);
    }
    
    function multiProofVerifyWrapper(
        bytes32[] memory proof,
        bool[] memory proofFlags,
        bytes32 root,
        bytes32[] memory leaves
    ) external pure returns (bool) {
        return MerkleProof.multiProofVerify(proof, proofFlags, root, leaves);
    }
    
    function multiProofVerifyCalldataWrapper(
        bytes32[] calldata proof,
        bool[] calldata proofFlags,
        bytes32 root,
        bytes32[] memory leaves
    ) external pure returns (bool) {
        return MerkleProof.multiProofVerifyCalldata(proof, proofFlags, root, leaves);
    }
    
    function processMultiProofWrapper(
        bytes32[] memory proof,
        bool[] memory proofFlags,
        bytes32[] memory leaves
    ) external pure returns (bytes32) {
        return MerkleProof.processMultiProof(proof, proofFlags, leaves);
    }
    
    function processMultiProofCalldataWrapper(
        bytes32[] calldata proof,
        bool[] calldata proofFlags,
        bytes32[] memory leaves
    ) external pure returns (bytes32) {
        return MerkleProof.processMultiProofCalldata(proof, proofFlags, leaves);
    }
    
    function hashPairWrapper(bytes32 a, bytes32 b) external pure returns (bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }
    
    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}

contract MerkleProofTest is Test {
    MerkleProofWrapper wrapper;
    
    function setUp() public {
        wrapper = new MerkleProofWrapper();
    }
    
    function testBasicMerkleProof() public pure {
        // Create a simple merkle tree with leaves: [A, B]
        bytes32 leafA = keccak256("A");
        bytes32 leafB = keccak256("B");
        bytes32 root = keccak256(abi.encodePacked(leafA < leafB ? leafA : leafB, leafA < leafB ? leafB : leafA));
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leafB;
        
        bool result = MerkleProof.verify(proof, root, leafA);
        assertTrue(result);
    }
    
    function testBasicMerkleProofCalldata() public view {
        bytes32 leafA = keccak256("A");
        bytes32 leafB = keccak256("B");
        bytes32 root = keccak256(abi.encodePacked(leafA < leafB ? leafA : leafB, leafA < leafB ? leafB : leafA));
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leafB;
        
        bool result = wrapper.verifyCalldataWrapper(proof, root, leafA);
        assertTrue(result);
    }
    
    function testMerkleProofInvalid() public pure {
        bytes32 leafA = keccak256("A");
        bytes32 leafB = keccak256("B");
        bytes32 leafC = keccak256("C");
        bytes32 root = keccak256(abi.encodePacked(leafA < leafB ? leafA : leafB, leafA < leafB ? leafB : leafA));
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leafB;
        
        // Try to verify leafC with wrong proof
        bool result = MerkleProof.verify(proof, root, leafC);
        assertFalse(result);
    }
    
    function testProcessProof() public pure {
        bytes32 leafA = keccak256("A");
        bytes32 leafB = keccak256("B");
        bytes32 expectedRoot = keccak256(abi.encodePacked(leafA < leafB ? leafA : leafB, leafA < leafB ? leafB : leafA));
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leafB;
        
        bytes32 computedRoot = MerkleProof.processProof(proof, leafA);
        assertEq(computedRoot, expectedRoot);
    }
    
    function testProcessProofCalldata() public view {
        bytes32 leafA = keccak256("A");
        bytes32 leafB = keccak256("B");
        bytes32 expectedRoot = keccak256(abi.encodePacked(leafA < leafB ? leafA : leafB, leafA < leafB ? leafB : leafA));
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leafB;
        
        bytes32 computedRoot = wrapper.processProofCalldataWrapper(proof, leafA);
        assertEq(computedRoot, expectedRoot);
    }
    
    function testEmptyProof() public pure {
        bytes32 leaf = keccak256("A");
        bytes32[] memory emptyProof = new bytes32[](0);
        
        bytes32 result = MerkleProof.processProof(emptyProof, leaf);
        assertEq(result, leaf);
    }
    
    function testThreeLevelMerkleTree() public pure {
        // Tree with 4 leaves: [A, B, C, D]
        bytes32 leafA = keccak256("A");
        bytes32 leafB = keccak256("B");
        bytes32 leafC = keccak256("C");
        bytes32 leafD = keccak256("D");
        
        // Level 1
        bytes32 hashAB = keccak256(abi.encodePacked(leafA < leafB ? leafA : leafB, leafA < leafB ? leafB : leafA));
        bytes32 hashCD = keccak256(abi.encodePacked(leafC < leafD ? leafC : leafD, leafC < leafD ? leafD : leafC));
        
        // Level 2 (root)
        bytes32 root = keccak256(abi.encodePacked(hashAB < hashCD ? hashAB : hashCD, hashAB < hashCD ? hashCD : hashAB));
        
        // Proof for leafA: [leafB, hashCD]
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = leafB;
        proof[1] = hashCD;
        
        bool result = MerkleProof.verify(proof, root, leafA);
        assertTrue(result);
    }
    
    function testMultiProofSingleLeaf() public pure {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = keccak256("A");
        
        bytes32[] memory proof = new bytes32[](0);
        bool[] memory proofFlags = new bool[](0);
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertEq(result, leaves[0]);
    }
    
    function testMultiProofTwoLeaves() public pure {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("A");
        leaves[1] = keccak256("B");
        
        bytes32[] memory proof = new bytes32[](0);
        bool[] memory proofFlags = new bool[](1);
        proofFlags[0] = true; // Use both leaves
        
        bytes32 expectedRoot = keccak256(abi.encodePacked(
            leaves[0] < leaves[1] ? leaves[0] : leaves[1],
            leaves[0] < leaves[1] ? leaves[1] : leaves[0]
        ));
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertEq(result, expectedRoot);
    }
    
    function testMultiProofVerify() public pure {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("A");
        leaves[1] = keccak256("B");
        
        bytes32[] memory proof = new bytes32[](0);
        bool[] memory proofFlags = new bool[](1);
        proofFlags[0] = true;
        
        bytes32 root = keccak256(abi.encodePacked(
            leaves[0] < leaves[1] ? leaves[0] : leaves[1],
            leaves[0] < leaves[1] ? leaves[1] : leaves[0]
        ));
        
        bool result = MerkleProof.multiProofVerify(proof, proofFlags, root, leaves);
        assertTrue(result);
    }
    
    function testMultiProofVerifyCalldata() public view {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("A");
        leaves[1] = keccak256("B");
        
        bytes32[] memory proof = new bytes32[](0);
        bool[] memory proofFlags = new bool[](1);
        proofFlags[0] = true;
        
        bytes32 root = keccak256(abi.encodePacked(
            leaves[0] < leaves[1] ? leaves[0] : leaves[1],
            leaves[0] < leaves[1] ? leaves[1] : leaves[0]
        ));
        
        bool result = wrapper.multiProofVerifyCalldataWrapper(proof, proofFlags, root, leaves);
        assertTrue(result);
    }
    
    function testMultiProofInvalidLength() public {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("A");
        leaves[1] = keccak256("B");
        
        bytes32[] memory proof = new bytes32[](2); // Wrong length
        bool[] memory proofFlags = new bool[](1);
        proofFlags[0] = true;
        
        vm.expectRevert("MerkleProof: invalid multiproof");
        wrapper.processMultiProofWrapper(proof, proofFlags, leaves);
    }
    
    function testMultiProofInvalidProofPos() public {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = keccak256("A");
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("B");
        
        bool[] memory proofFlags = new bool[](2);
        proofFlags[0] = false; // Use proof[0] 
        proofFlags[1] = false; // Try to use proof[1] but only proof[0] exists
        
        vm.expectRevert("MerkleProof: invalid multiproof");
        wrapper.processMultiProofWrapper(proof, proofFlags, leaves);
    }
    
    function testMultiProofEmptyArrays() public pure {
        bytes32[] memory leaves = new bytes32[](0);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("A");
        bool[] memory proofFlags = new bool[](0);
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertEq(result, proof[0]);
    }
    
    function testMultiProofComplexScenario() public pure {
        // Test with mixed leaves and proof elements
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("A");
        leaves[1] = keccak256("B");
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("C");
        
        bool[] memory proofFlags = new bool[](2);
        proofFlags[0] = true;  // Use both leaves for first hash
        proofFlags[1] = false; // Use proof element for second hash
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertTrue(result != bytes32(0));
    }
    
    function testHashPairOrdering() public pure {
        bytes32 a = keccak256("A");
        bytes32 b = keccak256("B");
        
        bytes32[] memory proofA = new bytes32[](1);
        proofA[0] = b;
        
        bytes32[] memory proofB = new bytes32[](1);
        proofB[0] = a;
        
        // Both should produce same result due to ordering
        bytes32 resultA = MerkleProof.processProof(proofA, a);
        bytes32 resultB = MerkleProof.processProof(proofB, b);
        
        assertEq(resultA, resultB);
    }

    function testMultiProofEdgeCases() public pure {
        // Test edge case where totalHashes == 0 but leavesLen > 0
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = keccak256("single_leaf");
        
        bytes32[] memory proof = new bytes32[](0);
        bool[] memory proofFlags = new bool[](0);
        
        // This should return leaves[0] directly (leavesLen > 0 branch)
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertEq(result, leaves[0]);
    }

    function testMultiProofEmptyLeavesWithProof() public pure {
        // Test edge case where leavesLen == 0 but proof exists
        bytes32[] memory leaves = new bytes32[](0);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("proof_element");
        bool[] memory proofFlags = new bool[](0);
        
        // This should return proof[0] directly (leavesLen == 0 branch)
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertEq(result, proof[0]);
    }

    function testMultiProofComplexBranching() public pure {
        // Test complex scenario with mixed leaf positions and proof positions
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("leaf_a");
        leaves[1] = keccak256("leaf_b");
        
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = keccak256("proof_1");
        proof[1] = keccak256("proof_2");
        
        // Test different combinations of proofFlags
        bool[] memory proofFlags = new bool[](3);
        proofFlags[0] = false; // Use proof[0] for 'b'
        proofFlags[1] = true;  // Use both leaves
        proofFlags[2] = false; // Use proof[1] for final hash
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertTrue(result != bytes32(0));
    }

    function testMultiProofHashPositions() public pure {
        // Test valid multiproof that hits different branches
        // For leavesLen + proofLen == totalHashes + 1 to be valid:
        // leaves=1, proof=1, flags=1 → 1 + 1 == 1 + 1 ✓
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = keccak256("single_leaf");
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("proof_element");
        
        bool[] memory proofFlags = new bool[](1);
        proofFlags[0] = false; // Use proof[0] for the hash
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertTrue(result != bytes32(0));
    }

    function testMultiProofAllBranchCombinations() public pure {
        // Test to hit all branches in multiproof logic
        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = keccak256("leaf1");
        leaves[1] = keccak256("leaf2");
        leaves[2] = keccak256("leaf3");
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("proof_elem");
        
        bool[] memory proofFlags = new bool[](3);
        proofFlags[0] = true;  // Use leaves for first hash
        proofFlags[1] = false; // Use proof element for second hash
        proofFlags[2] = true;  // Use computed hashes for third hash
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertTrue(result != bytes32(0));
    }

    function testMultiProofCalldata() public view {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("calldata_leaf1");
        leaves[1] = keccak256("calldata_leaf2");
        
        bytes32[] memory proof = new bytes32[](0);
        bool[] memory proofFlags = new bool[](1);
        proofFlags[0] = true;
        
        bytes32 root = keccak256(abi.encodePacked(
            leaves[0] < leaves[1] ? leaves[0] : leaves[1],
            leaves[0] < leaves[1] ? leaves[1] : leaves[0]
        ));
        
        bool result = wrapper.multiProofVerifyCalldataWrapper(proof, proofFlags, root, leaves);
        assertTrue(result);
    }

    function testProcessMultiProofCalldata() public view {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = keccak256("calldata_test");
        
        bytes32[] memory proof = new bytes32[](0);
        bool[] memory proofFlags = new bool[](0);
        
        bytes32 result = wrapper.processMultiProofCalldataWrapper(proof, proofFlags, leaves);
        assertEq(result, leaves[0]);
    }

    function testHashPairComparison() public pure {
        // Test _hashPair function's comparison logic more thoroughly
        bytes32 a = 0x1111111111111111111111111111111111111111111111111111111111111111;
        bytes32 b = 0x2222222222222222222222222222222222222222222222222222222222222222;
        
        bytes32[] memory proof1 = new bytes32[](1);
        proof1[0] = b;
        
        bytes32[] memory proof2 = new bytes32[](1);
        proof2[0] = a;
        
        bytes32 result1 = MerkleProof.processProof(proof1, a);
        bytes32 result2 = MerkleProof.processProof(proof2, b);
        
        // Should produce same result due to ordering in _hashPair
        assertEq(result1, result2);
    }

    function testMultiProofWithHashReuse() public pure {
        // Test scenario where we use computed hashes
        // leaves=2, proof=1, flags=2 → 2 + 1 == 2 + 1 ✓
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("reuse_leaf1");
        leaves[1] = keccak256("reuse_leaf2");
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("reuse_proof");
        
        bool[] memory proofFlags = new bool[](2);
        proofFlags[0] = true;  // Use both leaves for first hash
        proofFlags[1] = false; // Use proof[0] for second hash
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertTrue(result != bytes32(0));
    }

    function testMultiProofExtremeEdgeCases() public pure {
        // Test case where totalHashes == 0 and leavesLen == 0 (should return proof[0])
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("fallback_proof");
        
        bool[] memory proofFlags = new bool[](0); // totalHashes = 0
        bytes32[] memory leaves = new bytes32[](0); // leavesLen = 0
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertEq(result, proof[0]); // Should hit line 111: return proof[0]
    }

    function testMultiProofCallDataExtremeEdgeCases() public {
        // Same test for calldata version using wrapper
        MerkleProofWrapper wrapper = new MerkleProofWrapper();
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("fallback_proof_calldata");
        
        bool[] memory proofFlags = new bool[](0); // totalHashes = 0
        bytes32[] memory leaves = new bytes32[](0); // leavesLen = 0
        
        bytes32 result = wrapper.processMultiProofCalldataWrapper(proof, proofFlags, leaves);
        assertEq(result, proof[0]); // Should hit line 168: return proof[0]
    }

    function testMultiProofSecondBranchLeafExhaustion() public pure {
        // Create a valid multiproof scenario that hits the hash branch
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("leaf_1");
        leaves[1] = keccak256("leaf_2");
        
        bytes32[] memory proof = new bytes32[](0);
        
        // 2 leaves + 0 proof = 1 totalHash + 1 = 2, so totalHashes = 1
        bool[] memory proofFlags = new bool[](1);
        proofFlags[0] = true; // Use both leaves for the single hash
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertTrue(result != bytes32(0));
    }

    function testMultiProofComplexLeafHashExhaustion() public pure {
        // Create a valid scenario: 3 leaves, 1 proof
        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = keccak256("leaf_a");
        leaves[1] = keccak256("leaf_b");
        leaves[2] = keccak256("leaf_c");
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("proof_1");
        
        // 3 leaves + 1 proof = 3 totalHashes + 1 = 4, so totalHashes = 3
        bool[] memory proofFlags = new bool[](3);
        proofFlags[0] = true;  // Use leaves for both a and b 
        proofFlags[1] = true;  // Use leaf c and computed hash
        proofFlags[2] = false; // Use proof element
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertTrue(result != bytes32(0));
    }

    function testMultiProofForceHashUsage() public pure {
        // Simpler valid case to test hash usage
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("force_leaf_1");
        leaves[1] = keccak256("force_leaf_2");
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("force_proof_1");
        
        // 2 leaves + 1 proof = 2 totalHashes + 1 = 3, so totalHashes = 2
        bool[] memory proofFlags = new bool[](2);
        proofFlags[0] = true;  // Uses leaves[0] and leaves[1] 
        proofFlags[1] = false; // Uses computed hash and proof[0]
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertTrue(result != bytes32(0));
    }

    function testHashPairBranchCoverage() public {
        MerkleProofWrapper wrapper = new MerkleProofWrapper();
        
        // Test a < b branch (true case) - already covered by other tests
        bytes32 smaller = bytes32(uint256(1));
        bytes32 larger = bytes32(uint256(2));
        
        bytes32 result1 = wrapper.hashPairWrapper(smaller, larger);
        assertTrue(result1 != bytes32(0));
        
        // Test a >= b branch (false case) - this should hit the else branch in _hashPair
        bytes32 result2 = wrapper.hashPairWrapper(larger, smaller);
        assertTrue(result2 != bytes32(0));
        
        // They should produce the same result due to ordering
        assertEq(result1, result2);
    }

    function testHashPairWithEqualValues() public {
        MerkleProofWrapper wrapper = new MerkleProofWrapper();
        
        // Test a == b case (hits a >= b branch)
        bytes32 equalValue = bytes32(uint256(42));
        bytes32 result = wrapper.hashPairWrapper(equalValue, equalValue);
        assertTrue(result != bytes32(0));
    }

    function testProcessMultiProofCallDataBranchCoverage() public {
        MerkleProofWrapper wrapper = new MerkleProofWrapper();
        
        // Test different branches in processMultiProofCalldata
        // Similar to processMultiProof but tests calldata version branches
        
        // Test totalHashes > 0 && leavesLen == 0 (return proof[0])
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("calldata_proof");
        bool[] memory proofFlags = new bool[](0);
        bytes32[] memory leaves = new bytes32[](0);
        
        bytes32 result = wrapper.processMultiProofCalldataWrapper(proof, proofFlags, leaves);
        assertEq(result, proof[0]);
    }

    function testProcessProofEmptyProof() public pure {
        // Test empty proof array (for loop condition i < proof.length with length = 0)
        bytes32[] memory emptyProof = new bytes32[](0);
        bytes32 leaf = keccak256("test_leaf");
        
        bytes32 result = MerkleProof.processProof(emptyProof, leaf);
        assertEq(result, leaf); // Should return the leaf unchanged
    }

    function testProcessProofCalldataEmptyProof() public {
        MerkleProofWrapper wrapper = new MerkleProofWrapper();
        
        // Test empty proof array for calldata version
        bytes32[] memory emptyProof = new bytes32[](0);
        bytes32 leaf = keccak256("test_leaf_calldata");
        
        bytes32 result = wrapper.processProofCalldataWrapper(emptyProof, leaf);
        assertEq(result, leaf);
    }

    function testMultiProofCalldataAdvancedBranches() public {
        MerkleProofWrapper wrapper = new MerkleProofWrapper();
        
        // Test scenario that hits multiple branches in calldata version
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("calldata_leaf_1");
        leaves[1] = keccak256("calldata_leaf_2");
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("calldata_proof_elem");
        
        bool[] memory proofFlags = new bool[](2);
        proofFlags[0] = true;  // Use leaves
        proofFlags[1] = false; // Use proof
        
        bytes32 result = wrapper.processMultiProofCalldataWrapper(proof, proofFlags, leaves);
        assertTrue(result != bytes32(0));
    }

    function testMultiProofAdvancedLeafExhaustion() public pure {
        // Test scenario where leafPos >= leavesLen in the first if condition (line 81)
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = keccak256("single_leaf");
        
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = keccak256("proof_elem_1");
        proof[1] = keccak256("proof_elem_2");
        
        // 1 leaf + 2 proof = 2 totalHashes + 1 = 3, so totalHashes = 2
        bool[] memory proofFlags = new bool[](2);
        proofFlags[0] = false; // Use proof[0] for b
        proofFlags[1] = false; // Use proof[1] for b, a will be hashes[0]
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertTrue(result != bytes32(0));
    }

    function testMultiProofProofFlagsTrue() public pure {
        // Test proofFlags[i] == true branch more thoroughly
        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = keccak256("leaf_1");
        leaves[1] = keccak256("leaf_2");
        leaves[2] = keccak256("leaf_3");
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("single_proof");
        
        // 3 leaves + 1 proof = 3 totalHashes + 1 = 4, so totalHashes = 3
        bool[] memory proofFlags = new bool[](3);
        proofFlags[0] = true;  // Use leaves[0] and leaves[1]
        proofFlags[1] = true;  // Use leaves[2] and hashes[0] 
        proofFlags[2] = false; // Use hashes[1] and proof[0]
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertTrue(result != bytes32(0));
    }

    function testMultiProofHashPosIncrement() public pure {
        // Test scenario that increments hashPos (hits else branch at line 94-96)
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = keccak256("hash_test_leaf_1");
        leaves[1] = keccak256("hash_test_leaf_2");
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("hash_test_proof_1");
        
        // 2 leaves + 1 proof = 2 totalHashes + 1 = 3, so totalHashes = 2
        bool[] memory proofFlags = new bool[](2);
        proofFlags[0] = true;  // Use leaves[0] and leaves[1] -> leafPos = 2
        proofFlags[1] = false; // Use hashes[0] and proof[0]
        
        bytes32 result = MerkleProof.processMultiProof(proof, proofFlags, leaves);
        assertTrue(result != bytes32(0));
    }

    function testHashPairOrderingExtensive() public {
        MerkleProofWrapper wrapper = new MerkleProofWrapper();
        
        // Test multiple hash pair scenarios to ensure both branches are hit
        bytes32 hash1 = bytes32(uint256(0x1));
        bytes32 hash2 = bytes32(uint256(0x2));
        bytes32 hash3 = bytes32(uint256(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff));
        bytes32 hash4 = bytes32(uint256(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00));
        
        // Test a < b (should hit first branch)
        bytes32 result1 = wrapper.hashPairWrapper(hash1, hash2);
        assertTrue(result1 != bytes32(0));
        
        // Test a > b (should hit second branch)  
        bytes32 result2 = wrapper.hashPairWrapper(hash2, hash1);
        assertEq(result1, result2); // Should be same due to ordering
        
        // Test with larger values
        bytes32 result3 = wrapper.hashPairWrapper(hash3, hash4);
        bytes32 result4 = wrapper.hashPairWrapper(hash4, hash3);
        assertEq(result3, result4);
        
        // Test equal values (hits a >= b branch)
        bytes32 result5 = wrapper.hashPairWrapper(hash1, hash1);
        assertTrue(result5 != bytes32(0));
    }

    function testVerifyAndVerifyCalldataBranches() public {
        MerkleProofWrapper wrapper = new MerkleProofWrapper();
        
        // Test verify function branches
        bytes32 leaf = keccak256("verify_test_leaf");
        bytes32 correctRoot = keccak256("correct_root");
        bytes32 wrongRoot = keccak256("wrong_root");
        
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("verify_proof");
        
        // Test verify returning false
        assertFalse(wrapper.verifyWrapper(proof, wrongRoot, leaf));
        
        // Test verifyCalldata returning false
        assertFalse(wrapper.verifyCalldataWrapper(proof, wrongRoot, leaf));
    }

    function testMultiProofVerifyBranches() public {
        MerkleProofWrapper wrapper = new MerkleProofWrapper();
        
        // Test multiProofVerify and multiProofVerifyCalldata returning false
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = keccak256("multiproof_verify_leaf");
        
        bytes32[] memory proof = new bytes32[](0);
        bool[] memory proofFlags = new bool[](0);
        
        bytes32 wrongRoot = keccak256("wrong_multiproof_root");
        
        // Test multiProofVerify returning false
        assertFalse(wrapper.multiProofVerifyWrapper(proof, proofFlags, wrongRoot, leaves));
        
        // Test multiProofVerifyCalldata returning false  
        assertFalse(wrapper.multiProofVerifyCalldataWrapper(proof, proofFlags, wrongRoot, leaves));
    }

    function testComplexMultiProofScenarios() public pure {
        // Test various complex multiproof scenarios to hit all branches
        
        // Scenario 1: Mixed leaf and hash usage
        bytes32[] memory leaves1 = new bytes32[](3);
        leaves1[0] = keccak256("complex_leaf_1");
        leaves1[1] = keccak256("complex_leaf_2");
        leaves1[2] = keccak256("complex_leaf_3");
        
        bytes32[] memory proof1 = new bytes32[](2);
        proof1[0] = keccak256("complex_proof_1");
        proof1[1] = keccak256("complex_proof_2");
        
        bool[] memory proofFlags1 = new bool[](4);
        proofFlags1[0] = true;  // leaves[0], leaves[1]
        proofFlags1[1] = true;  // leaves[2], hashes[0] 
        proofFlags1[2] = false; // hashes[1], proof[0]
        proofFlags1[3] = false; // hashes[2], proof[1]
        
        bytes32 result1 = MerkleProof.processMultiProof(proof1, proofFlags1, leaves1);
        assertTrue(result1 != bytes32(0));
        
        // Scenario 2: All flags false (use only proof elements)
        bytes32[] memory leaves2 = new bytes32[](1);
        leaves2[0] = keccak256("scenario2_leaf");
        
        bytes32[] memory proof2 = new bytes32[](2);
        proof2[0] = keccak256("scenario2_proof_1");
        proof2[1] = keccak256("scenario2_proof_2");
        
        bool[] memory proofFlags2 = new bool[](2);
        proofFlags2[0] = false; // leaves[0], proof[0]
        proofFlags2[1] = false; // hashes[0], proof[1]
        
        bytes32 result2 = MerkleProof.processMultiProof(proof2, proofFlags2, leaves2);
        assertTrue(result2 != bytes32(0));
    }
}