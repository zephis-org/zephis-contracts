// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "./TestZKProofVerifierDirectDefault.sol";

contract ZKProofVerifierDirectDefaultTest is Test {
    TestZKProofVerifierDirectDefault public verifier;
    
    function setUp() public {
        verifier = new TestZKProofVerifierDirectDefault();
    }
    
    function testDirectDefaultCase() public view {
        bool result = verifier.testDefaultCase();
        assertFalse(result); // Should return false from the overridden default case
    }
}