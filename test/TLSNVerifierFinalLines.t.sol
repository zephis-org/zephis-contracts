// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "./TestTLSNVerifierForFinalLines.sol";

contract TLSNVerifierFinalLinesTest is Test {
    TestTLSNVerifierForFinalLines public verifier;
    
    function setUp() public {
        address initialNotary = makeAddr("initialNotary"); 
        verifier = new TestTLSNVerifierForFinalLines(initialNotary);
    }
    
    function testLine137HashMismatch() public view {
        (bool isValid, string memory reason) = verifier.testLine137();
        assertFalse(isValid);
        assertEq(reason, "Transcript hash mismatch");
    }
    
    function testLine156EmptyServerName() public view {
        (bool isValid, string memory reason) = verifier.testLine156();
        assertFalse(isValid);
        assertEq(reason, "Empty server name");
    }
}