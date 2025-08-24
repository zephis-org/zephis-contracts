// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/registries/TrustedCAs.sol";

contract TrustedCAsTest is Test {
    TrustedCAs public trustedCAs;
    
    address public admin = address(0x1);
    address public user = address(0x2);

    function setUp() public {
        vm.prank(admin);
        trustedCAs = new TrustedCAs();
    }

    function testInitialState() public view {
        assertTrue(trustedCAs.hasRole(trustedCAs.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(trustedCAs.hasRole(trustedCAs.CA_MANAGER_ROLE(), admin));
        assertTrue(trustedCAs.hasRole(trustedCAs.CA_UPDATER_ROLE(), admin));
    }

    function testInitialCasExist() public view {
        uint256 activeCas = trustedCAs.getActiveCasCount();
        assertGt(activeCas, 0);
        
        bytes32 merkleRoot = trustedCAs.getCaMerkleRoot();
        assertTrue(merkleRoot != bytes32(0));
    }

    function testAddCa() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp;
        uint256 validUntil = block.timestamp + 365 days;

        vm.prank(admin);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);

        ITrustedCAs.CaInfo memory caInfo = trustedCAs.getCaInfo(caHash);
        assertEq(caInfo.publicKeyHash, publicKeyHash);
        assertEq(caInfo.nameHash, nameHash);
        assertEq(caInfo.validFrom, validFrom);
        assertEq(caInfo.validUntil, validUntil);
        assertTrue(caInfo.isActive);
        assertTrue(trustedCAs.isValidCaRoot(caHash));
    }

    function testAddCaInvalidHash() public {
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp;
        uint256 validUntil = block.timestamp + 365 days;

        vm.prank(admin);
        vm.expectRevert(TrustedCAsErrors.InvalidCAHash.selector);
        trustedCAs.addCa(bytes32(0), publicKeyHash, nameHash, validFrom, validUntil);
    }

    function testAddCaInvalidPublicKeyHash() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp;
        uint256 validUntil = block.timestamp + 365 days;

        vm.prank(admin);
        vm.expectRevert(TrustedCAsErrors.InvalidPublicKeyHash.selector);
        trustedCAs.addCa(caHash, bytes32(0), nameHash, validFrom, validUntil);
    }

    function testAddCaAlreadyExists() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp;
        uint256 validUntil = block.timestamp + 365 days;

        vm.startPrank(admin);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);
        
        vm.expectRevert(TrustedCAsErrors.CAAlreadyExists.selector);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);
        vm.stopPrank();
    }

    function testRevokeCa() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp;
        uint256 validUntil = block.timestamp + 365 days;

        vm.startPrank(admin);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);
        assertTrue(trustedCAs.isValidCaRoot(caHash));
        
        trustedCAs.revokeCa(caHash);
        assertFalse(trustedCAs.isValidCaRoot(caHash));
        
        ITrustedCAs.CaInfo memory caInfo = trustedCAs.getCaInfo(caHash);
        assertFalse(caInfo.isActive);
        vm.stopPrank();
    }

    function testRevokeCaNonExistent() public {
        bytes32 caHash = keccak256("Non Existent CA");

        vm.prank(admin);
        vm.expectRevert(TrustedCAsErrors.CADoesNotExist.selector);
        trustedCAs.revokeCa(caHash);
    }

    function testUpdateCaValidity() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp;
        uint256 validUntil = block.timestamp + 365 days;

        vm.startPrank(admin);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);
        
        uint256 newValidUntil = block.timestamp + 730 days;
        trustedCAs.updateCaValidity(caHash, newValidUntil);
        
        ITrustedCAs.CaInfo memory caInfo = trustedCAs.getCaInfo(caHash);
        assertEq(caInfo.validUntil, newValidUntil);
        vm.stopPrank();
    }

    function testUnauthorizedAccess() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp;
        uint256 validUntil = block.timestamp + 365 days;

        vm.prank(user);
        vm.expectRevert();
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);
    }

    function testAddCaInvalidValidityPeriodFromGreaterThanUntil() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp + 365 days;
        uint256 validUntil = block.timestamp + 100 days;

        vm.prank(admin);
        vm.expectRevert(TrustedCAsErrors.InvalidValidityPeriod.selector);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);
    }

    function testAddCaInvalidValidityPeriodPastTime() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        
        vm.warp(block.timestamp + 200 days);
        
        uint256 validFrom = block.timestamp - 100 days;
        uint256 validUntil = block.timestamp - 50 days;

        vm.prank(admin);
        vm.expectRevert(TrustedCAsErrors.InvalidValidityPeriod.selector);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);
    }

    function testAddCaInvalidValidityPeriodTooLong() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp;
        uint256 validUntil = block.timestamp + 365 days * 15;

        vm.prank(admin);
        vm.expectRevert(TrustedCAsErrors.InvalidValidityPeriod.selector);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);
    }

    function testAddCaInvalidValidityPeriodTooShort() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp;
        uint256 validUntil = block.timestamp + 10 days;

        vm.prank(admin);
        vm.expectRevert(TrustedCAsErrors.InvalidValidityPeriod.selector);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);
    }

    function testUpdateCaValidityRevokedCa() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp;
        uint256 validUntil = block.timestamp + 365 days;

        vm.startPrank(admin);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);
        trustedCAs.revokeCa(caHash);
        
        uint256 newValidUntil = block.timestamp + 730 days;
        vm.expectRevert(TrustedCAsErrors.CARevoked.selector);
        trustedCAs.updateCaValidity(caHash, newValidUntil);
        vm.stopPrank();
    }

    function testUpdateCaValidityPastTime() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp;
        uint256 validUntil = block.timestamp + 365 days;

        vm.startPrank(admin);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);
        
        vm.warp(block.timestamp + 50 days);
        uint256 newValidUntil = block.timestamp - 1 days;
        vm.expectRevert(TrustedCAsErrors.InvalidValidityPeriod.selector);
        trustedCAs.updateCaValidity(caHash, newValidUntil);
        vm.stopPrank();
    }

    function testUpdateCaValidityTooLong() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp;
        uint256 validUntil = block.timestamp + 365 days;

        vm.startPrank(admin);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);
        
        uint256 newValidUntil = block.timestamp + 365 days * 15;
        vm.expectRevert(TrustedCAsErrors.InvalidValidityPeriod.selector);
        trustedCAs.updateCaValidity(caHash, newValidUntil);
        vm.stopPrank();
    }

    function testUpdateCaValidityNonExistentCa() public {
        bytes32 caHash = keccak256("Non Existent CA");
        uint256 newValidUntil = block.timestamp + 365 days;

        vm.prank(admin);
        vm.expectRevert(TrustedCAsErrors.CADoesNotExist.selector);
        trustedCAs.updateCaValidity(caHash, newValidUntil);
    }

    function testIsValidCaRootNonExistent() public view {
        bytes32 nonExistentCa = keccak256("Non Existent CA");
        assertFalse(trustedCAs.isValidCaRoot(nonExistentCa));
    }

    function testIsValidCaRootExpired() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp;
        uint256 validUntil = block.timestamp + 100 days;

        vm.prank(admin);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);

        vm.warp(block.timestamp + 200 days);
        assertFalse(trustedCAs.isValidCaRoot(caHash));
    }

    function testIsValidCaRootNotYetValid() public {
        bytes32 caHash = keccak256("Test CA");
        bytes32 publicKeyHash = keccak256("Test Public Key");
        bytes32 nameHash = keccak256("Test CA Name");
        uint256 validFrom = block.timestamp + 100 days;
        uint256 validUntil = block.timestamp + 365 days;

        vm.prank(admin);
        trustedCAs.addCa(caHash, publicKeyHash, nameHash, validFrom, validUntil);

        assertFalse(trustedCAs.isValidCaRoot(caHash));
    }
}