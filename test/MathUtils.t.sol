// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {MathUtils} from "../src/utils/MathUtils.sol";

// Wrapper contract to make library calls external for proper expectRevert handling
contract MathUtilsWrapper {
    function addWrapper(uint256 a, uint256 b) external pure returns (uint256) {
        return MathUtils.add(a, b);
    }

    function subWrapper(uint256 a, uint256 b) external pure returns (uint256) {
        return MathUtils.sub(a, b);
    }

    function mulWrapper(uint256 a, uint256 b) external pure returns (uint256) {
        return MathUtils.mul(a, b);
    }

    function divWrapper(uint256 a, uint256 b) external pure returns (uint256) {
        return MathUtils.div(a, b);
    }

    function modWrapper(uint256 a, uint256 b) external pure returns (uint256) {
        return MathUtils.mod(a, b);
    }

    function ceilDivWrapper(uint256 a, uint256 b) external pure returns (uint256) {
        return MathUtils.ceilDiv(a, b);
    }

    function modExpWrapper(uint256 base, uint256 exponent, uint256 modulus) external pure returns (uint256) {
        return MathUtils.modExp(base, exponent, modulus);
    }

    function invModWrapper(uint256 a, uint256 m) external pure returns (uint256) {
        return MathUtils.invMod(a, m);
    }

    function mulModWrapper(uint256 a, uint256 b, uint256 m) external pure returns (uint256) {
        return MathUtils.mulMod(a, b, m);
    }
}

contract MathUtilsTest is Test {
    using MathUtils for uint256;

    MathUtilsWrapper public wrapper;

    function setUp() public {
        wrapper = new MathUtilsWrapper();
    }

    function testAdd() public pure {
        assertEq(MathUtils.add(1, 2), 3);
        assertEq(MathUtils.add(0, 0), 0);
        assertEq(MathUtils.add(100, 200), 300);
    }

    function testAddOverflow() public {
        vm.expectRevert(abi.encodeWithSelector(MathUtils.Overflow.selector));
        wrapper.addWrapper(type(uint256).max, 1);
    }

    function testSub() public pure {
        assertEq(MathUtils.sub(5, 3), 2);
        assertEq(MathUtils.sub(100, 100), 0);
        assertEq(MathUtils.sub(1000, 1), 999);
    }

    function testSubUnderflow() public {
        vm.expectRevert(abi.encodeWithSelector(MathUtils.Underflow.selector));
        wrapper.subWrapper(3, 5);
    }

    function testMul() public pure {
        assertEq(MathUtils.mul(2, 3), 6);
        assertEq(MathUtils.mul(0, 100), 0);
        assertEq(MathUtils.mul(100, 0), 0);
        assertEq(MathUtils.mul(10, 20), 200);
    }

    function testMulOverflow() public {
        vm.expectRevert(abi.encodeWithSelector(MathUtils.Overflow.selector));
        wrapper.mulWrapper(type(uint256).max, 2);
    }

    function testDiv() public pure {
        assertEq(MathUtils.div(6, 2), 3);
        assertEq(MathUtils.div(100, 10), 10);
        assertEq(MathUtils.div(0, 10), 0);
        assertEq(MathUtils.div(7, 2), 3);
    }

    function testDivByZero() public {
        vm.expectRevert(abi.encodeWithSelector(MathUtils.DivisionByZero.selector));
        wrapper.divWrapper(10, 0);
    }

    function testMod() public pure {
        assertEq(MathUtils.mod(10, 3), 1);
        assertEq(MathUtils.mod(20, 5), 0);
        assertEq(MathUtils.mod(0, 5), 0);
        assertEq(MathUtils.mod(7, 2), 1);
    }

    function testModByZero() public {
        vm.expectRevert(abi.encodeWithSelector(MathUtils.ModuloByZero.selector));
        wrapper.modWrapper(10, 0);
    }

    function testPow() public pure {
        assertEq(MathUtils.pow(2, 3), 8);
        assertEq(MathUtils.pow(10, 2), 100);
        assertEq(MathUtils.pow(5, 0), 1);
        assertEq(MathUtils.pow(0, 5), 0);
        assertEq(MathUtils.pow(1, 100), 1);
    }

    function testSqrt() public pure {
        assertEq(MathUtils.sqrt(0), 0);
        assertEq(MathUtils.sqrt(1), 1);
        assertEq(MathUtils.sqrt(4), 2);
        assertEq(MathUtils.sqrt(9), 3);
        assertEq(MathUtils.sqrt(16), 4);
        assertEq(MathUtils.sqrt(25), 5);
        assertEq(MathUtils.sqrt(100), 10);
        assertEq(MathUtils.sqrt(10000), 100);
    }

    function testSqrtNonPerfectSquares() public pure {
        assertEq(MathUtils.sqrt(2), 1);
        assertEq(MathUtils.sqrt(3), 1);
        assertEq(MathUtils.sqrt(5), 2);
        assertEq(MathUtils.sqrt(10), 3);
        assertEq(MathUtils.sqrt(99), 9);
    }

    function testMin() public pure {
        assertEq(MathUtils.min(1, 2), 1);
        assertEq(MathUtils.min(100, 50), 50);
        assertEq(MathUtils.min(0, 1), 0);
        assertEq(MathUtils.min(5, 5), 5);
    }

    function testMax() public pure {
        assertEq(MathUtils.max(1, 2), 2);
        assertEq(MathUtils.max(100, 50), 100);
        assertEq(MathUtils.max(0, 1), 1);
        assertEq(MathUtils.max(5, 5), 5);
    }

    function testAverage() public pure {
        assertEq(MathUtils.average(2, 4), 3);
        assertEq(MathUtils.average(0, 10), 5);
        assertEq(MathUtils.average(1, 1), 1);
        assertEq(MathUtils.average(3, 4), 3);
        assertEq(MathUtils.average(10, 20), 15);
    }

    function testCeilDiv() public pure {
        assertEq(MathUtils.ceilDiv(0, 5), 0);
        assertEq(MathUtils.ceilDiv(1, 1), 1);
        assertEq(MathUtils.ceilDiv(10, 3), 4);
        assertEq(MathUtils.ceilDiv(9, 3), 3);
        assertEq(MathUtils.ceilDiv(11, 3), 4);
    }

    function testCeilDivByZero() public {
        vm.expectRevert(abi.encodeWithSelector(MathUtils.DivisionByZero.selector));
        wrapper.ceilDivWrapper(10, 0);
    }

    function testModExp() public pure {
        assertEq(MathUtils.modExp(2, 3, 5), 3);
        assertEq(MathUtils.modExp(3, 4, 7), 4);
        assertEq(MathUtils.modExp(10, 2, 13), 9);
        assertEq(MathUtils.modExp(2, 10, 1000), 24);
    }

    function testModExpWithZeroMod() public {
        vm.expectRevert(abi.encodeWithSelector(MathUtils.ModuloByZero.selector));
        wrapper.modExpWrapper(2, 3, 0);
    }

    function testModExpWithModOne() public pure {
        assertEq(MathUtils.modExp(2, 3, 1), 0);
        assertEq(MathUtils.modExp(100, 50, 1), 0);
    }

    function testAbs() public pure {
        assertEq(MathUtils.abs(5), 5);
        assertEq(MathUtils.abs(-5), 5);
        assertEq(MathUtils.abs(0), 0);
        assertEq(MathUtils.abs(int256(type(int256).max)), uint256(type(int256).max));
    }

    function testLog2() public pure {
        assertEq(MathUtils.log2(1), 0);
        assertEq(MathUtils.log2(2), 1);
        assertEq(MathUtils.log2(4), 2);
        assertEq(MathUtils.log2(8), 3);
        assertEq(MathUtils.log2(256), 8);
        assertEq(MathUtils.log2(1024), 10);
    }

    function testLog10() public pure {
        assertEq(MathUtils.log10(1), 0);
        assertEq(MathUtils.log10(10), 1);
        assertEq(MathUtils.log10(100), 2);
        assertEq(MathUtils.log10(1000), 3);
        assertEq(MathUtils.log10(10000), 4);
    }

    function testLog256() public pure {
        assertEq(MathUtils.log256(1), 0);
        assertEq(MathUtils.log256(256), 1);
        assertEq(MathUtils.log256(256 ** 2), 2);
        assertEq(MathUtils.log256(256 ** 3), 3);
    }

    function testInvMod() public pure {
        assertEq(MathUtils.invMod(3, 7), 5);
        assertEq(MathUtils.invMod(0, 7), 0);

        uint256 a = 17;
        uint256 m = 23;
        uint256 inv = MathUtils.invMod(a, m);
        assertEq((a * inv) % m, 1);
    }

    function testInvModWithZeroModulus() public {
        vm.expectRevert(abi.encodeWithSelector(MathUtils.ModuloByZero.selector));
        wrapper.invModWrapper(3, 0);
    }

    function testFuzzAdd(uint256 a, uint256 b) public {
        unchecked {
            uint256 sum = a + b;
            if (sum >= a && sum >= b) {
                assertEq(MathUtils.add(a, b), sum);
            } else {
                vm.expectRevert(abi.encodeWithSelector(MathUtils.Overflow.selector));
                wrapper.addWrapper(a, b);
            }
        }
    }

    function testFuzzSub(uint256 a, uint256 b) public {
        if (a >= b) {
            assertEq(MathUtils.sub(a, b), a - b);
        } else {
            vm.expectRevert(abi.encodeWithSelector(MathUtils.Underflow.selector));
            wrapper.subWrapper(a, b);
        }
    }

    function testFuzzMul(uint256 a, uint256 b) public {
        if (a == 0 || b == 0) {
            assertEq(MathUtils.mul(a, b), 0);
        } else {
            unchecked {
                uint256 product = a * b;
                if (product / a == b) {
                    assertEq(MathUtils.mul(a, b), product);
                } else {
                    vm.expectRevert(abi.encodeWithSelector(MathUtils.Overflow.selector));
                    wrapper.mulWrapper(a, b);
                }
            }
        }
    }

    function testFuzzDiv(uint256 a, uint256 b) public {
        if (b == 0) {
            vm.expectRevert(abi.encodeWithSelector(MathUtils.DivisionByZero.selector));
            wrapper.divWrapper(a, b);
        } else {
            assertEq(MathUtils.div(a, b), a / b);
        }
    }

    function testFuzzMinMax(uint256 a, uint256 b) public pure {
        assertEq(MathUtils.min(a, b), a < b ? a : b);
        assertEq(MathUtils.max(a, b), a > b ? a : b);
    }

    function testFuzzSqrt(uint256 a) public pure {
        uint256 result = MathUtils.sqrt(a);
        assertTrue(result * result <= a);
        if (result < type(uint256).max) {
            unchecked {
                uint256 nextSquare = (result + 1) * (result + 1);
                assertTrue(nextSquare > a || nextSquare < result * result);
            }
        }
    }

    // Additional coverage tests merged from MathUtilsCoverage.t.sol

    // Test all edge cases for 100% coverage
    function testPowWithZeroBase() public pure {
        assertEq(MathUtils.pow(0, 0), 1); // 0^0 = 1
        assertEq(MathUtils.pow(0, 1), 0);
        assertEq(MathUtils.pow(0, 10), 0);
    }

    function testPowWithZeroExponent() public pure {
        assertEq(MathUtils.pow(1, 0), 1);
        assertEq(MathUtils.pow(10, 0), 1);
        assertEq(MathUtils.pow(100, 0), 1);
    }

    function testSqrtLargeNumbers() public pure {
        // Test various branches in sqrt
        assertEq(MathUtils.sqrt(0x100000000000000000000000000000000), 0x10000000000000000);
        assertEq(MathUtils.sqrt(0x10000000000000000), 0x100000000);
        assertEq(MathUtils.sqrt(0x100000000), 0x10000);
        assertEq(MathUtils.sqrt(0x10000), 0x100);
        assertEq(MathUtils.sqrt(0x100), 0x10);
        assertEq(MathUtils.sqrt(0x10), 0x4);
        assertEq(MathUtils.sqrt(0x4), 0x2);
        assertEq(MathUtils.sqrt(0x3), 0x1);
    }

    function testLog2EdgeCases() public pure {
        assertEq(MathUtils.log2(1), 0);
        assertEq(MathUtils.log2(2), 1);
        assertEq(MathUtils.log2(3), 1);
        assertEq(MathUtils.log2(4), 2);
        assertEq(MathUtils.log2(type(uint128).max), 127);
        assertEq(MathUtils.log2(type(uint256).max), 255);
    }

    function testLog10EdgeCases() public pure {
        assertEq(MathUtils.log10(1), 0);
        assertEq(MathUtils.log10(9), 0);
        assertEq(MathUtils.log10(10), 1);
        assertEq(MathUtils.log10(99), 1);
        assertEq(MathUtils.log10(100), 2);
        assertEq(MathUtils.log10(10 ** 64), 64);
    }

    function testLog256EdgeCases() public pure {
        assertEq(MathUtils.log256(1), 0);
        assertEq(MathUtils.log256(255), 0);
        assertEq(MathUtils.log256(256), 1);
        assertEq(MathUtils.log256(256 ** 2), 2);
        assertEq(MathUtils.log256(256 ** 30), 30);
        assertEq(MathUtils.log256(type(uint256).max), 31);
    }

    function testAbsWithNegativeNumbers() public pure {
        assertEq(MathUtils.abs(int256(0)), 0);
        assertEq(MathUtils.abs(int256(42)), 42);
        assertEq(MathUtils.abs(-int256(42)), 42);
        assertEq(MathUtils.abs(type(int256).max), uint256(type(int256).max));
    }

    function testAverageEdgeCases() public pure {
        assertEq(MathUtils.average(0, 0), 0);
        assertEq(MathUtils.average(type(uint256).max, 0), type(uint256).max / 2);
        assertEq(MathUtils.average(type(uint256).max, type(uint256).max), type(uint256).max);
        assertEq(MathUtils.average(10, 20), 15);
        assertEq(MathUtils.average(11, 21), 16);
    }

    function testCeilDivEdgeCases() public pure {
        assertEq(MathUtils.ceilDiv(0, 1), 0);
        assertEq(MathUtils.ceilDiv(1, 1), 1);
        assertEq(MathUtils.ceilDiv(2, 1), 2);
        assertEq(MathUtils.ceilDiv(1, 2), 1);
        assertEq(MathUtils.ceilDiv(3, 2), 2);
        assertEq(MathUtils.ceilDiv(type(uint256).max, type(uint256).max), 1);
    }

    function testInvModEdgeCases() public pure {
        assertEq(MathUtils.invMod(1, 2), 1);
        assertEq(MathUtils.invMod(1, 3), 1);
        assertEq(MathUtils.invMod(2, 3), 2);
        assertEq(MathUtils.invMod(3, 7), 5);
        assertEq(MathUtils.invMod(5, 13), 8);
    }

    function testModExpEdgeCases() public pure {
        assertEq(MathUtils.modExp(0, 1, 7), 0);
        assertEq(MathUtils.modExp(5, 0, 7), 1);
        assertEq(MathUtils.modExp(2, 3, 1), 0);
        assertEq(MathUtils.modExp(2, 3, 5), 3);
        assertEq(MathUtils.modExp(3, 4, 7), 4);
    }

    function testPowLoopIterations() public pure {
        // Test pow with different iteration counts
        assertEq(MathUtils.pow(2, 1), 2);
        assertEq(MathUtils.pow(2, 2), 4);
        assertEq(MathUtils.pow(2, 3), 8);
        assertEq(MathUtils.pow(2, 10), 1024);
        assertEq(MathUtils.pow(3, 5), 243);
        assertEq(MathUtils.pow(5, 3), 125);
    }

    function testSqrtRoundingEdges() public pure {
        // Test sqrt with values that test rounding
        assertEq(MathUtils.sqrt(0), 0);
        assertEq(MathUtils.sqrt(1), 1);
        assertEq(MathUtils.sqrt(2), 1);
        assertEq(MathUtils.sqrt(3), 1);
        assertEq(MathUtils.sqrt(4), 2);
        assertEq(MathUtils.sqrt(8), 2);
        assertEq(MathUtils.sqrt(9), 3);
        assertEq(MathUtils.sqrt(15), 3);
        assertEq(MathUtils.sqrt(16), 4);
    }

    function testAllLogBranches() public pure {
        // Test to ensure all branches in log functions are covered
        uint256 val = 1;
        assertEq(MathUtils.log2(val), 0);
        assertEq(MathUtils.log10(val), 0);
        assertEq(MathUtils.log256(val), 0);

        val = type(uint256).max;
        assertEq(MathUtils.log2(val), 255);
        assertEq(MathUtils.log10(val), 77);
        assertEq(MathUtils.log256(val), 31);
    }

    // Tests to achieve 100% coverage - missing overflow and edge case branches

    function testAddOverflowBranchDetection() public {
        // Test line 15 overflow detection: if (c < a) revert Overflow()
        // Use wrapper to test the revert - Solidity 0.8+ automatically reverts on overflow
        vm.expectRevert(abi.encodeWithSelector(MathUtils.Overflow.selector));
        wrapper.addWrapper(type(uint256).max, 1);

        vm.expectRevert(abi.encodeWithSelector(MathUtils.Overflow.selector));
        wrapper.addWrapper(type(uint256).max - 1, 2);
    }

    function testMulOverflowBranchDetection() public {
        // Test line 27 overflow detection: if (c / a != b) revert Overflow()
        // Test a specific case that will trigger the overflow check

        // First test: max value times 2
        vm.expectRevert(abi.encodeWithSelector(MathUtils.Overflow.selector));
        wrapper.mulWrapper(type(uint256).max, 2);

        // Second test: large numbers that multiply to overflow
        uint256 largeA = type(uint256).max / 3;
        uint256 largeB = 4; // This should cause overflow
        vm.expectRevert(abi.encodeWithSelector(MathUtils.Overflow.selector));
        wrapper.mulWrapper(largeA, largeB);
    }

    function testMulModZeroModulusBranch() public {
        // Test line 124 zero modulus branch: if (modulus == 0) revert ModuloByZero()
        vm.expectRevert(abi.encodeWithSelector(MathUtils.ModuloByZero.selector));
        wrapper.mulModWrapper(5, 3, 0);

        vm.expectRevert(abi.encodeWithSelector(MathUtils.ModuloByZero.selector));
        wrapper.mulModWrapper(type(uint256).max, type(uint256).max, 0);
    }

    function testLog10MissingBranches() public pure {
        // Test the uncovered branches in log10 function (lines 219-220, 223-224)
        // These branches are for values >= 10^x but < 10^(x+1)

        // Test values that trigger different branches
        uint256 val1 = 10 ** 18; // Exactly 10^18
        assertEq(MathUtils.log10(val1), 18);

        uint256 val2 = 10 ** 36; // Exactly 10^36
        assertEq(MathUtils.log10(val2), 36);

        uint256 val3 = 10 ** 54; // Exactly 10^54
        assertEq(MathUtils.log10(val3), 54);

        uint256 val4 = 10 ** 72; // Exactly 10^72
        assertEq(MathUtils.log10(val4), 72);

        // Test values just below the thresholds to trigger the missing branches
        uint256 val5 = 10 ** 18 - 1; // Just below 10^18
        assertEq(MathUtils.log10(val5), 17);

        uint256 val6 = 10 ** 36 - 1; // Just below 10^36
        assertEq(MathUtils.log10(val6), 35);
    }

    function testAdditionalEdgeCasesFor100Coverage() public pure {
        // Test pow with edge case: base = 1 with large exponent
        assertEq(MathUtils.pow(1, type(uint256).max), 1);

        // Test ceilDiv with edge cases
        assertEq(MathUtils.ceilDiv(type(uint256).max, type(uint256).max), 1);
        assertEq(MathUtils.ceilDiv(type(uint256).max - 1, type(uint256).max), 1);

        // Test invMod with edge cases
        assertEq(MathUtils.invMod(1, type(uint256).max), 1);

        // Test modExp with edge cases
        assertEq(MathUtils.modExp(type(uint256).max, 0, type(uint256).max), 1);
        assertEq(MathUtils.modExp(0, type(uint256).max, type(uint256).max), 0);
    }
}
