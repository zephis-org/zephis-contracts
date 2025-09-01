// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MathUtils
 * @author Zephis Protocol
 * @notice Advanced mathematical operations library with overflow protection
 * @dev Provides safe arithmetic operations, advanced math functions, and utility helpers
 *
 * This library implements:
 * - Safe arithmetic operations with overflow/underflow protection
 * - Power and square root calculations
 * - Modular arithmetic operations
 * - Logarithmic functions (base 2, 10, 256)
 * - Utility functions for min/max/average
 */
library MathUtils {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when an arithmetic operation results in overflow
    error Overflow();

    /// @notice Thrown when a subtraction operation results in underflow
    error Underflow();

    /// @notice Thrown when attempting to divide by zero
    error DivisionByZero();

    /// @notice Thrown when attempting modulo operation with zero divisor
    error ModuloByZero();

    /// @notice Thrown when an invalid exponent is provided
    error InvalidExponent();

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum value for uint256 type
    uint256 constant MAX_UINT256 = type(uint256).max;

    /*//////////////////////////////////////////////////////////////
                        BASIC ARITHMETIC OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Performs safe addition of two unsigned integers
     * @dev Reverts on overflow using unchecked arithmetic for gas optimization
     * @param a First operand
     * @param b Second operand
     * @return Result of a + b
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            uint256 c = a + b;
            if (c < a) revert Overflow();
            return c;
        }
    }

    /**
     * @notice Performs safe subtraction of two unsigned integers
     * @dev Reverts if subtraction would result in negative value
     * @param a Minuend
     * @param b Subtrahend
     * @return Result of a - b
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b > a) revert Underflow();
        return a - b;
    }

    /**
     * @notice Performs safe multiplication of two unsigned integers
     * @dev Reverts on overflow, optimized for gas with early zero check
     * @param a First factor
     * @param b Second factor
     * @return Result of a * b
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        unchecked {
            uint256 c = a * b;
            if (c / a != b) revert Overflow();
            return c;
        }
    }

    /**
     * @notice Performs safe division of two unsigned integers
     * @dev Reverts when dividing by zero
     * @param a Dividend
     * @param b Divisor
     * @return Result of a / b (integer division)
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) revert DivisionByZero();
        return a / b;
    }

    /**
     * @notice Calculates modulo of two unsigned integers
     * @dev Reverts when modulo by zero
     * @param a Dividend
     * @param b Divisor
     * @return Remainder of a / b
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) revert ModuloByZero();
        return a % b;
    }

    /*//////////////////////////////////////////////////////////////
                           ADVANCED MATH OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Calculates base raised to the power of exponent
     * @dev Uses binary exponentiation for O(log n) complexity
     * @param base Base number
     * @param exponent Power to raise the base to
     * @return base^exponent with overflow protection
     */
    function pow(uint256 base, uint256 exponent) internal pure returns (uint256) {
        if (exponent == 0) return 1;
        if (base == 0) return 0;

        uint256 result = 1;
        uint256 b = base;
        uint256 e = exponent;

        // Binary exponentiation algorithm
        while (e > 0) {
            if (e & 1 == 1) {
                result = mul(result, b);
            }
            b = mul(b, b);
            e >>= 1;
        }

        return result;
    }

    /**
     * @notice Calculates integer square root of a number
     * @dev Uses Babylonian method with binary search initialization
     * @param a Number to calculate square root of
     * @return Largest integer x such that x^2 <= a
     */
    function sqrt(uint256 a) internal pure returns (uint256) {
        if (a == 0) return 0;

        // Initial approximation using binary search for the most significant bit
        uint256 result = 1;
        uint256 x = a;

        // Find the most significant bit position
        if (x >= 0x100000000000000000000000000000000) {
            x >>= 128;
            result <<= 64;
        }
        if (x >= 0x10000000000000000) {
            x >>= 64;
            result <<= 32;
        }
        if (x >= 0x100000000) {
            x >>= 32;
            result <<= 16;
        }
        if (x >= 0x10000) {
            x >>= 16;
            result <<= 8;
        }
        if (x >= 0x100) {
            x >>= 8;
            result <<= 4;
        }
        if (x >= 0x10) {
            x >>= 4;
            result <<= 2;
        }
        if (x >= 0x4) {
            result <<= 1;
        }

        // Seven iterations of Newton-Raphson method
        result = (result + a / result) >> 1;
        result = (result + a / result) >> 1;
        result = (result + a / result) >> 1;
        result = (result + a / result) >> 1;
        result = (result + a / result) >> 1;
        result = (result + a / result) >> 1;
        result = (result + a / result) >> 1;

        // Round down to the nearest integer
        uint256 roundedResult = a / result;
        return result < roundedResult ? result : roundedResult;
    }

    /*//////////////////////////////////////////////////////////////
                            UTILITY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Returns the smaller of two numbers
     * @param a First number
     * @param b Second number
     * @return The minimum value between a and b
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /**
     * @notice Returns the larger of two numbers
     * @param a First number
     * @param b Second number
     * @return The maximum value between a and b
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    /**
     * @notice Calculates average of two numbers without overflow
     * @dev Uses bitwise operations to prevent overflow: (a & b) + (a ^ b) / 2
     * @param a First number
     * @param b Second number
     * @return Average of a and b, rounded down
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // Equivalent to (a + b) / 2 but prevents overflow
        return (a & b) + ((a ^ b) >> 1);
    }

    /**
     * @notice Performs ceiling division of two numbers
     * @dev Returns the smallest integer greater than or equal to a/b
     * @param a Dividend
     * @param b Divisor
     * @return Ceiling of a/b
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) revert DivisionByZero();
        // Ceiling division formula: (a - 1) / b + 1
        return a == 0 ? 0 : (a - 1) / b + 1;
    }

    /*//////////////////////////////////////////////////////////////
                          MODULAR ARITHMETIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Calculates (a * b) mod m with full precision
     * @dev Uses EVM's native mulmod opcode for efficiency
     * @param a First factor
     * @param b Second factor
     * @param m Modulus
     * @return (a * b) mod m
     */
    function mulMod(uint256 a, uint256 b, uint256 m) internal pure returns (uint256) {
        if (m == 0) revert ModuloByZero();
        return mulmod(a, b, m);
    }

    /**
     * @notice Calculates modular multiplicative inverse
     * @dev Uses Extended Euclidean Algorithm
     * @param a Number to find inverse of
     * @param m Modulus
     * @return x such that (a * x) mod m = 1, or 0 if no inverse exists
     */
    function invMod(uint256 a, uint256 m) internal pure returns (uint256) {
        if (m == 0) revert ModuloByZero();
        if (a == 0) return 0;

        // Extended Euclidean Algorithm
        int256 t = 0;
        int256 newT = 1;
        uint256 r = m;
        uint256 newR = a;

        while (newR != 0) {
            uint256 quotient = r / newR;
            (t, newT) = (newT, t - int256(quotient) * newT);
            (r, newR) = (newR, r - quotient * newR);
        }

        // No inverse exists if gcd(a, m) != 1
        if (r > 1) return 0;

        // Make sure result is positive
        if (t < 0) t += int256(m);

        return uint256(t);
    }

    /**
     * @notice Calculates modular exponentiation (base^exponent mod modulus)
     * @dev Uses binary exponentiation with modular arithmetic
     * @param base Base number
     * @param exponent Power to raise the base to
     * @param modulus Modulus for the operation
     * @return (base^exponent) mod modulus
     */
    function modExp(uint256 base, uint256 exponent, uint256 modulus) internal pure returns (uint256) {
        if (modulus == 0) revert ModuloByZero();
        if (modulus == 1) return 0;

        uint256 result = 1;
        base = base % modulus;

        // Binary exponentiation with modular reduction
        while (exponent > 0) {
            if (exponent % 2 == 1) {
                result = mulmod(result, base, modulus);
            }
            exponent = exponent >> 1;
            base = mulmod(base, base, modulus);
        }

        return result;
    }

    /**
     * @notice Returns absolute value of a signed integer
     * @dev Handles edge case of int256.min safely
     * @param n Signed integer
     * @return Absolute value as unsigned integer
     */
    function abs(int256 n) internal pure returns (uint256) {
        unchecked {
            // Works correctly even for int256.min
            return uint256(n >= 0 ? n : -n);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          LOGARITHMIC FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Calculates floor(log2(value))
     * @dev Returns position of the most significant bit
     * @param value Number to calculate log2 of (must be > 0)
     * @return Floor of log base 2 of the value
     */
    function log2(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            // Binary search for the most significant bit
            if (value >> 128 > 0) {
                value >>= 128;
                result += 128;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 64;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 32;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 16;
            }
            if (value >> 8 > 0) {
                value >>= 8;
                result += 8;
            }
            if (value >> 4 > 0) {
                value >>= 4;
                result += 4;
            }
            if (value >> 2 > 0) {
                value >>= 2;
                result += 2;
            }
            if (value >> 1 > 0) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @notice Calculates floor(log10(value))
     * @dev Returns number of decimal digits minus 1
     * @param value Number to calculate log10 of (must be > 0)
     * @return Floor of log base 10 of the value
     */
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            // Check powers of 10 in descending order
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @notice Calculates floor(log256(value))
     * @dev Returns number of bytes needed to represent the value minus 1
     * @param value Number to calculate log256 of (must be > 0)
     * @return Floor of log base 256 of the value
     */
    function log256(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            // Each iteration checks if value occupies more than n bytes
            if (value >> 128 > 0) {
                value >>= 128;
                result += 16;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 8;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 4;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 2;
            }
            if (value >> 8 > 0) {
                result += 1;
            }
        }
        return result;
    }
}
