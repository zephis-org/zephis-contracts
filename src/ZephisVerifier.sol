// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {MathUtils} from "./utils/MathUtils.sol";
import {SecurityUtils} from "./utils/SecurityUtils.sol";

/**
 * @title ZephisVerifier
 * @author Zephis Protocol
 * @notice Production-ready zk-SNARK verifier for privacy-preserving proof verification
 * @dev Implements Groth16 proof verification using BN254 elliptic curve pairings.
 *      This contract enables trustless verification of zero-knowledge proofs,
 *      ensuring data privacy while maintaining cryptographic integrity.
 * @custom:security-contact security@zephis.io
 */
contract ZephisVerifier {
    using MathUtils for uint256;
    using SecurityUtils for bytes32;

    // ══════════════════════════════════════════════════════════════════════════════
    //                                  DATA STRUCTURES
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Groth16 proof data structure
     * @dev Contains three elliptic curve points (πA, πB, πC) that constitute the proof
     * @param a G1 point representing πA
     * @param b G2 point representing πB (2x2 array for x and y coordinates)
     * @param c G1 point representing πC
     */
    struct ProofData {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    /**
     * @notice Public inputs structure for proof verification
     * @dev All inputs are hashed and used in the verification equation
     * @param sessionHash Unique identifier for the verification session
     * @param claimHash Cryptographic commitment to the claim being proved
     * @param timestamp Unix timestamp when the proof was generated
     * @param issuer Address of the entity that issued the original claim
     */
    struct PublicInputs {
        bytes32 sessionHash;
        bytes32 claimHash;
        uint256 timestamp;
        address issuer;
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //                                    CONSTANTS
    // ══════════════════════════════════════════════════════════════════════════════

    /// @notice BN254 curve field modulus (p)
    /// @dev Prime field modulus for the BN254 elliptic curve
    uint256 public immutable P;

    /// @notice BN254 curve group order (q)
    /// @dev Order of the elliptic curve group for BN254
    uint256 public immutable Q;

    /// @notice Contract deployment timestamp for tracking contract age
    uint256 public immutable SETUP_TIMESTAMP;

    // ══════════════════════════════════════════════════════════════════════════════
    //                                 STATE VARIABLES
    // ══════════════════════════════════════════════════════════════════════════════

    /// @notice Contract owner with administrative privileges
    address public owner;

    /// @notice Contract version for upgrade tracking
    string public version = "1.0.0";

    /// @notice Emergency pause state
    bool public paused;

    /// @notice Default validity period for proofs (24 hours)
    uint256 public proofValidityPeriod = 24 hours;

    /// @notice Maximum age for accepting proofs (12 hours)
    uint256 public maxProofAge = 12 hours;

    // ══════════════════════════════════════════════════════════════════════════════
    //                              VERIFICATION KEYS
    // ══════════════════════════════════════════════════════════════════════════════

    /// @notice G2 verification key component
    uint256[4] public vkG2;

    /// @notice G1 verification key component
    uint256[2] public vkG1;

    /// @notice Alpha verification key (G2 point)
    uint256[4] public vkAlpha;

    /// @notice Beta verification key (G2 point)
    uint256[4] public vkBeta;

    // ══════════════════════════════════════════════════════════════════════════════
    //                                   METRICS
    // ══════════════════════════════════════════════════════════════════════════════

    /// @notice Total number of successfully verified proofs
    uint256 public totalProofsVerified;

    /// @notice Total number of failed verification attempts
    uint256 public totalFailedVerifications;

    /// @notice Track verification count per address
    mapping(address => uint256) public verifierProofCount;

    /// @notice Prevent replay attacks by tracking processed proofs
    mapping(bytes32 => bool) public processedProofs;

    // ══════════════════════════════════════════════════════════════════════════════
    //                                    EVENTS
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Emitted when a proof is successfully verified
     * @param sessionHash Unique session identifier
     * @param claimHash Hash of the verified claim
     * @param verifier Address that performed the verification
     * @param timestamp Time of verification
     */
    event ProofVerified(
        bytes32 indexed sessionHash, bytes32 indexed claimHash, address indexed verifier, uint256 timestamp
    );

    /**
     * @notice Emitted when verification keys are updated
     * @param owner Address that updated the keys
     * @param timestamp Time of update
     */
    event VerificationKeyUpdated(address indexed owner, uint256 timestamp);

    /**
     * @notice Emitted when contract is paused
     * @param owner Address that paused the contract
     * @param timestamp Time of pause
     */
    event ContractPaused(address indexed owner, uint256 timestamp);

    /**
     * @notice Emitted when contract is unpaused
     * @param owner Address that unpaused the contract
     * @param timestamp Time of unpause
     */
    event ContractUnpaused(address indexed owner, uint256 timestamp);

    /**
     * @notice Emitted when ownership is transferred
     * @param previousOwner Previous owner address
     * @param newOwner New owner address
     */
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @notice Emitted when proof validity period is updated
     * @param oldPeriod Previous validity period
     * @param newPeriod New validity period
     */
    event ProofValidityPeriodUpdated(uint256 oldPeriod, uint256 newPeriod);

    /**
     * @notice Emitted when maximum proof age is updated
     * @param oldMaxAge Previous maximum age
     * @param newMaxAge New maximum age
     */
    event MaxProofAgeUpdated(uint256 oldMaxAge, uint256 newMaxAge);

    // ══════════════════════════════════════════════════════════════════════════════
    //                                 CUSTOM ERRORS
    // ══════════════════════════════════════════════════════════════════════════════

    /// @notice Thrown when proof elements exceed field modulus
    error InvalidProofLength();

    /// @notice Thrown when public inputs are malformed
    error InvalidPublicInputs();

    /// @notice Thrown when proof verification fails
    error ProofVerificationFailed();

    /// @notice Thrown when proof exceeds validity period
    error StaleProof();

    /// @notice Thrown when caller lacks required permissions
    error Unauthorized();

    /// @notice Thrown when verification key is invalid
    error InvalidVerificationKey();

    /// @notice Thrown when proof is older than maximum age
    error ProofTooOld();

    /// @notice Thrown when proof structure validation fails
    error InvalidProofStructure();

    /// @notice Thrown when pairing check fails
    error PairingCheckFailed();

    /// @notice Thrown when verification keys are not initialized
    error VerificationKeysNotSet();

    // ══════════════════════════════════════════════════════════════════════════════
    //                                  MODIFIERS
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Restricts function access to contract owner
     */
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    /**
     * @notice Prevents function execution when contract is paused
     */
    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //                                 CONSTRUCTOR
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Initialize the verifier contract
     * @param _owner Address to be set as contract owner
     * @param _fieldModulus Prime field modulus for the elliptic curve
     * @param _groupOrder Order of the elliptic curve group
     * @dev Validates parameters and sets immutable curve constants
     */
    constructor(address _owner, uint256 _fieldModulus, uint256 _groupOrder) {
        if (_owner == address(0)) revert InvalidPublicInputs();
        if (_fieldModulus == 0 || _groupOrder == 0) revert InvalidPublicInputs();
        owner = _owner;
        P = _fieldModulus;
        Q = _groupOrder;
        SETUP_TIMESTAMP = block.timestamp;
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //                           EXTERNAL FUNCTIONS - VERIFICATION
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Verify a zk-SNARK proof with default validity period
     * @param proof The Groth16 proof to verify
     * @param inputs Public inputs for the proof
     * @return success True if verification succeeds
     * @dev Performs comprehensive validation before pairing check
     */
    function verifyProof(ProofData calldata proof, PublicInputs calldata inputs)
        external
        whenNotPaused
        returns (bool success)
    {
        _requireVerificationKeysSet();
        _validateInputs(inputs);
        _validateProofAge(inputs.timestamp, proofValidityPeriod);
        _validateProofStructure(proof);

        bytes32 proofHash = keccak256(abi.encode(proof, inputs));
        if (processedProofs[proofHash]) revert ProofVerificationFailed();

        success = _verifyPairing(proof, inputs);
        if (!success) {
            totalFailedVerifications++;
            revert ProofVerificationFailed();
        }

        processedProofs[proofHash] = true;
        totalProofsVerified++;
        verifierProofCount[msg.sender]++;

        emit ProofVerified(inputs.sessionHash, inputs.claimHash, msg.sender, inputs.timestamp);
        return true;
    }

    /**
     * @notice Verify a proof with custom validity period
     * @param proof The Groth16 proof to verify
     * @param inputs Public inputs for the proof
     * @param validityPeriod Custom validity period in seconds
     * @return success True if verification succeeds
     * @dev Allows flexible validity periods for different use cases
     */
    function verifyProofWithCustomValidity(
        ProofData calldata proof,
        PublicInputs calldata inputs,
        uint256 validityPeriod
    ) external whenNotPaused returns (bool success) {
        _requireVerificationKeysSet();
        _validateInputs(inputs);
        _validateProofAge(inputs.timestamp, validityPeriod);
        _validateProofStructure(proof);

        bytes32 proofHash = keccak256(abi.encode(proof, inputs));
        if (processedProofs[proofHash]) revert ProofVerificationFailed();

        success = _verifyPairing(proof, inputs);
        if (!success) {
            totalFailedVerifications++;
            revert ProofVerificationFailed();
        }

        processedProofs[proofHash] = true;
        totalProofsVerified++;
        verifierProofCount[msg.sender]++;

        emit ProofVerified(inputs.sessionHash, inputs.claimHash, msg.sender, inputs.timestamp);
        return true;
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //                          EXTERNAL FUNCTIONS - ADMIN
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Update verification keys for proof validation
     * @param newVkG2 New G2 verification key components
     * @param newVkG1 New G1 verification key components
     * @param newVkAlpha New alpha verification key
     * @param newVkBeta New beta verification key
     * @dev Only callable by owner, validates all key components
     */
    function updateVerificationKey(
        uint256[4] calldata newVkG2,
        uint256[2] calldata newVkG1,
        uint256[4] calldata newVkAlpha,
        uint256[4] calldata newVkBeta
    ) external onlyOwner {
        _validateVerificationKey(newVkG2, newVkG1, newVkAlpha, newVkBeta);

        vkG2 = newVkG2;
        vkG1 = newVkG1;
        vkAlpha = newVkAlpha;
        vkBeta = newVkBeta;

        emit VerificationKeyUpdated(msg.sender, block.timestamp);
    }

    /**
     * @notice Transfer contract ownership
     * @param newOwner Address of the new owner
     * @dev Validates new owner address before transfer
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid address");
        address previousOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    /**
     * @notice Update proof validity period
     * @param newPeriod New validity period in seconds
     * @dev Must be between 1 second and 7 days
     */
    function updateProofValidityPeriod(uint256 newPeriod) external onlyOwner {
        require(newPeriod > 0 && newPeriod <= 7 days, "Invalid validity period");
        uint256 oldPeriod = proofValidityPeriod;
        proofValidityPeriod = newPeriod;
        emit ProofValidityPeriodUpdated(oldPeriod, newPeriod);
    }

    /**
     * @notice Update maximum proof age
     * @param newMaxAge New maximum age in seconds
     * @dev Must be positive and not exceed validity period
     */
    function updateMaxProofAge(uint256 newMaxAge) external onlyOwner {
        require(newMaxAge > 0 && newMaxAge <= proofValidityPeriod, "Invalid max proof age");
        uint256 oldMaxAge = maxProofAge;
        maxProofAge = newMaxAge;
        emit MaxProofAgeUpdated(oldMaxAge, newMaxAge);
    }

    /**
     * @notice Update contract version string
     * @param newVersion New version identifier
     * @dev For tracking contract upgrades and migrations
     */
    function updateVersion(string calldata newVersion) external onlyOwner {
        version = newVersion;
    }

    /**
     * @notice Pause contract operations
     * @dev Emergency stop mechanism for security incidents
     */
    function pause() external onlyOwner {
        paused = true;
        emit ContractPaused(msg.sender, block.timestamp);
    }

    /**
     * @notice Resume contract operations
     * @dev Re-enables contract after pause
     */
    function unpause() external onlyOwner {
        paused = false;
        emit ContractUnpaused(msg.sender, block.timestamp);
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //                           EXTERNAL VIEW FUNCTIONS
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Calculate proof expiry timestamp
     * @param inputs Public inputs containing proof timestamp
     * @return expiryTime Timestamp when proof expires
     */
    function getProofExpiryTime(PublicInputs calldata inputs) external view returns (uint256 expiryTime) {
        return inputs.timestamp + proofValidityPeriod;
    }

    /**
     * @notice Check if a proof has expired
     * @param inputs Public inputs containing proof timestamp
     * @return expired True if proof is past validity period
     */
    function isProofExpired(PublicInputs calldata inputs) external view returns (bool expired) {
        return block.timestamp > inputs.timestamp + proofValidityPeriod;
    }

    /**
     * @notice Check if verification keys are properly initialized
     * @return initialized True if all keys are set
     */
    function areVerificationKeysSet() external view returns (bool initialized) {
        for (uint256 i = 0; i < 4; i++) {
            if (vkG2[i] == 0 || vkAlpha[i] == 0 || vkBeta[i] == 0) {
                return false;
            }
        }
        for (uint256 i = 0; i < 2; i++) {
            if (vkG1[i] == 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * @notice Validate proof structure without performing verification
     * @param proof Proof to validate
     * @return valid True if structure is valid
     */
    function validateProofStructure(ProofData calldata proof) external view returns (bool valid) {
        return _validateProofStructureInternal(proof);
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //                           EXTERNAL PURE FUNCTIONS
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Generate deterministic hash of proof data
     * @param proof Proof to hash
     * @return proofHash Keccak256 hash of proof elements
     */
    function hashProof(ProofData calldata proof) external pure returns (bytes32 proofHash) {
        return keccak256(abi.encode(proof.a, proof.b, proof.c));
    }

    /**
     * @notice Generate deterministic hash of public inputs
     * @param inputs Inputs to hash
     * @return inputHash Keccak256 hash of all inputs
     */
    function hashPublicInputs(PublicInputs calldata inputs) external pure returns (bytes32 inputHash) {
        return keccak256(abi.encode(inputs.sessionHash, inputs.claimHash, inputs.timestamp, inputs.issuer));
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //                            INTERNAL FUNCTIONS
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @dev Core pairing verification logic
     */
    function _verifyPairing(ProofData calldata proof, PublicInputs calldata inputs) internal view returns (bool) {
        uint256[8] memory points = _formatProofForVerification(proof);
        uint256[4] memory publicSignals = _formatPublicInputs(inputs);
        return _performPairingCheck(points, publicSignals);
    }

    /**
     * @dev Format proof elements for pairing check
     */
    function _formatProofForVerification(ProofData calldata proof) internal view returns (uint256[8] memory points) {
        points[0] = proof.a[0];
        points[1] = proof.a[1];
        points[2] = proof.b[0][0];
        points[3] = proof.b[0][1];
        points[4] = proof.b[1][0];
        points[5] = proof.b[1][1];
        points[6] = proof.c[0];
        points[7] = proof.c[1];

        for (uint256 i = 0; i < 8; i++) {
            if (points[i] >= P) revert InvalidProofLength();
        }
    }

    /**
     * @dev Format public inputs for verification
     */
    function _formatPublicInputs(PublicInputs calldata inputs) internal view returns (uint256[4] memory signals) {
        signals[0] = uint256(inputs.sessionHash);
        signals[1] = uint256(inputs.claimHash);
        signals[2] = inputs.timestamp;
        signals[3] = uint256(uint160(inputs.issuer));

        for (uint256 i = 0; i < 4; i++) {
            signals[i] = signals[i].modExp(1, Q);
        }
    }

    /**
     * @dev Execute elliptic curve pairing check
     */
    function _performPairingCheck(uint256[8] memory points, uint256[4] memory publicSignals)
        internal
        view
        virtual
        returns (bool)
    {
        uint256[24] memory input;

        input[0] = points[0];
        input[1] = points[1];
        _setG2Points(input, 2);

        input[6] = points[2];
        input[7] = points[3];
        input[8] = points[4];
        input[9] = points[5];
        _setG1Points(input, 10, publicSignals);

        input[12] = points[6];
        input[13] = points[7];
        _setAlphaPoints(input, 14);

        input[18] = _computeNegation(points[0]);
        input[19] = P - points[1];
        _setBetaPoints(input, 20);

        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(gas(), 0x08, input, 0x300, out, 0x20)
        }

        return success && out[0] == 1;
    }

    /**
     * @dev Set G2 verification key points
     */
    function _setG2Points(uint256[24] memory input, uint256 offset) internal view {
        input[offset] = vkG2[0];
        input[offset + 1] = vkG2[1];
        input[offset + 2] = vkG2[2];
        input[offset + 3] = vkG2[3];
    }

    /**
     * @dev Set G1 verification key points
     */
    function _setG1Points(uint256[24] memory input, uint256 offset, uint256[4] memory signals) internal view {
        input[offset] = MathUtils.mulMod(vkG1[0], signals[0], P);
        input[offset + 1] = MathUtils.mulMod(vkG1[1], signals[1], P);
    }

    /**
     * @dev Set alpha verification key points
     */
    function _setAlphaPoints(uint256[24] memory input, uint256 offset) internal view {
        input[offset] = vkAlpha[0];
        input[offset + 1] = vkAlpha[1];
        input[offset + 2] = vkAlpha[2];
        input[offset + 3] = vkAlpha[3];
    }

    /**
     * @dev Set beta verification key points
     */
    function _setBetaPoints(uint256[24] memory input, uint256 offset) internal view {
        input[offset] = vkBeta[0];
        input[offset + 1] = vkBeta[1];
        input[offset + 2] = vkBeta[2];
        input[offset + 3] = vkBeta[3];
    }

    /**
     * @dev Compute field negation
     */
    function _computeNegation(uint256 x) internal view returns (uint256) {
        return P - (x % P);
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //                           INTERNAL VALIDATION FUNCTIONS
    // ══════════════════════════════════════════════════════════════════════════════

    /**
     * @dev Ensure verification keys are initialized
     */
    function _requireVerificationKeysSet() internal view {
        bool keysSet = true;
        for (uint256 i = 0; i < 4; i++) {
            if (vkG2[i] == 0 || vkAlpha[i] == 0 || vkBeta[i] == 0) {
                keysSet = false;
                break;
            }
        }
        for (uint256 i = 0; i < 2; i++) {
            if (vkG1[i] == 0) {
                keysSet = false;
                break;
            }
        }
        if (!keysSet) revert VerificationKeysNotSet();
    }

    /**
     * @dev Validate public inputs
     */
    function _validateInputs(PublicInputs calldata inputs) internal pure {
        if (inputs.timestamp == 0 || inputs.issuer == address(0)) {
            revert InvalidPublicInputs();
        }
        if (inputs.sessionHash == bytes32(0) || inputs.claimHash == bytes32(0)) {
            revert InvalidPublicInputs();
        }
    }

    /**
     * @dev Validate proof age against limits
     */
    function _validateProofAge(uint256 timestamp, uint256 validityPeriod) internal view {
        // Check for ProofTooOld first (absolute maximum age)
        if (block.timestamp > timestamp + maxProofAge) {
            revert ProofTooOld();
        }
        // Then check for StaleProof (custom validity period)
        if (block.timestamp > timestamp + validityPeriod) {
            revert StaleProof();
        }
    }

    /**
     * @dev Validate proof structure
     */
    function _validateProofStructure(ProofData calldata proof) internal view {
        if (!_validateProofStructureInternal(proof)) {
            revert InvalidProofStructure();
        }
    }

    /**
     * @dev Internal proof structure validation
     */
    function _validateProofStructureInternal(ProofData calldata proof) internal view virtual returns (bool) {
        for (uint256 i = 0; i < 2; i++) {
            if (proof.a[i] >= P || proof.c[i] >= P) return false;
            for (uint256 j = 0; j < 2; j++) {
                if (proof.b[i][j] >= P) return false;
            }
        }
        return true;
    }

    /**
     * @dev Validate verification key components
     */
    function _validateVerificationKey(
        uint256[4] calldata newVkG2,
        uint256[2] calldata newVkG1,
        uint256[4] calldata newVkAlpha,
        uint256[4] calldata newVkBeta
    ) internal view {
        for (uint256 i = 0; i < 4; i++) {
            if (newVkG2[i] >= P) revert InvalidVerificationKey();
            if (newVkAlpha[i] >= P) revert InvalidVerificationKey();
            if (newVkBeta[i] >= P) revert InvalidVerificationKey();
        }
        for (uint256 i = 0; i < 2; i++) {
            if (newVkG1[i] >= P) revert InvalidVerificationKey();
        }
    }
}
