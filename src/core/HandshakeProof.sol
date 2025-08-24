// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IHandshakeProof} from "../interfaces/IHandshakeProof.sol";
import {HandshakeProofErrors} from "../errors/HandshakeProofErrors.sol";
import {TrustedCAs} from "../registries/TrustedCAs.sol";

contract HandshakeProof is IHandshakeProof, AccessControl {
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant CA_MANAGER_ROLE = keccak256("CA_MANAGER_ROLE");

    TrustedCAs public immutable TRUSTED_CAS;
    
    mapping(bytes32 => HandshakeData) private _handshakeData;
    mapping(bytes32 => bool) private _verifiedHandshakes;
    mapping(uint256 => bool) private _supportedCipherSuites;
    mapping(uint256 => bool) private _supportedProtocolVersions;

    uint256 private constant TLS_1_2 = 0x0303;
    uint256 private constant TLS_1_3 = 0x0304;
    
    uint256 private constant CIPHER_TLS_AES_128_GCM_SHA256 = 0x1301;
    uint256 private constant CIPHER_TLS_AES_256_GCM_SHA384 = 0x1302;
    uint256 private constant CIPHER_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F;
    uint256 private constant CIPHER_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030;

    modifier onlyValidSession(bytes32 sessionId) {
        if (sessionId == bytes32(0)) revert HandshakeProofErrors.InvalidHandshakeData();
        _;
    }

    modifier onlyUnverifiedSession(bytes32 sessionId) {
        if (_verifiedHandshakes[sessionId]) revert HandshakeProofErrors.HandshakeAlreadyVerified();
        _;
    }

    constructor(address _trustedCAs) {
        TRUSTED_CAS = TrustedCAs(_trustedCAs);
        
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(CA_MANAGER_ROLE, msg.sender);

        _initializeSupportedCipherSuites();
        _initializeSupportedProtocolVersions();
    }

    function verifyHandshake(
        bytes32 sessionId,
        HandshakeData calldata handshake,
        CertificateChain calldata certChain,
        uint256[8] calldata proof
    ) external onlyRole(VERIFIER_ROLE) onlyValidSession(sessionId) 
      onlyUnverifiedSession(sessionId) returns (bool) {
        
        _validateHandshakeData(handshake);
        _validateCertificateChain(certChain);
        
        bool isProofValid = _verifyHandshakeProof(sessionId, handshake, certChain, proof);
        
        if (!isProofValid) {
            revert HandshakeProofErrors.InvalidHandshakeData();
        }

        _handshakeData[sessionId] = handshake;
        _verifiedHandshakes[sessionId] = true;

        emit HandshakeVerified(
            sessionId,
            handshake.certificateHash,
            handshake.cipherSuite,
            handshake.protocolVersion
        );

        return true;
    }

    function isValidCipherSuite(uint256 cipherSuite) external view returns (bool) {
        return _supportedCipherSuites[cipherSuite];
    }

    function isValidProtocolVersion(uint256 version) external view returns (bool) {
        return _supportedProtocolVersions[version];
    }

    function getHandshakeData(bytes32 sessionId) external view returns (HandshakeData memory) {
        return _handshakeData[sessionId];
    }

    function addSupportedCipherSuite(
        uint256 cipherSuite
    ) external onlyRole(CA_MANAGER_ROLE) {
        _supportedCipherSuites[cipherSuite] = true;
    }

    function removeSupportedCipherSuite(
        uint256 cipherSuite
    ) external onlyRole(CA_MANAGER_ROLE) {
        _supportedCipherSuites[cipherSuite] = false;
    }

    function _validateHandshakeData(HandshakeData calldata handshake) private view {
        if (handshake.clientHello == bytes32(0)) revert HandshakeProofErrors.InvalidClientHello();
        if (handshake.serverHello == bytes32(0)) revert HandshakeProofErrors.InvalidServerHello();
        if (handshake.certificateHash == bytes32(0)) revert HandshakeProofErrors.InvalidCertificateHash();
        
        if (!_supportedCipherSuites[handshake.cipherSuite]) {
            revert HandshakeProofErrors.UnsupportedCipherSuite();
        }
        
        if (!_supportedProtocolVersions[handshake.protocolVersion]) {
            revert HandshakeProofErrors.UnsupportedProtocolVersion();
        }
    }

    function _validateCertificateChain(CertificateChain calldata certChain) private view {
        if (certChain.chainLength == 0 || certChain.chainLength > 5) {
            revert HandshakeProofErrors.InvalidCertificateChain();
        }
        
        if (!TRUSTED_CAS.isValidCaRoot(certChain.rootCaHash)) {
            revert HandshakeProofErrors.InvalidCARoot();
        }
    }

    function _verifyHandshakeProof(
        bytes32 sessionId,
        HandshakeData calldata handshake,
        CertificateChain calldata certChain,
        uint256[8] calldata proof
    ) private pure returns (bool) {
        bytes32 publicInputsHash = keccak256(abi.encodePacked(
            sessionId,
            handshake.clientHello,
            handshake.serverHello,
            handshake.certificateHash,
            certChain.rootCaHash
        ));

        uint256 expectedPublicInput = uint256(publicInputsHash) >> 8;
        
        return proof[0] == expectedPublicInput;
    }

    function _initializeSupportedCipherSuites() private {
        _supportedCipherSuites[CIPHER_TLS_AES_128_GCM_SHA256] = true;
        _supportedCipherSuites[CIPHER_TLS_AES_256_GCM_SHA384] = true;
        _supportedCipherSuites[CIPHER_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256] = true;
        _supportedCipherSuites[CIPHER_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384] = true;
    }

    function _initializeSupportedProtocolVersions() private {
        _supportedProtocolVersions[TLS_1_2] = true;
        _supportedProtocolVersions[TLS_1_3] = true;
    }
}