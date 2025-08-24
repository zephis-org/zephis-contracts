// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IHandshakeProof {
    struct HandshakeData {
        bytes32 clientHello;
        bytes32 serverHello;
        bytes32 certificateHash;
        bytes32 serverKeyExchange;
        bytes32 clientKeyExchange;
        uint256 cipherSuite;
        uint256 protocolVersion;
    }

    struct CertificateChain {
        bytes32[] certificates;
        bytes32 rootCaHash;
        uint256 chainLength;
    }

    event HandshakeVerified(
        bytes32 indexed sessionId,
        bytes32 certificateHash,
        uint256 cipherSuite,
        uint256 protocolVersion
    );

    function verifyHandshake(
        bytes32 sessionId,
        HandshakeData calldata handshake,
        CertificateChain calldata certChain,
        uint256[8] calldata proof
    ) external returns (bool);

    function isValidCipherSuite(uint256 cipherSuite) external view returns (bool);
    
    function isValidProtocolVersion(uint256 version) external view returns (bool);
    
    function getHandshakeData(bytes32 sessionId) external view returns (HandshakeData memory);
}