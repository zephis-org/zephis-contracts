// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library HandshakeProofErrors {
    error InvalidHandshakeData();
    error InvalidCertificateChain();
    error UnsupportedCipherSuite();
    error UnsupportedProtocolVersion();
    error InvalidCertificateHash();
    error CertificateExpired();
    error InvalidCARoot();
    error HandshakeAlreadyVerified();
    error InvalidClientHello();
    error InvalidServerHello();
}