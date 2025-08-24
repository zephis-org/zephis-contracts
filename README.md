![ZEPHIS Cover](assets/cover.webp)

**ZEPHIS** (Zero Exposure Proof Handling Isolated Sessions) is an open-source ZK-TLS framework that generates cryptographic proofs of TLS sessions, enabling users to prove web interactions without revealing sensitive data. Unlike simple API scrapers, ZEPHIS provides mathematical proof at the TLS protocol layer, ensuring cryptographic integrity from TLS handshake to application data.

ZEPHIS Contracts provide the smart contract infrastructure for on-chain verification of these zero-knowledge proofs, supporting TLS handshake validation, session key commitment, and transcript integrity verification.

## 🚀 Quick Start

```bash
git clone https://github.com/zephis-org/zephis-contracts.git
cd zephis-contracts
forge install
forge build
forge test
```

## 💻 Basic Usage

```solidity
// Verify a TLS session proof
IZKTLSVerifier.TLSProof memory proof = IZKTLSVerifier.TLSProof({
    sessionId: sessionId,
    handshakeCommitment: handshakeCommitment,
    keyCommitment: keyCommitment,
    transcriptRoot: transcriptRoot,
    groth16Proof: groth16Proof,
    publicInputs: publicInputs
});

bool isValid = zktlsVerifier.verifyTLSProof(proof);

// Check session validity
bool isSessionValid = zktlsVerifier.isValidSession(sessionId);

// Get verification result
IZKTLSVerifier.VerificationResult memory result = zktlsVerifier.getVerificationResult(sessionId);
```

## ✨ Core Features

- **Zero-Knowledge Proof Verification**: Groth16 zk-SNARK proofs with configurable circuit verifiers and time-based expiration
- **TLS Session Management**: Handshake validation, session key commitment, and transcript proof management with selective reveal
- **Trusted CA Registry**: Certificate authority management with Merkle tree validation and configurable validity periods
- **Security & Access Control**: Role-based permissions, reentrancy protection, and comprehensive input validation
- **Flexible Configuration**: TLS 1.2/1.3 support, multiple cipher suites, and KDF algorithms (HKDF-SHA256, HKDF-SHA384, TLS-PRF)
- **Data Management**: Selective transcript reveal, Merkle proof integration, and complete session state tracking
- **Development Tools**: Foundry testing, Slither security analysis, and multiple gas-optimized build profiles


## 🧪 Testing

```bash
forge test                    # Run all tests
forge test -vvv              # Verbose output
forge coverage              # Coverage report
slither .                   # Security analysis
```

## 📖 Documentation

For detailed documentation and advanced features, visit:
- [Official Documentation](https://zephis.org/docs)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📬 Contact

Zephis Team - [https://zephis.org](https://zephis.org)

Project Link: [https://github.com/zephis-org](https://github.com/zephis-org)