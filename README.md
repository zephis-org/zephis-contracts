![ZEPHIS Cover](cover.webp)

# ZEPHIS Contracts

Smart contracts for privacy-preserving authentication and data verification through zero-knowledge proofs of TLS communications.

## 🌟 Overview

ZEPHIS Contracts provide the on-chain infrastructure for verifying zero-knowledge TLS proofs, enabling privacy-first authentication without exposing sensitive user data. The protocol supports multiple proof systems including TLSN (TLS Notary) and MPCTLS proofs.

## ✨ Features

- **🔒 Zero-Knowledge TLS Proof Verification** - Verify TLS communications without revealing content
- **🌐 Multi-Proof System Support** - TLSN, MPCTLS, and custom proof types
- **⚖️ Governance & Challenges** - Decentralized challenge mechanism for proof disputes
- **🛡️ Security-First Design** - Role-based access control and pausable contracts
- **📊 Analytics & Tracking** - Comprehensive verification statistics and metrics
- **🔄 Batch Operations** - Efficient batch proof verification for scalability

## 📁 Project Structure

```
zephis-contracts/
├── src/
│   ├── verifiers/
│   │   ├── IZKProofVerifier.sol     # Core verification interface
│   │   ├── ZKProofVerifier.sol      # Base proof verification logic
│   │   └── TLSNVerifier.sol         # TLSN-specific verification
│   └── interfaces/
├── test/
│   ├── ZKProofVerifier.t.sol        # Main verification tests
│   ├── TLSNVerifier.t.sol           # TLSN-specific tests
│   └── ZKProofVerifierBranchCoverage.t.sol
├── script/                          # Deployment scripts
└── docs/                           # Documentation
```

## 🚀 Quick Start

### Prerequisites

- [Foundry](https://getfoundry.sh/) - Ethereum development toolkit
- [Node.js](https://nodejs.org/) v16+ (if using npm scripts)
- [Git](https://git-scm.com/)

### Installation

```bash
# Clone the repository
git clone https://github.com/zephis-org/zephis-contracts.git
cd zephis-contracts

# Install Foundry dependencies
forge install

# Compile contracts
forge build
```

### Testing

```bash
# Run all tests
forge test

# Run tests with verbosity
forge test -vvv

# Run specific test contract
forge test --match-contract ZKProofVerifierTest

# Generate coverage report
forge coverage --report summary
```

## 🏗️ Smart Contracts

### ZKProofVerifier.sol

Core contract for zero-knowledge proof verification with the following features:

- **Proof Submission** - Submit ZK-TLS proofs for verification
- **Verification Process** - Cryptographic verification of submitted proofs
- **Challenge System** - 7-day challenge period for disputes
- **Access Control** - Role-based permissions (VERIFIER_ROLE, CHALLENGER_ROLE, ADMIN_ROLE)
- **Batch Operations** - Efficient batch verification up to 50 proofs

### TLSNVerifier.sol

Specialized verifier for TLSN (TLS Notary) proofs:

- **Notary Management** - Trusted notary registration and verification
- **Server Name Extraction** - Extract server information from TLS handshakes
- **Transcript Validation** - Verify TLS transcript integrity
- **TLSN-Specific Logic** - Tailored verification for TLSN proof format

## 📊 Test Coverage

Our contracts maintain exceptional test coverage:

| File | Lines | Statements | Branches | Functions |
|------|-------|------------|----------|-----------|
| **ZKProofVerifier.sol** | 99.32% (145/146) | 99.31% (143/144) | 83.33% (55/66) | 100.00% (22/22) |
| **TLSNVerifier.sol** | 98.06% (101/103) | 98.17% (107/109) | 95.74% (45/47) | 100.00% (15/15) |
| **Total** | **98.80% (246/249)** | **98.81% (250/253)** | **88.50% (100/113)** | **100.00% (37/37)** |

✅ **109 tests passing** with comprehensive edge case coverage

## 🔧 Development Commands

```bash
# Compile contracts
forge build

# Run tests
forge test

# Run tests with gas reporting
forge test --gas-report

# Format code
forge fmt

# Generate documentation
forge doc

# Run slither security analysis
slither .

# Deploy to local network
forge script script/Deploy.s.sol --fork-url http://localhost:8545 --broadcast
```

## 🛠️ Configuration

### Supported Proof Types

- **TLSN** - TLS Notary proofs (enabled by default)
- **MPCTLS** - Multi-Party Computation TLS proofs (enabled by default)
- **CUSTOM** - Custom proof types (disabled by default, admin-configurable)

### Key Parameters

- **Challenge Period**: 7 days
- **Max Proof Size**: 1MB
- **Max Batch Size**: 50 proofs
- **Query Limit**: 100 results

## 🔐 Security Features

- **Role-Based Access Control** - Multi-level permission system
- **Reentrancy Protection** - OpenZeppelin ReentrancyGuard
- **Pausable Contracts** - Emergency pause functionality
- **Input Validation** - Comprehensive validation of all inputs
- **Challenge Mechanism** - Community-driven dispute resolution

## 🌐 Deployment

### Local Development

```bash
# Start local Foundry node
anvil

# Deploy contracts
forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast
```

### Testnet Deployment

```bash
# Deploy to Sepolia
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast --verify

# Deploy to Base Sepolia
forge script script/Deploy.s.sol --rpc-url $BASE_SEPOLIA_RPC_URL --broadcast --verify
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`forge test`)
5. Commit your changes (`git commit -am 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Documentation**: [docs.zephis.org](https://docs.zephis.org)
- **Website**: [zephis.org](https://zephis.org)
- **Discord**: [discord.gg/zephis](https://discord.gg/zephis)
- **Twitter**: [@ZephisProtocol](https://twitter.com/ZephisProtocol)

## 🏆 Acknowledgments

- [OpenZeppelin](https://openzeppelin.com/) for secure smart contract libraries
- [Foundry](https://getfoundry.sh/) for the excellent development toolkit
- [TLS Notary](https://tlsnotary.org/) for the TLSN protocol inspiration
- The broader zero-knowledge and privacy community

---

<p align="center">
  <strong>Built with ❤️ by the ZEPHIS team</strong>
</p>

<p align="center">
  <em>Privacy-first authentication for the decentralized web</em>
</p>