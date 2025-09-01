![ZEPHIS Cover](assets/intro.webp)

Smart contracts for ZEPHIS Protocol that enables on-chain verification of cryptographic proofs of TLS sessions.

[![npm version](https://badge.fury.io/js/@zephis%2Fcontracts.svg)](https://badge.fury.io/js/@zephis%2Fcontracts)
[![Solidity](https://img.shields.io/badge/Solidity-%5E0.8.19-blue)](https://docs.soliditylang.org/)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![Foundry](https://img.shields.io/badge/Built%20with-Foundry-FFDB1C.svg)](https://book.getfoundry.sh/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

### Using Foundry

```bash
forge install zephis-org/zephis-contracts
```

### Using npm

```bash
npm install @zephis/contracts
```

## Basic Usage

```solidity
import "@zephis/contracts/ZephisVerifier.sol";

contract MyContract {
    using ZephisVerifier for ZephisVerifier.ProofData;
    
    function verifyUserProof(
        ZephisVerifier.ProofData memory proof,
        ZephisVerifier.PublicInputs memory inputs
    ) external view returns (bool) {
        return ZephisVerifier.verifyProof(proof, inputs);
    }
}
```

## Core Features

- **Pure Verification Functions**: Stateless proof verification for seamless integration in any smart contract
- **Gas-Optimized**: Efficient cryptographic operations optimized for EVM execution
- **Replay Protection**: Built-in timestamp validation to prevent proof replay attacks
- **Custom Validity Periods**: Configurable proof expiration for different use cases
- **Security Utilities**: Helper functions for signature verification and secure hashing
- **Multi-chain Support**: Deploy and verify proofs across all EVM-compatible chains
- **Comprehensive Testing**: Full test coverage with gas optimization benchmarks
- **Type-Safe Structures**: Well-defined data structures for proof and input handling
- **Integration Examples**: Ready-to-use templates for DeFi, identity, and attestation protocols

## 📖 Documentation

For detailed documentation and advanced features, visit:
- [Official Documentation](https://zephis.org/docs/contracts)
- [Integration Guide](https://zephis.org/docs/contracts/integration)

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

Project Link: [https://github.com/zephis-org/zephis-contracts](https://github.com/zephis-org/zephis-contracts)