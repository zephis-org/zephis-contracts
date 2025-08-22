# Contributing to ZEPHIS Contracts

Thank you for your interest in contributing to ZEPHIS Contracts! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

We welcome contributions of all kinds:

- 🐛 **Bug reports and fixes**
- 💡 **Feature requests and implementations**
- 📝 **Documentation improvements**
- 🧪 **Tests and test coverage improvements**
- 🔍 **Security audits and vulnerability reports**
- 🎨 **Code quality improvements**

## 🚀 Getting Started

### Prerequisites

- [Foundry](https://getfoundry.sh/) - Ethereum development toolkit
- [Node.js](https://nodejs.org/) v16+ (if using npm scripts)
- [Git](https://git-scm.com/)
- Basic knowledge of Solidity and smart contracts

### Setup Development Environment

1. **Fork the repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/zephis-contracts.git
   cd zephis-contracts
   ```

2. **Install dependencies**
   ```bash
   forge install
   ```

3. **Verify setup**
   ```bash
   forge build
   forge test
   ```

4. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 📋 Development Guidelines

### Code Style

- **Solidity Version**: Use `pragma solidity ^0.8.28;`
- **Naming Conventions**: Follow Solidity style guide
  - Contracts: `PascalCase`
  - Functions: `camelCase`
  - Variables: `camelCase`
  - Constants: `UPPER_SNAKE_CASE`
- **Comments**: Use NatSpec documentation format
- **Line Length**: Maximum 100 characters
- **Formatting**: Use `forge fmt` before committing

### Testing Requirements

- **Coverage**: Maintain minimum 95% test coverage
- **Test Naming**: Use descriptive test names starting with `test`
- **Edge Cases**: Include tests for edge cases and error conditions
- **Gas Optimization**: Consider gas costs in implementations

### Security Guidelines

- **Access Control**: Use OpenZeppelin's role-based access control
- **Reentrancy**: Use `ReentrancyGuard` for external calls
- **Input Validation**: Validate all inputs thoroughly
- **Error Messages**: Provide clear, helpful error messages
- **Security Reviews**: Complex changes should be reviewed for security implications

## 🔄 Pull Request Process

### Before Submitting

1. **Run all tests**
   ```bash
   forge test
   ```

2. **Check coverage**
   ```bash
   forge coverage --report summary
   ```

3. **Format code**
   ```bash
   forge fmt
   ```

4. **Run static analysis** (if available)
   ```bash
   slither .
   ```

### PR Guidelines

1. **Clear Description**: Explain what your PR does and why
2. **Small Changes**: Keep PRs focused and reasonably sized
3. **Tests**: Include tests for new functionality
4. **Documentation**: Update docs if needed
5. **Breaking Changes**: Clearly mark and explain breaking changes

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that causes existing functionality to change)
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] Coverage maintained/improved
- [ ] New tests added for new functionality

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Code is commented, particularly in hard-to-understand areas
- [ ] Documentation updated
```

## 🐛 Reporting Issues

### Bug Reports

When reporting bugs, please include:

- **Environment**: Foundry version, OS, etc.
- **Steps to Reproduce**: Clear, step-by-step instructions
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Code Examples**: Minimal reproducible example
- **Error Messages**: Full error messages/stack traces

### Security Vulnerabilities

🔒 **Do not report security vulnerabilities in public issues!**

For security issues:
1. Create a private GitHub security advisory
2. Include detailed description and reproduction steps
3. Allow reasonable time for fixes before public disclosure

## 💡 Feature Requests

When suggesting features:

- **Use Case**: Explain the problem you're trying to solve
- **Proposed Solution**: Describe your suggested approach
- **Alternatives**: Consider alternative solutions
- **Impact**: Explain who benefits and how

## 🏗️ Architecture Guidelines

### Contract Design

- **Modularity**: Design contracts to be modular and composable
- **Upgradeability**: Consider upgrade patterns carefully
- **Gas Optimization**: Optimize for gas efficiency where reasonable
- **Interface Design**: Use clear, consistent interfaces

### Code Organization

```
src/
├── interfaces/          # Interface definitions
├── verifiers/          # Core verification contracts
├── utils/              # Utility contracts
└── libraries/          # Shared libraries

test/
├── unit/               # Unit tests
├── integration/        # Integration tests
└── fork/              # Fork tests
```

## 🎨 Documentation Standards

- **NatSpec**: Use complete NatSpec documentation
- **README**: Keep README.md updated
- **Code Comments**: Explain complex logic
- **Changelog**: Document significant changes

### NatSpec Example

```solidity
/**
 * @title ZKProofVerifier
 * @dev Verifies zero-knowledge proofs of TLS communications
 * @notice This contract allows submission and verification of ZK-TLS proofs
 */
contract ZKProofVerifier {
    /**
     * @notice Submit a proof for verification
     * @param proofData The proof data to verify
     * @return proofId Unique identifier for the submitted proof
     * @dev Validates proof format and stores for verification
     */
    function submitProof(ProofData calldata proofData) 
        external 
        returns (bytes32 proofId) 
    {
        // Implementation
    }
}
```

## 🏷️ Versioning

Smart contracts are typically deployed once and immutable. Version management is handled through:

- **Contract upgrades**: Using proxy patterns when necessary
- **Git tags**: For marking important releases
- **Documentation**: Tracking changes in commit messages

## 🎯 Areas for Contribution

### High Priority
- Gas optimization improvements
- Additional proof system integrations
- Security enhancements
- Documentation improvements

### Medium Priority
- Developer tooling
- Example implementations
- Performance optimizations
- Test coverage improvements

### Community Contributions
- Educational content
- Integration examples
- Bug fixes
- Feature enhancements

## 📞 Getting Help

- **GitHub Issues**: For bug reports and feature requests
- **GitHub Discussions**: Use for questions and general discussions

## 🙏 Recognition

Contributors will be:
- Mentioned in commit history and pull request credits
- Added to project acknowledgments for significant contributions
- Recognized in the project community

## 📜 Code of Conduct

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Expected Behavior

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- Trolling, insulting/derogatory comments, and personal attacks
- Public or private harassment
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

## 📝 License

By contributing to ZEPHIS Contracts, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to ZEPHIS Contracts! Together, we're building the future of privacy-preserving authentication. 🚀