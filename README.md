# Tuvi Key Derivation Library

TuviKeyDerivationLib is a .NET library designed for hierarchical key derivation, adhering to the BIP-32 (Hierarchical Deterministic Wallets) and BIP-39 (Mnemonic Code for Generating Deterministic Keys) standards. It provides secure and efficient key management and generation functionalities.

## Features

- Hierarchical Key Derivation: Implements BIP-32 for generating private and public keys in a hierarchical structure.
- BIP-39 Mnemonic Support: Generates and restores mnemonic seed phrases for secure key derivation.
- Public and Private Key Derivation: Supports derivation of both private and public keys from master keys or parent keys.
- BIP-44 Compliance: Provides strict BIP-44 derivation paths for compatibility with multi-coin wallet structures.
- Customizable Key Derivation: Allows derivation using custom tags (e.g., user IDs) for account-specific keys.
- Elliptic Curve Cryptography: Uses the `secp256k1` elliptic curve for key derivation, consistent with BIP-32 and Bitcoin standards.
- BouncyCastle Integration: Utilizes the BouncyCastle library for cryptographic operations, including elliptic curve computations and secure key handling.

## Installation

WIP

### Dependencies

- NBitcoin: Provides implementations for BIP-32 (Hierarchical Deterministic Wallets) and BIP-39 (Mnemonic Code for Generating Deterministic Keys).
- BouncyCastle: Supports elliptic curve cryptography operations, including `secp256k1` curve computations.

## Usage

WIP

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on the GitHub repository.

## License

This project is licensed under the Apache License 2.0 - See the [LICENSE](LICENSE) for details.

## Acknowledgements

- BIP-32: [Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- BIP-39: [Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- BIP-44: [Multi-Account Hierarchy for Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- NBitcoin: [Comprehensive Bitcoin library for the .NET framework.](https://github.com/MetacoSA/NBitcoin)
- BouncyCastle: [BouncyCastle.NET Cryptography Library](https://github.com/bcgit/bc-csharp)



