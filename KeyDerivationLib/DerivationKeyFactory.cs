///////////////////////////////////////////////////////////////////////////////
//   Copyright 2023 Eppie (https://eppie.io)
//
//   Licensed under the Apache License, Version 2.0(the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
///////////////////////////////////////////////////////////////////////////////

using KeyDerivation.Keys;
using NBitcoin;
using NBitcoin.Crypto;
using System;
using System.Text;

namespace KeyDerivationLib
{
    /// <summary>
    /// Implementation of hierarchical key derivation for separate accounts distinguished with user identities.
    /// Based on BIP-32 hierarchical key derivation.
    /// </summary>
    public static class DerivationKeyFactory
    {
        /// <summary>
        /// Derivation key creation from derivation (master) key and key tag (based on BIP-32).
        /// </summary>
        /// <param name="derivationKey">Derivation key.</param>
        /// <param name="tag">Tag to identify key(like user ID).</param>
        /// <returns>Private derivation key.</returns>
        public static PrivateDerivationKey CreatePrivateDerivationKey(PrivateDerivationKey derivationKey, string tag)
        {
            byte[] hashInput = derivationKey.ToByteBuffer();

            byte[] hashKey = Encoding.UTF8.GetBytes(tag);
            var hashMAC = Hashes.HMACSHA512(hashKey, hashInput);

            return hashMAC.ToPrivateDerivationKey();
        }

        /// <summary>
        /// Derive child key from private derivation key and it's index.
        /// </summary>
        /// <param name="derivationKey">Private derivation key.</param>
        /// <param name="index">Private child key index.</param>
        /// <returns>Child key.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static PrivateDerivationKey DerivePrivateChildKey(PrivateDerivationKey derivationKey, int index)
        {
            if (derivationKey is null)
            {
                throw new ArgumentNullException(nameof(derivationKey));
            }

            if (index < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(index), "Index must be a non-negative integer.");
            }

            if (derivationKey.Scalar is null || derivationKey.ChainCode is null)
            {
                throw new ArgumentException("Derivation key scalar or chain code cannot be null.");
            }

            if (derivationKey.Scalar.Length != 32 || derivationKey.ChainCode.Length != 32)
            {
                throw new ArgumentException("Derivation key scalar and chain code must be 32 bytes long.");
            }

            using (var eccKey = new Key(derivationKey.Scalar))
            {
                ExtKey derivationExtKey = new ExtKey(eccKey, derivationKey.ChainCode);
                derivationExtKey = derivationExtKey.Derive(index, true);
                
                var privKey = derivationExtKey.PrivateKey.ToBytes();
                var chainCode = derivationExtKey.ChainCode;

                return KeySerialization.ToPrivateDerivationKey(privKey, chainCode);
            }
        }

        /// <summary>
        /// Derives a child private key using the strict BIP44 standard from a given master key.
        /// The full derivation path follows the BIP44 convention: m/44'/coin'/account'/channel/index.
        /// </summary>
        /// <param name="masterKey">
        /// The BIP32 master key (also known as the root private key) used as the starting point for derivation.
        /// Must not be <c>null</c>.
        /// </param>
        /// <param name="coin">
        /// Coin type as defined by <see href="https://github.com/satoshilabs/slips/blob/master/slip-0044.md">SLIP-0044</see>.
        /// For example: 0 for Bitcoin, 60 for Ethereum, 3630 for Eppie.
        /// </param>
        /// <param name="account">
        /// Hardened account index, used to separate different logical accounts within the same wallet.
        /// Typically starts from 0.
        /// </param>
        /// <param name="channel">
        /// Unhardened channel index, allowing sub-classification of accounts (e.g., different application domains or usage categories).
        /// <b>Note:</b> Indices <c>0</c> and <c>1</c> are reserved according to the
        /// <see href="https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#change">BIP-44 specification</see>
        /// for internal wallet structure (<c>0</c> for external addresses, <c>1</c> for internal/change addresses).
        /// Custom derivations must avoid these values to maintain compatibility.
        /// </param>
        /// <param name="index">
        /// Unhardened address index. Allows generating multiple keys within the same channel.
        /// </param>
        /// <returns>
        /// A <see cref="PrivateDerivationKey"/> representing the derived private key at the specified path.
        /// </returns>
        public static PrivateDerivationKey CreatePrivateDerivationKeyBip44(PrivateDerivationKey masterKey, int coin, int account, int channel, int index)
        {
            if (masterKey is null)
            {
                throw new ArgumentNullException(nameof(masterKey));
            }

            var keyPath = KeyPath.Empty
                                 .Derive(44, true)
                                 .Derive(coin, true)
                                 .Derive(account, true)
                                 .Derive(channel, false)
                                 .Derive(index, false);

            using (var key = new Key(masterKey.Scalar))
            {
                ExtKey extKey = new ExtKey(key, masterKey.ChainCode);
                extKey = extKey.Derive(keyPath);
                
                var privKey = extKey.PrivateKey.ToBytes();
                var chainCode = extKey.ChainCode;
                return KeySerialization.ToPrivateDerivationKey(privKey, chainCode);
            }
        }
    }
}
