///////////////////////////////////////////////////////////////////////////////
//   Copyright 2025 Eppie (https://eppie.io)
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
using Org.BouncyCastle.Math.EC;
using System;
using System.Text;

namespace KeyDerivationLib
{
    /// <summary>
    /// Factory that derivate public keys from parent private or public keys.
    /// </summary>
    public static class PublicDerivationKeyFactory
    {
        /// <summary>
        /// Public derivation key creation from public derivation key and key tag (based on BIP-32).
        /// </summary>
        /// <param name="derivationKey">Public derivation key.</param>
        /// <param name="tag">Tag to identify key (like user ID).</param>
        /// <returns>New (deeper) public derivation key.</returns>
        public static PublicDerivationKey CreatePublicDerivationKey(PublicDerivationKey derivationKey, string tag)
        {
            byte[] hashInput = derivationKey.ToByteBuffer();

            byte[] hashKey = Encoding.UTF8.GetBytes(tag);
            var hashMAC = Hashes.HMACSHA512(hashKey, hashInput);

            return hashMAC.ToPublicDerivationKey(derivationKey);
        }

        /// <summary>
        /// Public derivation key creation from private derivation key and key tag (based on BIP-32).
        /// </summary>
        /// <param name="derivationKey">Private derivation key.</param>
        /// <param name="tag">Tag to identify key (like user ID).</param>
        /// <returns>New (deeper) public derivation key.</returns>
        public static PublicDerivationKey CreatePublicDerivationKey(PrivateDerivationKey derivationKey, string tag)
        {
            if (derivationKey is null)
            {
                throw new ArgumentNullException(nameof(derivationKey));
            }

            return CreatePublicDerivationKey(derivationKey.PublicDerivationKey, tag);
        }

        /// <summary>
        /// Derive public child key as byte array (compressed) from public derivation key and it's index.
        /// </summary>
        /// <param name="derivationKey">Public derivation key.</param>
        /// <param name="index">Public child key's index.</param>
        /// <returns>Public child key as byte array.</returns>
        public static byte[] DerivePublicChildKeyAsBytes(PublicDerivationKey derivationKey, uint index)
        {
            if (derivationKey is null)
            {
                throw new ArgumentNullException(nameof(derivationKey));
            }

            var eccKey = new PubKey(derivationKey.PublicKey.GetEncoded(true));

            ExtPubKey derivationExtKey = new ExtPubKey(eccKey, derivationKey.ChainCode.ToArray());
            return derivationExtKey.Derive(index).PubKey.ToBytes();
        }

        /// <summary>
        /// Derive public child key as ECPoint from public derivation key and it's index.
        /// </summary>
        /// <param name="derivationKey">Public derivation key.</param>
        /// <param name="index">Public child key's index.</param>
        /// <returns>Public child key as EC point.</returns>
        public static ECPoint DerivePublicChildKeyAsECPoint(PublicDerivationKey derivationKey, uint index)
        {
            var keyBytes = DerivePublicChildKeyAsBytes(derivationKey, index);
            return Secp256k1.DomainParams.Curve.DecodePoint(keyBytes);
        }

        private static PublicDerivationKey ToPublicDerivationKey(this byte[] buffer, PublicDerivationKey oldKey)
        {
            if (oldKey == null)
            {
                throw new ArgumentNullException(nameof(oldKey));
            }

            const int KeyChainCodeLength = Secp256k1.KeyChainCodeLength;
            const int ScalarLength = Secp256k1.ScalarLength;

            byte[] point = new byte[ScalarLength];
            byte[] chainCode = new byte[KeyChainCodeLength];

            Buffer.BlockCopy(buffer, 0, point, 0, ScalarLength);
            Buffer.BlockCopy(buffer, ScalarLength, chainCode, 0, KeyChainCodeLength);

            PublicDerivationKey tempKey = new PublicDerivationKey(point, chainCode);

            return new PublicDerivationKey(tempKey.PublicKey.Add(oldKey.PublicKey), chainCode);
        }
    }
}
