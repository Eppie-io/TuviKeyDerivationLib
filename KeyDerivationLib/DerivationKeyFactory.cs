///////////////////////////////////////////////////////////////////////////////
//   Copyright 2022 Eppie (https://eppie.io)
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
        public static PrivateDrivationKey CreatePrivateDerivationKey(PrivateDrivationKey derivationKey, string tag)
        {
            byte[] hashInput = derivationKey.ToByteBuffer();

            byte[] hashKey = Encoding.UTF8.GetBytes(tag);
            var hashMAC = Hashes.HMACSHA512(hashKey, hashInput);

            return hashMAC.ToPrivateDerivationKey();
        }

        /// <summary>
        /// Derive private child key from private derivation key and it's index.
        /// </summary>
        /// <param name="derivationKey">Private derivation key.</param>
        /// <param name="index">Private child key index.</param>
        /// <returns>Private child key.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] DerivePrivateChildKey(PrivateDrivationKey derivationKey, int index)
        {
            if (derivationKey is null)
            {
                throw new ArgumentNullException(nameof(derivationKey));
            }

            using (var eccKey = new Key(derivationKey.Scalar))
            {
                ExtKey derivationExtKey = new ExtKey(eccKey, derivationKey.ChainCode);
                return derivationExtKey.Derive(index, true).PrivateKey.ToBytes();
            }
        }
    }
}
