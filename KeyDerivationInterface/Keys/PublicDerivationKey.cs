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

using KeyDerivation.Entities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using System;

namespace KeyDerivation.Keys
{
    /// <summary>
    /// Represents a public derivation key for secp256k1.
    /// This class is not thread-safe; concurrent access from multiple threads must be synchronized externally.
    /// Does not implement IDisposable because it holds no private secrets.
    /// </summary>
    public sealed class PublicDerivationKey : IEquatable<PublicDerivationKey>
    {
        private readonly ECPoint publicKey;
        private readonly byte[] chainCode;
        private static readonly ECMultiplier Multiplier = new FixedPointCombMultiplier();

        public ECPoint PublicKey => publicKey;

        public ReadOnlyMemory<byte> ChainCode => chainCode.AsMemory();

        /// <summary>
        /// Initializes a new instance of the <see cref="PublicDerivationKey"/> class from a public key point and chain code.
        /// </summary>
        /// <param name="publicKey">The public key point.</param>
        /// <param name="chainCode">The chain code.</param>
        /// <exception cref="KeyCreationException">Thrown if inputs are invalid.</exception>
        public PublicDerivationKey(ECPoint publicKey, ReadOnlyMemory<byte> chainCode)
            : this(publicKey, chainCode.ToArray()) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="PublicDerivationKey"/> class from a private key scalar and a chain code.
        /// </summary>
        /// <param name="scalar">The private key scalar.</param>
        /// <param name="chainCode">The chain code associated with the key.</param>
        /// <exception cref="KeyCreationException">
        /// Thrown if the scalar is null, has an invalid length, is out of range, or if the chain code is null or invalid length.
        /// </exception>

        public PublicDerivationKey(ReadOnlyMemory<byte> scalar, ReadOnlyMemory<byte> chainCode)
            : this(scalar.ToArray(), chainCode.ToArray()) { }

        private PublicDerivationKey(byte[] scalar, byte[] chainCode)
        {
            Verify(scalar, chainCode);

            try
            {
                var biPrivateKey = new BigInteger(1, scalar);
                if (biPrivateKey.SignValue <= 0 || biPrivateKey.CompareTo(Secp256k1.DomainParams.N) >= 0)
                {
                    throw new KeyCreationException("Private key must be in [1, n-1].");
                }

                this.publicKey = Multiplier.Multiply(Secp256k1.DomainParams.G, biPrivateKey).Normalize();
                biPrivateKey = null;
            }
            finally
            {
                Secure.Clear(scalar);
            }

            this.chainCode = chainCode;
        }

        private PublicDerivationKey(ECPoint publicKey, byte[] chainCode)
        {
            Verify(publicKey, chainCode);

            this.publicKey = publicKey;
            this.chainCode = chainCode;
        }

        public override bool Equals(object obj) => Equals(obj as PublicDerivationKey);

        public bool Equals(PublicDerivationKey other)
        {
            if (other is null)
            {
                return false;
            }

            return PublicKey.Equals(other.PublicKey) &&
                   Secure.FixedTimeEquals(ChainCode.Span, other.ChainCode.Span);
        }

        public static bool operator ==(PublicDerivationKey left, PublicDerivationKey right)
        {
            if (left is null)
            {
                return right is null;
            }

            return left.Equals(right);
        }

        public static bool operator !=(PublicDerivationKey left, PublicDerivationKey right)
        {
            return !(left == right);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hash = 17;
                byte[] encoded = PublicKey.GetEncoded(true);
                foreach (byte b in encoded)
                {
                    hash = hash * 31 + b;
                }

                foreach (byte b in ChainCode.Span)
                {
                    hash = hash * 31 + b;
                }

                return hash;
            }
        }

        private static void Verify(byte[] scalar, byte[] chainCode)
        {
            if (scalar == null)
            {
                throw new KeyCreationException("Private key cannot be null.");
            }

            if (scalar.Length != Secp256k1.ScalarLength)
            {
                throw new KeyCreationException($"Private key must be {Secp256k1.ScalarLength} bytes.");
            }

            if (chainCode == null)
            {
                throw new KeyCreationException("Chain code cannot be null.");
            }

            if (chainCode.Length != Secp256k1.KeyChainCodeLength)
            {
                throw new KeyCreationException($"Chain code length must be {Secp256k1.KeyChainCodeLength} bytes.");
            }
        }

        private static void Verify(ECPoint publicKey, byte[] chainCode)
        {
            if (publicKey == null)
            {
                throw new KeyCreationException("Public key cannot be null.");
            }

            if (publicKey.IsInfinity)
            {
                throw new KeyCreationException("Public key cannot be point at infinity.");
            }

            if (!publicKey.Curve.Equals(Secp256k1.DomainParams.Curve))
            {
                throw new KeyCreationException("Public key must belong to secp256k1 domain.");
            }

            if (!publicKey.IsValid())
            {
                throw new KeyCreationException("Public key is not a valid point on the secp256k1 curve.");
            }

            if (chainCode == null)
            {
                throw new KeyCreationException("Chain code cannot be null.");
            }

            if (chainCode.Length != Secp256k1.KeyChainCodeLength)
            {
                throw new KeyCreationException($"Chain code length must be {Secp256k1.KeyChainCodeLength} bytes.");
            }
        }
    }
}