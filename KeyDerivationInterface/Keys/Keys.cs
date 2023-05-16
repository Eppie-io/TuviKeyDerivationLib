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

using KeyDerivation.Entities;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using System;
using System.Linq;

namespace KeyDerivation.Keys
{
    // Use this as Data Transfer Object only.
    public class MasterKey : PrivateDerivationKey
    {
    }

    public class PrivateDerivationKey : IEquatable<PrivateDerivationKey>
    {
        private byte[] scalar;
        private byte[] chainCode;

#pragma warning disable CA1819 // Properties should not return arrays
        public byte[] Scalar
        {
            get
            {
                return scalar;
            }

            internal set
            {
                if (value == null)
                {
                    throw new KeyCreationException($"Derivation key scalar can not be a null.");
                }

                scalar = value;
            }
        }

        public byte[] ChainCode
        {
            get
            {
                return chainCode;
            }

            internal set
            {
                if (value == null)
                {
                    throw new KeyCreationException($"Derivation key chain code can not be a null.");
                }

                chainCode = value;
            }
        }
#pragma warning restore CA1819 // Properties should not return arrays

        public PublicDerivationKey PublicDerivationKey => new PublicDerivationKey(Scalar, ChainCode);

        public override bool Equals(object obj)
        {
            return Equals(obj as PrivateDerivationKey);
        }

        public bool Equals(PrivateDerivationKey other)
        {
            if (other is null)
            {
                return false;
            }
            if (ReferenceEquals(this, other))
            {
                return true;
            }
            return Scalar.SequenceEqual(other.Scalar) &&
                   ChainCode.SequenceEqual(other.ChainCode);
        }

        public static bool operator ==(PrivateDerivationKey a, PrivateDerivationKey b)
        {
            return Equals(a, b);
        }

        public static bool operator !=(PrivateDerivationKey a, PrivateDerivationKey b)
        {
            return !(a == b);
        }

        public override int GetHashCode()
        {
            return new BigInteger(scalar.Concat(ChainCode).ToArray()).GetHashCode();
        }
    }

    public class PublicDerivationKey : IEquatable<PublicDerivationKey>
    {
        private const string BitcoinEllipticCurveName = "secp256k1";
        private DerObjectIdentifier curveOid;
        private ECKeyGenerationParameters keyParams;

        private readonly ECMultiplier multiplier = new FixedPointCombMultiplier();

        private const int KeyChainCodeLength = 32;
        private ECPoint publicKey;
        private byte[] chainCode;

        private PublicDerivationKey()
        {
            curveOid = ECNamedCurveTable.GetOid(BitcoinEllipticCurveName);
            keyParams = new ECKeyGenerationParameters(curveOid, new SecureRandom());
        }

        public PublicDerivationKey(byte[] privateKey, byte[] chainCode) : this()
        {
            PublicKey = multiplier.Multiply(keyParams.DomainParameters.G, new Org.BouncyCastle.Math.BigInteger(1, privateKey)).Normalize();
            ChainCode = chainCode;
        }

        public PublicDerivationKey(ECPoint publicKey, byte[] chainCode) : this()
        {
            PublicKey = publicKey;
            ChainCode = chainCode;
        }

        public ECKeyGenerationParameters KeyParams
        {
            get => keyParams;
        }

        public ECPoint PublicKey
        {
            get
            {
                return publicKey;
            }

            internal set
            {
                publicKey = value ?? throw new KeyCreationException($"Derivation public key can not be a null.");
            }
        }

#pragma warning disable CA1819 // Properties should not return arrays

        public byte[] ChainCode
        {
            get
            {
                return chainCode;
            }

            internal set
            {
                if (value == null)
                {
                    throw new KeyCreationException($"Derivation key chain code can not be a null.");
                }

                if (value.Length != KeyChainCodeLength)
                {
                    throw new KeyCreationException($"Derivation key chain code length should be equal to {KeyChainCodeLength} bytes.");
                }

                chainCode = value;
            }
        }
#pragma warning restore CA1819 // Properties should not return arrays

        public override bool Equals(object obj)
        {
            return Equals(obj as PublicDerivationKey);
        }

        public bool Equals(PublicDerivationKey other)
        {
            if (this == other)
            {
                return true;
            }
            if (other == null)
            {
                return false;
            }

            return PublicKey.Equals(other.PublicKey) &&
                   ChainCode.SequenceEqual(other.ChainCode);
        }

        public override int GetHashCode()
        {
            return (publicKey, new BigInteger(ChainCode)).GetHashCode();
        }
    }
}
