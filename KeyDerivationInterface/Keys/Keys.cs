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

using KeyDerivation.Entities;
using System.Linq;

namespace KeyDerivation.Keys
{
    // Use this as Data Transfer Object only.
    public class MasterKey : PrivateDerivationKey
    {
    }

    public class PrivateDerivationKey
    {
        private const int KeyChainCodeLength = 32;
        private const int KeyScalarLength = 32;
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

                if (value.Length != KeyScalarLength)
                {
                    throw new KeyCreationException($"Derivation key scalar length should be equal to {KeyScalarLength} bytes.");
                }

                scalar = value;
            }
        }

        public byte[] ChainCode {
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
            if (obj is PrivateDerivationKey other)
            {
                if ((Scalar == null && other.Scalar == null) ||
                     Scalar.SequenceEqual(other.Scalar))
                {
                    if ((ChainCode == null && other.ChainCode == null) ||
                         ChainCode.SequenceEqual(other.ChainCode))
                    {
                        return true;
                    }
                }
                return false;
            }
            else
            {
                return false;
            }
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
    }

    public class PgpPublicKeyBundle : PgpKeyBundle
    {
    }

    public class PgpSecretKeyBundle : PgpKeyBundle
    {
    }

    public class PgpKeyBundle
    {
#pragma warning disable CA1819 // Properties should not return arrays
        public byte[] Data { get; set; }
#pragma warning restore CA1819 // Properties should not return arrays

        public override bool Equals(object obj)
        {
            if (obj is PgpKeyBundle other)
            {
                if ((Data == null && other.Data == null) ||
                     Data.SequenceEqual(other.Data))
                {
                    return true;
                }
                return false;
            }
            else
            {
                return false;
            }
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
    }
}
