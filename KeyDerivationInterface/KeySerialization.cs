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

using System;

namespace KeyDerivation.Keys
{
    public static class KeySerialization
    {
        public static MasterKey ToMasterKey(this byte[] buffer)
        {
            using (var privateKey = buffer.ToPrivateDerivationKey())
            {
                return new MasterKey(privateKey.Scalar.ToArray(), privateKey.ChainCode.ToArray());
            }
        }

        public static byte[] ToByteBuffer(this MasterKey key)
        {
            var privateKey = key as PrivateDerivationKey;
            return privateKey?.ToByteBuffer();
        }

        public static PrivateDerivationKey ToPrivateDerivationKey(this byte[] buffer)
        {
            byte[] scalar = new byte[Secp256k1.ScalarLength];
            byte[] chainCode = new byte[Secp256k1.KeyChainCodeLength];

            Buffer.BlockCopy(buffer, 0, scalar, 0, Secp256k1.ScalarLength);
            Buffer.BlockCopy(buffer, Secp256k1.ScalarLength, chainCode, 0, Secp256k1.KeyChainCodeLength);

            return new PrivateDerivationKey(scalar, chainCode);
        }

        public static PrivateDerivationKey ToPrivateDerivationKey(byte[] scalar, byte[] chainCode)
        {
            return new PrivateDerivationKey(scalar, chainCode);
        }

        public static byte[] ToByteBuffer(this PrivateDerivationKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            byte[] buffer = new byte[Secp256k1.KeyChainCodeLength + Secp256k1.ScalarLength];

            Buffer.BlockCopy(key.Scalar.ToArray(), 0, buffer, 0, Secp256k1.ScalarLength);
            Buffer.BlockCopy(key.ChainCode.ToArray(), 0, buffer, Secp256k1.ScalarLength, Secp256k1.KeyChainCodeLength);

            return buffer;
        }

        public static PublicDerivationKey ToPublicDerivationKey(this byte[] buffer)
        {
            byte[] point = new byte[Secp256k1.PublicKeyLength];
            byte[] chainCode = new byte[Secp256k1.KeyChainCodeLength];

            Buffer.BlockCopy(buffer, 0, point, 0, Secp256k1.PublicKeyLength);
            Buffer.BlockCopy(buffer, Secp256k1.PublicKeyLength, chainCode, 0, Secp256k1.KeyChainCodeLength);

            var ecPoint = Secp256k1.DomainParams.Curve.DecodePoint(point);

            return new PublicDerivationKey(ecPoint, chainCode);
        }

        public static byte[] ToByteBuffer(this PublicDerivationKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            byte[] buffer = new byte[Secp256k1.KeyChainCodeLength + Secp256k1.PublicKeyLength];

            Buffer.BlockCopy(key.PublicKey.GetEncoded(true), 0, buffer, 0, Secp256k1.PublicKeyLength);
            Buffer.BlockCopy(key.ChainCode.ToArray(), 0, buffer, Secp256k1.PublicKeyLength, Secp256k1.KeyChainCodeLength);

            return buffer;
        }
    }
}
