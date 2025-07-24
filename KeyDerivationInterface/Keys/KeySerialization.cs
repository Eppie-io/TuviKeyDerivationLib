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

using Org.BouncyCastle.Asn1.X9;
using System;

namespace KeyDerivation.Keys
{
    public static class KeySerialization
    {
        public const int KeyChainCodeLength = 32;
        public const int PrivateKeyLength = 32;
        public const int PublicKeyLength = 33;

        public static MasterKey ToMasterKey(this byte[] buffer)
        {
            var privateKey = buffer.ToPrivateDerivationKey();
            return new MasterKey
            {
                Scalar = privateKey.Scalar,
                ChainCode = privateKey.ChainCode
            };
        }

        public static byte[] ToByteBuffer(this MasterKey key)
        {
            var privateKey = key as PrivateDerivationKey;
            return privateKey?.ToByteBuffer();
        }

        public static PrivateDerivationKey ToPrivateDerivationKey(this byte[] buffer)
        {
            byte[] scalar = new byte[PrivateKeyLength];
            byte[] chainCode = new byte[KeyChainCodeLength];

            Buffer.BlockCopy(buffer, 0, scalar, 0, PrivateKeyLength);
            Buffer.BlockCopy(buffer, PrivateKeyLength, chainCode, 0, KeyChainCodeLength);

            return new PrivateDerivationKey
            {
                Scalar = scalar,
                ChainCode = chainCode
            };
        }

        public static PrivateDerivationKey ToPrivateDerivationKey(byte[] scalar, byte[] chainCode)
        {
            return new PrivateDerivationKey
            {
                Scalar = scalar,
                ChainCode = chainCode
            };
        }

        public static byte[] ToByteBuffer(this PrivateDerivationKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            byte[] buffer = new byte[KeyChainCodeLength + PrivateKeyLength];

            Buffer.BlockCopy(key.Scalar, 0, buffer, 0, PrivateKeyLength);
            Buffer.BlockCopy(key.ChainCode, 0, buffer, PrivateKeyLength, KeyChainCodeLength);

            return buffer;
        }

        public static PublicDerivationKey ToPublicDerivationKey(this byte[] buffer)
        {
            byte[] point = new byte[PublicKeyLength];
            byte[] chainCode = new byte[KeyChainCodeLength];

            Buffer.BlockCopy(buffer, 0, point, 0, PublicKeyLength);
            Buffer.BlockCopy(buffer, PublicKeyLength, chainCode, 0, KeyChainCodeLength);

            string CurveName = "secp256k1";
            var ecPoint = ECNamedCurveTable.GetByName(CurveName).Curve.DecodePoint(point);

            return new PublicDerivationKey(ecPoint, chainCode);
        }

        public static byte[] ToByteBuffer(this PublicDerivationKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            byte[] buffer = new byte[KeyChainCodeLength + PublicKeyLength];

            Buffer.BlockCopy(key.PublicKey.GetEncoded(true), 0, buffer, 0, PublicKeyLength);
            Buffer.BlockCopy(key.ChainCode, 0, buffer, PublicKeyLength, KeyChainCodeLength);

            return buffer;
        }
    }
}
