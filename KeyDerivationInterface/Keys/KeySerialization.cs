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

using System;

namespace KeyDerivation.Keys
{
    public static class KeySerialization
    {
        public const int KeyChainCodeLength = 32;
        public const int PrivateKeyLength = 32;

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
            var privateKey = key as PrivateDrivationKey;
            return privateKey?.ToByteBuffer();
        }

        public static PrivateDrivationKey ToPrivateDerivationKey(this byte[] buffer)
        {
            byte[] scalar = new byte[PrivateKeyLength];
            byte[] chainCode = new byte[KeyChainCodeLength];

            Buffer.BlockCopy(buffer, 0, scalar, 0, PrivateKeyLength);
            Buffer.BlockCopy(buffer, PrivateKeyLength, chainCode, 0, KeyChainCodeLength);

            return new PrivateDrivationKey
            {
                Scalar = scalar,
                ChainCode = chainCode
            };
        }

        public static byte[] ToByteBuffer(this PrivateDrivationKey key)
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
    }
}
