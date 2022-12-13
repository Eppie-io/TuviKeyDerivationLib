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
using System.Text;

namespace KeyDerivationLib
{
    /// <summary>
    /// Implementation of hierarchical key derivation for separate accounts distinguished with user identities.
    /// </summary>
    public static class AccountKeyFactory
    {
        public static PrivateKey DeriveAccountKey(MasterKey masterKey, string userId)
        {
            byte[] hashInput = masterKey.ToByteBuffer();

            byte[] hashKey = Encoding.UTF8.GetBytes(userId);
            var hashMAC = Hashes.HMACSHA512(hashKey, hashInput);

            return hashMAC.ToPrivateKey();
        }

        public static byte[] DeriveAccountChildKey(MasterKey masterKey, string userId, int index)
        {
            PrivateKey accountKey = DeriveAccountKey(masterKey, userId);
            return DeriveAccountChildKey(accountKey, index);
        }

        private static byte[] DeriveAccountChildKey(PrivateKey accountKey, int index)
        {
            using (var eccKey = new Key(accountKey.Scalar))
            {
                ExtKey accountExtKey = new ExtKey(eccKey, accountKey.ChainCode);
                return accountExtKey.Derive(index, true).PrivateKey.ToBytes();
            }
        }
    }
}
