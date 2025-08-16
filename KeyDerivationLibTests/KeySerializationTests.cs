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
using KeyDerivationLib;

namespace KeyDerivationLibTests
{
    public class KeySerializationTests
    {
        [Test]
        public void SerializeDeserializePrivateDerivationKey()
        {
            var buffer = TestData.DerivationKeyForSerialization.ToByteBuffer();
            PrivateDerivationKey privateKey = buffer.ToPrivateDerivationKey();

            Assert.That(privateKey, Is.EqualTo(TestData.DerivationKeyForSerialization));
        }

        [Test]
        public void SerializeDeserializeMasterKey()
        {
            var buffer = TestData.MasterKey.ToByteBuffer();
            MasterKey masterKey = buffer.ToMasterKey();

            Assert.That(masterKey, Is.EqualTo(TestData.MasterKey));
        }

        [Test]
        public void SerializeDeserializePublicDerivationKey()
        {
            PublicDerivationKey initialKey = NewTestData.DerivationKeyForSerialization.PublicDerivationKey;
            var buffer = initialKey.ToByteBuffer();
            PublicDerivationKey publicKey = buffer.ToPublicDerivationKey();
            var buf = publicKey.ToByteBuffer(); 
            Assert.That(buffer, Is.EqualTo(buf));
            Assert.That(publicKey, Is.EqualTo(TestData.DerivationKeyForSerialization.PublicDerivationKey));
        }

    }
}
