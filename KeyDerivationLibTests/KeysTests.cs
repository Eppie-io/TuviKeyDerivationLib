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

using KeyDerivationLib;

namespace KeyDerivationLibTests
{
    public class KeysTests
    {
        [Test]
        public void PrivateDerivationKeyEqualsCorrectWork()
        {
            var key1 = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, NewTestData.RightTag);
            var key2 = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, NewTestData.RightTag);
            var key3 = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, NewTestData.WrongTag);
            
            Assert.That(key1.Equals(key1), Is.EqualTo(true));
            Assert.That(key1.Equals(key2), Is.EqualTo(true));
            Assert.That(key1.Equals(key3), Is.EqualTo(false));
            Assert.That(key1!=key2, Is.EqualTo(false));
            Assert.That(key1!=key3, Is.EqualTo(true));
        }

        [Test]
        public void PublicDerivationKeyEqualsCorrectWork()
        {
            var key1 = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey, NewTestData.RightTag);
            var key2 = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey, NewTestData.RightTag);
            var key3 = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey, NewTestData.WrongTag);

            Assert.That(key1.Equals(key1), Is.EqualTo(true));
            Assert.That(key1.Equals(key2), Is.EqualTo(true));
            Assert.That(key1.Equals(key3), Is.EqualTo(false));
        }

        [Test]
        public void PrivateDerivationKeyGethashCodeCorrectWork()
        {
            var key = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, "");
            var key2 = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, "");
            var key3 = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, "text");

            Assert.That(key.GetHashCode(), Is.EqualTo(NewTestData.PrivateKeyHashCode));
            Assert.That(key.GetHashCode(), Is.EqualTo(key2.GetHashCode()));
            Assert.That(key.GetHashCode(), Is.Not.EqualTo(key3.GetHashCode()));
        }

        [Test]
        public void PublicDerivationKeyGethashCodeCorrectWork()
        {
            var key = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey, "");
            var key2 = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey, "");
            var key3 = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey, "text");

            Assert.That(key.GetHashCode(), Is.EqualTo(key2.GetHashCode()));
            Assert.That(key.GetHashCode(), Is.Not.EqualTo(key3.GetHashCode()));
        }
    }
}
