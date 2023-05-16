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
    public class DerivationKeyFactoryTests
    {
        [Test]
        public void PrivateDerivationKeysAreDeterministic()
        {
            var key1 = DerivationKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.RightTag);
            var key2 = DerivationKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.WrongTag);

            Assert.That(TestData.PrivateDerivationKey1.scalar, Is.EqualTo(key1.Scalar), "Key is not same as predicted");
            Assert.That(TestData.PrivateDerivationKey1.chainCode, Is.EqualTo(key1.ChainCode), "Key is not same as predicted");
            Assert.That(TestData.PrivateDerivationKey2.scalar, Is.EqualTo(key2.Scalar), "Key is not same as predicted");
            Assert.That(TestData.PrivateDerivationKey2.chainCode, Is.EqualTo(key2.ChainCode), "Key is not same as predicted");
        }

        [Test]
        public void PrivateDerivationKeysAreDifferentWithMasterKey()
        {
            var key1 = DerivationKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.RightTag);
            var key2 = DerivationKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey2, TestData.RightTag);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different MasterKey have to be different too");
        }

        [Test]
        public void PrivateDerivationKeysAreDifferentWithTags()
        {
            var key1 = DerivationKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.RightTag);
            var key2 = DerivationKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.WrongTag);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different userId have to be different too");
        }

        [Test]
        public void PrivateChildKeysAreDeterministic()
        {
            var derivationKey = DerivationKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.RightTag);

            var key1 = DerivationKeyFactory.DerivePrivateChildKey(derivationKey, 0);
            var key2 = DerivationKeyFactory.DerivePrivateChildKey(derivationKey, 1);

            Assert.That(TestData.PrivateChildKey1, Is.EqualTo(key1), "Key is not same as predicted");
            Assert.That(TestData.PrivateChildKey2, Is.EqualTo(key2), "Key is not same as predicted");
        }

        [Test]
        public void PrivateChildKeysAreDifferentWithMasterKey()
        {
            var derivationKey1 = DerivationKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.RightTag);
            var derivationKey2 = DerivationKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey2, TestData.RightTag);

            var key1 = DerivationKeyFactory.DerivePrivateChildKey(derivationKey1, 0);
            var key2 = DerivationKeyFactory.DerivePrivateChildKey(derivationKey2, 0);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different MasterKey have to be different too");
        }

        [Test]
        public void PrivateChildKeysAreDifferentWithTags()
        {
            var derivationKey1 = DerivationKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.RightTag);
            var derivationKey2 = DerivationKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.WrongTag);

            var key1 = DerivationKeyFactory.DerivePrivateChildKey(derivationKey1, 0);
            var key2 = DerivationKeyFactory.DerivePrivateChildKey(derivationKey2, 0);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different userId have to be different too");
        }

        [Test]
        public void PrivateChildKeysAreDifferentWithKeyIndex()
        {
            var derivationKey = DerivationKeyFactory.CreatePrivateDerivationKey(TestData.MasterKey, TestData.RightTag);

            var key1 = DerivationKeyFactory.DerivePrivateChildKey(derivationKey, 0);
            var key2 = DerivationKeyFactory.DerivePrivateChildKey(derivationKey, 1);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different KeyIndex have to be different too");
        }

        [Test]
        public void NullDerivationKeyParamThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => DerivationKeyFactory.DerivePrivateChildKey(null, 1));
        }
    }
}
