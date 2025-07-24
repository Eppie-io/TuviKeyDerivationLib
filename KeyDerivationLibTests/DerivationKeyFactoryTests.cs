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
using NBitcoin;

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

        [Test]
        public void CreatePrivateDerivationKeyBip44CreatesKey()
        {
            var masterKey = TestData.MasterKey;
            var derivedKey = DerivationKeyFactory.CreatePrivateDerivationKeyBip44(masterKey, 3630, 0, 10, 0);
            Assert.That(derivedKey, Is.Not.Null);
            Assert.That(derivedKey.Scalar, Is.Not.Null.And.Length.EqualTo(32));
            Assert.That(derivedKey.ChainCode, Is.Not.Null.And.Length.EqualTo(32));
        }

        [Test]
        public void CreatePrivateDerivationKeyBip44NullMasterKeyThrows()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DerivationKeyFactory.CreatePrivateDerivationKeyBip44(null, 3630, 0, 10, 0);
            });
        }

        [Test]
        public void CreatePrivateDerivationKeyBip44BoundaryIndices()
        {
            var masterKey = TestData.MasterKey;
            var minKey = DerivationKeyFactory.CreatePrivateDerivationKeyBip44(masterKey, 0, 0, 0, 0);
            var maxKey = DerivationKeyFactory.CreatePrivateDerivationKeyBip44(masterKey, int.MaxValue, int.MaxValue, int.MaxValue, int.MaxValue);
            Assert.That(minKey, Is.Not.Null);
            Assert.That(maxKey, Is.Not.Null);
            Assert.That(minKey.Scalar, Is.Not.Null.And.Length.EqualTo(32));
            Assert.That(maxKey.Scalar, Is.Not.Null.And.Length.EqualTo(32));
        }

        [Test]
        public void CreatePrivateDerivationKeyBip44Repeatability()
        {
            var masterKey = TestData.MasterKey;
            var key1 = DerivationKeyFactory.CreatePrivateDerivationKeyBip44(masterKey, 3630, 0, 10, 0);
            var key2 = DerivationKeyFactory.CreatePrivateDerivationKeyBip44(masterKey, 3630, 0, 10, 0);
            Assert.That(key1.Scalar, Is.EqualTo(key2.Scalar));
            Assert.That(key1.ChainCode, Is.EqualTo(key2.ChainCode));
        }

        [Test]
        public void CreatePrivateDerivationKeyBip44Uniqueness()
        {
            var masterKey = TestData.MasterKey;
            var key1 = DerivationKeyFactory.CreatePrivateDerivationKeyBip44(masterKey, 3630, 0, 10, 0);
            var key2 = DerivationKeyFactory.CreatePrivateDerivationKeyBip44(masterKey, 3630, 0, 10, 1);
            Assert.That(key1.Scalar, Is.Not.EqualTo(key2.Scalar));
            Assert.That(key1.ChainCode, Is.Not.EqualTo(key2.ChainCode));
        }

        [Test]
        public void CreatePrivateDerivationKeyBip44BitcoinStandardPath()
        {
            string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
            var mnemo = new Mnemonic(mnemonic, Wordlist.English);
            ExtKey masterExtKey = mnemo.DeriveExtKey();
            
            var masterKey = KeySerialization.ToPrivateDerivationKey(
                masterExtKey.PrivateKey.ToBytes(),
                masterExtKey.ChainCode
            );

            var keyPath = new KeyPath("m/44'/0'/0'/0/0");

            var customKey = DerivationKeyFactory.CreatePrivateDerivationKeyBip44(masterKey, 0, 0, 0, 0);

            var derivedExtKey = masterExtKey.Derive(keyPath);
            var standardScalar = derivedExtKey.PrivateKey.ToBytes();
            var standardChainCode = derivedExtKey.ChainCode;

            Assert.That(customKey.Scalar.SequenceEqual(standardScalar));
            Assert.That(customKey.ChainCode.SequenceEqual(standardChainCode));
           
            using (var customPrivateKey = new Key(customKey.Scalar))
            using (var standardPrivateKey = new Key(standardScalar))
            {
                var customAddress = customPrivateKey.PubKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main);
                var standardAddress = standardPrivateKey.PubKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main);
                Assert.That(customAddress == standardAddress);

                var customWif = customPrivateKey.GetWif(Network.Main);
                var standardWif = standardPrivateKey.GetWif(Network.Main);
                Assert.That(customWif == standardWif);
            }
        }
    }
}
