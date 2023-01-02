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

using KeyDerivation;
using KeyDerivation.Keys;
using KeyDerivationLib;

namespace KeyDerivationLibTests
{
    internal class TestKeyDerivationDetailsProvider : IKeyDerivationDetailsProvider
    {
        public string GetSaltPhrase()
        {
            return "Bla-bla";
        }

        public int GetSeedPhraseLength()
        {
            return 12;
        }

        public Dictionary<SpecialPgpKeyType, string> GetSpecialPgpKeyIdentities()
        {
            throw new NotImplementedException();
        }
    }

    public class SeedFactoryTests
    {
        private IKeyDerivationDetailsProvider KeyDerivationDetails = new TestKeyDerivationDetailsProvider();
        private MasterKeyFactory KeyFactory;

        [OneTimeSetUp]
        public void Setup()
        {
            KeyFactory = new MasterKeyFactory(KeyDerivationDetails);
        }

        [Test]
        public void GenerateSeedPhrase()
        {
            string[] seed = KeyFactory.GenerateSeedPhrase();

            Assert.That(KeyDerivationDetails.GetSeedPhraseLength(), Is.EqualTo(seed.Length), "Seed phrase has to contain not less than 12 words");
            foreach (var word in seed)
            {
                Assert.IsNotEmpty(word);
            }
        }

        [Test]
        public void GetMasterKey()
        {
            string[] seed = KeyFactory.GenerateSeedPhrase();
            MasterKey key = KeyFactory.GetMasterKey();

            Assert.That(key.Scalar.Length, Is.EqualTo(KeySerialization.PrivateKeyLength), "Master key scalar length is wrong");
            Assert.That(key.ChainCode.Length, Is.EqualTo(KeySerialization.KeyChainCodeLength), "Key chain code length is wrong");
        }

        [Test]
        public void IsWordExistInDictionary()
        {
            foreach (var pair in TestData.GetDictionaryTestData())
            {
                string word = pair.Key;
                bool isExist = pair.Value;

                Assert.That(MasterKeyFactory.IsWordExistInDictionary(word) == isExist);
            }
        }

        [Test]
        public void IsNullWordExistInDictionary()
        {
            string? nullWord = null;

            Assert.Throws<NullReferenceException>(() => MasterKeyFactory.IsWordExistInDictionary(nullWord));
        }

        [Test]
        public void OnlyExistingWordsInGeneratedSeed()
        {
            string[] seed = KeyFactory.GenerateSeedPhrase();
            foreach (var word in seed)
            {
                Assert.IsTrue(MasterKeyFactory.IsWordExistInDictionary(word));
            }
        }

        [Test]
        public void RestoreKeySuccess()
        {
            string[] seed = KeyFactory.GenerateSeedPhrase();
            MasterKey originalKey = KeyFactory.GetMasterKey();

            KeyFactory.RestoreSeedPhrase(seed);
            MasterKey restoredKey = KeyFactory.GetMasterKey();

            Assert.That(restoredKey, Is.EqualTo(originalKey));
        }

        [Test]
        public void RestoreKeyFail()
        {
            string[] randomSeed = KeyFactory.GenerateSeedPhrase();
            MasterKey randomKey = KeyFactory.GetMasterKey();

            KeyFactory.RestoreSeedPhrase(TestData.GetTestSeed());
            MasterKey restoredKey = KeyFactory.GetMasterKey();

            Assert.That(randomSeed, Is.Not.EqualTo(TestData.GetTestSeed()));
            Assert.That(randomKey, Is.Not.EqualTo(restoredKey));
        }
    }
}
