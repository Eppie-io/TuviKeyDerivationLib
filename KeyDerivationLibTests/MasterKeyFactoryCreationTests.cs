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
using KeyDerivationLib;

namespace KeyDerivationLibTests
{
    public class MasterKeyFactoryCreationTests
    {
        [Test]
        public void MasterKeyFactoryCreationNullProviderThrowArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new MasterKeyFactory(null),
                message: "Provider can not be a null.");
        }

        [TestCase(11)]
        [TestCase(13)]
        [TestCase(15)]
        [TestCase(18)]
        [TestCase(21)]
        [TestCase(24)]
        public void MasterKeyFactoryCreationWrongSeedPhraseLengthThrowArgumentException(int length)
        {
            var mock = new Mock<IKeyDerivationDetailsProvider>();
            mock.Setup(a => a.GetSeedPhraseLength()).Returns(length);

            Assert.Throws<ArgumentException>(() => new MasterKeyFactory(mock.Object),
                message: "Provider required parameters are not supported.");
        }

        [Test]
        public void MasterKeyFactoryCreationSuccessfulCreation()
        {
            int correctMnemonicLength = 12;
            var mock = new Mock<IKeyDerivationDetailsProvider>();
            mock.Setup(a => a.GetSeedPhraseLength()).Returns(correctMnemonicLength);
            Assert.DoesNotThrow(() => new MasterKeyFactory(mock.Object), "Exception was thrown but shouldn't.");
        }
        
        [Test]
        public void GetMasterKeyNullMnemonicThrowArgumentNullException()
        {
            var mock = new Mock<IKeyDerivationDetailsProvider>();
            mock.Setup(a => a.GetSeedPhraseLength()).Returns(12);
            MasterKeyFactory factory = new MasterKeyFactory(mock.Object);
            Assert.Throws<ArgumentNullException>(() => factory.GetMasterKey(),
                message: "Mnemonic can not be a null.");
        }
    }
}