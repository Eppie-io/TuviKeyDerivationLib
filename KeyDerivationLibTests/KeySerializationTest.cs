using KeyDerivation.Keys;

namespace KeyDerivationLibTests
{
    public class KeySerializationTest
    {
        [Test]
        public void SerializeDeserializePrivateKey()
        {
            var buffer = TestData.AccountKey1.ToByteBuffer();
            PrivateKey privateKey = buffer.ToPrivateKey();

            Assert.That(privateKey, Is.EqualTo(TestData.AccountKey1));
        }

        [Test]
        public void SerializeDeserializeMasterKey()
        {
            var buffer = TestData.MasterKey.ToByteBuffer();
            MasterKey masterKey = buffer.ToMasterKey();

            Assert.That(masterKey, Is.EqualTo(TestData.MasterKey));
        }
    }
}
