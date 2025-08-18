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

using KeyDerivation.Entities;
using KeyDerivation.Keys;
using KeyDerivationLib;

namespace KeyDerivationLibTests
{
    public class KeysTests
    {
        [Test]
        public void PrivateDerivationKeyEqualsCorrectWork()
        {
            using var key1 = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, NewTestData.RightTag);
            using var key2 = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, NewTestData.RightTag);
            using var key3 = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, NewTestData.WrongTag);
            
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
            using var key = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, "");
            using var key2 = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, "");
            using var key3 = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, "text");

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

    [TestFixture]
    public class PrivateDerivationKeyTests
    {
        private static byte[] TestScalar
        {
            get
            {
                var data = new byte[Secp256k1.ScalarLength];
                data[^1] = 1; // ensure not all zeros
                return data;
            }
        }

        private static byte[] TestChainCode
        {
            get
            {
                var data = new byte[Secp256k1.KeyChainCodeLength];
                data[0] = 1; // ensure not all zeros
                return data;
            }
        }
        // -------------------- Constructor & Verify --------------------

        [Test]
        public void ConstructorThrowsWhenScalarIsNull()
        {
            Assert.That(() => new PrivateDerivationKey(null, TestChainCode),
                Throws.TypeOf<KeyCreationException>().With.Message.Contains("Scalar"));
        }

        [Test]
        public void ConstructorThrowsWhenChainCodeIsNull()
        {
            Assert.That(() => new PrivateDerivationKey(TestScalar, null),
                Throws.TypeOf<KeyCreationException>().With.Message.Contains("Chain code"));
        }

        [Test]
        public void ConstructorThrowsWhenScalarLengthInvalid()
        {
            var invalidScalar = new byte[Secp256k1.ScalarLength - 1];
            Assert.That(() => new PrivateDerivationKey(invalidScalar, TestChainCode),
                Throws.TypeOf<KeyCreationException>().With.Message.Contains("Scalar must be"));
        }

        [Test]
        public void ConstructorThrowsWhenChainCodeLengthInvalid()
        {
            var invalidChain = new byte[Secp256k1.KeyChainCodeLength - 1];
            Assert.That(() => new PrivateDerivationKey(TestScalar, invalidChain),
                Throws.TypeOf<KeyCreationException>().With.Message.Contains("Chain code must be"));
        }

        [Test]
        public void ConstructorCreatesIndependentCopies()
        {
            var scalar = (byte[])TestScalar.Clone();
            var chain = (byte[])TestChainCode.Clone();

            using var key = new PrivateDerivationKey(scalar, chain);

            scalar[0] = 42;
            chain[0] = 99;

            Assert.That(key.Scalar.Span[0], Is.Not.EqualTo(42), "Scalar should be copied internally");
            Assert.That(key.ChainCode.Span[0], Is.Not.EqualTo(99), "ChainCode should be copied internally");
        }

        // -------------------- Properties --------------------

        [Test]
        public void ScalarAndChainCodeReturnCorrectValues()
        {
            using var key = new PrivateDerivationKey(TestScalar, TestChainCode);

            Assert.That(key.Scalar.ToArray(), Is.EqualTo(TestScalar));
            Assert.That(key.ChainCode.ToArray(), Is.EqualTo(TestChainCode));
        }

        [Test]
        public void PropertiesThrowWhenDisposed()
        {
            var key = new PrivateDerivationKey(TestScalar, TestChainCode);
            key.Dispose();

            Assert.That(() => { var _ = key.Scalar; }, Throws.TypeOf<ObjectDisposedException>());
            Assert.That(() => { var _ = key.ChainCode; }, Throws.TypeOf<ObjectDisposedException>());
            Assert.That(() => { var _ = key.PublicDerivationKey; }, Throws.TypeOf<ObjectDisposedException>());
        }

        // -------------------- PublicDerivationKey --------------------

        [Test]
        public void PublicDerivationKeyIsLazyAndCached()
        {
            using var key = new PrivateDerivationKey(TestScalar, TestChainCode);

            var first = key.PublicDerivationKey;
            var second = key.PublicDerivationKey;

            Assert.That(second, Is.SameAs(first), "PublicDerivationKey should be cached");
        }

        // -------------------- Equals / Operators --------------------

        [Test]
        public void EqualsReturnsFalseWhenOtherIsNull()
        {
            using var key = new PrivateDerivationKey(TestScalar, TestChainCode);
            Assert.That(key, Is.Not.Null);
        }

        [Test]
        public void EqualsReturnsFalseWhenOtherType()
        {
            using var key = new PrivateDerivationKey(TestScalar, TestChainCode);
            Assert.That(key.Equals("not a key"), Is.False);
        }

        [Test]
        public void EqualsReturnsTrueForSameReference()
        {
            using var key = new PrivateDerivationKey(TestScalar, TestChainCode);
            Assert.That(key.Equals(key), Is.True);
        }

        [Test]
        public void EqualsReturnsTrueForSameValues()
        {
            using var key1 = new PrivateDerivationKey(TestScalar, TestChainCode);
            using var key2 = new PrivateDerivationKey(TestScalar, TestChainCode);

            Assert.That(key1.Equals(key2), Is.True);
            Assert.That(key1 == key2, Is.True);
            Assert.That(key1 != key2, Is.False);
        }

        [Test]
        public void EqualsReturnsFalseForDifferentScalar()
        {
            var scalar2 = (byte[])TestScalar.Clone();
            scalar2[0] = 2;

            using var key1 = new PrivateDerivationKey(TestScalar, TestChainCode);
            using var key2 = new PrivateDerivationKey(scalar2, TestChainCode);

            Assert.That(key1.Equals(key2), Is.False);
        }

        [Test]
        public void EqualsReturnsFalseForDifferentChainCode()
        {
            var chain2 = (byte[])TestChainCode.Clone();
            chain2[0] = 2;

            using var key1 = new PrivateDerivationKey(TestScalar, TestChainCode);
            using var key2 = new PrivateDerivationKey(TestScalar, chain2);

            Assert.That(key1.Equals(key2), Is.False);
        }

        // -------------------- GetHashCode --------------------

        [Test]
        public void GetHashCodeReturnsSameForEqualKeys()
        {
            using var key1 = new PrivateDerivationKey(TestScalar, TestChainCode);
            using var key2 = new PrivateDerivationKey(TestScalar, TestChainCode);

            Assert.That(key1.GetHashCode(), Is.EqualTo(key2.GetHashCode()));
        }

        [Test]
        public void GetHashCodeReturnsDifferentForDifferentKeys()
        {
            var chain2 = (byte[])TestChainCode.Clone();
            chain2[0] = 2;

            using var key1 = new PrivateDerivationKey(TestScalar, TestChainCode);
            using var key2 = new PrivateDerivationKey(TestScalar, chain2);

            Assert.That(key1.GetHashCode(), Is.Not.EqualTo(key2.GetHashCode()));
        }

        [Test]
        public void GetHashCodeThrowsWhenDisposed()
        {
            var key = new PrivateDerivationKey(TestScalar, TestChainCode);
            key.Dispose();

            Assert.That(() => key.GetHashCode(), Throws.TypeOf<ObjectDisposedException>());
        }

        // -------------------- Dispose --------------------

        [Test]
        public void DisposeClearsSensitiveData()
        {
            var key = new PrivateDerivationKey(TestScalar, TestChainCode);
            key.Dispose();

            Assert.That(() => { var _ = key.Scalar; }, Throws.TypeOf<ObjectDisposedException>());
        }

        [Test]
        public void DisposeCanBeCalledMultipleTimes()
        {
            using var key = new PrivateDerivationKey(TestScalar, TestChainCode);

            Assert.That(() => key.Dispose(), Throws.Nothing);
            Assert.That(() => key.Dispose(), Throws.Nothing);
        }
    }

    [TestFixture]
    public class MasterKeyTests
    {
        private static byte[] TestScalar
        {
            get
            {
                var data = new byte[Secp256k1.ScalarLength];
                data[^1] = 1; // ensure not all zeros
                return data;
            }
        }

        private static byte[] TestChainCode
        {
            get
            {
                var data = new byte[Secp256k1.KeyChainCodeLength];
                data[0] = 1; // ensure not all zeros
                return data;
            }
        }

        [Test]
        public void MasterKeyCanBeCreatedAndUsed()
        {
            using var master = new MasterKey(TestScalar, TestChainCode);

            Assert.That(master.Scalar.Length, Is.EqualTo(Secp256k1.ScalarLength));
            Assert.That(master.ChainCode.Length, Is.EqualTo(Secp256k1.KeyChainCodeLength));
            Assert.That(master.PublicDerivationKey, Is.Not.Null);
        }

        [Test]
        public void MasterKeyThrowIfNotValid()
        {
            var notValidScalar = new byte[Secp256k1.ScalarLength];
            var notValidChainCode = new byte[Secp256k1.KeyChainCodeLength];

            using var master = new MasterKey(notValidScalar, notValidChainCode);

            Assert.That(() => { var _ = master.PublicDerivationKey; }, Throws.TypeOf<KeyCreationException>());
        }
    }
}
