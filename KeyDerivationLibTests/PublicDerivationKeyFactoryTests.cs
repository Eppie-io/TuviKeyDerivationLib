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
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;
using KeyDerivation.Keys;

namespace KeyDerivationLibTests
{
    public class PublicDerivationKeyFactoryTests
    {
        [Test]
        public void PublicDerivationKeysAreDeterministic()
        {
            var initialPrivateKey = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, NewTestData.RightTag);
            var initialPublicKey = initialPrivateKey.PublicDerivationKey;
            var resultPublicKey = PublicDerivationKeyFactory.CreatePublicDerivationKey(initialPublicKey, NewTestData.RightTag);

            Assert.That(NewTestData.InitailPublicKey.compressedKey, Is.EqualTo(initialPublicKey.PublicKey.GetEncoded(true)), "Key is not same as predicted");
            Assert.That(NewTestData.InitailPublicKey.chainCode, Is.EqualTo(initialPublicKey.ChainCode), "Key is not same as predicted");
            Assert.That(NewTestData.ResultPublicKey.compressedKey, Is.EqualTo(resultPublicKey.PublicKey.GetEncoded(true)), "Key is not same as predicted");
            Assert.That(NewTestData.ResultPublicKey.chainCode, Is.EqualTo(resultPublicKey.ChainCode), "Key is not same as predicted");
        }

        [Test]
        public void PublicDerivationKeysAreDeterministicFromPrivateKey()
        {
            var initialPrivateKey = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, NewTestData.RightTag);
            var resultPublicKey = PublicDerivationKeyFactory.CreatePublicDerivationKey(initialPrivateKey, NewTestData.RightTag);

            Assert.That(NewTestData.InitailPublicKey.compressedKey, Is.EqualTo(initialPrivateKey.PublicDerivationKey.PublicKey.GetEncoded(true)), "Key is not same as predicted");
            Assert.That(NewTestData.InitailPublicKey.chainCode, Is.EqualTo(initialPrivateKey.PublicDerivationKey.ChainCode), "Key is not same as predicted");
            Assert.That(NewTestData.ResultPublicKey.compressedKey, Is.EqualTo(resultPublicKey.PublicKey.GetEncoded(true)), "Key is not same as predicted");
            Assert.That(NewTestData.ResultPublicKey.chainCode, Is.EqualTo(resultPublicKey.ChainCode), "Key is not same as predicted");
        }

        [Test]
        public void PublicDerivationKeysAreDifferentWithMasterKey()
        {
            var key1 = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey.PublicDerivationKey, NewTestData.RightTag);
            var key2 = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey2.PublicDerivationKey, NewTestData.RightTag);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different MasterKey have to be different too");
        }

        [Test]
        public void PublicDerivationKeysAreDifferentWithTags()
        {
            var key1 = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey.PublicDerivationKey, NewTestData.RightTag);
            var key2 = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey.PublicDerivationKey, NewTestData.WrongTag);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different userId have to be different too");
        }

        [Test]
        public void PublicChildKeysAreDifferentWithMasterKey()
        {
            var derivationKey1 = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey.PublicDerivationKey, NewTestData.RightTag);
            var derivationKey2 = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey2.PublicDerivationKey, NewTestData.RightTag);

            var key1 = PublicDerivationKeyFactory.DerivePublicChildKeyAsBytes(derivationKey1, 0);
            var key2 = PublicDerivationKeyFactory.DerivePublicChildKeyAsBytes(derivationKey2, 0);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different MasterKey have to be different too");
        }

        [Test]
        public void PublicChildKeysAreDifferentWithKeyIndex()
        {
            var derivationKey = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey.PublicDerivationKey, NewTestData.RightTag);

            var key1 = PublicDerivationKeyFactory.DerivePublicChildKeyAsBytes(derivationKey, 0);
            var key2 = PublicDerivationKeyFactory.DerivePublicChildKeyAsBytes(derivationKey, 1);

            Assert.That(key2, Is.Not.EqualTo(key1), "Keys with different KeyIndex have to be different too");
        }

        [Test]
        public void CompareChildDerivatedKeys()
        {
            var privateDerivationKey = PrivateDerivationKeyFactory.CreatePrivateDerivationKey(NewTestData.MasterKey, NewTestData.RightTag);
            var childPrivateKey = PrivateDerivationKeyFactory.DerivePrivateChildKey(privateDerivationKey, 0);

            string BitcoinEllipticCurveName = "secp256k1";
            DerObjectIdentifier curveOid = ECNamedCurveTable.GetOid(BitcoinEllipticCurveName);
            ECKeyGenerationParameters keyParams = new ECKeyGenerationParameters(curveOid, new SecureRandom());
            ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters("EC", new BigInteger(1, childPrivateKey), keyParams.PublicKeyParamSet);
            ECMultiplier multiplier = new FixedPointCombMultiplier();
            ECPoint q = multiplier.Multiply(keyParams.DomainParameters.G, privateKey.D); // child public key from private key

            var publicDerivationKey = PublicDerivationKeyFactory.CreatePublicDerivationKey(NewTestData.MasterKey.PublicDerivationKey, NewTestData.RightTag);
            var childPublicKey = PublicDerivationKeyFactory.DerivePublicChildKeyAsBytes(publicDerivationKey, 0);
            ECPoint q2 = keyParams.DomainParameters.Curve.DecodePoint(childPublicKey); // child public key from public key

            ECPoint q3 = PublicDerivationKeyFactory.DerivePublicChildKeyAsECPoint(publicDerivationKey, 0);

            Assert.That(q, Is.EqualTo(q2));
            Assert.That(q, Is.EqualTo(q3));
        }

        [Test]
        public void DerivePublicChildKeyAsBytesNullKeyParamThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => PublicDerivationKeyFactory.DerivePublicChildKeyAsBytes(null, 1));
        }

        [Test]
        public void CreatePublicChildKeyAsBytesNullKeyParamThrowsArgumentNullException()
        {
            PrivateDerivationKey? derivationKey = null;
            Assert.Throws<ArgumentNullException>(() => PublicDerivationKeyFactory.CreatePublicDerivationKey(derivationKey, ""));
        }
    }
}
