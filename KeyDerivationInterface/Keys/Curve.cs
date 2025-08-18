///////////////////////////////////////////////////////////////////////////////
//   Copyright 2025 Eppie (https://eppie.io)
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

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;

namespace KeyDerivation.Keys
{
    public static class Secp256k1
    {
        public const int KeyChainCodeLength = 32;
        public const int ScalarLength = 32;
        public const int PublicKeyLength = 33;

        public static readonly X9ECParameters CurveParams = ECNamedCurveTable.GetByName("secp256k1");
        public static readonly ECDomainParameters DomainParams =
            new ECDomainParameters(CurveParams.Curve, CurveParams.G, CurveParams.N, CurveParams.H, CurveParams.GetSeed());
    }

}
