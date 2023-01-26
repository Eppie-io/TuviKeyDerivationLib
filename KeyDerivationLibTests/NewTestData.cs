﻿///////////////////////////////////////////////////////////////////////////////
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
    internal static class NewTestData
    {
        public static readonly string[] TestSeedPhrase = {
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon"
        };

        public static readonly string[] TestSeedPhrase2 = {
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "ability"
        };

        public static string[] GetTestSeed()
        {
            return new string[] {
                "ozone",    "drill",    "grab",
                "fiber",    "curtain",  "grace",
                "pudding",  "thank",    "cruise",
                "elder",    "eight",    "picnic"
            };
        }

        public static List<KeyValuePair<string, bool>> GetDictionaryTestData()
        {
            return new List<KeyValuePair<string, bool>>()
            {
                new KeyValuePair<string, bool>("hello", true),
                new KeyValuePair<string, bool>("shine", true),
                new KeyValuePair<string, bool>("abracadabra", false),
                new KeyValuePair<string, bool>("fakdfbmsp", false)
            };
        }

        public static readonly MasterKey MasterKey = CreateMasterKey(TestSeedPhrase);

        public static readonly MasterKey MasterKey2 = CreateMasterKey(TestSeedPhrase2);

        private static MasterKey CreateMasterKey(string[] seedPhrase)
        {
            MasterKeyFactory factory = new MasterKeyFactory(new TestKeyDerivationDetailsProvider());
            factory.RestoreSeedPhrase(seedPhrase);
            return factory.GetMasterKey();
        }

        public static (byte[] scalar, byte[] chainCode) PrivateDerivationKey1 = (
            new byte[] {
                0xcc, 0xf6, 0xa0, 0xde, 0x4d, 0xc9, 0xcb, 0x52, 0xf6, 0xdf, 0xda, 0x87, 0xe1, 0x6d, 0x54, 0xaa,
                0x99, 0x7c, 0x16, 0x00, 0x39, 0xd3, 0xcf, 0xfa, 0x19, 0x6a, 0xf6, 0xd5, 0xd2, 0xb9, 0xce, 0xb9
            },
            new byte[] {
                0xf8, 0x24, 0x90, 0xae, 0xcb, 0x07, 0x81, 0x12, 0xbd, 0x20, 0xb5, 0x02, 0x05, 0x4a, 0x7c, 0x2c,
                0xee, 0x42, 0x24, 0xaf, 0xb5, 0x92, 0x8f, 0x77, 0x2a, 0xbf, 0x0f, 0x78, 0xc0, 0x2e, 0x9d, 0x74
            }
        );

        public static (byte[] scalar, byte[] chainCode) PrivateDerivationKey2 = (
            new byte[] {
                0x5f, 0x9a, 0xe0, 0x60, 0x8d, 0xf8, 0xde, 0x00, 0xf7, 0x1c, 0x9b, 0x9c, 0x38, 0x65, 0x67, 0x5e,
                0x96, 0xc0, 0x2d, 0x8e, 0xf0, 0x29, 0xf6, 0xd5, 0xaa, 0xfc, 0x4c, 0xae, 0xb2, 0x47, 0x88, 0xd1
            },
            new byte[] {
                0x7b, 0x85, 0x52, 0x37, 0x00, 0xb7, 0x87, 0x74, 0x38, 0xb6, 0x59, 0x14, 0xad, 0x22, 0x00, 0x57,
                0xab, 0x71, 0x6d, 0xa1, 0x82, 0x05, 0x2a, 0x7e, 0x22, 0xb8, 0x90, 0xb2, 0x35, 0x54, 0xd4, 0x88
            }
        );

        public static PrivateDerivationKey DerivationKeyForSerialization =
            DerivationKeyFactory.CreatePrivateDerivationKey(MasterKey, RightTag);

        public static readonly byte[] PrivateChildKey1 = new byte[32]
        {
            0xc3, 0xe3, 0x5f, 0xe4, 0xd0, 0x66, 0x3b, 0x06, 0xbf, 0x03, 0x2b, 0x3d, 0xe2, 0x10, 0x34, 0xc1,
            0x99, 0xc3, 0x3c, 0x12, 0xc8, 0xd0, 0x6c, 0xae, 0x0a, 0xb4, 0x41, 0x98, 0x80, 0xce, 0x06, 0x38
        };

        public static readonly byte[] PrivateChildKey2 = new byte[32]
        {
            0xb7, 0x48, 0x94, 0xbf, 0x2d, 0xd3, 0xd9, 0x68, 0x7d, 0xf0, 0x6b, 0x9f, 0x56, 0x85, 0x5a, 0x26,
            0xbe, 0x16, 0x45, 0xbf, 0x72, 0x8e, 0x2d, 0xe1, 0x35, 0xd2, 0x56, 0x17, 0x80, 0xdb, 0xbd, 0xe7
        };

        public const string RightTag = "test@user.net";

        public const string WrongTag = "abra-cadabra...";

        public static (byte[] compressedKey, byte[] chainCode) InitailPublicKey = (
           new byte[] {
                0x02, 
                0x63, 0xc1, 0x8e, 0xf9, 0xd2, 0xcb, 0xd4, 0x1a, 0xb2, 0x9f, 0xa2, 0xf8, 0xa6, 0x3b, 0xe4, 0x64,
                0x88, 0x00, 0xa9, 0x62, 0x47, 0xa7, 0xde, 0x26, 0x8b, 0xc8, 0x1e, 0x76, 0xf3, 0x71, 0x5c, 0x22
           },
           new byte[] {
                0xf8, 0x24, 0x90, 0xae, 0xcb, 0x07, 0x81, 0x12, 0xbd, 0x20, 0xb5, 0x02, 0x05, 0x4a, 0x7c, 0x2c,
                0xee, 0x42, 0x24, 0xaf, 0xb5, 0x92, 0x8f, 0x77, 0x2a, 0xbf, 0x0f, 0x78, 0xc0, 0x2e, 0x9d, 0x74
           }
       );

        public static (byte[] compressedKey, byte[] chainCode) ResultPublicKey = (
            new byte[] {
                0x03, 
                0x61, 0xf1, 0x0a, 0x0b, 0xec, 0x46, 0xc7, 0x49, 0x26, 0x44, 0xb9, 0xde, 0xac, 0x0d, 0x87, 0x94,
                0x39, 0x90, 0xfa, 0x8c, 0xc5, 0x36, 0x4d, 0xcc, 0x61, 0x98, 0x76, 0x81, 0x70, 0x26, 0x1b, 0xf3
            },
            new byte[] {
                0x37, 0x59, 0x66, 0x83, 0x01, 0x7b, 0x91, 0x86, 0x31, 0x4b, 0x20, 0x24, 0x3b, 0xb3, 0xbd, 0xfe,
                0xf3, 0xd4, 0x6e, 0xd0, 0xff, 0xf6, 0xfe, 0xbc, 0x28, 0xd7, 0x7e, 0x73, 0xe5, 0xf2, 0x70, 0x70
            }
        );
    }
}
