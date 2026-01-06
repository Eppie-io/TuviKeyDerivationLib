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

using System;

namespace KeyDerivation.Keys
{
    internal static class Secure
    {
#if NETSTANDARD2_0
        public static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }

            return diff == 0;
        }
#else
        public static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, b);
        }
#endif

        public static void Clear(byte[] data)
        {
#if NETSTANDARD2_0
            Array.Clear(data, 0, data.Length);
#else
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(data);
#endif
        }
    }
}
