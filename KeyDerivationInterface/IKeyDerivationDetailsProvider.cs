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

using System.Collections.Generic;

namespace KeyDerivation
{
    /// <summary>
    /// Used to require some information from Application during master key generation process.
    /// </summary>
    public interface IKeyDerivationDetailsProvider
    {
        /// <summary>
        /// Each application has to return constant unique phrase used as a salt in key derivation process.
        /// </summary>
        string GetSaltPhrase();

        /// <summary>
        /// Get required seed phrase length.
        /// </summary>
        /// <returns></returns>
        int GetSeedPhraseLength();

        /// <summary>
        /// Get table of special PGP key identities.
        /// </summary>
        Dictionary<SpecialPgpKeyType, string> GetSpecialPgpKeyIdentities();
    }
    
    /// <summary>
    /// Enumeration of special PGP key types.
    /// </summary>
    public enum SpecialPgpKeyType
    {
        Backup
    }
}
