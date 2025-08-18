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

using KeyDerivation.Entities;
using System;
using System.Linq;

namespace KeyDerivation.Keys
{
    /// <summary>
    /// Represents the master private derivation key in a hierarchical deterministic key derivation scheme,
    /// typically serving as the root key from which child keys are derived. This class is sealed and cannot be inherited.
    /// It inherits from <see cref="PrivateDerivationKey"/> and provides no additional functionality beyond initialization.
    /// </summary>
    public sealed class MasterKey : PrivateDerivationKey
    {
        public MasterKey(byte[] scalar, byte[] chainCode) : base(scalar, chainCode) { }
    }

    /// <summary>
    /// Represents a private derivation key for secp256k1, with secure disposal of sensitive data.
    /// This class is not thread-safe; concurrent access from multiple threads must be synchronized externally.
    /// </summary>
    /// <exception cref="KeyCreationException">Thrown if inputs are invalid.</exception>
    public class PrivateDerivationKey : IEquatable<PrivateDerivationKey>, IDisposable
    {
        private byte[] scalar;
        private byte[] chainCode;
        private PublicDerivationKey cachedPublicKey;
        private bool disposed;

        /// <summary>
        /// Gets the scalar value as a read-only memory.
        /// </summary>
        public ReadOnlyMemory<byte> Scalar
        {
            get
            {
                ThrowIfDisposed();

                return scalar.AsMemory();
            }
        }

        /// <summary>
        /// Gets the chain code as a read-only memory.
        /// </summary>
        public ReadOnlyMemory<byte> ChainCode
        {
            get
            {
                ThrowIfDisposed();

                return chainCode.AsMemory();
            }
        }

        /// <summary>
        /// Gets the corresponding public derivation key, lazily computed and cached.
        /// </summary>
        public PublicDerivationKey PublicDerivationKey
        {
            get
            {
                ThrowIfDisposed();

                if (cachedPublicKey is null)
                {
                    cachedPublicKey = new PublicDerivationKey(Scalar, ChainCode);
                }

                return cachedPublicKey;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PrivateDerivationKey"/> class from a private key scalar and a chain code.
        /// </summary>
        /// <param name="scalar">The private key scalar as a byte array.</param>
        /// <param name="chainCode">The chain code associated with the key as a byte array.</param>
        /// <exception cref="KeyCreationException">
        /// Thrown if the scalar or chain code is null, has invalid length, or is otherwise invalid.
        /// </exception>
        public PrivateDerivationKey(byte[] scalar, byte[] chainCode)
        {
            Verify(scalar, chainCode);

            this.scalar = scalar.ToArray();
            this.chainCode = chainCode.ToArray();
        }

        public override bool Equals(object obj) => Equals(obj as PrivateDerivationKey);

        public bool Equals(PrivateDerivationKey other)
        {
            ThrowIfDisposed();

            if (other is null)
            {
                return false; 
            }

            if (ReferenceEquals(this, other))
            {
                return true; 
            }

            return Secure.FixedTimeEquals(this.scalar.AsSpan(), other.scalar.AsSpan()) &&
                   Secure.FixedTimeEquals(this.chainCode.AsSpan(), other.chainCode.AsSpan());
        }

        public static bool operator ==(PrivateDerivationKey left, PrivateDerivationKey right)
        {
            if (left is null)
            {
                return right is null;
            }

            return left.Equals(right);
        }

        public static bool operator !=(PrivateDerivationKey left, PrivateDerivationKey right)
        {
            return !(left == right);
        }

        public override int GetHashCode()
        {
            ThrowIfDisposed();

            return PublicDerivationKey.GetHashCode();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed)
            {
                return; 
            }

            if (scalar != null)
            {
                Secure.Clear(scalar);
                scalar = null;
            }

            if (chainCode != null)
            {
                Secure.Clear(chainCode);
                chainCode = null;
            }

            if (disposing)
            {
                cachedPublicKey = null;
            }

            disposed = true;
        }

        ~PrivateDerivationKey()
        {
            Dispose(false);
        }

        private void ThrowIfDisposed()
        {
            if (disposed)
            {
                throw new ObjectDisposedException(nameof(PrivateDerivationKey));
            }
        }

        private static void Verify(byte[] scalar, byte[] chainCode)
        {
            if (scalar == null)
            {
                throw new KeyCreationException("Scalar cannot be null.");
            }

            if (chainCode == null)
            {
                throw new KeyCreationException("Chain code cannot be null.");
            }

            if (scalar.Length != Secp256k1.ScalarLength)
            {
                throw new KeyCreationException($"Scalar must be {Secp256k1.ScalarLength} bytes.");
            }

            if (chainCode.Length != Secp256k1.KeyChainCodeLength)
            {
                throw new KeyCreationException($"Chain code must be {Secp256k1.KeyChainCodeLength} bytes.");
            }
        }
    }
}
