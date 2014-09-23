/*
 *  Copyright © 2014 Thomas R. Lawrence
 *    except: "SkeinFish 0.5.0/*.cs", which are Copyright © 2010 Alberto Fajardo
 *    except: "SerpentEngine.cs", which is Copyright © 1997, 1998 Systemics Ltd on behalf of the Cryptix Development Team (but see license discussion at top of that file)
 * 
 *  GNU General Public License
 * 
 *  This file is part of Backup (CryptSikyur-Archiver)
 * 
 *  Backup (CryptSikyur-Archiver) is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
*/
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using Serpent;
using SkeinFish;

namespace Backup
{
    ////////////////////////////////////////////////////////////////////////////
    //
    // Composable cryptographic ciphersuites
    //
    ////////////////////////////////////////////////////////////////////////////

    // Interface defines a "crypto system" which includes:
    // - a key derivation method (from passphrase)
    // - a cipher applicable to byte streams
    // - a signed key hash (HMAC) provider
    // - encrypt and decrypt streams
    // - key lengths of various keys used by above components
    public interface ICryptoSystem
    {
        string Name { get; }
        string Description { get; }

        // Password salt is used during password to master key derivation.
        // It may be the same value in several different files, to ensure the same master
        // key is derived (which improves multi-file archive performance).
        int PasswordSaltLengthBytes { get; }

        int CipherBlockLengthBytes { get; }
        int MasterKeyLengthBytes { get; }
        int CipherKeyLengthBytes { get; }
        int SigningKeyLengthBytes { get; }
        // The per-file salt is used during session (file) key derivation.
        // It must be different for each individual file, to ensure session (file) keys
        // are unique for each file. (This derivation is faster.)
        int FileSaltLengthBytes { get; }
        int InitialVectorLengthBytes { get; }

        int DefaultRfc2898Rounds { get; }

        void DeriveMasterKey(ProtectedArray<byte> password, byte[] passwordSalt, int rounds, out ProtectedArray<byte> masterKey);
        void DeriveSessionKeys(ProtectedArray<byte> masterKey, byte[] salt, out CryptoKeygroup sessionKeys);
        void DeriveNewSessionKeys(ProtectedArray<byte> masterKey, out byte[] salt, out CryptoKeygroup sessionKeys);

        byte[] CreateRandomBytes(int count);

        int MACLengthBytes { get; }
        Core.ICheckValueGenerator CreateMACGenerator(byte[] signingKey);

        Stream CreateEncryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter);
        Stream CreateDecryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter);

        string UniquePersistentCiphersuiteIdentifier { get; }

        void Test();
    }

    public class CryptoKeygroupLengths
    {
        public readonly int CipherKeyLengthBytes;
        public readonly int SigningKeyLengthBytes;
        public readonly int InitialCounterLengthBytes;

        public CryptoKeygroupLengths(int cipherKeyLengthBytes, int signingKeyLengthBytes, int initialCounterLengthBytes)
        {
            this.CipherKeyLengthBytes = cipherKeyLengthBytes;
            this.SigningKeyLengthBytes = signingKeyLengthBytes;
            this.InitialCounterLengthBytes = initialCounterLengthBytes;
        }
    }

    public class CryptoKeygroup : IDisposable
    {
        public readonly byte[] CipherKey;
        public readonly byte[] SigningKey;
        public readonly byte[] InitialCounter;

        public CryptoKeygroup(byte[] cipherKey, byte[] signingKey, byte[] initialCounter)
        {
            this.CipherKey = cipherKey;
            this.SigningKey = signingKey;
            this.InitialCounter = initialCounter;
        }

        public void Dispose()
        {
        }
    }

    // ICryptoSystem is built from composable crypto system components:

    public interface ICryptoSystemRandomNumberGeneration
    {
        byte[] CreateRandomBytes(int count);

        void Test();
    }

    public interface ICryptoSystemBlockCipher
    {
        int CipherBlockLengthBytes { get; }
        int CipherKeyLengthBytes { get; }
        int InitialVectorLengthBytes { get; }

        Stream CreateEncryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter);
        Stream CreateDecryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter);

        void Test();
    }

    public interface ICryptoSystemAuthentication
    {
        int SigningKeyLengthBytes { get; }

        int MACLengthBytes { get; }
        Core.ICheckValueGenerator CreateMACGenerator(byte[] signingKey);

        void Test();
    }

    public interface ICryptoSystemKeyGeneration
    {
        int PasswordSaltLengthBytes { get; }
        int MasterKeyLengthBytes { get; }
        int FileSaltLengthBytes { get; }

        int DefaultRfc2898Rounds { get; }

        void DeriveMasterKey(ProtectedArray<byte> password, byte[] passwordSalt, int rounds, out ProtectedArray<byte> masterKey);
        void DeriveSessionKeys(ProtectedArray<byte> masterKey, byte[] salt, CryptoKeygroupLengths sessionKeyLengths, out CryptoKeygroup sessionKeys);
        void DeriveNewSessionKeys(ICryptoSystemRandomNumberGeneration rng, ProtectedArray<byte> masterKey, out byte[] salt, CryptoKeygroupLengths sessionKeyLengths, out CryptoKeygroup sessionKeys);

        void Test();
    }

    // Crypto system component composition class

    public abstract class CryptoSystemComposable : ICryptoSystem
    {
        private bool firstEncrypt = true;
        private ICryptoSystemRandomNumberGeneration rng;
        private ICryptoSystemBlockCipher cipher;
        private ICryptoSystemAuthentication auth;
        private ICryptoSystemKeyGeneration keygen;

        public CryptoSystemComposable(
            ICryptoSystemRandomNumberGeneration rng,
            ICryptoSystemBlockCipher cipher,
            ICryptoSystemAuthentication auth,
            ICryptoSystemKeyGeneration keygen)
        {
            this.rng = rng;
            this.cipher = cipher;
            this.auth = auth;
            this.keygen = keygen;
        }

        public abstract string Name { get; }
        public abstract string Description { get; }

        public abstract bool Weak { get; }

        public int PasswordSaltLengthBytes { get { return keygen.PasswordSaltLengthBytes; } }

        public int CipherBlockLengthBytes { get { return cipher.CipherBlockLengthBytes; } }
        public int MasterKeyLengthBytes { get { return keygen.MasterKeyLengthBytes; } }
        public int CipherKeyLengthBytes { get { return cipher.CipherKeyLengthBytes; } }
        public int SigningKeyLengthBytes { get { return auth.SigningKeyLengthBytes; } }
        public int FileSaltLengthBytes { get { return keygen.FileSaltLengthBytes; } }
        public int InitialVectorLengthBytes { get { return cipher.InitialVectorLengthBytes; } }

        public int DefaultRfc2898Rounds { get { return keygen.DefaultRfc2898Rounds; } }

        public void DeriveMasterKey(ProtectedArray<byte> password, byte[] passwordSalt, int rounds, out ProtectedArray<byte> masterKey)
        {
            keygen.DeriveMasterKey(password, passwordSalt, rounds, out masterKey);
        }

        public void DeriveSessionKeys(ProtectedArray<byte> masterKey, byte[] salt, out CryptoKeygroup sessionKeys)
        {
            keygen.DeriveSessionKeys(masterKey, salt, new CryptoKeygroupLengths(CipherKeyLengthBytes, SigningKeyLengthBytes, InitialVectorLengthBytes), out sessionKeys);
        }

        public void DeriveNewSessionKeys(ProtectedArray<byte> masterKey, out byte[] salt, out CryptoKeygroup sessionKeys)
        {
            keygen.DeriveNewSessionKeys(rng, masterKey, out salt, new CryptoKeygroupLengths(CipherKeyLengthBytes, SigningKeyLengthBytes, InitialVectorLengthBytes), out sessionKeys);
        }

        public byte[] CreateRandomBytes(int count)
        {
            return rng.CreateRandomBytes(count);
        }

        public int MACLengthBytes { get { return auth.MACLengthBytes; } }

        public Core.ICheckValueGenerator CreateMACGenerator(byte[] signingKey)
        {
            return auth.CreateMACGenerator(signingKey);
        }

        public Stream CreateEncryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
        {
            if (firstEncrypt)
            {
                firstEncrypt = false;
                if (Weak)
                {
                    Core.ConsoleWriteLineColor(ConsoleColor.Yellow, "Ciphersuite {0} is considered weak. Encrypting new data with it is not recommended", Name);
                }
            }

            return cipher.CreateEncryptStream(stream, cipherKey, initialCounter);
        }

        public Stream CreateDecryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
        {
            return cipher.CreateDecryptStream(stream, cipherKey, initialCounter);
        }

        public abstract string UniquePersistentCiphersuiteIdentifier { get; }

        public void Test()
        {
            rng.Test();
            cipher.Test();
            auth.Test();
            keygen.Test();
        }
    }

    // Supported crypto system configurations

    public class CryptoSystemAES128 : CryptoSystemComposable
    {
        // why not 256? see https://www.schneier.com/blog/archives/2009/07/another_new_aes.html

        public CryptoSystemAES128()
            : base(new CryptoSystemDefaultRNG(), new CryptoSystemBlockCipherAES128(), new CryptoSystemAuthenticationHMACSHA256(), new CryptoSystemKeyGenerationRfc2898Rfc5869())
        {
        }

        public override string Name { get { return "aes128"; } }
        public override string Description { get { return "AES-128 CTR, HMAC-SHA-256"; } }

        public override bool Weak { get { return false; } }

        public override string UniquePersistentCiphersuiteIdentifier { get { return "\x02"; } }
    }

    public class CryptoSystemSerpent256 : CryptoSystemComposable
    {
        public CryptoSystemSerpent256()
            : base(new CryptoSystemDefaultRNG(), new CryptoSystemBlockCipherSerpent256(), new CryptoSystemAuthenticationHMACSHA256(), new CryptoSystemKeyGenerationRfc2898Rfc5869())
        {
        }

        public override string Name { get { return "serpent256"; } }
        public override string Description { get { return "Serpent-256 (128 bit blocks) CTR, HMAC-SHA-256"; } }

        public override bool Weak { get { return false; } }

        public override string UniquePersistentCiphersuiteIdentifier { get { return "\x03"; } }
    }

    // Threefish is a block cipher underlying Skein, a NIST SHA-3 hash competition
    // finalist. The Skein/ThreeFish information portal is at:
    // https://www.schneier.com/skein.html
    // which provides reference source code, papers, test vectors, optimized code, etc.
    public class CryptoSystemThreefish1024 : CryptoSystemComposable
    {
        public CryptoSystemThreefish1024()
            : base(new CryptoSystemDefaultRNG(), new CryptoSystemBlockCipherThreefish1024(), new CryptoSystemAuthenticationHMACSkein1024(), new CryptoSystemKeyGenerationRfc2898Rfc5869())
        {
        }

        public override string Name { get { return "3fish1024"; } }
        public override string Description { get { return "ThreeFish-1024 CTR, HMAC-Skein-1024"; } }

        public override bool Weak { get { return false; } }

        public override string UniquePersistentCiphersuiteIdentifier { get { return "\x04"; } }
    }

    // Ferguson, Schneier, and Kohno [Cryptography Engineering, 2010, page 129]
    // are rather critical of systems that provide huge numbers of cipher suites.
    // In that spirit, our goal is to keep the list here to a minimum, trying to
    // provide just a few options to cover most goals.
    public static class CryptoSystems
    {
        public readonly static ICryptoSystem[] List = new ICryptoSystem[]
        {
            // AES128 may not be the strongest cipher but has a lot going for it
            // - standardized, and probably the *primary* standard today (2014)
            // - certainly the most scrutinized and attacked cipher today
            // - sufficient security with high performance (and hardware acceleration) available if needed
            new CryptoSystemAES128(),

            // Serpent was a runner-up in the AES competition. It is arguably more secure,
            // especially now, more than 10 years after Rijndael was selected, when it is showing
            // it's age. In particular, Rijndael with 256 bit keys is seen to be flawed.
            // Therefore, Serpent-256 is included here to provide a conservative option for
            // doubling the key length.
            // Interesting for testing because block length (128 bits) is different from key
            // length (256 bits).
            new CryptoSystemSerpent256(),

            // Threefish 1024 is the only very large block size cipher available at this time
            // that (as a SHA3 finalist) has undergone more than cursory scrutiny.
            new CryptoSystemThreefish1024(),


            // Eventually there will be a large-block cipher from NIST that would be
            // suitable to replace ThreeFish-1024
            // Also, once Keccak hash gets more scrutiny, that might make an appropriate
            // replacement for keyed-MAC.
        };
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Cryptographic primitives
    //
    ////////////////////////////////////////////////////////////////////////////

    // Miscellaneous references:
    //
    // Phillip Rogaway's 2011 review of block cipher modes of operation
    // http://cs.ucdavis.edu/~rogaway/papers/modes.pdf
    //
    // NIST AES description
    // from http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    //
    // Other NIST links
    // http://csrc.nist.gov/groups/STM/cavp/index.html

    // On modes of operation:
    // Ferguson and Schneier preferred CTR and CBC
    // [ http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29
    // Niels Ferguson, Bruce Schneier, Tadayoshi Kohno, Cryptography Engineering, page 71, 2010]
    // however, acrording to this: http://crypto.stackexchange.com/questions/1849/why-not-use-ctr-with-a-randomized-iv
    // they prefer CBC because CTR requires a nonce used at most once per key, ever,
    // which is hard to get right.
    //
    // On Authenticated Encryption (AE) by generic composition:
    // Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text.
    // http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html
    // with reference: M. Bellare and C. Namprempre, Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm, July 2007
    // (http://cseweb.ucsd.edu/users/mihir/papers/oem.pdf)
    // However, then there is C. Namprempre, P. Rogaway, and T. Shrimpton
    // claiming that it is not so clearcut:
    // http://eprint.iacr.org/2014/206 (or http://eprint.iacr.org/2014/206.pdf )
    // Also related is Hugo Krawczyk:
    // The Order of Encryption and Authentication for Protecting Communications
    // http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.106.5488&rep=rep1&type=pdf
    // Ferguson, Schneier, Kohno, Cryptography Engineering, 2010, Wiley Publishing
    // warn about the risk of omitting meta information (request header fields, file format
    // versions, etc) from the MAC with encrypt-then-MAC, which is easy to do since it
    // may be located somewhere other than the "plaintext stream" - but also easy to
    // do in MAC-first schemes (e.g. forgetting to include IVs in the MAC). Also, there is
    // no detection of using the wrong message key to decrypt (unless the MAC key is derived
    // in tandem with the message key in such a way that you would have both or neither).
    // Also, the risk with Encrypt-then-MAC of authenticating, but decrypting with the wrong
    // session key (because it's not in the MAC). One solution is to derive both session
    // and MAC key from one master key, but they complain that increases system complexity.
    // See chapter 7, section 7.2, page 102-104 in the above.
    // Why to verify MAC before decrypting (Moxie Marlinspike):
    // http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/
    // Ultimately, random-initialized AES-CTR followed by SHA-256 HMAC on the entire encrypted stream (including random start value) is still a good choice.
    //
    // Brief discussion of Padding Oracle Attack, with references.
    // http://www.limited-entropy.com/padding-oracle-attacks/
    //
    // Short summary of HMAC
    // http://en.wikipedia.org/wiki/HMAC
    // http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf

    // Implementations

    // Important note:
    // The implementations below are designed to be simple, in order to amke it easier
    // to ensure correctness. This may come at the cost of some efficiency.
    // In particular, there are several implementations of .NET's ICryptoTransform.
    // These implementations are simplified and do not provide full functionality,
    // particularly around object reusability. This means some classes (in particular,
    // the keyed hash functions) destroy themselves upon TransformFinalBlock() and must
    // be re-created for each use, even if the key does not change across uses.


    // Implementation of "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)",
    // as described in RFC 5869, using HMAC-SHA-256 as the hash function
    public class CryptoPrimitiveHKDFSHA256 : CryptoPrimitiveHKDF
    {
        public const int HashLen = 32;

        public CryptoPrimitiveHKDFSHA256()
            : base(new CryptoPrimitiveIteratedHashProviderSHA256())
        {
            Debug.Assert(HashLen == base.hashProvider.OutputLengthBytes);
            Debug.Assert(HashLen == base.hashLen);
        }

        private sealed class HKDFTestVector
        {
            internal readonly byte[] ikm;
            internal readonly byte[] salt;
            internal readonly byte[] info;
            internal readonly int l;

            internal readonly byte[] prk;
            internal readonly byte[] okm;

            internal HKDFTestVector(string ikm, string salt, string info, int l, string prk, string okm)
            {
                this.ikm = Core.HexDecode(ikm);
                this.salt = salt != null ? Core.HexDecode(salt) : null;
                this.info = info != null ? Core.HexDecode(info) : null;
                this.l = l;
                this.prk = Core.HexDecode(prk);
                this.okm = Core.HexDecode(okm);
            }
        }

        private readonly static HKDFTestVector[] TestVectorsHKDFSHA256 = new HKDFTestVector[]
            {
                // A.1. Test Case 1 - Basic test case with SHA-256
                new HKDFTestVector("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
                // A.2. Test Case 2 - Test with SHA-256 and longer inputs/outputs
                new HKDFTestVector("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", 82, "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"),
                // A.3. Test Case 3 - Test with SHA-256 and zero-length salt/info
                new HKDFTestVector("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", null, null, 42, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
            };

        public static void Test()
        {
            CryptoPrimitiveHKDF hkdf = new CryptoPrimitiveHKDF(new CryptoPrimitiveIteratedHashProviderSHA256());

            foreach (HKDFTestVector testVector in TestVectorsHKDFSHA256)
            {
                byte[] prk;
                ProtectedArray<byte> ikmProtected = new ProtectedArray<byte>(testVector.ikm.Length);
                ikmProtected.Reveal();
                Buffer.BlockCopy(testVector.ikm, 0, ikmProtected.ExposeArray(), 0, testVector.ikm.Length);
                ikmProtected.Protect();
                hkdf.Extract(testVector.salt, ikmProtected, out prk);
                if (!Core.ArrayEqual(prk, testVector.prk))
                {
                    throw new ApplicationException("HKDF-SHA256 implementation defect");
                }

                byte[] okm;
                hkdf.Expand(prk, testVector.info, testVector.l, out okm);
                if (!Core.ArrayEqual(okm, testVector.okm))
                {
                    throw new ApplicationException("HKDF-SHA256 implementation defect");
                }
            }
        }
    }

    // Generic implementation of "HMAC-based Extract-and-Expand Key Derivation
    // Function (HKDF)", described in RFC 5869.
    // see http://tools.ietf.org/html/rfc5869
    // The HKDF is a generalization of earlier methods, including the PRF+ method
    // described in section 2.13 of RFC 4306 and others:
    // http://tools.ietf.org/html/rfc4306#section-2.13
    // http://tools.ietf.org/html/rfc5996#section-2.13
    public class CryptoPrimitiveHKDF
    {
        protected readonly ICryptoPrimitiveIteratedHashProvider hashProvider;
        protected readonly int hashLen;

        public CryptoPrimitiveHKDF(ICryptoPrimitiveIteratedHashProvider hashProvider)
        {
            this.hashProvider = hashProvider;
            this.hashLen = hashProvider.OutputLengthBytes;
        }

        // Extract a key from salt (ideally HashLen bytes), IKM ("initial key material")
        // which may be non-uniformly distributed, producing PRK ("pseudo-random key")
        // Salt is optional; in that case it is replaced by HashLen bytes of zero.
        public void Extract(byte[] salt, ProtectedArray<byte> ikm, out byte[] prk)
        {
            if (salt == null)
            {
                salt = new byte[hashLen];
            }

            try
            {
                ikm.Reveal();
                using (CryptoPrimitiveHMAC hmac = new CryptoPrimitiveHMAC(hashProvider, salt/*key*/))
                {
                    prk = hmac.ComputeHash(ikm.ExposeArray());
                }
            }
            finally
            {
                ikm.Protect();
            }
        }

        // Expand a pseudo-random key (PRK), optional info (which may be null), into
        // key material of length l, in OKM ("output key material")
        public void Expand(byte[] prk, byte[] info, int l, out byte[] okm)
        {
            if (prk == null)
            {
                throw new ArgumentNullException();
            }
            if (!(l <= 255 * hashLen))
            {
                throw new ArgumentException();
            }

            if (info == null)
            {
                info = new byte[0];
            }

            byte counter = 1;

            byte[] t = new byte[hashLen + info.Length + 1];
            int tLen = 0;

            okm = new byte[l];
            int i = 0;
            while (i < okm.Length)
            {
                Buffer.BlockCopy(info, 0, t, tLen, info.Length);
                tLen += info.Length;
                Debug.Assert(counter != 0);
                t[tLen++] = counter++;
                byte[] output;
                using (CryptoPrimitiveHMAC hmac = new CryptoPrimitiveHMAC(hashProvider, prk/*key*/)) // inefficient to recreate, but my super-simple implementation of HMAC doesn't support reuse
                {
                    output = hmac.ComputeHash(t, 0, tLen);
                }
                Debug.Assert(output.Length == hashLen);
                Buffer.BlockCopy(output, 0, t, 0, output.Length);
                tLen = output.Length;

                int needed = Math.Min(okm.Length - i, tLen);
                Buffer.BlockCopy(t, 0, okm, i, needed);
                i += needed;
            }
        }
    }


    public interface ICryptoPrimitiveIteratedHashProvider
    {
        HashAlgorithm GetHash();
        int BlockLengthBytes { get; } // iterated hash algorithm internal block length
        int OutputLengthBytes { get; } // hash algorithm final result length
    }

    public sealed class CryptoPrimitiveIteratedHashProviderSHA256 : ICryptoPrimitiveIteratedHashProvider
    {
        public HashAlgorithm GetHash()
        {
            HashAlgorithm hash = SHA256.Create();
            Debug.Assert(hash.HashSize == OutputLengthBytes * 8);
            return hash;
        }

        public int BlockLengthBytes { get { return 64; } } // iterated hash algorithm internal block length
        public int OutputLengthBytes { get { return 32; } } // hash algorithm final result length
    }

    public sealed class CryptoPrimitiveIteratedHashProviderSkein1024 : ICryptoPrimitiveIteratedHashProvider
    {
        public HashAlgorithm GetHash()
        {
            HashAlgorithm hash = new Skein(BlockLengthBytes * 8, OutputLengthBytes * 8);
            Debug.Assert(hash.HashSize == OutputLengthBytes * 8);
            return hash;
        }

        public int BlockLengthBytes { get { return 1024 / 8; } } // iterated hash algorithm internal block length
        public int OutputLengthBytes { get { return 1024 / 8; } } // hash algorithm final result length
    }


    // Notes on keying the HMAC function (in this application):
    //
    // There is no provision for explicitly validating the cipher key in the HMAC
    // scheme used here. However, the cipher key and signing key are derived from
    // the same passphrase using the same process, so one would expect to have both
    // or neither.
    //
    // Ordinarily, the HMAC on very short messages (empty file or a couple of bytes)
    // would seem to risk divulging information about the key, since the length of
    // plaintext is known from the ciphertext, and the HMAC would depend mostly on the
    // signing key. If the HMAC is weak in some way, there could be an attack.
    // Using salt at the start of a file would mitigate that. However, in practice,
    // with the 32-byte session-key salt at the top of each stream, there are 2 blocks
    // (with AES128) of essentially random data that impacts the HMAC, so it is
    // considered unnecessary to add additional salt.

    // Generic HMAC implementation
    // Described by RFC 2104 "HMAC: Keyed-Hashing for Message Authentication":
    // http://tools.ietf.org/html/rfc2104
    // for use with iterated hash functions.
    public class CryptoPrimitiveHMAC : ICryptoTransform, IDisposable
    {
        private ICryptoPrimitiveIteratedHashProvider hashProvider;
        private HashAlgorithm innerHash;
        private int B; // RFC 2104 constant: hash function internal block length [SHA256]
        private int L; // RFC 2104 constant: hash function output length [SHA256]
        private byte[] key;

        private const byte ipad = 0x36;
        private const byte opad = 0x5C;

        private const int WorkspaceCapacityTarget = Core.Constants.BufferSize;
        private byte[] workspace;
        private int index;
        private bool started;

        private byte[] hash;

        public CryptoPrimitiveHMAC(ICryptoPrimitiveIteratedHashProvider hashProvider, byte[] key)
        {
            B = hashProvider.BlockLengthBytes;
            L = hashProvider.OutputLengthBytes;

#if false // causes short key test case to fail
            // per RFC 2104: minimum recommended key length is L. As we generate keys
            // by an expansion function, there is no need for us to risk supporting short keys here.
            if (key.Length < L)
            {
                throw new ArgumentException();
            }
#endif

            // per RFC 2014: keys longer than internal block length are hashed once
            if (key.Length > B)
            {
                using (HashAlgorithm keyHash = hashProvider.GetHash())
                {
                    key = keyHash.ComputeHash(key);
                }
            }

            // RFC 2104, section 2: Definition of HMAC
            // Step (1)
            if (key.Length < B)
            {
                // short keys are padded with zeroes
                Array.Resize(ref key, B);
            }

            this.hashProvider = hashProvider;
            this.innerHash = hashProvider.GetHash();
            this.key = key;

            int WorkspaceCapacity = WorkspaceCapacityTarget / B;
            WorkspaceCapacity *= B;
            this.workspace = new byte[WorkspaceCapacity];

            PrepareWorkspace(ipad);
        }

        private void PrepareWorkspace(byte pad)
        {
            // RFC 2104, section 2: Definition of HMAC
            // Step (2)
            index = 0;
            for (int i = 0; i < B; i++)
            {
                workspace[index++] = (byte)(pad ^ key[i]);
            }
        }

        public int HashSize { get { return hashProvider.OutputLengthBytes * 8; } }

        public bool CanReuseTransform { get { return false; } }
        public bool CanTransformMultipleBlocks { get { return true; } }
        public int InputBlockSize { get { return 1; } } // NOT the hash internal block size, but the transform's block size
        public int OutputBlockSize { get { return 1; } } // NOT the hash internal block size, but the transform's block size

        public byte[] Hash
        {
            get
            {
                if (hash == null)
                {
                    throw new InvalidOperationException();
                }
                return hash;
            }
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (innerHash == null)
            {
                throw new InvalidOperationException();
            }

            started = true;

            for (int i = 0; i < inputCount; i++)
            {
                workspace[index++] = inputBuffer[i + inputOffset];

                if (index == workspace.Length)
                {
                    // RFC 2104, section 2: Definition of HMAC
                    // Step (3): append text to stream
                    // Step (4): apply H (iteratively)
                    int transformed = innerHash.TransformBlock(workspace, 0, index, null, 0);
                    if (transformed != index)
                    {
                        throw new InvalidOperationException();
                    }

                    index = 0;
                }
            }
            return inputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (innerHash == null)
            {
                throw new InvalidOperationException();
            }

            this.TransformBlock(inputBuffer, inputOffset, inputCount, null, 0);
            if (index != 0)
            {
                // RFC 2104, section 2: Definition of HMAC
                // Step (4): apply H (iteratively) - flush remaining input
                int transformed = innerHash.TransformBlock(workspace, 0, index, null, 0);
                if (transformed != index)
                {
                    throw new InvalidOperationException();
                }
                index = 0;
            }

            // RFC 2104, section 2: Definition of HMAC
            // Step (4): apply H (iteratively) - final
            innerHash.TransformFinalBlock(workspace, 0, 0);
            byte[] innerHashResult = innerHash.Hash;

            ((IDisposable)innerHash).Dispose();
            innerHash = null;

            // RFC 2104, section 2: Definition of HMAC
            // Step (5)
            PrepareWorkspace(opad);
            // Step (6)
            Buffer.BlockCopy(innerHashResult, 0, workspace, index, innerHashResult.Length);
            index += innerHashResult.Length;
            // Step (7)
            using (HashAlgorithm outerHash = hashProvider.GetHash())
            {
                outerHash.TransformFinalBlock(workspace, 0, index);
                hash = outerHash.Hash;
            }

            Dispose(); // reuse is forbidden

            return null;
        }

        public byte[] ComputeHash(byte[] input)
        {
            if (started)
            {
                throw new InvalidOperationException();
            }
            TransformFinalBlock(input, 0, input.Length);
            return hash;
        }

        public byte[] ComputeHash(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (started)
            {
                throw new InvalidOperationException();
            }
            TransformFinalBlock(inputBuffer, inputOffset, inputCount);
            return hash;
        }

        public void Dispose()
        {
            if (innerHash != null)
            {
                ((IDisposable)innerHash).Dispose();
                innerHash = null;
            }
            workspace = null;
        }

        private sealed class KeyedHashTestVector
        {
            internal byte[] key;
            internal byte[] data;
            internal byte[] digest;

            internal KeyedHashTestVector(string key, string data, string digest)
            {
                this.key = Core.HexDecode(key);
                this.data = Core.HexDecode(data);
                this.digest = Core.HexDecode(digest);
            }
        }

        // Private internal, for checking the test vectors provided in RFC 2104.
        // MD5 is weak, so we do not want to expose it beyond here.
        private sealed class MD5Provider : ICryptoPrimitiveIteratedHashProvider
        {
            public HashAlgorithm GetHash()
            {
                return MD5.Create();
            }

            public int BlockLengthBytes { get { return 64; } } // iterated hash algorithm internal block length
            public int OutputLengthBytes { get { return 16; } } // hash algorithm final result length
        }

        private readonly static KeyedHashTestVector[] TestVectorsMD5 = new KeyedHashTestVector[]
            {
                // RFC 2104 appendix "Test Vectors"
                new KeyedHashTestVector("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", Core.HexEncodeASCII("Hi There"), "9294727a3638bb1c13f48ef8158bfc9d"),
                new KeyedHashTestVector(Core.HexEncodeASCII("Jefe"), Core.HexEncodeASCII("what do ya want for nothing?"), "750c783e6ab0b503eaa86e310a5db738"),
                new KeyedHashTestVector("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", "56be34521d144c88dbb8c733f0e8b3f6"),
            };

        public static void Test()
        {
            foreach (KeyedHashTestVector testVector in TestVectorsMD5)
            {
                using (CryptoPrimitiveHMAC hmac = new CryptoPrimitiveHMAC(new MD5Provider(), testVector.key))
                {
                    hmac.TransformFinalBlock(testVector.data, 0, testVector.data.Length);
                    byte[] digest = hmac.Hash;
                    if (!Core.ArrayEqual(digest, testVector.digest))
                    {
                        throw new ApplicationException("HMAC implementation defect");
                    }
                }
            }
        }
    }


    // TODO: consider providing a more modern key derivation algorithm. RFC 2898 is susceptable
    // to hardware-accelerated attacks. One possible replacement is "scrypt", developed
    // by Colin Percival for Tarsnap (http://www.tarsnap.com/, http://www.tarsnap.com/scrypt.html).
    // However, "scrypt" has it's own concerns, in particular that it is new and has not
    // been standardized, therefore has undergone insufficient scrutiny by the security community.

    // Composable bey derivation module implementing RFC 2898 (to expand passphrase into
    // a master key) and RFC 5869 [HKDF] (to convert master key & salt into session keys).
    public class CryptoSystemKeyGenerationRfc2898Rfc5869 : ICryptoSystemKeyGeneration
    {
        // !These values cannot be changed without breaking compatibility!

        // Password salt of 512 bits should be more than enough uniqueness for the
        // foreseeable future.
        private const int DefaultPasswordSaltLengthBits = 512;

        // Master key of 1024 bits is enough to incorporate the entropy from the password salt
        // and any entropy for the password itself, which is likely to be lower. In addition,
        // it provides room for exapansion in case a keyfile feature is added.
        private const int DefaultMasterKeyLengthBits = 1024;

        // Per RFC 5869: salt is optimally at least "HashLen",
        // which is 256 bits (32 bytes) for HMAC-SHA-256.
        // We have chosen a larger number for posterity (to make all suites contain
        // the same number of random bytes), even though some systems aren't able to
        // take advantage of that much entropy. (This application isn't starved for
        // data space.)
        // File salt should be larger than password salt since a lot more unique
        // instances will be used.
        private const int DefaultFileSaltLengthBits = 1024;

        private const int DefaultDefaultRfc2898Rounds = 20000;

        private int passwordSaltLengthBits;
        private int masterKeyLengthBits;
        private int fileSaltLengthBits;
        private int defaultRfc2898Rounds;

        public CryptoSystemKeyGenerationRfc2898Rfc5869(int? passwordSaltLengthBits, int? masterKeyLengthBits, int? fileSaltLengthBits, int? defaultRfc2898Rounds)
        {
            this.passwordSaltLengthBits = passwordSaltLengthBits.HasValue ? passwordSaltLengthBits.Value : DefaultPasswordSaltLengthBits;
            this.masterKeyLengthBits = masterKeyLengthBits.HasValue ? masterKeyLengthBits.Value : DefaultMasterKeyLengthBits;
            this.fileSaltLengthBits = fileSaltLengthBits.HasValue ? fileSaltLengthBits.Value : DefaultFileSaltLengthBits;
            this.defaultRfc2898Rounds = defaultRfc2898Rounds.HasValue ? defaultRfc2898Rounds.Value : DefaultDefaultRfc2898Rounds;
        }

        public CryptoSystemKeyGenerationRfc2898Rfc5869(int defaultRfc2898Rounds)
            : this(DefaultPasswordSaltLengthBits, DefaultMasterKeyLengthBits, DefaultFileSaltLengthBits, defaultRfc2898Rounds)
        {
        }

        public CryptoSystemKeyGenerationRfc2898Rfc5869()
            : this(DefaultPasswordSaltLengthBits, DefaultMasterKeyLengthBits, DefaultFileSaltLengthBits, DefaultDefaultRfc2898Rounds)
        {
        }

        public int DefaultRfc2898Rounds { get { return defaultRfc2898Rounds; } }

        public int PasswordSaltLengthBytes { get { return passwordSaltLengthBits / 8; } }
        public int MasterKeyLengthBytes { get { return masterKeyLengthBits / 8; } }
        public int FileSaltLengthBytes { get { return fileSaltLengthBits / 8; } }

        // See this article for a survey of key derivation functions:
        // http://tools.ietf.org/html/draft-irtf-cfrg-kdf-uses-00
        // in this implementation two are used:
        // 1. RFC 2898 is used for [password --> master key]
        // see PKCS #5: Password-Based Cryptography Specification:
        // http://tools.ietf.org/html/rfc2898
        // 2. RFC 5869 HKDF method is used for [master key + salt --> session keys]
        // see HMAC-based Extract-and-Expand Key Derivation Function (HKDF):
        // http://tools.ietf.org/html/rfc5869

        public void DeriveMasterKey(ProtectedArray<byte> password, byte[] passwordSalt, int rounds, out ProtectedArray<byte> masterKey)
        {
            password.Reveal();
            try
            {
                // 2014-09-21: Review of Rfc2898DeriveBytes (http://referencesource.microsoft.com/#mscorlib/system/security/cryptography/rfc2898derivebytes.cs)
                // It is prefereable to use the constructor that takes byte[] as first argument (rather
                // than any string argument) because underlying implementation converts to bytes using
                // "new UTF8Encoding(false).GetBytes()" and discards the resulting byte array after use
                // without scrubbing, so it is left as cleartext in the heap for an undetermined length
                // of time.
                // Another problem is that underlying Rfc2898DeriveBytes, the HMACSHA1 that it uses (http://referencesource.microsoft.com/#mscorlib/system/security/cryptography/hmac.cs)
                // (based on KeyedHashAlgorithm) calls HMAC.InitializeKey() which clones the key and
                // makes no attempt to pin it in memory, so copies may be left lying around by the
                // garbage collector for an indefinite amount of time. The Dispose() method does try to
                // zero the copied key array, but that's not enough.
                // This is also true of the internal buffers used by Rfc2898DeriveBytes, but it would be
                // harder for an attacker to reconstruct the master key from those buffers.
                // TODO: consider writing our own Rfc2898DeriveBytes.
                Rfc2898DeriveBytes keyMaker = new Rfc2898DeriveBytes(password.ExposeArray(), passwordSalt, rounds);
                masterKey = new ProtectedArray<byte>(MasterKeyLengthBytes);
                byte[] masterKeyBytes = keyMaker.GetBytes(MasterKeyLengthBytes);
                masterKey.AbsorbProtectAndScrub(masterKeyBytes);
            }
            finally
            {
                password.Protect();
            }
        }

        public void DeriveSessionKeys(ProtectedArray<byte> masterKey, byte[] salt, CryptoKeygroupLengths sessionKeyLengths, out CryptoKeygroup sessionKeys)
        {
            byte[] cipherKey = new byte[sessionKeyLengths.CipherKeyLengthBytes];
            byte[] signingKey = new byte[sessionKeyLengths.SigningKeyLengthBytes];
            byte[] initialCounter = new byte[sessionKeyLengths.InitialCounterLengthBytes];
            DeriveKeys(masterKey, salt, new byte[][] { cipherKey, signingKey, initialCounter }, Rfc5869DeriveBytes);
            sessionKeys = new CryptoKeygroup(cipherKey, signingKey, initialCounter);
        }

        public void DeriveNewSessionKeys(ICryptoSystemRandomNumberGeneration rng, ProtectedArray<byte> masterKey, out byte[] salt, CryptoKeygroupLengths sessionKeyLengths, out CryptoKeygroup sessionKeys)
        {
            salt = rng.CreateRandomBytes(FileSaltLengthBytes);
            DeriveSessionKeys(masterKey, salt, sessionKeyLengths, out sessionKeys);
        }

        private delegate void DeriveBytesMethod(ProtectedArray<byte> masterKey, byte[] sessionSalt, int sessionKeyMaterialLength, out byte[] sessionKeyMaterial);
        private static void DeriveKeys(ProtectedArray<byte> masterKey, byte[] salt, byte[][] keys, DeriveBytesMethod deriveBytes)
        {
            int aggregateLength = 0;
            for (int i = 0; i < keys.Length; i++)
            {
                aggregateLength += keys[i].Length;
            }

            byte[] sessionKeyMaterial;
            deriveBytes(masterKey, salt, aggregateLength, out sessionKeyMaterial);

            int offset = 0;
            for (int i = 0; i < keys.Length; i++)
            {
                Buffer.BlockCopy(sessionKeyMaterial, offset, keys[i], 0, keys[i].Length);
                offset += keys[i].Length;
            }
            Debug.Assert(offset == sessionKeyMaterial.Length);
        }

        // use RFC 5869 HKDF method
        private static void Rfc5869DeriveBytes(ProtectedArray<byte> masterKey, byte[] sessionSalt, int sessionKeyMaterialLength, out byte[] sessionKeyMaterial)
        {
            CryptoPrimitiveHKDF hkdf = new CryptoPrimitiveHKDFSHA256();
            byte[] prk;
            hkdf.Extract(sessionSalt, masterKey, out prk);
            hkdf.Expand(prk, null/*info*/, sessionKeyMaterialLength, out sessionKeyMaterial);
        }

        public virtual void Test()
        {
            CryptoPrimitiveHKDFSHA256.Test();
        }
    }


    // Composable module providing access to .NET default random number generator
    public class CryptoSystemDefaultRNG : ICryptoSystemRandomNumberGeneration
    {
        private RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

        public byte[] CreateRandomBytes(int count)
        {
            byte[] data = new byte[count];
            rng.GetBytes(data);
            return data;
        }

        public void Test()
        {
        }
    }


    // Composable module implementing ThreeFish family of block ciphers
    public abstract class CryptoSystemBlockCipherThreefish : ICryptoSystemBlockCipher
    {
        protected abstract int BlockLengthBits { get; }

        public int CipherBlockLengthBytes { get { return BlockLengthBits / 8; } }
        public int CipherKeyLengthBytes { get { return CipherBlockLengthBytes; } }
        public int InitialVectorLengthBytes { get { return CipherBlockLengthBytes; } }

        private SymmetricAlgorithm GetAlgorithm()
        {
            Threefish fish = new Threefish();
            fish.KeySize = CipherKeyLengthBytes * 8;
            fish.BlockSize = CipherKeyLengthBytes * 8;
            fish.Mode = CipherMode.ECB;
            fish.Padding = PaddingMode.None;
            return fish;
        }

        public Stream CreateEncryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
        {
            return new CryptoPrimitiveCounterModeEncryptStream(stream, this, GetAlgorithm(), cipherKey, initialCounter);
        }

        public Stream CreateDecryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
        {
            return new CryptoPrimitiveCounterModeDecryptStream(stream, this, GetAlgorithm(), cipherKey, initialCounter);
        }

        public void Test()
        {
            if (!SkeinTesting.TestHash())
            {
                throw new ApplicationException("Implementation fault: internal Skein hash test failed");
            }
        }
    }

    // Specific composable ThreeFish-1024 block cipher
    public sealed class CryptoSystemBlockCipherThreefish1024 : CryptoSystemBlockCipherThreefish
    {
        protected override int BlockLengthBits { get { return 1024; } }
    }


    // Composable module implementing AES family of block ciphers
    public abstract class CryptoSystemBlockCipherAES : ICryptoSystemBlockCipher
    {
        protected const int BlockLengthBits = 128;
        protected abstract int KeyLengthBits { get; }

        public int CipherBlockLengthBytes { get { return BlockLengthBits / 8; } }
        public int CipherKeyLengthBytes { get { return KeyLengthBits / 8; } }
        public int InitialVectorLengthBytes { get { return CipherBlockLengthBytes; } }

        protected SymmetricAlgorithm GetAlgorithm()
        {
            // AES is Rijndael with fixed block size and key size (128, 192, or 256)
            Rijndael rijndael = Rijndael.Create();
            rijndael.KeySize = KeyLengthBits;
            rijndael.BlockSize = BlockLengthBits;
            rijndael.Mode = CipherMode.ECB;
            rijndael.Padding = PaddingMode.None;
            return rijndael;
        }

        public Stream CreateEncryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
        {
            using (SymmetricAlgorithm algorithm = GetAlgorithm())
            {
                return new CryptoPrimitiveCounterModeEncryptStream(stream, this, algorithm, cipherKey, initialCounter);
            }
        }

        public Stream CreateDecryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
        {
            using (SymmetricAlgorithm algorithm = GetAlgorithm())
            {
                return new CryptoPrimitiveCounterModeDecryptStream(stream, this, algorithm, cipherKey, initialCounter);
            }
        }

        public virtual void Test()
        {
        }
    }

    // Composable module implementing AES-128 block cipher
    public sealed class CryptoSystemBlockCipherAES128 : CryptoSystemBlockCipherAES
    {
        protected override int KeyLengthBits { get { return 128; } }

        private sealed class CipherTestVector
        {
            internal readonly byte[] key;
            internal readonly byte[] iv;
            internal readonly byte[] plainText;
            internal readonly byte[] cipherText;

            internal CipherTestVector(string key, string iv, string plainText, string cipherText)
            {
                this.key = Core.HexDecode(key);
                this.iv = Core.HexDecode(iv);
                this.plainText = Core.HexDecode(plainText);
                this.cipherText = Core.HexDecode(cipherText);
            }
        }

        // from http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
        // see also http://csrc.nist.gov/groups/STM/cavp/index.html
        private readonly static CipherTestVector[] TestVectorsAES128ECB = new CipherTestVector[]
            {
                // ECB-AES128.Encrypt (appendix A section F.1.1 of above, page 24)
                new CipherTestVector("2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"),
            };
        private readonly static CipherTestVector[] TestVectorsAES128CTR = new CipherTestVector[]
            {
                // CTR-AES128.Encrypt (appendix A section F.5.1 of above, page 55)
                new CipherTestVector("2b7e151628aed2a6abf7158809cf4f3c", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"),
            };

        public override void Test()
        {
            base.Test();

            foreach (CipherTestVector test in TestVectorsAES128ECB)
            {
                ICryptoTransform transform;
                byte[] result;

                using (transform = GetAlgorithm().CreateEncryptor(test.key, test.iv))
                {
                    result = transform.TransformFinalBlock(test.plainText, 0, test.plainText.Length);
                    if (!Core.ArrayEqual(test.cipherText, result))
                    {
                        throw new ApplicationException("AES128-ECB implementation defect");
                    }
                }

                using (transform = GetAlgorithm().CreateDecryptor(test.key, test.iv))
                {
                    result = transform.TransformFinalBlock(test.cipherText, 0, test.cipherText.Length);
                    if (!Core.ArrayEqual(test.plainText, result))
                    {
                        throw new ApplicationException("AES128-ECB implementation defect");
                    }
                }
            }

            foreach (CipherTestVector test in TestVectorsAES128CTR)
            {
                using (SymmetricAlgorithm algorithm = GetAlgorithm())
                {
                    ICryptoTransform transform;
                    byte[] result;

                    algorithm.IV = test.iv;
                    algorithm.Key = test.key;

                    using (transform = new CryptoPrimitiveCounterModeTransform(algorithm, test.iv.Length * 8))
                    {
                        result = transform.TransformFinalBlock(test.plainText, 0, test.plainText.Length);
                        if (!Core.ArrayEqual(test.cipherText, result))
                        {
                            throw new ApplicationException("AES128-CTR implementation defect");
                        }
                    }

                    using (transform = new CryptoPrimitiveCounterModeTransform(algorithm, test.iv.Length * 8))
                    {
                        result = transform.TransformFinalBlock(test.cipherText, 0, test.cipherText.Length);
                        if (!Core.ArrayEqual(test.plainText, result))
                        {
                            throw new ApplicationException("AES128-CTR implementation defect");
                        }
                    }
                }
            }
        }
    }


    // Composable module implementing Serpent family of block ciphers
    public abstract class CryptoSystemBlockCipherSerpent : ICryptoSystemBlockCipher
    {
        protected const int BlockLengthBits = 128;
        protected abstract int KeyLengthBits { get; }

        public int CipherBlockLengthBytes { get { return BlockLengthBits / 8; } }
        public int CipherKeyLengthBytes { get { return KeyLengthBits / 8; } }
        public int InitialVectorLengthBytes { get { return CipherBlockLengthBytes; } }

        protected SymmetricAlgorithm GetAlgorithm()
        {
            SymmetricAlgorithm serpent = new SerpentAlgorithm();
            serpent.KeySize = KeyLengthBits;
            serpent.BlockSize = BlockLengthBits;
            serpent.Mode = CipherMode.ECB;
            serpent.Padding = PaddingMode.None;
            return serpent;
        }

        public Stream CreateEncryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
        {
            return new CryptoPrimitiveCounterModeEncryptStream(stream, this, GetAlgorithm(), cipherKey, initialCounter);
        }

        public Stream CreateDecryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
        {
            return new CryptoPrimitiveCounterModeDecryptStream(stream, this, GetAlgorithm(), cipherKey, initialCounter);
        }

        public virtual void Test()
        {
        }
    }

    // Composable module implementing Serpent-256 block cipher
    public sealed class CryptoSystemBlockCipherSerpent256 : CryptoSystemBlockCipherSerpent
    {
        protected override int KeyLengthBits { get { return 256; } }

        private sealed class CipherTestVector
        {
            internal readonly byte[] key;
            internal readonly byte[] iv;
            internal readonly byte[] plainText;
            internal readonly byte[] cipherText;
            internal readonly byte[] cipherText100;
            internal readonly byte[] cipherText1000;

            internal CipherTestVector(string key, string iv, string plainText, string cipherText, string cipherText100, string cipherText1000)
            {
                this.key = Core.HexDecode(key);
                this.iv = iv != null ? Core.HexDecode(iv) : null;
                this.plainText = Core.HexDecode(plainText);
                this.cipherText = Core.HexDecode(cipherText);
                this.cipherText100 = cipherText100 != null ? Core.HexDecode(cipherText100) : null;
                this.cipherText1000 = cipherText1000 != null ? Core.HexDecode(cipherText1000) : null;
            }

            internal CipherTestVector(string key, string iv, string plainText, string cipherText)
                : this(key, iv, plainText, cipherText, null, null)
            {
            }
        }

        // test vectors from http://www.cs.technion.ac.il/~biham/Reports/Serpent/
        private readonly static CipherTestVector[] TestVectorsSerpentMultiKeylenECB = new CipherTestVector[]
            {
                // http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors
                // Set 4, vector#  0
                new CipherTestVector("000102030405060708090A0B0C0D0E0F", null, "00112233445566778899AABBCCDDEEFF", "563E2CF8740A27C164804560391E9B27", "70795D35DEC6561F8AD83B2F454F9CC5", "4EA3765A7C3A94786850DF4812249718"),
                // Set 4, vector#  1
                new CipherTestVector("2BD6459F82C5B300952C49104881FF48", null, "EA024714AD5C4D84EA024714AD5C4D84", "92D7F8EF2C36C53409F275902F06539F", "180B795EAD8C6CB128348093A7E8E442", "C5F9E521F5FC7D9BB0C4674C48525460"),

                // http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-192-128.verified.test-vectors
                // Set 4, vector#  0
                new CipherTestVector("000102030405060708090A0B0C0D0E0F1011121314151617", null, "00112233445566778899AABBCCDDEEFF", "6AB816C82DE53B93005008AFA2246A02", "D8789291A6307A1DFCFB310CB5CEE8E1", "D4D1005991ACF56FDD6C45ED867CD679"),
                // Set 4, vector#  1
                new CipherTestVector("2BD6459F82C5B300952C49104881FF482BD6459F82C5B300", null, "EA024714AD5C4D84EA024714AD5C4D84", "827B18C2678A239DFC5512842000E204", "696E45B38A8181D1B07F1D311A6F4CFE", "7ECD356D2BE7B1FB7971A1A94BC7BE49"),

                // http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors
                // Set 4, vector#  0
                new CipherTestVector("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", null, "00112233445566778899AABBCCDDEEFF", "2868B7A2D28ECD5E4FDEFAC3C4330074", "8BF56992354F3F1A0F4E49DCBA82CBC0", "9B1D8B34845DF9BFD36AAAD0CDA1C8FE"),
                // Set 4, vector#  1
                new CipherTestVector("2BD6459F82C5B300952C49104881FF482BD6459F82C5B300952C49104881FF48", null, "EA024714AD5C4D84EA024714AD5C4D84", "3E507730776B93FDEA661235E1DD99F0", "3B5462E5D87A40C4BE745E3994D5E373", "99D5D067EF7C787E6A764EB47DAC59AD"),
            };

        public override void Test()
        {
            {
                Type serpentTestClass = Type.GetType("Serpent.SerpentTest");
                if (serpentTestClass != null)
                {
                    MethodInfo serpentTestMethod = serpentTestClass.GetMethod("RunTests");
                    serpentTestMethod.Invoke(null, null);
                }
            }

            base.Test();

            foreach (CipherTestVector test in TestVectorsSerpentMultiKeylenECB)
            {
                ICryptoTransform transform;
                byte[] result;

                using (transform = GetAlgorithm().CreateEncryptor(test.key, test.iv))
                {
                    result = transform.TransformFinalBlock(test.plainText, 0, test.plainText.Length);
                    if (!Core.ArrayEqual(test.cipherText, result))
                    {
                        throw new ApplicationException("Serpent-ECB implementation defect");
                    }
                }

                using (transform = GetAlgorithm().CreateDecryptor(test.key, test.iv))
                {
                    result = transform.TransformFinalBlock(test.cipherText, 0, test.cipherText.Length);
                    if (!Core.ArrayEqual(test.plainText, result))
                    {
                        throw new ApplicationException("Serpent-ECB implementation defect");
                    }
                }

                using (transform = GetAlgorithm().CreateEncryptor(test.key, test.iv))
                {
                    if (test.cipherText100 != null)
                    {
                        result = test.plainText;
                        for (int i = 0; i < 100; i++)
                        {
                            result = transform.TransformFinalBlock(result, 0, result.Length);
                        }
                        if (!Core.ArrayEqual(test.cipherText100, result))
                        {
                            throw new ApplicationException("Serpent-ECB implementation defect");
                        }
                    }
                    if (test.cipherText1000 != null)
                    {
                        result = test.plainText;
                        for (int i = 0; i < 1000; i++)
                        {
                            result = transform.TransformFinalBlock(result, 0, result.Length);
                        }
                        if (!Core.ArrayEqual(test.cipherText1000, result))
                        {
                            throw new ApplicationException("Serpent-ECB implementation defect");
                        }
                    }
                }
            }
        }
    }


    // from NIST AES description - Counter (CTR) mode
    // http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    // Counter mode has the unique property that encrypting and decrypting are
    // identical. In addition, padding is trivial, which eliminates padding oracle
    // attacks and reduces stream-wrapper complexity.
    // The difficulty is in the use of a (nonce, counter) that is non-repeating
    // over all uses of a particular key, ever, which necessitates careful choice
    // of the nonce when to rekey.
    public class CryptoPrimitiveCounterModeTransform : ICryptoTransform, IDisposable
    {
        private ICryptoTransform encryptor;
        private byte[] counter;
        private byte[] counterSequence;
        private byte[] counterSequenceEncrypted;
        private ulong blockLimit;
        private ulong blockCount;
        private int blockLengthBytes;

        // Use care in selecting initialCounter. All counter values must be forever
        // unique with a given key. Internally counters are generated significantly
        // by incrementing, in little-endian order. Various amounts of the highest-order
        // bytes may be a nonce, depending on how many messages are to be encrypted
        // under a given key, and how long each message will be, which must not exceed
        // 2^(bits-reserved-for-counter) * bytes-per-block
        private CryptoPrimitiveCounterModeTransform(SymmetricAlgorithm algorithm, byte[] initialCounter, int counterBits)
        {
            encryptor = algorithm.CreateEncryptor();

            if ((algorithm.Mode != CipherMode.ECB)
                || (algorithm.Padding != PaddingMode.None)
                || (encryptor.OutputBlockSize != encryptor.InputBlockSize)
                || ((encryptor.OutputBlockSize & (encryptor.OutputBlockSize - 1)) != 0))
            {
                throw new ArgumentException();
            }

            blockLengthBytes = algorithm.BlockSize / 8;

            if (initialCounter.Length != blockLengthBytes)
            {
                throw new ArgumentException();
            }

            this.blockLimit = 1UL << Math.Min(63, counterBits);

            this.counter = (byte[])initialCounter.Clone();
            this.counterSequence = new byte[blockLengthBytes];
            this.counterSequenceEncrypted = new byte[blockLengthBytes];
        }

        public CryptoPrimitiveCounterModeTransform(SymmetricAlgorithm algorithm, int counterBits)
            : this(algorithm, algorithm.IV, counterBits)
        {
        }

        public CryptoPrimitiveCounterModeTransform(SymmetricAlgorithm algorithm)
            : this(algorithm, algorithm.IV, algorithm.BlockSize)
        {
        }

        //public static byte[] CreateInitialCounter(int blockLengthBytes)
        //{
        //    byte[] b = new byte[blockLengthBytes];
        //    b[blockLengthBytes - 1] = 1;
        //    return b;
        //}

        public bool CanReuseTransform { get { return false; } }
        public bool CanTransformMultipleBlocks { get { return true; } }
        public int InputBlockSize { get { return blockLengthBytes; } }
        public int OutputBlockSize { get { return blockLengthBytes; } }

        private void GenerateCounterBlock(byte[] buffer, int offset)
        {
            if (blockLimit != 0)
            {
                blockCount++;
                if (blockCount >= blockLimit)
                {
                    throw new ApplicationException("Stream to encrypt is too long - CounterModeCryptoTransform counter limit exceeded");
                }
            }

            Debug.Assert(blockLengthBytes == counter.Length);
            Buffer.BlockCopy(counter, 0, buffer, offset, blockLengthBytes);

            for (int i = counter.Length - 1; i >= 0; i--)
            {
                counter[i]++;
                if (counter[i] != 0)
                {
                    break;
                }
            }
        }

        // input and output ranges are permitted to be overlapping.
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if ((inputCount & (blockLengthBytes - 1)) != 0)
            {
                throw new ArgumentException();
            }

            // create counter vector
            if (counterSequence.Length < inputCount)
            {
                Array.Resize(ref counterSequence, inputCount);
                Array.Resize(ref counterSequenceEncrypted, inputCount);
            }
            for (int i = 0; i < inputCount; i += blockLengthBytes)
            {
                GenerateCounterBlock(counterSequence, i);
            }

            // use separate counter array and pad array, in case some pluggable
            // ICryptoTransform can't handle overlap - better safe than sorry.

            // encrypt counter sequence to create pad
            int transformed = encryptor.TransformBlock(counterSequence, 0, inputCount, counterSequenceEncrypted, 0);
            if (transformed != inputCount)
            {
                throw new InvalidOperationException();
            }

            // xor with plaintext
            for (int i = 0; i < inputCount; i++)
            {
                outputBuffer[i + outputOffset] = (byte)(inputBuffer[i + inputOffset] ^ counterSequenceEncrypted[i]);
            }

            return inputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            int internalLength = (inputCount | (blockLengthBytes - 1)) + 1;
            byte[] internalInput = new byte[internalLength];
            Buffer.BlockCopy(inputBuffer, inputOffset, internalInput, 0, inputCount);

            TransformBlock(internalInput, 0, internalLength, internalInput, 0);

            byte[] final = new byte[inputCount];
            Buffer.BlockCopy(internalInput, 0, final, 0, inputCount);
            return final;
        }

        public void Dispose()
        {
            if (encryptor != null)
            {
                encryptor.Dispose();
                encryptor = null;
            }
            counter = null;
            counterSequence = null;
            counterSequenceEncrypted = null;
        }
    }

    // Provide a secure mechanism for CTR mode encryption. The limitation of CTR is that
    // counter||nonce values must be unique for any given key, globally, forever.
    // For realistic file sizes, this leaves only around 96 to 64 bits (for a 128 bit
    // block cipher, depending on counter range). Randomly chosen nonces are warned against
    // because of the likelihood of collisions, which would be after 2^(48 or 32) bits, because of
    // the birthday bound problem. In addition, a file backup program doesn't have
    // the necessary state for providing an ongoing nonce (such as an incremented message
    // identifier in a network messaging system).
    //
    // As a replacement for CBC with a one block initial vector, randomly chosen,
    // (e.g. 128 bits for AES128), our solution is to use a different session cipher
    // key for each stream. The key is derived using random salt (stored clear in the
    // stream header) and the HKDF-Expand function.
    // 
    // The proper choice of initial counter value is uncertain. The initial design called
    // for using the canonical value 1 as the initial counter value. However, since
    // there is plenty of entropy available in the session salt, the current
    // implementation derives the initial counter value alongside the session key in
    // the key expansion process. It may not help, but it can't hurt.
    //
    // This method should be roughly equivalent to CBC with random IV and the same key
    // across all streams. In the case of CBC random IV, IV collisions are expected in
    // 2^(blocksize/2), i.e. the birthday bound, which is around 2^(64) for AES. For
    // CTR as configured here, random-derived keys are expected to collide in the same
    // time bound of 2^(blocksize/2). Thus this scheme is no worse than CBC + random IV.
    //
    // Alternative methods:
    // An alternative method is to generate a random session key and random start counter
    // value for each stream and encrypt the key using the master key before writing it
    // to the stream header. The ic would be written in the clear, as it would be needed to
    // decrypt the session key. Since the master key would be used for each file, and all
    // individual encryptions would be on a single block (the session key) there would be
    // the same expectation of a counter collision after around 2^(blocksize/2) individual
    // session key encryptions, making this scheme equivalent to the above but requiring
    // an additional block of random data (the ic) to be written to each stream.
    //
    // Other options involve using esoteric constructions, such as:
    // "Luby-Rackoff backwards: Increasing security by making block ciphers non-invertible", Mihir Bellare, Ted Krovetz and Phillip Rogaway, Advances in Cryptology - EUROCRYPT '98, Lecture Notes in Computer Science, Vol. 1403, K. Nyberg, ed., Springer-Verlag, 1998
    // http://www.cs.ucdavis.edu/~rogaway/papers/p2f-abstract.html (http://http://www.cs.ucdavis.edu/~rogaway/papers/p2f.ps)
    // (originally referenced from: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ctr/ctr-spec.pdf)
    // There are a host of schemes besides this one that have been suggested by the
    // theoretical community, most involving conversion of PRPs (pseudo-random
    // permutators, which block ciphers are) into PRFs (pseudo-random functions) by
    // various machinations. See, for example, referenced works from
    // http://www.nuee.nagoya-u.ac.jp/labs/tiwata/cenc/docs/cenc-fse2006full.pdf
    // in particular, citations  [2], [4], [10], and [16]. They look promising -
    // eventually. These constructions are not favored at this time because:
    // - It is not determined how they hold up if the underlying block cipher falls
    //   short of ideal in some way.
    // - They are not well vetted theoretically or practically; they have not gone
    //   through a standards scrutiny process and there are no known widely used
    //   implementations.
    public class CryptoPrimitiveCounterModeDecryptStream : Stream
    {
        private const int DefaultWorkspaceLength = Core.Constants.BufferSize;

        private Stream inner;
        private ICryptoTransform decryptor;
        private byte[] workspace;
        private int index;

        public CryptoPrimitiveCounterModeDecryptStream(Stream inner, ICryptoSystemBlockCipher system, SymmetricAlgorithm algorithm, byte[] cipherKey, byte[] initialCounter)
        {
            if ((algorithm.Mode != CipherMode.ECB)
                || (algorithm.Padding != PaddingMode.None)
                || (system.CipherKeyLengthBytes != cipherKey.Length)
                || (system.InitialVectorLengthBytes != initialCounter.Length)
                || (algorithm.KeySize / 8 != system.CipherKeyLengthBytes)
                || (algorithm.BlockSize / 8 != system.InitialVectorLengthBytes))
            {
                throw new ArgumentException();
            }

            algorithm.IV = initialCounter;
            algorithm.Key = cipherKey;
            this.decryptor = new CryptoPrimitiveCounterModeTransform(algorithm);
            if ((decryptor.OutputBlockSize != decryptor.InputBlockSize)
                || ((decryptor.OutputBlockSize & (decryptor.OutputBlockSize - 1)) != 0))
            {
                throw new ArgumentException();
            }

            this.inner = inner;
            this.workspace = new byte[DefaultWorkspaceLength > decryptor.OutputBlockSize ? DefaultWorkspaceLength : decryptor.OutputBlockSize];

            LoadAndDecrypt();
        }

        public override bool CanRead { get { return false; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return true; } }
        public override long Length { get { throw new NotImplementedException(); } }
        public override long Position { get { throw new NotImplementedException(); } set { throw new NotImplementedException(); } }

        public override void Flush()
        {
        }

        public override void Close()
        {
            if (inner != null)
            {
                inner = null;
                decryptor.Dispose();
                decryptor = null;
                workspace = null;
            }
        }

        private void LoadAndDecrypt()
        {
            int read = inner.Read(workspace, 0, workspace.Length);
            if (read < workspace.Length)
            {
                Array.Resize(ref workspace, read);
            }

            if (workspace.Length > 0)
            {
                if ((workspace.Length & (decryptor.OutputBlockSize - 1)) == 0)
                {
                    Debug.Assert(decryptor is CryptoPrimitiveCounterModeTransform); // ours guarrantees TransformBlock works on overlapped input/output arrays
                    int transformed = decryptor.TransformBlock(workspace, 0, workspace.Length, workspace, 0);
                    if (transformed != workspace.Length)
                    {
                        throw new InvalidOperationException();
                    }
                }
                else
                {
                    workspace = decryptor.TransformFinalBlock(workspace, 0, workspace.Length);
                }
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (inner == null)
            {
                throw new InvalidOperationException();
            }

            int i;
            for (i = 0; i < count; i++)
            {
                if (index == workspace.Length)
                {
                    index = 0;
                    LoadAndDecrypt();
                }

                if (index == workspace.Length)
                {
                    break;
                }

                buffer[i + offset] = workspace[index++];
            }
            return i;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }

    // See security note at header of CounterModeDecryptStream
    public class CryptoPrimitiveCounterModeEncryptStream : Stream
    {
        private const int DefaultWorkspaceLength = Core.Constants.BufferSize;

        private Stream inner;
        private ICryptoTransform encryptor;
        private byte[] workspace;
        private int index;

        public CryptoPrimitiveCounterModeEncryptStream(Stream inner, ICryptoSystemBlockCipher system, SymmetricAlgorithm algorithm, byte[] cipherKey, byte[] initialCounter)
        {
            if ((algorithm.Mode != CipherMode.ECB)
                || (algorithm.Padding != PaddingMode.None)
                || (system.CipherKeyLengthBytes != cipherKey.Length)
                || (system.InitialVectorLengthBytes != initialCounter.Length)
                || (algorithm.KeySize / 8 != system.CipherKeyLengthBytes)
                || (algorithm.BlockSize / 8 != system.InitialVectorLengthBytes))
            {
                throw new ArgumentException();
            }

            algorithm.IV = initialCounter;
            algorithm.Key = cipherKey;
            this.encryptor = new CryptoPrimitiveCounterModeTransform(algorithm);
            if ((encryptor.OutputBlockSize != encryptor.InputBlockSize)
                || ((encryptor.OutputBlockSize & (encryptor.OutputBlockSize - 1)) != 0))
            {
                throw new ArgumentException();
            }

            this.inner = inner;
            this.workspace = new byte[DefaultWorkspaceLength > encryptor.OutputBlockSize ? DefaultWorkspaceLength : encryptor.OutputBlockSize];
        }

        public override bool CanRead { get { return false; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return true; } }
        public override long Length { get { throw new NotImplementedException(); } }
        public override long Position { get { throw new NotImplementedException(); } set { throw new NotImplementedException(); } }

        public override void Flush()
        {
        }

        public override void Close()
        {
            if (inner != null)
            {
                byte[] final = encryptor.TransformFinalBlock(workspace, 0, index);
                inner.Write(final, 0, final.Length);

                inner = null;
                encryptor.Dispose();
                encryptor = null;
                workspace = null;
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (inner == null)
            {
                throw new InvalidOperationException();
            }

            for (int i = 0; i < count; i++)
            {
                workspace[index++] = buffer[i + offset];
                if (index == workspace.Length)
                {
                    Debug.Assert(encryptor is CryptoPrimitiveCounterModeTransform); // ours guarrantees TransformBlock works on overlapped input/output arrays
                    int transformed = encryptor.TransformBlock(workspace, 0, workspace.Length, workspace, 0);
                    if (transformed != workspace.Length)
                    {
                        throw new InvalidOperationException();
                    }
                    inner.Write(workspace, 0, workspace.Length);
                    index = 0;
                }
            }
        }
    }


    // Simple hash functions (ICheckValueGenerator)

    // Specific implementation of a check value generator via SHA-256 hash function,
    // as standardized by NIST:
    // http://en.wikipedia.org/wiki/SHA256
    // http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf
    // http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf [2012]
    // https://www.cosic.esat.kuleuven.be/nessie/testvectors/hash/sha/index.html [test vectors]
    // http://csrc.nist.gov/groups/STM/cavp/index.html#03 [test vectors]
    public class CryptoPrimitiveHashCheckValueGeneratorSHA256 : CryptoPrimitiveHashCheckValueGenerator
    {
        public CryptoPrimitiveHashCheckValueGeneratorSHA256()
            : base(new CryptoPrimitiveIteratedHashProviderSHA256())
        {
        }
    }

    // Specific implementation of a check value generator via Skein-1024 hash function,
    // see http://www.skein-hash.info/ or https://www.schneier.com/skein.html
    public class CryptoPrimitiveHashCheckValueGeneratorSkein1024 : CryptoPrimitiveHashCheckValueGenerator
    {
        public CryptoPrimitiveHashCheckValueGeneratorSkein1024()
            : base(new CryptoPrimitiveIteratedHashProviderSkein1024())
        {
        }
    }

    // Generic cryptographic hash check value generator.
    // Using a caller-provided implementation of HashAlgorithm, it will compute
    // the hash of the total stream seen through ProcessBlock.
    public class CryptoPrimitiveHashCheckValueGenerator : Core.ICheckValueGenerator, IDisposable
    {
        private HashAlgorithm hash;
        private int checkValueLength;

        public CryptoPrimitiveHashCheckValueGenerator(ICryptoPrimitiveIteratedHashProvider hashProvider)
        {
            this.hash = hashProvider.GetHash();
            this.checkValueLength = hash.HashSize / 8;
            Debug.Assert(hashProvider.OutputLengthBytes == checkValueLength);
        }

        public void ProcessBlock(byte[] buffer, int start, int count)
        {
            if (hash == null)
            {
                throw new InvalidOperationException();
            }

            hash.TransformBlock(buffer, start, count, buffer, start);
        }

        public byte[] GetCheckValueAndClose()
        {
            if (hash == null)
            {
                throw new InvalidOperationException();
            }

            hash.TransformFinalBlock(new byte[0], 0, 0);
            byte[] hashResult = hash.Hash;
            Debug.Assert(hashResult.Length == CheckValueLength);

            Dispose(); // reuse is forbidden

            return hashResult;
        }

        public int CheckValueLength
        {
            get
            {
                return checkValueLength;
            }
        }

        public void Dispose()
        {
            if (hash != null)
            {
                ((IDisposable)hash).Dispose();
                hash = null;
            }
        }
    }


    // MAC implementations (ICryptoSystemAuthentication), mostly keyed-hash

    // Composable authentication module implementing HMAC-SHA-256
    public class CryptoSystemAuthenticationHMACSHA256 : ICryptoSystemAuthentication
    {
        public int SigningKeyLengthBytes { get { return 256 / 8; /* HMAC-SHA-256 */ } }

        public CryptoSystemAuthenticationHMACSHA256()
        {
            Debug.Assert(SigningKeyLengthBytes == CreateMACGenerator(new byte[0]).CheckValueLength);
        }

        public int MACLengthBytes { get { return 256 / 8; /* HMAC-SHA-256 */ } }

        public Core.ICheckValueGenerator CreateMACGenerator(byte[] signingKey)
        {
            return new CryptoPrimitiveHMACSHA256CheckValueGenerator(signingKey);
        }

        public void Test()
        {
            CryptoPrimitiveHMACSHA256CheckValueGenerator.Test();
            CryptoPrimitiveHMAC.Test();
        }
    }

    // Specific implementation of HMAC check value generator, using SHA-256 hash.
    public class CryptoPrimitiveHMACSHA256CheckValueGenerator : CryptoPrimitiveHMACCheckValueGenerator
    {
        public const int CheckValueLengthBytes = 256 / 8;
        public const int KeyLengthBytes = 512 / 8; // recommended key length (== iterated hash internal block size)

        public CryptoPrimitiveHMACSHA256CheckValueGenerator(byte[] signingKey)
            : base(new CryptoPrimitiveIteratedHashProviderSHA256(), signingKey)
        {
            Debug.Assert(CheckValueLength == CheckValueLengthBytes);
            Debug.Assert(new CryptoPrimitiveIteratedHashProviderSHA256().BlockLengthBytes == KeyLengthBytes);
            Debug.Assert(new CryptoPrimitiveIteratedHashProviderSHA256().OutputLengthBytes == CheckValueLengthBytes);
        }

        private sealed class TestVector
        {
            internal readonly byte[] key;
            internal readonly byte[] message;
            internal readonly byte[] mac;

            internal TestVector(string key, string message, string mac)
            {
                this.key = Core.HexDecode(key);
                this.message = Core.HexDecode(message);
                this.mac = Core.HexDecode(mac);
            }
        }

        // HMAC-SHA-256 test vectors from http://www.rfc-archive.org/getrfc.php?rfc=4231
        private readonly static TestVector[] TestVectorsSHA256 = new TestVector[]
            {
                // Test Case 1 (section 4.2)
                new TestVector("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
                // Test Case 2 (section 4.3) - short key
                new TestVector("4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
                // Test Case 6 (section 4.7) - overlong key
                new TestVector("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
                // Test Case 7 (section 4.8) - overlong all
                new TestVector("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
            };

        public static void Test()
        {
            foreach (TestVector testVector in TestVectorsSHA256)
            {
                using (CryptoPrimitiveHMACSHA256CheckValueGenerator hmac = new CryptoPrimitiveHMACSHA256CheckValueGenerator(testVector.key))
                {
                    hmac.ProcessBlock(testVector.message, 0, testVector.message.Length);
                    byte[] mac = hmac.GetCheckValueAndClose();
                    if (!Core.ArrayEqual(mac, testVector.mac))
                    {
                        throw new ApplicationException("HMAC-SHA-256 implementation defect");
                    }
                }
            }
        }
    }

    // Composable authentication module implementing HMAC-Skein-1024
    //
    // Strictly speaking, Skein is designed to be uased as a MAC without the HMAC
    // construction (it solves weaknesses in SHA-2 and earlier primitives that the
    // HMAC construction is designed to get around). However, as "messages" are
    // mostly large with this system, overhead is not a problem, so a more conservative
    // approach of retaining HMAC was chosen.
    public class CryptoSystemAuthenticationHMACSkein1024 : ICryptoSystemAuthentication
    {
        public int SigningKeyLengthBytes { get { return 1024 / 8; /* HMAC-Skein-1024 */ } }

        public CryptoSystemAuthenticationHMACSkein1024()
        {
            Debug.Assert(SigningKeyLengthBytes == CreateMACGenerator(new byte[0]).CheckValueLength);
        }

        public int MACLengthBytes { get { return 1024 / 8; /* HMAC-Skein-1024 */ } }

        public Core.ICheckValueGenerator CreateMACGenerator(byte[] signingKey)
        {
            return new CryptoPrimitiveHMACSkein1024CheckValueGenerator(signingKey);
        }

        public void Test()
        {
            CryptoPrimitiveHMACSkein1024CheckValueGenerator.Test();
            CryptoPrimitiveHMAC.Test();
        }
    }

    // Specific implementation of HMAC check value generator, using Skein-1024 hash.
    public class CryptoPrimitiveHMACSkein1024CheckValueGenerator : CryptoPrimitiveHMACCheckValueGenerator
    {
        public const int CheckValueLengthBytes = 1024 / 8;
        public const int KeyLengthBytes = 1024 / 8; // recommended key length (== iterated hash internal block size)

        public CryptoPrimitiveHMACSkein1024CheckValueGenerator(byte[] signingKey)
            : base(new CryptoPrimitiveIteratedHashProviderSkein1024(), signingKey)
        {
            Debug.Assert(CheckValueLength == CheckValueLengthBytes);
            Debug.Assert(new CryptoPrimitiveIteratedHashProviderSkein1024().BlockLengthBytes == KeyLengthBytes);
            Debug.Assert(new CryptoPrimitiveIteratedHashProviderSkein1024().OutputLengthBytes == CheckValueLengthBytes);
        }

        public static void Test()
        {
            if (!SkeinTesting.TestHash())
            {
                throw new ApplicationException("Implementation fault: internal Skein hash test failed");
            }
        }
    }

    // Generic keyed hash message authentication code (HMAC) implementation
    // of ICheckValueGenerator. See:
    // http://en.wikipedia.org/wiki/HMAC
    // http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf
    // http://www.ietf.org/rfc/rfc2104.txt
    public class CryptoPrimitiveHMACCheckValueGenerator : Core.ICheckValueGenerator, IDisposable
    {
        private CryptoPrimitiveHMAC hmac;
        private int checkValueLength; // permit queries after hmac is disposed

        public CryptoPrimitiveHMACCheckValueGenerator(ICryptoPrimitiveIteratedHashProvider hashProvider, byte[] signingKey)
        {
            this.hmac = new CryptoPrimitiveHMAC(hashProvider, signingKey);
            this.checkValueLength = hmac.HashSize / 8;
        }

        public void ProcessBlock(byte[] buffer, int start, int count)
        {
            if (hmac == null)
            {
                throw new InvalidOperationException();
            }

            hmac.TransformBlock(buffer, start, count, buffer, start);
        }

        public byte[] GetCheckValueAndClose()
        {
            if (hmac == null)
            {
                throw new InvalidOperationException();
            }

            hmac.TransformFinalBlock(new byte[0], 0, 0);
            byte[] hash = hmac.Hash;
            Debug.Assert(hash.Length == CheckValueLength);

            Dispose(); // reuse is forbidden

            return hash;
        }

        public int CheckValueLength
        {
            get
            {
                return checkValueLength;
            }
        }

        public void Dispose()
        {
            if (hmac != null)
            {
                ((IDisposable)hmac).Dispose();
                hmac = null;
            }
        }
    }
}
