/*
 *  Copyright 2014 Thomas R. Lawrence
 *    except: "SkeinFish 0.5.0" sources, which is Copyright 2010 Alberto Fajardo
 *    except: "SerpentEngine.cs", which is Copyright © 1997, 1998 Systemics Ltd on behalf of the Cryptix Development Team
 *    except: "Keccak/*.cs", which are Copyright © 2000 - 2011 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 *  GNU General Public License
 * 
 *  This program is free software: you can redistribute it and/or modify
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
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

using Backup;
using Org.BouncyCastle.Crypto.Digests;

namespace Keccak
{
    // Basic Keccak (SHA-3) implementation for .NET: HashAlgorithm
    // http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf
    // http://en.wikipedia.org/wiki/SHA-3

    public class KeccakHashAlgorithm : HashAlgorithm
    {
        private const bool EnableComprehensiveTest = false; // set to 'true' to enable testing on new platforms

        private Sha3Digest inner;

        public enum BitLength
        {
            SHA3_224 = 224,
            SHA3_256 = 256,
            SHA3_288 = 288,
            SHA3_384 = 384,
            SHA3_512 = 512,
        }

        public static KeccakHashAlgorithm Create(BitLength bitLength)
        {
            return new KeccakHashAlgorithm((int)bitLength);
        }

        protected KeccakHashAlgorithm(int bitLength)
        {
            inner = new Sha3Digest(bitLength);
            HashSizeValue = bitLength;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            inner.BlockUpdate(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            // Per SHA3 definition, bits 0b01 are appended to the message stream
            // (see 6.1 SHA-3 Hash Functions of http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf)
            // Bits in a partially-filled message byte fill in starting from highest bit
            // (see A.2 Examples of http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf)
            byte[] FinalPadding = new byte[] { 0x80 };
            const int FinalPaddingBitLength = 2;
            inner.DoUpdate(FinalPadding, 0, FinalPaddingBitLength);

            byte[] hash = new byte[inner.GetDigestSize()];
            inner.DoFinal(hash, 0);
            return hash;
        }

        public override void Initialize()
        {
            inner.Reset();
        }

        private class TestVector
        {
            internal readonly BitLength bits;
            internal readonly byte[] data;
            internal readonly int dataBitLength;
            internal readonly byte[] digest;
            internal readonly string source;

            internal TestVector(BitLength bits, string data, int dataBitLength, string digest)
            {
                this.bits = bits;
                this.data = !String.IsNullOrEmpty(data) ? HexUtility.HexDecode(data) : new byte[0];
                this.dataBitLength = dataBitLength;
                this.digest = HexUtility.HexDecode(digest);
            }

            internal TestVector(BitLength bits, byte[] data, int dataBitLength, byte[] digest, string source)
            {
                this.bits = bits;
                this.data = data;
                this.dataBitLength = dataBitLength;
                this.digest = digest;
                this.source = source;
            }
        }

        private class TestFile
        {
            internal readonly BitLength bits;
            internal readonly string filename;

            internal TestFile(BitLength bits, string filename)
            {
                this.bits = bits;
                this.filename = filename;
            }
        }

        private static readonly TestFile[] TestFiles = new TestFile[]
        {
            new TestFile(BitLength.SHA3_224, "ShortMsgKAT_SHA3-224.txt"),
            new TestFile(BitLength.SHA3_256, "ShortMsgKAT_SHA3-256.txt"),
            new TestFile(BitLength.SHA3_384, "ShortMsgKAT_SHA3-384.txt"),
            new TestFile(BitLength.SHA3_512, "ShortMsgKAT_SHA3-512.txt"),
        };

        private static readonly TestVector[] TestVectors = new TestVector[]
        {
            // selected test vectors - always checked

            // ShortMsgKAT_SHA3-256.txt
            new TestVector(BitLength.SHA3_256, null, 0, "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A"),
            new TestVector(BitLength.SHA3_256, "CC", 8, "677035391CD3701293D385F037BA32796252BB7CE180B00B582DD9B20AAAD7F0"),
            new TestVector(BitLength.SHA3_256, "82E192E4043DDCD12ECF52969D0F807EED", 136, "C7B12EFF692D842110CC39AC60616707ACB3F9B0F1CB361B94577EFC529CA26C"),
            new TestVector(BitLength.SHA3_256, "3A3A819C48EFDE2AD914FBF00E18AB6BC4F14513AB27D0C178A188B61431E7F5623CB66B23346775D386B50E982C493ADBBFC54B9A3CD383382336A1A0B2150A15358F336D03AE18F666C7573D55C4FD181C29E6CCFDE63EA35F0ADF5885CFC0A3D84A2B2E4DD24496DB789E663170CEF74798AA1BBCD4574EA0BBA40489D764B2F83AADC66B148B4A0CD95246C127D5871C4F11418690A5DDF01246A0C80A43C70088B6183639DCFDA4125BD113A8F49EE23ED306FAAC576C3FB0C1E256671D817FC2534A52F5B439F72E424DE376F4C565CCA82307DD9EF76DA5B7C4EB7E085172E328807C02D011FFBF33785378D79DC266F6A5BE6BB0E4A92ECEEBAEB1", 2040, "C11F3522A8FB7B3532D80B6D40023A92B489ADDAD93BF5D64B23F35E9663521C"),
        };

        public static void Test()
        {
            List<TestVector> testVectors = new List<TestVector>(TestVectors);

            if (EnableComprehensiveTest)
            {
                string testsPath = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
                testsPath = Path.Combine(testsPath, "Keccak");
                // When enabled, ensure build copies test vector files to <testsPath> directory.

                foreach (TestFile testFile in TestFiles)
                {
                    using (TextReader reader = new StreamReader(Path.Combine(testsPath, testFile.filename)))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            if (line.StartsWith("#"))
                            {
                                continue;
                            }
                            if (String.IsNullOrEmpty(line))
                            {
                                continue;
                            }

                            int length;
                            byte[] data;
                            byte[] digest;

                            const string Len = "Len = ";
                            if (!line.StartsWith(Len))
                            {
                                throw new InvalidDataException(testFile.filename);
                            }
                            length = Int32.Parse(line.Substring(Len.Length));

                            line = reader.ReadLine();

                            const string Msg = "Msg = ";
                            if (!line.StartsWith(Msg))
                            {
                                throw new InvalidDataException(testFile.filename);
                            }
                            data = HexUtility.HexDecode(line.Substring(Msg.Length));

                            line = reader.ReadLine();

                            const string MD = "MD = ";
                            if (!line.StartsWith(MD))
                            {
                                throw new InvalidDataException(testFile.filename);
                            }
                            digest = HexUtility.HexDecode(line.Substring(MD.Length));

                            // Implementation only supports byte-length data
                            if (length % 8 == 0)
                            {
                                testVectors.Add(new TestVector(testFile.bits, data, length, digest, testFile.filename));
                            }
                        }
                    }
                }
            }

            Debug.Assert(testVectors.Count >= TestVectors.Length);
            foreach (TestVector testVector in testVectors)
            {
                KeccakHashAlgorithm algorithm = KeccakHashAlgorithm.Create(testVector.bits);
                Debug.Assert(testVector.dataBitLength % 8 == 0);
                byte[] digest = algorithm.ComputeHash(testVector.data, 0, testVector.dataBitLength / 8);
                if (!Core.ArrayEqual(digest, testVector.digest))
                {
                    throw new ApplicationException(String.Format("Keccak implementation defect ({0})", testVector.source));
                }
            }
        }
    }
}
