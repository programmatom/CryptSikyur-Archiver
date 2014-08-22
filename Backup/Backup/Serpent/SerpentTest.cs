/*
 *  Copyright 2014 Thomas R. Lawrence
 *    except: "SkeinFish 0.5.0" sources, which is Copyright 2010 Alberto Fajardo
 *    except: "SerpentEngine.cs", which is Copyright 1997, 1998 Systemics Ltd on behalf of the Cryptix Development Team
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
using System.Text;

namespace Serpent
{
#if false // enable when testing on new platform
    public static class SerpentTest
    {
        private struct Test
        {
            internal readonly string file;
            internal readonly int operationCount;

            internal Test(string file, int operationCount)
            {
                this.file = file;
                this.operationCount = operationCount;
            }
        }

        private static readonly Test[] TestFiles = new Test[]
        {
            new Test("Serpent-128-128.verified.test-vectors.txt", 3084),
            new Test("Serpent-192-128.verified.test-vectors.txt", 3468),
            new Test("Serpent-256-128.verified.test-vectors.txt", 3852),
        };

        private static void RunTest(Test test)
        {
            string testsPath = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
            testsPath = Path.Combine(testsPath, "Serpent");
            // When enabled, ensure build copies test vector files to <testsPath> directory.

            Console.WriteLine(test.file);
            string file = Path.Combine(testsPath, test.file);
            using (TextReader reader = new StreamReader(file))
            {
                int operationCount = 0;

                byte[] key = null;
                object engineKey = null;
                int lastKeyLineNumber = -1;
                byte[] last = null;
                byte[] lastPlain = null;

                string lastComment = null;
                string line;
                int lineNumber = 0;
                while ((line = reader.ReadLine()) != null)
                {
                    lineNumber++;

                    const int Offset = 31;
                    if (/***/line.StartsWith("                           key="))
                    {
                        key = HexDecode(line.Substring(Offset));
                        engineKey = Serpent_BitSlice.makeKey(key);
                        lastKeyLineNumber = lineNumber;
                    }
                    else if (line.StartsWith("                               "))
                    {
                        // continuation of previous line - assuming key is not strictly correct, but is in our case
                        if ((last != null) || (lineNumber != lastKeyLineNumber + 1))
                        {
                            throw new InvalidOperationException();
                        }
                        lastKeyLineNumber = lineNumber;
                        byte[] key2 = HexDecode(line.Substring(Offset));
                        List<byte> combined = new List<byte>(key);
                        combined.AddRange(key2);
                        key = combined.ToArray();
                        engineKey = Serpent_BitSlice.makeKey(key);
                    }
                    else if (line.StartsWith("                         plain="))
                    {
                        if (last == null)
                        {
                            last = HexDecode(line.Substring(Offset));
                        }
                        else
                        {
                            byte[] expected = HexDecode(line.Substring(Offset));
                            byte[] result = Serpent_BitSlice.blockDecrypt(last, 0, engineKey);
                            operationCount++;
                            if (!ArrayEqual(result, expected))
                            {
                                throw new ApplicationException(String.Format("Serpent test failure: {0}", lastComment));
                            }
                            last = result;
                        }
                        lastPlain = last;
                    }
                    else if (line.StartsWith("                        cipher="))
                    {
                        if (last == null)
                        {
                            last = HexDecode(line.Substring(Offset));
                        }
                        else
                        {
                            byte[] expected = HexDecode(line.Substring(Offset));
                            byte[] result = Serpent_BitSlice.blockEncrypt(last, 0, engineKey);
                            operationCount++;
                            if (!ArrayEqual(result, expected))
                            {
                                throw new ApplicationException(String.Format("Serpent test failure: {0}", lastComment));
                            }
                            last = result;
                        }
                    }
                    else if (line.StartsWith("                     decrypted="))
                    {
                        if (last == null)
                        {
                            last = HexDecode(line.Substring(Offset));
                        }
                        else
                        {
                            byte[] expected = HexDecode(line.Substring(Offset));
                            byte[] result = Serpent_BitSlice.blockDecrypt(last, 0, engineKey);
                            operationCount++;
                            if (!ArrayEqual(result, expected))
                            {
                                throw new ApplicationException(String.Format("Serpent test failure: {0}", lastComment));
                            }
                            last = result;
                        }
                    }
                    else if (line.StartsWith("                     encrypted="))
                    {
                        if (last == null)
                        {
                            last = HexDecode(line.Substring(Offset));
                        }
                        else
                        {
                            byte[] expected = HexDecode(line.Substring(Offset));
                            byte[] result = Serpent_BitSlice.blockEncrypt(last, 0, engineKey);
                            operationCount++;
                            if (!ArrayEqual(result, expected))
                            {
                                throw new ApplicationException(String.Format("Serpent test failure: {0}", lastComment));
                            }
                            last = result;
                        }
                    }
                    else if (line.StartsWith("            Iterated 100 times="))
                    {
                        byte[] expected = HexDecode(line.Substring(Offset));
                        byte[] result = last;
                        for (int i = 0; i < 100; i++)
                        {
                            result = Serpent_BitSlice.blockEncrypt(result, 0, engineKey);
                        }
                        operationCount++;
                        if (!ArrayEqual(result, expected))
                        {
                            throw new ApplicationException(String.Format("Serpent test failure: {0}", lastComment));
                        }
                    }
                    else if (line.StartsWith("           Iterated 1000 times="))
                    {
                        byte[] expected = HexDecode(line.Substring(Offset));
                        byte[] result = last;
                        for (int i = 0; i < 1000; i++)
                        {
                            result = Serpent_BitSlice.blockEncrypt(result, 0, engineKey);
                        }
                        operationCount++;
                        if (!ArrayEqual(result, expected))
                        {
                            throw new ApplicationException(String.Format("Serpent test failure: {0}", lastComment));
                        }
                    }
                    else
                    {
                        lastComment = line;
                        key = null;
                        engineKey = null;
                        last = null;
                        lastPlain = null;
                    }
                }

                if (operationCount != test.operationCount)
                {
                    throw new ApplicationException(String.Format("Serpent test harness failure: operation count = {0} (expected {1})", operationCount, test.operationCount));
                }
            }
        }

        private const string Hex = "0123456789abcdef";

        private static string HexEncode(byte[] data)
        {
            StringBuilder encoded = new StringBuilder(data.Length * 2);
            foreach (byte b in data)
            {
                encoded.Append(Hex[(b >> 4) & 0x0f]);
                encoded.Append(Hex[b & 0x0f]);
            }
            return encoded.ToString();
        }

        private static string HexEncodeASCII(string s)
        {
            byte[] b = Encoding.ASCII.GetBytes(s);
            return HexEncode(b);
        }

        private static byte[] HexDecode(string s)
        {
            List<byte> b = new List<byte>(s.Length / 2);
            byte? l = null;
            foreach (char c in s.ToLowerInvariant())
            {
                byte v;
                if ((c >= '0') && (c <= '9'))
                {
                    v = (byte)(c - '0');
                }
                else if ((c >= 'a') && (c <= 'f'))
                {
                    v = (byte)(c - 'a' + 10);
                }
                else
                {
                    throw new InvalidDataException();
                }
                if (l.HasValue)
                {
                    b.Add((byte)((l.Value << 4) | v));
                    l = null;
                }
                else
                {
                    l = v;
                }
            }
            if (l.HasValue)
            {
                throw new InvalidDataException();
            }
            return b.ToArray();
        }

        private static bool ArrayEqual<T>(T[] l, int lStart, T[] r, int rStart, int count) where T : IComparable
        {
            for (int i = 0; i < count; i++)
            {
                if (!l[i + lStart].Equals(r[i + rStart]))
                {
                    return false;
                }
            }
            return true;
        }

        private static bool ArrayEqual<T>(T[] l, T[] r) where T : IComparable
        {
            if (l.Length != r.Length)
            {
                return false;
            }
            return ArrayEqual(l, 0, r, 0, l.Length);
        }

        public static void RunTests()
        {
            Console.WriteLine("Serpent self-test begin.");
            foreach (Test test in TestFiles)
            {
                RunTest(test);
            }
            Console.WriteLine("Serpent self-test finished.");
        }
    }
#endif
}
