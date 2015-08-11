/*
 *  Copyright © 2014 Thomas R. Lawrence
 *    except: "SkeinFish 0.5.0/*.cs", which are Copyright © 2010 Alberto Fajardo
 *    except: "SerpentEngine.cs", which is Copyright © 1997, 1998 Systemics Ltd on behalf of the Cryptix Development Team (but see license discussion at top of that file)
 *    except: "Keccak/*.cs", which are Copyright © 2000 - 2011 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
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
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

using Concurrent;
using Diagnostics;
using HexUtil;
using Keccak;
using ProtectedData;

namespace Backup
{
    public static class Core
    {
        ////////////////////////////////////////////////////////////////////////////
        //
        // Constants & globals
        //
        ////////////////////////////////////////////////////////////////////////////

        public static class Constants
        {
            private const int MaxSmallObjectHeapObjectSize = 85000; // http://msdn.microsoft.com/en-us/magazine/cc534993.aspx, http://blogs.msdn.com/b/dotnet/archive/2011/10/04/large-object-heap-improvements-in-net-4-5.aspx
            private const int PageSize = 4096;
            private const int MaxSmallObjectPageDivisibleSize = MaxSmallObjectHeapObjectSize & ~(PageSize - 1);

            public const int BufferSize = MaxSmallObjectPageDivisibleSize;

            // concurrency tuning parameters for various scenarios
            internal static readonly int ConcurrencyForDiskBound = Math.Max(1, Int32.Parse(Environment.GetEnvironmentVariable("NUMBER_OF_PROCESSORS")));
            internal static readonly int ConcurrencyForComputeBound = Math.Max(2, Int32.Parse(Environment.GetEnvironmentVariable("NUMBER_OF_PROCESSORS")));
            internal const int ConcurrencyForNetworkBound = 3;
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Exit codes
        //
        ////////////////////////////////////////////////////////////////////////////

        public enum ExitCodes
        {
            Success = 0,
            ProgramFailure = 1,
            Usage = 2,
            ConditionNotSatisfied = 3, // e.g. CompareFile finds differences
        }

        public class ExitCodeException : ApplicationException
        {
            public readonly int ExitCode;
            private readonly string message;

            public ExitCodeException(int exitCode)
                : base()
            {
                this.ExitCode = exitCode;
            }

            public ExitCodeException(int exitCode, string message)
                : base(message)
            {
                this.ExitCode = exitCode;
                this.message = message;
            }

            public ExitCodeException(int exitCode, string message, Exception innerException)
                : base(message, innerException)
            {
                this.ExitCode = exitCode;
                this.message = message;
            }

            public override string Message
            {
                get
                {
                    return message;
                }
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Display/console functions
        //
        ////////////////////////////////////////////////////////////////////////////

        private static bool? interactive;
        public static bool Interactive()
        {
            if (interactive.HasValue)
            {
                return interactive.Value;
            }
            try
            {
                using (TextWriter writer = new StreamWriter(Stream.Null))
                {
                    writer.Write(Console.BufferWidth);
                    writer.Write(Console.CursorTop);
                    Console.CursorTop = Console.CursorTop;
                }
                interactive = true;
            }
            catch (Exception)
            {
                interactive = false;
            }
            return interactive.Value;
        }

        public static void ConsoleWriteLineColor(ConsoleColor color, string line)
        {
            ConsoleColor colorOld = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine(line);
            Console.ForegroundColor = colorOld;
        }

        public static void ConsoleWriteLineColor(ConsoleColor color, string format, params object[] arg)
        {
            ConsoleColor colorOld = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine(format, arg);
            Console.ForegroundColor = colorOld;
        }

        public static void WriteStatusLine(string line)
        {
            if (Interactive())
            {
                if (line.Length > Console.BufferWidth - 1)
                {
                    line = line.Substring(0, Console.BufferWidth / 2 - 2) + "..." + line.Substring(line.Length - (Console.BufferWidth / 2 - 2));
                }
                line = line + new String(' ', Math.Max(0, Console.BufferWidth - 1 - line.Length));

                Console.WriteLine(line);

                Console.CursorTop -= 1;
            }
            else
            {
                Console.WriteLine(line);
            }
        }

        internal static void EraseStatusLine()
        {
            if (Interactive())
            {
                string line = new String(' ', Console.BufferWidth - 1);
                Console.WriteLine(line);
                Console.CursorTop -= 1;
            }
        }

        internal static char WaitReadKey(bool intercept, int timeout)
        {
            DateTime started = DateTime.Now;
            if (Interactive())
            {
                while (!Console.KeyAvailable)
                {
                    Thread.Sleep(50);
                    if ((timeout >= 0) && ((DateTime.Now - started).TotalMilliseconds >= timeout))
                    {
                        return (char)0;
                    }
                }
                ConsoleKeyInfo info = Console.ReadKey(intercept);
                return info.KeyChar;
            }
            else
            {
                while (Console.In.Peek() < 0)
                {
                    Thread.Sleep(50);
                    if ((timeout >= 0) && ((DateTime.Now - started).TotalMilliseconds >= timeout))
                    {
                        return (char)0;
                    }
                }
                return (char)Console.In.Read();
            }
        }

        internal static char WaitReadKey(bool intercept)
        {
            return WaitReadKey(intercept, -1/*wait forever*/);
        }

        internal static void Windiff(string oldPath, string newPath, bool waitForExit)
        {
            try
            {
                using (Process scriptCmd = new Process())
                {
                    scriptCmd.StartInfo.Arguments = String.Format(" \"{0}\" \"{1}\" ", oldPath, newPath);
                    scriptCmd.StartInfo.CreateNoWindow = true;
                    scriptCmd.StartInfo.FileName = "windiff.exe";
                    scriptCmd.StartInfo.RedirectStandardOutput = true;
                    scriptCmd.StartInfo.UseShellExecute = false;
                    scriptCmd.StartInfo.WorkingDirectory = Path.GetTempPath();
                    scriptCmd.Start();
                    if (waitForExit)
                    {
                        scriptCmd.WaitForExit();
                    }
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine("Windiff failed: {0}", exception.Message);
            }
        }

        // a proof-of-concept, but not very usable in practice (mouse-based schemes are much better)
        internal static ProtectedArray<byte> PromptPasswordRandomized()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            char[] letters = new char[127 - 32 + 1];
            byte[] randoms = new byte[letters.Length];
            rng.GetBytes(randoms);
            for (int i = 32; i < 127; i++)
            {
                letters[i - 32] = (char)i;
            }
            Array.Sort(randoms, letters);

            const int Columns = 16;
            byte[] b = new byte[1];
            rng.GetBytes(b);
            for (int i = 0; i < (b[0] & 0x03); i++)
            {
                Console.WriteLine();
            }
            rng.GetBytes(b);
            string prefix = new String(' ', b[0] & 0x0f);
            Console.WriteLine();
            Console.Write(prefix + "    ");
            for (int j = 0; j < Columns; j++)
            {
                Console.Write("{0}  ", (char)(j + 'A'));
            }
            Console.WriteLine();
            Console.Write(prefix + "    ");
            for (int j = 0; j < Columns; j++)
            {
                Console.Write("-  ");
            }
            Console.WriteLine();
            int count = 0;
            for (int i = 0; (i < 9) && (count < letters.Length); i++)
            {
                Console.Write(prefix + "{0} : ", i + 1);
                for (int j = 0; (j < Columns) && (count < letters.Length); j++)
                {
                    Console.Write("{0}  ", letters[i * Columns + j]);
                    count++;
                }
                Console.WriteLine();
            }
            rng.GetBytes(b);
            for (int i = 0; i < (b[0] & 0x03); i++)
            {
                Console.WriteLine();
            }

            bool interactive = true;
            try
            {
                Console.CursorLeft++;
                Console.CursorLeft--;
            }
            catch (IOException)
            {
                interactive = false;
            }

            ProtectedArray<char> passwordUnicode = new ProtectedArray<char>(0);
            while (true)
            {
                char column = WaitReadKey(true/*intercept*/);
                if (column == (char)ConsoleKey.Enter)
                {
                    break;
                }
                else if (column == (char)ConsoleKey.Backspace)
                {
                    if (passwordUnicode.Length > 0)
                    {
                        ProtectedArray<char> passwordTemp = ProtectedArray<char>.RemoveRange(passwordUnicode, passwordUnicode.Length - 1, 1);
                        passwordUnicode.Dispose();
                        passwordUnicode = passwordTemp;
                        if (interactive)
                        {
                            Console.CursorLeft--;
                            Console.Write(" ");
                            Console.CursorLeft--;
                        }
                    }
                    continue;
                }
                else if (!((column >= '1') && (column <= '9')))
                {
                    continue;
                }

                char row = WaitReadKey(true/*intercept*/);
                row = Char.ToLower(row);
                if (row == (char)ConsoleKey.Enter)
                {
                    break;
                }
                else if ((row == (char)ConsoleKey.Backspace) || (row == (char)ConsoleKey.Escape))
                {
                    continue;
                }
                else if (!((row >= 'a') && (row <= 'z')))
                {
                    continue;
                }

                int index = (column - '1') * Columns + (row - 'a');
                if ((index >= 0) && (index < letters.Length))
                {
                    ProtectedArray<char> passwordTemp = ProtectedArray<char>.Insert(passwordUnicode, passwordUnicode.Length, letters[index]);
                    passwordUnicode.Dispose();
                    passwordUnicode = passwordTemp;
                    if (interactive)
                    {
                        //Console.Write(".");
                        Console.Write(letters[index]);
                    }
                }
            }
            Console.WriteLine();

            passwordUnicode.Reveal();
            ProtectedArray<byte> password = ProtectedArray<byte>.CreateUtf8FromUtf16(passwordUnicode.ExposeArray());
            passwordUnicode.Dispose();
            return password;
        }

        internal static ProtectedArray<byte> PromptPassword(string prompt)
        {
            Console.Write(prompt);

            ProtectedArray<char> passwordUnicode = new ProtectedArray<char>(0);
            while (true)
            {
                char key = WaitReadKey(true/*intercept*/);
                if (key == (char)ConsoleKey.Enter)
                {
                    break;
                }
                else if (key == (char)ConsoleKey.Backspace)
                {
                    if (passwordUnicode.Length > 0)
                    {
                        ProtectedArray<char> passwordTemp = ProtectedArray<char>.RemoveRange(passwordUnicode, passwordUnicode.Length - 1, 1);
                        passwordUnicode.Dispose();
                        passwordUnicode = passwordTemp;
                        if (Interactive())
                        {
                            Console.CursorLeft--;
                            Console.Write(" ");
                            Console.CursorLeft--;
                        }
                    }
                }
                else if (key == (char)ConsoleKey.Escape)
                {
                    return PromptPasswordRandomized();
                }
                else if (key >= 32)
                {
                    ProtectedArray<char> passwordTemp = ProtectedArray<char>.Insert(passwordUnicode, passwordUnicode.Length, key);
                    passwordUnicode.Dispose();
                    passwordUnicode = passwordTemp;
                    if (Interactive())
                    {
                        Console.Write(".");
                    }
                }
            }
            Console.WriteLine();

            passwordUnicode.Reveal();
            ProtectedArray<byte> password = ProtectedArray<byte>.CreateUtf8FromUtf16(passwordUnicode.ExposeArray());
            passwordUnicode.Dispose();
            return password;
        }

        private static readonly string[] FileSizeSuffixes = new string[] { "B", "KB", "MB", "GB", "TB" };
        internal static string FileSizeString(long length)
        {
            double scaled = length;
            foreach (string suffix in FileSizeSuffixes)
            {
                if (Math.Round(scaled) < 1000)
                {
                    return scaled.ToString(scaled >= 1 ? "G3" : "G2") + suffix;
                }
                scaled /= 1024;
            }
            return (scaled * 1024).ToString("N0") + FileSizeSuffixes[FileSizeSuffixes.Length - 1];
        }

        internal static string FileSizeString(string path)
        {
            return FileSizeString(GetFileLength(path));
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Shared utility functions
        //
        ////////////////////////////////////////////////////////////////////////////

        public class StringSet : ICollection<string>, IEnumerable<string>
        {
            private Dictionary<string, bool> dictionary = new Dictionary<string, bool>();
            private bool caseInsensitive;

            public StringSet()
            {
            }

            public StringSet(bool caseInsensitive)
            {
                this.caseInsensitive = caseInsensitive;
            }

            // specialized methods

            public bool CaseInsensitive { get { return caseInsensitive; } }

            public void Set(string key)
            {
                if (caseInsensitive)
                {
                    key = key.ToLowerInvariant();
                }
                dictionary[key] = false;
            }

            public bool StartsWithAny(string value, string suffix)
            {
                if (caseInsensitive)
                {
                    value = value.ToLowerInvariant();
                    if (suffix != null)
                    {
                        suffix = suffix.ToLowerInvariant();
                    }
                }
                foreach (KeyValuePair<string, bool> item in dictionary)
                {
                    if (value.StartsWith(item.Key + suffix))
                    {
                        return true;
                    }
                }
                return false;
            }

            public bool EndsWithAny(string value, string prefix)
            {
                if (caseInsensitive)
                {
                    value = value.ToLowerInvariant();
                    if (prefix != null)
                    {
                        prefix = prefix.ToLowerInvariant();
                    }
                }
                foreach (KeyValuePair<string, bool> item in dictionary)
                {
                    if (value.EndsWith(prefix + item.Key))
                    {
                        return true;
                    }
                }
                return false;
            }

            // ICollection

            public void Add(string key)
            {
                if (caseInsensitive)
                {
                    key = key.ToLowerInvariant();
                }
                dictionary.Add(key, false);
            }

            public void Clear()
            {
                dictionary.Clear();
            }

            public bool Contains(string key)
            {
                if (caseInsensitive)
                {
                    key = key.ToLowerInvariant();
                }
                return dictionary.ContainsKey(key);
            }

            public void CopyTo(string[] array, int arrayIndex)
            {
                throw new NotImplementedException();
            }

            public int Count
            {
                get { return dictionary.Count; }
            }

            public bool IsReadOnly
            {
                get { return false; }
            }

            public bool Remove(string key)
            {
                if (caseInsensitive)
                {
                    key = key.ToLowerInvariant();
                }
                return dictionary.Remove(key);
            }

            // IEnumerable

            public IEnumerator<string> GetEnumerator()
            {
                return dictionary.Keys.GetEnumerator();
            }

            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            {
                return dictionary.Keys.GetEnumerator();
            }
        }

        public class InvariantStringSet : StringSet
        {
            public InvariantStringSet()
                : base(true/*caseInsensitive*/)
            {
            }
        }

        internal static long GetFileLength(string path)
        {
            using (Stream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                return stream.Length;
            }
        }

        internal static long GetFileLengthRetryable(string path, Context context, TextWriter trace)
        {
            return DoRetryable<long>(
                delegate { return GetFileLength(path); },
                delegate { return -1; },
                null,
                context,
                trace);
        }

        internal static long GetFileLengthNoError(string path)
        {
            try
            {
                return GetFileLength(path);
            }
            catch
            {
                return -1;
            }
        }

        internal static void ReadAndDiscardEntireStream(Stream stream)
        {
            byte[] buffer = new byte[Constants.BufferSize];
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) != 0)
            {
            }
        }

        internal static bool ArrayEqual<T>(T[] l, int lStart, T[] r, int rStart, int count) where T : IComparable
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

        internal static bool ArrayEqual<T>(T[] l, T[] r) where T : IComparable
        {
            if (l.Length != r.Length)
            {
                return false;
            }
            return ArrayEqual(l, 0, r, 0, l.Length);
        }

        internal static void ArrayRemoveAt<T>(ref T[] a, int index, int count)
        {
            Array.Copy(a, index + count, a, index, a.Length - (index + count));
            Array.Resize(ref a, a.Length - count);
        }

        internal static bool IsDriveRoot(string path)
        {
            Debug.Assert(Path.IsPathRooted(path));
            bool driveRoot = Path.GetPathRoot(path) == path;
            return driveRoot;
        }

        // (fileName, isDirectory)
        internal static readonly KeyValuePair<string, bool>[] ExcludedDriveRootItems = new KeyValuePair<string, bool>[]
        {
            //                              fileName,                   isDirectory
            new KeyValuePair<string, bool>("$RECYCLE.BIN",              true),
            new KeyValuePair<string, bool>("hiberfil.sys",              false),
            new KeyValuePair<string, bool>("pagefile.sys",              false),
            new KeyValuePair<string, bool>("RECYCLER",                  true),
            new KeyValuePair<string, bool>("System Volume Information", true),
        };

        internal static bool IsExcludedDriveRootItem(string file)
        {
            string directory = Path.GetDirectoryName(file);
            if (IsDriveRoot(directory))
            {
                string itemName = Path.GetFileName(file);
                if (Array.FindIndex(ExcludedDriveRootItems, delegate(KeyValuePair<string, bool> candidate) { return candidate.Key.Equals(itemName, StringComparison.OrdinalIgnoreCase); }) >= 0)
                {
                    FileAttributes attributes = File.GetAttributes(file);
                    if (((attributes & FileAttributes.Hidden) != 0) &&
                        ((attributes & FileAttributes.System) != 0))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        private static bool IsUnableToAccessException(Exception exception)
        {
            // permission denied
            if (exception is UnauthorizedAccessException)
            {
                return true;
            }

            // file in use
            if ((exception is IOException) && (Marshal.GetHRForException(exception) == unchecked((int)0x80070020)))
            {
                return true;
            }

            return false;
        }

        private static bool IsMissing(Exception exception)
        {
            // file was deleted after detection but before archiving
            if (exception is FileNotFoundException)
            {
                return true;
            }

            return false;
        }

        internal delegate ResultType TryFunctionType<ResultType>();
        internal delegate void ResetFunctionType();
        internal static ResultType DoRetryable<ResultType>(TryFunctionType<ResultType> tryFunction, TryFunctionType<ResultType> continueFunction, ResetFunctionType resetFunction, bool enable, Context context, TextWriter trace)
        {
            bool tried = false;
            while (true)
            {
                if (tried && (resetFunction != null))
                {
                    resetFunction();
                }
                try
                {
                    return tryFunction();
                }
                catch (Exception exception)
                {
                    tried = true;
                    if (trace != null)
                    {
                        trace.WriteLine("DoRetryable received exception: {0}", exception);
                    }
                    Console.WriteLine("EXCEPTION: {0}", exception.Message);

                    if (!enable)
                    {
                        throw;
                    }

                    if (context.continueOnAccessDenied
                        && IsUnableToAccessException(exception)
                        && (continueFunction != null))
                    {
                        if (trace != null)
                        {
                            trace.WriteLine("DoRetryable: automatically continuing from exception (-ignoreaccessdenied specified): {0}", exception);
                        }
                        return continueFunction();
                    }

                    if (context.continueOnMissing
                        && IsMissing(exception)
                        && (continueFunction != null))
                    {
                        if (trace != null)
                        {
                            trace.WriteLine("DoRetryable: automatically continuing from exception (-ignoremissing specified): {0}", exception);
                        }
                        return continueFunction();
                    }

                    if (context.beepEnabled)
                    {
                        Console.Beep(440, 500);
                        Thread.Sleep(200);
                        Console.Beep(440, 500);
                        Thread.Sleep(200);
                        Console.Beep(440, 500);
                    }
                    if (continueFunction == null)
                    {
                        Console.Write("r)etry or q)uit: ");
                    }
                    else
                    {
                        Console.Write("r)etry, q)uit, or c)ontinue: ");
                    }
                    while (true)
                    {
                        char key = WaitReadKey(false/*intercept*/);
                        Console.WriteLine();
                        if (key == 'q')
                        {
                            throw;
                        }
                        else if (key == 'r')
                        {
                            break;
                        }
                        else if ((key == 'c') && (continueFunction != null))
                        {
                            return continueFunction();
                        }
                    }
                }
            }
        }

        internal static ResultType DoRetryable<ResultType>(TryFunctionType<ResultType> tryFunction, TryFunctionType<ResultType> continueFunction, ResetFunctionType resetFunction, Context context, TextWriter trace)
        {
            return DoRetryable(tryFunction, continueFunction, resetFunction, true/*enable*/, context, trace);
        }

        internal static void GetExclusionArguments(string[] args, out InvariantStringSet excludedExtensions, bool relative, out InvariantStringSet excludedItems)
        {
            excludedExtensions = new InvariantStringSet();
            excludedItems = new InvariantStringSet(); // directories and files
            try
            {
                for (int i = 0; i < args.Length; )
                {
                    switch (args[i])
                    {
                        default:
                            throw new ArgumentException();

                        case "-skip":
                            if (i + 1 >= args.Length)
                            {
                                throw new ArgumentException();
                            }
                            string excludedExtension = args[i + 1];
                            if (!excludedExtension.StartsWith("."))
                            {
                                throw new ArgumentException();
                            }
                            if (excludedExtensions.Contains(excludedExtension))
                            {
                                throw new ArgumentException();
                            }
                            excludedExtensions.Add(excludedExtension);

                            i += 2;
                            break;

                        case "-exclude":
                            if (i + 1 >= args.Length)
                            {
                                throw new ArgumentException();
                            }
                            string excludedPath = args[i + 1];
                            if (excludedPath.StartsWith("\"") && excludedPath.EndsWith("\""))
                            {
                                excludedPath = excludedPath.Substring(1, excludedPath.Length - 2);
                            }
                            if (!relative)
                            {
                                excludedPath = Path.GetFullPath(excludedPath);
                            }
                            else
                            {
                                if (Path.IsPathRooted(excludedPath))
                                {
                                    throw new ArgumentException("excluded path must be relative to root");
                                }
                            }
                            if (excludedItems.Contains(excludedPath))
                            {
                                throw new ArgumentException();
                            }
                            excludedItems.Add(excludedPath);

                            i += 2;
                            break;
                    }
                }
            }
            catch (ArgumentException)
            {
                throw new UsageException();
            }
        }

        internal static bool GetAdHocArgument<T>(ref string[] args, string literal, T defaultValue, T explicitValue, out T value)
        {
            value = defaultValue;
            if ((args.Length >= 1) && String.Equals(args[0], literal, StringComparison.Ordinal))
            {
                value = explicitValue;
                ArrayRemoveAt(ref args, 0, 1);
                return true;
            }
            return false;
        }

        internal delegate T ParseArgument<T>(string s);
        internal static bool GetAdHocArgument<T>(ref string[] args, string literal, T defaultValue, ParseArgument<T> parse, out T value)
        {
            value = defaultValue;
            if ((args.Length >= 2) && String.Equals(args[0], literal, StringComparison.Ordinal))
            {
                value = parse(args[1]);
                ArrayRemoveAt(ref args, 0, 2);
                return true;
            }
            return false;
        }

        internal static void GetPasswordArgument(string[] args, ref int i, string prompt, out ICryptoSystem algorithm, out ProtectedArray<byte> password)
        {
            if (i < args.Length)
            {
                string name = args[i];
                algorithm = Array.Find(CryptoSystems.List, delegate(ICryptoSystem candidate) { return candidate.Name.Equals(name, StringComparison.Ordinal); });
                if (algorithm == null)
                {
                    throw new UsageException();
                }
            }
            else
            {
                throw new UsageException();
            }
            i++;

            if (i < args.Length)
            {
                if (String.Equals(args[i], "-protected"))
                {
                    // most secure method (passed in as CryptProtectData blob)
                    i++;
                    if (i < args.Length)
                    {
                        password = ProtectedArray<byte>.DecryptEphemeral(HexUtility.HexDecode(args[i]), ProtectedDataStorage.EphemeralScope.SameLogon);
                    }
                    else
                    {
                        throw new UsageException();
                    }
                }
                else
                {
                    if (String.IsNullOrEmpty(args[i]) || String.Equals(args[i], "-prompt"))
                    {
                        // somewhat secure method (prompt for password in console)
                        password = PromptPassword(prompt);
                    }
                    else
                    {
                        // insecure method (password passed plaintext as program argument)
                        password = ProtectedArray<byte>.CreateUtf8FromUtf16(args[i]);
                        args[i] = null; // does not help much
                    }
                }
            }
            else
            {
                throw new UsageException();
            }
        }

        public class OneWaySwitch
        {
            private bool status = false;

            public OneWaySwitch()
            {
            }

            public void Set()
            {
                status = true;
            }

            public bool Value
            {
                get
                {
                    return status;
                }
            }
        }

        private class FileNamePatternMatch
        {
            private Regex regex;

            public FileNamePatternMatch(string pattern)
            {
                string regexPattern = pattern;

                regexPattern = regexPattern.Replace(".", @"\.");
                regexPattern = regexPattern.Replace("*", ".*");
                regexPattern = regexPattern.Replace("?", ".");
                regexPattern = "^" + regexPattern + "$";

                regex = new Regex(regexPattern);
            }

            public bool IsMatch(string candidate)
            {
                return regex.IsMatch(candidate);
            }

            public static bool ContainsWildcards(string path)
            {
                return path.IndexOfAny(new char[] { '*', '?' }) >= 0;
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Context
        //
        ////////////////////////////////////////////////////////////////////////////

        [FlagsAttribute]
        public enum CompressionOption
        {
            None = 0,
            Compress = 0x01,
            Decompress = 0x02,
            Recompress = Compress | Decompress,
        }

        [FlagsAttribute]
        public enum EncryptionOption
        {
            None = 0,
            Encrypt = 0x01,
            Decrypt = 0x02,
            Recrypt = Encrypt | Decrypt,
        }

        public class CryptoMasterKeyCacheEntry : IDisposable
        {
            private readonly byte[] passwordSalt;
            private readonly int rfc2898Rounds;
            private readonly ProtectedArray<byte> masterKey;

            private CryptoMasterKeyCacheEntry()
            {
                throw new NotSupportedException();
            }

            public CryptoMasterKeyCacheEntry(byte[] passwordSalt, int rfc2898Rounds, ProtectedArray<byte> masterKey)
            {
                this.passwordSalt = passwordSalt;
                this.rfc2898Rounds = rfc2898Rounds;
                this.masterKey = ProtectedArray<byte>.Clone(masterKey);
            }

            public byte[] PasswordSalt { get { return passwordSalt; } }
            public int Rfc2898Rounds { get { return rfc2898Rounds; } }
            public ProtectedArray<byte> MasterKey { get { return ProtectedArray<byte>.Clone(masterKey); } }

            public void Dispose()
            {
                masterKey.Dispose();
            }
        }

        // this object may be accessed from multiple threads
        public class CryptoMasterKeyCache
        {
            private const int MaxCacheEntries = 10;
            private List<CryptoMasterKeyCacheEntry> masterKeys = new List<CryptoMasterKeyCacheEntry>(MaxCacheEntries);

            public CryptoMasterKeyCacheEntry Find(byte[] passwordSalt, int rfc2898Rounds)
            {
                lock (this)
                {
                    return masterKeys.Find(delegate(CryptoMasterKeyCacheEntry candidate) { return (candidate.Rfc2898Rounds == rfc2898Rounds) && ArrayEqual(candidate.PasswordSalt, passwordSalt); });
                }
            }

            public void Add(CryptoMasterKeyCacheEntry entry)
            {
                lock (this)
                {
                    if (null != Find(entry.PasswordSalt, entry.Rfc2898Rounds))
                    {
                        throw new ArgumentException();
                    }

                    if (masterKeys.Count >= MaxCacheEntries)
                    {
                        // always keep the first one (the default key)
                        for (int i = 0; i < masterKeys.Count / 2; i++)
                        {
                            masterKeys[1 + i].Dispose();
                        }
                        masterKeys.RemoveRange(1, masterKeys.Count / 2);
                    }

                    masterKeys.Add(entry);
                }
            }

            public CryptoMasterKeyCacheEntry Get(ProtectedArray<byte> password, byte[] passwordSalt, int rfc2898Rounds, ICryptoSystem system)
            {
                lock (this)
                {
                    CryptoMasterKeyCacheEntry entry = Find(passwordSalt, rfc2898Rounds);
                    if (entry != null)
                    {
                        return entry;
                    }

                    ProtectedArray<byte> masterKey;
                    system.DeriveMasterKey(password, passwordSalt, rfc2898Rounds, out masterKey);
                    entry = new CryptoMasterKeyCacheEntry(passwordSalt, rfc2898Rounds, masterKey);
                    Add(entry);
                    return entry;
                }
            }

            public CryptoMasterKeyCacheEntry GetDefault(ProtectedArray<byte> password, ICryptoSystem system, bool forceNewKeys)
            {
                lock (this)
                {
                    if (!forceNewKeys && (masterKeys.Count > 0))
                    {
                        return masterKeys[0];
                    }

                    byte[] passwordSalt = system.CreateRandomBytes(system.PasswordSaltLengthBytes);
                    ProtectedArray<byte> masterKey;
                    system.DeriveMasterKey(password, passwordSalt, system.DefaultRfc2898Rounds, out masterKey);
                    CryptoMasterKeyCacheEntry entry = new CryptoMasterKeyCacheEntry(passwordSalt, system.DefaultRfc2898Rounds, masterKey);
                    Add(entry);
                    return entry;
                }
            }
        }

        public class CryptoContext
        {
            public ICryptoSystem algorithm;
            public ProtectedArray<byte> password;
            // forceNewKeys will make multi-file archives run slower because it forces a new
            // random salt in each file, causing (slow) master key derivation to have to be
            // done again for each file.
            public bool forceNewKeys;
            private CryptoMasterKeyCache masterKeys = new CryptoMasterKeyCache();

            public CryptoMasterKeyCacheEntry GetMasterKeyEntry(byte[] passwordSalt, int rfc2898Rounds)
            {
                return masterKeys.Get(password, passwordSalt, rfc2898Rounds, algorithm);
            }

            public CryptoMasterKeyCacheEntry GetDefaultMasterKeyEntry()
            {
                return masterKeys.GetDefault(password, algorithm, forceNewKeys);
            }
        }

        public class Context
        {
            public CompressionOption compressionOption;
            public bool doNotPreValidateMAC;
            public bool dirsOnly;
            public bool continueOnAccessDenied;
            public bool continueOnMissing;
            public bool zeroLengthSpecial;
            public bool beepEnabled;
            public bool traceEnabled;

            public EncryptionOption cryptoOption;
            public CryptoContext encrypt;
            public CryptoContext decrypt;

            public string logPath;

            public DateTime now;

            public string refreshTokenProtected; // always CryptProtectMemory and HexEncode
            public bool overrideRemoteSecurityBlock;

            public int? explicitConcurrency;

            public FaultTemplateNode faultInjectionTemplateRoot;
            public IFaultInstance faultInjectionRoot;

            public System.Net.IPAddress socks5Address;
            public int socks5Port;

            public Context()
            {
            }

            public Context(Context original)
            {
                this.compressionOption = original.compressionOption;
                this.doNotPreValidateMAC = original.doNotPreValidateMAC;
                this.dirsOnly = original.dirsOnly;
                this.continueOnAccessDenied = original.continueOnAccessDenied;
                this.continueOnMissing = original.continueOnMissing;
                this.zeroLengthSpecial = original.zeroLengthSpecial;
                this.beepEnabled = original.beepEnabled;
                this.traceEnabled = original.traceEnabled;

                this.cryptoOption = original.cryptoOption;
                this.encrypt = original.encrypt;
                this.decrypt = original.decrypt;

                this.logPath = original.logPath;

                this.now = original.now;

                this.refreshTokenProtected = original.refreshTokenProtected;
                this.overrideRemoteSecurityBlock = original.overrideRemoteSecurityBlock;

                this.explicitConcurrency = original.explicitConcurrency;

                this.faultInjectionTemplateRoot = original.faultInjectionTemplateRoot;
                this.faultInjectionRoot = original.faultInjectionRoot;
            }
        }

        internal class EncryptedFileContainerHeader
        {
            public const byte EncryptedFileContainerHeaderNumber = 0x81;

            public byte headerNumber;
            public string uniquePersistentCiphersuiteIdentifier;
            public byte[] passwordSalt;
            public byte[] fileSalt;
            public int rfc2898Rounds;
            public byte[] extra;

            public EncryptedFileContainerHeader(CryptoContext crypto)
            {
                headerNumber = EncryptedFileContainerHeaderNumber;

                uniquePersistentCiphersuiteIdentifier = crypto.algorithm.UniquePersistentCiphersuiteIdentifier;
                rfc2898Rounds = crypto.algorithm.DefaultRfc2898Rounds;
            }

            public EncryptedFileContainerHeader(Stream stream2, bool peek, CryptoContext crypto)
            {
                BinaryReadUtils.Read(
                    stream2,
                    peek,
                    new BinaryReadUtils.Reader[]
                    {
                        delegate(Stream stream) { headerNumber = BinaryReadUtils.ReadBytes(stream, 1)[0]; },
                        delegate(Stream stream) { uniquePersistentCiphersuiteIdentifier = BinaryReadUtils.ReadStringUtf8(stream); },
                        delegate(Stream stream) { passwordSalt = BinaryReadUtils.ReadVariableLengthByteArray(stream); },
                        delegate(Stream stream) { fileSalt = BinaryReadUtils.ReadVariableLengthByteArray(stream); },
                        delegate(Stream stream) { rfc2898Rounds = BinaryReadUtils.ReadVariableLengthQuantityAsInt32(stream); },
                        delegate(Stream stream)
                        {
                            extra = BinaryReadUtils.ReadVariableLengthByteArray(stream);
                            if (extra.Length == 0)
                            {
                                extra = null;
                            }
                        },
                    });

                if (!Valid(crypto.algorithm))
                {
                    throw new InvalidDataException("Unrecognized encrypted file header - wrong ciphersuite specified?");
                }
            }

            public void Write(Stream stream, ICryptoSystem algorithm)
            {
                if (!Valid(algorithm))
                {
                    throw new ArgumentException();
                }

                BinaryWriteUtils.WriteBytes(stream, new byte[1] { EncryptedFileContainerHeaderNumber });
                BinaryWriteUtils.WriteStringUtf8(stream, uniquePersistentCiphersuiteIdentifier);
                BinaryWriteUtils.WriteVariableLengthByteArray(stream, passwordSalt);
                BinaryWriteUtils.WriteVariableLengthByteArray(stream, fileSalt);
                BinaryWriteUtils.WriteVariableLengthQuantity(stream, rfc2898Rounds);

                BinaryWriteUtils.WriteVariableLengthByteArray(stream, extra != null ? extra : new byte[0]);
            }

            public bool Valid(ICryptoSystem algorithm)
            {
                const int LegacyMinimumRfc2898Rounds = 20000;

                return (headerNumber == EncryptedFileContainerHeaderNumber)
                    && String.Equals(uniquePersistentCiphersuiteIdentifier, algorithm.UniquePersistentCiphersuiteIdentifier)
                    && (passwordSalt.Length == algorithm.PasswordSaltLengthBytes)
                    && (fileSalt.Length == algorithm.FileSaltLengthBytes)
                    && (rfc2898Rounds >= LegacyMinimumRfc2898Rounds) // allowed to vary, but must be a certain minimum
                    && (extra == null);
            }

            public override bool Equals(object obj)
            {
                EncryptedFileContainerHeader other = (EncryptedFileContainerHeader)obj;
                return (this.headerNumber == other.headerNumber)
                    && ArrayEqual(this.passwordSalt, other.passwordSalt)
                    && ArrayEqual(this.fileSalt, other.fileSalt)
                    && (this.rfc2898Rounds == other.rfc2898Rounds)
                    && ((this.extra == null) == (other.extra == null))
                    && ((this.extra == null) || ArrayEqual(this.extra, other.extra));
            }

            public override int GetHashCode()
            {
                throw new NotSupportedException();
            }

            public static int GetHeaderLength(CryptoContext crypto)
            {
                if (crypto == null)
                {
                    return 0;
                }

                // used only for measuring stream length

                EncryptedFileContainerHeader temp = new EncryptedFileContainerHeader(crypto);
                temp.passwordSalt = new byte[crypto.algorithm.PasswordSaltLengthBytes];
                temp.fileSalt = new byte[crypto.algorithm.FileSaltLengthBytes];
                temp.extra = null;

                using (MemoryStream stream = new MemoryStream())
                {
                    temp.Write(stream, crypto.algorithm);
                    return (int)stream.Length;
                }
            }
        }

        internal static void CopyStream(Stream inputStream, Stream outputStream, bool macValidated, EncryptedFileContainerHeader fchInput, CryptoKeygroup inputKeys, Context context)
        {
            StreamStack.DoWithStreamStack(
                inputStream,
                new StreamStack.StreamWrapMethod[]
                {
                    delegate(Stream stream)
                    {
                        // see note and references about
                        // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                        if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                            (context.cryptoOption == EncryptionOption.Recrypt))
                        {
                            if (!macValidated)
                            {
                                return new TaggedReadStream(stream, context.decrypt.algorithm.CreateMACGenerator(inputKeys.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                            }
                            else
                            {
                                return new ReadStreamHoldShort(stream, context.decrypt.algorithm.MACLengthBytes);
                            }
                        }
                        return null;
                    },
                    delegate(Stream stream)
                    {
                        if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                            (context.cryptoOption == EncryptionOption.Recrypt))
                        {
                            // why re-read here? need to read salt within HMAC container
                            EncryptedFileContainerHeader fch2 = new EncryptedFileContainerHeader(stream, false/*peek*/, context.decrypt);
                            if (!fch2.Equals(fchInput))
                            {
                                throw new InvalidOperationException();
                            }
                        }
                        return null;
                    },
                    delegate(Stream stream)
                    {
                        if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                            (context.cryptoOption == EncryptionOption.Recrypt))
                        {
                            return context.decrypt.algorithm.CreateDecryptStream(stream, inputKeys.CipherKey, inputKeys.InitialCounter);
                        }
                        return null;
                    },
                    delegate(Stream stream)
                    {
                        if (context.compressionOption == CompressionOption.Decompress)
                        {
                            return new BlockedDecompressStream(stream);
                        }
                        return null;
                    }
                },
                delegate(Stream finalInputStream)
                {
                    CryptoKeygroup outputKeys = null;
                    EncryptedFileContainerHeader fchOutput = null;
                    if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                        (context.cryptoOption == EncryptionOption.Recrypt))
                    {
                        CryptoMasterKeyCacheEntry entry = context.encrypt.GetDefaultMasterKeyEntry();
                        fchOutput = new EncryptedFileContainerHeader(context.encrypt);
                        fchOutput.passwordSalt = entry.PasswordSalt;
                        context.encrypt.algorithm.DeriveNewSessionKeys(entry.MasterKey, out fchOutput.fileSalt, out outputKeys);
                    }

                    StreamStack.DoWithStreamStack(
                        outputStream,
                        new StreamStack.StreamWrapMethod[]
                        {
                            delegate(Stream stream)
                            {
                                // see note and references about
                                // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                                    (context.cryptoOption == EncryptionOption.Recrypt))
                                {
                                    return new TaggedWriteStream(stream, context.encrypt.algorithm.CreateMACGenerator(outputKeys.SigningKey));
                                }
                                return null;
                            },
                            delegate(Stream stream)
                            {
                                if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                                    (context.cryptoOption == EncryptionOption.Recrypt))
                                {
                                    // why write here? need to write salt within HMAC container
                                    fchOutput.Write(stream, context.encrypt.algorithm);
                                }
                                return null;
                            },
                            delegate(Stream stream)
                            {
                                if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                                    (context.cryptoOption == EncryptionOption.Recrypt))
                                {
                                    return context.encrypt.algorithm.CreateEncryptStream(stream, outputKeys.CipherKey, outputKeys.InitialCounter);
                                }
                                return null;
                            },
                            delegate(Stream stream)
                            {
                                if (context.compressionOption == CompressionOption.Compress)
                                {
                                    return new BlockedCompressStream(stream);
                                }
                                return null;
                            }
                        },
                        delegate(Stream finalOutputStream)
                        {
                            byte[] buffer = new byte[Constants.BufferSize];
                            while (true)
                            {
                                int bytesRead = finalInputStream.Read(buffer, 0, buffer.Length);
                                if (bytesRead == 0)
                                {
                                    break;
                                }
                                finalOutputStream.Write(buffer, 0, bytesRead);
                            }
                        });
                });
        }

        internal static void CopyFile(string source, string target, Context context)
        {
            DoRetryable<int>(
                delegate
                {
                    try
                    {
                        if ((context.cryptoOption == EncryptionOption.None) && (context.compressionOption == CompressionOption.None))
                        {
                            File.Copy(source, target);
                            File.SetAttributes(target, File.GetAttributes(target) & ~(FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System));
                        }
                        else
                        {
                            using (Stream sourceStream = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                            {
                                CryptoKeygroup sourceKeys = null;
                                EncryptedFileContainerHeader fchSource = null;
                                if (sourceStream.Length != 0)
                                {
                                    if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                                        (context.cryptoOption == EncryptionOption.Recrypt))
                                    {
                                        fchSource = new EncryptedFileContainerHeader(sourceStream, true/*peek*/, context.decrypt);
                                        context.decrypt.algorithm.DeriveSessionKeys(context.decrypt.GetMasterKeyEntry(fchSource.passwordSalt, fchSource.rfc2898Rounds).MasterKey, fchSource.fileSalt, out sourceKeys);
                                    }
                                }

                                // Using Moxie Marlinspike's "doom principle": validate the MAC before ANY other
                                // action is taken. (http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/)
                                bool macValidated = false;
                                if (!context.doNotPreValidateMAC
                                    && ((context.cryptoOption == EncryptionOption.Decrypt)
                                    || (context.cryptoOption == EncryptionOption.Recrypt)))
                                {
                                    // zero-length "encrypted" files are considered valid (because backup creates them in checkpoints)
                                    if (sourceStream.Length != 0)
                                    {
                                        StreamStack.DoWithStreamStack(
                                            sourceStream,
                                            new StreamStack.StreamWrapMethod[]
                                            {
                                                delegate(Stream stream)
                                                {
                                                    // see note and references about
                                                    // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                                    return new TaggedReadStream(stream, context.decrypt.algorithm.CreateMACGenerator(sourceKeys.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                                },
                                            },
                                            delegate(Stream stream)
                                            {
                                                ReadAndDiscardEntireStream(stream);
                                            });
                                    }

                                    macValidated = true;
                                }

                                sourceStream.Position = 0;

                                using (Stream targetStream = new FileStream(target, FileMode.CreateNew))
                                {
                                    if (!context.zeroLengthSpecial || (sourceStream.Length != 0))
                                    {
                                        CopyStream(sourceStream, targetStream, macValidated, fchSource, sourceKeys, context);
                                    }
                                    else
                                    {
                                        // leave created target stream empty
                                        // provides work around for decrypting older archive points being unable to copy the zero length placeholders
                                    }
                                }
                            }
                        }
                    }
                    catch (PathTooLongException exception)
                    {
                        throw new PathTooLongException(String.Format("{0} (length={2}, path=\'{1}\')", exception.Message, target, target.Length));
                    }
                    catch (Exception exception)
                    {
                        throw new Exception(String.Format("{0} ({1})", exception.Message, source), exception);
                    }
                    return 0;
                },
                delegate { return 0; },
                delegate
                {
                    try
                    {
                        File.Delete(target);
                    }
                    catch (Exception)
                    {
                    }
                },
                context,
                null/*trace*/);

            try
            {
                File.SetCreationTime(target, File.GetCreationTime(source));
                File.SetLastWriteTime(target, File.GetLastWriteTime(source));
            }
            catch (Exception)
            {
            }
        }

        internal static bool CompareStreams(Stream firstStream, Stream secondStream, Context context)
        {
            bool result = false;

            CryptoKeygroup keysFirst = null;
            EncryptedFileContainerHeader fchFirst = null;
            if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                (context.cryptoOption == EncryptionOption.Recrypt))
            {
                fchFirst = new EncryptedFileContainerHeader(firstStream, true/*peek*/, context.decrypt);
                context.decrypt.algorithm.DeriveSessionKeys(context.decrypt.GetMasterKeyEntry(fchFirst.passwordSalt, fchFirst.rfc2898Rounds).MasterKey, fchFirst.fileSalt, out keysFirst);
            }

            CryptoKeygroup keysSecond = null;
            EncryptedFileContainerHeader fchSecond = null;
            if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                (context.cryptoOption == EncryptionOption.Recrypt))
            {
                fchSecond = new EncryptedFileContainerHeader(secondStream, true/*peek*/, context.encrypt);
                context.encrypt.algorithm.DeriveSessionKeys(context.encrypt.GetMasterKeyEntry(fchSecond.passwordSalt, fchSecond.rfc2898Rounds).MasterKey, fchSecond.fileSalt, out keysSecond);
            }

            try
            {
                StreamStack.DoWithStreamStack(
                    firstStream,
                    new StreamStack.StreamWrapMethod[]
                    {
                        delegate(Stream stream)
                        {
                            // see note and references about
                            // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                            if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                                (context.cryptoOption == EncryptionOption.Recrypt))
                            {
                                return new TaggedReadStream(stream, context.decrypt.algorithm.CreateMACGenerator(keysFirst.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                                (context.cryptoOption == EncryptionOption.Recrypt))
                            {
                                // why re-read here? need to read salt within HMAC container
                                EncryptedFileContainerHeader fch2 = new EncryptedFileContainerHeader(stream, false/*peek*/, context.decrypt);
                                if (!fch2.Equals(fchFirst))
                                {
                                    throw new InvalidOperationException();
                                }
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                                (context.cryptoOption == EncryptionOption.Recrypt))
                            {
                                return context.decrypt.algorithm.CreateDecryptStream(stream, keysFirst.CipherKey, keysFirst.InitialCounter);
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if ((context.compressionOption == CompressionOption.Decompress)
                                || (context.compressionOption == CompressionOption.Recompress))
                            {
                                return new BlockedDecompressStream(stream);
                            }
                            return null;
                        }
                    },
                    delegate(Stream finalFirstStream)
                    {
                        StreamStack.DoWithStreamStack(
                            secondStream,
                            new StreamStack.StreamWrapMethod[]
                            {
                                delegate(Stream stream)
                                {
                                    // see note and references about
                                    // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                    if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                                        (context.cryptoOption == EncryptionOption.Recrypt))
                                    {
                                        return new TaggedReadStream(stream, context.encrypt.algorithm.CreateMACGenerator(keysSecond.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                    }
                                    return null;
                                },
                                delegate(Stream stream)
                                {
                                    if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                                        (context.cryptoOption == EncryptionOption.Recrypt))
                                    {
                                        // why re-read here? need to read salt within HMAC container
                                        EncryptedFileContainerHeader fch2 = new EncryptedFileContainerHeader(stream, false/*peek*/, context.encrypt);
                                        if (!fch2.Equals(fchSecond))
                                        {
                                            throw new InvalidOperationException();
                                        }
                                    }
                                    return null;
                                },
                                delegate(Stream stream)
                                {
                                    if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                                        (context.cryptoOption == EncryptionOption.Recrypt))
                                    {
                                        return context.encrypt.algorithm.CreateDecryptStream(stream, keysSecond.CipherKey, keysSecond.InitialCounter);
                                    }
                                    return null;
                                },
                                delegate(Stream stream)
                                {
                                    if ((context.compressionOption == CompressionOption.Compress)
                                        || (context.compressionOption == CompressionOption.Recompress))
                                    {
                                        return new BlockedDecompressStream(stream);
                                    }
                                    return null;
                                }
                            },
                            delegate(Stream finalSecondStream)
                            {
                                byte[] bufferFirst = new byte[Constants.BufferSize];
                                byte[] bufferSecond = new byte[Constants.BufferSize];
                                result = true;
                                while (true)
                                {
                                    while (true)
                                    {
                                        int bytesReadFirst = finalFirstStream.Read(bufferFirst, 0, bufferFirst.Length);
                                        int bytesReadSecond = finalSecondStream.Read(bufferSecond, 0, bufferSecond.Length);
                                        if (bytesReadFirst != bytesReadSecond)
                                        {
                                            throw new ExitCodeException(0);
                                        }
                                        if (bytesReadFirst == 0)
                                        {
                                            Debug.Assert(bytesReadSecond == 0);
                                            return;
                                        }

                                        if (!ArrayEqual(bufferFirst, 0, bufferSecond, 0, bytesReadFirst))
                                        {
                                            throw new ExitCodeException(0);
                                        }
                                    }
                                }
                            });
                    });
            }
            catch (CryptographicException)
            {
                // hack because .NET 2.0 has a bug where stream throws exception if
                // it isn't at the end when closed. (Specifically: "Padding is invalid and cannot be removed.")
                result = false;
            }
            catch (ExitCodeException)
            {
                result = false;
            }

            return result;
        }

        internal static bool CompareFile(string source, string target, Context context)
        {
            using (Stream sourceStream = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                using (Stream targetStream = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    return CompareStreams(sourceStream, targetStream, context);
                }
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Copy
        //
        ////////////////////////////////////////////////////////////////////////////

        internal static void CopyRecursive(string sourceRootDirectory, string targetRootDirectory, Context context, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems)
        {
            WriteStatusLine(sourceRootDirectory);

            Directory.CreateDirectory(targetRootDirectory);

            List<string> subdirectories = new List<string>();
            bool driveRoot = IsDriveRoot(sourceRootDirectory);
            foreach (string file in DoRetryable<string[]>(delegate { return Directory.GetFileSystemEntries(sourceRootDirectory); }, delegate { return new string[0]; }, null, context, null/*trace*/))
            {
                if (!driveRoot || !IsExcludedDriveRootItem(file))
                {
                    FileAttributes fileAttributes = DoRetryable<FileAttributes>(delegate { return File.GetAttributes(file); }, delegate { return FileAttributes.Normal; }, null, context, null/*trace*/);
                    if ((fileAttributes & FileAttributes.Directory) != 0)
                    {
                        subdirectories.Add(file);
                    }
                    else
                    {
                        if (!context.dirsOnly)
                        {
                            if (!excludedItems.Contains(file.ToLowerInvariant()) &&
                                !excludedExtensions.Contains(Path.GetExtension(file).ToLowerInvariant()))
                            {
                                CopyFile(file, Path.Combine(targetRootDirectory, Path.GetFileName(file)), context);
                            }
                            else
                            {
                                EraseStatusLine();
                                Console.WriteLine("  SKIPPED FILE: {0}", file);
                            }
                        }
                    }
                }
            }

            foreach (string subdirectory in subdirectories)
            {
                if (!excludedItems.Contains(subdirectory.ToLowerInvariant()))
                {
                    CopyRecursive(subdirectory, Path.Combine(targetRootDirectory, Path.GetFileName(subdirectory)), context, excludedExtensions, excludedItems);
                }
                else
                {
                    EraseStatusLine();
                    Console.WriteLine("  SKIPPED SUBDIRECTORY: {0}", subdirectory);
                }
            }

            try
            {
                Directory.SetCreationTime(targetRootDirectory, Directory.GetCreationTime(sourceRootDirectory));
                Directory.SetLastWriteTime(targetRootDirectory, Directory.GetLastWriteTime(sourceRootDirectory));
            }
            catch (Exception)
            {
            }
        }

        internal static void Copy(string source, string target, Context context, string[] args)
        {
            InvariantStringSet excludedExtensions;
            InvariantStringSet excludedItems;
            GetExclusionArguments(args, out excludedExtensions, false/*relative*/, out excludedItems);

            FileAttributes sourceAttributes = DoRetryable<FileAttributes>(delegate { return File.GetAttributes(source); }, delegate { return FileAttributes.Normal; }, null, context, null/*trace*/);
            if ((sourceAttributes & FileAttributes.Directory) == 0)
            {
                CopyFile(
                    source,
                    Directory.Exists(target)
                        ? Path.Combine(target, Path.GetFileName(source))
                        : target,
                    context);
            }
            else
            {
                CopyRecursive(source, target, context, excludedExtensions, excludedItems);
            }

            EraseStatusLine();
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Compare
        //
        ////////////////////////////////////////////////////////////////////////////

        internal static void CompareRecursive(string sourceRootDirectory, string targetRootDirectory, Context context, OneWaySwitch different, bool red)
        {
            WriteStatusLine(sourceRootDirectory);

            SortedList<string, bool> allFiles = new SortedList<string, bool>();

            try
            {
                bool header = false;

                foreach (string file in Directory.GetFileSystemEntries(sourceRootDirectory))
                {
                    string message = null;
                    string fileName = Path.GetFileName(file);
                    FileAttributes fileAttributes = File.GetAttributes(file);
                    bool isDirectory = ((fileAttributes & FileAttributes.Directory) != 0);
                    allFiles.Add(fileName, isDirectory);
                    string targetFile = Path.Combine(targetRootDirectory, fileName);
                    if (!isDirectory)
                    {
                        if (!File.Exists(targetFile))
                        {
                            message = String.Format("Missing file: {0}", fileName);
                        }
                        else if (!CompareFile(file, targetFile, context))
                        {
                            message = String.Format("Different: {0}", fileName);
                        }
                    }
                    else
                    {
                        if (!Directory.Exists(targetFile))
                        {
                            bool empty = Directory.GetFileSystemEntries(file).Length == 0;
                            message = String.Format("Missing {1} directory: {0}", fileName, empty ? "empty" : "nonempty");
                        }
                    }
                    if (message != null)
                    {
                        EraseStatusLine();
                        different.Set();
                        if (!header)
                        {
                            header = true;
                            Console.WriteLine(targetRootDirectory);
                        }
                        if (red)
                        {
                            ConsoleWriteLineColor(ConsoleColor.Red, "  " + message);
                        }
                        else
                        {
                            Console.WriteLine("  " + message);
                        }
                    }
                }

                foreach (string file in Directory.GetFileSystemEntries(targetRootDirectory))
                {
                    string message = null;
                    string fileName = Path.GetFileName(file);
                    FileAttributes fileAttributes = File.GetAttributes(file);
                    bool isDirectory = ((fileAttributes & FileAttributes.Directory) != 0);
                    if (!allFiles.ContainsKey(fileName) || (allFiles[fileName] != isDirectory))
                    {
                        if (isDirectory)
                        {
                            bool empty = Directory.GetFileSystemEntries(file).Length == 0;
                            message = String.Format("Added {1} directory: {0}", fileName, empty ? "empty" : "nonempty");
                        }
                        else
                        {
                            message = String.Format("Added file: {0}", fileName);
                        }
                    }
                    if (message != null)
                    {
                        EraseStatusLine();
                        different.Set();
                        if (!header)
                        {
                            header = true;
                            Console.WriteLine(targetRootDirectory);
                        }
                        if (red)
                        {
                            ConsoleWriteLineColor(ConsoleColor.Red, "  " + message);
                        }
                        else
                        {
                            Console.WriteLine("  " + message);
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                EraseStatusLine();
                different.Set();
                Console.WriteLine("  Exception processing directory '{0}': {1}", sourceRootDirectory, exception.Message);
            }

            foreach (KeyValuePair<string, bool> item in allFiles)
            {
                if (item.Value && Directory.Exists(Path.Combine(targetRootDirectory, item.Key)))
                {
                    CompareRecursive(Path.Combine(sourceRootDirectory, item.Key), Path.Combine(targetRootDirectory, item.Key), context, different, red);
                }
            }
        }

        internal static void Compare(string source, string target, Context context)
        {
            OneWaySwitch different = new OneWaySwitch();

            FileAttributes sourceAttributes = File.GetAttributes(source);
            FileAttributes targetAttributes = File.GetAttributes(target);
            bool sourceIsFile = ((sourceAttributes & FileAttributes.Directory) == 0);
            bool targetIsFile = ((targetAttributes & FileAttributes.Directory) == 0);
            if (sourceIsFile != targetIsFile)
            {
                different.Set();
                Console.WriteLine("Different");
            }
            else if (sourceIsFile)
            {
                if (CompareFile(source, target, context))
                {
                    Console.WriteLine("Identical");
                }
                else
                {
                    different.Set();
                    Console.WriteLine("Different");
                }
            }
            else
            {
                CompareRecursive(source, target, context, different, false/*red*/);
            }

            EraseStatusLine();

            if (different.Value)
            {
                throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied);
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Sync
        //
        ////////////////////////////////////////////////////////////////////////////

        public interface IEnumerateHierarchy
        {
            bool Valid { get; }
            bool MoveNext();
            string Current { get; }
            string CurrentFullPath { get; }
            FileAttributes CurrentAttributes { get; }
            bool CurrentIsDirectory { get; }
            DateTime CurrentLastWrite { get; }
            void Close();
        }

        internal class EnumerateHierarchy : IEnumerateHierarchy
        {
            private struct Level
            {
                internal readonly string path;
                internal readonly string[] entries;
                internal int index;

                internal Level(string path, string[] entries, int index)
                {
                    this.path = path;
                    this.entries = entries;
                    this.index = index;
                }
            }

            private readonly string root;
            private readonly Stack<Level> stack = new Stack<Level>();
            private Level top;
            private string current;
            private FileAttributes? currentAttributes;
            private DateTime? currentLastWrite;

            internal EnumerateHierarchy(string root)
            {
                this.root = root;
                this.top = new Level(String.Empty, this.GetFileSystemEntries(String.Empty), -1);
            }

            internal EnumerateHierarchy(EnumerateHierarchy original)
            {
                this.root = original.root;
                this.stack = new Stack<Level>(original.stack);
                this.top = original.top;
                this.current = original.current;
            }

            public bool Valid
            {
                get
                {
                    return current != null;
                }
            }

            public bool MoveNext()
            {
                current = null;
                currentAttributes = null;
                currentLastWrite = null;

                string previous = null;
                bool previousIsDirectory = false;
                if (top.index >= 0)
                {
                    previous = !String.IsNullOrEmpty(top.path) ? Path.Combine(top.path, top.entries[top.index]) : top.entries[top.index];
                    try
                    {
                        previousIsDirectory = (File.GetAttributes(Path.Combine(root, previous)) & FileAttributes.Directory) != 0;
                    }
                    catch (FileNotFoundException)
                    {
                    }
                }

                top.index++;

                if (previousIsDirectory)
                {
                    Level newTop = new Level(previous, this.GetFileSystemEntries(previous), 0);
                    stack.Push(top);
                    top = newTop;
                }
                while ((top.index >= top.entries.Length) && (stack.Count > 0))
                {
                    top = stack.Pop();
                }

                if (top.index >= top.entries.Length)
                {
                    return false;
                }

                current = !String.IsNullOrEmpty(top.path) ? Path.Combine(top.path, top.entries[top.index]) : top.entries[top.index];

                return true;
            }

            public string Current
            {
                get
                {
                    if (!Valid)
                    {
                        throw new ApplicationException();
                    }
                    return current;
                }
            }

            public string CurrentFullPath
            {
                get
                {
                    return Path.Combine(root, Current);
                }
            }

            public FileAttributes CurrentAttributes
            {
                get
                {
                    if (!Valid)
                    {
                        throw new ApplicationException();
                    }
                    if (!currentAttributes.HasValue)
                    {
                        currentAttributes = File.GetAttributes(Path.Combine(root, current));
                    }
                    return currentAttributes.Value;
                }
            }

            public bool CurrentIsDirectory
            {
                get
                {
                    return (CurrentAttributes & FileAttributes.Directory) != 0;
                }
            }

            public DateTime CurrentLastWrite
            {
                get
                {
                    if (!Valid)
                    {
                        throw new ApplicationException();
                    }
                    if (!currentLastWrite.HasValue)
                    {
                        currentLastWrite = File.GetLastWriteTime(Path.Combine(root, current));
                    }
                    return currentLastWrite.Value;
                }
            }

            public void Close()
            {
            }

            private string[] GetFileSystemEntries(string path)
            {
                if (Array.FindIndex(ExcludedDriveRootItems, delegate(KeyValuePair<string, bool> candidate) { return candidate.Value/*isDir*/ && candidate.Key.Equals(path, StringComparison.OrdinalIgnoreCase); }) >= 0)
                {
                    return new string[0];
                }

                path = !String.IsNullOrEmpty(path) ? Path.Combine(root, path) : root;
                string[] entries = Directory.GetFileSystemEntries(path);
                for (int i = 0; i < entries.Length; i++)
                {
                    entries[i] = Path.GetFileName(entries[i]);
                }
                Array.Sort(entries, delegate(string l, string r) { return SyncPathCompare(l, r); });
                return entries;
            }
        }

        internal class EnumerateFile : IEnumerateHierarchy, IDisposable
        {
            private readonly string root;
            private readonly string path;
            private Stream stream;
            private string current;
            private FileAttributes currentAttributes;
            private DateTime currentLastWrite;

            internal EnumerateFile(string root, string path)
            {
                this.root = root;
                this.path = path;
                this.stream = new FileStream(this.path, FileMode.Open, FileAccess.Read, FileShare.Read);
                byte[] b = new byte[3];
                int c = this.stream.Read(b, 0, 3);
                if ((c < 3) || (b[0] != 0xEF) || (b[1] != 0xBB) || (b[2] != 0xBF))
                {
                    this.stream.Position = 0;
                }
            }

            internal EnumerateFile(string root)
            {
                this.root = root;
            }

            internal EnumerateFile(EnumerateFile original)
            {
                this.root = original.root;
                this.path = original.path;
                this.stream = new FileStream(this.path, FileMode.Open, FileAccess.Read, FileShare.Read);
                this.stream.Position = original.stream.Position;
                this.current = original.current;
                this.currentAttributes = original.currentAttributes;
                this.currentLastWrite = original.currentLastWrite;
            }

            public bool Valid
            {
                get
                {
                    return current != null;
                }
            }

            public bool MoveNext()
            {
                current = null;

                if (stream == null)
                {
                    return false;
                }

                string line = ReadLineUTF8(stream);
                if (line == null)
                {
                    stream.Close();
                    stream = null;
                    return false;
                }

                ParseLine(line, out current, out currentAttributes, out currentLastWrite);

                return true;
            }

            public string Current
            {
                get
                {
                    if (!Valid)
                    {
                        throw new ApplicationException();
                    }
                    return current;
                }
            }

            public string CurrentFullPath
            {
                get
                {
                    return Path.Combine(root, Current);
                }
            }

            public FileAttributes CurrentAttributes
            {
                get
                {
                    if (!Valid)
                    {
                        throw new ApplicationException();
                    }
                    return currentAttributes;
                }
            }

            public bool CurrentIsDirectory
            {
                get
                {
                    return (CurrentAttributes & FileAttributes.Directory) != 0;
                }
            }

            public DateTime CurrentLastWrite
            {
                get
                {
                    if (!Valid)
                    {
                        throw new ApplicationException();
                    }
                    return currentLastWrite;
                }
            }

            public void Close()
            {
                if (stream != null)
                {
                    stream.Close();
                    stream = null;
                }
            }

            void IDisposable.Dispose()
            {
                Close();
            }

            private const string SyncFileNewLine = "\r\n";
            internal static void WriteLine(TextWriter writer, string path, FileAttributes attributes, DateTime lastWrite)
            {
                writer.Write(String.Format("{0}\t{1}\t{2}" + SyncFileNewLine, (Int32)attributes, lastWrite.ToBinary(), path));
            }

            private static string ReadLineUTF8(Stream stream)
            {
                List<byte> encoded = new List<byte>();
                while ((encoded.Count < 2) || !((encoded[encoded.Count - 2] == '\r') && (encoded[encoded.Count - 1] == '\n')))
                {
                    int c = stream.ReadByte();
                    if (c == -1)
                    {
                        break;
                    }
                    encoded.Add((byte)c);
                }
                if ((encoded.Count >= 2) && (encoded[encoded.Count - 2] == '\r') && (encoded[encoded.Count - 1] == '\n'))
                {
                    encoded.RemoveRange(encoded.Count - 2, 2);
                }
                return encoded.Count > 0 ? new String(Encoding.UTF8.GetChars(encoded.ToArray())) : null;
            }

            public static void ParseLine(string line, out string path, out FileAttributes attributes, out DateTime lastWrite)
            {
                string[] parts = line.Split('\t');
                path = parts[2];
                attributes = (FileAttributes)Int32.Parse(parts[0]);
                lastWrite = DateTime.FromBinary(Int64.Parse(parts[1]));
            }
        }

        private static int SyncPathCompare(string l, string r)
        {
            int len = Math.Max(l.Length, r.Length);
            for (int i = 0; i < len; i++)
            {
                char cl = (i < l.Length ? l[i] : (char)0);
                if (cl == '\\')
                {
                    cl = (char)0;
                }
                char cr = (i < r.Length ? r[i] : (char)0);
                if (cr == '\\')
                {
                    cr = (char)0;
                }
                int c = Char.ToLowerInvariant(cl).CompareTo(Char.ToLowerInvariant(cr));
                if (c != 0)
                {
                    return c;
                }
            }
            return 0;
        }

        private static void SyncChange(string sourceRoot, string targetRoot, string path, int codePath, TextWriter log, bool l2r, IVolumeFlushHelperCollection volumeFlushHelperCollection, IFaultInstance faultContext)
        {
            try
            {
                if (log != null)
                {
                    string sizeLPath = Path.Combine(l2r ? sourceRoot : targetRoot, path);
                    string sizeRPath = Path.Combine(l2r ? targetRoot : sourceRoot, path);
                    string sizePart = String.Empty;
                    if (File.Exists(sizeLPath) && File.Exists(sizeRPath))
                    {
                        sizePart = String.Format("{0}, {1} ", FileSizeString(sizeLPath), FileSizeString(sizeRPath));
                    }
                    log.WriteLine("{1}{2}{3} \"{0}\" {5}[codePath={4}]", path, l2r ? sourceRoot : targetRoot, l2r ? "==>" : "<==", l2r ? targetRoot : sourceRoot, codePath, sizePart);
                }

                string sourcePath = Path.Combine(sourceRoot, path);
                string targetPath = Path.Combine(targetRoot, path);

                if (File.Exists(targetPath))
                {
                    if (log != null)
                    {
                        log.WriteLine("  {0,-8} {1,-3} \"{2}\"", "del", String.Empty, targetPath);
                    }
                    faultContext.Select("del", targetPath);
                    File.SetAttributes(targetPath, File.GetAttributes(targetPath) & ~FileAttributes.ReadOnly);
                    File.Delete(targetPath);
                }
                else if (Directory.Exists(targetPath))
                {
                    if (log != null)
                    {
                        log.WriteLine("  {0,-8} {1,-3} \"{2}\"", "rmdir /s", String.Empty, targetPath);
                    }
                    faultContext.Select("rmdir", targetPath);
                    bool retry = false;
                    try
                    {
                        Directory.Delete(targetPath, true/*recursive*/);
                    }
                    catch (IOException)
                    {
                        retry = true;
                    }
                    catch (UnauthorizedAccessException)
                    {
                        retry = true;
                    }
                    if (retry)
                    {
                        EnumerateHierarchy enumSubdir = new EnumerateHierarchy(targetPath);
                        while (enumSubdir.MoveNext())
                        {
                            File.SetAttributes(enumSubdir.CurrentFullPath, File.GetAttributes(enumSubdir.CurrentFullPath) & ~FileAttributes.ReadOnly);
                        }
                        Directory.Delete(targetPath, true/*recursive*/);
                    }
                }

                if (File.Exists(sourcePath))
                {
                    if (log != null)
                    {
                        log.WriteLine("  {0,-8} {1,-3} \"{2}\"", "copy", "to", targetPath);
                    }
                    faultContext.Select("copy", targetPath);
                    try
                    {
                        File.Copy(sourcePath, targetPath);
                        volumeFlushHelperCollection.MarkDirty(targetPath);
                    }
                    catch (PathTooLongException exception)
                    {
                        throw new PathTooLongException(String.Format("{0} (length={2}, path=\'{1}\')", exception.Message, targetPath, targetPath.Length));
                    }

                    FileAttributes fa = File.GetAttributes(targetPath);
                    File.SetAttributes(targetPath, fa & ~FileAttributes.ReadOnly);
                    File.SetCreationTime(targetPath, File.GetCreationTime(sourcePath));
                    File.SetLastWriteTime(targetPath, File.GetLastWriteTime(sourcePath));
                    File.SetAttributes(targetPath, fa);

                    File.SetAttributes(targetPath, (File.GetAttributes(sourcePath) & ~(FileAttributes.Compressed | FileAttributes.Encrypted)) | (File.GetAttributes(targetPath) & (FileAttributes.Compressed | FileAttributes.Encrypted)));
                }
                else if (Directory.Exists(sourcePath))
                {
                    if (log != null)
                    {
                        log.WriteLine("  {0,-8} {1,-3} \"{2}\"", "mkdir", String.Empty, targetPath);
                    }
                    faultContext.Select("mkdir", targetPath);
                    try
                    {
                        Directory.CreateDirectory(targetPath);
                        volumeFlushHelperCollection.MarkDirty(targetPath);
                    }
                    catch (PathTooLongException exception)
                    {
                        throw new PathTooLongException(String.Format("{0} (length={2}, path=\'{1}\')", exception.Message, targetPath, targetPath.Length));
                    }
                    Directory.SetCreationTime(targetPath, Directory.GetCreationTime(sourcePath));
                    Directory.SetLastWriteTime(targetPath, Directory.GetLastWriteTime(sourcePath));
                }
            }
            catch (Exception exception)
            {
                if (log != null)
                {
                    log.WriteLine("  {0} {2}", "EXCEPTION", String.Empty, exception.Message);
                }
                ConsoleWriteLineColor(ConsoleColor.Red, "EXCEPTION at \"{0}\": {1}", path, exception.Message);
                throw;
            }
        }

        private static void SyncChangeDirectoryCaseChangeOnly(string sourceRoot, string targetRoot, string path, int codePath, TextWriter log, bool l2r, IVolumeFlushHelperCollection volumeFlushHelperCollection, IFaultInstance faultContext)
        {
            try
            {
                if (log != null)
                {
                    string sizeLPath = Path.Combine(l2r ? sourceRoot : targetRoot, path);
                    string sizeRPath = Path.Combine(l2r ? targetRoot : sourceRoot, path);
                    string sizePart = String.Empty;
                    if (File.Exists(sizeLPath) && File.Exists(sizeRPath))
                    {
                        sizePart = String.Format("{0}, {1} ", FileSizeString(sizeLPath), FileSizeString(sizeRPath));
                    }
                    log.WriteLine("{1}{2}{3} \"{0}\" {5}[codePath={4}]", path, l2r ? sourceRoot : targetRoot, l2r ? "==>" : "<==", l2r ? targetRoot : sourceRoot, codePath, sizePart);
                }

                string sourcePath = Path.Combine(sourceRoot, path);
                string targetPath = Path.Combine(targetRoot, path);

                // Special case: if directory name and only case has changed, propagate as direct rename rather than rmdir-mkdir.
                // The rmdir-mkdir method relies on subsequent file traversal to copy the content, but since the directory name is
                // the same, the deletes are back-propagated, losing the directory content on both sides.
                if (Directory.Exists(sourcePath) && Directory.Exists(targetPath))
                {
                    string actualSourceName = null;
                    string actualTargetName = null;
                    string[] items;
                    items = Directory.GetDirectories(Path.GetDirectoryName(sourcePath), Path.GetFileName(sourcePath));
                    if (items.Length == 1)
                    {
                        actualSourceName = Path.GetFileName(items[0]);
                    }
                    items = Directory.GetDirectories(Path.GetDirectoryName(targetPath), Path.GetFileName(targetPath));
                    if (items.Length == 1)
                    {
                        actualTargetName = Path.GetFileName(items[0]);
                    }
                    if ((actualSourceName == null) && (actualTargetName == null))
                    {
                        throw new ApplicationException(String.Format("Directory inconsistency: \"{0}\" or \"{1}\"", sourcePath, targetPath));
                    }
                    if ((actualSourceName != null) && (actualTargetName != null)
                        && String.Equals(actualSourceName, actualTargetName, StringComparison.OrdinalIgnoreCase)
                        && !String.Equals(actualSourceName, actualTargetName, StringComparison.Ordinal))
                    {
                        if (log != null)
                        {
                            log.WriteLine("  {0,-8} {1,-3} \"{2}\"", "rename", "was", actualTargetName);
                        }
                        int temp = 0;
                        string tempPath;
                        while (Directory.Exists(tempPath = Path.Combine(Path.GetDirectoryName(targetPath), temp.ToString())))
                        {
                            temp++;
                        }
                        Directory.Move(targetPath, tempPath); // source is case insensitive
                        Directory.Move(tempPath, targetPath); // establishes desired case
                        return;
                    }
                }

                // should not be called in any other scenario than the special case
                throw new NotSupportedException();
            }
            catch (Exception exception)
            {
                if (log != null)
                {
                    log.WriteLine("  {0} {2}", "EXCEPTION", String.Empty, exception.Message);
                }
                ConsoleWriteLineColor(ConsoleColor.Red, "EXCEPTION at \"{0}\": {1}", path, exception.Message);
                throw;
            }
        }

        private const FileAttributes SyncPropagatedAttributes = FileAttributes.ReadOnly | FileAttributes.Directory;

        private static bool SyncSubdirChanged(string root, EnumerateHierarchy currentEntries, EnumerateFile previousEntries, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems)
        {
            currentEntries = new EnumerateHierarchy(currentEntries);
            using (previousEntries = new EnumerateFile(previousEntries))
            {
            Loop:
                while (currentEntries.Valid)
                {
                    if (!currentEntries.Current.Equals(root, StringComparison.OrdinalIgnoreCase) && !currentEntries.Current.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }

                    if (currentEntries.Valid
                        && ((excludedItems.Contains(currentEntries.Current) || excludedItems.StartsWithAny(currentEntries.Current, "\\"))
                        || (!currentEntries.CurrentIsDirectory && excludedExtensions.EndsWithAny(currentEntries.Current, null))))
                    {
                        currentEntries.MoveNext();
                        goto Loop;
                    }

                    string selected = currentEntries.Current;

                    while (previousEntries.Valid && (SyncPathCompare(previousEntries.Current, selected) < 0))
                    {
                        previousEntries.MoveNext();
                    }
                    bool previousExisted = previousEntries.Valid && (SyncPathCompare(previousEntries.Current, selected) == 0);

                    bool changed = !previousExisted || ((previousEntries.CurrentAttributes & SyncPropagatedAttributes) != (currentEntries.CurrentAttributes & SyncPropagatedAttributes)) || (!previousEntries.CurrentIsDirectory && (previousEntries.CurrentLastWrite != currentEntries.CurrentLastWrite));

                    if (changed)
                    {
                        return true;
                    }

                    currentEntries.MoveNext();
                }
            }

            return false;
        }

        private interface IVolumeFlushHelperCollection : IDisposable
        {
            int Add(string path);
            void MarkDirty(int index);
            void MarkDirty(string path);
            bool FlushNeeded();
            void Flush();
        }

        private class NullVolumeFlushHelperCollection : IVolumeFlushHelperCollection
        {
            private bool dirty = true;

            public int Add(string path)
            {
                return 0;
            }

            public void MarkDirty(int index)
            {
                dirty = true;
            }

            public void MarkDirty(string path)
            {
                dirty = true;
            }

            public bool FlushNeeded()
            {
                return dirty;
            }

            public void Flush()
            {
                dirty = false;
            }

            public void Dispose()
            {
            }
        }

        private class VolumeFlushHelperCollection : IVolumeFlushHelperCollection
        {
            private KeyValuePair<VolumeFlushHelper, bool>[] volumes = new KeyValuePair<VolumeFlushHelper, bool>[0];
            private readonly TextWriter log;

            private const int DirtyCountFlushThreshhold = 25;
            private int dirtyCount;
            private const int DirtyFlushIntervalSeconds = 15;
            private DateTime lastDirtyStart;

            private static bool GetFinalPathNameByHandle_Available = true;

            public VolumeFlushHelperCollection(TextWriter log)
            {
                this.log = log;
            }

            private int Find(string volumePath)
            {
                for (int i = 0; i < volumes.Length; i++)
                {
                    if (String.Equals(volumePath, volumes[i].Key.VolumePath, StringComparison.OrdinalIgnoreCase))
                    {
                        return i;
                    }
                }
                return -1;
            }

            // volume is initially marked dirty when added, but not if already present
            private int AddVolume(string volumePath)
            {
                int index = Find(volumePath);
                if (index >= 0)
                {
                    return index;
                }

                Array.Resize(ref volumes, volumes.Length + 1);
                volumes[volumes.Length - 1] = new KeyValuePair<VolumeFlushHelper, bool>(new VolumeFlushHelper(volumePath), true/*dirty*/);
                if (dirtyCount++ == 0)
                {
                    lastDirtyStart = DateTime.Now;
                }
                return volumes.Length - 1;
            }

            public int Add(string path)
            {
                string volumePath = GetVolumePath(path);
                return AddVolume(volumePath);
            }

            public void MarkDirty(int index)
            {
                volumes[index] = new KeyValuePair<VolumeFlushHelper, bool>(volumes[index].Key, true/*dirty*/);
                if (dirtyCount++ == 0)
                {
                    lastDirtyStart = DateTime.Now;
                }
            }

            public void MarkDirty(string path)
            {
                string volumePath = GetVolumePath(path);

                int index = Find(volumePath);
                if (index >= 0)
                {
                    MarkDirty(index);
                    return;
                }

                AddVolume(volumePath);
            }

            public bool FlushNeeded()
            {
                return (dirtyCount >= DirtyCountFlushThreshhold)
                    || ((dirtyCount > 0) && (lastDirtyStart.AddSeconds(DirtyFlushIntervalSeconds) < DateTime.Now));
            }

            public void Flush()
            {
                dirtyCount = 0;

                StringBuilder logMessage = null;
                if (log != null)
                {
                    logMessage = new StringBuilder();
                }

                for (int i = 0; i < volumes.Length; i++)
                {
                    if (volumes[i].Value)
                    {
                        if (log != null)
                        {
                            if (logMessage.Length != 0)
                            {
                                logMessage.Append(", ");
                            }
                            logMessage.Append(volumes[i].Key.VolumePath.Substring(D.Length));
                        }

                        volumes[i].Key.Flush();
                        volumes[i] = new KeyValuePair<VolumeFlushHelper, bool>(volumes[i].Key, false/*dirty*/);
                    }
                }

                if (log != null)
                {
                    log.WriteLine("[flush {0}]", logMessage);
                }
            }

            public void Dispose()
            {
                for (int i = 0; i < volumes.Length; i++)
                {
                    volumes[i].Key.Dispose();
                }
                volumes = new KeyValuePair<VolumeFlushHelper, bool>[0];
            }

            private const string Q = @"\\?\";
            private const string D = @"\\.\";
            private static string GetVolumePath(string path)
            {
                string normalizedPath = null;

                if (GetFinalPathNameByHandle_Available)
                {
                    IntPtr hPath;
                    if (Directory.Exists(path))
                    {
                        hPath = CreateFile(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
                    }
                    else
                    {
                        hPath = CreateFile(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                    }
                    if (Marshal.GetLastWin32Error() != 0)
                    {
                        Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                    }
                    try
                    {
                        StringBuilder normalizedPathBuffer = new StringBuilder(MAX_PATH);
                        try
                        {
                            if (0 == GetFinalPathNameByHandle(hPath, normalizedPathBuffer, MAX_PATH, FILE_NAME_NORMALIZED))
                            {
                                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                            }
                            normalizedPath = normalizedPathBuffer.ToString();
                        }
                        catch (EntryPointNotFoundException)
                        {
                            // GetFinalPathNameByHandle not available on WinXP
                        }
                    }
                    finally
                    {
                        CloseHandle(hPath);
                    }
                }
                if (normalizedPath == null)
                {
                    // WinXP fallback
                    normalizedPath = Q + path;
                }

                StringBuilder volumePathBuffer = new StringBuilder(MAX_PATH);
                if (!GetVolumePathName(normalizedPath, volumePathBuffer, MAX_PATH))
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }
                string volumePath = volumePathBuffer.ToString();
                if (volumePath[volumePath.Length - 1] == '\\')
                {
                    volumePath = volumePath.Substring(0, volumePath.Length - 1);
                }

                Debug.Assert(volumePath.StartsWith(Q));
                volumePath = D + volumePath.Substring(Q.Length);

                return volumePath;
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa364439%28v=vs.85%29.aspx
            [DllImport("Kernel32.dll", SetLastError = true)]
            private static extern bool FlushFileBuffers(IntPtr hFile);

            [DllImport("Kernel32.dll", SetLastError = true)]
            private static extern bool CloseHandle(IntPtr hObject);

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa363858%28v=vs.85%29.aspx
            private const Int32 GENERIC_WRITE = 0x40000000;
            private const Int32 FILE_SHARE_READ = 1;
            private const Int32 FILE_SHARE_WRITE = 2;
            private const Int32 OPEN_EXISTING = 3;
            private const Int32 FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
            [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            private static extern IntPtr CreateFile(string lpFileName, Int32 dwDesiredAccess, Int32 dwShareMode, IntPtr lpSecurityAttributes, Int32 dwCreationDisposition, Int32 dwFlagsAndAttributes, IntPtr hTemplateFile);

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa364996%28v=vs.85%29.aspx
            private const int MAX_PATH = 260;
            [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            private static extern bool GetVolumePathName(string lpszFileName, [Out] StringBuilder lpszVolumePathName, Int32 cchBufferLength);

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa364962%28v=vs.85%29.aspx
            private const Int32 FILE_NAME_NORMALIZED = 0;
            [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            private static extern Int32 GetFinalPathNameByHandle(IntPtr hFile, [Out] StringBuilder lpszFilePath, Int32 cchFilePath, Int32 dwFlags);

            private class VolumeFlushHelper : IDisposable
            {
                private IntPtr volumeHandle;
                private readonly string volumePath;

                public VolumeFlushHelper(string volumePath)
                {
                    this.volumePath = volumePath;
                    volumeHandle = CreateFile(volumePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                    if (Marshal.GetLastWin32Error() != 0)
                    {
                        Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                    }
                }

                public string VolumePath { get { return volumePath; } }

                public void Flush()
                {
                    if (!volumeHandle.Equals(IntPtr.Zero))
                    {
                        if (!FlushFileBuffers(volumeHandle))
                        {
                            Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                        }
                    }
                }

                public void Dispose()
                {
                    if (!volumeHandle.Equals(IntPtr.Zero))
                    {
                        CloseHandle(volumeHandle);
                        volumeHandle = IntPtr.Zero;
                    }
                }
            }
        }

        private static long PositionOfLastLineBreak(Stream stream)
        {
            byte[] pattern = Encoding.UTF8.GetBytes(Environment.NewLine);
            long offset = 0;
            long last = 0;
            byte[] buffer = new byte[Constants.BufferSize + pattern.Length - 1];

            int remaining = stream.Read(buffer, 0, buffer.Length);
            while (remaining != 0)
            {
                for (int i = 0; i < remaining - (pattern.Length - 1); i++)
                {
                    if (buffer[i] == pattern[0])
                    {
                        for (int j = 1; j < pattern.Length; j++)
                        {
                            if (buffer[i + j] != pattern[j])
                            {
                                goto Next;
                            }
                        }

                        last = offset + i + pattern.Length;

                    Next:
                        ;
                    }
                }

                if (remaining != buffer.Length)
                {
                    break;
                }

                Buffer.BlockCopy(buffer, Constants.BufferSize, buffer, 0, pattern.Length - 1);
                offset += Constants.BufferSize;
                remaining -= Constants.BufferSize;

                int read = stream.Read(buffer, pattern.Length - 1, Constants.BufferSize);
                remaining += read;
            }

            return last;
        }

        private static void SyncRollForward(string manifestNewRecovery, TextWriter newEntries, EnumerateHierarchy currentEntries, EnumerateFile previousEntries, TextWriter log, string logTag)
        {
            if (File.Exists(manifestNewRecovery))
            {
                if (log != null)
                {
                    log.WriteLine("(Resuming an incomplete operation)");
                }

                using (Stream stream = new FileStream(manifestNewRecovery, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    // if last line of file is incomplete, truncate to last complete line
                    long end = PositionOfLastLineBreak(stream);
                    stream.Position = 0;
                    stream.SetLength(end);

                    // roll forward new manifest to previous failure point
                    string last = null;
                    using (TextReader reader = new StreamReader(stream, Encoding.UTF8))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            newEntries.WriteLine(line);
                            last = line;
                        }
                    }
                    newEntries.Flush();

                    if (last != null)
                    {
                        string lastPath;
                        FileAttributes attributes;
                        DateTime lastWrite;
                        EnumerateFile.ParseLine(last, out lastPath, out attributes, out lastWrite);

                        if (log != null)
                        {
                            log.WriteLine("Roll forward {0} to {1}", logTag, lastPath);
                        }

                        // fast-forward current and previous iterators
                        while (currentEntries.Valid && (SyncPathCompare(currentEntries.Current, lastPath) <= 0))
                        {
                            currentEntries.MoveNext();
                        }
                        while (previousEntries.Valid && (SyncPathCompare(previousEntries.Current, lastPath) <= 0))
                        {
                            previousEntries.MoveNext();
                        }
                    }
                }

                File.Delete(manifestNewRecovery);

                if (log != null)
                {
                    log.WriteLine();
                }
            }
        }

        private const string SyncManifestLocalPrefix = "local";
        private const string SyncManifestRemotePrefix = "remote";
        private const string SyncManifestSavedSuffix = "sync.txt";
        private const string SyncManifestNewSuffix = "sync0.txt";
        private const string SyncManifestBackupExtension = ".bak";
        private const string SyncManifestRecoveryExtension = ".rec";
        internal static void Sync(string rootL, string rootR, string repository, Context context, string[] args)
        {
            // In this method, suffix L == "Left" or "Local" and R == "Right" or "Remote". Clever, eh?

            IFaultInstance faultInstanceSync = context.faultInjectionRoot.Select("Sync", String.Format("{0}|{1}", rootL, rootR));

            bool resolveSkip = false;

            string diagnosticPath;
            GetAdHocArgument(ref args, "-logpath", null/*default*/, delegate(string s) { return s; }, out diagnosticPath);
            TextWriter log = null;
            if (diagnosticPath != null)
            {
                log = new StreamWriter(diagnosticPath, false, Encoding.UTF8);
                log.WriteLine("Sync log");
                log.WriteLine();
            }

            bool flushVolumeEnabled;
            GetAdHocArgument(ref args, "-flushvols", false/*defaultValue*/, true/*explicitValue*/, out flushVolumeEnabled);

            InvariantStringSet excludedExtensions;
            InvariantStringSet excludedItems;
            GetExclusionArguments(args, out excludedExtensions, true/*relative*/, out excludedItems);
            if (IsDriveRoot(Path.GetFullPath(rootL)) || IsDriveRoot(Path.GetFullPath(rootR)))
            {
                foreach (KeyValuePair<string, bool> item in ExcludedDriveRootItems)
                {
                    excludedItems.Set(item.Key);
                }
            }

            IVolumeFlushHelperCollection volumeFlushHelperCollection = new NullVolumeFlushHelperCollection();
            int volumeFlushHelperRepository = -1;
            if (flushVolumeEnabled)
            {
                volumeFlushHelperCollection = new VolumeFlushHelperCollection(log);
                try
                {
                    volumeFlushHelperCollection.Add(rootL);
                    volumeFlushHelperCollection.Add(rootR);
                    volumeFlushHelperRepository = volumeFlushHelperCollection.Add(repository);
                }
                catch (UnauthorizedAccessException exception)
                {
                    throw new ApplicationException("Option to flush volume buffers (-flushvols) requires administrative privileges", exception);
                }
            }

            string manifestLocalSaved = Path.Combine(repository, SyncManifestLocalPrefix + SyncManifestSavedSuffix);
            string manifestLocalSavedBackup = manifestLocalSaved + SyncManifestBackupExtension;
            string manifestLocalNew = Path.Combine(repository, SyncManifestLocalPrefix + SyncManifestNewSuffix);
            string manifestLocalNewRecovery = manifestLocalNew + SyncManifestRecoveryExtension;
            string manifestRemoteSaved = Path.Combine(repository, SyncManifestRemotePrefix + SyncManifestSavedSuffix);
            string manifestRemoteSavedBackup = manifestRemoteSaved + SyncManifestBackupExtension;
            string manifestRemoteNew = Path.Combine(repository, SyncManifestRemotePrefix + SyncManifestNewSuffix);
            string manifestRemoteNewRecovery = manifestRemoteNew + SyncManifestRecoveryExtension;

            // If program failed while committing manifests, restore missing manifest from backup
            if (!File.Exists(manifestLocalSaved) && File.Exists(manifestLocalSavedBackup))
            {
                File.Move(manifestLocalSavedBackup, manifestLocalSaved);
            }
            if (!File.Exists(manifestRemoteSaved) && File.Exists(manifestRemoteSavedBackup))
            {
                File.Move(manifestRemoteSavedBackup, manifestRemoteSaved);
            }

            // If program failed and left "new" unfinished manifests, save for recovery
            if (File.Exists(manifestLocalNew))
            {
                try
                {
                    File.Delete(manifestLocalNewRecovery);
                }
                catch (FileNotFoundException)
                {
                }
                File.Move(manifestLocalNew, manifestLocalNewRecovery);
            }
            if (File.Exists(manifestRemoteNew))
            {
                try
                {
                    File.Delete(manifestRemoteNewRecovery);
                }
                catch (FileNotFoundException)
                {
                }
                File.Move(manifestRemoteNew, manifestRemoteNewRecovery);
            }

            EnumerateHierarchy currentEntriesL = new EnumerateHierarchy(rootL);
            currentEntriesL.MoveNext();
            EnumerateFile previousEntriesL = new EnumerateFile(rootL);
            if (File.Exists(manifestLocalSaved))
            {
                previousEntriesL = new EnumerateFile(rootL, manifestLocalSaved);
            }
            previousEntriesL.MoveNext();
            TextWriter newEntriesLPermanent = new StreamWriter(manifestLocalNew, false/*append*/, Encoding.UTF8);

            EnumerateHierarchy currentEntriesR = new EnumerateHierarchy(rootR);
            currentEntriesR.MoveNext();
            EnumerateFile previousEntriesR = new EnumerateFile(rootR);
            if (File.Exists(manifestRemoteSaved))
            {
                previousEntriesR = new EnumerateFile(rootR, manifestRemoteSaved);
            }
            previousEntriesR.MoveNext();
            TextWriter newEntriesRPermanent = new StreamWriter(manifestRemoteNew, false/*append*/, Encoding.UTF8);

            SyncRollForward(manifestLocalNewRecovery, newEntriesLPermanent, currentEntriesL, previousEntriesL, log, "local");
            SyncRollForward(manifestRemoteNewRecovery, newEntriesRPermanent, currentEntriesR, previousEntriesR, log, "remote");

            TextWriter newEntriesLTemporary = new StringWriter();
            TextWriter newEntriesRTemporary = new StringWriter();
            try
            {
                newEntriesLPermanent.Flush();
                newEntriesRPermanent.Flush();
                volumeFlushHelperCollection.MarkDirty(volumeFlushHelperRepository);
                volumeFlushHelperCollection.Flush();

            Loop:
                while (currentEntriesL.Valid || currentEntriesR.Valid)
                {
                    if (volumeFlushHelperCollection.FlushNeeded())
                    {
                        volumeFlushHelperCollection.Flush();

                        newEntriesLPermanent.Write(newEntriesLTemporary);
                        newEntriesLPermanent.Flush();
                        newEntriesLTemporary = new StringWriter();

                        newEntriesRPermanent.Write(newEntriesRTemporary);
                        newEntriesRPermanent.Flush();
                        newEntriesRTemporary = new StringWriter();

                        volumeFlushHelperCollection.MarkDirty(volumeFlushHelperRepository);
                        volumeFlushHelperCollection.Flush();
                    }

                    IFaultInstance faultInstanceIteration = faultInstanceSync.Select("Iteration");
                    IFaultInstance faultInstanceLeftEntry = faultInstanceIteration.Select("LeftEntry", currentEntriesL.Valid ? currentEntriesL.CurrentFullPath : null);
                    IFaultInstance faultInstanceRightEntry = faultInstanceIteration.Select("RightEntry", currentEntriesR.Valid ? currentEntriesR.CurrentFullPath : null);

                    int codePath = -1;

                    bool rootExclusion = false;
                    bool extensionExclusion = false;
                    if (currentEntriesL.Valid
                        && (((rootExclusion = excludedItems.Contains(currentEntriesL.Current)) || excludedItems.StartsWithAny(currentEntriesL.Current, "\\"))
                        || (!currentEntriesL.CurrentIsDirectory && (extensionExclusion = excludedExtensions.EndsWithAny(currentEntriesL.Current, null)))))
                    {
                        if (log != null)
                        {
                            if (rootExclusion || extensionExclusion)
                            {
                                log.WriteLine("SKIP \"{0}{1}\"", currentEntriesL.Current, Directory.Exists(Path.Combine(rootL, currentEntriesL.Current)) ? "\\" : String.Empty);
                            }
                        }
                        currentEntriesL.MoveNext();
                        goto Loop;
                    }
                    rootExclusion = false;
                    extensionExclusion = false;
                    if (currentEntriesR.Valid
                        && (((rootExclusion = excludedItems.Contains(currentEntriesR.Current)) || excludedItems.StartsWithAny(currentEntriesR.Current, "\\"))
                        || (!currentEntriesR.CurrentIsDirectory && (extensionExclusion = excludedExtensions.EndsWithAny(currentEntriesR.Current, null)))))
                    {
                        if (log != null)
                        {
                            if (rootExclusion || extensionExclusion)
                            {
                                log.WriteLine("SKIP \"{0}{1}\"", currentEntriesR.Current, Directory.Exists(Path.Combine(rootR, currentEntriesR.Current)) ? "\\" : String.Empty);
                            }
                        }
                        currentEntriesR.MoveNext();
                        goto Loop;
                    }

                    try
                    {
                        int c;
                        if (!currentEntriesR.Valid)
                        {
                            c = -1;
                        }
                        else if (!currentEntriesL.Valid)
                        {
                            c = 1;
                        }
                        else
                        {
                            c = SyncPathCompare(currentEntriesL.Current, currentEntriesR.Current);
                        }

                        string selected = (c <= 0) ? currentEntriesL.Current : currentEntriesR.Current;

                        if (c <= 0 ? Directory.Exists(Path.Combine(rootL, currentEntriesL.Current)) : Directory.Exists(Path.Combine(rootR, currentEntriesR.Current)))
                        {
                            if (log != null)
                            {
                                log.Flush();
                            }
                            WriteStatusLine(selected);
                        }

                        while (previousEntriesL.Valid && (SyncPathCompare(previousEntriesL.Current, selected) < 0))
                        {
                            previousEntriesL.MoveNext();
                        }
                        bool previousLExisted = previousEntriesL.Valid && (SyncPathCompare(previousEntriesL.Current, selected) == 0);
                        while (previousEntriesR.Valid && (SyncPathCompare(previousEntriesR.Current, selected) < 0))
                        {
                            previousEntriesR.MoveNext();
                        }
                        bool previousRExisted = previousEntriesR.Valid && (SyncPathCompare(previousEntriesR.Current, selected) == 0);

                        if (c < 0)
                        {
                            bool changedL = !previousLExisted || ((previousEntriesL.CurrentAttributes & SyncPropagatedAttributes) != (currentEntriesL.CurrentAttributes & SyncPropagatedAttributes)) || (!previousEntriesL.CurrentIsDirectory && (previousEntriesL.CurrentLastWrite != currentEntriesL.CurrentLastWrite));
                            bool changedR = previousRExisted;

                            if (!changedL && previousRExisted && Directory.Exists(Path.Combine(rootL, selected)))
                            {
                                changedL = SyncSubdirChanged(selected, currentEntriesL, previousEntriesL, excludedExtensions, excludedItems);
                            }

                        Conflict100Restart:
                            if (changedL && changedR)
                            {
                                codePath = 100;
                                if (log != null)
                                {
                                    log.WriteLine("CONFLICT '{0}' modified '{2}', deleted '{3}' [codePath={1}]", selected, codePath, rootL, rootR);
                                    log.Flush();
                                }
                                Console.WriteLine();
                                ConsoleWriteLineColor(ConsoleColor.Red, "CONFLICT '{0}' modified '{1}', deleted '{2}'", selected, rootL, rootR);
                                if (!resolveSkip)
                                {
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  L: keep \"{0}\"", Path.Combine(rootL, selected));
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  R: delete \"{0}\"", Path.Combine(rootL, selected));
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  I: ignore");
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  N: ignore all");
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  W: windiff");
                                    while (true)
                                    {
                                        char key = WaitReadKey(true/*intercept*/);
                                        if (key == 'l')
                                        {
                                            ConsoleWriteLineColor(ConsoleColor.Red, "L: keep \"{0}\"", Path.Combine(rootL, selected));
                                            codePath = 121;
                                            if (log != null)
                                            {
                                                log.WriteLine("  USER KEEPS L '{0}' [codePath={1}]", Path.Combine(rootL, selected), codePath);
                                            }
                                            changedL = true;
                                            changedR = false;
                                            goto Conflict100Restart;
                                        }
                                        else if (key == 'r')
                                        {
                                            ConsoleWriteLineColor(ConsoleColor.Red, "R: delete \"{0}\"", Path.Combine(rootL, selected));
                                            codePath = 122;
                                            if (log != null)
                                            {
                                                log.WriteLine("  USER DELETES L '{0}' [codePath={1}]", Path.Combine(rootR, selected), codePath);
                                            }
                                            changedL = false;
                                            changedR = true;
                                            goto Conflict100Restart;
                                        }
                                        else if (key == 'i')
                                        {
                                            break;
                                        }
                                        else if (key == 'n')
                                        {
                                            resolveSkip = true;
                                            break;
                                        }
                                        else if (Char.ToLowerInvariant(key) == 'w')
                                        {
                                            bool flip = key == 'W';
                                            Windiff(Path.Combine(!flip ? rootL : rootR, selected), Path.Combine(!flip ? rootR : rootL, selected), true/*waitForExit*/);
                                        }
                                    }
                                }

                                bool dirL = currentEntriesL.CurrentIsDirectory;
                                currentEntriesL.MoveNext();
                                if (dirL)
                                {
                                    while (currentEntriesL.Valid && currentEntriesL.Current.StartsWith(selected, StringComparison.OrdinalIgnoreCase))
                                    {
                                        currentEntriesL.MoveNext();
                                    }
                                }
                            }
                            else if (changedL)
                            {
                                if (codePath != 121)
                                {
                                    codePath = 101;
                                }
                                if (DoRetryable<bool>(delegate() { SyncChange(rootL, rootR, selected, codePath, log, true/*l2r*/, volumeFlushHelperCollection, faultInstanceIteration); return true; }, delegate() { return false; }, delegate() { }, context, null/*trace*/))
                                {
                                    EnumerateFile.WriteLine(newEntriesLTemporary, currentEntriesL.Current, currentEntriesL.CurrentAttributes, currentEntriesL.CurrentLastWrite);
                                    EnumerateFile.WriteLine(newEntriesRTemporary, currentEntriesL.Current, currentEntriesL.CurrentAttributes, currentEntriesL.CurrentLastWrite);
                                }
                                currentEntriesL.MoveNext();
                            }
                            else if (changedR)
                            {
                                codePath = 102;
                                DoRetryable<bool>(delegate() { SyncChange(rootR, rootL, selected, codePath, log, false/*l2r*/, volumeFlushHelperCollection, faultInstanceIteration); return true; }, delegate() { return false; }, delegate() { }, context, null/*trace*/);
                                currentEntriesL.MoveNext();
                            }
                            else
                            {
                                codePath = 103;
                                throw new ApplicationException("Differing names does not accord with no changes");
                            }
                        }
                        else if (c > 0)
                        {
                            bool changedL = previousLExisted;
                            bool changedR = !previousRExisted || ((previousEntriesR.CurrentAttributes & SyncPropagatedAttributes) != (currentEntriesR.CurrentAttributes & SyncPropagatedAttributes)) || (!previousEntriesR.CurrentIsDirectory && (previousEntriesR.CurrentLastWrite != currentEntriesR.CurrentLastWrite));

                            if (!changedR && previousLExisted && Directory.Exists(Path.Combine(rootR, selected)))
                            {
                                changedR = SyncSubdirChanged(selected, currentEntriesR, previousEntriesR, excludedExtensions, excludedItems);
                            }

                        Conflict200Restart:
                            if (changedL && changedR)
                            {
                                codePath = 200;
                                if (log != null)
                                {
                                    log.WriteLine("CONFLICT '{0}' deleted '{2}', modified '{3}' [codePath={1}]", selected, codePath, rootL, rootR);
                                    log.Flush();
                                }
                                Console.WriteLine();
                                ConsoleWriteLineColor(ConsoleColor.Red, "CONFLICT '{0}' deleted '{1}', modified '{2}'", selected, rootL, rootR);
                                if (!resolveSkip)
                                {
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  L: delete \"{0}\"", Path.Combine(rootR, selected));
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  R: keep \"{0}\"", Path.Combine(rootR, selected));
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  I: ignore");
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  N: ignore all");
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  W: windiff");
                                    while (true)
                                    {
                                        char key = WaitReadKey(true/*intercept*/);
                                        if (key == 'l')
                                        {
                                            ConsoleWriteLineColor(ConsoleColor.Red, "L: delete \"{0}\"", Path.Combine(rootR, selected));
                                            codePath = 221;
                                            if (log != null)
                                            {
                                                log.WriteLine("  USER DELETES R '{0}' [codePath={1}]", Path.Combine(rootR, selected), codePath);
                                            }
                                            changedL = true;
                                            changedR = false;
                                            goto Conflict200Restart;
                                        }
                                        else if (key == 'r')
                                        {
                                            ConsoleWriteLineColor(ConsoleColor.Red, "R: keep \"{0}\"", Path.Combine(rootR, selected));
                                            codePath = 222;
                                            if (log != null)
                                            {
                                                log.WriteLine("  USER KEEPS R '{0}' [codePath={1}]", Path.Combine(rootR, selected), codePath);
                                            }
                                            changedL = false;
                                            changedR = true;
                                            goto Conflict200Restart;
                                        }
                                        else if (key == 'i')
                                        {
                                            break;
                                        }
                                        else if (key == 'n')
                                        {
                                            resolveSkip = true;
                                            break;
                                        }
                                        else if (Char.ToLowerInvariant(key) == 'w')
                                        {
                                            bool flip = key == 'W';
                                            Windiff(Path.Combine(!flip ? rootL : rootR, selected), Path.Combine(!flip ? rootR : rootL, selected), true/*waitForExit*/);
                                        }
                                    }
                                }

                                bool dirR = currentEntriesR.CurrentIsDirectory;
                                currentEntriesR.MoveNext();
                                if (dirR)
                                {
                                    while (currentEntriesR.Valid && currentEntriesR.Current.StartsWith(selected, StringComparison.OrdinalIgnoreCase))
                                    {
                                        currentEntriesR.MoveNext();
                                    }
                                }
                            }
                            else if (changedL)
                            {
                                if (codePath != 221)
                                {
                                    codePath = 201;
                                }
                                DoRetryable<bool>(delegate() { SyncChange(rootL, rootR, selected, codePath, log, true/*l2r*/, volumeFlushHelperCollection, faultInstanceIteration); return true; }, delegate() { return false; }, delegate() { }, context, null/*trace*/);
                                currentEntriesR.MoveNext();
                            }
                            else if (changedR)
                            {
                                if (codePath != 222)
                                {
                                    codePath = 202;
                                }
                                if (DoRetryable<bool>(delegate() { SyncChange(rootR, rootL, selected, codePath, log, false/*l2r*/, volumeFlushHelperCollection, faultInstanceIteration); return true; }, delegate() { return false; }, delegate() { }, context, null/*trace*/))
                                {
                                    EnumerateFile.WriteLine(newEntriesLTemporary, currentEntriesR.Current, currentEntriesR.CurrentAttributes, currentEntriesR.CurrentLastWrite);
                                    EnumerateFile.WriteLine(newEntriesRTemporary, currentEntriesR.Current, currentEntriesR.CurrentAttributes, currentEntriesR.CurrentLastWrite);
                                }
                                currentEntriesR.MoveNext();
                            }
                            else
                            {
                                codePath = 203;
                                throw new ApplicationException("Differing names does not accord with no changes");
                            }
                        }
                        else
                        {
                            bool changedL = !previousLExisted || (!currentEntriesL.CurrentIsDirectory && !String.Equals(Path.GetFileName(previousEntriesL.Current), Path.GetFileName(currentEntriesL.Current))) || ((previousEntriesL.CurrentAttributes & SyncPropagatedAttributes) != (currentEntriesL.CurrentAttributes & SyncPropagatedAttributes)) || (!previousEntriesL.CurrentIsDirectory && (previousEntriesL.CurrentLastWrite != currentEntriesL.CurrentLastWrite));
                            bool changedR = !previousRExisted || (!currentEntriesR.CurrentIsDirectory && !String.Equals(Path.GetFileName(previousEntriesR.Current), Path.GetFileName(currentEntriesR.Current))) || ((previousEntriesR.CurrentAttributes & SyncPropagatedAttributes) != (currentEntriesR.CurrentAttributes & SyncPropagatedAttributes)) || (!previousEntriesR.CurrentIsDirectory && (previousEntriesR.CurrentLastWrite != currentEntriesR.CurrentLastWrite));
                            // Note the file name tests are case-sensitive (unlike most in this function) to detect case-change-only renames

                            bool changedLDirCaseChangeOnly = previousLExisted && currentEntriesL.CurrentIsDirectory && !String.Equals(Path.GetFileName(previousEntriesL.Current), Path.GetFileName(currentEntriesL.Current));
                            if (changedLDirCaseChangeOnly && !String.Equals(Path.GetFileName(previousEntriesL.Current), Path.GetFileName(currentEntriesL.Current), StringComparison.OrdinalIgnoreCase))
                            {
                                Debug.Assert(false);
                                throw new InvalidOperationException();
                            }
                            bool changedRDirCaseChangeOnly = previousRExisted && currentEntriesR.CurrentIsDirectory && !String.Equals(Path.GetFileName(previousEntriesR.Current), Path.GetFileName(currentEntriesR.Current));
                            if (changedRDirCaseChangeOnly && !String.Equals(Path.GetFileName(previousEntriesR.Current), Path.GetFileName(currentEntriesR.Current), StringComparison.OrdinalIgnoreCase))
                            {
                                Debug.Assert(false);
                                throw new InvalidOperationException();
                            }

                            if (!changedL && previousRExisted && Directory.Exists(Path.Combine(rootL, selected)) && File.Exists(Path.Combine(rootR, selected)))
                            {
                                changedL = SyncSubdirChanged(selected, currentEntriesL, previousEntriesL, excludedExtensions, excludedItems);
                            }
                            if (!changedR && previousLExisted && Directory.Exists(Path.Combine(rootR, selected)) && File.Exists(Path.Combine(rootL, selected)))
                            {
                                changedR = SyncSubdirChanged(selected, currentEntriesR, previousEntriesR, excludedExtensions, excludedItems);
                            }

                        Conflict300Restart:
                            if (changedL && changedR)
                            {
                                codePath = 300;
                                if (log != null)
                                {
                                    const string TimeStampFormat = "s";
                                    log.WriteLine("CONFLICT '{0}' L:{1},{2} R:{3},{4} [codePath={5}]", selected, (int)currentEntriesL.CurrentAttributes, !currentEntriesL.CurrentIsDirectory ? currentEntriesL.CurrentLastWrite.ToString(TimeStampFormat) : "0", (int)currentEntriesR.CurrentAttributes, !currentEntriesR.CurrentIsDirectory ? currentEntriesR.CurrentLastWrite.ToString(TimeStampFormat) : "0", codePath);
                                    log.Flush();
                                }
                                bool? same = null;
                                try
                                {
                                    same = CompareFile(Path.Combine(rootL, currentEntriesL.Current), Path.Combine(rootR, currentEntriesR.Current), new Context());
                                }
                                catch (Exception)
                                {
                                }
                                Console.WriteLine();
                                ConsoleWriteLineColor(ConsoleColor.Red, "CONFLICT '{0}' modified both, {1}", selected, same.HasValue ? (same.Value ? "identical" : "different") : "unreadable");
                                if (!resolveSkip)
                                {
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  L: keep \"{0}\"{1}", Path.Combine(rootL, currentEntriesL.Current), currentEntriesL.CurrentLastWrite > currentEntriesR.CurrentLastWrite ? " [more recent]" : String.Empty);
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  R: keep \"{0}\"{1}", Path.Combine(rootR, currentEntriesR.Current), currentEntriesL.CurrentLastWrite < currentEntriesR.CurrentLastWrite ? " [more recent]" : String.Empty);
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  I: ignore");
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  N: ignore all");
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  W: windiff (Shift-W to reverse)");
                                    while (true)
                                    {
                                        char key = WaitReadKey(true/*intercept*/);
                                        if (key == 'l')
                                        {
                                            ConsoleWriteLineColor(ConsoleColor.Red, "L: keep \"{0}\"", Path.Combine(rootL, currentEntriesL.Current));
                                            codePath = 321;
                                            if (log != null)
                                            {
                                                log.WriteLine("  USER KEEPS L '{0}' [codePath={1}]", Path.Combine(rootL, currentEntriesL.Current), codePath);
                                            }
                                            changedL = true;
                                            changedR = false;
                                            goto Conflict300Restart;
                                        }
                                        else if (key == 'r')
                                        {
                                            ConsoleWriteLineColor(ConsoleColor.Red, "R: keep \"{0}\"", Path.Combine(rootR, currentEntriesR.Current));
                                            codePath = 322;
                                            if (log != null)
                                            {
                                                log.WriteLine("  USER KEEPS R '{0}' [codePath={1}]", Path.Combine(rootR, currentEntriesR.Current), codePath);
                                            }
                                            changedL = false;
                                            changedR = true;
                                            goto Conflict300Restart;
                                        }
                                        else if (key == 'i')
                                        {
                                            break;
                                        }
                                        else if (key == 'n')
                                        {
                                            resolveSkip = true;
                                            break;
                                        }
                                        else if (Char.ToLowerInvariant(key) == 'w')
                                        {
                                            bool flip = key == 'W';
                                            Windiff(Path.Combine(!flip ? rootL : rootR, selected), Path.Combine(!flip ? rootR : rootL, selected), true/*waitForExit*/);
                                        }
                                    }
                                }

                                bool dirL = currentEntriesL.CurrentIsDirectory;
                                currentEntriesL.MoveNext();
                                if (dirL)
                                {
                                    while (currentEntriesL.Valid && currentEntriesL.Current.StartsWith(selected, StringComparison.OrdinalIgnoreCase))
                                    {
                                        currentEntriesL.MoveNext();
                                    }
                                }

                                bool dirR = currentEntriesR.CurrentIsDirectory;
                                currentEntriesR.MoveNext();
                                if (dirR)
                                {
                                    while (currentEntriesR.Valid && currentEntriesR.Current.StartsWith(selected, StringComparison.OrdinalIgnoreCase))
                                    {
                                        currentEntriesR.MoveNext();
                                    }
                                }
                            }
                            else if (changedL)
                            {
                                if (codePath != 321)
                                {
                                    codePath = 301;
                                }
                                bool dirR = currentEntriesR.CurrentIsDirectory;
                                if (DoRetryable<bool>(delegate() { SyncChange(rootL, rootR, currentEntriesL.Current, codePath, log, true/*l2r*/, volumeFlushHelperCollection, faultInstanceIteration); return true; }, delegate() { return false; }, delegate() { }, context, null/*trace*/))
                                {
                                    EnumerateFile.WriteLine(newEntriesLTemporary, currentEntriesL.Current, currentEntriesL.CurrentAttributes, currentEntriesL.CurrentLastWrite);
                                    EnumerateFile.WriteLine(newEntriesRTemporary, currentEntriesL.Current, currentEntriesL.CurrentAttributes, currentEntriesL.CurrentLastWrite);
                                }
                                currentEntriesL.MoveNext();
                                currentEntriesR.MoveNext();
                                if (dirR)
                                {
                                    while (currentEntriesR.Valid && currentEntriesR.Current.StartsWith(selected, StringComparison.OrdinalIgnoreCase))
                                    {
                                        currentEntriesR.MoveNext();
                                    }
                                }
                            }
                            else if (changedR)
                            {
                                if (codePath != 322)
                                {
                                    codePath = 302;
                                }
                                bool dirL = currentEntriesL.CurrentIsDirectory;
                                if (DoRetryable<bool>(delegate() { SyncChange(rootR, rootL, currentEntriesR.Current, codePath, log, false/*l2r*/, volumeFlushHelperCollection, faultInstanceIteration); return true; }, delegate() { return false; }, delegate() { }, context, null/*trace*/))
                                {
                                    EnumerateFile.WriteLine(newEntriesLTemporary, currentEntriesR.Current, currentEntriesR.CurrentAttributes, currentEntriesR.CurrentLastWrite);
                                    EnumerateFile.WriteLine(newEntriesRTemporary, currentEntriesR.Current, currentEntriesR.CurrentAttributes, currentEntriesR.CurrentLastWrite);
                                }
                                currentEntriesL.MoveNext();
                                if (dirL)
                                {
                                    while (currentEntriesL.Valid && currentEntriesL.Current.StartsWith(selected, StringComparison.OrdinalIgnoreCase))
                                    {
                                        currentEntriesL.MoveNext();
                                    }
                                }
                                currentEntriesR.MoveNext();
                            }
                            else
                            {
                                codePath = 303;

                                string currentEntriesL_Current = currentEntriesL.Current;
                                string currentEntriesR_Current = currentEntriesR.Current;

#if false
                                if (changedLDirCaseChangeOnly && changedRDirCaseChangeOnly)
                                {
                                    // do nothing - TODO: merge conflict prompt to select which name to use
                                    throw new NotImplementedException();
                                }
                                else
#endif
                                if (changedLDirCaseChangeOnly && !changedRDirCaseChangeOnly)
                                {
                                    bool dirR = currentEntriesR.CurrentIsDirectory;
                                    if (DoRetryable<bool>(delegate() { SyncChangeDirectoryCaseChangeOnly(rootL, rootR, currentEntriesL.Current, codePath, log, true/*l2r*/, volumeFlushHelperCollection, faultInstanceIteration); return true; }, delegate() { return false; }, delegate() { }, context, null/*trace*/))
                                    {
                                        currentEntriesR_Current = currentEntriesL_Current;
                                    }

                                }
                                else if (changedRDirCaseChangeOnly && !changedLDirCaseChangeOnly)
                                {
                                    bool dirL = currentEntriesL.CurrentIsDirectory;
                                    if (DoRetryable<bool>(delegate() { SyncChangeDirectoryCaseChangeOnly(rootR, rootL, currentEntriesR.Current, codePath, log, false/*l2r*/, volumeFlushHelperCollection, faultInstanceIteration); return true; }, delegate() { return false; }, delegate() { }, context, null/*trace*/))
                                    {
                                        currentEntriesL_Current = currentEntriesR_Current;
                                    }
                                }

                                EnumerateFile.WriteLine(newEntriesLTemporary, currentEntriesL_Current, currentEntriesL.CurrentAttributes, currentEntriesL.CurrentLastWrite);
                                EnumerateFile.WriteLine(newEntriesRTemporary, currentEntriesR_Current, currentEntriesR.CurrentAttributes, currentEntriesR.CurrentLastWrite);
                                currentEntriesL.MoveNext();
                                currentEntriesR.MoveNext();
                            }
                        }
                    }
                    catch (Exception exception)
                    {
                        if (log != null)
                        {
                            log.WriteLine("EXCEPTION: {0} [codePath={1}]", exception.Message, codePath);
                        }
                        throw;
                    }
                }

                EraseStatusLine();
                Console.WriteLine();
            }
            finally
            {
                volumeFlushHelperCollection.Flush();

                newEntriesLPermanent.Write(newEntriesLTemporary);
                newEntriesRPermanent.Write(newEntriesRTemporary);

                previousEntriesL.Close();
                currentEntriesL.Close();
                newEntriesLPermanent.Close();

                previousEntriesR.Close();
                currentEntriesR.Close();
                newEntriesRPermanent.Close();

                volumeFlushHelperCollection.MarkDirty(volumeFlushHelperRepository);
                volumeFlushHelperCollection.Flush();

                if (log != null)
                {
                    log.WriteLine();
                    log.WriteLine("Finished");

                    log.Close();
                    log = null;
                }

                volumeFlushHelperCollection.Dispose();
            }


            DateTime localCreated = context.now;
            if (File.Exists(manifestLocalSaved))
            {
                localCreated = File.GetCreationTime(manifestLocalSaved);
                try
                {
                    DateTime created = File.GetCreationTime(manifestLocalSaved);
                    File.Copy(manifestLocalSaved, manifestLocalSavedBackup, true/*overwrite*/);
                    File.SetCreationTime(manifestLocalSavedBackup, created);
                }
                catch (Exception)
                {
                }
                File.Delete(manifestLocalSaved);
            }
            DateTime remoteCreated = context.now;
            if (File.Exists(manifestRemoteSaved))
            {
                remoteCreated = File.GetCreationTime(manifestRemoteSaved);
                try
                {
                    DateTime created = File.GetCreationTime(manifestRemoteSaved);
                    File.Copy(manifestRemoteSaved, manifestRemoteSavedBackup, true/*overwrite*/);
                    File.SetCreationTime(manifestRemoteSavedBackup, created);
                }
                catch (Exception)
                {
                }
                File.Delete(manifestRemoteSaved);
            }
            File.Move(manifestLocalNew, manifestLocalSaved);
            File.SetCreationTime(manifestLocalSaved, localCreated);
            File.SetLastWriteTime(manifestLocalSaved, context.now);
            File.Move(manifestRemoteNew, manifestRemoteSaved);
            File.SetCreationTime(manifestRemoteSaved, remoteCreated);
            File.SetLastWriteTime(manifestRemoteSaved, context.now);
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Backup
        //
        ////////////////////////////////////////////////////////////////////////////

        private static void CreateZeroLengthFile(string path, Context context)
        {
            DoRetryable<int>(
                delegate
                {
                    using (Stream placeholder = File.Create(path))
                    {
                    }
                    return 0;
                },
                delegate { return 0; },
                delegate
                {
                    try
                    {
                        File.Delete(path);
                    }
                    catch (Exception)
                    {
                    }
                },
                context,
                null/*trace*/);
        }

        private static void DeleteFile(string path, Context context)
        {
            DoRetryable<int>(
                delegate
                {
                    File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
                    File.Delete(path);
                    return 0;
                },
                delegate { return 0; },
                null,
                context,
                null/*trace*/);
        }

        private static void MoveFile(string sourcePath, string targetPath, Context context)
        {
            DoRetryable<int>(
                delegate
                {
                    DateTime created = File.GetCreationTime(sourcePath);
                    DateTime lastWritten = File.GetLastWriteTime(sourcePath);
                    File.Move(sourcePath, targetPath);
                    File.SetCreationTime(targetPath, created);
                    File.SetLastWriteTime(targetPath, lastWritten);
                    return 0;
                },
                delegate { return 0; },
                null,
                context,
                null/*trace*/);
        }

        private static string FormatArchivePointName(DateTime timestamp)
        {
            return timestamp.ToString("s").Replace(':', '+');
        }

        private static DateTime ParseArchivePointName(string name)
        {
            DateTime timestamp;
            if (!DateTime.TryParse(name.Replace('+', ':'), out timestamp))
            {
                throw new ApplicationException(String.Format("Invalid archive point '{0}'", name));
            }
            return timestamp;
        }

        private static readonly byte[] EncryptionCheckBytes = new byte[16] { 0xA6, 0x87, 0xDF, 0xB6, 0x75, 0x64, 0xDE, 0x14, 0x8D, 0x2C, 0x0C, 0x24, 0xA6, 0x16, 0x22, 0x2F };
        private const int EncryptionCheckSaltLength = 8;
        private static void EnsureCheck(string archiveFolder, bool firstRun, Context context, DateTime now)
        {
            bool checkExists = false;
            bool checkC = false;
            foreach (string file in Directory.GetFileSystemEntries(archiveFolder))
            {
                string name = Path.GetFileName(file);
                if (name == "check.bin")
                {
                    checkExists = true;
                }
                else if (name == "checkc.bin")
                {
                    checkExists = true;
                    checkC = true;
                }
                else if (name == "nocheckc.bin")
                {
                    checkC = true;
                }
            }

            if (!firstRun)
            {
                if (checkC != (context.compressionOption == CompressionOption.Compress))
                {
                    throw new ApplicationException("Previous backups have compression setting incompatible with current setting");
                }

                if (context.cryptoOption != EncryptionOption.None)
                {
                    CryptoContext cryptoContext;
                    if (context.cryptoOption == EncryptionOption.Encrypt)
                    {
                        cryptoContext = context.encrypt;
                    }
                    else if (context.cryptoOption == EncryptionOption.Decrypt)
                    {
                        cryptoContext = context.decrypt;
                    }
                    else
                    {
                        throw new InvalidOperationException();
                    }

                    if (!checkExists)
                    {
                        throw new ApplicationException("Previous backups prevent encryption from being allowed");
                    }
                    else
                    {
                        try
                        {
                            using (FileStream fileStream = File.Open(Path.Combine(archiveFolder, (context.compressionOption == CompressionOption.Compress) ? "checkc.bin" : "check.bin"), FileMode.Open))
                            {
                                EncryptedFileContainerHeader fch = new EncryptedFileContainerHeader(fileStream, true/*peek*/, cryptoContext);
                                CryptoKeygroup keys;
                                cryptoContext.algorithm.DeriveSessionKeys(cryptoContext.GetMasterKeyEntry(fch.passwordSalt, fch.rfc2898Rounds).MasterKey, fch.fileSalt, out keys);

                                StreamStack.DoWithStreamStack(
                                    fileStream,
                                    new StreamStack.StreamWrapMethod[]
                                    {
                                        delegate(Stream stream)
                                        {
                                            // see note and references about
                                            // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                            return new TaggedReadStream(stream, cryptoContext.algorithm.CreateMACGenerator(keys.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                        },
                                        delegate(Stream stream)
                                        {
                                            // why re-read here? need to read salt within HMAC container
                                            EncryptedFileContainerHeader fch2 = new EncryptedFileContainerHeader(stream, false/*peek*/, cryptoContext);
                                            if (!fch2.Equals(fch))
                                            {
                                                throw new InvalidOperationException();
                                            }
                                            return null;
                                        },
                                        delegate(Stream stream)
                                        {
                                            return context.encrypt.algorithm.CreateDecryptStream(stream, keys.CipherKey, keys.InitialCounter);
                                        },
                                    },
                                    delegate(Stream stream)
                                    {
                                        BinaryReadUtils.ReadBytes(stream, EncryptionCheckSaltLength); // check string's salt
                                        byte[] checkBytes = BinaryReadUtils.ReadBytes(stream, EncryptionCheckBytes.Length);

                                        if (!ArrayEqual(EncryptionCheckBytes, checkBytes))
                                        {
                                            throw new ApplicationException("Encryption key does not match key from previous run");
                                        }
                                    });
                            }
                        }
                        catch (ExitCodeException)
                        {
                            throw new ApplicationException("Encryption key does not match key from previous run");
                        }
                    }
                }
                else
                {
                    if (checkExists)
                    {
                        throw new ApplicationException("Previous backups require encryption to be specified");
                    }
                }
            }
            else
            {
                if (checkExists)
                {
                    throw new ApplicationException("Check shouldn't exist on first run!");
                }
                if (context.cryptoOption != EncryptionOption.None)
                {
                    if (context.cryptoOption != EncryptionOption.Encrypt)
                    {
                        throw new InvalidOperationException(); // firstRun can't ever be an extract/restore operation
                    }

                    CryptoMasterKeyCacheEntry entry = context.encrypt.GetDefaultMasterKeyEntry();
                    EncryptedFileContainerHeader fch = new EncryptedFileContainerHeader(context.encrypt);
                    fch.passwordSalt = entry.PasswordSalt;
                    CryptoKeygroup keys;
                    context.encrypt.algorithm.DeriveNewSessionKeys(entry.MasterKey, out fch.fileSalt, out keys);

                    string checkFilePath = Path.Combine(archiveFolder, (context.compressionOption == CompressionOption.Compress) ? "checkc.bin" : "check.bin");
                    using (FileStream fileStream = File.Open(checkFilePath, FileMode.Create))
                    {
                        StreamStack.DoWithStreamStack(
                            fileStream,
                            new StreamStack.StreamWrapMethod[]
                            {
                                delegate(Stream stream)
                                {
                                    // see note and references about
                                    // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                    return new TaggedWriteStream(stream, context.encrypt.algorithm.CreateMACGenerator(keys.SigningKey));
                                },
                                delegate(Stream stream)
                                {
                                    // why write here? need to write salt within HMAC container
                                    fch.Write(stream, context.encrypt.algorithm);
                                    return null;
                                },
                                delegate(Stream stream)
                                {
                                    return context.encrypt.algorithm.CreateEncryptStream(stream, keys.CipherKey, keys.InitialCounter);
                                },
                            },
                            delegate(Stream stream)
                            {
                                BinaryWriteUtils.WriteBytes(stream, context.encrypt.algorithm.CreateRandomBytes(EncryptionCheckSaltLength)); // yet more salt before check string
                                BinaryWriteUtils.WriteBytes(stream, EncryptionCheckBytes);
                            });
                    }
                    File.SetCreationTime(checkFilePath, now);
                    File.SetLastWriteTime(checkFilePath, now);
                }
                else
                {
                    if (context.compressionOption == CompressionOption.Compress)
                    {
                        string checkFilePath = Path.Combine(archiveFolder, "nocheckc.bin");
                        using (FileStream file = File.Open(checkFilePath, FileMode.Create))
                        {
                        }
                        File.SetCreationTime(checkFilePath, now);
                        File.SetLastWriteTime(checkFilePath, now);
                    }
                }
            }
        }

#if false // EXPERIMENTAL: iterative implementation of Backup() [unmaintained]
        private class EnumerateHierarchyN
        {
            private IEnumerateHierarchy[] ehs;
            private int[] earliestSet;
            private bool[] finished;

            internal EnumerateHierarchyN(string[] roots)
            {
                ehs = new EnumerateHierarchy[roots.Length];
                earliestSet = new int[roots.Length];
                finished = new bool[roots.Length];
                for (int i = 0; i < roots.Length; i++)
                {
                    ehs[i] = new EnumerateHierarchy(roots[i]);
                    earliestSet[i] = i;
                }
            }

            private static int[] SelectEarliest(IEnumerateHierarchy[] ehs)
            {
                int[] earliestSet = new int[0];
                int first = -1;
                for (int i = 0; i < ehs.Length; i++)
                {
                    if (ehs[i].Valid)
                    {
                        if (first == -1)
                        {
                            first = i;
                            Array.Resize(ref earliestSet, earliestSet.Length + 1);
                            earliestSet[earliestSet.Length - 1] = i;
                        }
                        else
                        {
                            string[] firstParts = ehs[first].Current.Split(new char[] { '\\' });
                            string[] iParts = ehs[i].Current.Split(new char[] { '\\' });

                            // compare algorithm:
                            // root dir of given name comes first, then contained items inside that dir, and last a file of that name
                            int c = 0;
                            int commonPrefix = Math.Min(firstParts.Length, iParts.Length);
                            for (int j = 0; j < commonPrefix; j++)
                            {
                                c = String.Compare(firstParts[j], iParts[j], StringComparison.OrdinalIgnoreCase);
                                if (c != 0)
                                {
                                    break;
                                }
                            }
                            if (c == 0)
                            {
                                c = firstParts.Length - iParts.Length;
                            }

                            if (c == 0)
                            {
                                Array.Resize(ref earliestSet, earliestSet.Length + 1);
                                earliestSet[earliestSet.Length - 1] = i;
                            }
                            else if (c > 0)
                            {
                                first = i;
                                earliestSet = new int[1];
                                earliestSet[0] = i;
                            }
                        }
                    }
                }
                return earliestSet;
            }

            public int[] EarliestSet()
            {
                return (int[])earliestSet.Clone();
            }

            public bool Valid
            {
                get
                {
                    return earliestSet.Length > 0;
                }
            }

            public bool MoveNext()
            {
                if (earliestSet.Length == 0)
                {
                    throw new InvalidOperationException();
                }

                bool result = false;
                foreach (int i in earliestSet)
                {
                    bool result1 = !finished[i] && ehs[i].MoveNext();
                    finished[i] = !result1;
                    result = result || result1;
                }
                earliestSet = SelectEarliest(ehs);
                return result;
            }

            public string Current
            {
                get
                {
                    if (earliestSet.Length == 0)
                    {
                        throw new InvalidOperationException();
                    }

                    return ehs[earliestSet[0]].Current;
                }
            }

            public string GetCurrent(int index)
            {
                if (Array.IndexOf(earliestSet, index) < 0)
                {
                    throw new InvalidOperationException();
                }
                return ehs[index].Current;
            }

            public void Close()
            {
                ehs = null;
                earliestSet = null;
                finished = null;
            }
        }

        private static void BackupProcess(string source, string previous, string current, Context context, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems, TextWriter log)
        {
            string lastStatus = String.Empty;

            const int SourceIndex = 0, CurrentIndex = 1, PreviousIndex = 2;
            EnumerateHierarchyN eh = new EnumerateHierarchyN(new string[] { source, current, previous });
            string deepRollbackRoot = null;
            bool deferredCopy = false;
            while (deferredCopy || (eh.Valid && eh.MoveNext() ? true : (deepRollbackRoot != null))) // awkward logic around eh.MoveNext() and deepRollbackRoot is because eh.MoveNext() terminates one step too early when the last item was a directory undergoing deep rollback - one more cycle needed to finialize rollback and apply any deferred copy
            {
                deferredCopy = false;

                string sourcePath = null, currentPath = null, previousPath = null;
                int[] earliestSet = null;

                if (eh.Valid)
                {
                    earliestSet = eh.EarliestSet();
                    sourcePath = Path.Combine(source, Array.IndexOf(earliestSet, SourceIndex) >= 0 ? eh.GetCurrent(SourceIndex) : eh.Current);
                    currentPath = Path.Combine(current, Array.IndexOf(earliestSet, CurrentIndex) >= 0 ? eh.GetCurrent(CurrentIndex) : eh.Current);
                    previousPath = Path.Combine(previous, Array.IndexOf(earliestSet, PreviousIndex) >= 0 ? eh.GetCurrent(PreviousIndex) : eh.Current);

                    if (Directory.Exists(sourcePath) && (lastStatus != eh.Current))
                    {
                        lastStatus = eh.Current;
                        WriteStatusLine(lastStatus);
                    }
                }

                if ((deepRollbackRoot != null) && (!eh.Valid || !eh.Current.StartsWith(deepRollbackRoot, StringComparison.OrdinalIgnoreCase)))
                {
                    sourcePath = Path.Combine(source, deepRollbackRoot);
                    currentPath = Path.Combine(current, deepRollbackRoot);
                    previousPath = Path.Combine(previous, deepRollbackRoot);
                    deepRollbackRoot = null;
                    deferredCopy = true;

                    Directory.Delete(currentPath, true/*recursive*/); // will fail if read-only attributes in archive becomes supported
                }

                // roll back anything found already in checkpoint
                if (!deferredCopy)
                {
                    if (deepRollbackRoot == null)
                    {
                        if (Directory.Exists(currentPath) && File.Exists(sourcePath))
                        {
                            deepRollbackRoot = eh.Current;
                        }
                    }

                    if (File.Exists(previousPath))
                    {
                        if (GetFileLengthRetriable(previousPath, context) == 0)
                        {
                            // previous item was carried to current during prior incompleted pass - move it back.
                            if (File.Exists(currentPath))
                            {
                                DeleteFile(previousPath, context);
                                MoveFile(currentPath, previousPath, context);
                            }
                        }
                    }
                    if (File.Exists(currentPath))
                    {
                        DeleteFile(currentPath, context);
                    }
                }

                // create checkpoint of source
                if (deepRollbackRoot == null)
                {
                    bool excluded = false;
                    {
                        bool driveRoot = Directory.Exists(sourcePath) && IsDriveRoot(sourcePath);
                        if (driveRoot && IsExcludedDriveRootItem(sourcePath))
                        {
                            excluded = true;
                        }
                        else
                        {
                            if (excludedItems.Count > 0)
                            {
                                string[] parts = sourcePath.ToLowerInvariant().Split(new char[] { '\\' });
                                StringBuilder sb = new StringBuilder(sourcePath.Length);
                                for (int i = parts.Length - 1; i >= 0; i--)
                                {
                                    sb.Length = 0;
                                    for (int j = 0; j <= i; j++)
                                    {
                                        if (j > 0)
                                        {
                                            sb.Append('\\');
                                        }
                                        sb.Append(parts[j]);
                                    }
                                    if (excludedItems.Contains(sb.ToString()))
                                    {
                                        excluded = true;
                                        EraseStatusLine();
                                        Console.WriteLine(String.Format("  SKIPPED SUBDIRECTORY: {0}", sourcePath));
                                    }
                                }
                            }

                            if (!excluded && File.Exists(sourcePath) && excludedExtensions.Contains(Path.GetExtension(sourcePath).ToLowerInvariant()))
                            {
                                excluded = true;
                                EraseStatusLine();
                                Console.WriteLine(String.Format("  SKIPPED FILE: {0}", sourcePath));
                            }
                        }
                    }

                    if (!excluded)
                    {
                        // filename case handling: make current take on case of source
                        // (but enumerator no longer valid if deferredCopy is set - decided to be acceptable to miss any filename case change in this case)
                        if (!deferredCopy && (File.Exists(sourcePath) || Directory.Exists(sourcePath)))
                        {
                            currentPath = Path.Combine(current, Array.IndexOf(earliestSet, SourceIndex) >= 0 ? eh.GetCurrent(SourceIndex) : eh.Current);
                        }

                        if (Directory.Exists(sourcePath))
                        {
                            Directory.CreateDirectory(currentPath);
                            if (log != null)
                            {
                                log.WriteLine("added {0}\\", sourcePath);
                            }
                        }
                        else if (File.Exists(sourcePath))
                        {
                            if (File.Exists(previousPath))
                            {
                                bool unchanged = true;

                                DateTime sourceItemCreationTime = DoRetryable<DateTime>(delegate { return File.GetCreationTime(sourcePath); }, delegate { return DateTime.MaxValue; }, null, context);
                                DateTime previousItemCreationTime = DoRetryable<DateTime>(delegate { return File.GetCreationTime(previousPath); }, delegate { return DateTime.MinValue; }, null, context);
                                unchanged = unchanged && (sourceItemCreationTime == previousItemCreationTime);
                                DateTime sourceItemLastWriteTime = DoRetryable<DateTime>(delegate { return File.GetLastWriteTime(sourcePath); }, delegate { return DateTime.MaxValue; }, null, context);
                                DateTime previousItemLastWriteTime = DoRetryable<DateTime>(delegate { return File.GetLastWriteTime(previousPath); }, delegate { return DateTime.MinValue; }, null, context);
                                unchanged = unchanged && (sourceItemLastWriteTime == previousItemLastWriteTime);

                                if (unchanged)
                                {
                                    MoveFile(previousPath, currentPath, context);
                                    CreateZeroLengthFile(previousPath, context);

                                    try
                                    {
                                        File.SetCreationTime(previousPath, File.GetCreationTime(currentPath));
                                        File.SetLastWriteTime(previousPath, File.GetLastWriteTime(currentPath));
                                    }
                                    catch (Exception)
                                    {
                                    }
                                }
                                else
                                {
                                    if (log != null)
                                    {
                                        log.WriteLine("modified {0}", sourcePath);
                                    }
                                    CopyFile(sourcePath, currentPath, context);
                                }
                            }
                            else
                            {
                                if (log != null)
                                {
                                    log.WriteLine("added {0}", sourcePath);
                                }
                                CopyFile(sourcePath, currentPath, context);
                            }
                        }
                        else
                        {
                            bool wasDir = false;
                            if (File.Exists(previousPath) || (wasDir = Directory.Exists(previousPath)))
                            {
                                if (log != null)
                                {
                                    log.WriteLine("removed {1}{0}", previousPath, wasDir ? "/s " : String.Empty);
                                }
                            }
                        }
                    }
                }

                deferredCopy = deferredCopy && eh.Valid; // no deferred next pass needed if at end
            }

            EraseStatusLine();
        }
#else // TESTED: recursive implementation of Backup()
        private class TriEntry
        {
            internal string source;
            internal string current;
            internal string previous;
        }

        delegate int MergeCompare<T>(T left, T right);
        private static T[] MergeSorted<T>(IList<T> a, IList<T> b, MergeCompare<T> compare)
        {
            T[] c = new T[a.Count + b.Count];
            int ia = 0;
            int ib = 0;
            int ic = 0;
            while ((ia < a.Count) || (ib < b.Count))
            {
                if ((ia < a.Count) && (ib < b.Count))
                {
                    if (compare(a[ia], b[ib]) <= 0)
                    {
                        c[ic++] = a[ia++];
                    }
                    else
                    {
                        c[ic++] = b[ib++];
                    }
                }
                else if (ia < a.Count)
                {
                    c[ic++] = a[ia++];
                }
                else if (ib < b.Count)
                {
                    c[ic++] = b[ib++];
                }
                else
                {
                    throw new InvalidDataException();
                }
            }
            return c;
        }

        private static int CompareEntries(KeyValuePair<string, int> l, KeyValuePair<string, int> r)
        {
            int c = String.Compare(l.Key, r.Key, StringComparison.OrdinalIgnoreCase);
            if (c == 0)
            {
                c = l.Value.CompareTo(r.Value);
            }
            return c;
        }

        private static class NTFSFileCompressionHelper
        {
            [Flags]
            private enum EFileAttributes : uint
            {
                Readonly = 0x00000001,
                Hidden = 0x00000002,
                System = 0x00000004,
                Directory = 0x00000010,
                Archive = 0x00000020,
                Device = 0x00000040,
                Normal = 0x00000080,
                Temporary = 0x00000100,
                SparseFile = 0x00000200,
                ReparsePoint = 0x00000400,
                Compressed = 0x00000800,
                Offline = 0x00001000,
                NotContentIndexed = 0x00002000,
                Encrypted = 0x00004000,
                Write_Through = 0x80000000,
                Overlapped = 0x40000000,
                NoBuffering = 0x20000000,
                RandomAccess = 0x10000000,
                SequentialScan = 0x08000000,
                DeleteOnClose = 0x04000000,
                BackupSemantics = 0x02000000,
                PosixSemantics = 0x01000000,
                OpenReparsePoint = 0x00200000,
                OpenNoRecall = 0x00100000,
                FirstPipeInstance = 0x00080000
            }
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern IntPtr CreateFile(
                 [MarshalAs(UnmanagedType.LPTStr)] string filename,
                 [MarshalAs(UnmanagedType.U4)] FileAccess access,
                 [MarshalAs(UnmanagedType.U4)] FileShare share,
                 IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
                 [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
                 [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
                 IntPtr templateFile);

            [DllImport("Kernel32.dll", SetLastError = true)]
            public static extern bool DeviceIoControl(
                SafeFileHandle hDevice,
                [MarshalAs(UnmanagedType.U4)] int IoControlCode,
                byte[] InBuffer,
                [MarshalAs(UnmanagedType.U4)] int nInBufferSize,
                byte[] OutBuffer,
                [MarshalAs(UnmanagedType.U4)] int nOutBufferSize,
                [MarshalAs(UnmanagedType.U4)] out int pBytesReturned,
                IntPtr Overlapped);
            private const int FSCTL_SET_COMPRESSION = 0x0009C040;
            private const short COMPRESSION_FORMAT_DEFAULT = 1;
            private const short COMPRESSION_FORMAT_NONE = 0;

            public static bool IsCompressed(string path)
            {
                if (File.Exists(path))
                {
                    return (File.GetAttributes(path) & FileAttributes.Compressed) != 0;
                }
                else if (Directory.Exists(path))
                {
                    return (File.GetAttributes(path) & FileAttributes.Compressed) != 0;
                }
                else
                {
                    throw new FileNotFoundException("File not found", path);
                }
            }

            public static void SetCompressed(string path, bool compress)
            {
                bool directory;
                if (File.Exists(path))
                {
                    directory = false;
                }
                else if (Directory.Exists(path))
                {
                    directory = true;
                }
                else
                {
                    throw new FileNotFoundException("File or directory not found", path);
                }

                using (SafeFileHandle file = new SafeFileHandle(CreateFile(path, FileAccess.ReadWrite, FileShare.ReadWrite, IntPtr.Zero, FileMode.Open, directory ? (FileAttributes)EFileAttributes.BackupSemantics : (FileAttributes)0, IntPtr.Zero), true/*ownsHandle*/))
                {
                    if (file.IsInvalid)
                    {
                        Marshal.ThrowExceptionForHR(Marshal.GetLastWin32Error());
                    }
                    int lpBytesReturned = 0;
                    byte[] lpInBuffer = new byte[2];
                    lpInBuffer[0] = (byte)(compress ? COMPRESSION_FORMAT_DEFAULT : COMPRESSION_FORMAT_NONE);
                    if (!DeviceIoControl(file, FSCTL_SET_COMPRESSION, lpInBuffer, sizeof(short), null, 0, out lpBytesReturned, IntPtr.Zero))
                    {
                        Marshal.ThrowExceptionForHR(Marshal.GetLastWin32Error());
                    }
                }
            }
        }

        internal static void BackupRecursive(string source, string previous, string current, Context context, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems, TextWriter log, bool deepRollback)
        {
            Debug.Assert(Directory.Exists(source) == !deepRollback);

            WriteStatusLine(source);

            bool driveRoot = IsDriveRoot(source);

            List<TriEntry> combined = new List<TriEntry>();
            {
                const int SourceIndex = 0, CurrentIndex = 1, PreviousIndex = 2;

                List<KeyValuePair<string, int>> aggregateCurrent = new List<KeyValuePair<string, int>>();
                if (Directory.Exists(current))
                {
                    foreach (string currentPath in Directory.GetFileSystemEntries(current))
                    {
                        aggregateCurrent.Add(new KeyValuePair<string, int>(Path.GetFileName(currentPath), CurrentIndex));
                    }
                }
                List<KeyValuePair<string, int>> aggregatePrevious = new List<KeyValuePair<string, int>>();
                if (Directory.Exists(previous))
                {
                    foreach (string previousPath in Directory.GetFileSystemEntries(previous))
                    {
                        aggregatePrevious.Add(new KeyValuePair<string, int>(Path.GetFileName(previousPath), PreviousIndex));
                    }
                }
                List<KeyValuePair<string, int>> aggregateSource = new List<KeyValuePair<string, int>>();
                if (!deepRollback && Directory.Exists(source))
                {
                    foreach (string sourcePath in Directory.GetFileSystemEntries(source))
                    {
                        bool excluded = false;
                        {
                            if (driveRoot && IsExcludedDriveRootItem(sourcePath))
                            {
                                excluded = true;
                            }
                            else
                            {
                                if (excludedItems.Count > 0)
                                {
                                    if (excludedItems.Contains(sourcePath.ToLowerInvariant()))
                                    {
                                        excluded = true;
                                        EraseStatusLine();
                                        Console.WriteLine("  SKIPPED {1}: {0}", sourcePath, Directory.Exists(sourcePath) ? "SUBDIRECTORY" : "FILE");
                                    }
                                }

                                if (!excluded && !Directory.Exists(sourcePath) && excludedExtensions.Contains(Path.GetExtension(sourcePath).ToLowerInvariant()))
                                {
                                    excluded = true;
                                    EraseStatusLine();
                                    Console.WriteLine("  SKIPPED FILE: {0}", sourcePath);
                                }
                            }
                        }

                        if (!excluded)
                        {
                            aggregateSource.Add(new KeyValuePair<string, int>(Path.GetFileName(sourcePath), SourceIndex));
                        }
                    }
                }

                KeyValuePair<string, int>[] aggregate;
                aggregate = MergeSorted(aggregateSource, aggregateCurrent, CompareEntries);
                aggregate = MergeSorted(aggregatePrevious, aggregate, CompareEntries);

                int index = -1;
                string last = null;
                foreach (KeyValuePair<string, int> entry in aggregate)
                {
                    if (!String.Equals(entry.Key, last, StringComparison.OrdinalIgnoreCase))
                    {
                        last = entry.Key;
                        index++;
                        combined.Add(new TriEntry());
                    }
                    switch (entry.Value)
                    {
                        default:
                            throw new InvalidDataException();
                        case SourceIndex:
                            combined[index].source = entry.Key;
                            break;
                        case CurrentIndex:
                            combined[index].current = entry.Key;
                            break;
                        case PreviousIndex:
                            combined[index].previous = entry.Key;
                            break;
                    }
                }
            }

            foreach (TriEntry entry in combined)
            {
                string sourcePath, currentPath, previousPath;
                {
                    string canonical = (entry.source != null) ? entry.source : (entry.current != null) ? entry.current : entry.previous;
                    Debug.Assert(canonical != null);
                    sourcePath = Path.Combine(source, entry.source != null ? entry.source : canonical);
                    currentPath = Path.Combine(current, entry.current != null ? entry.current : canonical);
                    previousPath = Path.Combine(previous, entry.previous != null ? entry.previous : canonical);
                }

                // roll back anything found already in checkpoint
                if (File.Exists(previousPath) && (GetFileLengthRetryable(previousPath, context, null/*trace*/) == 0))
                {
                    if (File.Exists(currentPath))
                    {
                        // previous item was carried to current during prior incompleted pass - move it back.
                        DeleteFile(previousPath, context);
                        MoveFile(currentPath, previousPath, context);
                    }
                    // else item is missing in current and really was zero length
                }
                else if (File.Exists(currentPath))
                {
                    // item added/modified during prior incompleted pass - remove
                    DeleteFile(currentPath, context);
                }
                else if (Directory.Exists(currentPath))
                {
                    // directory may have existed during prior incompleted pass but gone now - push back all forwarded contained items and then remove
                    if (!Directory.Exists(sourcePath))
                    {
                        // deep rollback
                        BackupRecursive(
                            Path.Combine(source, entry.current),
                            Path.Combine(previous, entry.current),
                            Path.Combine(current, entry.current),
                            context,
                            excludedExtensions,
                            excludedItems,
                            log,
                            true/*deepRollback*/);

                        Directory.Delete(currentPath, true/*recursive*/);
                    }
                }

                // create checkpoint of source
                if (!deepRollback)
                {
                    // filename case handling: make current take on case of source
                    try
                    {
                        currentPath = Path.Combine(Path.GetDirectoryName(currentPath), Path.GetFileName(sourcePath));
                    }
                    catch (PathTooLongException)
                    {
                        // if path too long, don't change case and allow subsequent code to fail on copy attempts
                    }

                    if (Directory.Exists(sourcePath) && (entry.source != null/*not excluded*/))
                    {
                        if (log != null)
                        {
                            if (!Directory.Exists(previousPath))
                            {
                                log.WriteLine("added {0}\\", sourcePath);
                            }
                        }

                        if (DoRetryable<bool>(
                            delegate()
                            {
                                try
                                {
                                    Directory.CreateDirectory(currentPath);

                                    if ((context.cryptoOption == EncryptionOption.None)
                                        && (context.compressionOption == CompressionOption.None)
                                        && ((File.GetAttributes(sourcePath) & FileAttributes.Compressed) != 0))
                                    {
                                        // if source directory is compressed, assume it's for a good reason
                                        try
                                        {
                                            NTFSFileCompressionHelper.SetCompressed(currentPath, true/*compress*/);
                                        }
                                        catch
                                        {
                                            // ignore any errors and proceed uncompressed
                                        }
                                    }

                                    return true;
                                }
                                catch (PathTooLongException exception)
                                {
                                    throw new PathTooLongException(String.Format("{0} (length={2}, path=\'{1}\')", exception.Message, currentPath, currentPath.Length));
                                }
                            },
                            delegate() { return false; },
                            delegate() { },
                            context,
                            null/*trace*/))
                        {
                            BackupRecursive(
                                Path.Combine(source, entry.source),
                                Path.Combine(previous, entry.source),
                                Path.Combine(current, entry.source),
                                context,
                                excludedExtensions,
                                excludedItems,
                                log,
                                false/*deepRollback*/);
                        }
                    }
                    else if (File.Exists(sourcePath) && (entry.source != null/*not excluded*/))
                    {
                        if (File.Exists(previousPath))
                        {
                            bool unchanged = true;

                            DateTime sourceItemCreationTime = DoRetryable<DateTime>(delegate { return File.GetCreationTime(sourcePath); }, delegate { return DateTime.MaxValue; }, null, context, null/*trace*/);
                            DateTime previousItemCreationTime = DoRetryable<DateTime>(delegate { return File.GetCreationTime(previousPath); }, delegate { return DateTime.MinValue; }, null, context, null/*trace*/);
                            unchanged = unchanged && (sourceItemCreationTime == previousItemCreationTime);
                            DateTime sourceItemLastWriteTime = DoRetryable<DateTime>(delegate { return File.GetLastWriteTime(sourcePath); }, delegate { return DateTime.MaxValue; }, null, context, null/*trace*/);
                            DateTime previousItemLastWriteTime = DoRetryable<DateTime>(delegate { return File.GetLastWriteTime(previousPath); }, delegate { return DateTime.MinValue; }, null, context, null/*trace*/);
                            unchanged = unchanged && (sourceItemLastWriteTime == previousItemLastWriteTime);

                            if (unchanged)
                            {
                                MoveFile(previousPath, currentPath, context);
                                CreateZeroLengthFile(previousPath, context);

                                try
                                {
                                    File.SetCreationTime(previousPath, File.GetCreationTime(currentPath));
                                    File.SetLastWriteTime(previousPath, File.GetLastWriteTime(currentPath));
                                }
                                catch (Exception)
                                {
                                }
                            }
                            else
                            {
                                if (log != null)
                                {
                                    log.WriteLine("modified {0}", sourcePath);
                                }
                                CopyFile(sourcePath, currentPath, context);
                            }
                        }
                        else
                        {
                            if (log != null)
                            {
                                log.WriteLine("added {0}", sourcePath);
                            }
                            CopyFile(sourcePath, currentPath, context);
                        }
                    }
                    else
                    {
                        bool wasDir = false;
                        if (File.Exists(previousPath) || (wasDir = Directory.Exists(previousPath)))
                        {
                            if (log != null)
                            {
                                log.WriteLine("removed {1}{0}{2}", sourcePath, wasDir ? "/s " : String.Empty, wasDir ? "\\" : String.Empty);
                            }
                        }
                    }
                }
            }
        }

        private static void BackupProcess(string source, string previous, string current, Context context, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems, TextWriter log)
        {
            BackupRecursive(source, previous, current, context, excludedExtensions, excludedItems, log, false/*deepRollback*/);
        }
#endif

        internal static void BackupDecremental(string source, string archiveFolder, Context context, string[] args)
        {
            if (!Directory.Exists(source))
            {
                Console.WriteLine("source directory \"{0}\" does not exist", source);
                throw new UsageException();
            }

            bool finish;
            GetAdHocArgument(ref args, "-nofinish", true/*default*/, false/*explicit*/, out finish);

            InvariantStringSet excludedExtensions;
            InvariantStringSet excludedItems;
            GetExclusionArguments(args, out excludedExtensions, false/*relative*/, out excludedItems);


            string workingArchivePoint = FormatArchivePointName(DateTime.MaxValue);
            string currentArchivePoint = FormatArchivePointName(context.now);

            SortedList<string, bool> archivePoints = new SortedList<string, bool>();
            foreach (string file in Directory.GetFileSystemEntries(archiveFolder))
            {
                string name = Path.GetFileName(file);
                if (!((name == "check.bin") || (name == "checkc.bin") || (name == "nocheckc.bin")))
                {
                    archivePoints.Add(name, false);
                }
            }
            DateTime mostRecentArchivePointDate = DateTime.MinValue;
            string mostRecentArchivePoint = null;
            foreach (string archivePoint in archivePoints.Keys)
            {
                if (!archivePoint.Equals(workingArchivePoint))
                {
                    DateTime date = ParseArchivePointName(archivePoint);
                    if (mostRecentArchivePointDate < date)
                    {
                        mostRecentArchivePointDate = date;
                        mostRecentArchivePoint = archivePoint;
                    }
                }
            }
            if ((mostRecentArchivePoint != null) && (mostRecentArchivePointDate.CompareTo(context.now) >= 0))
            {
                throw new ApplicationException(String.Format("Archive point '{0}' is more recent than now {0}", mostRecentArchivePoint, currentArchivePoint));
            }

            if (File.Exists(Path.Combine(archiveFolder, currentArchivePoint)))
            {
                throw new ApplicationException(String.Format("Archive point '{0}' already exists", context.now));
            }

            EnsureCheck(archiveFolder, mostRecentArchivePoint == null, context, context.now);

            Directory.CreateDirectory(Path.Combine(archiveFolder, workingArchivePoint));


            TextWriter log = null;
            if (context.logPath != null)
            {
                log = new StreamWriter(context.logPath, false/*append*/, Encoding.UTF8);
                log.WriteLine("Backup of {0} to {1}", source, Path.Combine(archiveFolder, currentArchivePoint));
                log.WriteLine();
            }


            bool fakeMostRecentArchivePoint = (mostRecentArchivePoint == null);
            if (fakeMostRecentArchivePoint)
            {
                mostRecentArchivePoint = FormatArchivePointName(DateTime.MinValue);
                string mostRecentArchivePointPath = Path.Combine(archiveFolder, mostRecentArchivePoint);
                Directory.CreateDirectory(mostRecentArchivePointPath);
                if (Directory.GetDirectories(mostRecentArchivePointPath).Length > 0)
                {
                    throw new ApplicationException(String.Format("Temporary archive workspace \"{0}\" is nonempty!", mostRecentArchivePointPath));
                }
            }

            BackupProcess(
                source,
                Path.Combine(archiveFolder, mostRecentArchivePoint),
                Path.Combine(archiveFolder, workingArchivePoint),
                context,
                excludedExtensions,
                excludedItems,
                log);

            if (fakeMostRecentArchivePoint)
            {
                Directory.Delete(Path.Combine(archiveFolder, mostRecentArchivePoint));
            }

            if (finish)
            {
                Directory.Move(Path.Combine(archiveFolder, workingArchivePoint), Path.Combine(archiveFolder, currentArchivePoint));
            }


            if (log != null)
            {
                log.WriteLine();
                log.WriteLine("Finished.");
                log.Close();
                log = null;
            }

            EraseStatusLine();
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Verify
        //
        ////////////////////////////////////////////////////////////////////////////

        private static void VerifyRecursive(string sourceRootDirectory, string targetRootDirectory, Context context, OneWaySwitch different)
        {
            WriteStatusLine(sourceRootDirectory);

            SortedList<string, bool> allFiles = new SortedList<string, bool>();

            try
            {
                bool header = false;

                foreach (string file in Directory.GetFileSystemEntries(sourceRootDirectory))
                {
                    string message = null;
                    string fileName = Path.GetFileName(file);
                    bool isDirectory = ((File.GetAttributes(file) & FileAttributes.Directory) != 0);
                    allFiles.Add(fileName, isDirectory);
                    string targetFile = Path.Combine(targetRootDirectory, fileName);
                    if (!isDirectory)
                    {
                        if (!File.Exists(targetFile))
                        {
                            message = String.Format("Missing file: {0}", fileName);
                        }
                        else if (!CompareFile(file, targetFile, context))
                        {
                            message = String.Format("Different: {0}", fileName);
                        }
                    }
                    else
                    {
                        if (!Directory.Exists(targetFile))
                        {
                            message = String.Format("Missing directory: {0}", fileName);
                        }
                    }
                    if (message != null)
                    {
                        EraseStatusLine();
                        different.Set();
                        if (!header)
                        {
                            header = true;
                            Console.WriteLine(targetRootDirectory);
                        }
                        ConsoleWriteLineColor(ConsoleColor.Red, "  " + message);
                    }
                }

                foreach (string file in Directory.GetFileSystemEntries(targetRootDirectory))
                {
                    string message = null;
                    string fileName = Path.GetFileName(file);
                    bool isDirectory = ((File.GetAttributes(file) & FileAttributes.Directory) != 0);
                    if (!allFiles.ContainsKey(fileName) || (allFiles[fileName] != isDirectory))
                    {
                        if (isDirectory)
                        {
                            message = String.Format("Added directory: {0}", fileName);
                        }
                        else
                        {
                            message = String.Format("Added file: {0}", fileName);
                        }
                    }
                    if (message != null)
                    {
                        EraseStatusLine();
                        different.Set();
                        if (!header)
                        {
                            header = true;
                            Console.WriteLine(targetRootDirectory);
                        }
                        ConsoleWriteLineColor(ConsoleColor.Red, "  " + message);
                    }
                }
            }
            catch (Exception exception)
            {
                different.Set();
                ConsoleWriteLineColor(ConsoleColor.Red, "Exception processing directory '{0}': {1}", sourceRootDirectory, exception.Message);
            }

            foreach (KeyValuePair<string, bool> item in allFiles)
            {
                if (item.Value && Directory.Exists(Path.Combine(targetRootDirectory, item.Key)))
                {
                    CompareRecursive(Path.Combine(sourceRootDirectory, item.Key), Path.Combine(targetRootDirectory, item.Key), context, different, true/*red*/);
                }
            }
        }

        internal static void Verify(string source, string archiveFolder, Context context)
        {
            OneWaySwitch different = new OneWaySwitch();

            DateTime mostRecentArchivePointDate = DateTime.MinValue;
            string mostRecentArchivePoint = null;
            foreach (string file in Directory.GetFileSystemEntries(archiveFolder))
            {
                string name = Path.GetFileName(file);
                if (!((name == "check.bin") || (name == "checkc.bin") || (name == "nocheckc.bin")))
                {
                    DateTime date = ParseArchivePointName(name);
                    if (mostRecentArchivePointDate < date)
                    {
                        mostRecentArchivePointDate = date;
                        mostRecentArchivePoint = name;
                    }
                }
            }
            if (mostRecentArchivePoint == null)
            {
                throw new ApplicationException("No archive points found");
            }

            EnsureCheck(archiveFolder, false, context, context.now);

            VerifyRecursive(
                source,
                Path.Combine(archiveFolder, mostRecentArchivePoint),
                context,
                different);

            EraseStatusLine();

            if (different.Value)
            {
                throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied);
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Purge
        //
        ////////////////////////////////////////////////////////////////////////////

        private static void PurgeRecursive(string earlySaveRootDirectory, string latePurgeRootDirectory, Context context, out int movedFiles, out int discardedFiles, out int discardedRoots)
        {
            movedFiles = 0;
            discardedFiles = 0;
            discardedRoots = 0;

            // walk only items in early save directory. any items in late that are not in
            // early were created newly with late and therefore are not propagated back.
            foreach (string earlySaveFile in Directory.GetFiles(earlySaveRootDirectory))
            {
                string earlySaveFileName = Path.GetFileName(earlySaveFile);
                string latePurgeFile = Path.Combine(latePurgeRootDirectory, earlySaveFileName);

                long earlySaveLength = DoRetryable<long>(
                    delegate
                    {
                        using (Stream earlySaveStream = new FileStream(earlySaveFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        {
                            return earlySaveStream.Length;
                        }
                    },
                    delegate { return -1; },
                    null,
                    context,
                    null/*trace*/);
                long latePurgeLength = DoRetryable<long>(
                    delegate
                    {
                        if (!File.Exists(latePurgeFile))
                        {
                            // missing (deleted) in late is equivalent to no change to propagate back
                            return 0;
                        }
                        using (Stream latePurgeStream = new FileStream(latePurgeFile, FileMode.Open, FileAccess.Read))
                        {
                            return latePurgeStream.Length;
                        }
                    },
                    delegate { return -1; },
                    null,
                    context,
                    null/*trace*/);

                if (earlySaveLength != 0)
                {
                    // early is real: keep unchanged (was either change-terminal, placeholder, or removed in late)

                    if (latePurgeLength != 0)
                    {
                        discardedFiles++;
                    }
                }
                else
                {
                    // early is placeholder

                    if (latePurgeLength == 0)
                    {
                        // early is placeholder, late is placeholder: keep unchanged
                        // (real file is post-late and placeholder relationship in early remains)
                    }
                    else
                    {
                        // late is real, early is placeholder: propagate late back to early

                        movedFiles++;

                        Console.WriteLine("  {0}", earlySaveFile);

                        DoRetryable<int>(
                            delegate
                            {
                                File.Delete(earlySaveFile);
                                return 0;
                            },
                            delegate { return 0; },
                            null,
                            context,
                            null/*trace*/);
                        DoRetryable<int>(
                            delegate
                            {
                                File.Move(latePurgeFile, earlySaveFile);
                                return 0;
                            },
                            delegate { return 0; },
                            null,
                            context,
                            null/*trace*/);
                    }
                }
            }

            // note: if a directory existed in checkpoint 1, then was removed in checkpoint 2,
            // and a new one created of same name in checkpoint 3, when checkpoint 2 is purged
            // that information is lost. if checkpoint 3 is subsequently purged, any zero-length
            // items in checkpoint 1 will erroneously receive propagation from checkpoint 3.

            foreach (string earlySaveSubdirectory in Directory.GetDirectories(earlySaveRootDirectory))
            {
                string earlySaveSubdirectoryName = Path.GetFileName(earlySaveSubdirectory);
                string latePurgeSubdirectory = Path.Combine(latePurgeRootDirectory, earlySaveSubdirectoryName);

                if (Directory.Exists(latePurgeSubdirectory))
                {
                    // propagate all late subdirectory items and remove late subdirectory
                    int movedFilesInner, discardedFilesInner, discardedRootsInner;
                    PurgeRecursive(earlySaveSubdirectory, latePurgeSubdirectory, context, out movedFilesInner, out discardedFilesInner, out discardedRootsInner);
                    movedFiles += movedFilesInner;
                    discardedFiles += discardedFilesInner;
                    discardedRoots += discardedRootsInner;
                }
                else
                {
                    // missing in late means removed in late: no change needed (keep early)
                }
            }

            foreach (string latePurgeSubdirectory in Directory.GetDirectories(latePurgeRootDirectory))
            {
                string latePurgeSubdirectoryName = Path.GetFileName(latePurgeSubdirectory);
                string earlySaveSubdirectory = Path.Combine(earlySaveRootDirectory, latePurgeSubdirectoryName);

                if (!Directory.Exists(earlySaveSubdirectory))
                {
                    discardedRoots++;
                }
            }

            // propagation finished: remove late root
            Directory.Delete(latePurgeRootDirectory, true/*recursive*/);
        }

        internal static void Purge(string archiveRoot, string beginCheckpoint, string endCheckpoint, Context context)
        {
            if (!Directory.Exists(Path.Combine(archiveRoot, beginCheckpoint)))
            {
                throw new ApplicationException(String.Format("Archive point {0} does not exist", beginCheckpoint));
            }
            if (!Directory.Exists(Path.Combine(archiveRoot, endCheckpoint)))
            {
                throw new ApplicationException(String.Format("Archive point {0} does not exist", endCheckpoint));
            }
            DateTime beginDate;
            if (!DateTime.TryParse(beginCheckpoint.Replace('+', ':'), out beginDate))
            {
                throw new ApplicationException(String.Format("Invalid archive point '{0}'", beginCheckpoint));
            }
            DateTime endDate;
            if (!DateTime.TryParse(endCheckpoint.Replace('+', ':'), out endDate))
            {
                throw new ApplicationException(String.Format("Invalid archive point '{0}'", endCheckpoint));
            }
            if (endDate < beginDate)
            {
                throw new ApplicationException("End checkpoint is earlier then begin checkpoint");
            }

            List<string> toPurge = new List<string>();
            foreach (string file in Directory.GetFileSystemEntries(archiveRoot))
            {
                string name = Path.GetFileName(file);
                if (!((name == "check.bin") || (name == "checkc.bin") || (name == "nocheckc.bin")))
                {
                    DateTime date;
                    if (!DateTime.TryParse(name.Replace('+', ':'), out date))
                    {
                        throw new ApplicationException(String.Format("Invalid archive point '{0}' found in archive folder", name));
                    }
                    if ((date > beginDate) && (date < endDate))
                    {
                        Debug.Assert((toPurge.Count == 0) || (String.Compare(toPurge[toPurge.Count - 1], name, StringComparison.OrdinalIgnoreCase) < 0));
                        toPurge.Add(name);
                    }
                }
            }
            toPurge.Sort();

            foreach (string name in toPurge)
            {
                bool quit = false;
                while (Console.KeyAvailable)
                {
                    if (Char.ToLower(Console.ReadKey().KeyChar) == 'q')
                    {
                        quit = true;
                    }
                }
                if (quit)
                {
                    break;
                }

                ConsoleWriteLineColor(ConsoleColor.Yellow, "Purging {0}", name);
                int movedFiles, discardedFiles, discardedRoots;
                PurgeRecursive(
                    Path.Combine(archiveRoot, beginCheckpoint),
                    Path.Combine(archiveRoot, name),
                    context,
                    out movedFiles,
                    out discardedFiles,
                    out discardedRoots);
                Console.WriteLine("moved files {0}, discarded files {1}, discarded roots {2}", movedFiles, discardedFiles, discardedRoots);
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Prune
        //
        ////////////////////////////////////////////////////////////////////////////

        private const int PreserveFull = 2; // in months
        private const int PreserveMonthly = 3; // in months
        private const int PreserveQuarterly = 6; // in months
        internal static void Prune(string archiveRoot, Context context)
        {
            List<string> checkpoints = new List<string>();
            foreach (string file in Directory.GetFileSystemEntries(archiveRoot))
            {
                string name = Path.GetFileName(file);
                if (!((name == "check.bin") || (name == "checkc.bin") || (name == "nocheckc.bin")))
                {
                    DateTime date;
                    if (!DateTime.TryParse(name.Replace('+', ':'), out date))
                    {
                        throw new ApplicationException(String.Format("Invalid archive point '{0}' found in archive folder", name));
                    }
                    checkpoints.Add(name);
                }
            }
            checkpoints.Sort();

            Console.WriteLine("All checkpoints:");
            foreach (string checkpoint in checkpoints)
            {
                Console.WriteLine("  {0}", checkpoint);
            }
            Console.WriteLine();

            SortedList<string, string> purgeSeries = new SortedList<string, string>();
            int i = checkpoints.Count;
            int j, l;
            DateTime stop;
            // no change
            stop = (new DateTime(context.now.Year, context.now.Month, 1)).AddMonths(-PreserveFull);
            while ((i > 0) && (DateTime.Parse(checkpoints[i - 1].Replace('+', ':')) >= stop))
            {
                i--;
            }
            // preserve once a month
            stop = stop.AddMonths(-PreserveMonthly);
            stop = stop.AddMonths(-((stop.Month - 1) % 3)); // round up to previous end of quarter
            j = i;
            while ((i > 0) && (DateTime.Parse(checkpoints[i - 1].Replace('+', ':')) >= stop))
            {
                i--;
            }
            l = i;
            for (int k = i; k <= Math.Min(j, checkpoints.Count - 1); k++)
            {
                if (DateTime.Parse(checkpoints[l].Replace('+', ':')).Month != DateTime.Parse(checkpoints[k].Replace('+', ':')).Month)
                {
                    if (l + 1 < k)
                    {
                        purgeSeries.Add(checkpoints[l], checkpoints[k]);
                    }
                    l = k;
                }
            }
            // preserve once a quarter
            stop = stop.AddMonths(-PreserveQuarterly);
            stop = stop.AddMonths(-((stop.Month - 1) % 12)); // round up to previous end of year
            j = i;
            while ((i > 0) && (DateTime.Parse(checkpoints[i - 1].Replace('+', ':')) >= stop))
            {
                i--;
            }
            l = i;
            for (int k = i; k <= Math.Min(j, checkpoints.Count - 1); k++)
            {
                DateTime lDate = DateTime.Parse(checkpoints[l].Replace('+', ':'));
                DateTime kDate = DateTime.Parse(checkpoints[k].Replace('+', ':'));
                if ((lDate.Year * 12 + lDate.Month - 1) / 3 != (kDate.Year * 12 + kDate.Month - 1) / 3)
                {
                    if (l + 1 < k)
                    {
                        purgeSeries.Add(checkpoints[l], checkpoints[k]);
                    }
                    l = k;
                }
            }
            // remainder -- preserve once a year
            j = i;
            i = 0;
            l = i;
            for (int k = i; k <= Math.Min(j, checkpoints.Count - 1); k++)
            {
                DateTime lDate = DateTime.Parse(checkpoints[l].Replace('+', ':'));
                DateTime kDate = DateTime.Parse(checkpoints[k].Replace('+', ':'));
                if ((lDate.Year != kDate.Year) || (l == 0))
                {
                    if (l + 1 < k)
                    {
                        purgeSeries.Add(checkpoints[l], checkpoints[k]);
                    }
                    l = k;
                }
            }

            Console.WriteLine("Pending purge command sequence:");
            foreach (KeyValuePair<string, string> purge in purgeSeries)
            {
                Console.WriteLine("  purge {0} {1}", purge.Key, purge.Value);
            }
            Console.WriteLine();
            while (true)
            {
                Console.Write("c)ontinue or q)uit?  ");
                string answer = Console.ReadLine();
                if (answer == "q")
                {
                    return;
                }
                else if (answer == "c")
                {
                    break;
                }
            }

            foreach (KeyValuePair<string, string> purge in purgeSeries)
            {
                bool quit = false;
                while (Console.KeyAvailable)
                {
                    if (Char.ToLower(Console.ReadKey().KeyChar) == 'q')
                    {
                        quit = true;
                    }
                }
                if (quit)
                {
                    break;
                }
                Purge(archiveRoot, purge.Key, purge.Value, context);
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Restore
        //
        ////////////////////////////////////////////////////////////////////////////

        private static void RestoreFile(string archiveRoot, string checkpointPart, string target, string[] checkpoints, Context context, string checkpointPartName)
        {
            string checkpointTerminal = null;
            foreach (string checkpointCandidate in checkpoints)
            {
                string candidateCheckpointPartFilePath = Path.Combine(Path.Combine(Path.Combine(archiveRoot, checkpointCandidate), checkpointPart), checkpointPartName);

                long candidateLength = GetFileLengthNoError(candidateCheckpointPartFilePath);
                if (candidateLength > 0)
                {
                    // change-terminal found
                    checkpointTerminal = checkpointCandidate;
                    break;
                }
                else if (candidateLength < 0)
                {
                    // file was deleted: use last known checkpoint
                    break;
                }
                else
                {
                    // placeholder: keep exploring, or end with this zero-length file as change-terminal
                    checkpointTerminal = checkpointCandidate;
                }
            }
            Debug.Assert(checkpointTerminal != null);

            string sourceFilePath = Path.Combine(Path.Combine(Path.Combine(archiveRoot, checkpointTerminal), checkpointPart), checkpointPartName);
            string targetFilePath = target; // directory restore caller needs to do this (because it may not always be appropriate): Path.Combine(target, checkpointPartName);
            CopyFile(sourceFilePath, target, context);
        }

        private static void RestoreRecursive(string archiveRoot, string checkpointPart, string target, string[] checkpoints, Context context)
        {
            Console.WriteLine(target);

            if (File.Exists(target) || Directory.Exists(target))
            {
                throw new ApplicationException(String.Format("Target {0} already exists", target));
            }
            Directory.CreateDirectory(target);

            foreach (string checkpointPartFile in Directory.GetFiles(Path.Combine(Path.Combine(archiveRoot, checkpoints[0]), checkpointPart)))
            {
                string checkpointPartName = Path.GetFileName(checkpointPartFile);
                RestoreFile(archiveRoot, checkpointPart, Path.Combine(target, checkpointPartName), checkpoints, context, checkpointPartName);
            }

            foreach (string checkpointPartSubdirectory in Directory.GetDirectories(Path.Combine(Path.Combine(archiveRoot, checkpoints[0]), checkpointPart)))
            {
                string checkpointPartSubdirectoryName = Path.GetFileName(checkpointPartSubdirectory);
                RestoreRecursive(archiveRoot, Path.Combine(checkpointPart, checkpointPartSubdirectoryName), Path.Combine(target, checkpointPartSubdirectoryName), checkpoints, context);
            }
        }

        internal static void Restore(string archiveRoot, string checkpointPath, string target, Context context)
        {
            context.zeroLengthSpecial = true;

            string checkpoint = checkpointPath;
            string checkpointPart = String.Empty;
            while (Path.GetDirectoryName(checkpoint) != String.Empty)
            {
                checkpointPart = Path.Combine(Path.GetFileName(checkpoint), checkpointPart);
                checkpoint = Path.GetDirectoryName(checkpoint);
            }

            DateTime checkpointDate = ParseArchivePointName(checkpoint);
            if (!Directory.Exists(Path.Combine(archiveRoot, checkpoint)))
            {
                throw new ApplicationException(String.Format("Archive point \"{0}\" does not exist", checkpoint));
            }

            List<string> checkpoints = new List<string>();
            foreach (string file in Directory.GetFileSystemEntries(archiveRoot))
            {
                string name = Path.GetFileName(file);
                if (!((name == "check.bin") || (name == "checkc.bin") || (name == "nocheckc.bin")))
                {
                    DateTime date = ParseArchivePointName(name);
                    if (date >= checkpointDate)
                    {
                        Debug.Assert((checkpoints.Count == 0) || (String.Compare(checkpoints[checkpoints.Count - 1], name, StringComparison.OrdinalIgnoreCase) < 0));
                        checkpoints.Add(name);
                    }
                }
            }

            if (File.Exists(Path.Combine(archiveRoot, checkpointPath)))
            {
                if (File.Exists(Path.Combine(target, Path.GetFileName(checkpointPart))))
                {
                    throw new ApplicationException(String.Format("Target \"{0}\" already exists", target));
                }
                RestoreFile(archiveRoot, Path.GetDirectoryName(checkpointPart), target, checkpoints.ToArray(), context, Path.GetFileName(checkpointPart));
            }
            else if (Directory.Exists(Path.Combine(archiveRoot, checkpointPath)))
            {
                if (File.Exists(target) || Directory.Exists(target))
                {
                    throw new ApplicationException(String.Format("Target \"{0}\" already exists", target));
                }
                RestoreRecursive(archiveRoot, checkpointPart, target, checkpoints.ToArray(), context);
            }
            else
            {
                throw new ApplicationException(String.Format("Checkpoint \"{0}\" does not exist", Path.Combine(archiveRoot, checkpointPath)));
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Split, Unsplit
        //
        ////////////////////////////////////////////////////////////////////////////

        internal static void Split(string sourceFile, string destinationTemplate, long size, Context context)
        {
            if (size < 0)
            {
                if (size == -1)
                {
                    size = Int64.MaxValue;
                }
                else
                {
                    throw new ApplicationException();
                }
            }

            byte[] hash;

            using (Stream stream = File.Open(sourceFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                long length = stream.Length;

                using (CheckedReadStream checkedStream = new CheckedReadStream(stream, new CryptoPrimitiveHashCheckValueGeneratorSHA2_512()))
                {
                    int parts = (int)((length + size - 1) / size);
                    int digits = parts.ToString().Length;
                    long position = 0;
                    while (position < length)
                    {
                        Debug.Assert(position % size == 0);
                        string destinationFile = String.Concat(destinationTemplate, ".", (position / size).ToString("D" + digits.ToString()));
                        Console.WriteLine("Generating {0}", destinationFile);
                        using (Stream destinationStream = File.Open(destinationFile, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        {
                            byte[] buffer = new byte[Constants.BufferSize];
                            long toReadOne = Math.Min(size, length - position);
                            while (toReadOne > 0)
                            {
                                int toRead = (int)Math.Min(toReadOne, buffer.Length);
                                int read = checkedStream.Read(buffer, 0, toRead);
                                if (read != toRead)
                                {
                                    throw new ApplicationException("Read failure");
                                }
                                destinationStream.Write(buffer, 0, read);
                                position += read;
                                toReadOne -= read;
                            }
                        }
                        File.SetCreationTime(destinationFile, context.now);
                        File.SetLastWriteTime(destinationFile, context.now);
                    }

                    checkedStream.Close();
                    hash = checkedStream.CheckValue;
                }
            }

            string destinationFileHash = String.Concat(destinationTemplate, ".sha512");
            Console.WriteLine("Generating {0}", destinationFileHash);
            using (Stream destinationStreamHash = File.Open(destinationFileHash, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                using (TextWriter writer = new StreamWriter(destinationStreamHash))
                {
                    string hashText = HexUtility.HexEncode(hash);
                    writer.WriteLine(hashText);
                    Console.WriteLine("SHA512={0}", hashText);
                }
            }
            File.SetCreationTime(destinationFileHash, context.now);
            File.SetLastWriteTime(destinationFileHash, context.now);
        }

        internal static void Unsplit(string sourcePrefix, string destinationFile, Context context)
        {
            bool hashValid = false;

            SortedList<string, bool> files = new SortedList<string, bool>();
            foreach (string file in Directory.GetFiles(Path.GetDirectoryName(sourcePrefix), String.Concat(Path.GetFileName(sourcePrefix), ".*")))
            {
                files.Add(file, false);
            }

            byte[] hash;
            string sha512OriginalHashText = null;

            using (Stream stream = File.Open(destinationFile, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                using (CheckedWriteStream checkedStream = new CheckedWriteStream(stream, new CryptoPrimitiveHashCheckValueGeneratorSHA2_512()))
                {
                    foreach (KeyValuePair<string, bool> file1 in files)
                    {
                        string path = file1.Key;
                        string extension = Path.GetExtension(file1.Key);
                        int sequence;

                        Console.WriteLine("Incorporating {0}", path);

                        if (extension.StartsWith(".") && Int32.TryParse(extension.Substring(1), out sequence))
                        {
                            using (Stream segmentStream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                            {
                                byte[] buffer = new byte[Constants.BufferSize];
                                while (true)
                                {
                                    int read = segmentStream.Read(buffer, 0, buffer.Length);
                                    if (read == 0)
                                    {
                                        break;
                                    }
                                    checkedStream.Write(buffer, 0, read);
                                }
                            }
                        }
                        else if (extension.Equals(".sha512", StringComparison.OrdinalIgnoreCase))
                        {
                            using (TextReader reader = new StreamReader(path))
                            {
                                sha512OriginalHashText = reader.ReadLine();
                            }
                        }
                        else
                        {
                            Console.WriteLine("  UNKNOWN FILE EXTENSION -- IGNORED");
                        }
                    }

                    checkedStream.Close();
                    hash = checkedStream.CheckValue;
                }
            }

            string sha512HashText = HexUtility.HexEncode(hash);
            Console.WriteLine("SHA512={0}", sha512HashText);
            hashValid = sha512HashText.Equals(sha512OriginalHashText, StringComparison.OrdinalIgnoreCase);
            Console.WriteLine(hashValid
                ? "  SHA512 hashes match"
                : "  SHA512 hashes do not match, FILE IS DAMAGED");

            File.SetCreationTime(destinationFile, context.now);
            File.SetLastWriteTime(destinationFile, context.now);
            if (!hashValid)
            {
                throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied);
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Validate
        //
        ////////////////////////////////////////////////////////////////////////////

        private static void ValidateEncryptionRecursive(string file, OneWaySwitch invalid, Context context)
        {
            if (File.Exists(file))
            {
                bool valid = true;
                try
                {
                    // validate HMAC
                    using (Stream fileStream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        // zero-length "encrypted" files are considered valid because backup creates them in checkpoints
                        if (fileStream.Length != 0)
                        {
                            CryptoKeygroup keys;
                            EncryptedFileContainerHeader fch = null;
                            try
                            {
                                fch = new EncryptedFileContainerHeader(fileStream, true/*peek*/, context.decrypt);
                            }
                            catch (InvalidDataException)
                            {
                                // function-local escape
                                throw new TaggedReadStream.TagInvalidException();
                            }
                            context.decrypt.algorithm.DeriveSessionKeys(context.decrypt.GetMasterKeyEntry(fch.passwordSalt, fch.rfc2898Rounds).MasterKey, fch.fileSalt, out keys);

                            // zero-length files are considered valid because backup creates them in checkpoints
                            // when a file has not changed when the next checkpoint is created.
                            if (fileStream.Length > 0)
                            {
                                StreamStack.DoWithStreamStack(
                                    fileStream,
                                    new StreamStack.StreamWrapMethod[]
                                    {
                                        delegate(Stream stream)
                                        {
                                            // see note and references about
                                            // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                            return new TaggedReadStream(stream, context.decrypt.algorithm.CreateMACGenerator(keys.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                        },
                                    },
                                    delegate(Stream stream)
                                    {
                                        ReadAndDiscardEntireStream(stream);
                                    });
                            }
                        }
                    }
                }
                catch (TaggedReadStream.TagInvalidException)
                {
                    valid = false;
                }

                string message = String.Format("{0,-7} {1}", valid ? "valid" : "INVALID", file);
                if (valid)
                {
                    Console.WriteLine(message);
                }
                else
                {
                    invalid.Set();
                    ConsoleWriteLineColor(ConsoleColor.Yellow, message);
                }
            }
            else
            {
                foreach (string contained in Directory.GetFileSystemEntries(file))
                {
                    ValidateEncryptionRecursive(contained, invalid, context);
                }
            }
        }

        internal static void ValidateEncryption(string sourcePattern, Context context)
        {
            string[] sourceFileList = new string[] { sourcePattern };
            if (FileNamePatternMatch.ContainsWildcards(sourcePattern))
            {
                sourceFileList = Directory.GetFiles(Path.GetDirectoryName(sourcePattern), Path.GetFileName(sourcePattern));
            }

            OneWaySwitch invalid = new OneWaySwitch();
            foreach (string sourceFile in sourceFileList)
            {
                ValidateEncryptionRecursive(sourceFile, invalid, context);
            }

            if (invalid.Value)
            {
                throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied);
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Pack, Unpack, DynamicPack
        //
        ////////////////////////////////////////////////////////////////////////////

        public const byte PackArchiveFixedHeaderNumber = 0x01;

        private const int PackRandomSignatureLengthBytes = 256 / 8;

        public const int PackArchiveStructureTypeManifest = 1;
        public const int PackArchiveStructureTypeFiles = 2;

        internal class PackedFileHeaderRecord
        {
            internal enum Fields
            {
                Terminator = 0,

                // file data fields
                Version = 1, // reserved & optional; must come first
                Subpath = 2,
                CreationTimeUtc = 3,
                LastWriteTimeUtc = 4,
                Attributes = 5,

                // these fields used only for manifest; 
                // - these fields must occur both or neither
                // - if present, no other fields may be set and data stream must be zero length
                // - if present implies PackArchiveStructureTypeManifest, if absent implies PackArchiveStructureTypeFiles
                SegmentName = 6,
                SegmentSerialNumber = 7,

                // used for large files split across multiple segments - optional
                Range = 8,

                Digest = 9, // field id 9 will always be a Merkel tree hash SHA2-512 blocksize=65536, base-64 encoded
            }

            internal const int SupportedVersionNumber = 1;

            [Flags]
            internal enum HeaderAttributes : ulong
            {
                None = 0,

                Directory = 1,
                ReadOnly = 2,
            }

            internal static readonly KeyValuePair<HeaderAttributes, FileAttributes>[] AttributeMapping = new KeyValuePair<HeaderAttributes, FileAttributes>[]
            {
                new KeyValuePair<HeaderAttributes, FileAttributes>(HeaderAttributes.Directory,  FileAttributes.Directory),
                new KeyValuePair<HeaderAttributes, FileAttributes>(HeaderAttributes.ReadOnly,   FileAttributes.ReadOnly),
            };

            internal static readonly KeyValuePair<HeaderAttributes, char>[] AttributeSymbolMapping = new KeyValuePair<HeaderAttributes, char>[]
            {
                new KeyValuePair<HeaderAttributes, char>(HeaderAttributes.ReadOnly,     'r'),
                new KeyValuePair<HeaderAttributes, char>(HeaderAttributes.Directory,    'd'),
            };

            internal static FileAttributes ToFileAttributes(HeaderAttributes a)
            {
                FileAttributes r = (FileAttributes)0;
                foreach (KeyValuePair<HeaderAttributes, FileAttributes> i in AttributeMapping)
                {
                    if ((i.Key & a) != 0)
                    {
                        r |= i.Value;
                    }
                }
                if (r == (FileAttributes)0)
                {
                    r = FileAttributes.Normal;
                }
                return r;
            }

            internal static HeaderAttributes ToHeaderAttributes(FileAttributes a)
            {
                HeaderAttributes r = HeaderAttributes.None;
                foreach (KeyValuePair<HeaderAttributes, FileAttributes> i in AttributeMapping)
                {
                    if ((i.Value & a) != 0)
                    {
                        r |= i.Key;
                    }
                }
                return r;
            }

            public class RangeRecord
            {
                public readonly long Start;
                public readonly long End;
                public readonly long TotalFileLength;

                public RangeRecord(long start, long end, long totalFileLength)
                {
                    this.Start = start;
                    this.End = end;
                    this.TotalFileLength = totalFileLength;
                }

                public long Length { get { return End + 1 - Start; } }

                public override string ToString()
                {
                    return String.Format("{0}-{1}/{2}", Start, End, TotalFileLength);
                }

                public static RangeRecord Parse(string value)
                {
                    string[] parts = value.Split(new char[] { '-', '/' });
                    if (parts.Length != 3)
                    {
                        throw new InvalidDataException();
                    }
                    long start = Int64.Parse(parts[0]);
                    long end = Int64.Parse(parts[1]);
                    long totalFileLength = Int64.Parse(parts[2]);
                    return new RangeRecord(start, end, totalFileLength);
                }

                public static bool Equals(RangeRecord l, RangeRecord r)
                {
                    if (l == null)
                    {
                        if (r == null)
                        {
                            return true;
                        }
                        return false;
                    }
                    return (l.Start == r.Start) && (l.End == r.End) && (l.TotalFileLength == r.TotalFileLength);
                }
            }

            internal const int HeaderTokenLength = 4;
            private static readonly byte[] PackedFileHeaderToken = new byte[HeaderTokenLength] { 0x81, 0x72, 0x63, 0x54 };

            public static readonly PackedFileHeaderRecord NullHeaderRecord = new PackedFileHeaderRecord();

            private object subpath;
            private DateTime creationTimeUtc;
            private DateTime lastWriteTimeUtc;
            private HeaderAttributes attributes;
            private long embeddedStreamLength; // if range==null: orig. file & embedded data length, else embedded data length only

            private string segmentName;
            private ulong segmentSerialNumber;

            private RangeRecord range; // null if file is not split

            private byte[] digest; // null if hash not present

            private PackedFileHeaderRecord()
            {
            }

            internal PackedFileHeaderRecord(object subpath, DateTime creationTimeUtc, DateTime lastWriteTimeUtc, HeaderAttributes attributes, long embeddedStreamLength, string segmentName, ulong segmentSerialNumber, RangeRecord range, byte[] digest)
            {
                if (range != null)
                {
                    if (embeddedStreamLength != range.Length)
                    {
                        throw new ArgumentException();
                    }
                }

                this.subpath = subpath;
                this.creationTimeUtc = creationTimeUtc;
                this.lastWriteTimeUtc = lastWriteTimeUtc;
                this.attributes = attributes;
                this.embeddedStreamLength = embeddedStreamLength;

                this.segmentName = segmentName;
                this.segmentSerialNumber = segmentSerialNumber;

                this.range = range;

                this.digest = digest;
            }

            internal PackedFileHeaderRecord(object subpath, DateTime creationTimeUtc, DateTime lastWriteTimeUtc, HeaderAttributes attributes, long embeddedStreamLength, string segmentName, ulong segmentSerialNumber)
                : this(subpath, creationTimeUtc, lastWriteTimeUtc, attributes, embeddedStreamLength, segmentName, segmentSerialNumber, null/*range*/, null/*digest*/)
            {
            }

            internal PackedFileHeaderRecord(object subpath, DateTime creationTimeUtc, DateTime lastWriteTimeUtc, HeaderAttributes attributes, long embeddedStreamLength, RangeRecord range, byte[] digest)
                : this(subpath, creationTimeUtc, lastWriteTimeUtc, attributes, embeddedStreamLength, null/*segmentName*/, 0/*segmentSerialNumber*/, range, digest)
            {
            }

            private const string PackedFileDateTimeFormat = "O"; // "round-trip"

            internal static DateTime ParseDateTime(string datetime)
            {
                return DateTime.ParseExact(datetime, PackedFileDateTimeFormat, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind);
            }

            internal static string FormatDateTime(DateTime datetimeUtc)
            {
                if (datetimeUtc.Kind != DateTimeKind.Utc)
                {
                    throw new InvalidDataException();
                }
                return datetimeUtc.ToString(PackedFileDateTimeFormat, System.Globalization.CultureInfo.InvariantCulture);
            }

            internal void Write(Stream stream)
            {
                byte[] checkValue;

                ValidateRecordInvariants(false/*nullHeader*/); // writing null header is not permitted with this method, use WriteNullHeader

                stream.Write(PackedFileHeaderToken, 0, PackedFileHeaderToken.Length);

                using (CheckedWriteStream checkedStream = new CheckedWriteStream(stream, new CRC32()))
                {
                    // header fields section start

                    if (subpath != null)
                    {
                        Debug.Assert(!String.IsNullOrEmpty(subpath.ToString()));
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.Subpath);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, subpath.ToString());
                    }

                    if (creationTimeUtc != default(DateTime))
                    {
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.CreationTimeUtc);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, FormatDateTime(creationTimeUtc));
                    }

                    if (lastWriteTimeUtc != default(DateTime))
                    {
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.LastWriteTimeUtc);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, FormatDateTime(lastWriteTimeUtc));
                    }

                    if (attributes != default(HeaderAttributes))
                    {
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.Attributes);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, ((ulong)attributes).ToString());
                    }

                    if ((segmentName != null) != (segmentSerialNumber != 0))
                    {
                        throw new InvalidOperationException();
                    }
                    if (segmentName != null)
                    {
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.SegmentName);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, segmentName);
                    }
                    if (segmentSerialNumber != 0)
                    {
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.SegmentSerialNumber);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, segmentSerialNumber.ToString());
                    }

                    if (range != null)
                    {
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.Range);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, range.ToString());
                    }

                    if (digest != null)
                    {
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.Digest);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, Convert.ToBase64String(digest));
                    }

                    BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.Terminator);

                    // header fields section end

                    BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, embeddedStreamLength);

                    checkedStream.Close();
                    checkValue = checkedStream.CheckValue;
                }

                stream.Write(checkValue, 0, checkValue.Length);
            }

            // Null header contains only a terminator field and zero for file length.
            internal static void WriteNullHeader(Stream stream)
            {
                byte[] checkValue;

                stream.Write(PackedFileHeaderToken, 0, PackedFileHeaderToken.Length);

                using (CheckedWriteStream checkedStream = new CheckedWriteStream(stream, new CRC32()))
                {
                    BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.Terminator);

                    BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, 0); // file length field

                    checkedStream.Close();
                    checkValue = checkedStream.CheckValue;
                }

                stream.Write(checkValue, 0, checkValue.Length);
            }

            internal static PackedFileHeaderRecord Read(Stream stream, bool strict, DateTime now)
            {
                PackedFileHeaderRecord header = new PackedFileHeaderRecord();
                bool nullHeader;
                header.ReadInternal(stream, strict, now, out nullHeader);
                return !nullHeader ? header : NullHeaderRecord;
            }

            private void ReadInternal(Stream stream, bool strict, DateTime now, out bool nullHeader)
            {
                nullHeader = false;

                byte[] checkValue;

                using (CheckedReadStream checkedStream = new CheckedReadStream(stream, new CRC32()))
                {
                    int count = 0;
                    while (true)
                    {
                        int field = BinaryReadUtils.ReadVariableLengthQuantityAsInt32(checkedStream);
                        if ((Fields)field == Fields.Terminator)
                        {
                            break;
                        }
                        string value = BinaryReadUtils.ReadStringUtf8(checkedStream);
                        count++;
                        switch ((Fields)field)
                        {
                            default:
                                if (strict)
                                {
                                    throw new InvalidDataException();
                                }
                                // ignore unrecognized header fields
                                break;

                            case Fields.Version:
                                // version field is optional, but must be first
                                if (count != 1)
                                {
                                    throw new InvalidDataException();
                                }
                                if (Int32.Parse(value) != SupportedVersionNumber)
                                {
                                    throw new InvalidDataException();
                                }
                                break;

                            case Fields.Subpath:
                                subpath = value; // must be validated at time of use
                                break;

                            case Fields.CreationTimeUtc:
                                try
                                {
                                    creationTimeUtc = ParseDateTime(value);
                                }
                                catch (Exception)
                                {
                                    if (strict)
                                    {
                                        throw;
                                    }
                                    creationTimeUtc = now;
                                }
                                break;

                            case Fields.LastWriteTimeUtc:
                                try
                                {
                                    lastWriteTimeUtc = ParseDateTime(value);
                                }
                                catch (Exception)
                                {
                                    if (strict)
                                    {
                                        throw;
                                    }
                                    lastWriteTimeUtc = now;
                                }
                                break;

                            case Fields.Attributes:
                                try
                                {
                                    attributes = (HeaderAttributes)UInt64.Parse(value);
                                }
                                catch (Exception)
                                {
                                    if (strict)
                                    {
                                        throw;
                                    }
                                }
                                break;

                            case Fields.SegmentName:
                                segmentName = value;
                                break;

                            case Fields.SegmentSerialNumber:
                                segmentSerialNumber = UInt64.Parse(value);
                                break;

                            case Fields.Range:
                                try
                                {
                                    range = RangeRecord.Parse(value);
                                }
                                catch (Exception)
                                {
                                    if (strict)
                                    {
                                        throw;
                                    }
                                    else
                                    {
                                        // invalid range - problem dealt with elsewhere
                                        range = new RangeRecord(-1, -1, -1);
                                    }
                                }
                                break;

                            case Fields.Digest:
                                try
                                {
                                    digest = Convert.FromBase64String(value);
                                }
                                catch (Exception)
                                {
                                    if (strict)
                                    {
                                        throw;
                                    }
                                    // else leave hash field null
                                }
                                break;
                        }
                    }

                    embeddedStreamLength = BinaryReadUtils.ReadVariableLengthQuantityAsInt64(checkedStream);

                    nullHeader = (count == 0) && (embeddedStreamLength == 0);

                    checkedStream.Close();
                    checkValue = checkedStream.CheckValue;
                }

                byte[] savedCheckValue = BinaryReadUtils.ReadBytes(stream, checkValue.Length);
                if (!ArrayEqual(checkValue, savedCheckValue))
                {
                    throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied, "Individual archived file header check values do not match");
                }

                try
                {
                    ValidateRecordInvariants(nullHeader);
                }
                catch (InvalidOperationException)
                {
                    throw new InvalidDataException(); // makes more sense when reading a file
                }
            }

            // Validate invariant conditions on the structure of a record. This conceptually
            // violates the layer of abstraction (should be done by clients of the struct),
            // but is more reliable to do it here, in one place, for all clients.
            private void ValidateRecordInvariants(bool nullHeader)
            {
                // special case for null header
                if (nullHeader)
                {
                    // (everything must be null)
                    if (!((subpath == null)
                        && (creationTimeUtc == default(DateTime))
                        && (lastWriteTimeUtc == default(DateTime))
                        && (attributes == default(HeaderAttributes))
                        && (embeddedStreamLength == 0)
                        && (segmentName == null)
                        && (segmentSerialNumber == 0)))
                    {
                        throw new InvalidOperationException();
                    }

                    return;
                }

                // require segmentName and segmentSerialNumber be coexistant
                if (!((segmentName != null) == (segmentSerialNumber != 0)))
                {
                    throw new InvalidOperationException();
                }

                // require exactly one of {either file, segment header}
                if (!((segmentName != null) != (subpath != null)))
                {
                    throw new InvalidOperationException();
                }

                // require no other values for segment header (implies file length == 0)
                if (segmentName != null)
                {
                    if (!((subpath == null)
                        && (creationTimeUtc == default(DateTime))
                        && (lastWriteTimeUtc == default(DateTime))
                        && (attributes == default(HeaderAttributes))
                        && (embeddedStreamLength == 0)))
                    {
                        throw new InvalidOperationException();
                    }
                }

                // directories never have a stream associated with them
                if (!(!((attributes & HeaderAttributes.Directory) != 0) || (embeddedStreamLength == 0)))
                {
                    throw new InvalidOperationException();
                }

                // range invariant
                if ((range != null) && (range.Length != embeddedStreamLength))
                {
                    throw new InvalidOperationException();
                }

                // ensure SHA2-512 hash array is correct length
                if ((digest != null) && (digest.Length != 512 / 8))
                {
                    throw new InvalidOperationException();
                }
            }

            internal static bool ValidFileHeaderToken(byte[] buffer)
            {
                return ArrayEqual(buffer, PackedFileHeaderToken);
            }

            internal int GetHeaderLength()
            {
                using (MemoryStream stream = new MemoryStream())
                {
                    Write(stream);
                    return (int)stream.Length;
                }
            }

            internal string Subpath
            {
                get
                {
                    return subpath.ToString();
                }
            }

            internal object SubpathObject
            {
                get
                {
                    return subpath;
                }
            }

            internal DateTime CreationTimeUtc
            {
                get
                {
                    return creationTimeUtc;
                }
            }

            internal DateTime LastWriteTimeUtc
            {
                get
                {
                    return lastWriteTimeUtc;
                }
            }

            internal HeaderAttributes Attributes
            {
                get
                {
                    return attributes;
                }
            }

            internal long EmbeddedStreamLength
            {
                get
                {
                    return embeddedStreamLength;
                }
            }

            internal string SegmentName
            {
                get
                {
                    return segmentName;
                }

                set
                {
                    segmentName = value;
                }
            }

            internal ulong SegmentSerialNumber
            {
                get
                {
                    return segmentSerialNumber;
                }

                set
                {
                    segmentSerialNumber = value;
                }
            }

            internal RangeRecord Range
            {
                get
                {
                    return range;
                }
            }

            internal long TotalFileLength
            {
                get
                {
                    return range == null ? embeddedStreamLength : range.TotalFileLength;
                }
            }

            internal byte[] Digest
            {
                get
                {
                    return digest;
                }
                set
                {
                    if ((value != null) && (value.Length != 512 / 8))
                    {
                        throw new ArgumentException();
                    }
                    digest = value;
                }
            }

            private class HashBlock : IDisposable
            {
                public readonly long sequenceNumber;
                public int height;
                public ConcurrentTasks.CompletionObject completionObject;
                public byte[] hash;

                public HashBlock(int height, long sequenceNumber)
                {
                    this.height = height;
                    this.sequenceNumber = sequenceNumber;
                }

                public void Dispose()
                {
                    if (completionObject != null)
                    {
                        completionObject.Dispose();
                        completionObject = null;
                    }
                }
            }

            internal void SetDigest(ConcurrentTasks concurrent, string root)
            {
                digest = null;

                string partialPath = subpath.ToString();
                const string Prefix = @".\";
                if (!partialPath.StartsWith(Prefix))
                {
                    throw new InvalidOperationException();
                }
                partialPath = partialPath.Substring(Prefix.Length);
                string fullPath = Path.Combine(root, partialPath);
                using (Stream controlStream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    // Merkle hash tree

                    byte[] leafPrefix = new byte[1] { 0x00 };
                    byte[] interiorPrefix = new byte[1] { 0x01 };

                    const int BlockLength = 65536;
                    long blocks = Math.Max((controlStream.Length + BlockLength - 1) / BlockLength, 1);

                    long leafSequenceNumbering = 1;
                    long interiorSequenceNumbering = 1;
                    Stack<HashBlock> partial = new Stack<HashBlock>();
                    try
                    {
                        for (long iEnum = 0; iEnum <= blocks; iEnum++)
                        {
                            // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                            // variable) in order to capture each value in the anonymous method.
                            // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                            long i = iEnum;

                            if (i < blocks)
                            {
                                HashBlock leaf = new HashBlock(0, leafSequenceNumbering++);
                                partial.Push(leaf);
                                concurrent.Do(
                                    String.Format("merkel-leaf-hash seq={0}", leaf.sequenceNumber),
                                    true/*desireCompletionObject*/,
                                    out leaf.completionObject,
                                    delegate(ConcurrentTasks.ITaskContext taskContext)
                                    {
                                        using (CryptoPrimitiveHashCheckValueGenerator check = new CryptoPrimitiveHashCheckValueGeneratorSHA2_512())
                                        {
                                            check.ProcessBlock(leafPrefix, 0, leafPrefix.Length);
                                            using (Stream taskStream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                                            {
                                                taskStream.Position = i * BlockLength;
                                                byte[] buffer = new byte[Math.Min(BlockLength, Constants.BufferSize)];
                                                int count = BlockLength;
                                                while (count > 0)
                                                {
                                                    int read = taskStream.Read(buffer, 0, Math.Min(count, buffer.Length));
                                                    if (read == 0)
                                                    {
                                                        break;
                                                    }
                                                    check.ProcessBlock(buffer, 0, read);
                                                    count -= read;
                                                }
                                            }
                                            leaf.hash = check.GetCheckValueAndClose();
                                        }
                                    },
                                    null,
                                    -1);
                            }

                            long cascade = i < blocks ? i : Int64.MaxValue;
                            while ((partial.Count > 1) && ((cascade & 1) != 0))
                            {
                                HashBlock right = partial.Pop();
                                HashBlock left = partial.Pop();
                                if (left.height == right.height)
                                {
                                    HashBlock parent = new HashBlock(right.height + 1, interiorSequenceNumbering++);
                                    partial.Push(parent);
                                    concurrent.Do(
                                        String.Format("merkel-parent-hash height={1} seq={0}", parent.sequenceNumber, parent.height),
                                        true/*desireCompletionObject*/,
                                        out parent.completionObject,
                                        delegate(ConcurrentTasks.ITaskContext taskContext)
                                        {
                                            using (CryptoPrimitiveHashCheckValueGenerator check = new CryptoPrimitiveHashCheckValueGeneratorSHA2_512())
                                            {
                                                check.ProcessBlock(interiorPrefix, 0, interiorPrefix.Length);

                                                left.completionObject.Wait();
                                                check.ProcessBlock(left.hash, 0, left.hash.Length);
                                                left.Dispose();

                                                right.completionObject.Wait();
                                                check.ProcessBlock(right.hash, 0, right.hash.Length);
                                                right.Dispose();

                                                parent.hash = check.GetCheckValueAndClose();
                                            }
                                        },
                                        null,
                                        -1);
                                }
                                else if (left.height > right.height)
                                {
                                    Debug.Assert(i == blocks);
                                    if (!(i == blocks))
                                    {
                                        left.Dispose();
                                        right.Dispose();
                                        throw new ApplicationException("program defect");
                                    }
                                    partial.Push(left);
                                    right.height++;
                                    partial.Push(right);
                                }
                                else
                                {
                                    Debug.Assert(false);
                                    left.Dispose();
                                    right.Dispose();
                                    throw new ApplicationException("program defect");
                                }

                                cascade >>= 1;
                            }
                        }

                        Debug.Assert(partial.Count == 1);
                        if (!(partial.Count == 1))
                        {
                            throw new ApplicationException("program defect");
                        }
                        HashBlock top = partial.Pop();
                        top.completionObject.Wait();
                        digest = top.hash;
                        top.Dispose();
                    }
                    finally
                    {
                        // only occurs for program defect or failure
                        while (partial.Count > 0)
                        {
                            partial.Pop().Dispose();
                        }
                    }
                }
            }
        }

        private static void PackOne(string file, Stream stream, string partialPathPrefix, PackedFileHeaderRecord.RangeRecord range, bool enableRetry, Context context, TextWriter trace)
        {
            bool directory = false;

            using (Stream inputStream = DoRetryable<Stream>(
                delegate
                {
                    try
                    {
                        if (Directory.Exists(file))
                        {
                            directory = true;
                            return null;
                        }
                        return new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    }
                    catch (PathTooLongException exception)
                    {
                        throw new PathTooLongException(String.Format("{0} (length={2}, path=\'{1}\')", exception.Message, file, file.Length));
                    }
                },
                delegate { return null; },
                delegate { },
                enableRetry,
                context,
                trace))
            {
                if ((inputStream != null) || directory)
                {
                    // write header

                    long embeddedStreamLength = 0;
                    if (!directory)
                    {
                        if (range == null)
                        {
                            embeddedStreamLength = inputStream.Length;
                            if (inputStream.Position != 0)
                            {
                                throw new InvalidOperationException(); // program defect
                            }
                        }
                        else
                        {
                            embeddedStreamLength = range.Length;
                            inputStream.Position = range.Start;
                        }
                    }
                    else
                    {
                        if (range != null)
                        {
                            throw new InvalidOperationException(); // program defect
                        }
                    }

                    PackedFileHeaderRecord header = new PackedFileHeaderRecord(
                        Path.Combine(partialPathPrefix, Path.GetFileName(file)),
                        !directory ? File.GetCreationTimeUtc(file) : default(DateTime),
                        !directory ? File.GetLastWriteTimeUtc(file) : default(DateTime),
                        PackedFileHeaderRecord.ToHeaderAttributes(File.GetAttributes(file)),
                        embeddedStreamLength,
                        range,
                        null/*digest*/);
                    header.Write(stream);


                    // write data

                    byte[] fileDataCheckValue;
                    using (CheckedWriteStream checkedStream = new CheckedWriteStream(stream, new CRC32()))
                    {
                        if (!directory)
                        {
                            byte[] buffer = new byte[Constants.BufferSize];
                            long bytesRemaining = embeddedStreamLength;
                            while (bytesRemaining > 0)
                            {
                                int bytesRead;
                                try
                                {
                                    int needed = (int)Math.Min(buffer.Length, bytesRemaining);
                                    bytesRead = inputStream.Read(buffer, 0, needed);
                                }
                                catch (Exception exception)
                                {
                                    throw new Exception(String.Format("{0} [file \"{1}\"]", exception.Message, file), exception);
                                }
                                checkedStream.Write(buffer, 0, bytesRead);
                                bytesRemaining -= bytesRead;
                            }
                        }

                        checkedStream.Close();
                        fileDataCheckValue = checkedStream.CheckValue;
                    }

                    stream.Write(fileDataCheckValue, 0, fileDataCheckValue.Length);
                }
            }
        }

        private static void PackRecursive(string sourceRootDirectory, Stream stream, Context context, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems, string partialPathPrefix, ref long addedCount)
        {
            WriteStatusLine(sourceRootDirectory);

            List<string> subdirectories = new List<string>();
            bool driveRoot = IsDriveRoot(sourceRootDirectory);
            foreach (string file in DoRetryable<string[]>(delegate { return Directory.GetFileSystemEntries(sourceRootDirectory); }, delegate { return new string[0]; }, null, context, null/*trace*/))
            {
                if (!driveRoot || !IsExcludedDriveRootItem(file))
                {
                    FileAttributes fileAttributes = DoRetryable<FileAttributes>(delegate { return File.GetAttributes(file); }, delegate { return FileAttributes.Normal; }, null, context, null/*trace*/);
                    if ((fileAttributes & FileAttributes.Directory) != 0)
                    {
                        subdirectories.Add(file);
                    }
                    else
                    {
                        if (!excludedItems.Contains(file.ToLowerInvariant())
                            && !excludedExtensions.Contains(Path.GetExtension(file).ToLowerInvariant()))
                        {
                            PackOne(file, stream, partialPathPrefix, null/*range*/, true/*enableRetry*/, context, null/*trace*/);
                            addedCount++;
                        }
                        else
                        {
                            Console.WriteLine("  SKIPPED FILE: {0}", file);
                        }
                    }
                }
            }

            foreach (string subdirectory in subdirectories)
            {
                if (!excludedItems.Contains(subdirectory.ToLowerInvariant()))
                {
                    long initialAddedCount = addedCount;

                    PackRecursive(subdirectory, stream, context, excludedExtensions, excludedItems, Path.Combine(partialPathPrefix, Path.GetFileName(subdirectory)), ref addedCount);

                    // for subdirectories, only if it is empty add it explicitly
                    if (addedCount == initialAddedCount)
                    {
                        PackOne(subdirectory, stream, partialPathPrefix, null/*range*/, true/*enableRetry*/, context, null/*trace*/);
                        addedCount++;
                    }
                }
                else
                {
                    Console.WriteLine("  SKIPPED SUBDIRECTORY: {0}", subdirectory);
                }
            }
        }

        internal static void Pack(string source, string targetFile, Context context, string[] args)
        {
            byte[] randomArchiveSignature = new byte[PackRandomSignatureLengthBytes];
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                rng.GetBytes(randomArchiveSignature);
            }

            InvariantStringSet excludedExtensions;
            InvariantStringSet excludedItems;
            GetExclusionArguments(args, out excludedExtensions, false/*relative*/, out excludedItems);

            if (!Directory.Exists(source))
            {
                throw new UsageException();
            }

            using (Stream fileStream = new FileStream(targetFile, FileMode.CreateNew, FileAccess.Write))
            {
                CryptoKeygroup keys = null;
                EncryptedFileContainerHeader fch = null;
                if (context.cryptoOption == EncryptionOption.Encrypt)
                {
                    CryptoMasterKeyCacheEntry entry = context.encrypt.GetDefaultMasterKeyEntry();
                    fch = new EncryptedFileContainerHeader(context.encrypt);
                    fch.passwordSalt = entry.PasswordSalt;
                    context.encrypt.algorithm.DeriveNewSessionKeys(entry.MasterKey, out fch.fileSalt, out keys);
                }

                StreamStack.DoWithStreamStack(
                    fileStream,
                    new StreamStack.StreamWrapMethod[]
                    {
                        delegate(Stream stream)
                        {
                            // see note and references about
                            // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                            if (context.cryptoOption == EncryptionOption.Encrypt)
                            {
                                return new TaggedWriteStream(stream, context.encrypt.algorithm.CreateMACGenerator(keys.SigningKey));
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if (context.cryptoOption == EncryptionOption.Encrypt)
                            {
                                // why write here? need to write salt within HMAC container
                                fch.Write(stream, context.encrypt.algorithm);
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if (context.cryptoOption == EncryptionOption.Encrypt)
                            {
                                return context.encrypt.algorithm.CreateEncryptStream(stream, keys.CipherKey, keys.InitialCounter);
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if (context.compressionOption == CompressionOption.Compress)
                            {
                                return new BlockedCompressStream(stream);
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            // total file CRC32 check value
                            return new TaggedWriteStream(stream, new CRC32());
                        }
                    },
                    delegate(Stream stream)
                    {
                        BinaryWriteUtils.WriteBytes(stream, new byte[1] { PackArchiveFixedHeaderNumber });

                        BinaryWriteUtils.WriteVariableLengthByteArray(stream, randomArchiveSignature);

                        BinaryWriteUtils.WriteVariableLengthQuantity(stream, 1); // single pack files have fixed sequence number

                        KeyValuePair<int, string>[] parameters = new KeyValuePair<int, string>[0];
                        foreach (KeyValuePair<int, string> parameter in parameters)
                        {
                            if (!(parameter.Key > 0))
                            {
                                throw new InvalidOperationException("assertion failed: parameter.Key > 0");
                            }
                            BinaryWriteUtils.WriteVariableLengthQuantity(stream, parameter.Key);
                        }
                        BinaryWriteUtils.WriteVariableLengthQuantity(stream, 0);

                        BinaryWriteUtils.WriteVariableLengthQuantity(stream, PackArchiveStructureTypeFiles);

                        long addedCount = 0;
                        PackRecursive(
                            source,
                            stream,
                            context,
                            excludedExtensions,
                            excludedItems,
                            ".",
                            ref addedCount);

                        PackedFileHeaderRecord.WriteNullHeader(stream);
                    });
            }

            EraseStatusLine();

            File.SetCreationTime(targetFile, context.now);
            File.SetLastWriteTime(targetFile, context.now);
        }

        internal struct UnpackedFileRecord
        {
            private string fullPath;
            private PackedFileHeaderRecord header;

            internal UnpackedFileRecord(string fullPath, PackedFileHeaderRecord header)
            {
                this.fullPath = fullPath;
                this.header = header;
            }

            internal string FullPath
            {
                get
                {
                    return fullPath;
                }
            }


            internal string ArchivePath
            {
                get
                {
                    return header.Subpath;
                }
            }

            internal DateTime CreationTimeUtc
            {
                get
                {
                    return header.CreationTimeUtc;
                }
            }

            internal DateTime LastWriteTimeUtc
            {
                get
                {
                    return header.LastWriteTimeUtc;
                }
            }

            internal long EmbeddedStreamLength
            {
                get
                {
                    return header.EmbeddedStreamLength;
                }
            }

            internal PackedFileHeaderRecord.HeaderAttributes Attributes
            {
                get
                {
                    return header.Attributes;
                }
            }

            internal string SegmentName
            {
                get
                {
                    return header.SegmentName;
                }
            }

            internal ulong SegmentSerialNumber
            {
                get
                {
                    return header.SegmentSerialNumber;
                }
            }

            internal PackedFileHeaderRecord.RangeRecord Range
            {
                get
                {
                    return header.Range;
                }
            }

            internal byte[] Digest
            {
                get
                {
                    return header.Digest;
                }
            }

            internal long TotalFileLength
            {
                get
                {
                    return header.TotalFileLength;
                }
            }
        }

        private class RangeSequenceException : ApplicationException
        {
            public RangeSequenceException(string message)
                : base(message)
            {
            }
        }

        private class DeferredMultiException : ApplicationException
        {
            private Exception[] innerExceptions = new Exception[0];

            public DeferredMultiException(Exception[] innerExceptions)
            {
                if (innerExceptions != null)
                {
                    this.innerExceptions = innerExceptions;
                }
            }

            public override string Message
            {
                get
                {
                    StringBuilder sb = new StringBuilder();
                    foreach (Exception exception in innerExceptions)
                    {
                        string one = exception.ToString().Replace(Environment.NewLine, ";");
                        sb.AppendLine(one);
                    }
                    return sb.ToString();
                }
            }
        }

        [Flags]
        internal enum UnpackMode
        {
            Parse = 0, // always implied

            SignatureOnly = 1 << 0,

            Unpack = 1 << 1,
            Resume = 1 << 2,
            ShowProgress = 1 << 3,
        }

        private static UnpackedFileRecord[] UnpackInternal(Stream fileStream, string targetDirectory, Context context, UnpackMode mode, out ulong segmentSerialNumberOut, out byte[] randomArchiveSignatureOut, TextWriter trace, IFaultInstance faultContainer, out ApplicationException[] deferredExceptions, string localSignaturePath)
        {
            List<ApplicationException> deferredExceptionsList = new List<ApplicationException>();

            try
            {
                bool writeFiles = (mode & UnpackMode.Unpack) == UnpackMode.Unpack;
                bool displayProgress = (mode & UnpackMode.ShowProgress) == UnpackMode.ShowProgress;
                bool resume = (mode & UnpackMode.Resume) == UnpackMode.Resume;
                bool signatureOnly = (mode & UnpackMode.SignatureOnly) == UnpackMode.SignatureOnly;
                if (signatureOnly && writeFiles)
                {
                    throw new ArgumentException();
                }

                IFaultInstance faultUnpackInternal = faultContainer.Select("UnpackInternal");

                ulong segmentSerialNumber = 0;
                byte[] randomArchiveSignature = new byte[0];
                CheckedReadStream localSignature = null;

                List<UnpackedFileRecord> unpackedFileRecords = new List<UnpackedFileRecord>();

                if (fileStream.Position != 0)
                {
                    throw new InvalidOperationException();
                }


                CryptoKeygroup keys = null;
                EncryptedFileContainerHeader fch = null;
                if (context.cryptoOption == EncryptionOption.Decrypt)
                {
                    fch = new EncryptedFileContainerHeader(fileStream, true/*peek*/, context.decrypt);
                    context.decrypt.algorithm.DeriveSessionKeys(context.decrypt.GetMasterKeyEntry(fch.passwordSalt, fch.rfc2898Rounds).MasterKey, fch.fileSalt, out keys);
                }

                // Using Moxie Marlinspike's "doom principle": validate the MAC before ANY other
                // action is taken. (http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/)
                bool macValidated = false;
                if (!context.doNotPreValidateMAC && (context.cryptoOption != EncryptionOption.None))
                {
                    StreamStack.DoWithStreamStack(
                        fileStream,
                        new StreamStack.StreamWrapMethod[]
                        {
                            delegate(Stream stream)
                            {
                                // see note and references about
                                // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                return new TaggedReadStream(stream, context.decrypt.algorithm.CreateMACGenerator(keys.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                            },
                        },
                        delegate(Stream stream)
                        {
                            ReadAndDiscardEntireStream(stream);
                        });

                    macValidated = true;
                }

                fileStream.Position = 0;

                StreamStack.DoWithStreamStack(
                    fileStream,
                    new StreamStack.StreamWrapMethod[]
                    {
                        delegate(Stream stream)
                        {
                            if (localSignaturePath != null)
                            {
                                localSignature = new CheckedReadStream(stream, context.decrypt.algorithm.CreateLocalSignatureMACGenerator(keys.LocalSignatureKey));
                            }
                            return localSignature;
                        },
                        delegate(Stream stream)
                        {
                            // see note and references about
                            // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                            if (context.cryptoOption == EncryptionOption.Decrypt)
                            {
                                if (!macValidated)
                                {
                                    return new TaggedReadStream(stream, context.decrypt.algorithm.CreateMACGenerator(keys.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                }
                                else
                                {
                                    return new ReadStreamHoldShort(stream, context.decrypt.algorithm.MACLengthBytes);
                                }
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if (context.cryptoOption == EncryptionOption.Decrypt)
                            {
                                // why re-read here? need to read salt within HMAC container
                                EncryptedFileContainerHeader fch2 = new EncryptedFileContainerHeader(stream, false/*peek*/, context.decrypt);
                                if (!fch2.Equals(fch))
                                {
                                    throw new InvalidOperationException();
                                }
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if (context.cryptoOption == EncryptionOption.Decrypt)
                            {
                                return context.decrypt.algorithm.CreateDecryptStream(stream, keys.CipherKey, keys.InitialCounter);
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if (context.compressionOption == CompressionOption.Decompress)
                            {
                                return new BlockedDecompressStream(stream);
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            // total file CRC32 check value
                            return new TaggedReadStream(stream, new CRC32(), "File check values do not match - file is damaged");
                        }
                    },
                    delegate(Stream stream)
                    {
                        if (trace != null)
                        {
                            trace.WriteLine("UnpackInternal writeFiles={0}, resume={1}", writeFiles, resume);
                        }

                        byte[] headerNumber = BinaryReadUtils.ReadBytes(stream, 1);
                        if (trace != null)
                        {
                            trace.WriteLine("HeaderNumber: {0}", headerNumber[0]);
                        }
                        if (headerNumber[0] != PackArchiveFixedHeaderNumber)
                        {
                            throw new InvalidDataException(); // unrecognized format
                        }

                        randomArchiveSignature = BinaryReadUtils.ReadVariableLengthByteArray(stream);
                        if (trace != null)
                        {
                            trace.WriteLine("Signature: {0}", LogWriter.ScrubSecuritySensitiveValue(randomArchiveSignature));
                        }

                        segmentSerialNumber = BinaryReadUtils.ReadVariableLengthQuantityAsUInt64(stream);
                        if (trace != null)
                        {
                            trace.WriteLine("SerialNumber: {0}", segmentSerialNumber);
                        }

                        if (signatureOnly)
                        {
                            ReadAndDiscardEntireStream(stream);
                            return;
                        }

                        int structureType;
                        List<KeyValuePair<int, string>> parameters = new List<KeyValuePair<int, string>>();
                        while (true)
                        {
                            int parameterType = BinaryReadUtils.ReadVariableLengthQuantityAsInt32(stream);
                            if (parameterType == 0)
                            {
                                if (trace != null)
                                {
                                    trace.WriteLine("New pack format");
                                }
                                break;
                            }
                            else if ((parameterType == PackArchiveStructureTypeManifest) || (parameterType == PackArchiveStructureTypeFiles))
                            {
                                if (parameters.Count > 0)
                                {
                                    throw new InvalidDataException("Expandable parameter area does not conform to old or new archive format");
                                }
                                structureType = parameterType;
                                if (trace != null)
                                {
                                    trace.WriteLine("Old pack format -- invoking hack");
                                }
                                goto TransitionalHack;
                            }
                            else
                            {
                                string value = BinaryReadUtils.ReadStringUtf8(stream);
                                parameters.Add(new KeyValuePair<int, string>(parameterType, value));
                            }
                        }

                        /*int */
                        structureType = BinaryReadUtils.ReadVariableLengthQuantityAsInt32(stream);
                    TransitionalHack:
                        if (trace != null)
                        {
                            trace.WriteLine("StructureType: {0}", structureType);
                        }
                        if ((structureType != PackArchiveStructureTypeManifest)
                            && (structureType != PackArchiveStructureTypeFiles))
                        {
                            throw new InvalidDataException(); // unrecognized format
                        }

                        if (writeFiles)
                        {
                            Directory.CreateDirectory(targetDirectory);
                        }

                        bool fileDataOmitted = false;
                        string currentSegmentName = null;
                        ulong currentSegmentSerialNumber = 0;
                        bool firstHeader = true;
                        bool firstHeaderWasSegment = false;
                        string currentDisplayDirectory = null;
                        //
                        string lastSubpath = null;
                        PackedFileHeaderRecord.RangeRecord lastRange = null;
                        //
                        while (true)
                        {
                            byte[] startToken = BinaryReadUtils.ReadBytes(stream, PackedFileHeaderRecord.HeaderTokenLength);
                            if (!PackedFileHeaderRecord.ValidFileHeaderToken(startToken))
                            {
                                throw new InvalidDataException("Unexpected value for start token");
                            }

                            PackedFileHeaderRecord header = PackedFileHeaderRecord.Read(stream, false/*strict*/, context.now);
                            if (header == PackedFileHeaderRecord.NullHeaderRecord)
                            {
                                if (trace != null)
                                {
                                    trace.WriteLine("Header[Terminator]");
                                }
                                break;
                            }

                            // if any segment headers exist (== manifest file), the first record in file must be one
                            if (firstHeader)
                            {
                                if (header.SegmentName != null)
                                {
                                    firstHeaderWasSegment = true;
                                }
                            }
                            else
                            {
                                if (!firstHeaderWasSegment && (header.SegmentName != null))
                                {
                                    throw new InvalidDataException();
                                }
                            }
                            firstHeader = false;

                            // process segment header records differently
                            if (header.SegmentName != null)
                            {
                                if (trace != null)
                                {
                                    trace.WriteLine("Header[SegmetName={0}, SegmentSerialNumber={1}]", header.SegmentName, header.SegmentSerialNumber);
                                }

                                if (structureType != PackArchiveStructureTypeManifest)
                                {
                                    throw new InvalidDataException(); // segment records not permitted in files structure
                                }

                                // do not write any files "archived" in the manifest
                                writeFiles = false;
                                fileDataOmitted = true;

                                currentSegmentName = header.SegmentName;
                                currentSegmentSerialNumber = header.SegmentSerialNumber;

                                continue;
                            }

                            // normal file header record processing

                            if (trace != null)
                            {
                                trace.WriteLine("Header[Path=\"{0}\", ESL={1}, Created={2}, LastWrite={3}, Attr={4}, Range={5}]", header.Subpath, header.EmbeddedStreamLength, header.CreationTimeUtc, header.LastWriteTimeUtc, (int)header.Attributes, header.Range);
                            }

                            IFaultInstance faultFileHeader = faultUnpackInternal.Select("FileHeader", header.Subpath);

                            // segment name and serial are written as a special header record.
                            // this is not exposed to caller; instead, each proper file record is
                            // annotated with the segment name and serial number.
                            header.SegmentName = currentSegmentName;
                            header.SegmentSerialNumber = currentSegmentSerialNumber;

                            string[] pathParts = header.Subpath.Split(new char[] { '\\' });
                            if (!pathParts[0].Equals("."))
                            {
                                throw new ApplicationException("Invalid relative path found in stream");
                            }
                            string fullPath = targetDirectory;
                            for (int i = 1; i < pathParts.Length; i++)
                            {
                                string pathPart = pathParts[i];
                                if (String.IsNullOrEmpty(pathPart) || (pathPart == ".") || (pathPart == ".."))
                                {
                                    throw new ApplicationException("Illegal step found in path");
                                }
                                fullPath = Path.Combine(fullPath, pathPart);
                                if (i == pathParts.Length - 2) // last directory component
                                {
                                    if (displayProgress)
                                    {
                                        if (!String.Equals(currentDisplayDirectory, fullPath))
                                        {
                                            currentDisplayDirectory = fullPath;
                                            WriteStatusLine(currentDisplayDirectory);
                                        }
                                    }

                                    if (writeFiles)
                                    {
                                        Directory.CreateDirectory(fullPath);
                                    }
                                }
                            }

                            if (String.Equals(header.Subpath, lastSubpath, StringComparison.OrdinalIgnoreCase))
                            {
                                // a file split into multiple ranges must have consistent range information
                                // for each entry.
                                if (((lastRange == null) != (header.Range == null))
                                    || (lastRange.TotalFileLength != header.Range.TotalFileLength)
                                    || (lastRange.End + 1 != header.Range.Start))
                                {
                                    if (trace != null)
                                    {
                                        trace.WriteLine("Error: inconsistent ranges, last={0}, current={1} (lastSubpath={2}, currentSubpath={3})", lastRange, header.Range, lastSubpath, header.Subpath);
                                    }
                                    throw new InvalidDataException();
                                }
                            }
                            lastSubpath = header.Subpath;
                            lastRange = header.Range;

                            if (!fileDataOmitted) // i.e. not a manifest
                            {
                                byte[] fileDataCheckValue;
                                using (CheckedReadStream checkedStream = new CheckedReadStream(stream, new CRC32()))
                                {
                                    bool directory = (header.Attributes & PackedFileHeaderRecord.HeaderAttributes.Directory) != 0;
                                    if (writeFiles && directory)
                                    {
                                        Directory.CreateDirectory(fullPath);
                                    }

                                    Stream output;
                                    if (writeFiles && !directory)
                                    {
                                        if (header.Range == null)
                                        {
                                            output = null;

                                            // for simple files - always create (fail if it exists)
                                            try
                                            {
                                                output = new FileStream(fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                                                if (trace != null)
                                                {
                                                    trace.WriteLine("  [simple] created \"{0}\"", fullPath);
                                                }
                                            }
                                            catch (Exception exception)
                                            {
                                                // permit file to exist if "resume" specified - do nothing (outputX remains null)
                                                if (resume)
                                                {
                                                    long length = GetFileLengthNoError(fullPath);
                                                    if (length != header.EmbeddedStreamLength)
                                                    {
                                                        // File may have been written incompletely - rewrite
                                                        // (It could also be some old or updated version fo the file -
                                                        // but we're assuming user knows what he's doing of specifying
                                                        // "resume" mode.)
                                                        output = new FileStream(fullPath, FileMode.Create, FileAccess.Write, FileShare.None);
                                                        if (trace != null)
                                                        {
                                                            trace.WriteLine("  [simple] replaced \"{0}\" (old length {1}) [resume mode]", fullPath, length);
                                                        }
                                                    }
                                                    else
                                                    {
                                                        if (trace != null)
                                                        {
                                                            trace.WriteLine("  [simple] skipped preexisting \"{0}\" (old length={1}) [resume mode]", fullPath, length);
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    if (trace != null)
                                                    {
                                                        trace.WriteLine("  [simple] failed: \"{0}\"", exception.Message);
                                                    }
                                                    throw; // for non-"resume": always an error if file already exists
                                                }
                                            }
                                        }
                                        else
                                        {
                                            // for ranged files - create if needed or open existing.
                                            // it would be nice to use FileMode.CreateNew for the first segment and
                                            // FileMode.Open for subsequent ones, since that would be more precise,
                                            // but since ranges span archive segments, this method will exit and be
                                            // reinvoked between ranges, and plumbing the state up to the top level
                                            // caller to check for this is not worth it.

                                            // IMPORTANT: for the following to work, all ranged segments applying to a
                                            // given target file must be done SERIALIZED and IN ORDER, so that the
                                            // file length is always a correct indicator of what has not been done yet.
                                            // This is the responsibility of the caller that has specified
                                            // UnpackMode.Unpack, which is currently ValidateOrUnpackDynamicInternal().

                                            // if "resume" specified, we detect whether the file was completely
                                            // written by comparing the file's length with the range length.
                                            // (do not check timestamps because they may be incorrect if code was aborted
                                            // while in the loop below, i.e. before timestamp setting part is reached.
                                            // we assume the user knows what he's doing specifying "resume".)
                                            long length = GetFileLengthNoError(fullPath);
                                            if (length == header.Range.TotalFileLength)
                                            {
                                                if (trace != null)
                                                {
                                                    trace.WriteLine("  [ranged] skipped: \"{0}\" (old length={1})", fullPath, length);
                                                }
                                                output = null;
                                            }
                                            else
                                            {
                                                if (File.Exists(fullPath))
                                                {
                                                    if ((File.GetAttributes(fullPath) & FileAttributes.ReadOnly) != 0)
                                                    {
                                                        File.SetAttributes(fullPath, File.GetAttributes(fullPath) & ~FileAttributes.ReadOnly);
                                                        // will be restored again at end of this range write pass
                                                    }
                                                }

                                                if (trace != null)
                                                {
                                                    trace.WriteLine("  [ranged] updating: \"{0}\" (old length={1})", fullPath, length);
                                                }
                                                output = new FileStream(fullPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        output = null;
                                    }

                                    if (writeFiles && (header.Range != null) && (output != null))
                                    {
                                        if (output.Length < header.Range.Start)
                                        {
                                            if (trace != null)
                                            {
                                                trace.WriteLine("Range update failed: file length {0} less than range start {1} [probably previous segment missing or defect in sequencing code]", output.Length, header.Range.Start);
                                            }
                                            deferredExceptionsList.Add(new RangeSequenceException(String.Format("Update to file \"{0}\" failed - part of file content is missing", fullPath)));

                                            // cancel writing of this file
                                            output.Close();
                                            output = null;
                                        }
                                    }

                                    IFaultInstance faultWrite = faultFileHeader.Select("Write");
                                    IFaultPredicate faultWritePosition = faultWrite.SelectPredicate("Position");

                                    using (output)
                                    {
                                        byte[] buffer = new byte[Constants.BufferSize];
                                        long length = header.EmbeddedStreamLength;
                                        if (directory && (length != 0))
                                        {
                                            throw new InvalidDataException();
                                        }
                                        if (writeFiles && (header.Range != null))
                                        {
                                            if (length != header.Range.Length)
                                            {
                                                throw new InvalidDataException();
                                            }
                                            if (output != null)
                                            {
                                                // Do not set file length [output.SetLength(header.Range.TotalFileLength);]
                                                // that is how we know how much has been written (for "resume" mode - see above)
                                                output.Position = header.Range.Start;
                                            }
                                        }
                                        while (length > 0)
                                        {
                                            long lengthOne = Math.Min(length, buffer.Length);
                                            int read = checkedStream.Read(buffer, 0, (int)lengthOne);
                                            if (read != lengthOne)
                                            {
                                                throw new IOException("Unexpected end of stream");
                                            }
                                            if (output != null)
                                            {
                                                output.Write(buffer, 0, (int)lengthOne);

                                                faultWritePosition.Test(output.Position);
                                            }
                                            length -= lengthOne;
                                        }

                                        if (output != null)
                                        {
                                            if (trace != null)
                                            {
                                                trace.WriteLine("  final: length={0}", output.Length);
                                            }
                                        }
                                    }

                                    checkedStream.Close();
                                    fileDataCheckValue = checkedStream.CheckValue;
                                }

                                if (writeFiles)
                                {
                                    try
                                    {
                                        if (header.CreationTimeUtc != default(DateTime))
                                        {
                                            File.SetCreationTimeUtc(fullPath, header.CreationTimeUtc);
                                        }
                                        if (header.LastWriteTimeUtc != default(DateTime))
                                        {
                                            File.SetLastWriteTime(fullPath, header.LastWriteTimeUtc);
                                        }
                                        // do this last - may include read-only
                                        File.SetAttributes(fullPath, File.GetAttributes(fullPath) | (PackedFileHeaderRecord.ToFileAttributes(header.Attributes) & ~FileAttributes.Directory));
                                    }
                                    catch (Exception exception)
                                    {
                                        if (trace != null)
                                        {
                                            trace.WriteLine("  exception updating timestamps and attributes: {0}", exception);
                                        }
                                    }
                                }

                                byte[] savedFileDataCheckValue = BinaryReadUtils.ReadBytes(stream, fileDataCheckValue.Length);
                                if (!ArrayEqual(fileDataCheckValue, savedFileDataCheckValue))
                                {
                                    throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied, "Individual archived file data check values do not match");
                                }
                            }

                            unpackedFileRecords.Add(new UnpackedFileRecord(fullPath, header));
                        }

                        BinaryReadUtils.RequireAtEOF(stream);
                    });


                if (displayProgress)
                {
                    EraseStatusLine();
                }

                if (localSignaturePath != null)
                {
                    CheckLocalSignature(localSignaturePath, localSignature);
                }

                segmentSerialNumberOut = segmentSerialNumber;
                randomArchiveSignatureOut = randomArchiveSignature;
                return unpackedFileRecords.ToArray();
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.Write("UnpackInternal exception occurred: {0}", exception);
                }
                throw;
            }
            finally
            {
                deferredExceptions = deferredExceptionsList.Count > 0 ? deferredExceptionsList.ToArray() : null;
            }
        }

        internal static void Unpack(string sourceFile, string targetDirectory, Context context)
        {
            ulong segmentSerialNumber;
            byte[] randomArchiveSignature;
            ApplicationException[] deferredExceptions;
            using (Stream fileStream = new FileStream(sourceFile, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                UnpackInternal(fileStream, targetDirectory, context, UnpackMode.Unpack | UnpackMode.ShowProgress, out segmentSerialNumber, out randomArchiveSignature, null/*trace*/, context.faultInjectionRoot.Select("UnpackInternal"), out deferredExceptions, null/*localSignaturePath*/);
            }
            if (deferredExceptions != null)
            {
                throw new DeferredMultiException(deferredExceptions);
            }
        }

        internal static void Dumppack(string sourcePattern, Context context)
        {
            IFaultInstance faultDumppack = context.faultInjectionRoot.Select("Dumppack");

            string fileName;
            bool remote;
            using (IArchiveFileManager fileManager = GetArchiveFileManager(sourcePattern, out fileName, out remote, context))
            {
                List<string> sourceFileList = new List<string>();
                if (FileNamePatternMatch.ContainsWildcards(sourcePattern))
                {
                    FileNamePatternMatch matcher = new FileNamePatternMatch(Path.GetFileName(sourcePattern));
                    foreach (string file in fileManager.GetFileNames(null, fileManager.GetMasterTrace()))
                    {
                        if (matcher.IsMatch(file))
                        {
                            sourceFileList.Add(file);
                        }
                    }
                }
                else
                {
                    sourceFileList.Add(fileName);
                }

                foreach (string sourceFile in sourceFileList)
                {
                    if (sourceFileList.Count > 1)
                    {
                        Console.WriteLine("FILE: \"{0}\"", sourceFile);
                    }

                    ulong serialNumber;
                    byte[] randomArchiveSignature;
                    UnpackedFileRecord[] files;
                    using (ILocalFileCopy fileRef = fileManager.Read(sourceFile, null/*progressTracker*/, fileManager.GetMasterTrace()))
                    {
                        using (Stream stream = fileRef.Read())
                        {
                            ApplicationException[] deferredExceptions;
                            files = UnpackInternal(stream, ".", context, UnpackMode.Parse, out serialNumber, out randomArchiveSignature, null/*trace*/, faultDumppack, out deferredExceptions, null/*localSignaturePath*/);
                            if (deferredExceptions != null)
                            {
                                throw new DeferredMultiException(deferredExceptions);
                            }
                        }
                    }

                    Console.WriteLine("SERIAL: {0}; SIGNATURE: {1}", serialNumber, LogWriter.ScrubSecuritySensitiveValue(randomArchiveSignature));

                    int index = 0;
                    string lastSegment = null;
                    foreach (UnpackedFileRecord file in files)
                    {
                        if (!String.Equals(lastSegment, file.SegmentName))
                        {
                            lastSegment = file.SegmentName;
                            Console.WriteLine(" [{0}: {1}]", lastSegment, file.SegmentSerialNumber);
                        }

                        string attrs = String.Empty;
                        foreach (KeyValuePair<PackedFileHeaderRecord.HeaderAttributes, char> symbol in PackedFileHeaderRecord.AttributeSymbolMapping)
                        {
                            attrs = attrs + ((file.Attributes & symbol.Key) != 0 ? new String(symbol.Value, 1) : "-");
                        }

                        const string TimeStampFormat = "s";

                        Console.WriteLine(" {5,8} {0,-6} {1} {2} {3} {4}",
                            FileSizeString(file.TotalFileLength),
                            file.CreationTimeUtc.ToLocalTime().ToString(TimeStampFormat),
                            file.LastWriteTimeUtc.ToLocalTime().ToString(TimeStampFormat),
                            attrs,
                            file.ArchivePath,
                            ++index);
                        if (file.Range != null)
                        {
                            Console.WriteLine("   {0}", file.Range);
                        }
                        if (file.Digest != null)
                        {
                            Console.WriteLine("   {0}", HexUtility.HexEncode(file.Digest));
                        }
                    }

                    if (sourceFileList.Count > 1)
                    {
                        Console.WriteLine();
                    }
                }
            }
        }

        private const string DynPackManifestName = "0";
        private const string DynPackBackupPrefix = "-";
        private const string DynPackManifestNameOld = DynPackBackupPrefix + "0";

        private const string DynPackFileExtension = ".dynpack";
        private const string DynPackTempFileExtension = ".tmp";

        private const string DynPackTraceFilePrefix = "dynpacktrace";
        private const string DynUnpackTraceFilePrefix = "dynunpacktrace";
        private const string DynPackManifestLogFileExtension = ".log";
        private const string DynPackManifestLogFileExtensionOld = ".previous.log";

        public abstract class FilePath /*: IComparable<FilePath>, IEquatable<FilePath>*/
        {
            public abstract string Step { get; }
            public abstract FilePath Parent { get; }

            private const int StepsToReserve = 8;
            public override string ToString()
            {
                string[] steps = Steps();

                int chars = -1; // no separator at start of path
                for (int i = 0; i < steps.Length; i++)
                {
                    chars = chars + 1/*separator*/ + steps[i].Length;
                }

                StringBuilder builder = new StringBuilder(chars);
                builder.Append(steps[0]);
                for (int i = 1; i < steps.Length; i++)
                {
                    builder.Append('\\');
                    builder.Append(steps[i]);
                }
                if (chars != builder.Length)
                {
                    throw new InvalidOperationException("Defect in FilePathBase.ToString()");
                }
                return builder.ToString();
            }

            //public static implicit operator string(FilePath path)
            //{
            //    return path.ToString();
            //}

            //public override int GetHashCode()
            //{
            //    return ToString().GetHashCode();
            //}

            //public override bool Equals(object obj)
            //{
            //    FilePath other;
            //    if ((other = obj as FilePath) != null)
            //    {
            //        return String.Equals(this.ToString(), other.ToString());
            //    }
            //    return base.Equals(obj);
            //}

            //int IComparable<FilePath>.CompareTo(FilePath other)
            //{
            //    List<FilePath> leftSteps = new List<FilePath>(StepsToReserve);
            //    List<FilePath> rightSteps = new List<FilePath>(StepsToReserve);
            //    FilePath step;
            //    step = this;
            //    while (step != null)
            //    {
            //        leftSteps.Add(step);
            //        step = step.Parent();
            //    }
            //    step = other;
            //    while (step != null)
            //    {
            //        rightSteps.Add(step);
            //        step = step.Parent();
            //    }
            //    int left = leftSteps.Count - 1;
            //    int right = rightSteps.Count - 1;
            //    while ((left >= 0) && (right >= 0))
            //    {
            //        int stepCompare = String.Compare(leftSteps[left].Step(), rightSteps[right].Step(), StringComparison.OrdinalIgnoreCase);
            //        if (stepCompare != 0)
            //        {
            //            return stepCompare;
            //        }
            //    }
            //    if (left > 0)
            //    {
            //        return 1;
            //    }
            //    else if (right > 0)
            //    {
            //        return -1;
            //    }
            //    return 0;
            //}

            //bool IEquatable<FilePath>.Equals(FilePath other)
            //{
            //    return 0 == ((IComparable<FilePath>)this).CompareTo(other);
            //}

            public string[] Steps()
            {
                int stepCount = 0;

                FilePath step = this;
                while (step != null)
                {
                    stepCount++;
                    step = step.Parent;
                }

                string[] steps = new string[stepCount];

                int i = stepCount - 1;
                step = this;
                while (step != null)
                {
                    steps[i--] = step.Step;
                    step = step.Parent;
                }

                return steps;
            }

            public static FilePath Create(FilePath parent, string file)
            {
                return new FilePathItem(parent, file);
            }

            public static FilePath Create(string path)
            {
                return (new FilePathItem.Factory()).Create(path); // create one-off
            }

            public static FilePath Create(FilePathItem.Factory factory, string path)
            {
                return factory.Create(path);
            }
        }

        private class FilePathRoot : FilePath
        {
            private readonly string file;

            public FilePathRoot(string file)
            {
                this.file = file;
            }

            public override string Step { get { return file; } }
            public override FilePath Parent { get { return null; } }
        }

        public class FilePathItem : FilePath
        {
            private readonly FilePath parent;
            private readonly string file;

            public FilePathItem(FilePath parent, string file)
            {
                this.parent = parent;
                this.file = file;
            }

            public override string Step { get { return file; } }
            public override FilePath Parent { get { return parent; } }

            public class Factory // last used item
            {
                private List<FilePath> current = new List<FilePath>();

                public FilePath Create(string path)
                {
                    string[] steps = path.Split(new char[] { '\\' });

                    int i;
                    for (i = 0; (i < current.Count) && (i < steps.Length); i++)
                    {
                        if (!steps[i].Equals(current[i].Step, StringComparison.OrdinalIgnoreCase))
                        {
                            break;
                        }
                    }

                    FilePath step = null;
                    if (i > 0)
                    {
                        step = current[i - 1];
                    }

                    current.RemoveRange(i, current.Count - i);
                    for (; i < steps.Length; i++)
                    {
                        step = i == 0 ? (FilePath)new FilePathRoot(steps[i]) : (FilePath)new FilePathItem(step, steps[i]);
                        current.Add(step);
                    }

                    if (!step.ToString().Equals(path, StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException("Defect in FilePathItem.Factory.Create(string)");
                    }

                    return step;
                }
            }
        }

        private static int dynpackDiagnosticSerialNumberGenerator;

        private class SegmentRecord
        {
            private string name;
            private OneWaySwitch dirty = new OneWaySwitch();
            internal int? start;
            private readonly int diagnosticSerialNumber = Interlocked.Increment(ref dynpackDiagnosticSerialNumberGenerator);
            private ulong serialNumber;
            internal long estimatedDataLengthInformationalOnly; // for status display - not to be relied upon for correctness

            internal SegmentRecord()
            {
                dirty.Set();
            }

            internal SegmentRecord(string Name, ulong serialNumber)
            {
                this.name = Name;
                this.serialNumber = serialNumber;
            }

            internal string Name
            {
                get
                {
                    return name;
                }

                set
                {
                    name = value;
                    dirty.Set();
                }
            }

            internal OneWaySwitch Dirty
            {
                get
                {
                    return dirty;
                }
            }

            internal ulong SerialNumber
            {
                get
                {
                    if (serialNumber == 0)
                    {
                        // program defect - number was never set properly
                        throw new InvalidOperationException();
                    }
                    return serialNumber;
                }
                set
                {
                    serialNumber = value;
                }
            }

            internal string DiagnosticSerialNumber
            {
                get
                {
                    byte[] four = new byte[4];
                    four[0] = (byte)(diagnosticSerialNumber >> 24);
                    four[1] = (byte)(diagnosticSerialNumber >> 16);
                    four[2] = (byte)(diagnosticSerialNumber >> 8);
                    four[3] = (byte)diagnosticSerialNumber;
                    return String.Concat("seg0x", HexUtility.HexEncode(four));
                }
            }
        }

        private class FileRecord
        {
            private SegmentRecord segment;
            private readonly PackedFileHeaderRecord header;
            private int? headerOverhead;

            private readonly int diagnosticSerialNumber = Interlocked.Increment(ref dynpackDiagnosticSerialNumberGenerator);

            internal FileRecord(SegmentRecord segment, FilePath partialPath, DateTime creationTimeUtc, DateTime lastWriteTimeUtc, PackedFileHeaderRecord.HeaderAttributes attributes, long embeddedStreamLength, PackedFileHeaderRecord.RangeRecord range, byte[] digest)
            {
                this.segment = segment;
                this.header = new PackedFileHeaderRecord(partialPath, creationTimeUtc, lastWriteTimeUtc, attributes, embeddedStreamLength, range, digest);
            }

            internal FileRecord(FileRecord original)
                : this(original.Segment, original.PartialPath, original.CreationTimeUtc, original.LastWriteTimeUtc, original.Attributes, original.EmbeddedStreamLength, original.Range, original.Digest)
            {
            }

            private FileRecord()
            {
                throw new NotSupportedException();
            }

            internal SegmentRecord Segment
            {
                get
                {
                    return segment;
                }

                set
                {
                    segment = value;
                }
            }

            internal FilePath PartialPath
            {
                get
                {
                    return (FilePath)header.SubpathObject;
                }
            }

            internal DateTime CreationTimeUtc
            {
                get
                {
                    return header.CreationTimeUtc;
                }
            }

            internal DateTime LastWriteTimeUtc
            {
                get
                {
                    return header.LastWriteTimeUtc;
                }
            }

            internal PackedFileHeaderRecord.HeaderAttributes Attributes
            {
                get
                {
                    return header.Attributes;
                }
            }

            internal long EmbeddedStreamLength
            {
                get
                {
                    return header.EmbeddedStreamLength;
                }
            }

            internal int HeaderOverhead
            {
                get
                {
                    if (!headerOverhead.HasValue)
                    {
                        headerOverhead = header.GetHeaderLength();
                    }
                    return headerOverhead.Value;
                }
            }

            internal PackedFileHeaderRecord.RangeRecord Range
            {
                get
                {
                    return header.Range;
                }
            }

            internal byte[] Digest
            {
                get
                {
                    return header.Digest;
                }
                set
                {
                    header.Digest = value;
                }
            }

            internal void SetDigest(ConcurrentTasks concurrent, string root)
            {
                header.SetDigest(concurrent, root);

                headerOverhead = null; // digests computed later, on demand; reset overhead as length may have changed
            }

            internal void WriteHeader(Stream stream)
            {
                header.SegmentName = null;
                header.SegmentSerialNumber = 0;

                header.Write(stream);
            }

            internal string DiagnosticSerialNumber
            {
                get
                {
                    byte[] four = new byte[4];
                    four[0] = (byte)(diagnosticSerialNumber >> 24);
                    four[1] = (byte)(diagnosticSerialNumber >> 16);
                    four[2] = (byte)(diagnosticSerialNumber >> 8);
                    four[3] = (byte)diagnosticSerialNumber;
                    return String.Concat("file0x", HexUtility.HexEncode(four));
                }
            }
        }

        private static void ItemizeFilesRecursive(List<FileRecord> files, string sourceRootDirectory, long? largeFileSegmentSize, Context context, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems, FilePath partialPathPrefix, TextWriter trace)
        {
            WriteStatusLine(sourceRootDirectory);

            List<string> subdirectories = new List<string>();
            bool driveRoot = IsDriveRoot(sourceRootDirectory);
            foreach (string file in DoRetryable<string[]>(delegate { return Directory.GetFileSystemEntries(sourceRootDirectory); }, delegate { return new string[0]; }, null, context, null/*trace*/))
            {
                if (!driveRoot || !IsExcludedDriveRootItem(file))
                {
                    FileAttributes fileAttributes = DoRetryable<FileAttributes>(delegate { return File.GetAttributes(file); }, delegate { return FileAttributes.Normal; }, null, context, null/*trace*/);
                    if ((fileAttributes & FileAttributes.Directory) != 0)
                    {
                        subdirectories.Add(file);
                    }
                    else
                    {
                        if (!excludedItems.Contains(file.ToLowerInvariant())
                            && !excludedExtensions.Contains(Path.GetExtension(file).ToLowerInvariant()))
                        {
                            long inputStreamLength = GetFileLengthRetryable(file, context, trace);
                            if (inputStreamLength >= 0)
                            {
                                FilePath partialPath = FilePathItem.Create(partialPathPrefix, Path.GetFileName(file));
                                DateTime creationTimeUtc = File.GetCreationTimeUtc(file);
                                DateTime lastWriteTimeUtc = File.GetLastWriteTimeUtc(file);
                                PackedFileHeaderRecord.HeaderAttributes attributes = PackedFileHeaderRecord.ToHeaderAttributes(File.GetAttributes(file));
                                Debug.Assert((creationTimeUtc == PackedFileHeaderRecord.ParseDateTime(PackedFileHeaderRecord.FormatDateTime(creationTimeUtc)))
                                    && (lastWriteTimeUtc == PackedFileHeaderRecord.ParseDateTime(PackedFileHeaderRecord.FormatDateTime(lastWriteTimeUtc))));

                                if (!largeFileSegmentSize.HasValue || (inputStreamLength <= largeFileSegmentSize.Value))
                                {
                                    files.Add(new FileRecord(null/*segment*/, partialPath, creationTimeUtc, lastWriteTimeUtc, attributes, inputStreamLength, null/*range*/, null/*digest*/));
                                }
                                else
                                {
                                    // estimate overhead (tries to reserve worst case)
                                    int headerOverhead = new FileRecord(null/*segment*/, partialPath, creationTimeUtc, lastWriteTimeUtc, attributes, inputStreamLength, null/*range*/, null/*digest*/).HeaderOverhead;
                                    headerOverhead += 1/*opcode*/ + 1/*length*/ + new PackedFileHeaderRecord.RangeRecord(inputStreamLength, inputStreamLength, inputStreamLength).ToString().Length;
                                    long largeFileSegmentSizeThisInstance = largeFileSegmentSize.Value - headerOverhead;
                                    if (largeFileSegmentSizeThisInstance <= 0)
                                    {
                                        throw new InvalidOperationException();
                                    }

                                    // split file into ranges
                                    long currentStart = 0;
                                    while (currentStart < inputStreamLength)
                                    {
                                        long currentLength = Math.Min(inputStreamLength - currentStart, largeFileSegmentSizeThisInstance);
                                        long currentEnd = currentStart + currentLength - 1;
                                        files.Add(new FileRecord(null/*segment*/, partialPath, creationTimeUtc, lastWriteTimeUtc, attributes, currentLength, new PackedFileHeaderRecord.RangeRecord(currentStart, currentEnd, inputStreamLength), null/*digest*/));
                                        currentStart += largeFileSegmentSizeThisInstance;
                                    }
                                }
                            }
                            else
                            {
                                EraseStatusLine();
                                Console.WriteLine("  SKIPPED FILE - UNREADABLE: {0}", file);
                            }
                        }
                        else
                        {
                            EraseStatusLine();
                            Console.WriteLine("  SKIPPED FILE: {0}", file);
                        }
                    }
                }
            }

            foreach (string subdirectory in subdirectories)
            {
                if (!excludedItems.Contains(subdirectory.ToLowerInvariant()))
                {
                    int initialFilesCount = files.Count;

                    ItemizeFilesRecursive(files, subdirectory, largeFileSegmentSize, context, excludedExtensions, excludedItems, FilePathItem.Create(partialPathPrefix, Path.GetFileName(subdirectory)), trace);

                    // for subdirectories, only if it is empty add it explicitly
                    if (initialFilesCount == files.Count)
                    {
                        files.Add(new FileRecord(null/*segment*/, FilePathItem.Create(partialPathPrefix, Path.GetFileName(subdirectory)), default(DateTime), default(DateTime), PackedFileHeaderRecord.ToHeaderAttributes(File.GetAttributes(subdirectory)), 0, null/*range*/, null/*digest*/));
                    }
                }
                else
                {
                    EraseStatusLine();
                    Console.WriteLine("  SKIPPED SUBDIRECTORY: {0}", subdirectory);
                }
            }
        }

        private static int DynPackPathComparePartialPathOnly(FileRecord l, FileRecord r)
        {
            int c;

            string[] lParts = l.PartialPath.Steps();
            string[] rParts = r.PartialPath.Steps();
            int i;
            for (i = 0; i < Math.Min(lParts.Length, rParts.Length) - 1; i++)
            {
                c = String.Compare(lParts[i], rParts[i], StringComparison.OrdinalIgnoreCase);
                if (c != 0)
                {
                    return c;
                }
            }

            c = lParts.Length.CompareTo(rParts.Length);
            if (c != 0)
            {
                return c;
            }

            for (; i < lParts.Length; i++)
            {
                c = String.Compare(lParts[i], rParts[i], StringComparison.OrdinalIgnoreCase);
                if (c != 0)
                {
                    return c;
                }
            }

            return 0;
        }

        private static int DynPackPathCompareWithRange(FileRecord l, FileRecord r)
        {
            int c;

            c = DynPackPathComparePartialPathOnly(l, r);
            if (c != 0)
            {
                return c;
            }

            if (r.Range != null)
            {
                if (l.Range == null)
                {
                    return -1;
                }
                c = l.Range.Start.CompareTo(r.Range.Start);
                if (c != 0)
                {
                    return c;
                }
            }

            return 0;
        }

        private static int DynPackSegmentNameCompare(string l, string r)
        {
            while (l.Length < r.Length)
            {
                l = l + 'a';
            }
            while (r.Length < l.Length)
            {
                r = r + 'a';
            }
            return l.CompareTo(r);
        }

        // segment names are like the fractional part of a decimal number, but base 26 (letters)
        private static string DynPackMakeSegmentNameBetween(string l, string r)
        {
            if (!(DynPackSegmentNameCompare(l, r) < 0))
            {
                throw new ApplicationException(String.Format("Segment order error: {0} {1}", l, r));
            }
            while (l.Length < r.Length)
            {
                l = l + 'a';
            }
            while (r.Length < l.Length)
            {
                r = r + 'a';
            }

            string s = String.Empty;
            {
                int[] s2 = new int[l.Length + 1];

                // add
                bool carry = false;
                for (int i = l.Length - 1; i >= 0; i--)
                {
                    int l1 = l[i] - 'a';
                    int r1 = r[i] - 'a';
                    int lr1 = l1 + r1 + (carry ? 1 : 0);
                    carry = lr1 >= 26;
                    if (carry)
                    {
                        lr1 -= 26;
                    }
                    s2[i + 1] = lr1;
                }
                s2[0] = carry ? 1 : 0;

                // divide by 2
                bool borrow = false;
                for (int i = 0; i < s2.Length; i++)
                {
                    bool borrow2 = s2[i] % 2 != 0;
                    s2[i] = (s2[i] + (borrow ? 26 : 0)) / 2;
                    borrow = borrow2;
                }

                for (int i = 1; i < s2.Length; i++)
                {
                    s = s + (char)('a' + s2[i]);
                }
            }

            if (s.Equals(r))
            {
                throw new ApplicationException(String.Format("Impossible: {0} {1} {2}", l, r, s));
            }
            if (s.Equals(l))
            {
                s = s + 'm';
            }

            while (s.Length > 1)
            {
                string ss = s.Substring(0, s.Length - 1);
                if (!(DynPackSegmentNameCompare(l, ss) < 0))
                {
                    break;
                }
                s = ss;
            }
            while ((s.Length > 1) && (s[s.Length - 1] == 'a'))
            {
                s = s.Substring(0, s.Length - 1);
            }

            return s;
        }

        private static void DynPackMakeSegmentNamesBetweenRecursive(string[] s, int first, int last)
        {
            int mid = (first + last) / 2;
            if (first < mid)
            {
                s[mid] = DynPackMakeSegmentNameBetween(s[first], s[last]);
                DynPackMakeSegmentNamesBetweenRecursive(s, first, mid);
                DynPackMakeSegmentNamesBetweenRecursive(s, mid, last);
            }
        }

        private static string[] DynPackMakeSegmentNamesBetween(string l, string r, int count)
        {
            string[] s = new string[count + 2];
            s[0] = l;
            s[count + 2 - 1] = r;
            DynPackMakeSegmentNamesBetweenRecursive(s, 0, count + 2 - 1);
            string[] ss = new string[count];
            Array.Copy(s, 1, ss, 0, count);
            return ss;
        }

        private static bool FatalPromptContinue(ConcurrentTasks concurrent, ConcurrentMessageLog messagesLog, ConcurrentTasks.WaitIntervalMethod waitIntervalMethod, int waitInterval, ConcurrentMessageLog.PrepareConsoleMethod prepareConsole)
        {
            concurrent.Drain(waitIntervalMethod, waitInterval);
            if (prepareConsole != null)
            {
                prepareConsole();
            }
            messagesLog.Flush();

            ConsoleColor oldColor = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("q)uit or c)ontinue: ");
            Console.ForegroundColor = oldColor;
            while (true)
            {
                char key = WaitReadKey(false/*intercept*/);
                Console.WriteLine();
                if (key == 'q')
                {
                    return false;
                }
                else if (key == 'c')
                {
                    return true;
                }
            }
        }

        internal static void DynamicPack(string source, string targetArchivePathTemplate, long segmentSizeTarget, Context context, string[] args)
        {
            const int SegmentOverheadFixed = 1/*FixedHeaderNumber*/ + (1 + PackRandomSignatureLengthBytes) + 10/*SerialNumber(var-max)*/ + 1/*empty parameters list*/ + 1/*StructureType*/ + PackedFileHeaderRecord.HeaderTokenLength + 4/*segment CRC32*/;
            int SegmentOverheadEncrypted = EncryptedFileContainerHeader.GetHeaderLength(context.encrypt) + (context.encrypt != null ? context.encrypt.algorithm.MACLengthBytes : 0);
            int SegmentOverheadTotal = SegmentOverheadFixed + SegmentOverheadEncrypted;

            const int WaitInterval = 2000; // milliseconds
            const string DynPackDiagnosticDateTimeFormat = "yyyy-MM-ddTHH:mm:ss";
            const int MinimumSegmentSize = 4096;

            IFaultInstance faultDynamicPack = context.faultInjectionRoot.Select("DynamicPack");

            ulong segmentSerialNumbering = 0;
            byte[] randomArchiveSignature = new byte[PackRandomSignatureLengthBytes];
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                rng.GetBytes(randomArchiveSignature);
            }

            segmentSizeTarget -= SegmentOverheadTotal;
            // segmentSizeTarget is only approximate anyway and may be exceeded due to
            // encryption/validation and compression potential compression overhead.


            // options (and their defaults)
            bool safe = true;
            long? largeFileSegmentSize = segmentSizeTarget;
            bool verifyNonDirtyMetadata = false;
            string diagnosticPath = null;
            bool windiff = false;
            bool ignoreUnchangedFiles = false;
            string localSignaturePath = null;
            {
                bool parsed = true;
                while (parsed && (args.Length > 0))
                {
                    parsed = true;
                    switch (args[0])
                    {
                        default:
                            parsed = false;
                            break;
                        case "-nosplitlargefiles":
                            {
                                largeFileSegmentSize = null;

                                bool split;
                                GetAdHocArgument(ref args, "-nosplitlargefiles", true/*default*/, false/*explicit*/, out split);
                                if (split)
                                {
                                    largeFileSegmentSize = segmentSizeTarget;
                                }
                            }
                            break;
                        case "-unsafe":
                            GetAdHocArgument(ref args, "-unsafe", true/*default*/, false/*explicit*/, out safe);
                            break;
                        case "-verify":
                            GetAdHocArgument(ref args, "-verify", false/*default*/, true/*explicit*/, out verifyNonDirtyMetadata);
                            break;
                        case "-logpath":
                            GetAdHocArgument(ref args, "-logpath", null/*default*/, delegate(string s) { return s; }, out diagnosticPath);
                            break;
                        case "-windiff":
                            GetAdHocArgument(ref args, "-windiff", false/*default*/, true/*explicit*/, out windiff);
                            break;
                        case "-ignoreunchanged":
                            GetAdHocArgument(ref args, "-ignoreunchanged", false/*default*/, true/*explicit*/, out ignoreUnchangedFiles);
                            break;
                        case "-localsig":
                            GetAdHocArgument(ref args, "-localsig", null/*default*/, delegate(string s) { return s; }, out localSignaturePath);
                            break;
                    }
                }
            }

            InvariantStringSet excludedExtensions;
            InvariantStringSet excludedItems;
            GetExclusionArguments(args, out excludedExtensions, false/*relative*/, out excludedItems);

            if (!Directory.Exists(source))
            {
                throw new UsageException();
            }

            if (segmentSizeTarget < MinimumSegmentSize)
            {
                throw new UsageException();
            }


            TextWriter traceDynpack = context.traceEnabled ? LogWriter.CreateLogFile(DynPackTraceFilePrefix) : null;


            // build current file list
            List<FileRecord> currentFiles = new List<FileRecord>();
            ItemizeFilesRecursive(currentFiles, source, largeFileSegmentSize, context, excludedExtensions, excludedItems, FilePathItem.Create("."), traceDynpack);
            EraseStatusLine();
            if (traceDynpack != null)
            {
                traceDynpack.WriteLine("Current Files:");
                for (int i = 0; i < currentFiles.Count; i++)
                {
                    FileRecord record = currentFiles[i];
                    traceDynpack.WriteLine("    {5,-8} {6} {0}{4} {1} {2} {3}", record.EmbeddedStreamLength, record.CreationTimeUtc, record.LastWriteTimeUtc, record.PartialPath, record.Range != null ? String.Format("[{0}]", record.Range) : String.Empty, i, record.DiagnosticSerialNumber);
                }
                traceDynpack.WriteLine();
            }

            string targetArchiveFileNameTemplate;
            bool remote;
            using (IArchiveFileManager fileManager = GetArchiveFileManager(targetArchivePathTemplate, out targetArchiveFileNameTemplate, out remote, context))
            {
                if (remote && (context.cryptoOption != EncryptionOption.Encrypt) && !context.overrideRemoteSecurityBlock)
                {
                    throw new ApplicationException("You have specified storage on a remote service without any encryption. This is regarded as insecure and dangerous and is blocked by default. If you really mean to do this (and if so we suggest you reconsider), use the -overridesecurityblock option to bypass this block.");
                }

                // Read old manifest (if any)
                //
                // Note: there's a two-phase commit process that occurs with respect to the manifest
                // throughout this code.
                //  1. old segments incl. manifest are renamed, e.g. foo.0.dynpack --> foo.-0.dynpack
                //  2. new files are generated
                //  3. old files (foo.-*.dynpack) are deleted.
                // A complication: if a segment has not been written in the old manifest, it's serial number
                // will be bumped in the new manifest. Therefore, an empty backup segment is created for any
                // non-existing dirty segment to prevent propagating backward of an item with an invalid
                // serial number. The command "dynpack-rollback" looks for empty backup segments and deletes
                // current segments (and empty backup placeholders) instead of restoring to current name.
                //
                List<SegmentRecord> segments = new List<SegmentRecord>();
                List<FileRecord> previousFiles = new List<FileRecord>();
                string manifestFileName = String.Concat(targetArchiveFileNameTemplate, ".", DynPackManifestName, DynPackFileExtension);
                {
                    string manifestFileNameOld = String.Concat(targetArchiveFileNameTemplate, ".", DynPackManifestNameOld, DynPackFileExtension);
                    bool manifestFileNameExists = fileManager.Exists(manifestFileName, fileManager.GetMasterTrace());
                    bool manifestFileNameOldExists = fileManager.Exists(manifestFileNameOld, fileManager.GetMasterTrace());
                    if (manifestFileNameExists || manifestFileNameOldExists)
                    {
                        string manifestFileNameActual = manifestFileName;
                        Console.WriteLine("Reading: {0}", manifestFileName);
                        if (!manifestFileNameExists)
                        {
#if false // automatic recovery is dangerous to integrity
                            manifestFileNameActual = manifestFileNameOld;
                            Console.WriteLine("Manifest file {0} does not exist, reading backup copy {1}", manifestFileName, manifestFileNameOld);
#else
                            throw new ApplicationException(String.Format("Manifest file \"{0}\" does not exist (backup copy \"{1}\" does exist)! Manual intervention required - may be device connectivity failure. If manifest is indeed missing, archive integrity must be verified.", manifestFileName, manifestFileNameOld));
#endif
                        }

                        Dictionary<string, SegmentRecord> segmentMap = new Dictionary<string, SegmentRecord>();

                        CheckedReadStream localSignature = null;

                        using (ILocalFileCopy fileRef = fileManager.Read(manifestFileNameActual, null/*progressTracker*/, fileManager.GetMasterTrace()))
                        {
                            using (Stream fileStream = fileRef.Read())
                            {
                                CryptoKeygroup keysManifest = null;
                                EncryptedFileContainerHeader fchManifest = null;
                                if (context.cryptoOption == EncryptionOption.Encrypt)
                                {
                                    fchManifest = new EncryptedFileContainerHeader(fileStream, true/*peek*/, context.encrypt);
                                    context.encrypt.algorithm.DeriveSessionKeys(context.encrypt.GetMasterKeyEntry(fchManifest.passwordSalt, fchManifest.rfc2898Rounds).MasterKey, fchManifest.fileSalt, out keysManifest);
                                }

                                // Using Moxie Marlinspike's "doom principle": validate the MAC before ANY other
                                // action is taken. (http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/)
                                bool macValidated = false;
                                if (!context.doNotPreValidateMAC && (context.cryptoOption != EncryptionOption.None))
                                {
                                    StreamStack.DoWithStreamStack(
                                        fileStream,
                                        new StreamStack.StreamWrapMethod[]
                                        {
                                            delegate(Stream stream)
                                            {
                                                // see note and references about
                                                // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                                return new TaggedReadStream(stream, context.encrypt.algorithm.CreateMACGenerator(keysManifest.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                            },
                                        },
                                        delegate(Stream stream)
                                        {
                                            ReadAndDiscardEntireStream(stream);
                                        });

                                    macValidated = true;
                                }

                                fileStream.Position = 0;

                                StreamStack.DoWithStreamStack(
                                    fileStream,
                                    new StreamStack.StreamWrapMethod[]
                                    {
                                        delegate(Stream stream)
                                        {
                                            if (localSignaturePath != null)
                                            {
                                                localSignature = new CheckedReadStream(stream, context.encrypt.algorithm.CreateLocalSignatureMACGenerator(keysManifest.LocalSignatureKey));
                                            }
                                            return localSignature;
                                        },
                                        delegate(Stream stream)
                                        {
                                            // see note and references about
                                            // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                            if (context.cryptoOption == EncryptionOption.Encrypt)
                                            {
                                                if (!macValidated)
                                                {
                                                    return new TaggedReadStream(stream, context.encrypt.algorithm.CreateMACGenerator(keysManifest.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                                }
                                                else
                                                {
                                                    return new ReadStreamHoldShort(stream, context.encrypt.algorithm.MACLengthBytes);
                                                }
                                            }
                                            return null;
                                        },
                                        delegate(Stream stream)
                                        {
                                            if (context.cryptoOption == EncryptionOption.Encrypt)
                                            {
                                                // why re-read here? need to read salt within HMAC container
                                                EncryptedFileContainerHeader fch2 = new EncryptedFileContainerHeader(stream, false/*peek*/, context.encrypt);
                                                if (!fch2.Equals(fchManifest))
                                                {
                                                    throw new InvalidOperationException();
                                                }
                                            }
                                            return null;
                                        },
                                        delegate(Stream stream)
                                        {
                                            if (context.cryptoOption == EncryptionOption.Encrypt)
                                            {
                                                return context.encrypt.algorithm.CreateDecryptStream(stream, keysManifest.CipherKey, keysManifest.InitialCounter);
                                            }
                                            return null;
                                        },
                                        delegate(Stream stream)
                                        {
                                            if (context.compressionOption == CompressionOption.Compress)
                                            {
                                                return new BlockedDecompressStream(stream);
                                            }
                                            return null;
                                        },
                                        delegate(Stream stream)
                                        {
                                            // total file CRC32 check value
                                            return new TaggedReadStream(stream, new CRC32(), "File check values do not match - file is damaged");
                                        }
                                    },
                                    delegate(Stream stream)
                                    {
                                        byte[] headerNumber = BinaryReadUtils.ReadBytes(stream, 1);
                                        if (headerNumber[0] != PackArchiveFixedHeaderNumber)
                                        {
                                            throw new InvalidDataException(); // unrecognized format
                                        }

                                        randomArchiveSignature = BinaryReadUtils.ReadVariableLengthByteArray(stream);

                                        segmentSerialNumbering = BinaryReadUtils.ReadVariableLengthQuantityAsUInt64(stream);

                                        int structureType;
                                        List<KeyValuePair<int, string>> parameters = new List<KeyValuePair<int, string>>();
                                        while (true)
                                        {
                                            int parameterType = BinaryReadUtils.ReadVariableLengthQuantityAsInt32(stream);
                                            if (parameterType == 0)
                                            {
                                                if (traceDynpack != null)
                                                {
                                                    traceDynpack.WriteLine("New pack format");
                                                }
                                                break;
                                            }
                                            else if ((parameterType == PackArchiveStructureTypeManifest) || (parameterType == PackArchiveStructureTypeFiles))
                                            {
                                                if (parameters.Count > 0)
                                                {
                                                    throw new InvalidDataException("Expandable parameter area does not conform to old or new archive format");
                                                }
                                                structureType = parameterType;
                                                if (traceDynpack != null)
                                                {
                                                    traceDynpack.WriteLine("Old pack format -- invoking hack");
                                                }
                                                goto TransitionalHack;
                                            }
                                            else
                                            {
                                                string value = BinaryReadUtils.ReadStringUtf8(stream);
                                                parameters.Add(new KeyValuePair<int, string>(parameterType, value));
                                            }
                                        }

                                        /*int */
                                        structureType = BinaryReadUtils.ReadVariableLengthQuantityAsInt32(stream);
                                    TransitionalHack:
                                        if (structureType != PackArchiveStructureTypeManifest)
                                        {
                                            throw new InvalidDataException(); // must be manifest structure
                                        }

                                        FilePathItem.Factory pathFactory = new FilePathItem.Factory();
                                        string currentSegmentName = null;
                                        ulong currentSegmentSerialNumber = 0;
                                        bool firstHeader = true;
                                        bool firstHeaderWasSegment = false;
                                        while (true)
                                        {
                                            byte[] startToken = BinaryReadUtils.ReadBytes(stream, PackedFileHeaderRecord.HeaderTokenLength);
                                            if (!PackedFileHeaderRecord.ValidFileHeaderToken(startToken))
                                            {
                                                throw new InvalidDataException("Unexpected value for start token");
                                            }

                                            PackedFileHeaderRecord header = PackedFileHeaderRecord.Read(stream, false/*strict*/, context.now);
                                            if (header == PackedFileHeaderRecord.NullHeaderRecord)
                                            {
                                                break;
                                            }

                                            // if any segment headers exist (== manifest file), the first record in file must be one
                                            if (firstHeader)
                                            {
                                                if (header.SegmentName != null)
                                                {
                                                    firstHeaderWasSegment = true;
                                                }
                                            }
                                            else
                                            {
                                                if (!firstHeaderWasSegment && (header.SegmentName != null))
                                                {
                                                    throw new InvalidDataException();
                                                }
                                            }
                                            firstHeader = false;

                                            // process segment header records differently
                                            if (header.SegmentName != null)
                                            {
                                                currentSegmentName = header.SegmentName;
                                                currentSegmentSerialNumber = header.SegmentSerialNumber;

                                                continue;
                                            }

                                            // normal file header record processing

                                            // segment name and serial are written as a special header record.
                                            // this is not exposed to caller; instead, each proper file record is
                                            // annotated with the segment name and serial number.
                                            header.SegmentName = currentSegmentName;
                                            header.SegmentSerialNumber = currentSegmentSerialNumber;

                                            const string ExpectedPathPrefix = @".\";
                                            if (!header.Subpath.StartsWith(ExpectedPathPrefix))
                                            {
                                                throw new InvalidDataException("Invalid relative path found in manifest");
                                            }

                                            // this code really ought to be folded in with "currentSegmentName"
                                            // code above, but has been tested, so is left unchanged for now.
                                            string segmentName = header.SegmentName;
                                            if (segmentName == null)
                                            {
                                                throw new InvalidDataException("Missing segment name in manifest");
                                            }
                                            ulong segmentSerialNumber = header.SegmentSerialNumber;
                                            if (segmentSerialNumber == 0)
                                            {
                                                throw new InvalidDataException("Segment serial number not initialized");
                                            }
                                            if (segmentSerialNumber >= segmentSerialNumbering)
                                            {
                                                throw new InvalidDataException("Invalid segment serial number");
                                            }
                                            SegmentRecord segment;
                                            if (!segmentMap.TryGetValue(segmentName, out segment))
                                            {
                                                segment = new SegmentRecord(segmentName, segmentSerialNumber);
                                                segments.Add(segment);
                                                segmentMap.Add(segmentName, segment);
                                            }
                                            if (segment.SerialNumber != segmentSerialNumber)
                                            {
                                                throw new InvalidDataException("Segment serial number inconsistent");
                                            }

                                            previousFiles.Add(new FileRecord(segment, pathFactory.Create(header.Subpath), header.CreationTimeUtc, header.LastWriteTimeUtc, header.Attributes, header.EmbeddedStreamLength, header.Range, header.Digest));
                                        }

                                        BinaryReadUtils.RequireAtEOF(stream);
                                    });

                            }
                        }

                        if (localSignaturePath != null)
                        {
                            CheckLocalSignature(localSignaturePath, localSignature);
                        }
                    }
                }
                if (traceDynpack != null)
                {
                    traceDynpack.WriteLine("Previous Files:");
                    for (int i = 0; i < previousFiles.Count; i++)
                    {
                        FileRecord record = previousFiles[i];
                        traceDynpack.WriteLine("    {5,-8} {6} {7}({8})  {0}{4} {1} {2} {3}", record.EmbeddedStreamLength, record.CreationTimeUtc, record.LastWriteTimeUtc, record.PartialPath, record.Range != null ? String.Format("[{0}]", record.Range) : String.Empty, i, record.DiagnosticSerialNumber, record.Segment.DiagnosticSerialNumber, record.Segment.Name);
                    }
                    traceDynpack.WriteLine();
                }

                // Sort and merge
                List<FileRecord> mergedFiles = new List<FileRecord>();
                {
                    int iCurrent;
                    int iPrevious;

                    currentFiles.Sort(DynPackPathCompareWithRange);
                    previousFiles.Sort(DynPackPathCompareWithRange); // ensure sorted - do not trust old manifest
                    // detect flaws in comparison algorithm
                    for (int i = 0; i < currentFiles.Count - 1; i++)
                    {
                        if (!(DynPackPathCompareWithRange(currentFiles[i], currentFiles[i + 1]) < 0))
                        {
                            Debugger.Break();
                            throw new ApplicationException(String.Format("Sort defect: {0} {1}", currentFiles[i].PartialPath, currentFiles[i + 1].PartialPath));
                        }
                    }
                    for (int i = 0; i < previousFiles.Count - 1; i++)
                    {
                        if (!(DynPackPathCompareWithRange(previousFiles[i], previousFiles[i + 1]) < 0))
                        {
                            Debugger.Break();
                            throw new ApplicationException(String.Format("Sort defect: {0} {1}", previousFiles[i].PartialPath, previousFiles[i + 1].PartialPath));
                        }
                    }

                    // Here is a hack to ensure that range-split files are not gratuitously
                    // rearchived if the segment target size changes. (This also affects the case
                    // where an archive containing unsplit large file, i.e. length > segment target size,
                    // is run with the split option enabled, where the file has not changed).
                    // Find all ranged files in currentFiles or previousFiles and if the
                    // underlying file has not changed, ensure that the structure from previousFiles
                    // is retained.
                    iCurrent = 0;
                    iPrevious = 0;
                    while ((iCurrent < currentFiles.Count) && (iPrevious < previousFiles.Count))
                    {
                        int c = DynPackPathComparePartialPathOnly(currentFiles[iCurrent], previousFiles[iPrevious]);
                        if (c < 0)
                        {
                            iCurrent++;
                        }
                        else if (c > 0)
                        {
                            iPrevious++;
                        }
                        else
                        {
                            int iPreviousStart = iPrevious;
                            int iCurrentStart = iCurrent;
                            bool range = false;
                            do
                            {
                                range = range || (previousFiles[iPrevious].Range != null);
                                iPrevious++;
                            } while ((iPrevious < previousFiles.Count)
                                && (0 == DynPackPathComparePartialPathOnly(previousFiles[iPrevious - 1], previousFiles[iPrevious])));
                            do
                            {
                                range = range || (currentFiles[iCurrent].Range != null);
                                iCurrent++;
                            } while ((iCurrent < currentFiles.Count)
                                && (0 == DynPackPathComparePartialPathOnly(currentFiles[iCurrent - 1], currentFiles[iCurrent])));

                            if (range
                                && previousFiles[iPreviousStart].CreationTimeUtc.Equals(currentFiles[iCurrentStart].CreationTimeUtc)
                                && previousFiles[iPreviousStart].LastWriteTimeUtc.Equals(currentFiles[iCurrentStart].LastWriteTimeUtc))
                            {
                                bool notDirty = true;
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("[gratuitous re-ranging suppression dirty check begins: previous=(start={0}, length={1}) current=(start={2}, length={3})]", iPreviousStart, iPrevious - iPreviousStart, iCurrentStart, iCurrent - iCurrentStart);
                                }
                                for (int i = iPreviousStart; notDirty && (i < iPrevious); i++)
                                {
                                    bool segmentAssigned = previousFiles[i].Segment != null;
                                    bool segmentExist = segmentAssigned && fileManager.Exists(String.Concat(targetArchiveFileNameTemplate, ".", previousFiles[i].Segment.Name, DynPackFileExtension), fileManager.GetMasterTrace());
                                    bool thisNotDirty = segmentAssigned && segmentExist;
                                    if (!thisNotDirty)
                                    {
                                        if (traceDynpack != null)
                                        {
                                            traceDynpack.WriteLine("[gratuitous re-ranging suppression: {0} dirty; segmentAssigned={1}, segmentExist={2}]", previousFiles[i].DiagnosticSerialNumber, segmentAssigned, segmentExist);
                                        }
                                    }
                                    notDirty = notDirty && segmentAssigned && segmentExist;
                                }

                                if (notDirty)
                                {
                                    // unchanged, and ranges involved in either previous or current

                                    if (traceDynpack != null)
                                    {
                                        traceDynpack.WriteLine("Gratuitous re-ranging of large files suppressed: previous=(start={0}, length={1}) current=(start={2}, length={3})", iPreviousStart, iPrevious - iPreviousStart, iCurrentStart, iCurrent - iCurrentStart);
                                        traceDynpack.Write("  previous={");
                                        for (int i = iPreviousStart; i < iPrevious; i++)
                                        {
                                            traceDynpack.Write("{0},", previousFiles[i].DiagnosticSerialNumber);
                                        }
                                        traceDynpack.Write("}  current={");
                                        for (int i = iCurrentStart; i < iCurrent; i++)
                                        {
                                            traceDynpack.Write("{0},", currentFiles[i].DiagnosticSerialNumber);
                                        }
                                        traceDynpack.WriteLine("}");
                                    }

                                    FileRecord[] currentSequenceReplacement = new FileRecord[iPrevious - iPreviousStart];
                                    for (int i = 0; i < iPrevious - iPreviousStart; i++)
                                    {
                                        FileRecord previous = previousFiles[i + iPreviousStart];
                                        currentSequenceReplacement[i] = new FileRecord(previous);
                                    }
                                    currentFiles.RemoveRange(iCurrentStart, iCurrent - iCurrentStart);
                                    currentFiles.InsertRange(iCurrentStart, currentSequenceReplacement);
                                    iCurrent = iCurrentStart + (iPrevious - iPreviousStart);
                                }
                            }
                        }
                    }
                    if (traceDynpack != null)
                    {
                        traceDynpack.WriteLine();
                    }

                    if (ignoreUnchangedFiles)
                    {
                        Console.WriteLine("Computing any needed file hashes for -ignoreunchanged");
                    }

                    // main merge occurs here
                    using (ConcurrentTasks concurrent = new ConcurrentTasks(Constants.ConcurrencyForComputeBound, null, null, traceDynpack != null ? TextWriter.Synchronized(traceDynpack) : null))
                    {
                        iCurrent = 0;
                        iPrevious = 0;
                        while ((iCurrent < currentFiles.Count) || (iPrevious < previousFiles.Count))
                        {
                            if (!(iCurrent < currentFiles.Count))
                            {
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Deleted(1): {5} {0}{4} {1} {2} {3}", previousFiles[iPrevious].EmbeddedStreamLength, previousFiles[iPrevious].CreationTimeUtc, previousFiles[iPrevious].LastWriteTimeUtc, previousFiles[iPrevious].PartialPath, previousFiles[iPrevious].Range != null ? String.Format("[{0}]", previousFiles[iPrevious].Range) : String.Empty, previousFiles[iPrevious].DiagnosticSerialNumber);
                                }

                                previousFiles[iPrevious].Segment.Dirty.Set(); // segment modified by deletion
                                iPrevious++;
                            }
                            else if (!(iPrevious < previousFiles.Count))
                            {
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Added(1): {5} {0}{4} {1} {2} {3}", currentFiles[iCurrent].EmbeddedStreamLength, currentFiles[iCurrent].CreationTimeUtc, currentFiles[iCurrent].LastWriteTimeUtc, currentFiles[iCurrent].PartialPath, currentFiles[iCurrent].Range != null ? String.Format("[{0}]", currentFiles[iCurrent].Range) : String.Empty, currentFiles[iCurrent].DiagnosticSerialNumber);
                                }

                                // Addition MAY or MAY NOT cause segment to be dirty:
                                // - If files are added between segments, the code tries to avoid modifying those
                                // segments, so they do not need to be marked dirty (unless the segments are small
                                // enough to be merged during the join phase, which marks them dirty).
                                // - If new files are inserted into the middle of an existing segment, the segment
                                // must be split in two and the second half renamed, during a fixup pass that
                                // occurs after merging.
                                // Therefore, marking dirty is not done here in any case.

                                if (ignoreUnchangedFiles
                                    && ((currentFiles[iCurrent].Attributes & PackedFileHeaderRecord.HeaderAttributes.Directory) == 0)
                                    && ((currentFiles[iCurrent].Range == null) || (currentFiles[iCurrent].Range.Start == 0)))
                                {
                                    faultDynamicPack.Select("SetDigest", currentFiles[iCurrent].PartialPath.ToString());
                                    currentFiles[iCurrent].SetDigest(concurrent, source);
                                }

                                mergedFiles.Add(currentFiles[iCurrent]);
                                iCurrent++;
                            }
                            else
                            {
                                int c = DynPackPathCompareWithRange(currentFiles[iCurrent], previousFiles[iPrevious]);
                                if (c < 0)
                                {
                                    if (traceDynpack != null)
                                    {
                                        traceDynpack.WriteLine("Added(2): {5} {0}{4} {1} {2} {3}", currentFiles[iCurrent].EmbeddedStreamLength, currentFiles[iCurrent].CreationTimeUtc, currentFiles[iCurrent].LastWriteTimeUtc, currentFiles[iCurrent].PartialPath, currentFiles[iCurrent].Range != null ? String.Format("[{0}]", currentFiles[iCurrent].Range) : String.Empty, currentFiles[iCurrent].DiagnosticSerialNumber);
                                    }

                                    // IMPORTANT: see comment in "Added(1)" clause about marking dirty

                                    if (ignoreUnchangedFiles
                                        && ((currentFiles[iCurrent].Attributes & PackedFileHeaderRecord.HeaderAttributes.Directory) == 0)
                                        && ((currentFiles[iCurrent].Range == null) || (currentFiles[iCurrent].Range.Start == 0)))
                                    {
                                        faultDynamicPack.Select("SetDigest", currentFiles[iCurrent].PartialPath.ToString());
                                        currentFiles[iCurrent].SetDigest(concurrent, source);
                                    }

                                    mergedFiles.Add(currentFiles[iCurrent]);
                                    iCurrent++;
                                }
                                else if (c > 0)
                                {
                                    if (traceDynpack != null)
                                    {
                                        traceDynpack.WriteLine("Deleted(2): {5} {0}{4} {1} {2} {3}", previousFiles[iPrevious].EmbeddedStreamLength, previousFiles[iPrevious].CreationTimeUtc, previousFiles[iPrevious].LastWriteTimeUtc, previousFiles[iPrevious].PartialPath, previousFiles[iPrevious].Range != null ? String.Format("[{0}]", previousFiles[iPrevious].Range) : String.Empty, previousFiles[iPrevious].DiagnosticSerialNumber);
                                    }

                                    previousFiles[iPrevious].Segment.Dirty.Set(); // segment modified by deletion
                                    iPrevious++;
                                }
                                else
                                {
                                    FileRecord record = currentFiles[iCurrent];
                                    record.Segment = previousFiles[iPrevious].Segment;
                                    mergedFiles.Add(record);

                                    bool creationChanged = !previousFiles[iPrevious].CreationTimeUtc.Equals(currentFiles[iCurrent].CreationTimeUtc);
                                    bool lastWriteChanged = !previousFiles[iPrevious].LastWriteTimeUtc.Equals(currentFiles[iCurrent].LastWriteTimeUtc);
                                    bool rangeChanged = !PackedFileHeaderRecord.RangeRecord.Equals(previousFiles[iPrevious].Range, currentFiles[iCurrent].Range);
                                    if (ignoreUnchangedFiles && !rangeChanged && (creationChanged || lastWriteChanged)
                                        && ((currentFiles[iCurrent].Attributes & PackedFileHeaderRecord.HeaderAttributes.Directory) == 0))
                                    {
                                        byte[] currentDigest, previousDigest;
                                        if ((currentFiles[iCurrent].Range == null) || (currentFiles[iCurrent].Range.Start == 0))
                                        {
                                            faultDynamicPack.Select("SetDigest", currentFiles[iCurrent].PartialPath.ToString());
                                            currentFiles[iCurrent].SetDigest(concurrent, source);
                                            currentDigest = currentFiles[iCurrent].Digest;
                                        }
                                        else
                                        {
                                            int i = iCurrent;
                                            while ((i > 0) && (currentFiles[i].Range.Start != 0))
                                            {
                                                i--;
                                            }
                                            currentDigest = currentFiles[i].Digest;
                                        }
                                        if ((previousFiles[iPrevious].Range == null) || (previousFiles[iPrevious].Range.Start == 0))
                                        {
                                            previousDigest = previousFiles[iPrevious].Digest;
                                        }
                                        else
                                        {
                                            int i = iPrevious;
                                            while ((i > 0) && (previousFiles[i].Range.Start != 0))
                                            {
                                                i--;
                                            }
                                            previousDigest = previousFiles[i].Digest;
                                        }
                                        if ((previousDigest != null) && ArrayEqual(previousDigest, currentDigest)) // missing previous hash will cause arrays to be not equal, preventing suppression
                                        {
                                            if (traceDynpack != null)
                                            {
                                                traceDynpack.WriteLine("Changed: {5} {0}{4} {1} {2} {3}", previousFiles[iPrevious].EmbeddedStreamLength, previousFiles[iPrevious].CreationTimeUtc, previousFiles[iPrevious].LastWriteTimeUtc, previousFiles[iPrevious].PartialPath, previousFiles[iPrevious].Range != null ? String.Format("[{0}]", previousFiles[iPrevious].Range) : String.Empty, previousFiles[iPrevious].DiagnosticSerialNumber);
                                                traceDynpack.WriteLine("       : {5} {0}{4} {1} {2} {3}", currentFiles[iCurrent].EmbeddedStreamLength, currentFiles[iCurrent].CreationTimeUtc, currentFiles[iCurrent].LastWriteTimeUtc, currentFiles[iCurrent].PartialPath, currentFiles[iCurrent].Range != null ? String.Format("[{0}]", currentFiles[iCurrent].Range) : String.Empty, currentFiles[iCurrent].DiagnosticSerialNumber);
                                                traceDynpack.WriteLine("       (reason: creation-changed={0} lastwrite-changed={1} range-changed={2})", creationChanged, lastWriteChanged, rangeChanged);
                                                traceDynpack.WriteLine("       SUPPRESSED because -ignoreunchanged specified and file hash values indicate content unchanged");
                                                traceDynpack.Write("       ");
                                            }
                                            creationChanged = false;
                                            lastWriteChanged = false;
                                        }
                                    }
                                    if (creationChanged || lastWriteChanged || rangeChanged)
                                    {
                                        if (traceDynpack != null)
                                        {
                                            traceDynpack.WriteLine("Changed: {5} {0}{4} {1} {2} {3}", previousFiles[iPrevious].EmbeddedStreamLength, previousFiles[iPrevious].CreationTimeUtc, previousFiles[iPrevious].LastWriteTimeUtc, previousFiles[iPrevious].PartialPath, previousFiles[iPrevious].Range != null ? String.Format("[{0}]", previousFiles[iPrevious].Range) : String.Empty, previousFiles[iPrevious].DiagnosticSerialNumber);
                                            traceDynpack.WriteLine("       : {5} {0}{4} {1} {2} {3}", currentFiles[iCurrent].EmbeddedStreamLength, currentFiles[iCurrent].CreationTimeUtc, currentFiles[iCurrent].LastWriteTimeUtc, currentFiles[iCurrent].PartialPath, currentFiles[iCurrent].Range != null ? String.Format("[{0}]", currentFiles[iCurrent].Range) : String.Empty, currentFiles[iCurrent].DiagnosticSerialNumber);
                                            traceDynpack.WriteLine("       (reason: creation-changed={0} lastwrite-changed={1} range-changed={2})", creationChanged, lastWriteChanged, rangeChanged);
                                        }

                                        previousFiles[iPrevious].Segment.Dirty.Set(); // segment modified because file changed
                                    }
                                    else
                                    {
                                        if (traceDynpack != null)
                                        {
                                            traceDynpack.WriteLine("Unchanged: {5} {0}{4} {1} {2} {3}", currentFiles[iCurrent].EmbeddedStreamLength, currentFiles[iCurrent].CreationTimeUtc, currentFiles[iCurrent].LastWriteTimeUtc, currentFiles[iCurrent].PartialPath, currentFiles[iCurrent].Range != null ? String.Format("[{0}]", currentFiles[iCurrent].Range) : String.Empty, currentFiles[iCurrent].DiagnosticSerialNumber);
                                        }

                                        if ((previousFiles[iPrevious].Digest != null) && (mergedFiles[mergedFiles.Count - 1].Digest == null))
                                        {
                                            mergedFiles[mergedFiles.Count - 1].Digest = previousFiles[iPrevious].Digest;
                                        }
                                    }

                                    iPrevious++;
                                    iCurrent++;
                                }
                            }

                            // ConcurrentTasks.Dispose() will wait until all SetDigest() operations have completed
                        }
                    }

                    currentFiles = null;
                    previousFiles = null;
                }
                if (traceDynpack != null)
                {
                    traceDynpack.WriteLine();
                    traceDynpack.WriteLine("Merged Files:");
                    for (int i = 0; i < mergedFiles.Count; i++)
                    {
                        FileRecord record = mergedFiles[i];
                        traceDynpack.WriteLine("    {5,-8} {6} {7}  {0}{4} {1} {2} {3}", record.EmbeddedStreamLength, record.CreationTimeUtc, record.LastWriteTimeUtc, record.PartialPath, record.Range != null ? String.Format("[{0}]", record.Range) : String.Empty, i, record.DiagnosticSerialNumber, record.Segment != null ? record.Segment.DiagnosticSerialNumber : "null");
                    }
                    traceDynpack.WriteLine();
                }

                // Fixup pass for files inserted into the middle of segments (breaking segment
                // ordering invariants) - see also comment in "Added(1)" clause above.
                {
                    Dictionary<string, bool> usedSegmentNames = new Dictionary<string, bool>();
                    string currentSegmentName = String.Empty;
                    SegmentRecord currentSegment = null;
                    bool splitSegment = false;
                    for (int i = 0; i < mergedFiles.Count - 1; i++)
                    {
                        if (mergedFiles[i].Segment == null)
                        {
                            splitSegment = true;
                            continue;
                        }

                        string candidateSegmentName = mergedFiles[i].Segment.Name;
                        if (splitSegment || !String.Equals(currentSegmentName, candidateSegmentName))
                        {
                            int c = DynPackSegmentNameCompare(currentSegmentName, candidateSegmentName);
                            if ((c > 0) || (splitSegment && (c == 0)))
                            {
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Insertion: segment name sequence violation:  {0} {5} {2}  [{1},{3}]  ({4})", currentSegmentName, currentSegment != null ? currentSegment.DiagnosticSerialNumber : "<null>", mergedFiles[i].Segment.Name, mergedFiles[i].Segment.DiagnosticSerialNumber, mergedFiles[i].DiagnosticSerialNumber, splitSegment ? ">=" : ">");
                                    traceDynpack.WriteLine("  marking segment dirty, then voiding segment from {0}", mergedFiles[i].DiagnosticSerialNumber);
                                }
                                mergedFiles[i].Segment.Dirty.Set();
                                mergedFiles[i].Segment = null;
                                continue;
                            }

                            if (usedSegmentNames.ContainsKey(mergedFiles[i].Segment.Name))
                            {
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Insertion: segment name used more than once for separated regions:  {0} [{1}]  ({2})", mergedFiles[i].Segment.Name, mergedFiles[i].Segment.DiagnosticSerialNumber, mergedFiles[i].DiagnosticSerialNumber);
                                    traceDynpack.WriteLine("  marking segment dirty, then voiding segment from {0}", mergedFiles[i].DiagnosticSerialNumber);
                                }
                                mergedFiles[i].Segment.Dirty.Set();
                                mergedFiles[i].Segment = null;
                                continue;
                            }

                            currentSegment = mergedFiles[i].Segment;
                            currentSegmentName = mergedFiles[i].Segment.Name;
                            usedSegmentNames[currentSegmentName] = false;
                            splitSegment = false;
                        }
                    }

                    if (traceDynpack != null)
                    {
                        traceDynpack.WriteLine();
                    }
                }

                // Ensure segment contiguity and uniqueness
                {
                    Dictionary<SegmentRecord, bool> usedSegments = new Dictionary<SegmentRecord, bool>();
                    SegmentRecord currentSegment = null;

                    // first, ensure first file and first segment assignment are valid
                    if (mergedFiles.Count > 0)
                    {
                        currentSegment = mergedFiles[0].Segment;
                        if (currentSegment == null)
                        {
                            // special case - first file is a new file - create new first segment for it
                            currentSegment = new SegmentRecord();
                            if (traceDynpack != null)
                            {
                                traceDynpack.WriteLine("New segment: {0}", currentSegment.DiagnosticSerialNumber);
                            }
                            segments.Add(currentSegment);
                            mergedFiles[0].Segment = currentSegment;
                            if (traceDynpack != null)
                            {
                                traceDynpack.WriteLine("Segment assign: {0} {2} {1}", currentSegment.DiagnosticSerialNumber, mergedFiles[0].PartialPath, mergedFiles[0].Range != null ? String.Format("[{0}]", mergedFiles[0].Range) : String.Empty);
                            }
                        }
                        usedSegments.Add(currentSegment, false);
                        currentSegment.start = 0;
                    }

                    for (int i = 1; i < mergedFiles.Count; i++)
                    {
                        if (mergedFiles[i].Segment == null)
                        {
                            // unnassigned file
                            if (currentSegment.Dirty.Value)
                            {
                                // only append new unnassigned file to the previous segment if it
                                // is already dirty - if segment is already full, we'll end up splitting
                                // it and quite likely having to rewrite a segment that didn't actually
                                // change
                                mergedFiles[i].Segment = currentSegment;
                            }
                            else
                            {
                                // create new segment if previous segment is not dirty
                                mergedFiles[i].Segment = currentSegment = new SegmentRecord();
                                usedSegments.Add(currentSegment, false);
                                currentSegment.start = i;
                                segments.Add(currentSegment);
                                Debug.Assert(currentSegment.Dirty.Value);
                            }
                            if (traceDynpack != null)
                            {
                                traceDynpack.WriteLine("Segment assign: {0} {2} {1}", currentSegment.DiagnosticSerialNumber, mergedFiles[i].PartialPath, mergedFiles[i].Range != null ? String.Format("[{0}]", mergedFiles[i].Range) : String.Empty);
                            }
                        }
                        else if (mergedFiles[i].Segment != currentSegment)
                        {
                            // file is in a segment other than current segment (just crossed boundary)
                            if (!usedSegments.ContainsKey(mergedFiles[i].Segment))
                            {
                                // if this segment hasn't been seen, it becomes the current segment
                                currentSegment = mergedFiles[i].Segment;
                            }
                            else
                            {
                                // if it has been seen, then segments have become interleaved.
                                // create new segment and reassign file to it
                                currentSegment = new SegmentRecord();
                                segments.Add(currentSegment);
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("New segment: {0}", currentSegment.DiagnosticSerialNumber);
                                }
                            }
                            usedSegments.Add(currentSegment, false);
                            currentSegment.start = i;
                        }
                        else
                        {
                            // file is in same segment as previous file - no action needed
                        }
                    }
                }
                segments.RemoveAll(delegate(SegmentRecord a) { return !a.start.HasValue; });
                segments.Sort(delegate(SegmentRecord l, SegmentRecord r) { return l.start.Value.CompareTo(r.start.Value); });
                if (traceDynpack != null)
                {
                    traceDynpack.WriteLine();
                    traceDynpack.WriteLine("Segments:");
                    foreach (SegmentRecord segment in segments)
                    {
                        traceDynpack.WriteLine("    {0} {1}", segment.DiagnosticSerialNumber, segment.Name != null ? segment.Name : "<>");
                    }
                    traceDynpack.WriteLine();
                }

                // First scan (before splitting or merging) - ensure missing segments are dirty
                foreach (SegmentRecord segment in segments)
                {
                    string segmentFileName = targetArchiveFileNameTemplate + "." + segment.Name + DynPackFileExtension;
                    if (!fileManager.Exists(segmentFileName, fileManager.GetMasterTrace()))
                    {
                        segment.Dirty.Set();
                    }
                }

                // Split segments too large
                for (int i = 0; i < segments.Count; i++)
                {
                    SegmentRecord segment = segments[i];

                    if (!segment.Dirty.Value)
                    {
                        // do not gratuitously split too-large segments that already exist and aren't dirty
                        continue;
                    }

                    // determine prefix that fits in one segment
                    int start = segment.start.Value;
                    int end = (i + 1 < segments.Count) ? segments[i + 1].start.Value : mergedFiles.Count;
                    int count = end - start;
                    long totalSize = 0;
                    int j = 0;
                    while (j < count)
                    {
                        totalSize += mergedFiles[j + start].EmbeddedStreamLength + mergedFiles[j + start].HeaderOverhead;
                        if (totalSize > segmentSizeTarget)
                        {
                            if (j > 0)
                            {
                                break;
                            }
                        }
                        j++;
                    }

                    if (j < count)
                    {
                        // this segment was too large - split it

                        // special case: try to split the segment evenly (only exactly two segments can contain data)
                        {
                            int left = 0;
                            int right = count;
                            long leftSize = 0;
                            long rightSize = 0;
                            while ((left < right) && (leftSize <= segmentSizeTarget) && (rightSize <= segmentSizeTarget))
                            {
                                long leftOne = mergedFiles[left + start].EmbeddedStreamLength + mergedFiles[left + start].HeaderOverhead;
                                long rightOne = mergedFiles[right - 1 + start].EmbeddedStreamLength + mergedFiles[right - 1 + start].HeaderOverhead;
                                if ((leftSize + leftOne <= rightSize) || (rightSize + rightOne > segmentSizeTarget))
                                {
                                    leftSize += leftOne;
                                    left++;
                                }
                                else
                                {
                                    rightSize += rightOne;
                                    right--;
                                }
                            }
                            if ((left == right) && (leftSize <= segmentSizeTarget) && (rightSize <= segmentSizeTarget))
                            {
                                j = left;
                            }
                        }

                        // assign the new segment for the overflow items
                        segment.Dirty.Set();
                        SegmentRecord newSegment = new SegmentRecord();
                        newSegment.start = j + start;
                        if (traceDynpack != null)
                        {
                            traceDynpack.WriteLine("Split: {0} after {1}", segment.DiagnosticSerialNumber, mergedFiles[newSegment.start.Value].PartialPath);
                        }
                        segments.Insert(i + 1, newSegment);
                        for (int k = j; k < count; k++)
                        {
                            mergedFiles[k + start].Segment = newSegment;
                        }
                    }
                }

                // Join (fold) small segments
                for (int i = 0; i < segments.Count - 1; i++)
                {
                    if (!segments[i].Dirty.Value && !segments[i + 1].Dirty.Value)
                    {
                        // do not gratuitously merge too-small segments that already exist and aren't dirty
                        continue;
                    }

                    int start = segments[i].start.Value;
                    int end = (i + 2 < segments.Count) ? segments[i + 2].start.Value : mergedFiles.Count;
                    int count = end - start;
                    long totalSize = 0;
                    for (int j = 0; j < count; j++)
                    {
                        totalSize += mergedFiles[j + start].EmbeddedStreamLength + mergedFiles[j + start].HeaderOverhead;
                    }
                    if (totalSize <= segmentSizeTarget)
                    {
                        if (traceDynpack != null)
                        {
                            traceDynpack.WriteLine("Join: {0}, {1}", segments[i].DiagnosticSerialNumber, segments[i + 1].DiagnosticSerialNumber);
                        }

                        segments[i].Dirty.Set();

                        if ((segments[i].Name == null) && (segments[i + 1].Name != null))
                        {
                            segments[i].Name = segments[i + 1].Name;
                        }
                        for (int j = 0; j < count; j++)
                        {
                            mergedFiles[j + start].Segment = segments[i];
                        }
                        segments.RemoveAt(i + 1);
                        i--;
                    }
                }

                // program logic test - verify segment structure validity
                for (int i = 0; i < segments.Count - 1; i++)
                {
                    if (segments[i].start.Value >= segments[i + 1].start.Value)
                    {
                        Console.WriteLine("DEFECT! Segment overlap!");
                        Debugger.Break();
                        throw new ApplicationException("DEFECT! Segment overlap!");
                    }
                }

                // Rename segments
                {
                    if (segments.Count > 0)
                    {
                        if (segments[0].Name != "a")
                        {
                            segments[0].Name = "a";
                            if (traceDynpack != null)
                            {
                                traceDynpack.WriteLine("Rename: {0} --> {1}", segments[0].DiagnosticSerialNumber, segments[0].Name);
                            }
                        }
                    }
                    int lastName = 0;
                    int i;
                    for (i = 1; i < segments.Count; i++)
                    {
                        if (segments[i].Name != null)
                        {
                            if (DynPackSegmentNameCompare(segments[lastName].Name, segments[i].Name) >= 0)
                            {
                                // later segment with same or earlier (less than) name has an
                                // invalid name and must be renamed - remove name here to trigger that
                                segments[i].Name = null;
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Rename: {0} --> {1}", segments[i].DiagnosticSerialNumber, "<>");
                                }
                            }
                            else
                            {
                                lastName = i;
                            }
                        }
                    }
                    i = 1;
                    while (i < segments.Count)
                    {
                        if (segments[i].Name == null)
                        {
                            int nextName = i + 1;
                            while ((nextName < segments.Count) && (segments[nextName].Name == null))
                            {
                                nextName++;
                            }
                            string[] newNames = DynPackMakeSegmentNamesBetween(segments[i - 1].Name, nextName < segments.Count ? segments[nextName].Name : "z", nextName - i);
                            for (int j = 0; j < nextName - i; j++)
                            {
                                segments[i + j].Name = newNames[j];
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Rename: {0} --> {1}", segments[i + j].DiagnosticSerialNumber, segments[i + j].Name);
                                }
                            }
                        }
                        i++;
                    }
                    for (i = 1; i < segments.Count; i++)
                    {
                        if (segments[i].Dirty.Value)
                        {
                            string newName = segments[i].Name;
                            newName = newName.Substring(0, newName.Length - 1);
                            if ((newName.Length >= 1) && (newName[newName.Length - 1] != 'a') && (DynPackSegmentNameCompare(segments[i - 1].Name, newName) < 0))
                            {
                                segments[i].Name = newName;
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Rename: {0} --> {1}", segments[i].DiagnosticSerialNumber, segments[i].Name);
                                }
                            }
                        }
                    }
                }
                if (traceDynpack != null)
                {
                    traceDynpack.WriteLine();
                    traceDynpack.WriteLine("Segments (2):");
                    foreach (SegmentRecord segment in segments)
                    {
                        traceDynpack.WriteLine("    {0} {1}", segment.DiagnosticSerialNumber, segment.Name != null ? segment.Name : "<>");
                    }
                    traceDynpack.WriteLine();
                }

                // program logic test - verify segment naming validity
                {
                    bool fault1 = false, fault2 = false;
                    Dictionary<string, bool> usedSegmentNames = new Dictionary<string, bool>();
                    string currentSegmentName = String.Empty;
                    SegmentRecord currentSegment = null;
                    for (int i = 0; i < mergedFiles.Count - 1; i++)
                    {
                        if (!String.Equals(currentSegmentName, mergedFiles[i].Segment.Name))
                        {
                            if (DynPackSegmentNameCompare(currentSegmentName, mergedFiles[i].Segment.Name) > 0)
                            {
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Program defect: segment name sequence violation:  {0} > {2}  [{1},{3}]  ({4})", currentSegmentName, currentSegment.DiagnosticSerialNumber, mergedFiles[i].Segment.Name, mergedFiles[i].Segment.DiagnosticSerialNumber, mergedFiles[i].DiagnosticSerialNumber);
                                }
                                fault1 = true;
                            }

                            if (usedSegmentNames.ContainsKey(mergedFiles[i].Segment.Name))
                            {
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Program defect: name used more than once for separated regions:  {0} [{1}]  ({2})", mergedFiles[i].Segment.Name, mergedFiles[i].Segment.DiagnosticSerialNumber, mergedFiles[i].DiagnosticSerialNumber);
                                }
                                fault2 = true;
                            }

                            currentSegment = mergedFiles[i].Segment;
                            currentSegmentName = mergedFiles[i].Segment.Name;
                            usedSegmentNames[currentSegmentName] = false;
                        }
                    }
                    if (fault1 || fault2)
                    {
                        string message = String.Empty;
                        if (fault1)
                        {
                            message = message + "DEFECT! Segment name sequence violation! ";
                        }
                        if (fault2)
                        {
                            message = message + "DEFECT! Segment name used more than once for separated regions!";
                        }
                        Debugger.Break();
                        throw new ApplicationException(message);
                    }
                }

                // TODO: rename segments (and rename files) if names have become too long for file system

                // Second scan (after renaming) - ensure missing segments are dirty
                foreach (SegmentRecord segment in segments)
                {
                    string segmentFileName = targetArchiveFileNameTemplate + "." + segment.Name + DynPackFileExtension;
                    if (!fileManager.Exists(segmentFileName, fileManager.GetMasterTrace()))
                    {
                        segment.Dirty.Set();
                    }
                }

                // Compute segment size estimates
                for (int i = 0; i < segments.Count; i++)
                {
                    int start = segments[i].start.Value;
                    int end = (i + 1 < segments.Count) ? segments[i + 1].start.Value : mergedFiles.Count;
                    segments[i].estimatedDataLengthInformationalOnly = 0;
                    for (int j = start; j < end; j++)
                    {
                        segments[i].estimatedDataLengthInformationalOnly += mergedFiles[j].EmbeddedStreamLength;
                    }
                }

                // debug logging - callouts
                if (traceDynpack != null)
                {
                    traceDynpack.WriteLine();

                    traceDynpack.WriteLine("Callout - over-large (unsplit) files");
                    for (int i = 0; i < mergedFiles.Count; i++)
                    {
                        if ((mergedFiles[i].Range == null) && (mergedFiles[i].EmbeddedStreamLength > segmentSizeTarget))
                        {
                            traceDynpack.WriteLine("{7} [{5}] {0}{4}{6} {1} {2} {3}", mergedFiles[i].EmbeddedStreamLength, mergedFiles[i].CreationTimeUtc, mergedFiles[i].LastWriteTimeUtc, mergedFiles[i].PartialPath, mergedFiles[i].Range != null ? String.Format("[{0}]", mergedFiles[i].Range) : String.Empty, i, mergedFiles[i].Segment.Dirty.Value ? " dirty=true" : String.Empty, mergedFiles[i].DiagnosticSerialNumber);
                        }
                    }
                    traceDynpack.WriteLine();

                    traceDynpack.WriteLine("Callout - all files with Range record");
                    for (int i = 0; i < mergedFiles.Count; i++)
                    {
                        if (mergedFiles[i].Range != null)
                        {
                            traceDynpack.WriteLine("{7} [{5}] {0}{4}{6} {1} {2} {3}", mergedFiles[i].EmbeddedStreamLength, mergedFiles[i].CreationTimeUtc, mergedFiles[i].LastWriteTimeUtc, mergedFiles[i].PartialPath, mergedFiles[i].Range != null ? String.Format("[{0}]", mergedFiles[i].Range) : String.Empty, i, mergedFiles[i].Segment.Dirty.Value ? " dirty=true" : String.Empty, mergedFiles[i].DiagnosticSerialNumber);
                        }
                    }
                    traceDynpack.WriteLine();
                }


                // From this point forward, all concurrency-unsafe updates to data structures should
                // be finished. Some safe updates (such as setting dirty flags or changing serial
                // numbers) are permitted after this point


                IFaultInstance faultDynamicPackStage = faultDynamicPack.Select("Stage", "1-start");

                using (ConcurrentMessageLog messagesLog = new ConcurrentMessageLog(Interactive(), true/*enableSequencing*/))
                {
                    int threadCount = GetConcurrency(fileManager, context);
                    using (ConcurrentTasks concurrent = new ConcurrentTasks(threadCount, 0, messagesLog, traceDynpack != null ? traceDynpack : fileManager.GetMasterTrace()))
                    {
                        int fatal;
                        bool abort = false;


                        // begin concurrent region


                        // remove abandoned temp files
                        faultDynamicPackStage = faultDynamicPack.Select("Stage", "2-remove-temporary-files");
                        fatal = 0;
                        {
                            string targetFileNamePrefix = targetArchiveFileNameTemplate + ".";
                            foreach (string segmentFileNameEnum in fileManager.GetFileNames(targetFileNamePrefix, fileManager.GetMasterTrace()))
                            {
                                concurrent.WaitQueueNotFull();
                                if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                {
                                    if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                                    {
                                        abort = true;
                                        break;
                                    }
                                    fatal = 0;
                                }

                                // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                // variable) in order to capture each value in the anonymous method.
                                // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                string segmentFileName = segmentFileNameEnum;

                                Debug.Assert(segmentFileName.StartsWith(targetFileNamePrefix, StringComparison.OrdinalIgnoreCase));

                                if (segmentFileName.EndsWith(DynPackTempFileExtension))
                                {
                                    IFaultInstance faultDynamicPackFileOperation = faultDynamicPackStage.Select("Delete", segmentFileName);
                                    long sequenceNumber = messagesLog.GetSequenceNumber();
                                    concurrent.Do(
                                        String.Format("delete-tempfile:{0}", segmentFileName),
                                        delegate(ConcurrentTasks.ITaskContext taskContext)
                                        {
                                            using (TextWriter threadTraceDynPack = TaskLogWriter.Create(traceDynpack))
                                            {
                                                using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                                {
                                                    try
                                                    {
                                                        using (TextWriter threadTraceFileManager = TaskLogWriter.Create(fileManager.GetMasterTrace()))
                                                        {
                                                            messages.WriteLine("Deleting (old temporary file): {0}", segmentFileName);
                                                            fileManager.Delete(segmentFileName, threadTraceFileManager);
                                                        }
                                                    }
                                                    catch (Exception exception)
                                                    {
                                                        if (threadTraceDynPack != null)
                                                        {
                                                            threadTraceDynPack.WriteLine("Exception deleting {0}: {1}", segmentFileName, exception);
                                                        }
                                                        messages.WriteLine("Error deleting {0}: {1}", segmentFileName, exception.Message);

                                                        Interlocked.Exchange(ref fatal, 1);
                                                        throw;
                                                    }
                                                }
                                            }
                                        });
                                }

                                messagesLog.Flush();
                            }
                        }

                        // state of "fatal" continues into this region

                        // verify integrity of non-dirty segments - note this validates metadata
                        // (i.e. the structure of the segment pack file) but DOES NOT verify content
                        // of each file.
                        faultDynamicPackStage = faultDynamicPack.Select("Stage", "3-validate-nondirty-segment-files");
                        List<string> badSegments = new List<string>(); // multi-threaded: lock this!
                        if (verifyNonDirtyMetadata)
                        {
                            for (int iEnum = 0; iEnum < segments.Count; iEnum++)
                            {
                                concurrent.WaitQueueNotFull();
                                if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                {
                                    if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                                    {
                                        abort = true;
                                        break;
                                    }
                                    fatal = 0;
                                }

                                // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                // variable) in order to capture each value in the anonymous method.
                                // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                int i = iEnum;
                                SegmentRecord segment = segments[iEnum];

                                if (!segment.Dirty.Value)
                                {
                                    string segmentFileName = targetArchiveFileNameTemplate + "." + segment.Name + DynPackFileExtension;

                                    IFaultInstance faultDynamicPackFileOperation = faultDynamicPackStage.Select("Validate", segmentFileName);
                                    long sequenceNumber = messagesLog.GetSequenceNumber();
                                    concurrent.Do(
                                        String.Format("validate-nondirty:{0}", segmentFileName),
                                        delegate(ConcurrentTasks.ITaskContext taskContext)
                                        {
                                            using (TextWriter threadTraceDynPack = TaskLogWriter.Create(traceDynpack))
                                            {
                                                using (TextWriter threadTraceFileManager = TaskLogWriter.Create(fileManager.GetMasterTrace()))
                                                {
                                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                                    {
                                                        bool invalid = false;

                                                        if (threadTraceDynPack != null)
                                                        {
                                                            threadTraceDynPack.WriteLine("Validating non-dirty segment: {0} {1}", segment.DiagnosticSerialNumber, segment.Name);
                                                        }
                                                        messages.WriteLine("Validating non-dirty segment: {0}", segment.Name);

                                                        using (ILocalFileCopy fileRef = fileManager.Read(segmentFileName, null/*progressTracker*/, threadTraceFileManager))
                                                        {
                                                            Context unpackContext = new Context(context);
                                                            if (unpackContext.compressionOption == CompressionOption.Compress)
                                                            {
                                                                unpackContext.compressionOption = CompressionOption.Decompress;
                                                            }
                                                            if (unpackContext.cryptoOption == EncryptionOption.Encrypt)
                                                            {
                                                                unpackContext.cryptoOption = EncryptionOption.Decrypt;
                                                                unpackContext.decrypt = unpackContext.encrypt;
                                                                unpackContext.encrypt = null;
                                                            }
                                                            ulong segmentSerialNumber = 0;
                                                            byte[] segmentRandomArchiveSignature = new byte[0];
                                                            UnpackedFileRecord[] archiveFiles = null;
                                                            try
                                                            {
                                                                using (Stream segmentStream = fileRef.Read())
                                                                {
                                                                    ApplicationException[] deferredExceptions;
                                                                    archiveFiles = UnpackInternal(segmentStream, source, unpackContext, UnpackMode.Parse, out segmentSerialNumber, out segmentRandomArchiveSignature, threadTraceDynPack, faultDynamicPack.Select("VerifySegment", segmentFileName), out deferredExceptions, null/*localSignaturePath*/);
                                                                    Debug.Assert(deferredExceptions == null); // load manifest should never generate deferred exceptions
                                                                }
                                                            }
                                                            catch (Exception exception)
                                                            {
                                                                invalid = true;

                                                                if (traceDynpack != null)
                                                                {
                                                                    traceDynpack.WriteLine("Segment corrupt, could not be read: {0}", exception);
                                                                }
                                                                messages.WriteLine("SEGMENT INTEGRITY PROBLEM {0} (segment corrupt, could not be read): {1}", segment.Name, exception);
                                                            }

                                                            if (!ArrayEqual(segmentRandomArchiveSignature, randomArchiveSignature))
                                                            {
                                                                invalid = true;

                                                                if (traceDynpack != null)
                                                                {
                                                                    traceDynpack.WriteLine("Segment random signature mismatch: expected={0}, actual={1}", LogWriter.ScrubSecuritySensitiveValue(randomArchiveSignature), LogWriter.ScrubSecuritySensitiveValue(segmentRandomArchiveSignature));
                                                                }
                                                                messages.WriteLine("SEGMENT INTEGRITY PROBLEM {0} (serial number mismatch): {1}", segment.Name, segmentFileName);
                                                            }

                                                            if (segmentSerialNumber != segment.SerialNumber)
                                                            {
                                                                invalid = true;

                                                                if (traceDynpack != null)
                                                                {
                                                                    traceDynpack.WriteLine("Segment serial number mismatch: manfest-ref={0}, actual={1}", segment.SerialNumber, segmentSerialNumber);
                                                                }
                                                                messages.WriteLine("SEGMENT INTEGRITY PROBLEM {0} (serial number mismatch): {1}", segment.Name, segmentFileName);
                                                            }

                                                            if (archiveFiles != null)
                                                            {
                                                                int segmentStart = segment.start.Value;
                                                                int segmentLength = (i < segments.Count - 1 ? segments[i + 1].start.Value : mergedFiles.Count) - segmentStart;
                                                                if (segmentLength != archiveFiles.Length)
                                                                {
                                                                    invalid = true;

                                                                    if (traceDynpack != null)
                                                                    {
                                                                        traceDynpack.WriteLine("Length mismatch: {0}, {1}", segmentLength, archiveFiles.Length);
                                                                    }
                                                                    messages.WriteLine("SEGMENT INTEGRITY PROBLEM {0} (length mismatch): {1}", segment.Name, segmentFileName);
                                                                }

                                                                bool stop = false;
                                                                for (int j = 0; (j < segmentLength) && !stop; j++)
                                                                {
                                                                    if (!String.Equals(archiveFiles[j].ArchivePath, mergedFiles[j + segmentStart].PartialPath.ToString()))
                                                                    {
                                                                        invalid = true;
                                                                        stop = true;

                                                                        if (traceDynpack != null)
                                                                        {
                                                                            traceDynpack.WriteLine("File added or removed: {0} : {1}", archiveFiles[j].ArchivePath, mergedFiles[j + segmentStart].PartialPath);
                                                                        }
                                                                        messages.WriteLine("SEGMENT INTEGRITY PROBLEM {0} (file added or removed): {1} : {2}", segment.Name, archiveFiles[j].ArchivePath, mergedFiles[j + segmentStart].PartialPath);
                                                                    }
                                                                    else if ((archiveFiles[j].CreationTimeUtc != mergedFiles[j + segmentStart].CreationTimeUtc) ||
                                                                        (archiveFiles[j].LastWriteTimeUtc != mergedFiles[j + segmentStart].LastWriteTimeUtc))
                                                                    {
                                                                        // TODO: when using -ignoreunchanged, hashes should be checked.
                                                                        // BUT: hashes are stored only in manifest, not segment - requires change to that
                                                                        // Putting manifest hash in segment is misleading if file has changed since manifest creation,
                                                                        // but it's inefficient to recompute hash for each file. No good solution at this time.

                                                                        invalid = true;

                                                                        if (traceDynpack != null)
                                                                        {
                                                                            traceDynpack.WriteLine("File timestamp(s) different: {0}", archiveFiles[j].ArchivePath);
                                                                        }
                                                                        messages.WriteLine("SEGMENT INTEGRITY PROBLEM {0} (file timestamp(s) different): {1}", segment.Name, archiveFiles[j].ArchivePath);
                                                                        break;
                                                                    }
                                                                    else if (archiveFiles[j].EmbeddedStreamLength != mergedFiles[j + segmentStart].EmbeddedStreamLength)
                                                                    {
                                                                        invalid = true;

                                                                        if (traceDynpack != null)
                                                                        {
                                                                            traceDynpack.WriteLine("File length different: {0}", archiveFiles[j].ArchivePath);
                                                                        }
                                                                        messages.WriteLine("SEGMENT INTEGRITY PROBLEM {0} (file length different): {1}", segment.Name, archiveFiles[j].ArchivePath);
                                                                        break;
                                                                    }
                                                                }
                                                            }
                                                            if (invalid)
                                                            {
                                                                segment.Dirty.Set();
                                                                // dirty segment will be removed in subsequent pass

                                                                try
                                                                {
                                                                    string tempFile = Path.GetTempFileName();
                                                                    fileRef.CopyLocal(tempFile, true/*overwrite*/);
                                                                    string message = String.Format("Copied of corrupt segment \"{0}\" to \"{1}\"", segmentFileName, tempFile);
                                                                    if (traceDynpack != null)
                                                                    {
                                                                        traceDynpack.WriteLine(message);
                                                                    }
                                                                    messages.WriteLine(ConsoleColor.Yellow, message);
                                                                }
                                                                catch (IOException exception)
                                                                {
                                                                    if (threadTraceDynPack != null)
                                                                    {
                                                                        threadTraceDynPack.WriteLine("Exception verifying {0}: {1}", segmentFileName, exception);
                                                                    }
                                                                    messages.WriteLine("Exception verifying {0}: {1}", segmentFileName, exception);
                                                                    uint hr = (uint)Marshal.GetHRForException(exception);
                                                                    if (hr != 0x80070070/*out of disk space*/)
                                                                    {
                                                                        Interlocked.Exchange(ref fatal, 1);
                                                                        throw;
                                                                    }
                                                                    // running out of disk space saving the invalid segment was regarded as non-fatal
                                                                }

                                                                // TODO: rename segment to backup name or delete segment as appropriate
                                                            }

                                                            if (invalid)
                                                            {
                                                                lock (badSegments)
                                                                {
                                                                    badSegments.Add(segmentFileName);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        });
                                }

                                messagesLog.Flush();
                            }
                        }

                        // turns out that updating segment serial numbers (below) could break
                        // non-dirty segment validation, as the serial number changes out from
                        // under it. therefore, introduce a barrier here.
                        concurrent.Drain(delegate() { messagesLog.Flush(); }, WaitInterval);
                        messagesLog.Flush();
                        if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                        {
                            if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                            {
                                throw new ApplicationException("Unable to continue after last error");
                            }
                        }

                        // Assign new serial numbers for dirty segments
                        segmentSerialNumbering++; // do not reuse manifest serial number
                        foreach (SegmentRecord segment in segments)
                        {
                            if (segment.Dirty.Value)
                            {
                                segment.SerialNumber = segmentSerialNumbering++;
                            }
                        }

                        // Backup (or remove if !safe) dirty segments
                        faultDynamicPackStage = faultDynamicPack.Select("Stage", "4-backup-dirty-segment-files");
                        fatal = 0;
                        {
                            List<KeyValuePair<string, bool>> namesToBackupOrRemove = new List<KeyValuePair<string, bool>>();
                            namesToBackupOrRemove.Add(new KeyValuePair<string, bool>(DynPackManifestName, false/*backup*/));
                            foreach (SegmentRecord segment in segments)
                            {
                                if (segment.Dirty.Value)
                                {
                                    namesToBackupOrRemove.Add(new KeyValuePair<string, bool>(segment.Name, false/*backup*/));
                                }
                            }
                            string targetFileNamePrefix = targetArchiveFileNameTemplate + ".";
                            foreach (string file in fileManager.GetFileNames(targetFileNamePrefix, fileManager.GetMasterTrace()))
                            {
                                Debug.Assert(file.StartsWith(targetFileNamePrefix, StringComparison.OrdinalIgnoreCase));

                                string suffix = file.Substring(targetFileNamePrefix.Length);

                                if (!suffix.StartsWith(DynPackBackupPrefix) && suffix.EndsWith(DynPackFileExtension))
                                {
                                    suffix = suffix.Substring(0, suffix.Length - DynPackFileExtension.Length);
                                    if ((suffix != DynPackManifestName)
                                        && (null == segments.Find(delegate(SegmentRecord a) { return a.Name == suffix; })))
                                    {
                                        namesToBackupOrRemove.Add(new KeyValuePair<string, bool>(suffix, true/*unreferenced*/));
                                    }
                                }
                            }

                            foreach (KeyValuePair<string, bool> nameEnum in namesToBackupOrRemove)
                            {
                                concurrent.WaitQueueNotFull();
                                if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                {
                                    if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                                    {
                                        abort = true;
                                        break;
                                    }
                                    fatal = 0;
                                }

                                // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                // variable) in order to capture each value in the anonymous method.
                                // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                string name = nameEnum.Key;
                                bool unreferenced = nameEnum.Value;

                                string segmentFileName = String.Concat(targetArchiveFileNameTemplate, ".", name, DynPackFileExtension);
                                string segmentBackupFileName = String.Concat(targetArchiveFileNameTemplate, ".", DynPackBackupPrefix, name, DynPackFileExtension);

                                IFaultInstance faultDynamicPackFileOperation = faultDynamicPackStage.Select("RenameOld", segmentFileName);
                                long sequenceNumber = messagesLog.GetSequenceNumber();
                                concurrent.Do(
                                    String.Format("rename-old-segment:{0}", name),
                                    delegate(ConcurrentTasks.ITaskContext taskContext)
                                    {
                                        using (TextWriter threadTraceDynPack = TaskLogWriter.Create(traceDynpack))
                                        {
                                            using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                            {
                                                try
                                                {
                                                    using (TextWriter threadTraceFileManager = TaskLogWriter.Create(fileManager.GetMasterTrace()))
                                                    {
                                                        bool manifest = name.Equals(DynPackManifestName);

                                                        if (fileManager.Exists(segmentFileName, threadTraceFileManager))
                                                        {
                                                            // Back up segments and manifest if "safe" mode set.
                                                            // But only back up if no backup exists. Otherwise, retain the older backup files
                                                            // so that the backup is a coherent picture. They will be cleared when a
                                                            // run finally completes. (Which means delete the "newer" items to restore to backup.)
                                                            if (!safe || fileManager.Exists(segmentBackupFileName, threadTraceFileManager))
                                                            {
                                                                // For safety, don't delete manifest even in "unsafe" mode, but also don't rename.
                                                                // Manifest file is atomically overwritten later.
                                                                if (!manifest)
                                                                {
                                                                    messages.WriteLine("Deleting (segment {1}): {0}", segmentFileName, unreferenced ? "unreferenced" : "dirty");
                                                                    fileManager.Delete(segmentFileName, threadTraceFileManager);
                                                                }
                                                            }
                                                            else
                                                            {
                                                                if (!manifest)
                                                                {
                                                                    messages.WriteLine("Renaming (segment {2}): {0} to {1}", segmentFileName, segmentBackupFileName, unreferenced ? "unreferenced" : "dirty");
                                                                    fileManager.Rename(segmentFileName, segmentBackupFileName, threadTraceFileManager);
                                                                }
                                                                else
                                                                {
                                                                    messages.WriteLine("Copying: {0} to {1}", segmentFileName, segmentBackupFileName);
                                                                    fileManager.Copy(segmentFileName, segmentBackupFileName, false/*overwrite*/, threadTraceFileManager);
                                                                }
                                                            }
                                                        }
                                                        // else - creation of new segment backup barrier is done in individual segment archiving task
                                                    }
                                                }
                                                catch (Exception exception)
                                                {
                                                    if (threadTraceDynPack != null)
                                                    {
                                                        threadTraceDynPack.WriteLine("Exception renaming or deleting old segment {0}{1}: {2}", segmentFileName, segmentBackupFileName != null ? " to " + segmentBackupFileName : String.Empty, exception);
                                                    }
                                                    messages.WriteLine("Error renaming/deleting {0}: {1}", segmentFileName, exception.Message);

                                                    // Failure is fatal because it interferes with the integrity of backup
                                                    // files. If process were allowed to continue and files overwritten, the
                                                    // archive could be inconsistent (e.g. if old segments are not removed or
                                                    // renamed but new manifest is written, then program fails before writing
                                                    // new versions of the segments - old segment will remain while manifest
                                                    // will claim it is the new one, resulting in serial number inconsistency)
                                                    Interlocked.Exchange(ref fatal, 1);
                                                    throw;
                                                }
                                            }
                                        }
                                    });

                                messagesLog.Flush();
                            }
                        }

                        // Drain all rename/delete of old segment files so that uploads can be
                        // initiated subsequently without worry of colliding with a file that hasn't
                        // been moved out of the way yet.
                        concurrent.Drain(delegate() { messagesLog.Flush(); }, WaitInterval);
                        messagesLog.Flush();
                        if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                        {
                            if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                            {
                                throw new ApplicationException("Unable to continue after last error");
                            }
                        }


                        // From this point forward, ALL UPDATES (threadsafe or not) should be completed.
                        // Structures should be regarded as immutable/read-only


                        // redundancy check - ensure all serial numbers are valid
                        {
                            Dictionary<ulong, bool> used = new Dictionary<ulong, bool>(segments.Count);
                            for (int i = 0; i < segments.Count; i++)
                            {
                                ulong segmentSerialNumber = segments[i].SerialNumber;
                                if (segmentSerialNumber == 0)
                                {
                                    throw new InvalidOperationException("Segment serial number not initialized");
                                }
                                if (segmentSerialNumber > segmentSerialNumbering)
                                {
                                    throw new InvalidOperationException("Segment serial number beyond limit");
                                }
                                if (used.ContainsKey(segmentSerialNumber))
                                {
                                    throw new InvalidOperationException("Segment serial number used multiple times");
                                }
                                used.Add(segmentSerialNumber, false);
                            }
                        }

                        // Save manifest and diagnostic file
                        // these tasks are done synchronously since they represent a small fraction of
                        // run time for a large job.
                        {
                            faultDynamicPackStage = faultDynamicPack.Select("Stage", "5-write-diagnostic-file");
                            if (diagnosticPath != null)
                            {
                                string newDiagnosticFile = Path.Combine(diagnosticPath, manifestFileName + DynPackManifestLogFileExtension);
                                string oldDiagnosticFile = Path.Combine(diagnosticPath, manifestFileName + DynPackManifestLogFileExtensionOld);

                                // "rotate" diagnostic files to facilitate windiff for seeing what changed
                                if (File.Exists(oldDiagnosticFile))
                                {
                                    File.Delete(oldDiagnosticFile);
                                }
                                if (File.Exists(newDiagnosticFile))
                                {
                                    File.Move(newDiagnosticFile, oldDiagnosticFile);
                                }

                                // the sole purpose of this is to compute a segment metadata digest value (using CRC32) to be written to the diagnostic log file
                                Dictionary<SegmentRecord, uint> segmentDiagnosticCRC32 = new Dictionary<SegmentRecord, uint>();
                                for (int i = 0; i < segments.Count; i++)
                                {
                                    byte[] b;
                                    using (CheckedWriteStream checkedStream = new CheckedWriteStream(Stream.Null, new CRC32()))
                                    {
                                        int start = segments[i].start.Value;
                                        int endP1 = i < segments.Count - 1 ? segments[i + 1].start.Value : mergedFiles.Count;
                                        for (int j = start; j < endP1; j++)
                                        {
                                            FileRecord record = mergedFiles[j];
                                            BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, record.EmbeddedStreamLength);
                                            if (record.CreationTimeUtc != default(DateTime))
                                            {
                                                BinaryWriteUtils.WriteStringUtf8(checkedStream, PackedFileHeaderRecord.FormatDateTime(record.CreationTimeUtc));
                                            }
                                            if (record.LastWriteTimeUtc != default(DateTime))
                                            {
                                                BinaryWriteUtils.WriteStringUtf8(checkedStream, PackedFileHeaderRecord.FormatDateTime(record.LastWriteTimeUtc));
                                            }
                                            BinaryWriteUtils.WriteStringUtf8(checkedStream, record.PartialPath.ToString());
                                        }

                                        checkedStream.Close();
                                        b = checkedStream.CheckValue;
                                    }

                                    uint checkValue = (uint)b[0] + ((uint)b[1] << 8) + ((uint)b[2] << 16) + ((uint)b[3] << 24);
                                    segmentDiagnosticCRC32.Add(segments[i], checkValue);
                                }

                                Dictionary<SegmentRecord, long> segmentSizes = new Dictionary<SegmentRecord, long>();
                                foreach (FileRecord record in mergedFiles)
                                {
                                    if (!segmentSizes.ContainsKey(record.Segment))
                                    {
                                        segmentSizes.Add(record.Segment, 0);
                                    }
                                    segmentSizes[record.Segment] = segmentSizes[record.Segment] + record.EmbeddedStreamLength + record.HeaderOverhead;
                                }

                                using (TextWriter writer = new StreamWriter(newDiagnosticFile))
                                {
                                    if (verifyNonDirtyMetadata)
                                    {
                                        writer.WriteLine("[Non-dirty segment metadata verification enabled]");
                                        if (badSegments.Count != 0)
                                        {
                                            writer.WriteLine("{0} BAD SEGMENTS DETECTED DURING VERIFICATION:", badSegments.Count);
                                            foreach (string badSegment in badSegments)
                                            {
                                                writer.WriteLine("  {0}", badSegment);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        writer.WriteLine("[Non-dirty segment metadata verification skipped]");
                                    }
                                    writer.WriteLine();

                                    SegmentRecord currentSegment = null;
                                    foreach (FileRecord record in mergedFiles)
                                    {
                                        if (currentSegment != record.Segment)
                                        {
                                            currentSegment = record.Segment;
                                            writer.WriteLine("SEGMENT {0} {1} {2:x8}" + Environment.NewLine + "{3} {4}", currentSegment.Name, segmentSizes[currentSegment], segmentDiagnosticCRC32[currentSegment], currentSegment.SerialNumber, currentSegment.Dirty.Value ? "dirty" : "not-dirty");
                                        }
                                    }
                                    writer.WriteLine();

                                    currentSegment = null;
                                    foreach (FileRecord record in mergedFiles)
                                    {
                                        if (currentSegment != record.Segment)
                                        {
                                            currentSegment = record.Segment;
                                            writer.WriteLine("SEGMENT {0} {1} {2:x8}", currentSegment.Name, segmentSizes[currentSegment], segmentDiagnosticCRC32[currentSegment]);
                                        }
                                        writer.WriteLine("  FILE {0,12}{4} {1} {2} {3}", record.EmbeddedStreamLength, record.CreationTimeUtc.ToString(DynPackDiagnosticDateTimeFormat), record.LastWriteTimeUtc.ToString(DynPackDiagnosticDateTimeFormat), record.PartialPath, record.Range != null ? String.Format("[{0}]", record.Range) : String.Empty);
                                    }
                                }
                                File.SetLastWriteTime(newDiagnosticFile, context.now);
                                File.SetCreationTime(newDiagnosticFile, context.now);

                                if (windiff && File.Exists(newDiagnosticFile) && File.Exists(oldDiagnosticFile))
                                {
                                    Windiff(oldDiagnosticFile, newDiagnosticFile, false/*waitForExit*/);
                                }
                            }


                            // Write actual archive manifest
                            faultDynamicPackStage = faultDynamicPack.Select("Stage", "6-write-manifest-file");
                            if (traceDynpack != null)
                            {
                                traceDynpack.WriteLine("Writing: {0}", manifestFileName);
                            }
                            Console.WriteLine("Writing: {0}", manifestFileName);
                            string manifestTempFileName = String.Concat(targetArchiveFileNameTemplate, ".", DynPackManifestName, DynPackTempFileExtension);
                            CheckedWriteStream localSignature = null;
                            using (ILocalFileCopy fileRef = fileManager.WriteTemp(manifestTempFileName, fileManager.GetMasterTrace()))
                            {
                                using (Stream fileStream = fileRef.Write())
                                {
                                    CryptoKeygroup keys = null;
                                    EncryptedFileContainerHeader fch = null;
                                    if (context.cryptoOption == EncryptionOption.Encrypt)
                                    {
                                        CryptoMasterKeyCacheEntry entry = context.encrypt.GetDefaultMasterKeyEntry();
                                        fch = new EncryptedFileContainerHeader(context.encrypt);
                                        fch.passwordSalt = entry.PasswordSalt;
                                        context.encrypt.algorithm.DeriveNewSessionKeys(entry.MasterKey, out fch.fileSalt, out keys);
                                    }

                                    StreamStack.DoWithStreamStack(
                                        fileStream,
                                        new StreamStack.StreamWrapMethod[]
                                        {
                                            delegate(Stream stream)
                                            {
                                                if (localSignaturePath != null)
                                                {
                                                    localSignature = new CheckedWriteStream(stream, context.encrypt.algorithm.CreateLocalSignatureMACGenerator(keys.LocalSignatureKey));
                                                }
                                                return localSignature;
                                            },
                                            delegate(Stream stream)
                                            {
                                                // see note and references about
                                                // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                                if (context.cryptoOption == EncryptionOption.Encrypt)
                                                {
                                                    return new TaggedWriteStream(stream, context.encrypt.algorithm.CreateMACGenerator(keys.SigningKey));
                                                }
                                                return null;
                                            },
                                            delegate(Stream stream)
                                            {
                                                if (context.cryptoOption == EncryptionOption.Encrypt)
                                                {
                                                    // why write here? need to write salt within HMAC container
                                                    fch.Write(stream, context.encrypt.algorithm);
                                                }
                                                return null;
                                            },
                                            delegate(Stream stream)
                                            {
                                                if (context.cryptoOption == EncryptionOption.Encrypt)
                                                {
                                                    return context.encrypt.algorithm.CreateEncryptStream(stream, keys.CipherKey, keys.InitialCounter);
                                                }
                                                return null;
                                            },
                                            delegate(Stream stream)
                                            {
                                                if (context.compressionOption == CompressionOption.Compress)
                                                {
                                                    return new BlockedCompressStream(stream);
                                                }
                                                return null;
                                            },
                                            delegate(Stream stream)
                                            {
                                                // total file CRC32 check value
                                                return new TaggedWriteStream(stream, new CRC32());
                                            }
                                        },
                                        delegate(Stream stream)
                                        {
                                            BinaryWriteUtils.WriteBytes(stream, new byte[1] { PackArchiveFixedHeaderNumber });

                                            BinaryWriteUtils.WriteVariableLengthByteArray(stream, randomArchiveSignature);

                                            BinaryWriteUtils.WriteVariableLengthQuantity(stream, segmentSerialNumbering++);

                                            KeyValuePair<int, string>[] parameters = new KeyValuePair<int, string>[0];
                                            foreach (KeyValuePair<int, string> parameter in parameters)
                                            {
                                                if (!(parameter.Key > 0))
                                                {
                                                    throw new InvalidOperationException("assertion failed: parameter.Key > 0");
                                                }
                                                BinaryWriteUtils.WriteVariableLengthQuantity(stream, parameter.Key);
                                            }
                                            BinaryWriteUtils.WriteVariableLengthQuantity(stream, 0);

                                            BinaryWriteUtils.WriteVariableLengthQuantity(stream, PackArchiveStructureTypeManifest);

                                            string currentSegmentName = null;
                                            ulong currentSegmentSerialNumber = 0;
                                            foreach (FileRecord record in mergedFiles)
                                            {
                                                if (!String.Equals(currentSegmentName, record.Segment.Name))
                                                {
                                                    currentSegmentName = record.Segment.Name;
                                                    currentSegmentSerialNumber = record.Segment.SerialNumber;

                                                    PackedFileHeaderRecord segmentHeader = new PackedFileHeaderRecord(null, default(DateTime), default(DateTime), default(PackedFileHeaderRecord.HeaderAttributes), 0, record.Segment.Name, record.Segment.SerialNumber);
                                                    segmentHeader.Write(stream);
                                                }

                                                record.WriteHeader(stream);
                                            }

                                            PackedFileHeaderRecord.WriteNullHeader(stream);
                                        });
                                }

                                faultDynamicPackStage.Select("Wrote", manifestTempFileName);
                                fileManager.Commit(fileRef, manifestTempFileName, manifestFileName, true/*overwrite*/, null/*progressTracker*/, fileManager.GetMasterTrace());
                                faultDynamicPackStage.Select("Committed", manifestFileName);
                            }
                            if (localSignaturePath != null)
                            {
                                string directory = Path.GetDirectoryName(localSignaturePath);
                                if (!String.IsNullOrEmpty(directory))
                                {
                                    Directory.CreateDirectory(directory);
                                }
                                File.WriteAllBytes(localSignaturePath, localSignature.CheckValue);
                            }
                        }

                        long bytesRemaining = 0;
                        foreach (SegmentRecord segment in segments)
                        {
                            if (segment.Dirty.Value)
                            {
                                Interlocked.Add(ref bytesRemaining, segment.estimatedDataLengthInformationalOnly);
                            }
                        }


                        List<ProgressTracker> progressTrackers = new List<ProgressTracker>(); // Use lock() on this!
                        int maxStatusLines = 0;
                        bool progressVisible = false;
                        DateTime lastProgressUpdate = default(DateTime);
                        ConcurrentTasks.WaitIntervalMethod eraseProgress = delegate()
                        {
                            EraseProgress(ref lastProgressUpdate, progressTrackers, ref maxStatusLines, ref progressVisible);
                        };
                        ConcurrentMessageLog.PrepareConsoleMethod prepareConsole = delegate()
                        {
                            eraseProgress();
                        };
                        ConcurrentTasks.WaitIntervalMethod showProgress = delegate()
                        {
                            ShowProgress(ShowProgressType.Upload, messagesLog, prepareConsole, WaitInterval, ref lastProgressUpdate, progressTrackers, Http.HttpGlobalControl.NetworkMeterCombined, ref maxStatusLines, ref progressVisible, ref fatal, ref bytesRemaining);
                        };


                        // Archive modified segments (concurrently)
                        faultDynamicPackStage = faultDynamicPack.Select("Stage", "7-write-segment-files");
                        long sharedSequenceNumber = messagesLog.GetSequenceNumber();
                        using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sharedSequenceNumber))
                        {
                            // ensure this shared sequence number is used at least once.
                        }
                        fatal = 0;
                        for (int iEnum = 0; iEnum < segments.Count; iEnum++)
                        {
                            concurrent.WaitQueueNotFull(showProgress, WaitInterval);
                            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                            {
                                if (abort || !FatalPromptContinue(concurrent, messagesLog, showProgress, WaitInterval, prepareConsole))
                                {
                                    abort = true;
                                    break;
                                }
                                fatal = 0;
                            }

                            // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                            // variable) in order to capture each value in the anonymous method.
                            // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                            int i = iEnum;
                            SegmentRecord segment = segments[i];

                            if (segment.Dirty.Value)
                            {
                                string segmentFileName = String.Concat(targetArchiveFileNameTemplate, ".", segment.Name, DynPackFileExtension);

                                IFaultInstance faultDynamicPackFileOperation = faultDynamicPackStage.Select("ArchiveSegment", segmentFileName);

                                long sequenceNumber = sharedSequenceNumber; // messagesLog.GetSequenceNumber();

                                concurrent.Do(
                                    String.Format("write-segment:{0}", segmentFileName),
                                    delegate(ConcurrentTasks.ITaskContext taskContext)
                                    {
                                        using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                        {
                                            messages.WriteLine("Writing: {0}", segmentFileName);
                                        }

                                        ProgressTracker progressTracker = null;

                                        try
                                        {
                                            using (TextWriter threadTraceDynPack = TaskLogWriter.Create(traceDynpack))
                                            {
                                                using (TextWriter threadTraceFileManager = TaskLogWriter.Create(fileManager.GetMasterTrace()))
                                                {
                                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                                    {
                                                        progressTracker = new ProgressTracker(segmentFileName);
                                                        lock (progressTrackers)
                                                        {
                                                            progressTrackers.Add(progressTracker);
                                                        }

                                                        try
                                                        {
                                                            bool succeeded = false;
                                                            string segmentTempFileName = String.Concat(targetArchiveFileNameTemplate, ".", segment.Name, DynPackTempFileExtension);
                                                            using (ILocalFileCopy fileRef = fileManager.WriteTemp(segmentTempFileName, threadTraceFileManager))
                                                            {
                                                                try
                                                                {
                                                                    if (threadTraceDynPack != null)
                                                                    {
                                                                        threadTraceDynPack.WriteLine("Writing: {0}", segmentFileName);
                                                                    }
                                                                    using (Stream fileStream = fileRef.Write())
                                                                    {
                                                                        // reserve estimated file size now, to reduce file system fragmentation
                                                                        try
                                                                        {
                                                                            long estimatedSegmentSize = segmentSizeTarget;
                                                                            int start = segment.start.Value;
                                                                            int end = (i + 1 < segments.Count) ? segments[i + 1].start.Value : mergedFiles.Count;
                                                                            int count = end - start;
                                                                            if (count == 1)
                                                                            {
                                                                                if (estimatedSegmentSize < mergedFiles[start].EmbeddedStreamLength)
                                                                                {
                                                                                    estimatedSegmentSize = mergedFiles[start].EmbeddedStreamLength;
                                                                                }
                                                                            }
                                                                            fileStream.SetLength(estimatedSegmentSize);
                                                                        }
                                                                        catch (IOException)
                                                                        {
                                                                        }

                                                                        CryptoKeygroup keys = null;
                                                                        EncryptedFileContainerHeader fch = null;
                                                                        if (context.cryptoOption == EncryptionOption.Encrypt)
                                                                        {
                                                                            CryptoMasterKeyCacheEntry entry = context.encrypt.GetDefaultMasterKeyEntry();
                                                                            fch = new EncryptedFileContainerHeader(context.encrypt);
                                                                            fch.passwordSalt = entry.PasswordSalt;
                                                                            context.encrypt.algorithm.DeriveNewSessionKeys(entry.MasterKey, out fch.fileSalt, out keys);
                                                                        }

                                                                        StreamStack.DoWithStreamStack(
                                                                            fileStream,
                                                                            new StreamStack.StreamWrapMethod[]
                                                                            {
                                                                                delegate(Stream stream)
                                                                                {
                                                                                    // see note and references about
                                                                                    // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                                                                    if (context.cryptoOption == EncryptionOption.Encrypt)
                                                                                    {
                                                                                        return new TaggedWriteStream(stream, context.encrypt.algorithm.CreateMACGenerator(keys.SigningKey));
                                                                                    }
                                                                                    return null;
                                                                                },
                                                                                delegate(Stream stream)
                                                                                {
                                                                                    if (context.cryptoOption == EncryptionOption.Encrypt)
                                                                                    {
                                                                                        // why write here? need to write salt within HMAC container
                                                                                        fch.Write(stream, context.encrypt.algorithm);
                                                                                    }
                                                                                    return null;
                                                                                },
                                                                                delegate(Stream stream)
                                                                                {
                                                                                    if (context.cryptoOption == EncryptionOption.Encrypt)
                                                                                    {
                                                                                        return context.encrypt.algorithm.CreateEncryptStream(stream, keys.CipherKey, keys.InitialCounter);
                                                                                    }
                                                                                    return null;
                                                                                },
                                                                                delegate(Stream stream)
                                                                                {
                                                                                    if (context.compressionOption == CompressionOption.Compress)
                                                                                    {
                                                                                        return new BlockedCompressStream(stream);
                                                                                    }
                                                                                    return null;
                                                                                },
                                                                                delegate(Stream stream)
                                                                                {
                                                                                    // total file CRC32 check value
                                                                                    return new TaggedWriteStream(stream, new CRC32());
                                                                                }
                                                                            },
                                                                            delegate(Stream stream)
                                                                            {
                                                                                BinaryWriteUtils.WriteBytes(stream, new byte[1] { PackArchiveFixedHeaderNumber });

                                                                                BinaryWriteUtils.WriteVariableLengthByteArray(stream, randomArchiveSignature);

                                                                                BinaryWriteUtils.WriteVariableLengthQuantity(stream, segment.SerialNumber);

                                                                                KeyValuePair<int, string>[] parameters = new KeyValuePair<int, string>[0];
                                                                                foreach (KeyValuePair<int, string> parameter in parameters)
                                                                                {
                                                                                    if (!(parameter.Key > 0))
                                                                                    {
                                                                                        throw new InvalidOperationException("assertion failed: parameter.Key > 0");
                                                                                    }
                                                                                    BinaryWriteUtils.WriteVariableLengthQuantity(stream, parameter.Key);
                                                                                }
                                                                                BinaryWriteUtils.WriteVariableLengthQuantity(stream, 0);

                                                                                BinaryWriteUtils.WriteVariableLengthQuantity(stream, PackArchiveStructureTypeFiles);

                                                                                int start = segment.start.Value;
                                                                                int end = (i + 1 < segments.Count) ? segments[i + 1].start.Value : mergedFiles.Count;
                                                                                int count = end - start;
                                                                                for (int j = 0; j < count; j++)
                                                                                {
                                                                                    const string NoOpPrefix = ".\\";
                                                                                    string fullPath = mergedFiles[j + start].PartialPath.ToString();
                                                                                    if (fullPath.StartsWith(NoOpPrefix))
                                                                                    {
                                                                                        // remove .\ from path because Path.Combine() doesn't do it,
                                                                                        // and a path that is exactly the maximum length will become
                                                                                        // too long as a result.
                                                                                        fullPath = fullPath.Substring(NoOpPrefix.Length);
                                                                                    }
                                                                                    fullPath = Path.Combine(source, fullPath);
                                                                                    PackOne(fullPath, stream, Path.GetDirectoryName(mergedFiles[j + start].PartialPath.ToString()), mergedFiles[j + start].Range, threadCount == 0/*enableRetry*/, context, threadTraceDynPack);
                                                                                }

                                                                                PackedFileHeaderRecord.WriteNullHeader(stream);
                                                                            });

                                                                        // remove any reserved space that turned out to be unneeded
                                                                        if (fileStream.Position < fileStream.Length)
                                                                        {
                                                                            fileStream.SetLength(fileStream.Position);
                                                                        }

                                                                        // create backup barrier before committing segment
                                                                        if (!fileManager.Exists(segmentFileName, threadTraceFileManager))
                                                                        {
                                                                            string segmentBackupFileName = String.Concat(targetArchiveFileNameTemplate, ".", DynPackBackupPrefix, segment.Name, DynPackFileExtension);
                                                                            if (safe && !fileManager.Exists(segmentBackupFileName, threadTraceFileManager))
                                                                            {
                                                                                // For non-existing segment, create empty backup file to ensure integrity
                                                                                // if partial archive is rolled back. Specifically: if a segment existed in the old
                                                                                // manifest but had not yet been created, in the new manifest the serial number will
                                                                                // be changed. Therefore, any such segments subsequently written must be removed
                                                                                // during roll-back or the archive will fail integrity checks.
                                                                                using (ConcurrentMessageLog.ThreadMessageLog messages2 = messagesLog.GetNewMessageLog(sequenceNumber))
                                                                                {
                                                                                    messages2.WriteLine("Marking (uncreated segment barrier): {0}", segmentBackupFileName);
                                                                                }
                                                                                string segmentBackupFileNameTemp = String.Concat(targetArchiveFileNameTemplate, ".", DynPackBackupPrefix, segment.Name, DynPackTempFileExtension);
                                                                                using (ILocalFileCopy fileRefBarrier = fileManager.WriteTemp(segmentBackupFileNameTemp, fileManager.GetMasterTrace()))
                                                                                {
                                                                                    fileManager.Commit(fileRefBarrier, segmentBackupFileNameTemp, segmentBackupFileName, true/*overwrite*/, null, threadTraceFileManager);
                                                                                }
                                                                            }
                                                                        }

                                                                        succeeded = true;
                                                                    }
                                                                }
                                                                finally
                                                                {
                                                                    Interlocked.Add(ref bytesRemaining, -segment.estimatedDataLengthInformationalOnly);

                                                                    faultDynamicPackFileOperation.Select("Wrote", segmentTempFileName);
                                                                    if (!succeeded)
                                                                    {
                                                                        fileManager.Abandon(fileRef, segmentTempFileName, threadTraceFileManager);
                                                                        faultDynamicPackFileOperation.Select("Abandoned", segmentFileName);
                                                                    }
                                                                    else
                                                                    {
                                                                        fileManager.Commit(fileRef, segmentTempFileName, segmentFileName, false/*overwrite*/, progressTracker, threadTraceFileManager);
                                                                        faultDynamicPackFileOperation.Select("Committed", segmentFileName);
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        catch (Exception exception)
                                                        {
                                                            if (threadTraceDynPack != null)
                                                            {
                                                                threadTraceDynPack.WriteLine("Exception archiving {0}: {1}", segmentFileName, exception);
                                                            }
                                                            messages.WriteLine("Error archiving {0}: {1}", segmentFileName, exception.Message);

                                                            Interlocked.Exchange(ref fatal, 1);
                                                            throw;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        finally
                                        {
                                            if (progressTracker != null)
                                            {
                                                lock (progressTrackers)
                                                {
                                                    progressTrackers.Remove(progressTracker);
                                                }
                                            }
                                        }
                                    },
                                    showProgress,
                                    WaitInterval);
                            }

                            messagesLog.Flush(prepareConsole);
                            showProgress();
                        }

                        // Finish creating (or uploading) segments
                        concurrent.Drain(showProgress, WaitInterval);
                        messagesLog.Flush(prepareConsole);
                        eraseProgress();
                        if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                        {
                            if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                            {
                                throw new ApplicationException("Unable to continue after last error");
                            }
                        }
                        faultDynamicPackStage = faultDynamicPack.Select("Stage", "8-write-segment-files-completed");


                        // upon successful completion - delete unreferenced items (backups and abandoned segments)
                        faultDynamicPackStage = faultDynamicPack.Select("Stage", "9-remove-backup-files");
                        fatal = 0;
                        {
                            string targetFileNamePrefix = targetArchiveFileNameTemplate + ".";
                            foreach (string segmentFileNameEnum in fileManager.GetFileNames(targetFileNamePrefix, fileManager.GetMasterTrace()))
                            {
                                concurrent.WaitQueueNotFull(showProgress, WaitInterval);
                                if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                {
                                    if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                                    {
                                        abort = true;
                                        break;
                                    }
                                    fatal = 0;
                                }

                                // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                // variable) in order to capture each value in the anonymous method.
                                // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                string segmentFileName = segmentFileNameEnum;

                                Debug.Assert(segmentFileName.StartsWith(targetFileNamePrefix, StringComparison.OrdinalIgnoreCase));

                                string suffix = segmentFileName.Substring(targetFileNamePrefix.Length);
                                if (suffix.EndsWith(DynPackFileExtension))
                                {
                                    suffix = suffix.Substring(0, suffix.Length - DynPackFileExtension.Length);
                                    if ((suffix != DynPackManifestName)
                                        && (null == segments.Find(delegate(SegmentRecord a) { return a.Name == suffix; })))
                                    {
                                        long sequenceNumber = messagesLog.GetSequenceNumber();
                                        concurrent.Do(
                                            String.Format("cleanup:{0}", segmentFileName),
                                            delegate(ConcurrentTasks.ITaskContext taskContext)
                                            {
                                                using (TextWriter threadTraceDynPack = TaskLogWriter.Create(traceDynpack))
                                                {
                                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                                    {
                                                        messages.WriteLine("Deleting (backup file): {0}", segmentFileName);
                                                        try
                                                        {
                                                            using (TextWriter threadTraceFileManager = TaskLogWriter.Create(fileManager.GetMasterTrace()))
                                                            {
                                                                fileManager.Delete(segmentFileName, threadTraceFileManager);
                                                            }
                                                        }
                                                        catch (Exception exception)
                                                        {
                                                            if (threadTraceDynPack != null)
                                                            {
                                                                threadTraceDynPack.WriteLine("Exception deleting {0}: {1}", segmentFileName, exception);
                                                            }
                                                            messages.WriteLine("Exception deleting {0}: {1}", segmentFileName, exception);

                                                            Interlocked.Exchange(ref fatal, 1);
                                                            throw;
                                                        }
                                                    }
                                                }
                                            });
                                    }
                                }

                                messagesLog.Flush();
                            }
                        }

                        // final flush of tasks and messages
                        concurrent.Drain(delegate() { messagesLog.Flush(); }, WaitInterval);
                        messagesLog.Flush();
                        if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                        {
                            if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                            {
                                throw new ApplicationException("Unable to continue after last error");
                            }
                            fatal = 0;
                        }


                        // end concurrent region
                        faultDynamicPackStage = faultDynamicPack.Select("Stage", "10-finished");
                    }
                }
            }

            if (traceDynpack != null)
            {
                traceDynpack.Dispose();
            }

            Console.WriteLine();
        }

        private enum ShowProgressType
        {
            Upload,
            Download,
        }
        private static void ShowProgress(ShowProgressType type, ConcurrentMessageLog messagesLog, ConcurrentMessageLog.PrepareConsoleMethod prepareConsole, int WaitInterval, ref DateTime lastProgressUpdate, List<ProgressTracker> progressTrackers, Http.IThroughputMeter throughputMeter, ref int maxStatusLines, ref bool progressVisible, ref int fatal, ref long bytesRemaining)
        {
            messagesLog.Flush(prepareConsole);

            if (Interactive())
            {
                while (Console.KeyAvailable)
                {
                    ConsoleKeyInfo key = Console.ReadKey(true/*intercept*/);
                    if (key.KeyChar == 't')
                    {
                        Console.Write("Network throttle (bytes per second): ");
                        string s = Console.ReadLine();
                        try
                        {
                            Http.HttpGlobalControl.SetThrottleFromString(s);
                        }
                        catch (ArgumentException)
                        {
                            // ignore invalid inputs
                        }
                    }
                    else if (key.KeyChar == 'q')
                    {
                        Interlocked.Exchange(ref fatal, 1);
                    }
                }

                if (lastProgressUpdate.AddMilliseconds(WaitInterval - 100) <= DateTime.Now)
                {
                    lock (progressTrackers)
                    {
                        List<KeyValuePair<string, ConsoleColor?>> lines = new List<KeyValuePair<string, ConsoleColor?>>();

                        if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                        {
                            lines.Add(new KeyValuePair<string, ConsoleColor?>("  [fatal error pending]", ConsoleColor.Yellow));
                        }

                        ProgressTracker[] progressTrackers2 = progressTrackers.ToArray();
                        Array.Sort(progressTrackers2, delegate(ProgressTracker l, ProgressTracker r) { return l.Tag.CompareTo(r.Tag); });
                        for (int i = 0; i < progressTrackers.Count; i++)
                        {
                            ProgressTracker progressTracker = progressTrackers2[i];
                            string progress;

                            switch (type)
                            {
                                default:
                                    throw new NotSupportedException();

                                case ShowProgressType.Upload:
                                    if (progressTracker.Total >= 0)
                                    {
                                        progress = String.Format("{0}% of {1}", progressTracker.Current * 100 / progressTracker.Total, FileSizeString(progressTracker.Total));
                                    }
                                    else
                                    {
                                        progress = "creating";
                                    }
                                    break;

                                case ShowProgressType.Download:
                                    if ((progressTracker.Current == 0) || (progressTracker.Total >= 0))
                                    {
                                        progress = String.Format("{0}%{1}", progressTracker.Current * 100 / Math.Max(progressTracker.Total, 1), progressTracker.Total > 0 ? String.Format(" of {0}", FileSizeString(Math.Max(progressTracker.Total, 0))) : String.Empty);
                                    }
                                    else
                                    {
                                        progress = "processing";
                                    }
                                    break;
                            }

                            lines.Add(new KeyValuePair<string, ConsoleColor?>(String.Format("  [{0}: {1}]", progressTracker.Tag, progress), null));
                        }

                        if (type == ShowProgressType.Upload)
                        {
                            string first = null;
                            string second = null;

                            long m = Interlocked.Read(ref bytesRemaining);
                            if (m != 0)
                            {
                                first = String.Format("  {0} queued", FileSizeString(m));
                            }

                            if (throughputMeter != null)
                            {
                                long throughput = throughputMeter.AverageBytesPerSecond;
                                if (throughput > 0)
                                {
                                    second = String.Format("  {0}/sec", FileSizeString(throughput));
                                }
                            }

                            if ((first != null) || (second != null))
                            {
                                lines.Add(new KeyValuePair<string, ConsoleColor?>(String.Concat(first, second), null));
                            }
                        }

                        while (lines.Count < maxStatusLines)
                        {
                            lines.Add(new KeyValuePair<string, ConsoleColor?>(String.Empty, null));
                        }
                        maxStatusLines = lines.Count;

                        foreach (KeyValuePair<string, ConsoleColor?> line in lines)
                        {
                            ConsoleColor? oldConsoleColor = null;
                            if (line.Value.HasValue && Interactive())
                            {
                                oldConsoleColor = Console.ForegroundColor;
                                Console.ForegroundColor = line.Value.Value;
                            }
                            Console.WriteLine(line.Key + new String(' ', Math.Max(0, Console.BufferWidth - 1 - line.Key.Length)));
                            if (oldConsoleColor.HasValue)
                            {
                                Console.ForegroundColor = oldConsoleColor.Value;
                            }
                        }
                        Console.CursorTop -= lines.Count;
                        progressVisible = true;
                    }

                    lastProgressUpdate = DateTime.Now;
                }
            }
        }

        private static void EraseProgress(ref DateTime lastProgressUpdate, List<ProgressTracker> progressTrackers, ref int maxStatusLines, ref bool progressVisible)
        {
            if (Interactive())
            {
                lock (progressTrackers)
                {
                    if (progressVisible)
                    {
                        for (int i = 0; i < maxStatusLines; i++)
                        {
                            Console.WriteLine(new String(' ', Math.Max(0, Console.BufferWidth - 1)));
                        }
                        Console.CursorTop -= maxStatusLines;

                        progressVisible = false;
                        lastProgressUpdate = default(DateTime);
                    }
                }
            }
        }

        private static void CheckLocalSignature(string localSignaturePath, CheckedReadStream localSignature)
        {
            if (localSignaturePath != null)
            {
                if (!File.Exists(localSignaturePath))
                {
                    ConsoleWriteLineColor(ConsoleColor.Yellow, "Local signature \"{0}\" does not exist - proceeding anyway!", localSignaturePath);
                    Thread.Sleep(5000);
                }
                else
                {
                    byte[] savedLocalSignatureBytes = File.ReadAllBytes(localSignaturePath);
                    if (!ArrayEqual(localSignature.CheckValue, savedLocalSignatureBytes))
                    {
                        string message = String.Format("Local signature \"{0}\" does not match computed signature from manifest! Aborting!", localSignaturePath);
                        ConsoleWriteLineColor(ConsoleColor.Yellow, message);
                        throw new ApplicationException(message);
                    }
                }
            }
        }

        private static int GetConcurrency(IArchiveFileManager fileManager, Context context)
        {
            int threadCount;
            if (context.explicitConcurrency.HasValue)
            {
                threadCount = context.explicitConcurrency.Value;
            }
            else
            {
                threadCount = Constants.ConcurrencyForDiskBound;
                if (!(fileManager is LocalArchiveFileManager))
                {
                    threadCount = Math.Max(threadCount, Constants.ConcurrencyForNetworkBound);
                }
                if ((context.cryptoOption != EncryptionOption.None)
                    || (context.compressionOption != CompressionOption.None))
                {
                    threadCount = Math.Max(threadCount, Constants.ConcurrencyForComputeBound);
                }
            }
            return threadCount;
        }

        private static IArchiveFileManager GetArchiveFileManager(string archivePathTemplate, out string archiveFileNameTemplate, out bool remote, Context context)
        {
            archiveFileNameTemplate = null;

            Uri uri;
            if (Uri.TryCreate(archivePathTemplate, UriKind.Absolute, out uri))
            {
                if (uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
                    || uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        int lastSlash = uri.PathAndQuery.LastIndexOf('/');
                        archiveFileNameTemplate = uri.PathAndQuery.Substring(lastSlash + 1);
                        remote = true;
                        return new RemoteArchiveFileManager(uri.Scheme + "://" + uri.Host, uri.PathAndQuery.Substring(0, lastSlash), context.refreshTokenProtected, context);
                    }
                    catch (NotSupportedException)
                    {
                        throw new UsageException(String.Format("Specified remote storage service is not supported: \"{0}\"", uri.Scheme + "://" + uri.Host));
                    }
                }
                // else fall through to local filesystem manager
            }
            // else fall through to local filesystem manager

            archiveFileNameTemplate = Path.GetFileName(archivePathTemplate);
            remote = false;
            return new LocalArchiveFileManager(context, Path.GetDirectoryName(Path.IsPathRooted(archivePathTemplate) ? archivePathTemplate : Path.Combine(Environment.CurrentDirectory, archivePathTemplate)));
        }

        private class LocalArchiveFileManager : IArchiveFileManager
        {
            // all members should be threadsafe, read-only, or protected with lock() in class code
            private Context context;
            private string root;
            private Dictionary<string, DateTime> stickyCreationTimestamps = new Dictionary<string, DateTime>();
            private Dictionary<string, LocalFileCopy> uncommittedLocalTempFiles = new Dictionary<string, LocalFileCopy>(1);

            private LocalArchiveFileManager()
            {
                throw new NotSupportedException();
            }

            public LocalArchiveFileManager(Context context, string root)
            {
                this.context = context;
                this.root = root;
            }

            public void Dispose()
            {
                root = null;

                stickyCreationTimestamps = null;

                if (uncommittedLocalTempFiles != null)
                {
                    foreach (KeyValuePair<string, LocalFileCopy> item in uncommittedLocalTempFiles)
                    {
                        item.Value.Release();
                    }
                    uncommittedLocalTempFiles.Clear();
                    uncommittedLocalTempFiles = null;
                }
            }

            private void CheckSimpleName(string name)
            {
                if (!String.Equals(Path.GetFileName(name), name))
                {
                    throw new ArgumentException();
                }
            }

            private void RememberTimestamps(string name)
            {
                lock (stickyCreationTimestamps)
                {
                    if (!stickyCreationTimestamps.ContainsKey(name))
                    {
                        string path = Path.Combine(root, name);
                        DateTime creationTime = File.GetCreationTime(path);
                        stickyCreationTimestamps.Add(name, creationTime);
                    }
                }
            }

            private void EnsureTimestamps(string name)
            {
                string path = Path.Combine(root, name);

                File.SetLastWriteTime(path, context.now);
                DateTime created;
                lock (stickyCreationTimestamps)
                {
                    if (!stickyCreationTimestamps.TryGetValue(name, out created))
                    {
                        created = context.now;
                    }
                }
                File.SetCreationTime(path, created);
            }

            public ILocalFileCopy Read(string name, ProgressTracker progressTracker, TextWriter trace)
            {
                CheckSimpleName(name);
                return new LocalFileCopy(Path.Combine(root, name), false/*writable*/, false/*delete*/);
            }

            public ILocalFileCopy WriteTemp(string nameTemp, TextWriter trace)
            {
                CheckSimpleName(nameTemp);
                string pathTemp = Path.Combine(root, nameTemp);

                if (File.Exists(pathTemp))
                {
                    File.Delete(pathTemp);
                }

                using (LocalFileCopy localCopy = new LocalFileCopy(pathTemp, true/*writable*/, false/*delete*/))
                {
                    // refcount == 1, owned by using()

                    lock (uncommittedLocalTempFiles)
                    {
                        // Could throw if nameTemp is already used
                        uncommittedLocalTempFiles.Add(nameTemp, localCopy);
                        localCopy.AddRef(); // refcount++ for uncommittedLocalTempFiles's reference
                    }

                    return localCopy.AddRef(); // refcount++ for callee's using() reference
                }
            }

            public ILocalFileCopy GetTempExisting(string localPath, string nameTemp, TextWriter trace)
            {
                CheckSimpleName(nameTemp);
                string pathTemp = Path.Combine(root, nameTemp);

                using (Stream tempStream = new FileStream(pathTemp, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    using (Stream localStream = new FileStream(localPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        tempStream.SetLength(localStream.Length);

                        byte[] buffer = new byte[Constants.BufferSize];
                        int read;
                        while ((read = localStream.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            tempStream.Write(buffer, 0, read);
                        }
                    }
                }

                using (LocalFileCopy localCopy = new LocalFileCopy(pathTemp, false/*writable*/, false/*delete*/))
                {
                    // refcount == 1, owned by using()

                    lock (uncommittedLocalTempFiles)
                    {
                        // Could throw if nameTemp is already used
                        uncommittedLocalTempFiles.Add(nameTemp, localCopy);
                        localCopy.AddRef(); // refcount++ for uncommittedLocalTempFiles's reference
                    }

                    return localCopy.AddRef(); // refcount++ for callee's using() reference
                }
            }

            public void Commit(ILocalFileCopy localFile, string nameTemp, string name, bool overwrite, ProgressTracker progressTracker, TextWriter trace)
            {
                if (!overwrite && Exists(name, trace))
                {
                    throw new InvalidOperationException();
                }

                CheckSimpleName(nameTemp);
                CheckSimpleName(name);
                string pathTemp = Path.Combine(root, nameTemp);
                string path = Path.Combine(root, name);

                if (!File.Exists(pathTemp))
                {
                    throw new InvalidOperationException();
                }

                if (pathTemp != ((LocalFileCopy)localFile).LocalFilePath)
                {
                    throw new InvalidOperationException();
                }

                LocalFileCopy uncommitted;
                lock (uncommittedLocalTempFiles)
                {
                    if (!uncommittedLocalTempFiles.TryGetValue(nameTemp, out uncommitted)
                        || (uncommitted != localFile))
                    {
                        throw new InvalidOperationException();
                    }

                    uncommittedLocalTempFiles.Remove(nameTemp); // transfer ownership to using()
                }
                using (uncommitted) // refcount-- at end of scope
                {

                    if (!name.Equals(nameTemp))
                    {
                        if (Exists(name, trace))
                        {
                            Delete(name, trace); // use our version - records creation timestamp
                        }

                        uncommitted.Vacate(); // give up ownership - file will survive program termination
                        File.Move(pathTemp, path); // move file to final permanent location
                    }

                    EnsureTimestamps(name);
                }
            }

            public void Abandon(ILocalFileCopy localFile, string nameTemp, TextWriter trace)
            {
                CheckSimpleName(nameTemp);
                string pathTemp = Path.Combine(root, nameTemp);

                if (pathTemp != ((LocalFileCopy)localFile).LocalFilePath)
                {
                    throw new InvalidOperationException();
                }

                LocalFileCopy uncommitted;
                lock (uncommittedLocalTempFiles)
                {
                    if (!uncommittedLocalTempFiles.TryGetValue(nameTemp, out uncommitted)
                        || (uncommitted != localFile))
                    {
                        throw new InvalidOperationException();
                    }
                    uncommittedLocalTempFiles.Remove(nameTemp);
                }
                uncommitted.Release();

                File.Delete(pathTemp);
            }

            public void Delete(string name, TextWriter trace)
            {
                CheckSimpleName(name);
                string path = Path.Combine(root, name);

                if (!File.Exists(path))
                {
                    throw new FileNotFoundException(name);
                }

                lock (stickyCreationTimestamps)
                {
                    if (!stickyCreationTimestamps.ContainsKey(name))
                    {
                        DateTime creationTime = File.GetCreationTime(path);
                        stickyCreationTimestamps.Add(name, creationTime);
                    }
                }

                File.Delete(path);
            }

            public void DeleteById(string id, TextWriter trace)
            {
                throw new NotSupportedException();
            }

            public bool Exists(string name, TextWriter trace)
            {
                CheckSimpleName(name);
                string path = Path.Combine(root, name);
                return File.Exists(path) || Directory.Exists(path);
            }

            public void Rename(string oldName, string newName, TextWriter trace)
            {
                CheckSimpleName(oldName);
                CheckSimpleName(newName);
                RememberTimestamps(oldName);
                File.Move(Path.Combine(root, oldName), Path.Combine(root, newName));
                EnsureTimestamps(newName);
            }

            public void RenameById(string id, string newName, TextWriter trace)
            {
                throw new NotSupportedException();
            }

            public void Copy(string sourceName, string copyName, bool overwrite, TextWriter trace)
            {
                CheckSimpleName(sourceName);
                CheckSimpleName(copyName);
                string sourcePath = Path.Combine(root, sourceName);
                string copyPath = Path.Combine(root, copyName);
                if (!File.Exists(sourcePath))
                {
                    throw new InvalidOperationException();
                }
                if (!overwrite && File.Exists(copyPath))
                {
                    throw new InvalidOperationException();
                }
                RememberTimestamps(sourceName);
                File.Copy(sourcePath, copyPath, overwrite/*overwrite*/);
                EnsureTimestamps(copyName);
            }

            public string[] GetFileNames(string prefix, TextWriter trace)
            {
                if (prefix == null)
                {
                    prefix = String.Empty;
                }
                if (FileNamePatternMatch.ContainsWildcards(prefix))
                {
                    throw new ArgumentException();
                }

                string[] files = Directory.GetFileSystemEntries(root, prefix + "*");
                for (int i = 0; i < files.Length; i++)
                {
                    files[i] = Path.GetFileName(files[i]);
                }
                return files;
            }

            public void GetFileInfo(string name, out string id, out bool directory, out DateTime created, out DateTime modified, out long size, TextWriter trace)
            {
                CheckSimpleName(name);
                string path = Path.Combine(root, name);

                if (!File.Exists(path) && !Directory.Exists(path))
                {
                    throw new FileNotFoundException(name);
                }

                id = null;
                directory = Directory.Exists(path);
                created = File.GetCreationTime(path);
                modified = File.GetLastWriteTime(path);
                size = File.Exists(path) ? GetFileLength(path) : -1;
            }

            public void GetFileInfo(string name, out bool directory, TextWriter trace)
            {
                string id;
                DateTime created, modified;
                long size;
                GetFileInfo(name, out id, out directory, out created, out modified, out size, trace);
            }

            public void GetQuota(out long quotaTotal, out long quotaUsed, TextWriter trace)
            {
                quotaTotal = Int64.MaxValue;
                quotaUsed = 0;
            }

            public TextWriter GetMasterTrace() // TextWriter is threadsafe; remains owned - do not Dispose()
            {
                return null;
            }
        }

        private struct DynUnpackJournalEntry
        {
            public readonly string segmentName;
            public readonly ulong segmentSerialNumber;

            public DynUnpackJournalEntry(string segmentName, ulong segmentSerialNumber)
            {
                this.segmentName = segmentName;
                this.segmentSerialNumber = segmentSerialNumber;
            }

            public DynUnpackJournalEntry(string line)
            {
                string[] parts = line.Split(new char[] { '(', ',', ')' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length != 2)
                {
                    throw new InvalidDataException();
                }
                this.segmentName = parts[0];
                this.segmentSerialNumber = UInt64.Parse(parts[1]);
            }

            public void WriteLine(TextWriter writer)
            {
                writer.WriteLine("({0}, {1})", segmentName, segmentSerialNumber);
            }
        }

        internal static void ValidateOrUnpackDynamicInternal(string archivePathTemplate, string targetDirectory, Context context, UnpackMode mode, string journalPath, string localSignaturePath)
        {
            IFaultInstance faultValidateOrUnpackDynamicInternal = context.faultInjectionRoot.Select("ValidateOrUnpackDynamicInternal");

            int fatal = 0;
            OneWaySwitch invalid = new OneWaySwitch();
            ConcurrentTasks.CompletionObject[] completionTable = null;

            const string ExpectedManifestExtension = "." + DynPackManifestName + DynPackFileExtension;
            string manifestPath = archivePathTemplate + ExpectedManifestExtension;

            Dictionary<string, DynUnpackJournalEntry> journal = new Dictionary<string, DynUnpackJournalEntry>();
            ulong journalManifestSerialNumber = 0;
            byte[] journalRandomArchiveSignatureDigest = null;
            if ((mode & UnpackMode.Resume) == UnpackMode.Resume)
            {
                if (File.Exists(journalPath))
                {
                    using (TextReader reader = new StreamReader(journalPath, Encoding.UTF8))
                    {
                        string line;

                        line = reader.ReadLine();
                        if (line != null)
                        {
                            journalRandomArchiveSignatureDigest = HexUtility.HexDecode(line);
                        }

                        line = reader.ReadLine();
                        if (line != null)
                        {
                            journalManifestSerialNumber = UInt64.Parse(line);
                        }

                        while ((line = reader.ReadLine()) != null)
                        {
                            try
                            {
                                DynUnpackJournalEntry journalEntry = new DynUnpackJournalEntry(line);
                                journal.Add(journalEntry.segmentName, journalEntry);
                            }
                            catch (Exception)
                            {
                                // ignore improperly formatted entries - file may have been truncated
                                Console.WriteLine("Journal: ignoring improperly formatted entry");
                            }
                        }
                    }
                }
            }
            else
            {
                if (File.Exists(journalPath))
                {
                    throw new UsageException("Journal already exists, but -resume not specified");
                }
            }

            TextWriter traceDynunpack = context.traceEnabled ? LogWriter.CreateLogFile(DynUnpackTraceFilePrefix) : null;

            string archiveFileNameTemplate;
            string manifestFileName = Path.GetFileName(manifestPath);
            bool remote;
            using (IArchiveFileManager fileManager = GetArchiveFileManager(archivePathTemplate, out archiveFileNameTemplate, out remote, context))
            {
                string targetFileNamePrefix = archiveFileNameTemplate + ".";


                Dictionary<ulong, bool> usedMapping = new Dictionary<ulong, bool>(); // use lock() on this!


                if (!fileManager.Exists(manifestFileName, fileManager.GetMasterTrace()))
                {
                    Console.WriteLine("Manifest file \"{0}\" could not be found", manifestFileName);
                    throw new UsageException();
                }


                // read manifest
                ulong manifestSerialNumber;
                byte[] randomArchiveSignature;
                UnpackedFileRecord[] manifestFileList;
                Console.WriteLine("Reading {0}", manifestFileName);
                using (ILocalFileCopy fileRef = fileManager.Read(manifestFileName, null/*progressTracker*/, fileManager.GetMasterTrace()))
                {
                    using (Stream manifestStream = fileRef.Read())
                    {
                        ApplicationException[] deferredExceptions;
                        manifestFileList = UnpackInternal(manifestStream, targetDirectory, context, UnpackMode.Parse, out manifestSerialNumber, out randomArchiveSignature, traceDynunpack, faultValidateOrUnpackDynamicInternal.Select("Segment", manifestFileName), out deferredExceptions, localSignaturePath);
                        Debug.Assert(deferredExceptions == null); // load manifest should never generate deferred exceptions
                    }
                }

                byte[] randomArchiveSignatureDigest;
                {
                    SHA256 sha256 = SHA256.Create();
                    randomArchiveSignatureDigest = sha256.ComputeHash(randomArchiveSignature);
                }

                if (journalRandomArchiveSignatureDigest != null)
                {
                    if (!ArrayEqual(journalRandomArchiveSignatureDigest, randomArchiveSignatureDigest))
                    {
                        throw new UsageException("Journal appears to be for a different archive.");
                    }

                    if (journalManifestSerialNumber != manifestSerialNumber)
                    {
                        ConsoleWriteLineColor(ConsoleColor.Yellow, "Journal was generated with older version of manifest. Updated segments will be re-unpacked. Files that were extracted from previous version and do not exist in new version may be left behind on disk. Continue? [y/n]");
                        while (true)
                        {
                            char key = WaitReadKey(false/*intercept*/);
                            Console.WriteLine();
                            if (key == 'y')
                            {
                                break;
                            }
                            else if (key == 'n')
                            {
                                throw new ApplicationException("The user cancelled the operation");
                            }
                        }
                    }
                }

                journalRandomArchiveSignatureDigest = null;
                journalManifestSerialNumber = 0;


                // process manifest contents
                Dictionary<string, ulong> serialNumberMapping = new Dictionary<string, ulong>();
                List<string> segmentNameList = new List<string>();
                foreach (UnpackedFileRecord file in manifestFileList)
                {
                    string segmentName = file.SegmentName;
                    ulong segmentSerialNumber = file.SegmentSerialNumber;
                    if ((segmentSerialNumber == 0) || (segmentSerialNumber >= manifestSerialNumber))
                    {
                        ConsoleWriteLineColor(ConsoleColor.Yellow, "Manifest segment {0}: serial number {1} is invalid", segmentName, segmentSerialNumber);
                        invalid.Set();
                        if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                        {
                            goto Abort; // if unpacking, abort, otherwise continue to see what else is wrong
                        }
                    }
                    ulong expectedSerialNumber;
                    if (serialNumberMapping.TryGetValue(segmentName.ToLowerInvariant(), out expectedSerialNumber))
                    {
                        if (expectedSerialNumber != segmentSerialNumber)
                        {
                            ConsoleWriteLineColor(ConsoleColor.Yellow, "Manifest segment {0}: wrong serial number (is {1}, should be {2})", segmentName, segmentSerialNumber, expectedSerialNumber);
                            invalid.Set();
                            if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                            {
                                goto Abort; // if unpacking, abort, otherwise continue to see what else is wrong
                            }
                        }
                    }
                    else
                    {
                        serialNumberMapping.Add(segmentName, segmentSerialNumber);
                        usedMapping.Add(segmentSerialNumber, false);
                        segmentNameList.Add(segmentName);

                        DynUnpackJournalEntry journalEntry;
                        if (journal.TryGetValue(segmentName, out journalEntry))
                        {
                            if (journalEntry.segmentSerialNumber != segmentSerialNumber)
                            {
                                Console.WriteLine("Journal: segment {0} changed since last run", segmentName);
                                journal.Remove(segmentName);
                            }
                        }
                    }
                }

                Dictionary<string, string> dependencyGraph = new Dictionary<string, string>();
                Dictionary<string, int> completionIndexTable = new Dictionary<string, int>();
                {
                    int completionCounter = 0;
                    if (traceDynunpack != null)
                    {
                        traceDynunpack.WriteLine("Dependency graph (for ranged segment serialization):");
                    }
                    for (int i = 1; i < manifestFileList.Length; i++)
                    {
                        if ((manifestFileList[i].Range != null)
                            && String.Equals(manifestFileList[i].FullPath, manifestFileList[i - 1].FullPath)
                            && (manifestFileList[i].SegmentSerialNumber != manifestFileList[i - 1].SegmentSerialNumber))
                        {
                            dependencyGraph.Add(manifestFileList[i].SegmentName, manifestFileList[i - 1].SegmentName);
                            completionIndexTable.Add(manifestFileList[i - 1].SegmentName, completionCounter);
                            if (traceDynunpack != null)
                            {
                                traceDynunpack.WriteLine("{0} --> {1} (completion-index={2})", manifestFileList[i].SegmentName, manifestFileList[i - 1].SegmentName, completionCounter);
                            }
                            completionCounter++;
                        }
                    }
                    if (traceDynunpack != null)
                    {
                        traceDynunpack.WriteLine();
                    }
                    completionTable = new ConcurrentTasks.CompletionObject[completionCounter];
                }

                manifestFileList = null;

                if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                {
                    Directory.CreateDirectory(targetDirectory);
                }


                // enumerate invalid files
                foreach (string segmentFileName in fileManager.GetFileNames(targetFileNamePrefix, fileManager.GetMasterTrace()))
                {
                    string name = segmentFileName.Substring(targetFileNamePrefix.Length, segmentFileName.Length - targetFileNamePrefix.Length - DynPackFileExtension.Length);

                    bool manifest = String.Equals(segmentFileName, manifestFileName, StringComparison.OrdinalIgnoreCase);
                    bool eligible = !manifest
                        && segmentFileName.EndsWith(DynPackFileExtension, StringComparison.OrdinalIgnoreCase);

                    if (!eligible && !manifest)
                    {
                        if (traceDynunpack != null)
                        {
                            traceDynunpack.WriteLine("skipping {0} - invalid extension", segmentFileName);
                        }
                    }

                    bool member = serialNumberMapping.ContainsKey(name);
                    if (eligible && !member && !manifest)
                    {
                        if (traceDynunpack != null)
                        {
                            traceDynunpack.WriteLine("Validation error: {0} not a member of this archive", segmentFileName);
                        }
                        ConsoleWriteLineColor(ConsoleColor.Yellow, "Error: {0} is not a member of this archive", segmentFileName);

                        // it is considered a validation error (because someone could "unpack *") but continue
                        // to look for other errors or proceed with unpack (this method won't unpack extraneous
                        // files such as this one).
                        invalid.Set();
                    }
                }


                using (TextWriter journalWriter = journalPath != null ? TextWriter.Synchronized(new StreamWriter(journalPath, false/*append*/, Encoding.UTF8)) : null)
                {
                    if (journalWriter != null)
                    {
                        journalWriter.WriteLine(HexUtility.HexEncode(randomArchiveSignatureDigest));
                        journalWriter.WriteLine(manifestSerialNumber);
                        foreach (KeyValuePair<string, DynUnpackJournalEntry> journalEntry in journal)
                        {
                            journalEntry.Value.WriteLine(journalWriter);
                        }
                        journalWriter.Flush(); // ensure data is pushed out of process in case of failure in manifest loading code (next)
                    }


                    // set up concurrency status reporting
                    using (ConcurrentMessageLog messagesLog = new ConcurrentMessageLog(Interactive(), true/*enableSequencing*/))
                    {
                        int threadCount = GetConcurrency(fileManager, context);
                        using (ConcurrentTasks concurrent = new ConcurrentTasks(threadCount, 0, messagesLog, fileManager.GetMasterTrace()))
                        {
                            const int WaitInterval = 2000; // milliseconds
                            List<ProgressTracker> progressTrackers = new List<ProgressTracker>(); // Use lock() on this!
                            int maxStatusLines = 0;
                            bool progressVisible = false;
                            DateTime lastProgressUpdate = default(DateTime);
                            long bytesRemaining = Int64.MinValue; // not used
                            ConcurrentTasks.WaitIntervalMethod eraseProgress = delegate()
                            {
                                EraseProgress(ref lastProgressUpdate, progressTrackers, ref maxStatusLines, ref progressVisible);
                            };
                            ConcurrentMessageLog.PrepareConsoleMethod prepareConsole = delegate()
                            {
                                eraseProgress();
                            };
                            ConcurrentTasks.WaitIntervalMethod showProgress = delegate()
                            {
                                ShowProgress(ShowProgressType.Download, messagesLog, prepareConsole, WaitInterval, ref lastProgressUpdate, progressTrackers, Http.HttpGlobalControl.NetworkMeterCombined, ref maxStatusLines, ref progressVisible, ref fatal, ref bytesRemaining);
                            };


                            // process segments (concurrently)
                            long sharedSequenceNumber = messagesLog.GetSequenceNumber();
                            using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sharedSequenceNumber))
                            {
                                // ensure this shared sequence number is used at least once.
                            }
                            foreach (String segmentNameEnum in segmentNameList)
                            {
                                concurrent.WaitQueueNotFull(showProgress, WaitInterval);
                                if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                {
                                    break;
                                }


                                // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                // variable) in order to capture each value in the anonymous method.
                                // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                string name = segmentNameEnum;

                                string segmentFileName = String.Concat(targetFileNamePrefix, name, DynPackFileExtension);

                                bool exists = fileManager.Exists(segmentFileName, fileManager.GetMasterTrace());
                                bool processedPreviousRun;
                                lock (journal)
                                {
                                    processedPreviousRun = journal.ContainsKey(name);
                                }
                                if (processedPreviousRun || !exists)
                                {
                                    if (processedPreviousRun)
                                    {
                                        if (traceDynunpack != null)
                                        {
                                            traceDynunpack.WriteLine("Journal: skipping {0} - processed during previous run", segmentFileName);
                                        }
                                        using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                        {
                                            messages.WriteLine("Journal: skipping {0} - processed during previous run", segmentFileName);
                                        }
                                    }
                                    if (!exists)
                                    {
                                        if (traceDynunpack != null)
                                        {
                                            traceDynunpack.WriteLine("Skipping {0}: file does not exist", segmentFileName);
                                        }
                                        using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                        {
                                            messages.WriteLine(ConsoleColor.Yellow, "Skipping {0}: file does not exist", segmentFileName);
                                        }
                                    }

                                    int completionIndex;
                                    if (completionIndexTable.TryGetValue(name, out completionIndex))
                                    {
                                        Debug.Assert(completionTable[completionIndex] == null);
                                        completionTable[completionIndex] = new ConcurrentTasks.NullCompletionObject();
                                        completionTable[completionIndex].SetSucceeded();
                                        if (traceDynunpack != null)
                                        {
                                            traceDynunpack.WriteLine("  dependency exists: creating NullCompletionObject for task {0} index {1}; setting succeeded", name, completionIndex);
                                        }
                                    }

                                    continue;
                                }

                                if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                {
                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                    {
                                        messages.WriteLine("Unpacking {0}", segmentFileName);
                                    }
                                }

                                long sequenceNumber = sharedSequenceNumber;

                                // if task has dependency, ask for completion object
                                bool needCompletionObject = false;
                                int completionIndex2 = 0;
                                ConcurrentTasks.CompletionObject[] completionObjectReceiver = new ConcurrentTasks.CompletionObject[1];
                                if (needCompletionObject = completionIndexTable.TryGetValue(name, out completionIndex2))
                                {
                                    completionObjectReceiver = completionTable;
                                    Debug.Assert(completionTable[completionIndex2] == null);
                                    if (traceDynunpack != null)
                                    {
                                        traceDynunpack.WriteLine("  [dependency exists: preparing to receive CompletionObject for task {0} index {1}", name, completionIndex2);
                                    }
                                }

                                concurrent.Do(
                                    String.Format("unpack:{0}", segmentFileName),
                                    needCompletionObject,
                                    out completionObjectReceiver[completionIndex2],
                                    delegate(ConcurrentTasks.ITaskContext taskContext)
                                    {
                                        using (TextWriter threadTraceDynunpack = TaskLogWriter.Create(traceDynunpack))
                                        {
                                            if (threadTraceDynunpack != null)
                                            {
                                                threadTraceDynunpack.WriteLine("unpack:{0}", segmentFileName);
                                            }

                                            using (TextWriter threadTraceFileManager = TaskLogWriter.Create(fileManager.GetMasterTrace()))
                                            {
                                                if (threadTraceFileManager != null)
                                                {
                                                    threadTraceFileManager.WriteLine("unpack:{0}", segmentFileName);
                                                }

                                                ProgressTracker progressTracker = null;

                                                try
                                                {
                                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                                    {
                                                        progressTracker = new ProgressTracker(segmentFileName);
                                                        lock (progressTrackers)
                                                        {
                                                            progressTrackers.Add(progressTracker);
                                                        }

                                                        ulong segmentSerialNumber = 0;
                                                        try
                                                        {
                                                            using (ILocalFileCopy fileRef = fileManager.Read(segmentFileName, progressTracker, threadTraceFileManager))
                                                            {
                                                                using (Stream segmentStream = fileRef.Read())
                                                                {
                                                                    progressTracker.Reset();


                                                                    // wait on dependency - before unpacking data

                                                                    string dependentOnName;
                                                                    if (dependencyGraph.TryGetValue(name, out dependentOnName))
                                                                    {
                                                                        if (threadTraceDynunpack != null)
                                                                        {
                                                                            threadTraceDynunpack.WriteLine("dependency: waiting for completion of {0}", dependentOnName);
                                                                        }

                                                                        int completionIndex;
                                                                        if (!completionIndexTable.TryGetValue(dependentOnName, out completionIndex))
                                                                        {
                                                                            if (threadTraceDynunpack != null)
                                                                            {
                                                                                threadTraceDynunpack.WriteLine("  completion object missing for required dependency {0}", dependentOnName);
                                                                            }
                                                                            Interlocked.Exchange(ref fatal, 1);
                                                                            throw new InvalidOperationException();
                                                                        }

                                                                        ConcurrentTasks.CompletionObject completionObject = completionTable[completionIndex];
                                                                        if (completionObject == null)
                                                                        {
                                                                            if (threadTraceDynunpack != null)
                                                                            {
                                                                                threadTraceDynunpack.WriteLine("  completion object null for index={0}", completionIndex);
                                                                            }
                                                                            Interlocked.Exchange(ref fatal, 1);
                                                                            throw new InvalidOperationException();
                                                                        }

                                                                        completionObject.Wait();

                                                                        if (threadTraceDynunpack != null)
                                                                        {
                                                                            threadTraceDynunpack.WriteLine("  wait completed, proceeding");
                                                                        }

                                                                        if (!completionObject.Succeeded)
                                                                        {
                                                                            if (threadTraceDynunpack != null)
                                                                            {
                                                                                threadTraceDynunpack.WriteLine("  dependency task failed, aborting");
                                                                            }
                                                                            Interlocked.Exchange(ref fatal, 1);
                                                                            throw new InvalidOperationException();
                                                                        }
                                                                    }


                                                                    // membership and MAC validation

                                                                    byte[] segmentRandomArchiveSignature;

                                                                    ApplicationException[] deferredExceptions;
                                                                    UnpackedFileRecord[] segmentFileList;

                                                                    UnpackMode firstPassMode;
                                                                    if (((mode & UnpackMode.Unpack) != UnpackMode.Unpack) || !context.doNotPreValidateMAC)
                                                                    {
                                                                        firstPassMode = (mode & ~UnpackMode.Unpack) | UnpackMode.SignatureOnly;
                                                                    }
                                                                    else
                                                                    {
                                                                        firstPassMode = mode;
                                                                    }
                                                                    segmentFileList = UnpackInternal(segmentStream, targetDirectory, context, firstPassMode, out segmentSerialNumber, out segmentRandomArchiveSignature, threadTraceDynunpack, faultValidateOrUnpackDynamicInternal.Select("Segment", segmentFileName), out deferredExceptions, null/*localSignaturePath*/);
                                                                    if (deferredExceptions != null)
                                                                    {
                                                                        throw new DeferredMultiException(deferredExceptions);
                                                                    }

                                                                    if (!ArrayEqual(segmentRandomArchiveSignature, randomArchiveSignature))
                                                                    {
                                                                        messages.WriteLine(ConsoleColor.Yellow, "Segment {0}: random signature number is invalid - segment does not belong to this archive. Segment may have been inadvertently included, or segments have been deliberately tampered with. Examine unpacked contents carefully!", name);
                                                                        invalid.Set();
                                                                        if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                                                        {
                                                                            Interlocked.Exchange(ref fatal, 1);
                                                                            return; // if unpacking, abort, otherwise continue to see what else is wrong
                                                                        }
                                                                    }

                                                                    if ((segmentSerialNumber == 0) || (segmentSerialNumber >= manifestSerialNumber))
                                                                    {
                                                                        messages.WriteLine(ConsoleColor.Yellow, "Segment {0}: serial number {1} is invalid", name, segmentSerialNumber);
                                                                        invalid.Set();
                                                                        if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                                                        {
                                                                            Interlocked.Exchange(ref fatal, 1);
                                                                            return; // if unpacking, abort, otherwise continue to see what else is wrong
                                                                        }
                                                                    }

                                                                    ulong expectedSerialNumber;
                                                                    if (serialNumberMapping.TryGetValue(name.ToLowerInvariant(), out expectedSerialNumber))
                                                                    {
                                                                        if (expectedSerialNumber != segmentSerialNumber)
                                                                        {
                                                                            messages.WriteLine(ConsoleColor.Yellow, "Segment {0}: wrong serial number (is {1}, should be {2})", name, segmentSerialNumber, expectedSerialNumber);
                                                                            invalid.Set();
                                                                            if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                                                            {
                                                                                Interlocked.Exchange(ref fatal, 1);
                                                                                return; // if unpacking, abort, otherwise continue to see what else is wrong
                                                                            }
                                                                        }
                                                                        else
                                                                        {
                                                                            lock (usedMapping)
                                                                            {
                                                                                usedMapping[segmentSerialNumber] = true;
                                                                            }
                                                                        }
                                                                    }
                                                                    else
                                                                    {
                                                                        messages.WriteLine(ConsoleColor.Yellow, "Segment {0}: segment is extraneous (not referenced from manifest)", name);
                                                                        invalid.Set();
                                                                        if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                                                        {
                                                                            Interlocked.Exchange(ref fatal, 1);
                                                                            return; // if unpacking, abort, otherwise continue to see what else is wrong
                                                                        }
                                                                    }


                                                                    // content validation or unpacking pass, if not done earlier

                                                                    if (((mode & UnpackMode.Unpack) == UnpackMode.Unpack) && ((firstPassMode & UnpackMode.Unpack) != UnpackMode.Unpack))
                                                                    {
                                                                        segmentStream.Position = 0; // rewind
                                                                        segmentFileList = UnpackInternal(segmentStream, targetDirectory, context, mode, out segmentSerialNumber, out segmentRandomArchiveSignature, threadTraceDynunpack, faultValidateOrUnpackDynamicInternal.Select("Segment", segmentFileName), out deferredExceptions, null/*localSignaturePath*/);
                                                                        if (deferredExceptions != null)
                                                                        {
                                                                            throw new DeferredMultiException(deferredExceptions);
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        catch (DeferredMultiException exception)
                                                        {
                                                            messages.WriteLine(ConsoleColor.Yellow, "Segment {0}: {1}", name, exception);
                                                            invalid.Set();
                                                            // continue processing remaining files
                                                        }
                                                        catch (Exception exception)
                                                        {
                                                            if (!(exception is TaggedReadStream.TagInvalidException)
                                                               && !(exception is InvalidDataException))
                                                            {
                                                                messages.WriteLine("Exception processing {0}: {1}", segmentFileName, exception);
                                                                Interlocked.Exchange(ref fatal, 1);
                                                                throw;
                                                            }

                                                            messages.WriteLine(ConsoleColor.Yellow, "Segment {0}: {1}", name, exception.Message);
                                                            invalid.Set();
                                                            if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                                            {
                                                                Interlocked.Exchange(ref fatal, 1);
                                                                return; // if unpacking, abort, otherwise continue to see what else is wrong
                                                            }
                                                            // do nothing further with cryptographically inauthentic segments
                                                            return;
                                                        }

                                                        DynUnpackJournalEntry journalEntry = new DynUnpackJournalEntry(name, segmentSerialNumber);
                                                        lock (journal)
                                                        {
                                                            journal.Add(journalEntry.segmentName, journalEntry);
                                                        }
                                                        if (journalWriter != null)
                                                        {
                                                            journalEntry.WriteLine(journalWriter);
                                                            journalWriter.Flush();
                                                        }

                                                        taskContext.SetSucceeded();
                                                    }
                                                }
                                                finally
                                                {
                                                    if (progressTracker != null)
                                                    {
                                                        lock (progressTrackers)
                                                        {
                                                            progressTrackers.Remove(progressTracker);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    showProgress,
                                    WaitInterval);

                                messagesLog.Flush(prepareConsole);
                                showProgress();
                            }

                            // Finish parsing or unpacking segments
                            concurrent.Drain(showProgress, WaitInterval);
                            messagesLog.Flush(prepareConsole);
                            eraseProgress();
                            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                            {
                                if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                {
                                    if (traceDynunpack != null)
                                    {
                                        traceDynunpack.WriteLine("aborting");
                                    }
                                    goto Abort;
                                }
                            }


                            // final pass to list missing segments
                            foreach (KeyValuePair<string, ulong> declaredSegments in serialNumberMapping)
                            {
                                if (!usedMapping[declaredSegments.Value])
                                {
                                    ConsoleWriteLineColor(ConsoleColor.Yellow, "Segment {0}: missing segment (referenced in manifest, serial number {1})", declaredSegments.Key, declaredSegments.Value);
                                    invalid.Set();
                                    if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                    {
                                        goto Abort; // if unpacking, abort, otherwise continue to see what else is wrong
                                    }
                                }
                            }
                        }
                    }
                }
            }

        Abort:

            if (traceDynunpack != null)
            {
                traceDynunpack.Close();
            }

            if (completionTable != null)
            {
                foreach (ConcurrentTasks.CompletionObject completionObject in completionTable)
                {
                    if (completionObject != null)
                    {
                        completionObject.Dispose();
                    }
                }
            }

            if (invalid.Value)
            {
                throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied);
            }
            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
            {
                throw new ApplicationException();
            }
        }

        internal static void DynamicUnpack(string manifestPrefix, string targetDirectory, Context context, string[] args)
        {
            UnpackMode mode = UnpackMode.Unpack;

            // options
            bool resume = false;
            string journalPath = null;
            string localSignaturePath = null;

            while (args.Length > 0)
            {
                switch (args[0])
                {
                    default:
                        throw new UsageException();
                    case "-resume":
                        GetAdHocArgument(ref args, "-resume", false/*defaultValue*/, true/*explicitValue*/, out resume);
                        if (resume)
                        {
                            mode |= UnpackMode.Resume;
                        }
                        break;
                    case "-journal":
                        GetAdHocArgument(ref args, "-journal", null/*defaultValue*/, delegate(string s) { return s; }, out journalPath);
                        break;
                    case "-localsig":
                        GetAdHocArgument(ref args, "-localsig", null/*default*/, delegate(string s) { return s; }, out localSignaturePath);
                        break;
                }
            }

#if false // In remote case, causes download of all data twice. Per-segment prevalidation still occurs.
            if ((context.cryptoOption != EncryptionOption.None) && !context.doNotPreValidateMAC)
            {
                ValidateOrUnpackDynamicInternal(manifestPrefix, ".", context, UnpackMode.ParseOnly, args);
                // throws ExitCodeException()
            }
#endif

            ValidateOrUnpackDynamicInternal(manifestPrefix, targetDirectory, context, mode, journalPath, localSignaturePath);
            // throws ExitCodeException()
        }

        internal static void ValidateDynamicPack(string manifestPrefix, Context context, string[] args)
        {
            // options
            string localSignaturePath = null;

            while (args.Length > 0)
            {
                switch (args[0])
                {
                    default:
                        throw new UsageException();
                    case "-localsig":
                        GetAdHocArgument(ref args, "-localsig", null/*default*/, delegate(string s) { return s; }, out localSignaturePath);
                        break;
                }
            }

            ValidateOrUnpackDynamicInternal(manifestPrefix, ".", context, UnpackMode.Parse, null/*journalPath*/, localSignaturePath);
            // throws ExitCodeException()
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Remote web service access tools
        //
        ////////////////////////////////////////////////////////////////////////////

        public static void RemoteCommand(string[] args, Context context)
        {
            IArchiveFileManager fileManager;
            string path;

            if (args.Length < 1)
            {
                throw new UsageException();
            }

            string serviceUrl = args[0];
            Uri serviceUri;
            if (Uri.TryCreate(serviceUrl, UriKind.Absolute, out serviceUri)
                && (serviceUri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
                || serviceUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)))
            {
                if (!serviceUrl.EndsWith("/"))
                {
                    throw new UsageException();
                }

                try
                {
                    int lastSlash = serviceUri.PathAndQuery.LastIndexOf('/');
                    string name = serviceUri.PathAndQuery.Substring(lastSlash + 1);
                    Debug.Assert(String.IsNullOrEmpty(name));
                    path = serviceUri.PathAndQuery.Substring(0, lastSlash);
                    fileManager = new RemoteArchiveFileManager(serviceUri.Scheme + "://" + serviceUri.Host, path, context.refreshTokenProtected, context);
                }
                catch (NotSupportedException)
                {
                    throw new UsageException(String.Format("Specified remote storage service is not supported: \"{0}\"", serviceUri.Scheme + "://" + serviceUri.Host));
                }
            }
            else
            {
                if (!Directory.Exists(serviceUrl))
                {
                    throw new UsageException();
                }

                if (!serviceUrl.EndsWith(@"\"))
                {
                    serviceUrl = serviceUrl + @"\";
                }

                string name = Path.GetFileName(serviceUrl);
                Debug.Assert(String.IsNullOrEmpty(name));
                path = serviceUrl.Substring(0, serviceUrl.Length - name.Length);
                string fullPath = Path.GetDirectoryName(Path.IsPathRooted(serviceUrl) ? serviceUrl : Path.Combine(Environment.CurrentDirectory, serviceUrl));
                serviceUri = new Uri(fullPath);
                fileManager = new LocalArchiveFileManager(context, fullPath);
            }

            ArrayRemoveAt(ref args, 0, 1);

            using (fileManager)
            {
                using (ConcurrentMessageLog messagesLog = new ConcurrentMessageLog(Interactive(), false/*enableSequencing*/))
                {
                    using (ConcurrentTasks concurrent = new ConcurrentTasks(context.explicitConcurrency.HasValue ? context.explicitConcurrency.Value : Constants.ConcurrencyForNetworkBound, 0, messagesLog, fileManager.GetMasterTrace()))
                    {
                        int fatal = 0;

                        while ((args.Length > 0) && (Interlocked.CompareExchange(ref fatal, 1, 1) == 0))
                        {
                            int used;

                            switch (args[0])
                            {
                                default:
                                    throw new ArgumentException();

                                case "quota":
                                    {
                                        long quotaTotal, quotaUsed;
                                        fileManager.GetQuota(out quotaTotal, out quotaUsed, fileManager.GetMasterTrace());
                                        long quotaAvailable = quotaTotal - quotaUsed;
                                        Console.WriteLine("Quota: total={0}, used={1}, available={2}", FileSizeString(quotaTotal), FileSizeString(quotaUsed), FileSizeString(quotaAvailable));
                                    }
                                    used = 1;
                                    break;

                                case "list":
                                    {
                                        Console.WriteLine("list {0}{1}/*", String.Concat(serviceUri.Scheme, "://", serviceUri.Host), path);
                                        string[] names = fileManager.GetFileNames(null, fileManager.GetMasterTrace());
                                        Array.Sort(names, delegate(string l, string r) { return String.Compare(l, r, StringComparison.OrdinalIgnoreCase); });
                                        foreach (string file in names)
                                        {
                                            string id;
                                            bool directory;
                                            DateTime created, modified;
                                            long size;

                                            fileManager.GetFileInfo(file, out id, out directory, out created, out modified, out size, fileManager.GetMasterTrace());

                                            Console.WriteLine("{0:yyyy-MM-dd HH:mm}  {1:yyyy-MM-dd HH:mm} {2} {3,44} {4}", created, modified, directory ? String.Format("{0,-15}", "<DIR>") : String.Format("{0,15}", size), id, file);
                                        }
                                    }
                                    used = 1;
                                    break;

                                case "rename":
                                    if (args.Length < 3)
                                    {
                                        throw new ArgumentException();
                                    }
                                    {
                                        string name = args[1];
                                        string newName = args[2];
                                        Console.WriteLine("rename {0} to {1}", name, newName);
                                        fileManager.Rename(name, newName, fileManager.GetMasterTrace());
                                    }
                                    used = 3;
                                    break;

                                case "rename-id":
                                    if (args.Length < 3)
                                    {
                                        throw new ArgumentException();
                                    }
                                    {
                                        string id = args[1];
                                        string newName = args[2];
                                        Console.WriteLine("rename id {0} to {1}", id, newName);
                                        fileManager.RenameById(id, newName, fileManager.GetMasterTrace());
                                    }
                                    used = 3;
                                    break;

                                case "copy":
                                    if (args.Length < 3)
                                    {
                                        throw new ArgumentException();
                                    }
                                    {
                                        string name = args[1];
                                        string newName = args[2];
                                        Console.WriteLine("copy {0} to {1}", name, newName);
                                        fileManager.Copy(name, newName, true/*overwrite*/, fileManager.GetMasterTrace());
                                    }
                                    used = 3;
                                    break;

                                case "delete":
                                case "del":
                                    if (args.Length < 2)
                                    {
                                        throw new ArgumentException();
                                    }
                                    if (!FileNamePatternMatch.ContainsWildcards(args[1]))
                                    {
                                        string name = args[1];
                                        if (fileManager.Exists(name, fileManager.GetMasterTrace()))
                                        {
                                            Console.WriteLine("delete {0}", name);
                                            fileManager.Delete(name, fileManager.GetMasterTrace());
                                        }
                                    }
                                    else
                                    {
                                        string pattern = args[1];
                                        FileNamePatternMatch matcher = new FileNamePatternMatch(pattern);
                                        List<string> names = new List<string>();
                                        foreach (string name in fileManager.GetFileNames(null, fileManager.GetMasterTrace()))
                                        {
                                            if (matcher.IsMatch(name))
                                            {
                                                if (fileManager.Exists(name, fileManager.GetMasterTrace()))
                                                {
                                                    bool directory;
                                                    fileManager.GetFileInfo(name, out directory, fileManager.GetMasterTrace());
                                                    if (!directory)
                                                    {
                                                        names.Add(name);
                                                    }
                                                }
                                            }
                                        }
                                        foreach (string nameEnum in names)
                                        {
                                            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                            {
                                                break;
                                            }

                                            // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                            // variable) in order to capture each value in the anonymous method.
                                            // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                            string name = nameEnum;

                                            concurrent.Do(
                                                String.Empty,
                                                delegate(ConcurrentTasks.ITaskContext taskContext)
                                                {
                                                    using (TextWriter threadTrace = TaskLogWriter.Create(fileManager.GetMasterTrace()))
                                                    {
                                                        using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                                        {
                                                            try
                                                            {
                                                                messages.WriteLine("delete {0}", name);
                                                                fileManager.Delete(name, threadTrace);
                                                            }
                                                            catch (Exception exception)
                                                            {
                                                                Interlocked.Exchange(ref fatal, 1);
                                                                messages.WriteLine("Exception: {0}", exception);
                                                            }
                                                        }
                                                    }
                                                });

                                            messagesLog.Flush();
                                        }
                                    }
                                    used = 2;
                                    break;

                                case "delete-id":
                                case "del-id":
                                    if (args.Length < 2)
                                    {
                                        throw new ArgumentException();
                                    }
                                    {
                                        string id = args[1];
                                        Console.WriteLine("delete id {0}", id);
                                        fileManager.DeleteById(id, fileManager.GetMasterTrace());
                                    }
                                    used = 2;
                                    break;

                                case "rename-stem":
                                    if (args.Length < 2)
                                    {
                                        throw new ArgumentException();
                                    }
                                    {
                                        string oldStem = args[1];
                                        string newStem = args[2];
                                        Console.WriteLine("rename {0}* to {1}*", oldStem, newStem);
                                        string[] oldNames = fileManager.GetFileNames(oldStem/*prefix*/, fileManager.GetMasterTrace());
                                        string[] newNames = new string[oldNames.Length];
                                        for (int i = 0; i < newNames.Length; i++)
                                        {
                                            Debug.Assert(oldNames[i].StartsWith(oldStem/*prefix*/));
                                            string suffix = oldNames[i].Substring(oldStem/*prefix*/.Length);
                                            newNames[i] = newStem + suffix;
                                            if (fileManager.Exists(newNames[i], fileManager.GetMasterTrace()))
                                            {
                                                throw new IOException(String.Format("File exists: remote:{0}", newNames[i]));
                                            }
                                        }
                                        for (int iEnum = 0; iEnum < newNames.Length; iEnum++)
                                        {
                                            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                            {
                                                break;
                                            }

                                            // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                            // variable) in order to capture each value in the anonymous method.
                                            // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                            int i = iEnum;

                                            concurrent.Do(
                                                "rename",
                                                delegate(ConcurrentTasks.ITaskContext taskContext)
                                                {
                                                    using (TextWriter threadTrace = TaskLogWriter.Create(fileManager.GetMasterTrace()))
                                                    {
                                                        using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                                        {
                                                            try
                                                            {
                                                                messages.WriteLine("rename {0} to {1}", oldNames[i], newNames[i]);
                                                                fileManager.Rename(oldNames[i], newNames[i], threadTrace);
                                                            }
                                                            catch (Exception exception)
                                                            {
                                                                Interlocked.Exchange(ref fatal, 1);
                                                                messages.WriteLine("Exception: {0}", exception);
                                                            }
                                                        }
                                                    }
                                                });

                                            messagesLog.Flush();
                                        }
                                    }
                                    used = 3;
                                    break;

                                case "upload":
                                    if (!FileNamePatternMatch.ContainsWildcards(args[1]))
                                    {
                                        // single file, explicit names
                                        if (args.Length < 3)
                                        {
                                            throw new ArgumentException();
                                        }
                                        string localFileToUpload = args[1];
                                        string targetName = args[2];
                                        Console.WriteLine("upload {0} to {1}", localFileToUpload, targetName);
                                        Random rnd = new Random();
                                        string nameTemp = null;
                                        ILocalFileCopy fileRef = null;
                                        while (fileRef == null)
                                        {
                                            nameTemp = rnd.Next().ToString();
                                            try
                                            {
                                                fileRef = fileManager.GetTempExisting(localFileToUpload, nameTemp, fileManager.GetMasterTrace());
                                            }
                                            catch (Exception)
                                            {
                                            }
                                        }
                                        using (fileRef)
                                        {
                                            fileManager.Commit(fileRef, nameTemp, targetName, true/*overwrite*/, null/*progressTracker*/, fileManager.GetMasterTrace());
                                        }
                                        used = 3;
                                    }
                                    else
                                    {
                                        // multiple files
                                        if (args.Length < 2)
                                        {
                                            throw new ArgumentException();
                                        }
                                        string pattern = args[1];
                                        string directory = Path.GetDirectoryName(pattern);
                                        if (String.IsNullOrEmpty(directory))
                                        {
                                            directory = ".";
                                        }
                                        if (!Directory.Exists(directory))
                                        {
                                            throw new UsageException();
                                        }
                                        FileNamePatternMatch matcher = new FileNamePatternMatch(pattern);
                                        List<string> names = new List<string>();
                                        foreach (string sourcePath in Directory.GetFiles(directory))
                                        {
                                            string sourceName = Path.GetFileName(sourcePath);
                                            if (matcher.IsMatch(sourceName))
                                            {
                                                names.Add(sourceName);
                                            }
                                            if (fileManager.Exists(sourceName, fileManager.GetMasterTrace()))
                                            {
                                                throw new IOException(String.Format("File exists: remote:{0}", sourceName));
                                            }
                                        }
                                        foreach (string nameEnum in names)
                                        {
                                            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                            {
                                                break;
                                            }

                                            // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                            // variable) in order to capture each value in the anonymous method.
                                            // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                            string name = nameEnum;

                                            concurrent.Do(
                                                "upload",
                                                delegate(ConcurrentTasks.ITaskContext taskContext)
                                                {
                                                    using (TextWriter threadTrace = TaskLogWriter.Create(fileManager.GetMasterTrace()))
                                                    {
                                                        using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                                        {
                                                            try
                                                            {
                                                                messages.WriteLine("upload {0}", name);
                                                                Random rnd = new Random();
                                                                string nameTemp = null;
                                                                ILocalFileCopy fileRef = null;
                                                                while (fileRef == null)
                                                                {
                                                                    nameTemp = rnd.Next().ToString();
                                                                    try
                                                                    {
                                                                        fileRef = fileManager.GetTempExisting(Path.Combine(directory, name), nameTemp, threadTrace);
                                                                    }
                                                                    catch (Exception)
                                                                    {
                                                                    }
                                                                }
                                                                using (fileRef)
                                                                {
                                                                    fileManager.Commit(fileRef, nameTemp, name, true/*overwrite*/, null/*progressTracker*/, threadTrace);
                                                                }
                                                            }
                                                            catch (Exception exception)
                                                            {
                                                                Interlocked.Exchange(ref fatal, 1);
                                                                messages.WriteLine("Exception: {0}", exception);
                                                            }
                                                        }
                                                    }
                                                });

                                            messagesLog.Flush();
                                        }
                                        used = 2;
                                    }
                                    break;

                                case "download":
                                    if (args.Length < 3)
                                    {
                                        throw new ArgumentException();
                                    }
                                    if (!FileNamePatternMatch.ContainsWildcards(args[1]))
                                    {
                                        // single file, explicit names
                                        string sourceName = args[1];
                                        string localFileToSaveInto = args[2];
                                        if (File.Exists(localFileToSaveInto))
                                        {
                                            throw new IOException(String.Format("File exists: {0}", localFileToSaveInto));
                                        }
                                        Console.WriteLine("download {0} to {1}", sourceName, localFileToSaveInto);
                                        using (ILocalFileCopy fileRef = fileManager.Read(sourceName, null/*progressTracker*/, fileManager.GetMasterTrace()))
                                        {
                                            fileRef.CopyLocal(localFileToSaveInto, true/*overwrite*/);
                                        }
                                        File.SetCreationTime(localFileToSaveInto, context.now);
                                        File.SetLastWriteTime(localFileToSaveInto, context.now);
                                    }
                                    else
                                    {
                                        // multiple files
                                        if (args.Length < 3)
                                        {
                                            throw new ArgumentException();
                                        }
                                        string pattern = args[1];
                                        string directory = args[2];
                                        if (!Directory.Exists(directory))
                                        {
                                            throw new UsageException();
                                        }
                                        FileNamePatternMatch matcher = new FileNamePatternMatch(pattern);
                                        List<string> names = new List<string>();
                                        foreach (string sourceName in fileManager.GetFileNames(null, fileManager.GetMasterTrace()))
                                        {
                                            if (matcher.IsMatch(sourceName))
                                            {
                                                names.Add(sourceName);
                                            }
                                            string localPath = Path.Combine(directory, sourceName);
                                            if (File.Exists(localPath) || Directory.Exists(localPath))
                                            {
                                                throw new IOException(String.Format("File or directory exists: {0}", localPath));
                                            }
                                        }
                                        foreach (string nameEnum in names)
                                        {
                                            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                            {
                                                break;
                                            }

                                            // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                            // variable) in order to capture each value in the anonymous method.
                                            // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                            string name = nameEnum;

                                            concurrent.Do(
                                                "download",
                                                delegate(ConcurrentTasks.ITaskContext taskContext)
                                                {
                                                    using (TextWriter threadTrace = TaskLogWriter.Create(fileManager.GetMasterTrace()))
                                                    {
                                                        using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                                        {
                                                            try
                                                            {
                                                                messages.WriteLine("download {0}", name);
                                                                string localFileToSaveInto = Path.Combine(directory, name);
                                                                using (ILocalFileCopy fileRef = fileManager.Read(name, null/*progressTracker*/, threadTrace))
                                                                {
                                                                    fileRef.CopyLocal(localFileToSaveInto, true/*overwrite*/);
                                                                }
                                                                File.SetCreationTime(localFileToSaveInto, context.now);
                                                                File.SetLastWriteTime(localFileToSaveInto, context.now);
                                                            }
                                                            catch (Exception exception)
                                                            {
                                                                Interlocked.Exchange(ref fatal, 1);
                                                                messages.WriteLine("Exception: {0}", exception);
                                                            }
                                                        }
                                                    }
                                                });

                                            messagesLog.Flush();
                                        }
                                    }
                                    used = 3;
                                    break;

                                // specialized command for undoing a failed/incomplete partial dynpack update
                                case "dynpack-rollback":
                                    if (args.Length < 2)
                                    {
                                        throw new ArgumentException();
                                    }
                                    used = 2;
                                    {
                                        string targetArchiveFileNameTemplate = args[1];

                                        string manifestFileName = String.Concat(targetArchiveFileNameTemplate, ".", DynPackManifestName, DynPackFileExtension);
                                        string manifestFileNameOld = String.Concat(targetArchiveFileNameTemplate, ".", DynPackManifestNameOld, DynPackFileExtension);
                                        if (!fileManager.Exists(manifestFileNameOld, fileManager.GetMasterTrace()))
                                        {
                                            Console.WriteLine("Old manifest does not exist ({0}), rollback not possible.", manifestFileNameOld);
                                            break;
                                        }
                                        if (fileManager.Exists(manifestFileName, fileManager.GetMasterTrace()))
                                        {
                                            Console.Write("A newer manifest also exists ({0}). Are you sure you want to roll back? [y/n] ", manifestFileName);
                                            bool accepted;
                                            while (true)
                                            {
                                                char key = WaitReadKey(false/*intercept*/);
                                                if (key == 'n')
                                                {
                                                    accepted = false;
                                                    break;
                                                }
                                                else if (key == 'y')
                                                {
                                                    accepted = true;
                                                    break;
                                                }
                                            }
                                            Console.WriteLine();
                                            if (!accepted)
                                            {
                                                break;
                                            }
                                        }

                                        string targetArchiveFileNameTemplateDot = targetArchiveFileNameTemplate + ".";
                                        foreach (string file in fileManager.GetFileNames(targetArchiveFileNameTemplateDot, fileManager.GetMasterTrace()))
                                        {
                                            Debug.Assert(file.StartsWith(targetArchiveFileNameTemplateDot, StringComparison.OrdinalIgnoreCase));
                                            string suffix = file.Substring(targetArchiveFileNameTemplateDot.Length);
                                            if (suffix.StartsWith(DynPackBackupPrefix))
                                            {
                                                string targetSuffix = suffix.Substring(1);

                                                string targetFile = targetArchiveFileNameTemplateDot + targetSuffix;
                                                if (fileManager.Exists(targetFile, fileManager.GetMasterTrace()))
                                                {
                                                    Console.WriteLine("deleting {0}", targetFile);
                                                    fileManager.Delete(targetFile, fileManager.GetMasterTrace());
                                                }
                                                bool backupIsEmpty;
                                                {
                                                    string id;
                                                    bool directory;
                                                    DateTime created, modified;
                                                    long size;
                                                    fileManager.GetFileInfo(file, out id, out directory, out created, out modified, out size, fileManager.GetMasterTrace());
                                                    backupIsEmpty = size == 0;
                                                }
                                                if (!backupIsEmpty)
                                                {
                                                    Console.WriteLine("renaming {0} to {1}", file, targetFile);
                                                    fileManager.Rename(file, targetFile, fileManager.GetMasterTrace());
                                                }
                                                else
                                                {
                                                    Console.WriteLine("clearing {0}", file);
                                                    fileManager.Delete(file, fileManager.GetMasterTrace());
                                                }
                                            }
                                        }
                                    }
                                    break;
                            }

                            concurrent.Drain();
                            messagesLog.Flush();

                            ArrayRemoveAt(ref args, 0, used);
                        }

                        if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                        {
                            throw new ExitCodeException((int)ExitCodes.ProgramFailure);
                        }
                    }
                }
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Dir
        //
        ////////////////////////////////////////////////////////////////////////////

        private static void DirRecursive(string path, string[] parts, int index)
        {
            if ((index == 0) && (parts[index].EndsWith(":")))
            {
                DirRecursive(String.Concat(parts[0], "\\"), parts, index + 1);
            }
            else if (index == parts.Length - 1)
            {
                path = Path.Combine(path, parts[index]);
                if (Directory.Exists(path) || File.Exists(path))
                {
                    StringBuilder output = new StringBuilder();
                    using (StringWriter writer = new StringWriter(output))
                    {
                        using (Process process = new Process())
                        {
                            process.StartInfo.FileName = "cmd.exe";
                            process.StartInfo.Arguments = String.Format("/C dir \"{0}\"", path);
                            process.StartInfo.CreateNoWindow = true;
                            process.StartInfo.RedirectStandardOutput = true;
                            process.StartInfo.RedirectStandardError = true;
                            process.StartInfo.UseShellExecute = false;
                            process.StartInfo.WorkingDirectory = Path.GetTempPath();
                            process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) { writer.WriteLine(e.Data); } };
                            process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) { writer.WriteLine(e.Data); } };
                            process.Start();
                            process.BeginOutputReadLine();
                            process.WaitForExit();
                        }
                    }
                    Console.Write(output.ToString());
                }
            }
            else if (0 <= parts[index].IndexOf('*'))
            {
                string[] subdirs = Directory.GetDirectories(path, parts[index]);
                foreach (string subdir in subdirs)
                {
                    DirRecursive(Path.Combine(path, subdir), parts, index + 1);
                }
            }
            else
            {
                path = Path.Combine(path, parts[index]);
                DirRecursive(path, parts, index + 1);
            }
        }

        internal static void Dir(string path)
        {
            string[] parts = path.Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            DirRecursive(String.Empty, parts, 0);
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Main
        //
        ////////////////////////////////////////////////////////////////////////////

        public class UsageException : ApplicationException
        {
            private string message;

            public UsageException()
                : base()
            {
            }

            public UsageException(string message)
                : base(message)
            {
                this.message = message;
            }

            public override string Message
            {
                get
                {
                    return message;
                }
            }
        }

        private static string ListCryptoSystems()
        {
            StringBuilder sb = new StringBuilder();
            bool first = true;
            foreach (ICryptoSystem cryptoSystem in CryptoSystems.List)
            {
                if (!first)
                {
                    sb.Append(", ");
                }
                first = false;
                sb.Append(cryptoSystem.Name);
            };
            return sb.ToString();
        }

        internal static void UsageThrow()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  backup [<options>] copy <source-path> [<destination-path>]");
            Console.WriteLine("  backup [<options>] compare <source-path> <destination-path>");
            Console.WriteLine("  backup [<options>] backup <source-path> <archive-folder-path> [<backup-options>] [<exclusion-options>]");
            Console.WriteLine("  backup [<options>] verify <source-path> <archive-folder-path>");
            Console.WriteLine("  backup [<options>] purge <archive-folder-path> <start-checkpoint> <end-checkpoint>");
            Console.WriteLine("  backup [<options>] prune <archive-folder-path>");
            Console.WriteLine("  backup [<options>] restore <archive-folder-path> <checkpoint-path> <destination-path>");
            Console.WriteLine("  backup [<options>] pack <source-path> <destination-file> [<exclusion-options>]");
            Console.WriteLine("  backup [<options>] unpack <source-file> <destination-path>");
            Console.WriteLine("  backup [<options>] split <source-file> <destination-file-prefix> <segment-size-in-bytes>");
            Console.WriteLine("  backup [<options>] unsplit <source-file-prefix> <destination-file>");
            Console.WriteLine("  backup [<options>] dynpack <source-path> <destination-file-prefix> <segment-size-in-bytes> [<dynpack-options>] [<exclusion-options>]");
            Console.WriteLine("  backup [<options>] dynunpack <source-file-prefix> <destination-path>");
            Console.WriteLine("  backup [<options>] sync <local-path> <remote-path> [<sync-options>] [<sync-exclusion-options>]");
            Console.WriteLine("");
            Console.WriteLine("Options (<options>):");
            Console.WriteLine("  -decompress | -compress");
            Console.WriteLine("  -decrypt <algo> <source-key> | -encrypt <algo> <destination-key> | -recrypt <algo1> <algo2> <source-key> <destination-key>");
            Console.WriteLine("     <algo> one of {{{0}}}", ListCryptoSystems());
            Console.WriteLine("  -dirsonly");
            Console.WriteLine("  -ignoreaccessdenied");
            Console.WriteLine("  -ignoredeleted");
            Console.WriteLine("  -zerolen");
            Console.WriteLine("  -beep");
            Console.WriteLine("  -priority {lowest | belownormal | normal | abovenormal | highest }");
            Console.WriteLine("  -waitdebugger");
            Console.WriteLine("  -break");
            Console.WriteLine("  -date <datetime>");
            Console.WriteLine("  -logpath <log-file-path>");
            Console.WriteLine("");
            Console.WriteLine("Cryptography configurations:");
            int maxWidth = 0;
            foreach (ICryptoSystem cryptoSystem in CryptoSystems.List)
            {
                maxWidth = Math.Max(maxWidth, cryptoSystem.Name.Length);
            }
            foreach (ICryptoSystem cryptoSystem in CryptoSystems.List)
            {
                Console.WriteLine("  {0,-" + maxWidth.ToString() + "} {1}", cryptoSystem.Name, cryptoSystem.Description);
            }
            Console.WriteLine("");
            Console.WriteLine("Backup options (<backup-options>):");
            Console.WriteLine("  -nofinish");
            Console.WriteLine("");
            Console.WriteLine("Exclusion options (<exclusion-options>):");
            Console.WriteLine("  -skip .<file-extension>");
            Console.WriteLine("  -exclude <path>");
            Console.WriteLine("");
            Console.WriteLine("Sync exclusion options (<sync-exclusion-options>):");
            Console.WriteLine("  -exclude <relative-path>");
            Console.WriteLine("");
            Console.WriteLine("Options -decompress, -decrypt, -recrypt, or -dirsonly can't be used with 'backup' or 'verify'");
            Console.WriteLine("Option -dirsonly can't be used with 'compare' or 'restore'");
            Console.WriteLine("No options can be used with 'purge'");
            Console.WriteLine("");

            throw new UsageException(String.Empty);
        }

        private static string EnsureRootedLocalPath(string path)
        {
            return Path.IsPathRooted(path) ? path : Path.Combine(Environment.CurrentDirectory, path);
        }

        private static string EnsureRootedRemotablePath(string path)
        {
            try
            {
                Uri uri = new Uri(path);
                if (uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
                    || uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                {
                    return path;
                }
            }
            catch (UriFormatException)
            {
            }
            return Path.IsPathRooted(path) ? path : Path.Combine(Environment.CurrentDirectory, path);
        }

        private static void Main(string[] args)
        {
            int exitCode = (int)ExitCodes.Success;
            Context context = new Context();
            context.faultInjectionTemplateRoot = new FaultTemplateNode();



            // implementation validations
            {
                CRC32.Test();
                KeccakHashAlgorithm.Test();
                Dictionary<string, bool> uniquePersistedID = new Dictionary<string, bool>();
                foreach (ICryptoSystem cryptoSystem in CryptoSystems.List)
                {
                    cryptoSystem.Test();
                    uniquePersistedID.Add(cryptoSystem.UniquePersistentCiphersuiteIdentifier, false);
                }
            }


            try
            {
                bool debug = false;
                bool waitDebugger = false;
                bool traceFaultPoints = false;

                context.now = DateTime.Now;

                if (args.Length == 0)
                {
                    UsageThrow();
                }

                int i = 0;
                while (i < args.Length)
                {
                    if (args[i] == "-break")
                    {
                        debug = true;
                    }
                    else if (args[i] == "-waitdebugger")
                    {
                        waitDebugger = true;
                    }
                    else if (args[i] == "-trace")
                    {
                        context.traceEnabled = true;
                    }
                    else if (args[i] == "-dirsonly")
                    {
                        context.dirsOnly = true;
                    }
                    else if (args[i] == "-ignoreaccessdenied")
                    {
                        context.continueOnAccessDenied = true;
                    }
                    else if (args[i] == "-ignoredeleted")
                    {
                        context.continueOnMissing = true;
                    }
                    else if (args[i] == "-date")
                    {
                        i++;
                        if (!(i < args.Length))
                        {
                            throw new UsageException();
                        }
                        context.now = DateTime.Parse(args[i]);
                    }
                    else if (args[i] == "-logpath")
                    {
                        i++;
                        if (!(i < args.Length))
                        {
                            throw new UsageException();
                        }
                        context.logPath = EnsureRootedLocalPath(args[i]);
                    }
                    else if (args[i] == "-compress")
                    {
                        if (context.compressionOption != CompressionOption.None)
                        {
                            throw new UsageException();
                        }
                        context.compressionOption = CompressionOption.Compress;
                    }
                    else if (args[i] == "-decompress")
                    {
                        if (context.compressionOption != CompressionOption.None)
                        {
                            throw new UsageException();
                        }
                        context.compressionOption = CompressionOption.Decompress;
                    }
                    else if (args[i] == "-recompress")
                    {
                        if (context.compressionOption != CompressionOption.None)
                        {
                            throw new UsageException();
                        }
                        context.compressionOption = CompressionOption.Recompress;
                    }
                    else if (args[i] == "-encrypt")
                    {
                        if (context.cryptoOption != EncryptionOption.None)
                        {
                            throw new UsageException();
                        }
                        i++;

                        context.cryptoOption = EncryptionOption.Encrypt;
                        context.encrypt = new CryptoContext();

                        GetPasswordArgument(args, ref i, "Password:", out context.encrypt.algorithm, out context.encrypt.password);
                    }
                    else if (args[i] == "-decrypt")
                    {
                        if (context.cryptoOption != EncryptionOption.None)
                        {
                            throw new UsageException();
                        }
                        i++;

                        context.cryptoOption = EncryptionOption.Decrypt;
                        context.decrypt = new CryptoContext();

                        GetPasswordArgument(args, ref i, "Password:", out context.decrypt.algorithm, out context.decrypt.password);
                    }
                    else if (args[i] == "-recrypt")
                    {
                        if (context.cryptoOption != EncryptionOption.None)
                        {
                            throw new UsageException();
                        }
                        i++;

                        context.cryptoOption = EncryptionOption.Recrypt;
                        context.encrypt = new CryptoContext();
                        context.decrypt = new CryptoContext();

                        GetPasswordArgument(args, ref i, "Password 1:", out context.decrypt.algorithm, out context.decrypt.password);
                        i++;

                        GetPasswordArgument(args, ref i, "Password 2:", out context.encrypt.algorithm, out context.encrypt.password);
                    }
                    else if (args[i] == "-zerolen")
                    {
                        context.zeroLengthSpecial = true;
                    }
                    else if (args[i] == "-beep")
                    {
                        context.beepEnabled = true;
                    }
                    else if (args[i] == "-nomacprevalidate")
                    {
                        context.doNotPreValidateMAC = true;
                    }
                    else if (args[i] == "-forcenewkeys")
                    {
                        if (context.encrypt == null)
                        {
                            throw new UsageException();
                        }
                        context.encrypt.forceNewKeys = true;
                    }
                    else if (args[i] == "-priority")
                    {
                        i++;
                        if (i < args.Length)
                        {
                            switch (args[i].ToLowerInvariant())
                            {
                                default:
                                    throw new UsageException();
                                case "-":
                                case "belownormal":
                                    Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
                                    break;
                                case "--":
                                case "lowest":
                                    Thread.CurrentThread.Priority = ThreadPriority.Lowest;
                                    break;
                                case "+":
                                case "abovenormal":
                                    Thread.CurrentThread.Priority = ThreadPriority.AboveNormal;
                                    break;
                                case "++":
                                case "highest":
                                    Thread.CurrentThread.Priority = ThreadPriority.Highest;
                                    break;
                                case "0":
                                case "n":
                                case "normal":
                                    Thread.CurrentThread.Priority = ThreadPriority.Normal;
                                    break;
                            }
                        }
                        else
                        {
                            throw new UsageException();
                        }
                    }
                    else if (args[i] == "-refreshtoken")
                    {
                        i++;
                        if (i < args.Length)
                        {
                            context.refreshTokenProtected = args[i]; // always CryptProtectMemory and HexEncode
                        }
                        else
                        {
                            throw new UsageException();
                        }
                    }
                    else if (args[i] == "-concurrency")
                    {
                        i++;
                        if (i < args.Length)
                        {
                            if (args[i].Equals("default"))
                            {
                                context.explicitConcurrency = null;
                            }
                            else
                            {
                                context.explicitConcurrency = Int32.Parse(args[i]);
                                if (context.explicitConcurrency.Value == 1)
                                {
                                    context.explicitConcurrency = 0; // see ConcurrentTasks constructor for why
                                }
                                if ((context.explicitConcurrency.Value < 0) || (context.explicitConcurrency.Value > 64))
                                {
                                    throw new UsageException();
                                }
                            }
                        }
                        else
                        {
                            throw new UsageException();
                        }
                    }
                    else if (args[i] == "-overridesecurityblock")
                    {
                        context.overrideRemoteSecurityBlock = true;
                    }
                    else if (args[i] == "-injectfault")
                    {
                        i++;
                        if (!(i < args.Length))
                        {
                            throw new UsageException();
                        }
                        const string ProofPrefix = "proof:";
                        string proofPath = null;
                        if (args[i].StartsWith(ProofPrefix))
                        {
                            proofPath = EnsureRootedLocalPath(args[i].Substring(ProofPrefix.Length));
                            i++;
                        }
                        string method = args[i];
                        i++;
                        if (!(i < args.Length))
                        {
                            throw new UsageException();
                        }
                        FaultTemplateNode.ParseFaultInjectionPath(context.faultInjectionTemplateRoot, method, proofPath, args[i]);
                    }
                    else if (args[i] == "-tracefaultpoints")
                    {
                        traceFaultPoints = true;
                    }
                    else if (args[i] == "-throttle")
                    {
                        i++;
                        if (!(i < args.Length))
                        {
                            throw new UsageException();
                        }
                        Http.HttpGlobalControl.SetThrottleFromString(args[i]);
                    }
                    else if (args[i] == "-maxretries")
                    {
                        i++;
                        if (!(i < args.Length))
                        {
                            throw new UsageException();
                        }
                        int maxRetries = Int32.Parse(args[i]);
                        RetryHelper.SetMaxRetries(maxRetries);
                    }
                    else if (args[i] == "-socks5")
                    {
                        i++;
                        if (!(i < args.Length))
                        {
                            throw new UsageException();
                        }
                        string proxy = args[i];
                        int colon = proxy.IndexOf(':');
                        if (colon < 0)
                        {
                            context.socks5Address = new System.Net.IPAddress(new byte[] { 127, 0, 0, 1 });
                        }
                        else
                        {
                            context.socks5Address = System.Net.IPAddress.Parse(proxy.Substring(0, colon));
                            proxy = proxy.Substring(colon + 1);
                        }
                        context.socks5Port = Int32.Parse(proxy);
                    }
                    else
                    {
                        break;
                    }
                    i++;
                }

                context.faultInjectionRoot = new FaultInstanceNode(context.faultInjectionTemplateRoot).Select(null);
                if (traceFaultPoints)
                {
                    context.faultInjectionRoot = new FaultTraceNode(context.faultInjectionRoot);
                }

                if (waitDebugger)
                {
                    Console.Write("Attach debugger... ");
                    while (!Debugger.IsAttached)
                    {
                        Thread.Sleep(250);
                    }
                    Console.WriteLine("found");
                }
                if (debug)
                {
                    Debugger.Break();
                }

                switch (args[i++])
                {
                    default:
                        throw new UsageException();

                    case "copy":
                        if (i + 1 > args.Length)
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            string[] argsExtra = new string[args.Length - (i + 2)];
                            Array.Copy(args, i + 2, argsExtra, 0, argsExtra.Length);
                            Copy(
                                EnsureRootedLocalPath(args[i]),
                                i + 1 < args.Length
                                    ? EnsureRootedLocalPath(args[i + 1])
                                    : Environment.CurrentDirectory,
                                context,
                                argsExtra);
                        }
                        break;

                    case "compare":
                        if ((i + 2 > args.Length) || context.dirsOnly)
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Compare(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context);
                        }
                        break;

                    case "backup":
                        if ((i + 2 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Compress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Encrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            string[] argsExtra = new string[args.Length - (i + 2)];
                            Array.Copy(args, i + 2, argsExtra, 0, argsExtra.Length);
                            if (context.cryptoOption != EncryptionOption.None)
                            {
                                ConsoleWriteLineColor(ConsoleColor.Yellow, "WARNING: Use of encryption in \"backup\" archiving mode is not recommended. Filenames and directory structure can provide substantial information to an adversary, even if the file contents can't be read.");
                            }
                            BackupDecremental(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context,
                                argsExtra);
                        }
                        break;

                    case "verify":
                        if ((i + 2 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Compress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Encrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Verify(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context);
                        }
                        break;

                    case "purge":
                        if ((i + 3 > args.Length) ||
                            context.dirsOnly ||
                            (context.compressionOption != CompressionOption.None) ||
                            (context.cryptoOption != EncryptionOption.None) ||
                            Path.IsPathRooted(args[i + 1]) ||
                            (args[i + 1] != Path.GetFileName(args[i + 1])) ||
                            Path.IsPathRooted(args[i + 2]) ||
                            (args[i + 2] != Path.GetFileName(args[i + 2])))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Purge(
                                EnsureRootedLocalPath(args[i]),
                                args[i + 1],
                                args[i + 2],
                                context);
                        }
                        break;

                    case "prune":
                        if ((i + 1 > args.Length) ||
                            context.dirsOnly ||
                            (context.compressionOption != CompressionOption.None) ||
                            (context.cryptoOption != EncryptionOption.None))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Prune(
                                EnsureRootedLocalPath(args[i]),
                                context);
                        }
                        break;

                    case "restore":
                        if ((i + 3 > args.Length) ||
                            context.dirsOnly ||
                            Path.IsPathRooted(args[i + 1]))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Restore(
                                EnsureRootedLocalPath(args[i]),
                                args[i + 1],
                                EnsureRootedLocalPath(args[i + 2]),
                                context);
                        }
                        break;

                    case "pack":
                        if ((i + 2 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Compress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Encrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            string[] argsExtra = new string[args.Length - (i + 2)];
                            Array.Copy(args, i + 2, argsExtra, 0, argsExtra.Length);
                            Pack(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context,
                                argsExtra);
                        }
                        break;

                    case "unpack":
                        if ((i + 2 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Decompress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Decrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Unpack(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context);
                        }
                        break;

                    case "dumppack":
                        if ((i + 1 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Decompress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Decrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Dumppack(
                                EnsureRootedRemotablePath(args[i]),
                                context);
                        }
                        break;

                    case "validate":
                        if ((i + 1 > args.Length) ||
                            context.dirsOnly ||
                            (context.compressionOption != CompressionOption.None) ||
                            (context.cryptoOption != EncryptionOption.Decrypt))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            ValidateEncryption(
                                EnsureRootedLocalPath(args[i]),
                                context);
                        }
                        break;

                    case "valdynpack":
                        if ((i + 1 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Decompress)) ||
                            (context.cryptoOption != EncryptionOption.Decrypt))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            string[] argsExtra = new string[args.Length - (i + 1)];
                            Array.Copy(args, i + 1, argsExtra, 0, argsExtra.Length);
                            ValidateDynamicPack(
                                EnsureRootedRemotablePath(args[i]),
                                context,
                                argsExtra);
                        }
                        break;

                    case "split":
                        {
                            int size;
                            if ((i + 3 > args.Length) ||
                                context.dirsOnly ||
                                (context.compressionOption != CompressionOption.None) ||
                                (context.cryptoOption != EncryptionOption.None) ||
                                !Int32.TryParse(args[i + 2], out size))
                            {
                                throw new UsageException();
                            }
                            else
                            {
                                Split(
                                    EnsureRootedLocalPath(args[i]),
                                    EnsureRootedLocalPath(args[i + 1]),
                                    size,
                                    context);
                            }
                        }
                        break;

                    case "unsplit":
                        if ((i + 2 > args.Length) ||
                            context.dirsOnly ||
                            (context.compressionOption != CompressionOption.None) ||
                            (context.cryptoOption != EncryptionOption.None))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Unsplit(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context);
                        }
                        break;

                    case "sync":
                        if ((i + 3 > args.Length) || context.dirsOnly)
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            string[] argsExtra = new string[args.Length - (i + 3)];
                            Array.Copy(args, i + 3, argsExtra, 0, argsExtra.Length);
                            Sync(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                EnsureRootedLocalPath(args[i + 2]),
                                context,
                                argsExtra);
                        }
                        break;

                    case "dynpack":
                        if ((i + 3 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Compress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Encrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            string[] argsExtra = new string[args.Length - (i + 3)];
                            Array.Copy(args, i + 3, argsExtra, 0, argsExtra.Length);
                            DynamicPack(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedRemotablePath(args[i + 1]),
                                Int64.Parse(args[i + 2], NumberStyles.Integer | NumberStyles.AllowThousands),
                                context,
                                argsExtra);
                        }
                        break;

                    case "dynunpack":
                        if ((i + 2 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Decompress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Decrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            string[] argsExtra = new string[args.Length - (i + 2)];
                            Array.Copy(args, i + 2, argsExtra, 0, argsExtra.Length);
                            DynamicUnpack(
                                EnsureRootedRemotablePath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context,
                                argsExtra);
                        }
                        break;

                    case "dir":
                        if (i + 1 > args.Length)
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Dir(EnsureRootedLocalPath(args[i]));
                        }
                        break;

                    case "remote":
                        {
                            string[] argsExtra = new string[args.Length - i];
                            Array.Copy(args, i, argsExtra, 0, argsExtra.Length);
                            RemoteCommand(
                                argsExtra,
                                context);
                        }
                        break;
                }
            }
            catch (UsageException exception)
            {
                if (exception.Message == null)
                {
                    Console.WriteLine("Invalid program arguments");
                }
                else if (!String.IsNullOrEmpty(exception.Message))
                {
                    Console.WriteLine(exception.Message);
                }
                exitCode = (int)ExitCodes.Usage;
            }
            catch (ExitCodeException exception)
            {
                if (!String.IsNullOrEmpty(exception.Message))
                {
                    ConsoleWriteLineColor(ConsoleColor.Red, exception.Message);
                }
                exitCode = exception.ExitCode;
            }
            catch (Exception exception)
            {
                if (context.beepEnabled)
                {
                    Console.Beep(440, 500);
                }
                ConsoleWriteLineColor(ConsoleColor.Red, "");
                ConsoleWriteLineColor(ConsoleColor.Red, "Error:");
                ConsoleWriteLineColor(ConsoleColor.Red, exception.Message);
                foreach (KeyValuePair<object, object> items in exception.Data)
                {
                    ConsoleWriteLineColor(ConsoleColor.Red, "{0}: {1}", items.Key != null ? items.Key.ToString() : "(null)", items.Value != null ? items.Value.ToString() : "(null)");
                }
                ConsoleWriteLineColor(ConsoleColor.Red, exception.StackTrace);

                exitCode = (int)ExitCodes.ProgramFailure;
            }

            Environment.ExitCode = exitCode;
        }
    }
}
