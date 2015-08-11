/*
 *  Copyright © 2014 Thomas R. Lawrence
 * 
 *  This file is part of FileUtilityTester
 *
 *  FileUtilityTester is free software: you can redistribute it and/or modify
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
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32.SafeHandles;

using HexUtil;
using ProtectedData;

namespace FileUtilityTester
{
    class Program
    {
        private const string WorkspaceRoot = "test-workspace";

        private const string CodeCoverageReports = "test-coverage";
        // OpenCoverage reports can be processed after run with a script like this:
        //   cd %TEMP%\test-coverage
        //   "C:\Program Files\ReportGenerator\ReportGenerator_1.9.1.0\bin\ReportGenerator.exe" -reports:results*.xml -targetdir:.
        //   start index.html

        private static readonly RandomNumberGenerator random = RNGCryptoServiceProvider.Create();
        private static readonly SHA256 sha256 = SHA256.Create();

        private static class FileCompressionHelper
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

        private static object EvalExpression(string expression, Dictionary<string, object> variables)
        {
            expression = expression.Trim();
            if (expression[0] == '"')
            {
                return expression.Substring(1, expression.IndexOf('"', 1) - 1);
            }
            else if (Char.IsLetter(expression[0]))
            {
                return variables[expression];
            }
            else
            {
                return Int64.Parse(expression);
            }
        }

        private static void Eval(TextReader scriptReader, int scriptNumber, string scriptName, TestResultMatrix resultMatrix)
        {
            Dictionary<string, KeyValuePair<string, string>> commands = new Dictionary<string, KeyValuePair<string, string>>();
            Dictionary<string, bool> opencover = new Dictionary<string, bool>();
            Dictionary<string, object> variables = new Dictionary<string, object>();
            DateTime resetNow = new DateTime(2010, 1, 1);
            DateTime now;
            int moduleNumber = 0;
            string moduleName = null;
            int testNumber = 0;
            string testName = null;
            bool testFailed = false;
            HashDispenser hashes = new HashDispenser();
            int lastExitCode = 0;
            string lastOutput = null;
            string skipToModule = null;
            const string InitialDefaultDateFormat = "s"; // sortable datetime format: yyyy-MM-ddTHH:mm:ss
            string defaultDateFormat = InitialDefaultDateFormat;
            bool failPause = false;
            int? commandTimeoutSeconds = null;
            Dictionary<string, Stream> openFiles = new Dictionary<string, Stream>();

            now = resetNow;
            variables["DATE"] = now.ToString(InitialDefaultDateFormat);

            int lineNumber = 0;
            //try
            {
                string line;
                while ((line = scriptReader.ReadLine()) != null)
                {
                    bool currentFailed = false;

                    lineNumber++;

                    if (line.StartsWith("#"))
                    {
                        continue;
                    }

                    line = line.TrimEnd();
                    if (String.IsNullOrEmpty(line))
                    {
                        continue;
                    }

                    string command;
                    int space = line.IndexOf(' ');
                    if (space >= 0)
                    {
                        command = line.Substring(0, space);
                    }
                    else
                    {
                        command = line;
                    }
                    if (space < 0)
                    {
                        space = line.Length;
                    }

                    string[] args = ParseArguments(line.Substring(space));
                    switch (command)
                    {
                        default:
                            throw new ApplicationException(String.Format("Invalid command \"{0}\" on line {1}", command, lineNumber));

                        case "reset":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length != 0)
                            {
                                throw new ApplicationException();
                            }
                        Reset:
                            hashes = new HashDispenser();
                            lastExitCode = 0;
                            lastOutput = null;
                            variables = new Dictionary<string, object>();
                            foreach (Stream stream in openFiles.Values)
                            {
                                stream.Dispose();
                            }
                            openFiles.Clear();
                            PrepareWorkspace(); // delete temp files

                            now = resetNow;
                            variables["DATE"] = now.ToString(InitialDefaultDateFormat);
                            break;

                        case "module":
                            moduleNumber++;
                            testFailed = false;
                            testNumber = 0;
                            testName = null;
                            moduleName = Combine(args, 0, args.Length, " ", false/*quoteWhitespace*/);
                            if (skipToModule != null)
                            {
                                if (!skipToModule.Equals(moduleName))
                                {
                                    testFailed = true;
                                }
                                else
                                {
                                    skipToModule = null;
                                }
                            }
                            Console.WriteLine();
                            Console.WriteLine();
                            Console.WriteLine(String.Format("MODULE {0} ({1})", moduleName, moduleNumber));
                            goto Reset;

                        case "test":
                            if (testFailed)
                            {
                                resultMatrix.Skipped();
                                break;
                            }
                            testNumber++;
                            testName = Combine(args, 0, args.Length, " ", false/*quoteWhitespace*/);
                            resultMatrix.InitTest(scriptNumber, scriptName, moduleNumber, moduleName, testNumber, testName);
                            Console.WriteLine();
                            Console.WriteLine(String.Format("TEST {0} ({1})", testName, testNumber));
                            break;

                        case "skip-to":
                            if (args.Length == 0)
                            {
                                throw new ApplicationException();
                            }
                            if (args[0].Equals("module", StringComparison.OrdinalIgnoreCase))
                            {
                                skipToModule = Combine(args, 1, args.Length - 1, " ", false/*quoteWhitespace*/);
                                testFailed = true;
                            }
                            else
                            {
                                throw new ApplicationException();
                            }
                            break;

                        case "set":
                            {
                                string statement = Combine(args, 0, args.Length, " ", false/*quoteWhitespace*/);
                                int equals = statement.IndexOf('=');
                                string var = statement.Substring(0, equals).Trim();
                                string expression = statement.Substring(equals + 1);
                                variables[var] = EvalExpression(expression, variables);
                            }
                            break;

                        case "fail-pause":
                            if (args.Length != 1)
                            {
                                throw new ApplicationException();
                            }
                            switch (args[0])
                            {
                                default:
                                    throw new ApplicationException();
                                case "on":
                                    failPause = true;
                                    break;
                                case "off":
                                    failPause = false;
                                    break;
                            }
                            break;

                        case "timeout":
                            if (args.Length != 1)
                            {
                                throw new ApplicationException();
                            }
                            if (args[0].Equals("none"))
                            {
                                commandTimeoutSeconds = null;
                            }
                            else
                            {
                                commandTimeoutSeconds = Int32.Parse(args[0]);
                            }
                            break;

                        case "command":
                            if (args.Length < 2)
                            {
                                throw new ApplicationException();
                            }
                            commands[args[0]] = new KeyValuePair<string, string>(FindCommand(args[1]), Combine(args, 2, args.Length - 2, " ", true/*quoteWhitespace*/));
                            break;

                        case "opencover":
                            if (args.Length != 1)
                            {
                                throw new ApplicationException();
                            }
                            if (!commands.ContainsKey(args[0]))
                            {
                                throw new ApplicationException();
                            }
                            opencover[args[0]] = true;
                            break;

                        case "mkdir":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length != 1)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string path = CheckPath(args[0], lineNumber);
                                Directory.CreateDirectory(path);
                                Directory.SetCreationTime(path, now);
                                Directory.SetLastWriteTime(path, now);
                            }
                            break;

                        case "rmdir":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length != 1)
                            {
                                throw new ApplicationException();
                            }
                            DeleteDirectory(CheckPath(args[0], lineNumber));
                            break;

                        case "show-output":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length != 0)
                            {
                                throw new ApplicationException();
                            }
                            Console.Write(lastOutput);
                            break;

                        case "save-output":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length != 1)
                            {
                                throw new ApplicationException();
                            }
                            File.WriteAllText(CheckPath(args[0], lineNumber), lastOutput);
                            break;

                        case "lastoutput-verify":
                            StreamVerify(
                                command,
                                scriptReader,
                                args,
                                0,
                                "endoutput",
                                ref lineNumber,
                                defaultDateFormat,
                                delegate(string dateFormat) { return lastOutput; },
                                testFailed,
                                ref currentFailed,
                                resultMatrix,
                                scriptNumber,
                                moduleNumber,
                                testNumber);
                            break;

                        case "call":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length < 1)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string exe = args[0];
                                string commandArgs = String.Concat(commands[exe].Value, " ", Combine(args, 1, args.Length - 1, " ", true/*quoteWhitespace*/));
                                foreach (KeyValuePair<string, object> variable in variables)
                                {
                                    commandArgs = commandArgs.Replace(String.Concat("%", variable.Key, "%"), variable.Value.ToString());
                                }
                                Console.WriteLine("{0} {1}", commands[exe].Key, commandArgs);
                                if (!Exec(commands[exe].Key, opencover.ContainsKey(exe), commandArgs, null, commandTimeoutSeconds, out lastExitCode, out lastOutput))
                                {
                                    currentFailed = true;
                                    resultMatrix.Failed(scriptNumber, moduleNumber, testNumber, lineNumber);

                                    Console.WriteLine("FAILURE: command exceeded timeout, script line {0}", lineNumber);
                                }
                            }
                            break;

                        case "call-with-input":
                            if (args.Length < 1)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string linePrefix = ".";
                                if (args[0].Equals("-lineprefix"))
                                {
                                    linePrefix = args[1];
                                    string[] args2 = new string[args.Length - 2];
                                    Array.Copy(args, 2, args2, 0, args2.Length);
                                    args = args2;
                                }

                                string exe = args[0];
                                string commandArgs = String.Concat(commands[exe].Value, " ", Combine(args, 1, args.Length - 1, " ", true/*quoteWhitespace*/));
                                foreach (KeyValuePair<string, object> variable in variables)
                                {
                                    commandArgs = commandArgs.Replace(String.Concat("%", variable.Key, "%"), variable.Value.ToString());
                                }

                                string input = ReadInlineContent(scriptReader, linePrefix, "endinput", ref lineNumber, null);

                                if (testFailed)
                                {
                                    break;
                                }

                                Console.WriteLine("{0} {1}", commands[exe].Key, commandArgs);
                                if (!Exec(commands[exe].Key, opencover.ContainsKey(exe), commandArgs, input, commandTimeoutSeconds, out lastExitCode, out lastOutput))
                                {
                                    currentFailed = true;
                                    resultMatrix.Failed(scriptNumber, moduleNumber, testNumber, lineNumber);

                                    Console.WriteLine("FAILURE: command exceeded timeout, script line {0}", lineNumber);
                                }
                            }
                            break;

                        case "date":
                        case "time":
                            if (args.Length < 1)
                            {
                                throw new ApplicationException();
                            }
                            if (args[0] == "+")
                            {
                                if (args.Length != 2)
                                {
                                    throw new ApplicationException();
                                }
                                now = now.Add(TimeSpan.Parse(args[1]));
                                variables["DATE"] = now.ToString(InitialDefaultDateFormat);
                            }
                            else if (args[0] == "-")
                            {
                                if (args.Length != 2)
                                {
                                    throw new ApplicationException();
                                }
                                now = now.Subtract(TimeSpan.Parse(args[1]));
                                variables["DATE"] = now.ToString(InitialDefaultDateFormat);
                            }
                            else
                            {
                                if (args.Length != 1)
                                {
                                    throw new ApplicationException();
                                }
                                now = DateTime.Parse(args[0]);
                                variables["DATE"] = now.ToString(InitialDefaultDateFormat);
                            }
                            break;

                        case "delete":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length != 1)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string file = CheckPath(args[0], lineNumber);
                                File.Delete(file);
                            }
                            break;

                        case "edit":
                        case "create":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length < 1)
                            {
                                throw new ApplicationException();
                            }
                            {
                                bool create = command == "create";
                                long? size = null;
                                string valueUtf8Literal = null;
                                string binaryResourcePath = null;
                                for (int i = 1; i < args.Length; i++)
                                {
                                    if (args[i] == "-size")
                                    {
                                        i++;
                                        size = Int64.Parse(args[i]);
                                    }
                                    else if (args[i] == "-value")
                                    {
                                        i++;
                                        valueUtf8Literal = args[i];
                                    }
                                    else if (args[i] == "-resource")
                                    {
                                        i++;
                                        binaryResourcePath = CheckPath(args[i], lineNumber);
                                    }
                                    else
                                    {
                                        throw new ApplicationException();
                                    }
                                }
                                string file = CheckPath(args[0], lineNumber);
                                if (create == File.Exists(file))
                                {
                                    throw new ApplicationException(String.Format("file already exists, line {0}", lineNumber));
                                }
                                using (Stream stream = new FileStream(file, FileMode.Create))
                                {
                                    if (valueUtf8Literal != null)
                                    {
                                        byte[] data = Encoding.UTF8.GetBytes(valueUtf8Literal);
                                        stream.Write(data, 0, data.Length);
                                        if (size.HasValue)
                                        {
                                            stream.SetLength(size.Value);
                                        }
                                    }
                                    else if (binaryResourcePath != null)
                                    {
                                        using (FileStream resource = new FileStream(Path.Combine(Path.GetDirectoryName(scriptName), binaryResourcePath), FileMode.Open, FileAccess.Read, FileShare.Read))
                                        {
                                            byte[] buffer = new byte[4096];
                                            int read;
                                            while ((read = resource.Read(buffer, 0, buffer.Length)) != 0)
                                            {
                                                stream.Write(buffer, 0, read);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        using (TextWriter writer = new StreamWriter(stream, Encoding.ASCII))
                                        {
                                            byte[] rnd = new byte[2];
                                            random.GetBytes(rnd);
                                            long length = size.HasValue ? size.Value : Math.Max(0x0fff, 0x3fff & (rnd[0] + ((int)rnd[1] << 8)));
                                            long count = 0;
                                            StringBuilder one = new StringBuilder();
                                            while (count < length)
                                            {
                                                one.Length = 0;
                                                rnd = new byte[1];
                                                random.GetBytes(rnd);
                                                rnd = new byte[(rnd[0] & 0x7) + 1];
                                                random.GetBytes(rnd);
                                                foreach (byte i in rnd)
                                                {
                                                    rnd = new byte[(i & 0xf) + 1];
                                                    random.GetBytes(rnd);
                                                    foreach (byte j in rnd)
                                                    {
                                                        char c = (char)(j % 26 + 'a');
                                                        one.Append(c);
                                                    }
                                                    one.Append(' ');
                                                }
                                                one.AppendLine();
                                                if (count + one.Length > length)
                                                {
                                                    one.Length = (int)(length - count);
                                                }
                                                writer.Write(one);
                                                count += one.Length;
                                            }
                                        }
                                    }
                                }
                                if (create)
                                {
                                    File.SetCreationTime(file, now);
                                }
                                File.SetLastWriteTime(file, now);
                            }
                            break;

                        case "write":
                            if (args.Length < 1)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string file = CheckPath(args[0], lineNumber);
                                string linePrefix = ".";
                                bool binary = false;
                                for (int i = 1; i < args.Length; i++)
                                {
                                    if (args[i].Equals("-lineprefix"))
                                    {
                                        i++;
                                        linePrefix = args[i];
                                    }
                                    else if (args[i].Equals("-binary"))
                                    {
                                        binary = true;
                                    }
                                    else
                                    {
                                        throw new ApplicationException();
                                    }
                                }

                                bool create = !File.Exists(file);
                                string content = ReadInlineContent(scriptReader, linePrefix, "endwrite", ref lineNumber, null);
                                if (testFailed)
                                {
                                    break;
                                }
                                if (!binary)
                                {
                                    using (TextWriter writer = new StreamWriter(file))
                                    {
                                        writer.Write(content);
                                    }
                                }
                                else
                                {
                                    using (TextReader reader = new StringReader(content))
                                    {
                                        File.WriteAllBytes(file, BinaryDecode(linePrefix, reader));
                                    }
                                }
                                if (create)
                                {
                                    File.SetCreationTime(file, now);
                                }
                                File.SetLastWriteTime(file, now);
                            }
                            break;

                        case "invert-range":
                            if (args.Length != 3)
                            {
                                throw new ApplicationException();
                            }
                            if (testFailed)
                            {
                                break;
                            }
                            {
                                string file = CheckPath(args[0], lineNumber);
                                int offset = Int32.Parse(args[1]); // offset >= 0: from start, offset <= 0: from end
                                int range = Int32.Parse(args[2]);

                                using (Stream stream = File.Open(file, FileMode.Open))
                                {
                                    stream.Seek(offset >= 0 ? offset : stream.Length + offset, SeekOrigin.Begin);
                                    byte[] b = new byte[range];
                                    int r = stream.Read(b, 0, range);
                                    if (r != range)
                                    {
                                        throw new IOException();
                                    }
                                    for (int i = 0; i < b.Length; i++)
                                    {
                                        b[i] = (byte)~b[i];
                                    }
                                    stream.Seek(offset >= 0 ? offset : stream.Length + offset, SeekOrigin.Begin);
                                    stream.Write(b, 0, range);
                                }
                                File.SetLastWriteTime(file, now);
                            }
                            break;

                        case "file-verify":
                            if (args.Length < 1)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string file = CheckPath(args[0], lineNumber);
                                StreamVerify(
                                    command,
                                    scriptReader,
                                    args,
                                    1,
                                    "endfile",
                                    ref lineNumber,
                                    defaultDateFormat,
                                    delegate(string dateFormat) { return File.ReadAllText(file); },
                                    testFailed,
                                    ref currentFailed,
                                    resultMatrix,
                                    scriptNumber,
                                    moduleNumber,
                                    testNumber);
                            }
                            break;

                        case "open":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length != 2)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string file = CheckPath(args[0], lineNumber);
                                switch (args[1])
                                {
                                    default:
                                        throw new ApplicationException();
                                    case "wx":
                                        openFiles[file] = File.Open(file, FileMode.Open, FileAccess.Write, FileShare.None);
                                        break;
                                    case "rx":
                                        openFiles[file] = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.None);
                                        break;
                                    case "rr":
                                        openFiles[file] = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.Read);
                                        break;
                                    case "ra":
                                        openFiles[file] = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                        break;
                                }
                            }
                            break;

                        case "close-all":
                            if (testFailed)
                            {
                                break;
                            }
                            foreach (Stream stream in openFiles.Values)
                            {
                                stream.Dispose();
                            }
                            openFiles.Clear();
                            break;

                        case "copy":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length != 2)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string source = CheckPath(args[0], lineNumber);
                                string target = CheckPath(args[1], lineNumber);
                                if (File.Exists(source))
                                {
                                    File.Copy(source, target);
                                    File.SetAttributes(target, File.GetAttributes(target) & ~FileAttributes.ReadOnly);
                                    File.SetCreationTime(target, File.GetCreationTime(source));
                                    File.SetLastWriteTime(target, File.GetLastWriteTime(source));
                                    File.SetAttributes(target, File.GetAttributes(source));
                                }
                                else if (Directory.Exists(source))
                                {
                                    CopyTree(source, target);
                                }
                                else
                                {
                                    throw new ApplicationException();
                                }
                            }
                            break;

                        case "move":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length != 2)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string source = CheckPath(args[0], lineNumber);
                                string target = CheckPath(args[1], lineNumber);
                                if (Directory.Exists(source))
                                {
                                    if (!String.Equals(source, target, StringComparison.OrdinalIgnoreCase))
                                    {
                                        Directory.Move(source, target);
                                    }
                                    else
                                    {
                                        string container = Path.GetDirectoryName(source);
                                        uint i = 0;
                                        byte[] start = new byte[sizeof(uint)];
                                        random.GetBytes(start);
                                        foreach (byte b in start)
                                        {
                                            i = (i << 8) | b;
                                        }
                                        string temp;
                                        while (File.Exists(temp = Path.Combine(container, i.ToString())) || Directory.Exists(temp))
                                        {
                                            i++;
                                        }
                                        Directory.Move(source, temp);
                                        Directory.Move(temp, target);
                                    }
                                }
                                else
                                {
                                    File.Move(source, target);
                                }
                            }
                            break;

                        case "attrib":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length < 1)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string path = CheckPath(args[0], lineNumber);
                                for (int i = 1; i < args.Length; i++)
                                {
                                    if (args[i].Length != 2)
                                    {
                                        throw new ApplicationException();
                                    }
                                    FileAttributes mask = 0;
                                    switch (Char.ToLower(args[i][1]))
                                    {
                                        default:
                                            throw new ApplicationException();
                                        case 'a':
                                            mask = FileAttributes.Archive;
                                            break;
                                        case 'r':
                                            mask = FileAttributes.ReadOnly;
                                            break;
                                        case 'h':
                                            mask = FileAttributes.Hidden;
                                            break;
                                        case 's':
                                            mask = FileAttributes.System;
                                            break;
                                        case 'c':
                                            mask = FileAttributes.Compressed;
                                            break;
                                    }
                                    if (((mask & FileAttributes.Compressed) != 0) && ((mask & ~FileAttributes.Compressed) != 0))
                                    {
                                        throw new ApplicationException("compressed attribute must be set/cleared by itself");
                                    }
                                    if ((mask & FileAttributes.Compressed) == 0)
                                    {
                                        switch (args[i][0])
                                        {
                                            default:
                                                throw new ApplicationException();
                                            case '-':
                                                File.SetAttributes(path, File.GetAttributes(path) & ~mask);
                                                break;
                                            case '+':
                                                File.SetAttributes(path, File.GetAttributes(path) | mask);
                                                break;
                                        }
                                    }
                                    else
                                    {
                                        switch (args[i][0])
                                        {
                                            default:
                                                throw new ApplicationException();
                                            case '-':
                                                FileCompressionHelper.SetCompressed(path, false);
                                                break;
                                            case '+':
                                                FileCompressionHelper.SetCompressed(path, true);
                                                break;
                                        }
                                    }
                                }
                            }
                            break;

                        case "touch":
                            if (args.Length < 1)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string path = CheckPath(args[0], lineNumber);
                                if (testFailed)
                                {
                                    break;
                                }
                                if (args.Length == 1)
                                {
                                    File.SetLastWriteTime(path, now);
                                }
                                else if ((args.Length == 2) && args[1].Equals("-created"))
                                {
                                    File.SetCreationTime(path, now);
                                }
                                else if ((args.Length == 2) && args[1].Equals("-modified"))
                                {
                                    File.SetLastWriteTime(path, now);
                                }
                                else
                                {
                                    DateTime? created = null;
                                    DateTime? lastWritten = null;
                                    for (int i = 1; i < args.Length; i++)
                                    {
                                        if (args[i].Equals("-created"))
                                        {
                                            i++;
                                            created = DateTime.Parse(args[i]);
                                        }
                                        else if (args[i].Equals("-modified"))
                                        {
                                            i++;
                                            lastWritten = DateTime.Parse(args[i]);
                                        }
                                        else
                                        {
                                            throw new ApplicationException();
                                        }
                                    }
                                    if (created.HasValue)
                                    {
                                        File.SetCreationTime(path, created.Value);
                                    }
                                    if (lastWritten.HasValue)
                                    {
                                        File.SetLastWriteTime(path, lastWritten.Value);

                                    }
                                }
                            }
                            break;

                        case "date-format":
                            if (args.Length != 1)
                            {
                                throw new ApplicationException();
                            }
                            defaultDateFormat = args[0];
                            DateTime.Now.ToString(defaultDateFormat); // validate
                            break;

                        case "list":
                        case "qlist":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length < 1)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string path = CheckPath(args[0], lineNumber);
                                string dateFormat = defaultDateFormat;
                                string linePrefix = ".";
                                bool showSizes = false;
                                bool showCompressed = false;
                                for (int i = 1; i < args.Length; i++)
                                {
                                    if (args[i].Equals("-lineprefix"))
                                    {
                                        i++;
                                        linePrefix = args[i];
                                    }
                                    else if (args[i].Equals("-dateformat"))
                                    {
                                        i++;
                                        dateFormat = args[i];
                                    }
                                    else if (args[i].Equals("-sizes"))
                                    {
                                        showSizes = true;
                                    }
                                    else if (args[i].Equals("-compressed"))
                                    {
                                        showCompressed = true;
                                    }
                                    else
                                    {
                                        throw new ApplicationException();
                                    }
                                }

                                string output = List(path, hashes, dateFormat, showSizes, showCompressed);
                                if (command != "qlist")
                                {
                                    WriteWithLinePrefix(Console.Out, output, linePrefix);
                                    Console.WriteLine("endlist");
                                }
                            }
                            break;

                        case "list-verify":
                            if (args.Length < 1)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string path = CheckPath(args[0], lineNumber);
                                bool showSizes = false;
                                if ((args.Length > 1) && args[1].Equals("-sizes"))
                                {
                                    showSizes = true;
                                    Array.Copy(args, 2, args, 1, args.Length - 2);
                                    Array.Resize(ref args, args.Length - 1);
                                }
                                bool showCompressed = false;
                                if ((args.Length > 1) && args[1].Equals("-compressed"))
                                {
                                    showCompressed = true;
                                    Array.Copy(args, 2, args, 1, args.Length - 2);
                                    Array.Resize(ref args, args.Length - 1);
                                }
                                StreamVerify(
                                    command,
                                    scriptReader,
                                    args,
                                    1,
                                    "endlist",
                                    ref lineNumber,
                                    defaultDateFormat,
                                    delegate(string dateFormat) { return List(path, hashes, dateFormat, showSizes, showCompressed); },
                                    testFailed,
                                    ref currentFailed,
                                    resultMatrix,
                                    scriptNumber,
                                    moduleNumber,
                                    testNumber);
                            }
                            break;

                        case "dirs-equal-verify":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length < 2)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string left = CheckPath(args[0], lineNumber);
                                string right = CheckPath(args[1], lineNumber);
                                string dateFormat = defaultDateFormat;
                                string linePrefix = ".";
                                bool showSizes = false;
                                bool showCompressed = false;
                                for (int i = 2; i < args.Length; i++)
                                {
                                    if (args[i].StartsWith("-lineprefix"))
                                    {
                                        i++;
                                        linePrefix = args[i];
                                    }
                                    else if (args[i].Equals("-dateformat"))
                                    {
                                        i++;
                                        dateFormat = args[i];
                                    }
                                    else if (args[i].Equals("-sizes"))
                                    {
                                        showSizes = true;
                                    }
                                    else if (args[i].Equals("-compressed"))
                                    {
                                        showCompressed = true;
                                    }
                                    else
                                    {
                                        throw new ApplicationException();
                                    }
                                }
                                string leftList = List(left, hashes, dateFormat, showSizes, showCompressed);
                                string rightList = List(right, hashes, dateFormat, showSizes, showCompressed);
                                if (!String.Equals(leftList, rightList))
                                {
                                    currentFailed = true;
                                    resultMatrix.Failed(scriptNumber, moduleNumber, testNumber, lineNumber);

                                    Console.WriteLine("FAILURE in 'dirs-equal-verify', script line {0}", lineNumber);
                                    Console.WriteLine("LEFT");
                                    WriteWithLinePrefix(Console.Out, leftList, linePrefix);
                                    Console.WriteLine("RIGHT");
                                    WriteWithLinePrefix(Console.Out, rightList, linePrefix);

                                    string leftTemp = Path.GetTempFileName();
                                    string rightTemp = Path.GetTempFileName();
                                    File.WriteAllText(leftTemp, leftList);
                                    File.WriteAllText(rightTemp, rightList);
                                    Process.Start("windiff.exe", String.Format(" \"{0}\" \"{1}\"", leftTemp, rightTemp));
                                }
                            }
                            break;

                        case "exitcode-verify":
                            if (testFailed)
                            {
                                break;
                            }
                            if ((args.Length < 1) || (args.Length > 2))
                            {
                                throw new ApplicationException();
                            }
                            {
                                bool not = args[0] == "not";
                                int expected = Int32.Parse(args[args.Length - 1]);
                                if (not != (lastExitCode != expected))
                                {
                                    currentFailed = true;
                                    resultMatrix.Failed(scriptNumber, moduleNumber, testNumber, lineNumber);

                                    Console.WriteLine("FAILURE in 'exitcode-verify', script line {0}", lineNumber);
                                    Console.WriteLine("EXITCODE expected={0}{1} actual={2}", not ? "not " : String.Empty, expected, lastExitCode);
                                    Console.WriteLine("program output was:{0}", String.IsNullOrEmpty(lastOutput) ? " [none]" : String.Empty);
                                    Console.WriteLine(lastOutput);
                                }
                            }
                            break;

                        case "verify-not-exist":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length != 1)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string path = CheckPath(args[0], lineNumber);
                                if (File.Exists(path) || Directory.Exists(path))
                                {
                                    currentFailed = true;
                                    resultMatrix.Failed(scriptNumber, moduleNumber, testNumber, lineNumber);

                                    Console.WriteLine("FAILURE in 'verify-not-exist', script line {0}", lineNumber);
                                    Console.WriteLine(lastOutput);
                                }
                            }
                            break;

                        case "load-resource":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length != 2)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string variable = args[0];
                                string resourcePath = CheckPath(args[1], lineNumber);
                                variables[variable] = File.ReadAllText(Path.Combine(Path.GetDirectoryName(scriptName), resourcePath));
                            }
                            break;

                        case "encrypt-memory":
                            if (testFailed)
                            {
                                break;
                            }
                            if (args.Length != 1)
                            {
                                throw new ApplicationException();
                            }
                            {
                                string variable = args[0];
                                byte[] data = Encoding.UTF8.GetBytes(variables[variable].ToString());
                                byte[] encryptedData = ProtectedDataStorage.EncryptEphemeral(data, 0, data.Length, ProtectedDataStorage.EphemeralScope.SameLogon);
                                variables[variable] = HexUtility.HexEncode(encryptedData);
                            }
                            break;
                    }

                    testFailed = testFailed || currentFailed;
                    if (currentFailed && failPause)
                    {
                        Console.Write("<ENTER> to continue ('r' to attempt to ignore error)...");
                        string s = Console.ReadLine();
                        if (s == "r")
                        {
                            testFailed = false;
                        }
                    }
                }
            }
            //catch (Exception exception)
            //{
            //    if (exception is ApplicationException)
            //    {
            //        throw;
            //    }
            //    throw new Exception(String.Format("line {0} of script", lineNumber), exception);
            //}
        }

        private static string FindCommand(string specifiedPath)
        {
            string[] specifiedPathParts = specifiedPath.Split(Path.DirectorySeparatorChar);
            string path = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
            foreach (string specifiedPathPart in specifiedPathParts)
            {
                if (specifiedPathPart == ".")
                {
                    continue;
                }
                else if (specifiedPathPart == "..")
                {
                    path = Path.GetDirectoryName(path);
                }
                else
                {
                    path = Path.Combine(path, specifiedPathPart);
                }
            }
            return path;
        }

        private static void CopyTree(string source, string target)
        {
            Directory.CreateDirectory(target);
            foreach (string file in Directory.GetFileSystemEntries(source))
            {
                string name = Path.GetFileName(file);
                string sourcePath = Path.Combine(source, name);
                string targetPath = Path.Combine(target, name);
                if (File.Exists(sourcePath))
                {
                    File.Copy(sourcePath, targetPath);
                    FileAttributes attr = File.GetAttributes(targetPath);
                    File.SetAttributes(targetPath, attr & ~FileAttributes.ReadOnly);
                    File.SetCreationTime(targetPath, File.GetCreationTime(sourcePath));
                    File.SetLastWriteTime(targetPath, File.GetLastWriteTime(sourcePath));
                    File.SetAttributes(targetPath, attr);
                }
                else
                {
                    CopyTree(sourcePath, targetPath);
                }
            }
        }

        private delegate string GetContent(string dateFormat);
        private static void StreamVerify(string command, TextReader scriptReader, string[] args, int argsStart, string endKeyword, ref int lineNumber, string defaultDateFormat, GetContent getActual, bool testFailed, ref bool currentFailed, TestResultMatrix resultMatrix, int scriptNumber, int moduleNumber, int testNumber)
        {
            int startLineNumber = lineNumber;
            string dateFormat = defaultDateFormat;
            string linePrefix = ".";
            bool ignoreExtraLines = false;
            bool workspacePathHack = false;
            for (int i = argsStart; i < args.Length; i++)
            {
                if (args[i].StartsWith("-lineprefix"))
                {
                    i++;
                    linePrefix = args[i];
                }
                else if (args[i].Equals("-dateformat"))
                {
                    i++;
                    dateFormat = args[i];
                }
                else if (args[i].Equals("-ignoreextralines"))
                {
                    ignoreExtraLines = true;
                }
                else if (args[i].Equals("-workspacepathhack"))
                {
                    workspacePathHack = true;
                }
                else
                {
                    throw new ApplicationException();
                }
            }

            List<int> wildcardLines = new List<int>();
            string standard = ReadInlineContent(scriptReader, linePrefix, endKeyword, ref lineNumber, wildcardLines);
            if (testFailed)
            {
                return;
            }
            string actual = getActual(dateFormat);
            if (workspacePathHack)
            {
                actual = actual.Replace(Environment.CurrentDirectory, "%WORKSPACE%");
                actual = actual.Replace(Environment.CurrentDirectory.ToLowerInvariant(), "%WORKSPACE%"); // try a common case variation
            }
            if (!CompareContent(standard, actual, wildcardLines.ToArray(), ignoreExtraLines))
            {
                currentFailed = true;
                resultMatrix.Failed(scriptNumber, moduleNumber, testNumber, startLineNumber);

                Console.WriteLine("FAILURE in '{0}', script line {1}", command, startLineNumber);
                //
                Console.WriteLine("EXPECTED");
                WriteWithLinePrefix(Console.Out, standard, linePrefix);
                string standardPrefixedTempFile = Path.GetTempFileName();
                using (TextWriter writer = new StreamWriter(standardPrefixedTempFile, false/*append*/, Encoding.UTF8))
                {
                    WriteWithLinePrefix(writer, standard, linePrefix);
                }
                //
                Console.WriteLine("ACTUAL");
                WriteWithLinePrefix(Console.Out, actual, linePrefix);
                string actualPrefixedTempFile = Path.GetTempFileName();
                using (TextWriter writer = new StreamWriter(actualPrefixedTempFile, false/*append*/, Encoding.UTF8))
                {
                    WriteWithLinePrefix(writer, actual, linePrefix);
                }

                Console.WriteLine("Prefixed standard available at \"{0}\", actual at \"{1}\"", standardPrefixedTempFile, actualPrefixedTempFile);

                string standardTemp = Path.GetTempFileName();
                string actualTemp = Path.GetTempFileName();
                File.WriteAllText(standardTemp, standard);
                File.WriteAllText(actualTemp, actual);
                Process.Start("windiff.exe", String.Format(" \"{0}\" \"{1}\"", standardTemp, actualTemp));
            }
        }

        private static string[] ParseArguments(string line)
        {
            List<string> arguments = new List<string>();

            int i = 0;
            while (i < line.Length)
            {
                if (Char.IsWhiteSpace(line[i]))
                {
                    i++;
                    continue;
                }

                if (line[i] == '"')
                {
                    char stop = line[i];
                    i++;
                    StringBuilder sb = new StringBuilder();
                    while (line[i] != stop)
                    {
                        if ((line[i] == '\\') && (line[i + 1] == '"'))
                        {
                            sb.Append(line[i++]);
                        }
                        sb.Append(line[i++]);
                    }
                    i++;
                    arguments.Add(sb.ToString());
                }
                else
                {
                    StringBuilder sb = new StringBuilder();
                    while ((i < line.Length) && !Char.IsWhiteSpace(line[i]))
                    {
                        if ((line[i] == '\\') && (line[i + 1] == '"'))
                        {
                            sb.Append(line[i++]);
                        }
                        sb.Append(line[i++]);
                    }
                    arguments.Add(sb.ToString());
                }
            }

            return arguments.ToArray();
        }

        private static string Combine(string[] parts, int start, int count, string separator, bool quoteWhitespace)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = start; i < start + count; i++)
            {
                if (i > start)
                {
                    sb.Append(separator);
                }
                bool quote = quoteWhitespace && (String.IsNullOrEmpty(parts[i]) || Array.Exists(parts[i].ToCharArray(), delegate(char c) { return Char.IsWhiteSpace(c); }));
                if (quote)
                {
                    sb.Append('"');
                }
                sb.Append(parts[i]);
                if (quote)
                {
                    sb.Append('"');
                }
            }
            return sb.ToString();
        }

        private static string ReadInlineContent(TextReader scriptReader, string linePrefix, string ender, ref int lineNumber, List<int> wildcardLines)
        {
            string line;
            StringBuilder sb = new StringBuilder();
            int localLineNumber = 0;
            while ((line = scriptReader.ReadLine()) != null)
            {
                localLineNumber++;
                lineNumber++;

                if (line.StartsWith(linePrefix))
                {
                    sb.AppendLine(line.Substring(linePrefix.Length));
                }
                else if (line == ender)
                {
                    break;
                }
                else if (line.StartsWith("#"))
                {
                    localLineNumber--;
                    continue;
                }
                else if ((wildcardLines != null) && line.StartsWith("*"))
                {
                    wildcardLines.Add(localLineNumber);
                    sb.AppendLine(line.Substring(1));
                    continue;
                }
                else
                {
                    throw new ApplicationException();
                }
            }
            return sb.ToString();
        }

        private static bool CompareContent(string standard, string actual, int[] wildcardLines, bool skipExtraLines)
        {
            using (TextReader standardReader = new StringReader(standard))
            {
                using (TextReader actualReader = new StringReader(actual))
                {
                    int lineNumber = 0;
                    string lineActual, lineStandard;
                    while (true)
                    {
                        lineNumber++;
                        lineStandard = standardReader.ReadLine();
                        lineActual = actualReader.ReadLine();
                        if ((lineStandard == null) && (lineActual == null))
                        {
                            break;
                        }
                        if ((lineStandard == null) != (lineActual == null))
                        {
                            if (skipExtraLines && (lineStandard == null) && (lineActual != null))
                            {
                                return true;
                            }
                            return false;
                        }
                        if (Array.IndexOf(wildcardLines, lineNumber) >= 0)
                        {
                            if (!String.IsNullOrEmpty(lineStandard))
                            {
                                // http://msdn.microsoft.com/en-us/library/az24scfc%28v=vs.110%29.aspx
                                if (!Regex.IsMatch(lineActual, lineStandard))
                                {
                                    return false;
                                }
                            }
                            continue;
                        }
                        if (!String.Equals(lineStandard, lineActual))
                        {
                            return false;
                        }
                    }
                }
            }
            return true;
        }

        private static void WriteWithLinePrefix(TextWriter writer, string text, string linePrefix)
        {
            using (TextReader reader = new StringReader(text))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    writer.WriteLine(linePrefix + line);
                }
            }
        }

        private class HashDispenser
        {
            private Dictionary<string, int> hashes = new Dictionary<string, int>();

            internal HashDispenser()
            {
                hashes[ComputeHash(new byte[0])] = 0;
            }

            internal int GetNumber(string path)
            {
                string hashString = ComputeHash(File.ReadAllBytes(path));
                if (!hashes.ContainsKey(hashString))
                {
                    hashes[hashString] = hashes.Count;
                }
                return hashes[hashString];
            }

            private static string ComputeHash(byte[] data)
            {
                byte[] hashBytes = sha256.ComputeHash(data);
                char[] hashChars = new char[hashBytes.Length];
                for (int i = 0; i < hashChars.Length; i++)
                {
                    hashChars[i] = (char)hashBytes[i];
                }
                return new String(hashChars);
            }
        }

        private static string List(string root, HashDispenser hashes, string dateFormat, bool showSizes, bool showCompressed)
        {
            StringBuilder sb = new StringBuilder();
            using (TextWriter writer = new StringWriter(sb))
            {
                ListRecursive(root, writer, hashes, dateFormat, showSizes, showCompressed, root.Length + 1);
            }
            return sb.ToString();
        }

        private static void ListRecursive(string root, TextWriter writer, HashDispenser hashes, string dateFormat, bool showSizes, bool showCompressed, int substring)
        {
            foreach (string entry in Directory.GetFileSystemEntries(root))
            {
                string entryPrintable = entry.Substring(substring);
                bool isDirectory = Directory.Exists(entry);
                int hashNum = 0;
                if (!isDirectory)
                {
                    hashNum = hashes.GetNumber(entry);
                }
                string created = !isDirectory ? File.GetCreationTime(entry).ToString(dateFormat) : String.Empty;
                string lastModified = !isDirectory ? File.GetLastWriteTime(entry).ToString(dateFormat) : String.Empty;
                FileAttributes entryAttrs = File.GetAttributes(entry);
                string attrs = new String(
                    new char[]
                    {
                        ((entryAttrs & FileAttributes.ReadOnly) != 0) ? 'R' : '-',
                        ((entryAttrs & FileAttributes.Archive) != 0) ? 'A' : '-',
                        ((entryAttrs & FileAttributes.Hidden) != 0) ? 'H' : '-',
                        ((entryAttrs & FileAttributes.System) != 0) ? 'S' : '-',
                        !isDirectory && (GetFileLength(entry) == 0) ? 'Z' : '-',
                        ((entryAttrs & FileAttributes.Directory) != 0) ? 'D' : '-',
                    });
                if (showCompressed)
                {
                    attrs = String.Concat(attrs, new String(FileCompressionHelper.IsCompressed(entry) ? 'C' : '-', 1));
                }
                writer.WriteLine(" {0,19} {1,19} {2,5}{5} {3}{4}",
                    created,
                    lastModified,
                    attrs,
                    entryPrintable,
                    isDirectory ? new String(Path.DirectorySeparatorChar, 1) : String.Format(" [{0}]", hashNum),
                    showSizes ? String.Format("{0,12}", !isDirectory ? GetFileLength(entry).ToString() : String.Empty) : String.Empty);
                if (isDirectory)
                {
                    ListRecursive(entry, writer, hashes, dateFormat, showSizes, showCompressed, substring);
                }
            }
        }

        private static string coverageReportsPath;
        private static int coverageResultsCounter;
        private static bool Exec(string program, bool opencover, string arguments, string input, int? commandTimeoutSeconds, out int exitCode, out string output)
        {
            if (opencover)
            {
                coverageResultsCounter++;
                arguments = arguments.Replace("\"", "\\\"");
                arguments = String.Format("-register \"-target:{0}\" \"-targetargs:{1}\" \"-output:{2}\" -returntargetcode -log:Off", program, arguments, Path.Combine(coverageReportsPath, String.Format("results{0}.xml", coverageResultsCounter)));
                string openCoverHome = Path.Combine(Environment.GetEnvironmentVariable("USERPROFILE"), @"Local Settings\Application Data\Apps\OpenCover");
                if (!Directory.Exists(openCoverHome))
                {
                    throw new ApplicationException(String.Format("{0} does not exist - is OpenCover installed", openCoverHome));
                }
                program = Path.Combine(openCoverHome, "OpenCover.Console.exe");
                if (!File.Exists(program))
                {
                    throw new ApplicationException(String.Format("{0} does not exist - is OpenCover installed", program));
                }
            }

            bool killed = false;
            exitCode = 0;
            output = null;

            StringBuilder output2 = new StringBuilder();
            using (TextWriter outputWriter = TextWriter.Synchronized(new StringWriter(output2)))
            {
                using (Process cmd = new Process())
                {
                    cmd.StartInfo.Arguments = arguments;
                    cmd.StartInfo.CreateNoWindow = true;
                    cmd.StartInfo.FileName = program;
                    cmd.StartInfo.UseShellExecute = false;
                    cmd.StartInfo.WorkingDirectory = Environment.CurrentDirectory;
                    if (input != null)
                    {
                        cmd.StartInfo.RedirectStandardInput = true;
                    }
                    cmd.StartInfo.RedirectStandardOutput = true;
                    cmd.StartInfo.RedirectStandardError = true;
                    cmd.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) { outputWriter.WriteLine(e.Data); } };
                    cmd.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) { outputWriter.WriteLine(e.Data); } };

                    cmd.Start();
                    cmd.BeginOutputReadLine();
                    cmd.BeginErrorReadLine();
                    if (input != null)
                    {
                        using (TextWriter inputWriter = cmd.StandardInput)
                        {
                            inputWriter.Write(input);
                        }
                    }
                    cmd.WaitForExit(commandTimeoutSeconds.HasValue ? (int)Math.Min((long)commandTimeoutSeconds.Value * 1000, Int32.MaxValue - 1) : Int32.MaxValue);
                    if (!cmd.HasExited)
                    {
                        cmd.Kill();
                        cmd.WaitForExit();
                        killed = true;
                    }
                    cmd.CancelOutputRead();
                    cmd.CancelErrorRead();
                    exitCode = cmd.ExitCode;
                }
            }
            output = output2.ToString();
            if (opencover)
            {
                if (output.StartsWith("Executing: "))
                {
                    int firstLineEnd = output.IndexOf(Environment.NewLine) + Environment.NewLine.Length;
                    output = output.Substring(firstLineEnd);
                }
            }
            return !killed;
        }

        private static string CheckPath(string path, int lineNumber)
        {
            if (String.IsNullOrEmpty(path) || Path.IsPathRooted(path))
            {
                throw new ApplicationException(String.Format("Invalid path \"{0}\" on line {1}", path, lineNumber));
            }

            Stack<string> parts = new Stack<string>();
            foreach (string part in path.Split(new char[] { Path.DirectorySeparatorChar }))
            {
                if (part == ".")
                {
                    continue;
                }
                else if (part == "..")
                {
                    if (parts.Count == 0)
                    {
                        throw new ApplicationException(String.Format("Invalid path \"{0}\" on line {1}", path, lineNumber));
                    }
                    parts.Pop();
                }
                else
                {
                    if (part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                    {
                        throw new ApplicationException(String.Format("Invalid path \"{0}\" on line {1}", path, lineNumber));
                    }
                    parts.Push(part);
                }
            }

            StringBuilder sb = new StringBuilder(path.Length);
            if (parts.Count == 0)
            {
                sb.Append(".");
            }
            else
            {
                string[] parts2 = parts.ToArray();
                Array.Reverse(parts2);
                foreach (string part in parts2)
                {
                    if (sb.Length > 0)
                    {
                        sb.Append(Path.DirectorySeparatorChar);
                    }
                    sb.Append(part);
                }
            }

            return sb.ToString();
        }

        private static long GetFileLength(string path)
        {
            using (Stream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                return stream.Length;
            }
        }

        private static void DeleteDirectory(string path)
        {
            foreach (string subdirectory in Directory.GetDirectories(path))
            {
                DeleteDirectory(subdirectory);
            }

            foreach (string file in Directory.GetFiles(path))
            {
                File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.ReadOnly);
                File.Delete(file);
            }

            Directory.Delete(path);
        }

        private static void PrepareWorkspace()
        {
            string previousDirectory = Environment.CurrentDirectory;
            Environment.CurrentDirectory = Path.GetTempPath();

            try
            {
                Directory.CreateDirectory(WorkspaceRoot);
                DeleteDirectory(WorkspaceRoot);
            }
            catch (Exception exception)
            {
                // This failure usually occurs because two reasons:
                // 1. Some process is still running (usually a hung test exe or windiff)
                // 2. Some object *in this process* has a filesystem reference to one of the
                //    files and was leaked (i.e. Dispose() wasn't called on it)
                throw new ApplicationException("Unable to empty workspace directory", exception);
            }
            Directory.CreateDirectory(WorkspaceRoot);

            Environment.CurrentDirectory = previousDirectory;
        }

        private class TestResultMatrix
        {
            private ScriptInfo[] scripts = new ScriptInfo[0];
            private int skippedTests;

            private class ScriptInfo
            {
                internal readonly string scriptName;
                internal ModuleInfo[] modules = new ModuleInfo[0];

                internal ScriptInfo(string scriptName)
                {
                    this.scriptName = scriptName;
                }
            }

            private class ModuleInfo
            {
                internal readonly string moduleName;
                internal TestInfo[] tests = new TestInfo[0];

                internal ModuleInfo(string moduleName)
                {
                    this.moduleName = moduleName;
                }
            }

            private class TestInfo
            {
                internal readonly string testName;
                internal bool passed = true;
                internal int lineNumber = -1;

                internal TestInfo(string testName)
                {
                    this.testName = testName;
                }
            }

            internal void InitTest(int scriptNumber, string scriptName, int moduleNumber, string moduleName, int testNumber, string testName)
            {
                if (scripts.Length < scriptNumber)
                {
                    Array.Resize(ref scripts, scriptNumber);
                }
                if (scripts[scriptNumber - 1] == null)
                {
                    scripts[scriptNumber - 1] = new ScriptInfo(scriptName);
                }
                ScriptInfo script = scripts[scriptNumber - 1];

                if (script.modules.Length < moduleNumber)
                {
                    Array.Resize(ref script.modules, moduleNumber);
                }
                if (script.modules[moduleNumber - 1] == null)
                {
                    script.modules[moduleNumber - 1] = new ModuleInfo(moduleName);
                }
                ModuleInfo module = script.modules[moduleNumber - 1];

                if (module.tests.Length < testNumber)
                {
                    Array.Resize(ref module.tests, testNumber);
                }
                if (module.tests[testNumber - 1] == null)
                {
                    module.tests[testNumber - 1] = new TestInfo(testName);
                }
                TestInfo testInfo = module.tests[testNumber - 1];
            }

            internal void Failed(int scriptNumber, int moduleNumber, int testNumber, int lineNumber)
            {
                TestInfo testInfo = scripts[scriptNumber - 1].modules[moduleNumber - 1].tests[testNumber - 1];
                testInfo.passed = false;
                testInfo.lineNumber = lineNumber;
            }

            internal void Skipped()
            {
                skippedTests++;
            }

            internal void WriteResults(out int failCount, out int passCount, out int skipCount)
            {
                failCount = 0;
                passCount = 0;
                skipCount = skippedTests;
                for (int scriptNumber = 1; scriptNumber <= scripts.Length; scriptNumber++)
                {
                    ScriptInfo script = scripts[scriptNumber - 1];
                    if (script != null)
                    {
                        Console.WriteLine("SCRIPT \"{0}\" ({1})", script.scriptName, scriptNumber);
                        for (int moduleNumber = 1; moduleNumber <= script.modules.Length; moduleNumber++)
                        {
                            ModuleInfo modules = script.modules[moduleNumber - 1];
                            if (modules != null)
                            {
                                Console.WriteLine("  MODULE {0} ({1})", modules.moduleName, moduleNumber);
                                for (int testNumber = 1; testNumber <= modules.tests.Length; testNumber++)
                                {
                                    TestInfo test = modules.tests[testNumber - 1];
                                    ConsoleColor oldColor = Console.ForegroundColor;
                                    if (!test.passed)
                                    {
                                        Console.ForegroundColor = ConsoleColor.Yellow;
                                    }
                                    Console.WriteLine("    {0,6} : TEST {1} ({2}){3}", test.passed ? "passed" : "FAILED", test.testName, testNumber, test.passed ? String.Empty : String.Format(" at line {0}", test.lineNumber));
                                    Console.ForegroundColor = oldColor;

                                    if (!test.passed)
                                    {
                                        failCount++;
                                    }
                                    else
                                    {
                                        passCount++;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        const string Hex = "0123456789abcdef";

        static byte[] BinaryDecode(string linePrefix, TextReader reader)
        {
            bool deflated = false;

            List<byte> result = new List<byte>();

            string line;
            while ((line = reader.ReadLine()) != null)
            {
                if (line.StartsWith(linePrefix))
                {
                    line = line.Substring(linePrefix.Length);
                }
                if ((result.Count == 0) && line.Equals("deflate", StringComparison.OrdinalIgnoreCase))
                {
                    deflated = true;
                    continue;
                }
                for (int i = 0; i < line.Length; )
                {
                    if (Char.IsWhiteSpace(line[i]))
                    {
                        i++;
                        continue;
                    }
                    if (!(i + 1 < line.Length))
                    {
                        throw new ApplicationException();
                    }
                    byte b = (byte)((Hex.IndexOf(Char.ToLowerInvariant(line[i])) << 4)
                        | Hex.IndexOf(Char.ToLowerInvariant(line[i + 1])));
                    i += 2;
                    result.Add(b);
                }
            }

            if (deflated)
            {
                using (MemoryStream stream = new MemoryStream(result.ToArray()))
                {
                    result.Clear();
                    using (Stream decompressor = new DeflateStream(stream, CompressionMode.Decompress, true/*leaveOpen*/))
                    {
                        byte[] buffer = new byte[4096];
                        int read;
                        while ((read = decompressor.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            for (int i = 0; i < read; i++)
                            {
                                result.Add(buffer[i]);
                            }
                        }
                    }
                }
            }

            return result.ToArray();
        }

        static string BinaryEncode(string linePrefix, byte[] data, bool? compress)
        {
            bool deflated = false;
            if (!(compress.HasValue && !compress.Value))
            {
                byte[] compressed;
                using (MemoryStream stream = new MemoryStream(data.Length))
                {
                    using (Stream compressor = new DeflateStream(stream, CompressionMode.Compress, true/*leaveOpen*/))
                    {
                        compressor.Write(data, 0, data.Length);
                    }
                    compressed = stream.ToArray();
                }

                if ((compress.HasValue && compress.Value) || (compressed.Length < data.Length))
                {
                    deflated = true;
                    data = compressed;
                }
            }

            StringBuilder sb = new StringBuilder(data.Length * 3);

            if (deflated)
            {
                sb.AppendLine(".deflate");
            }

            const int BytesPerLine = 64;
            const int BytesPerGroup = 16;
            for (int i = 0; i < data.Length; i++)
            {
                if (i % BytesPerLine == 0)
                {
                    if (i > 0)
                    {
                        sb.AppendLine();
                    }
                    sb.Append('.');
                }
                else
                {
                    if (i % BytesPerGroup == 0)
                    {
                        sb.Append(' ');
                    }
                }
                sb.Append(Hex[data[i] >> 4]);
                sb.Append(Hex[data[i] & 0x0f]);
            }
            sb.AppendLine();

            return sb.ToString();
        }

        static void Main(string[] args)
        {
            // special hacks
            if ((args.Length >= 2) && (args[0] == "-binaryencode"))
            {
                Console.WriteLine(BinaryEncode(".", File.ReadAllBytes(args[1]), args.Length > 2 ? (args[2] == "-compress" ? (bool?)true : args[2] == "-nocompress" ? (bool?)false : (bool?)null) : (bool?)null));
                return;
            }
            else if ((args.Length >= 2) && (args[0] == "-binarydecode"))
            {
                File.WriteAllBytes(args[1], BinaryDecode(".", Console.In));
                return;
            }
            else if ((args.Length >= 2) && (args[0] == "-decryptmemory"))
            {
                byte[] encryptedData = HexUtility.HexDecode(args[1]);
                using (ProtectedArray<byte> data = ProtectedDataStorage.DecryptEphemeral(encryptedData, 0, encryptedData.Length, ProtectedDataStorage.EphemeralScope.SameLogon))
                {
                    data.Reveal();
                    Console.WriteLine(Encoding.UTF8.GetString(data.ExposeArray()));
                }
                return;
            }
            else if ((args.Length >= 2) && (args[0] == "-encryptmemory"))
            {
                byte[] data = Encoding.UTF8.GetBytes(args[1]);
                byte[] encryptedData = ProtectedDataStorage.EncryptEphemeral(data, 0, data.Length, ProtectedDataStorage.EphemeralScope.SameLogon);
                Console.WriteLine(HexUtility.HexEncode(encryptedData));
                return;
            }


            Environment.ExitCode = 2;

            string originalDirectory = Environment.CurrentDirectory;

            PrepareWorkspace();
            Environment.CurrentDirectory = Path.Combine(Path.GetTempPath(), WorkspaceRoot);

            coverageReportsPath = Path.Combine(Path.GetTempPath(), CodeCoverageReports);
            try
            {
                Directory.Delete(coverageReportsPath, true/*recursive*/);
            }
            catch
            {
            }
            Directory.CreateDirectory(coverageReportsPath);
            if (Directory.GetFileSystemEntries(coverageReportsPath).Length > 0)
            {
                throw new ApplicationException(String.Format("Unable to empty/create {0}", coverageReportsPath));
            }

            List<string> scripts = new List<string>();
            foreach (string manifest in args)
            {
                string manifestPath = manifest;
                if (!Path.IsPathRooted(manifestPath))
                {
                    manifestPath = Path.Combine(originalDirectory, manifestPath);
                }
                if (File.Exists(manifestPath))
                {
                    using (TextReader reader = new StreamReader(manifestPath))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            if (line.StartsWith("#"))
                            {
                                continue;
                            }
                            line = line.Trim();
                            if (String.IsNullOrEmpty(line))
                            {
                                continue;
                            }

                            string scriptPath = line;
                            if (!Path.IsPathRooted(scriptPath))
                            {
                                string scriptPath2 = Path.Combine(Path.GetDirectoryName(manifestPath), scriptPath);
                                if (!File.Exists(scriptPath2))
                                {
                                    scriptPath2 = Path.Combine(originalDirectory, scriptPath);
                                }
                                scriptPath = scriptPath2;
                            }
                            scripts.Add(scriptPath);
                        }
                    }
                }
                else if (Directory.Exists(manifestPath))
                {
                    foreach (string scriptPath in Directory.GetFiles(manifestPath))
                    {
                        scripts.Add(scriptPath);
                    }
                }
                else
                {
                    throw new ApplicationException(String.Format("{0} does not exist", manifestPath));
                }
            }

            TestResultMatrix resultMatrix = new TestResultMatrix();
            for (int i = 0; i < scripts.Count; i++)
            {
                string scriptPath = scripts[i];

                Console.WriteLine();
                Console.WriteLine();
                Console.WriteLine(new String('-', Console.BufferWidth - 1));
                Console.WriteLine("SCRIPT \"{0}\" ({1})", scriptPath, i + 1);
                using (TextReader reader = new StreamReader(scriptPath))
                {
                    Console.Title = String.Format("{0} - {1}", Path.GetFileName(Process.GetCurrentProcess().MainModule.FileName), Path.GetFileName(scriptPath));
                    Eval(reader, i + 1, scriptPath, resultMatrix);
                }
            }

            Console.Title = String.Format("{0} - {1}", Path.GetFileName(Process.GetCurrentProcess().MainModule.FileName), "Finished");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("finished");
            Console.WriteLine();
            Console.WriteLine();
            int failCount, passCount, skipCount;
            resultMatrix.WriteResults(out failCount, out passCount, out skipCount);
            Console.WriteLine();
            Console.WriteLine("failed={0} skipped={2} passed={1}", failCount, passCount, skipCount);
            Console.WriteLine();
            if (Debugger.IsAttached)
            {
                Console.ReadLine();
            }

            Environment.ExitCode = failCount > 0 ? 1 : 0;
        }
    }
}
