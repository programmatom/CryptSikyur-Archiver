/*
 *  Copyright © 2014 Thomas R. Lawrence
 *    except: "SkeinFish 0.5.0/*.cs", which are Copyright 2010 Alberto Fajardo
 *    except: "SerpentEngine.cs", which is Copyright 1997, 1998 Systemics Ltd on behalf of the Cryptix Development Team (but see license discussion at top of that file)
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
using System.Runtime.InteropServices;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web;

using Backup;

namespace Backup
{
    ////////////////////////////////////////////////////////////////////////////
    //
    // Constants
    //
    ////////////////////////////////////////////////////////////////////////////

    static class Constants
    {
        private const int MaxSmallObjectHeapObjectSize = 85000; // http://msdn.microsoft.com/en-us/magazine/cc534993.aspx, http://blogs.msdn.com/b/dotnet/archive/2011/10/04/large-object-heap-improvements-in-net-4-5.aspx
        private const int PageSize = 4096;
        private const int MaxSmallObjectPageDivisibleSize = MaxSmallObjectHeapObjectSize & ~(PageSize - 1);

        public const int BufferSize = MaxSmallObjectPageDivisibleSize;
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Debug Logging
    //
    ////////////////////////////////////////////////////////////////////////////

    class Logging
    {
        public static readonly bool EnableLogging = true;
        public static int StreamLoggingLengthLimit = Int32.MaxValue;

        private static readonly string LoggingPath = EnableLogging ? Environment.ExpandEnvironmentVariables(@"%TEMP%\BackupOneDrive.log") : null;

        private static bool logEntriesLost;
        private static bool logEntriesLostOne;

        private static TextWriter AcquireWriter(bool append)
        {
            Exception lastException = null;
            for (int retry = 0; retry < 5; retry++)
            {
                if (retry > 0)
                {
                    Random rnd = new Random();
                    Thread.Sleep(100 * (1 << (retry - 1)) + rnd.Next(100));
                }
                try
                {
                    TextWriter writer = new StreamWriter(Logging.LoggingPath, append, Encoding.UTF8);
                    if (logEntriesLostOne)
                    {
                        logEntriesLostOne = false;
                        writer.WriteLine();
                        writer.WriteLine();
                        writer.WriteLine("*** SOME LOG ENTRIES LOST ***");
                        writer.WriteLine();
                        writer.WriteLine();
                    }
                    return writer;
                }
                catch (IOException exception)
                {
                    lastException = exception;
                }
            }
            //throw lastException;
            logEntriesLostOne = logEntriesLost = true;
            return null;
        }

        public static void InitializeLog()
        {
            if (EnableLogging)
            {
                using (TextWriter writer = AcquireWriter(false/*append*/))
                {
                }
            }
        }

        public static void WriteLine()
        {
            if (EnableLogging)
            {
                using (TextWriter writer = AcquireWriter(true/*append*/))
                {
                    if (writer != null)
                    {
                        writer.WriteLine();
                    }
                }
            }
        }

        public static void WriteLine(string value)
        {
            if (EnableLogging)
            {
                using (TextWriter writer = AcquireWriter(true/*append*/))
                {
                    if (writer != null)
                    {
                        writer.WriteLine(value);
                    }
                }
            }
        }

        public static void WriteLine(string format, params object[] arg)
        {
            if (EnableLogging)
            {
                using (TextWriter writer = AcquireWriter(true/*append*/))
                {
                    if (writer != null)
                    {
                        writer.WriteLine(format, arg);
                    }
                }
            }
        }

        public static void WriteLineTimestamp()
        {
            if (EnableLogging)
            {
                using (TextWriter writer = AcquireWriter(true/*append*/))
                {
                    if (writer != null)
                    {
                        writer.WriteLine("{0}", DateTime.Now);
                    }
                }
            }
        }

        public static string ToString(Stream stream)
        {
            return ToString(stream, false/*omitContent*/);
        }

        public static string ToString(Stream stream, bool omitContent)
        {
            StringBuilder sb = new StringBuilder();
            if (stream == null)
            {
                sb.Append("null");
            }
            else
            {
                sb.AppendFormat("{0}(", typeof(Stream).Name);
                sb.AppendFormat("len={0}, pos={1}", stream.Length, stream.Position);
                if (!omitContent && (stream is MemoryStream))
                {
                    sb.Append(", content=");
                    sb.Append(Encoding.ASCII.GetString(((MemoryStream)stream).ToArray(), 0, Math.Min((int)stream.Length, StreamLoggingLengthLimit)).Replace("\r", " ").Replace("\n", " "));
                }
                sb.Append(")");
            }
            return sb.ToString();
        }
    }



    ////////////////////////////////////////////////////////////////////////////
    //
    // JSON Parsing
    //
    ////////////////////////////////////////////////////////////////////////////

    // TODO: Replace with System.Web.Script.Serialization.JavaScriptSerializer
    // when I move out of the stone age (i.e. to .NET Framework 3.5 or later)
    class JSONDictionary
    {
        private KeyValuePair<string, object>[] items;
        private Dictionary<string, int> dictionary = new Dictionary<string, int>();

        public JSONDictionary(string s)
            : this(Parse(s))
        {
        }

        private JSONDictionary(KeyValuePair<string, object>[] items)
        {
            this.items = (KeyValuePair<string, object>[])items.Clone();
            for (int i = 0; i < this.items.Length; i++)
            {
                dictionary.Add(this.items[i].Key, i); // duplicates forbidden - throws
            }
        }

        public object this[string key]
        {
            get
            {
                return dictionary[key];
            }
        }

        public bool TryGetValue(string key, out object value)
        {
            value = null;
            int i;
            if (!dictionary.TryGetValue(key, out i))
            {
                return false;
            }

            KeyValuePair<string, Object> item = this[i];
            value = item.Value;
            return true;
        }

        public bool TryGetValueAs<T>(string key, out T value)
        {
            value = default(T);
            object o;
            if (!TryGetValue(key, out o))
            {
                return false;
            }
            value = (T)o;
            return true;
        }

        public KeyValuePair<string, object> this[int index]
        {
            get
            {
                KeyValuePair<string, object> result = items[index];
                if (result.Value is KeyValuePair<string, object>[])
                {
                    result = new KeyValuePair<string, object>(result.Key, new JSONDictionary((KeyValuePair<string, object>[])result.Value));
                }
                else if (result.Value is object[])
                {
                    JSONDictionary[] array = new JSONDictionary[((object[])result.Value).Length];
                    for (int i = 0; i < array.Length; i++)
                    {
                        array[i] = new JSONDictionary((KeyValuePair<string, object>[])((object[])result.Value)[i]);
                    }
                    result = new KeyValuePair<string, object>(result.Key, array);
                }
                return result;
            }
        }

        public int Count
        {
            get
            {
                return items.Length;
            }
        }

        public override string ToString()
        {
            throw new NotImplementedException();
        }

        private static string NextToken(string s, ref int i)
        {
            while ((i < s.Length) && Char.IsWhiteSpace(s[i]))
            {
                i++;
            }
            if (i == s.Length)
            {
                return null;
            }
            if (s[i] == '"')
            {
                StringBuilder sb = new StringBuilder();
                sb.Append(s[i]);
                bool escapedQuote;
                do
                {
                    i++;
                    escapedQuote = false;
                    if ((s[i] == '\\') && (s[i + 1] == '"'))
                    {
                        i++;
                        escapedQuote = true;
                    }
                    sb.Append(s[i]);
                } while (escapedQuote || (s[i] != '"'));
                i++;
                return sb.ToString();
            }
            else if (Char.IsLetterOrDigit(s[i]) || (s[i] == '_'))
            {
                StringBuilder sb = new StringBuilder();
                while (Char.IsLetterOrDigit(s[i]) || (s[i] == '_'))
                {
                    sb.Append(s[i]);
                    i++;
                }
                return sb.ToString();
            }
            else if (":{},[]".IndexOf(s[i]) >= 0)
            {
                string r = new String(s[i], 1);
                i++;
                return r;
            }
            else
            {
                throw new InvalidDataException();
            }
        }

        private static KeyValuePair<string, object>[] Parse(string s)
        {
            int i = 0;
            object o = ParseValue(s, ref i);
            Debug.Assert(o is KeyValuePair<string, object>[]);
            return (KeyValuePair<string, object>[])o;
        }

        private static KeyValuePair<string, object>[] ParseGroup(string s, ref int i)
        {
            List<KeyValuePair<string, object>> items = new List<KeyValuePair<string, object>>();

            string t = NextToken(s, ref i);
            if (t == null)
            {
                return items.ToArray();
            }
            if (t != "{")
            {
                throw new InvalidDataException();
            }

            while (true)
            {
                t = NextToken(s, ref i);
                if (t == "}")
                {
                    break;
                }

                if (t[0] == '"')
                {
                    string key = t.Substring(1, t.Length - 2);

                    t = NextToken(s, ref i);
                    if (t != ":")
                    {
                        throw new InvalidDataException();
                    }

                    object value = ParseValue(s, ref i);
                    items.Add(new KeyValuePair<string, object>(key, value));

                    int oldi = i;
                    t = NextToken(s, ref i);
                    if (t == "}")
                    {
                        i = oldi; // unget
                    }
                    else if (t == ",")
                    {
                    }
                    else
                    {
                        throw new InvalidDataException();
                    }
                }
                else
                {
                    throw new InvalidDataException();
                }
            }

            return items.ToArray();
        }

        private static object[] ParseArray(string s, ref int i)
        {
            List<object> items = new List<object>();

            string t = NextToken(s, ref i);
            if (t != "[")
            {
                throw new InvalidDataException();
            }

            while (true)
            {
                int oldi = i;
                t = NextToken(s, ref i);
                if (t == "]")
                {
                    break;
                }
                if (t == ",")
                {
                    continue;
                }

                i = oldi; // unget
                object value = ParseValue(s, ref i);
                items.Add(value);
            }

            return items.ToArray();
        }

        private static object ParseValue(string s, ref int i)
        {
            int oldi = i;
            string t = NextToken(s, ref i);

            long l;
            if (t == "{")
            {
                i = oldi; // unget
                return ParseGroup(s, ref i);
            }
            else if (t == "[")
            {
                i = oldi; // unget
                return ParseArray(s, ref i);
            }
            else if (t.StartsWith("\""))
            {
                return t.Substring(1, t.Length - 2);
            }
            else if (t == "true")
            {
                return true;
            }
            else if (t == "false")
            {
                return false;
            }
            else if (Int64.TryParse(t, out l))
            {
                return l;
            }
            else
            {
                throw new InvalidDataException();
            }
        }

        private static void Dump(JSONDictionary json, int indent, TextWriter writer)
        {
            for (int i = 0; i < json.Count; i++)
            {
                KeyValuePair<string, object> item = json[i];
                const int Spaces = 4;
                string spacer = new String(' ', indent * Spaces);
                writer.WriteLine("{0}{1}: {2}", spacer, item.Key, !(item.Value is JSONDictionary || item.Value is JSONDictionary[]) ? (item.Value != null ? item.Value : "<null>") : String.Empty);
                if (item.Value is JSONDictionary)
                {
                    Dump((JSONDictionary)item.Value, indent + 1, writer);
                }
                else if (item.Value is JSONDictionary[])
                {
                    writer.WriteLine("{0}[", spacer);
                    foreach (JSONDictionary o in (JSONDictionary[])item.Value)
                    {
                        if (o is JSONDictionary)
                        {
                            Dump((JSONDictionary)o, indent + 1, writer);
                            writer.WriteLine("{0},", spacer);
                        }
                        else
                        {
                            writer.WriteLine("{0}{1},", spacer, o);
                        }
                    }
                    writer.WriteLine("{0}]", spacer);
                }
            }
        }

        internal void Dump(TextWriter writer)
        {
            Dump(this, 0, writer);
        }
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Windows Protected Storage (DPAPI)
    //
    ////////////////////////////////////////////////////////////////////////////

    // There is a copy of this in the RemoteDriveAuth project
    static class ProtectedDataStorage
    {
        // http://www.pinvoke.net/default.aspx/crypt32/CryptProtectData.html
        // http://msdn.microsoft.com/en-us/library/ms995355.aspx

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;

            internal byte[] GetData()
            {
                byte[] data = new byte[cbData];
                if (pbData != IntPtr.Zero)
                {
                    Marshal.Copy(pbData, data, 0, cbData);
                }
                return data;
            }

            internal void SetData(byte[] data, int index, int count)
            {
                if (pbData != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pbData);
                    pbData = IntPtr.Zero;
                }

                cbData = count;
                pbData = Marshal.AllocHGlobal(count);
                Marshal.Copy(data, index, pbData, count);
            }

            internal void Clear()
            {
                if (pbData != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pbData);
                    pbData = IntPtr.Zero;
                }
            }
        }

        [Flags]
        private enum CryptProtectFlags
        {
            // for remote-access situations where ui is not an option
            // if UI was specified on protect or unprotect operation, the call
            // will fail and GetLastError() will indicate ERROR_PASSWORD_RESTRICTION
            CRYPTPROTECT_UI_FORBIDDEN = 0x1,

            // per machine protected data -- any user on machine where CryptProtectData
            // took place may CryptUnprotectData
            CRYPTPROTECT_LOCAL_MACHINE = 0x4,

            // force credential synchronize during CryptProtectData()
            // Synchronize is only operation that occurs during this operation
            CRYPTPROTECT_CRED_SYNC = 0x8,

            // Generate an Audit on protect and unprotect operations
            CRYPTPROTECT_AUDIT = 0x10,

            // Protect data with a non-recoverable key
            CRYPTPROTECT_NO_RECOVERY = 0x20,

            // Verify the protection of a protected blob
            CRYPTPROTECT_VERIFY_PROTECTION = 0x40
        }

        [Flags]
        private enum CryptProtectPromptFlags
        {
            // prompt on unprotect
            CRYPTPROTECT_PROMPT_ON_UNPROTECT = 0x1,

            // prompt on protect
            CRYPTPROTECT_PROMPT_ON_PROTECT = 0x2
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CRYPTPROTECT_PROMPTSTRUCT
        {
            public int cbSize;
            public CryptProtectPromptFlags dwPromptFlags;
            public IntPtr hwndApp;
            public String szPrompt;
        }

        [DllImport("Crypt32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptProtectData(
            ref DATA_BLOB pDataIn,
            String szDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            CryptProtectFlags dwFlags,
            ref DATA_BLOB pDataOut);

        [DllImport("Crypt32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn,
            StringBuilder szDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            CryptProtectFlags dwFlags,
            ref DATA_BLOB pDataOut);

        internal static byte[] Encrypt(byte[] plaintext, int index, int count, byte[] secondaryEntropy)
        {
            byte[] encrypted;
            DATA_BLOB savedPlaintext = new DATA_BLOB();
            savedPlaintext.SetData(plaintext, index, count);
            DATA_BLOB entropyOptional = new DATA_BLOB();
            entropyOptional.SetData(secondaryEntropy, 0, secondaryEntropy.Length);
            CRYPTPROTECT_PROMPTSTRUCT promptStruct = new CRYPTPROTECT_PROMPTSTRUCT();
            DATA_BLOB savedProtected = new DATA_BLOB();
            if (!CryptProtectData(ref savedPlaintext, null, ref entropyOptional, IntPtr.Zero, ref promptStruct, CryptProtectFlags.CRYPTPROTECT_UI_FORBIDDEN, ref savedProtected))
            {
                throw new ApplicationException("CryptProtectData failed");
            }
            encrypted = savedProtected.GetData();
            savedPlaintext.Clear();
            entropyOptional.Clear();
            savedProtected.Clear();
            return encrypted;
        }

        internal static byte[] Decrypt(byte[] encrypted, int index, int count, byte[] secondaryEntropy)
        {
            byte[] plaintext;
            DATA_BLOB savedProtected = new DATA_BLOB();
            savedProtected.SetData(encrypted, index, count);
            DATA_BLOB entropyOptional = new DATA_BLOB();
            entropyOptional.SetData(secondaryEntropy, 0, secondaryEntropy.Length);
            CRYPTPROTECT_PROMPTSTRUCT promptStruct = new CRYPTPROTECT_PROMPTSTRUCT();
            DATA_BLOB savedPlaintext = new DATA_BLOB();
            if (!CryptUnprotectData(ref savedProtected, null, ref entropyOptional, IntPtr.Zero, ref promptStruct, CryptProtectFlags.CRYPTPROTECT_UI_FORBIDDEN, ref savedPlaintext))
            {
                throw new ApplicationException("CryptUnprotectData failed");
            }
            plaintext = savedPlaintext.GetData();
            savedProtected.Clear();
            entropyOptional.Clear();
            savedPlaintext.Clear();
            return plaintext;
        }
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Resource Owner Authentication
    //
    ////////////////////////////////////////////////////////////////////////////

    class RemoteAccessControl : IDisposable
    {
        private RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

        private readonly string remoteServiceUrl;

        private readonly bool enableRefreshToken;
        private readonly string refreshTokenPath;

        private string accessToken; // null if not initialized or invalidated
        private const int TokenExpirationGracePeriodSeconds = 60;
        private DateTime accessTokenExpiry;
        private string refreshToken; // null if not enabled
        private string userId;

        // All accesses are through critical section to prevent multiple re-authorizations
        // from occurring simultaneously if access token has expired.

        private RemoteAccessControl()
        {
            throw new NotSupportedException();
        }

        public RemoteAccessControl(string remoteServiceUrl, bool enableRefreshToken, string refreshTokenPath)
        {
            lock (this)
            {
                this.remoteServiceUrl = remoteServiceUrl;

                this.enableRefreshToken = enableRefreshToken;
                this.refreshTokenPath = refreshTokenPath;

                Authenticate();
            }
        }

        public void Dispose()
        {
            lock (this)
            {
                accessToken = null;
                refreshToken = null;
                userId = null;
                rng = null;
            }
        }

        public string AccessToken
        {
            get
            {
                lock (this)
                {
                    if (DateTime.Now >= accessTokenExpiry)
                    {
                        if (Logging.EnableLogging)
                        {
                            Logging.WriteLine("[access token expiring]");
                        }
                        InvalidateAccessToken();
                    }

                    if (accessToken == null)
                    {
                        Authenticate();
                    }

                    return accessToken;
                }
            }
        }

        public bool AccessTokenExpirationImminant
        {
            get
            {
                lock (this)
                {
                    return (DateTime.Now >= accessTokenExpiry);
                }
            }
        }

        public void InvalidateAccessToken()
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLineTimestamp();
                Logging.WriteLine("*InvalidateAccessToken()");
            }

            lock (this)
            {
                accessToken = null;
                accessTokenExpiry = DateTime.MinValue;
            }
        }

        private const string LoginProgramName = "RemoteDriveAuth.exe";
        private const int SecondaryEntropyLengthBytes = 256 / 8;
        private void Authenticate()
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+RemoteAccessControl.Authenticate()");
                Logging.WriteLineTimestamp();
            }

            RecoverSavedRefreshToken();

            byte[] secondaryEntropy = new byte[SecondaryEntropyLengthBytes];
            rng.GetBytes(secondaryEntropy);

            string arg0 = "-auth";
            string arg1 = Core.HexEncode(secondaryEntropy);
            string arg2 = String.Format("refresh-token={0}", enableRefreshToken ? "yes" : "no");
            string arg3 = enableRefreshToken && !String.IsNullOrEmpty(refreshToken) ? Core.HexEncodeASCII(refreshToken) : "\"\"";
            string arg4 = remoteServiceUrl;
            string args = String.Concat(arg0, " ", arg1, " ", arg2, " ", arg3, " ", arg4);
            int exitCode;
            string output;
            Exec(LoginProgramName, args, null, null/*timeout*/, out exitCode, out output);
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("call {0} {1} {2} {3} {4} {5}", LoginProgramName, arg0, /*arg1*/"(secondary entropy omitted)", arg2, /*arg3*/(enableRefreshToken && !String.IsNullOrEmpty(refreshToken) ? "(refresh token omitted)" : "\"\""), arg4);
                Logging.WriteLine("exit code: {0}", exitCode);
                Logging.WriteLine("output:");
                Logging.WriteLine(output != null ? output.Trim() : "null");
                Logging.WriteLine();
            }

            if (exitCode != 0)
            {
                if (exitCode == 2)
                {
                    throw new ApplicationException(String.Format("Authentication to remote service failed with message: {0}", output));
                }
                throw new ApplicationException(String.Format("Unable to authenticate to remote service \"{0}\"", remoteServiceUrl));
            }

            string oldRefreshToken = refreshToken;

            byte[] outputBytes = Core.HexDecode(output.Trim());
            byte[] decryptedOutput = ProtectedDataStorage.Decrypt(outputBytes, 0, outputBytes.Length, secondaryEntropy);
            JSONDictionary tokenJSON = new JSONDictionary(Encoding.ASCII.GetString(decryptedOutput));
            string token_type, scope;
            long expires_in;
            if (!tokenJSON.TryGetValueAs("token_type", out token_type)
                || !tokenJSON.TryGetValueAs("expires_in", out expires_in)
                || !tokenJSON.TryGetValueAs("access_token", out accessToken))
            {
                throw new InvalidDataException(String.Format("Unable to authenticate to remote service \"{0}\"", remoteServiceUrl));
            }
            tokenJSON.TryGetValueAs("scope", out scope); // not needed - in any case only returned by Microsoft, not returned by Google
            tokenJSON.TryGetValueAs("refresh_token", out refreshToken); // may be absent (--> null)
            tokenJSON.TryGetValueAs("user_id", out userId); // not needed
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("Acquired tokens:");
                Logging.WriteLine("  access_token={0}", !String.IsNullOrEmpty(accessToken) ? "(omitted)" : "no");
                Logging.WriteLine("  refresh_token={0}", !String.IsNullOrEmpty(refreshToken) ? "(omitted)" : "no");
                Logging.WriteLine("  user_id={0}", !String.IsNullOrEmpty(userId) ? "(omitted)" : "no");
                Logging.WriteLine("  other: token_type={0}, expires_in={1}, scope=\"{2}\"", token_type, expires_in, scope);
                Logging.WriteLine();
            }
            if (!token_type.Equals("bearer", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("token_type");
            }
            // subtract a grace period from expiration to force proactive renewal
            accessTokenExpiry = DateTime.Now.AddSeconds(expires_in).AddSeconds(-TokenExpirationGracePeriodSeconds);
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("Token expiration set to: {0}", accessTokenExpiry);
            }

            if (refreshToken == null)
            {
                refreshToken = oldRefreshToken;
            }

            SaveRefeshToken();

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("-RemoteAccessControl.Authenticate");
            }
        }

        private void SaveRefeshToken()
        {
            if (enableRefreshToken && (refreshTokenPath != null))
            {
                using (TextWriter writer = new StreamWriter(refreshTokenPath))
                {
                    if (!String.IsNullOrEmpty(refreshToken))
                    {
                        byte[] secondaryEntropy = new byte[SecondaryEntropyLengthBytes];
                        rng.GetBytes(secondaryEntropy);

                        byte[] decryptedRefreshToken = Encoding.ASCII.GetBytes(refreshToken);
                        byte[] encryptedRefreshToken = ProtectedDataStorage.Encrypt(decryptedRefreshToken, 0, decryptedRefreshToken.Length, secondaryEntropy);

                        writer.WriteLine(Core.HexEncode(secondaryEntropy));
                        writer.WriteLine(Core.HexEncode(encryptedRefreshToken));
                    }
                }
            }
        }

        private void RecoverSavedRefreshToken()
        {
            if (enableRefreshToken && (refreshTokenPath != null) && File.Exists(refreshTokenPath))
            {
                refreshToken = null;

                byte[] secondaryEntropy;
                byte[] refreshTokenEncrypted;
                using (TextReader reader = new StreamReader(refreshTokenPath))
                {
                    string line = reader.ReadLine();
                    if (line == null)
                    {
                        return;
                    }
                    secondaryEntropy = Core.HexDecode(line);

                    line = reader.ReadLine();
                    refreshTokenEncrypted = Core.HexDecode(line);
                }

                byte[] refreshTokenDecrypted = ProtectedDataStorage.Decrypt(refreshTokenEncrypted, 0, refreshTokenEncrypted.Length, secondaryEntropy);
                refreshToken = Encoding.ASCII.GetString(refreshTokenDecrypted);
            }
        }

        private static bool Exec(string program, string arguments, string input, int? commandTimeoutSeconds, out int exitCode, out string output)
        {
            bool killed = false;
            exitCode = 0;
            output = null;

            StringBuilder output2 = new StringBuilder();
            using (StringWriter outputWriter = new StringWriter(output2))
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
            return !killed;
        }
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Microsoft OneDrive Support
    // Google Drive Support
    //
    ////////////////////////////////////////////////////////////////////////////

    class RemoteFileSystemEntry
    {
        public readonly string Id;
        public readonly string Name;
        public readonly bool Folder;
        public readonly DateTime Created;
        public readonly DateTime Modified;
        public readonly long Size;
        private List<RemoteFileSystemEntry> duplicates; // for Google

        public RemoteFileSystemEntry(string id, string name, bool folder, DateTime created, DateTime modified, long size)
        {
            this.Id = id;
            this.Name = name;
            this.Folder = folder;
            this.Created = created;
            this.Modified = modified;
            this.Size = size;
        }

        public override string ToString()
        {
            return String.Format("RemoteFileSystemEntry(id=\"{0}\", name=\"{1}\", folder=\"{2}\"{3})", Id, Name, Folder, Duplicates.Count > 0 ? ", duplicates=" + Duplicates.Count.ToString() : String.Empty);
        }

        public bool HasDuplicates
        {
            get
            {
                return (duplicates != null) && (duplicates.Count > 0);
            }
        }

        public List<RemoteFileSystemEntry> Duplicates
        {
            get
            {
                if (duplicates == null)
                {
                    duplicates = new List<RemoteFileSystemEntry>(1);
                }
                return duplicates;
            }
        }
    }

    interface IWebMethods
    {
        RemoteFileSystemEntry[] RemoteGetFileSystemEntries(string folderId);
        RemoteFileSystemEntry NavigateRemotePath(string remotePath, bool includeLast);
        void DownloadFile(string fileId, Stream streamDownloadInto);
        RemoteFileSystemEntry UploadFile(string folderId, string remoteName, Stream streamUploadFrom);
        void DeleteFile(string fileId);
        RemoteFileSystemEntry RenameFile(string fileId, string newName);
    }

    class WebMethodsBase
    {
        private readonly RemoteAccessControl remoteAccessControl;
        private readonly bool enableRestartableUploads;
        private readonly bool? UseCustomHttpImplementation = null;

        private const string UserAgent = "Backup (CryptSikyur-Archiver) v0 [github.com/programmatom/CryptSikyur-Archiver]";

        protected WebMethodsBase(RemoteAccessControl remoteAccessControl, bool enableRestartableUploads)
        {
            this.remoteAccessControl = remoteAccessControl;
            this.enableRestartableUploads = enableRestartableUploads;
        }

        private static string StreamReadLine(Stream stream)
        {
            StringBuilder sb = new StringBuilder();
            byte[] buffer = new byte[1];
            int read;
            while ((read = stream.Read(buffer, 0, 1)) > 0)
            {
                sb.Append((char)buffer[0]);
                if ((sb.Length >= 2) && (sb[sb.Length - 2] == '\r') && (sb[sb.Length - 1] == '\n'))
                {
                    sb.Length = sb.Length - 2; // remove CR-LF
                    break;
                }
            }
            return sb.ToString();
        }

        private const int SendTimeout = 60 * 1000;
        private const int ReceiveTimeout = 60 * 1000;
        private WebExceptionStatus SocketRequest(Uri uri, IPAddress hostAddress, bool twoStageRequest, byte[] requestHeaderBytes, Stream requestBodySource, out string[] responseHeaders, Stream responseBodyDestination)
        {
            byte[] buffer = new byte[Constants.BufferSize];

            bool useTLS = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);

            responseHeaders = new string[0];

            try
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    socket.Connect(hostAddress, uri.Port);

                    socket.SendTimeout = SendTimeout;
                    socket.ReceiveTimeout = ReceiveTimeout;

                    List<string> headers = new List<string>();
                    using (Stream socketStream = !useTLS ? (Stream)new NetworkStream(socket, false/*ownsSocket*/) : (Stream)new SslStream(new NetworkStream(socket, false/*ownsSocket*/)))
                    {
                        if (useTLS)
                        {
                            SslStream ssl = (SslStream)socketStream;

                            //ssl.AuthenticateAsClient(uri.Host, new X509Certificate2Collection(clientCertificate), SslProtocols.Default, true/*checkCertificateRevocation*/);
                            ssl.AuthenticateAsClient(uri.Host);

                            if (!ssl.IsAuthenticated || !ssl.IsEncrypted || !ssl.IsSigned/* || !(ssl.SslProtocol >= SslProtocols.Tls)*/)
                            {
                                throw new ApplicationException("TLS Unsecure");
                            }
                        }


                        // write request header

                        socketStream.Write(requestHeaderBytes, 0, requestHeaderBytes.Length);

                        // wait for 100-continue if two-stage request in use

                        if (twoStageRequest)
                        {
                            string line2;
                            List<string> headers2 = new List<string>();
                            while (!String.IsNullOrEmpty(line2 = StreamReadLine(socketStream)))
                            {
                                headers2.Add(line2);
                            }
                            string[] line2Parts;
                            int code;
                            if ((headers2.Count < 1)
                                || String.IsNullOrEmpty(headers2[0])
                                || ((line2Parts = headers2[0].Split(new char[] { ' ' })).Length < 2)
                                || (!line2Parts[0].StartsWith("HTTP"))
                                || !Int32.TryParse(line2Parts[1], out code)
                                || (code != 100))
                            {
                                return WebExceptionStatus.ServerProtocolViolation;
                            }
                        }


                        // write request body

                        if (requestBodySource != null)
                        {
                            const int MaxBytesPerWebRequest = 30 * 1024 * 1024;
                            const int UpdateIntervalSeconds = 5;

                            DateTime lastDisplay = DateTime.Now;
                            long requestBytesSent = 0;
                            int read;
                            while ((read = requestBodySource.Read(buffer, 0, buffer.Length)) != 0)
                            {
                                socketStream.Write(buffer, 0, read);
                                requestBytesSent += read;

                                if ((DateTime.Now - lastDisplay).TotalSeconds >= UpdateIntervalSeconds)
                                {
                                    Console.Write("{0}%  ", requestBodySource.Position * 100 / requestBodySource.Length);
                                    Console.CursorLeft = 0;
                                    lastDisplay = DateTime.Now;

                                    if (enableRestartableUploads)
                                    {
                                        if (remoteAccessControl.AccessTokenExpirationImminant)
                                        {
                                            remoteAccessControl.InvalidateAccessToken();
                                            return WebExceptionStatus.ReceiveFailure;
                                        }
                                        if (requestBytesSent > MaxBytesPerWebRequest)
                                        {
                                            return WebExceptionStatus.ReceiveFailure;
                                        }
                                    }
                                }
                            }
                        }


                        // read response header and body

                        long contentLength = responseBodyDestination != null ? Int64.MaxValue : 0;
                        bool chunked = false;

                        string line;
                        while (!String.IsNullOrEmpty(line = StreamReadLine(socketStream)))
                        {
                            headers.Add(line);

                            const string ContentLengthHeaderPrefix = "Content-Length:";
                            if (line.StartsWith(ContentLengthHeaderPrefix, StringComparison.OrdinalIgnoreCase))
                            {
                                contentLength = Int64.Parse(line.Substring(ContentLengthHeaderPrefix.Length).Trim());
                            }
                            const string TransferEncodingHeaderPrefix = "Transfer-Encoding:";
                            if (line.StartsWith(TransferEncodingHeaderPrefix, StringComparison.OrdinalIgnoreCase))
                            {
                                string transferEncoding = line.Substring(TransferEncodingHeaderPrefix.Length).Trim();
                                chunked = transferEncoding.Equals("chunked");
                            }
                        }
                        responseHeaders = headers.ToArray();

                        long responseBodyTotalRead = 0;
                        int chunkRemaining = 0;
                        while (responseBodyTotalRead < contentLength)
                        {
                            long needed = contentLength - responseBodyTotalRead;
                            if (chunked)
                            {
                                if (chunkRemaining == 0)
                                {
                                SkipEmbeddedHeader:
                                    if (responseBodyTotalRead > 0)
                                    {
                                        string s = StreamReadLine(socketStream);
                                        if (!String.IsNullOrEmpty(s))
                                        {
                                            return WebExceptionStatus.ServerProtocolViolation;
                                        }
                                    }
                                    string hex = StreamReadLine(socketStream);
                                    if (0 <= hex.IndexOf(':'))
                                    {
                                        goto SkipEmbeddedHeader;
                                    }
                                    hex = hex.Trim();
                                    chunkRemaining = 0;
                                    foreach (char c in hex)
                                    {
                                        int value = "0123456789abcdef".IndexOf(Char.ToLower(c));
                                        if (value < 0)
                                        {
                                            return WebExceptionStatus.ServerProtocolViolation;
                                        }
                                        chunkRemaining = (chunkRemaining << 4) + value;
                                    }
                                    if (chunkRemaining == 0)
                                    {
                                        contentLength = responseBodyTotalRead;
                                    }
                                }

                                needed = Math.Min(needed, chunkRemaining);
                            }

                            needed = Math.Min(buffer.Length, needed);
                            Debug.Assert(needed >= 0);
                            int read = socketStream.Read(buffer, 0, (int)needed);
                            responseBodyDestination.Write(buffer, 0, read);
                            chunkRemaining -= read;
                            responseBodyTotalRead += read;
                        }
                    }
                }
            }
            catch (IOException exception)
            {
                if (Logging.EnableLogging)
                {
                    Logging.WriteLine("Exception: {0}", exception);
                }
                return WebExceptionStatus.ReceiveFailure;
            }

            return WebExceptionStatus.Success;
        }

        private static string[] ForbiddenHeaders = new string[] { "Accept-Encoding", "Content-Length", "Expect", "Connection" };
        private WebExceptionStatus SocketHttpRequest(Uri uri, IPAddress hostAddress, string verb, KeyValuePair<string, string>[] requestHeaders, Stream requestBodySource, out HttpStatusCode httpStatus, out KeyValuePair<string, string>[] responseHeaders, Stream responseBodyDestination, out string finalUrl)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+SocketHttpRequest(url={0}, hostAddress={1}, verb={2}, request-body={3}, response-body={4})", uri, hostAddress, verb, Logging.ToString(requestBodySource), Logging.ToString(responseBodyDestination, true/*omitContent*/));
            }

            foreach (string forbiddenHeader in ForbiddenHeaders)
            {
                if (Array.FindIndex(requestHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, forbiddenHeader); }) >= 0)
                {
                    throw new ArgumentException();
                }
            }

            int redirectCount = 0;
            const int MaxRedirects = 15;
            finalUrl = null;

            const int MaxOneStagePutBodyLength = 5 * 1024 * 1024;
            bool twoStageRequest = (verb == "PUT") && (requestBodySource != null) && (requestBodySource.Length > MaxOneStagePutBodyLength);

        Restart:
            if (!uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
                && !uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException();
            }

            httpStatus = (HttpStatusCode)0;
            responseHeaders = new KeyValuePair<string, string>[0];

            byte[] requestHeaderBytes;
            using (MemoryStream stream = new MemoryStream())
            {
                using (TextWriter writer = new StreamWriter(stream))
                {
                    writer.WriteLine("{0} {1} HTTP/1.1", verb, uri.PathAndQuery);
                    writer.WriteLine("Host: {0}", uri.Host);
                    foreach (KeyValuePair<string, string> header in requestHeaders)
                    {
                        writer.WriteLine("{0}: {1}", header.Key, header.Value);
                    }
                    writer.WriteLine("Accept-Encoding: gzip, deflate");
                    // Is there any harm in always writing Content-Length header?
                    writer.WriteLine("Content-Length: {0}", (requestBodySource != null) && (requestBodySource.Length > requestBodySource.Position) ? requestBodySource.Length - requestBodySource.Position : 0);
                    if (twoStageRequest)
                    {
                        writer.WriteLine("Expect: 100-continue");
                    }
                    writer.WriteLine("Connection: keep-alive"); // HTTP 1.0 superstition
                    writer.WriteLine();
                }
                requestHeaderBytes = stream.ToArray();
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("Request headers:");
                Logging.WriteLine(Encoding.ASCII.GetString(requestHeaderBytes));
            }


            string[] responseHeadersLines;
            long responseBodyDestinationStart = (responseBodyDestination != null) ? responseBodyDestination.Position : 0;
            WebExceptionStatus result = SocketRequest(uri, hostAddress, twoStageRequest, requestHeaderBytes, requestBodySource, out responseHeadersLines, responseBodyDestination);
            long responseBodyDestinationEnd = (responseBodyDestination != null) ? responseBodyDestination.Position : 0;
            long responseBodyBytesReceived = responseBodyDestinationEnd - responseBodyDestinationStart;

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("Socket request result: {0} ({1})", (int)result, result);
                Logging.WriteLine("Response headers:");
                foreach (string s in responseHeadersLines)
                {
                    Logging.WriteLine(s);
                }
            }


            if (responseHeadersLines.Length < 1)
            {
                result = WebExceptionStatus.ServerProtocolViolation;
                goto Exit;
            }

            string[] parts = responseHeadersLines[0].Split(new char[] { (char)32 });
            if ((parts.Length < 2)
                || (!parts[0].Equals("HTTP/1.1") && !parts[0].Equals("HTTP/1.0")))
            {
                result = WebExceptionStatus.ServerProtocolViolation;
                goto Exit;
            }
            httpStatus = (HttpStatusCode)Int32.Parse(parts[1]);
            {
                List<KeyValuePair<string, string>> responseHeadersList = new List<KeyValuePair<string, string>>(responseHeadersLines.Length);
                for (int i = 1; i < responseHeadersLines.Length; i++)
                {
                    int marker = responseHeadersLines[i].IndexOf(':');
                    if (marker < 0)
                    {
                        throw new InvalidDataException();
                    }
                    string key = responseHeadersLines[i].Substring(0, marker);
                    string value = responseHeadersLines[i].Substring(marker + 1).Trim();
                    responseHeadersList.Add(new KeyValuePair<string, string>(key, value));
                }
                responseHeaders = responseHeadersList.ToArray();
            }

            int contentLengthHeaderIndex = Array.FindIndex(responseHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, "Content-Length"); });
            if (contentLengthHeaderIndex >= 0)
            {
                long contentLengthExpected;
                if (!Int64.TryParse(responseHeaders[contentLengthHeaderIndex].Value, out contentLengthExpected))
                {
                    return WebExceptionStatus.ServerProtocolViolation;
                }
                if (contentLengthExpected != responseBodyBytesReceived)
                {
                    if (result == WebExceptionStatus.Success)
                    {
                        result = WebExceptionStatus.ReceiveFailure;
                    }
                }
            }

            int contentEncodingHeaderIndex = Array.FindIndex(responseHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, "Content-Encoding"); });
            if (contentEncodingHeaderIndex >= 0)
            {
                bool gzip = responseHeaders[contentEncodingHeaderIndex].Value.Equals("gzip", StringComparison.OrdinalIgnoreCase);
                bool deflate = responseHeaders[contentEncodingHeaderIndex].Value.Equals("deflate", StringComparison.OrdinalIgnoreCase);
                if (!gzip && !deflate)
                {
                    throw new NotSupportedException(String.Format("Content-Encoding: {0}", responseHeaders[contentLengthHeaderIndex].Value));
                }

                byte[] buffer = new byte[Constants.BufferSize];

                string tempPath = Path.GetTempFileName();
                using (Stream tempStream = new FileStream(tempPath, FileMode.Create, FileAccess.ReadWrite, FileShare.Read))
                {
                    responseBodyDestination.Position = responseBodyDestinationStart;

                    while (responseBodyDestinationEnd > responseBodyDestination.Position)
                    {
                        int needed = (int)Math.Min(buffer.Length, responseBodyDestinationEnd - responseBodyDestination.Position);
                        int read;
                        read = responseBodyDestination.Read(buffer, 0, needed);
                        tempStream.Write(buffer, 0, read);
                    }

                    tempStream.Position = 0;

                    responseBodyDestination.Position = responseBodyDestinationStart;
                    responseBodyDestination.SetLength(responseBodyDestinationStart);

                    using (Stream inputStream = gzip ? (Stream)new GZipStream(tempStream, CompressionMode.Decompress) : (Stream)new DeflateStream(tempStream, CompressionMode.Decompress))
                    {
                        int read;
                        while ((read = inputStream.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            responseBodyDestination.Write(buffer, 0, read);
                        }
                    }

                    responseBodyDestinationEnd = responseBodyDestination.Position;
                    responseBodyBytesReceived = responseBodyDestinationEnd - responseBodyDestinationStart;

                    if (contentLengthHeaderIndex >= 0)
                    {
                        responseHeaders[contentLengthHeaderIndex] = new KeyValuePair<string, string>("Content-Length", responseBodyBytesReceived.ToString());
                    }
                }
                File.Delete(tempPath);

                responseHeaders[contentEncodingHeaderIndex] = new KeyValuePair<string, string>();
            }

            int locationHeaderIndex = -1;
            if (((httpStatus >= (HttpStatusCode)300) && (httpStatus <= (HttpStatusCode)307))
                && ((locationHeaderIndex = Array.FindIndex(responseHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, "Location"); })) >= 0))
            {
                if (Logging.EnableLogging)
                {
                    if (Array.FindAll(responseHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, "Location"); }).Length > 1)
                    {
                        Logging.WriteLine(" NOTICE: multiple Location response headers present - using first one (http status was {0} {1})", (int)httpStatus, httpStatus);
                    }
                }

                redirectCount++;
                if (redirectCount > MaxRedirects)
                {
                    result = WebExceptionStatus.UnknownError;
                    goto Exit;
                }
                string location = responseHeaders[locationHeaderIndex].Value;
                if (location.StartsWith("/"))
                {
                    uri = new Uri(uri, location);
                }
                else
                {
                    uri = new Uri(location);
                }
                goto Restart;
            }


            finalUrl = uri.ToString();

        Exit:
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("-SocketHttpRequest returns {0} ({1})", (int)result, result);
            }
            return result;
        }

        private static bool DNSLookupName(string hostName, out IPAddress hostAddress)
        {
            hostAddress = null;
            IPHostEntry hostInfo = Dns.GetHostEntry(hostName);
            if (hostInfo.AddressList.Length < 1)
            {
                return false;
            }
            hostAddress = hostInfo.AddressList[0];
            return true;
        }

        // Throws exceptions for program defects and unrecoverable errors
        // Returns false + (WebExceptionStatus, HttpStatusCode) for potentially recoverable errors
        private static readonly string[] SupportedVerbs = new string[] { "GET", "PUT", "POST", "DELETE", "PATCH" };
        private static readonly string[] ForbiddenRequestHeaders = new string[] { "Host", "Content-Length", "Accept-Encoding", "Expect", "Authorization" };
        protected bool DoWebAction(string url, string verb, Stream requestBodySource, Stream responseBodyDestination, KeyValuePair<string, string>[] requestHeaders, KeyValuePair<string, string>[] responseHeadersOut, out WebExceptionStatus webStatusCodeOut, out HttpStatusCode httpStatusCodeOut)
        {
            bool useCustomHttpImplementation = UseCustomHttpImplementation.HasValue ? UseCustomHttpImplementation.Value : ((DateTime.Now.Minute % 5) % 2 != 0); // how'd-ya like dem apples?

            if (requestHeaders == null)
            {
                requestHeaders = new KeyValuePair<string, string>[0];
            }
            if (responseHeadersOut == null)
            {
                responseHeadersOut = new KeyValuePair<string, string>[0];
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+DoWebAction(url={0}, verb={1}, request-body={2}, response-body={3})", url, verb, Logging.ToString(requestBodySource), responseBodyDestination != null ? "yes" : "no");
            }

            foreach (KeyValuePair<string, string> header in requestHeaders)
            {
                if (Array.IndexOf(ForbiddenRequestHeaders, header.Key) >= 0)
                {
                    throw new ArgumentException();
                }
            }

            bool hasRequestBody = (requestBodySource != null) && (requestBodySource.Length > 0);
            if (hasRequestBody && (requestBodySource.Position != 0))
            {
                // not empty or not at beginning of stream - is that what caller intended?

                int contentRangeHeaderIndex = Array.FindIndex(requestHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, "Content-Range"); });
                if (contentRangeHeaderIndex < 0)
                {
                    throw new InvalidOperationException();
                }
                string contentRangeHeader = requestHeaders[contentRangeHeaderIndex].Value;
                const string BytesPrefix = "bytes ";
                if (!contentRangeHeader.StartsWith(BytesPrefix))
                {
                    throw new InvalidOperationException();
                }
                string[] parts = contentRangeHeader.Substring(BytesPrefix.Length).Split(new char[] { '-', '/' });
                if (parts.Length != 3)
                {
                    throw new InvalidOperationException();
                }
                long startPosition = Int64.Parse(parts[0]);
                long endPositionInclusive = Int64.Parse(parts[1]);
                long length = Int64.Parse(parts[2]);
                if (length != endPositionInclusive + 1)
                {
                    throw new InvalidOperationException();
                }
                if ((startPosition != requestBodySource.Position)
                    || (length != requestBodySource.Length))
                {
                    throw new InvalidOperationException();
                }
            }
            bool wantsResponseBody = (responseBodyDestination != null);
            if (wantsResponseBody && ((responseBodyDestination.Length != 0) || (responseBodyDestination.Position != 0)))
            {
                // not empty or not at beginning of stream - is that what caller intended?

                if (responseBodyDestination.Length != responseBodyDestination.Position)
                {
                    throw new InvalidOperationException();
                }

                int rangeHeaderIndex = Array.FindIndex(requestHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, "Range"); });
                if (rangeHeaderIndex < 0)
                {
                    throw new InvalidOperationException();
                }
                string rangeHeader = requestHeaders[rangeHeaderIndex].Value;
                const string BytesPrefix = "bytes=";
                if (!rangeHeader.StartsWith(BytesPrefix))
                {
                    throw new InvalidOperationException();
                }
                string[] parts = rangeHeader.Substring(BytesPrefix.Length).Split(new char[] { '-' });
                if (parts.Length != 2)
                {
                    throw new InvalidOperationException();
                }
                long startPosition = Int64.Parse(parts[0]);
                long endPositionInclusive = Int64.Parse(parts[1]);
                if (responseBodyDestination.Length != startPosition)
                {
                    throw new InvalidOperationException();
                }
            }
            if (Array.IndexOf(SupportedVerbs, verb) < 0)
            {
                throw new ArgumentException();
            }
            if (wantsResponseBody && ((verb != "GET") && (verb != "PUT") && (verb != "PATCH")))
            {
                throw new ArgumentException();
            }
            if (hasRequestBody && ((verb != "PUT") && (verb != "POST") && (verb != "PATCH")))
            {
                throw new ArgumentException();
            }

            bool accessDeniedRetried = false;
        RetryForAccessDenied:
            WebExceptionStatus webStatusCode = WebExceptionStatus.UnknownError;
            HttpStatusCode httpStatusCode = (HttpStatusCode)0;


            if (useCustomHttpImplementation)
            {
                // My own HTTP request-making code


                Uri uri = new Uri(url);
                IPAddress hostAddress;
                DNSLookupName(uri.Host, out hostAddress);

                // generally, headers in ForbiddenRequestHeaders[] are managed by SocketHttpRequest
                Dictionary<string, bool> requestHeadersSeen = new Dictionary<string, bool>();
                List<KeyValuePair<string, string>> requestHeadersList = new List<KeyValuePair<string, string>>();
                requestHeadersList.Add(new KeyValuePair<string, string>("Authorization", String.Format("{0} {1}", "Bearer", remoteAccessControl.AccessToken)));
                foreach (KeyValuePair<string, string> header in requestHeaders)
                {
                    Debug.Assert(Array.IndexOf(ForbiddenHeaders, header.Key) < 0);
                    requestHeadersList.Add(header);
                    requestHeadersSeen[header.Key] = true;
                }
                if (!requestHeadersSeen.ContainsKey("Accept"))
                {
                    requestHeadersList.Add(new KeyValuePair<string, string>("Accept", "*/*"));
                }
                if (!requestHeadersSeen.ContainsKey("User-Agent"))
                {
                    requestHeadersList.Add(new KeyValuePair<string, string>("User-Agent", UserAgent));
                }
                // omitted: Accept-Language - is there any need for it in this application?

                KeyValuePair<string, string>[] responseHeaders;
                string finalUrl;
                webStatusCode = SocketHttpRequest(uri, hostAddress, verb, requestHeadersList.ToArray(), requestBodySource, out httpStatusCode, out responseHeaders, responseBodyDestination, out finalUrl);

                for (int i = 0; i < responseHeadersOut.Length; i++)
                {
                    int index = Array.FindIndex(responseHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, responseHeadersOut[i].Key); });
                    if (index >= 0)
                    {
                        responseHeadersOut[i] = new KeyValuePair<string, string>(responseHeadersOut[i].Key, responseHeaders[index].Value);
                    }
                }

                if ((httpStatusCode == (HttpStatusCode)401) && !accessDeniedRetried)
                {
                    accessDeniedRetried = true;
                    remoteAccessControl.InvalidateAccessToken();
                    goto RetryForAccessDenied;
                }
            }
            else
            {
                // asynchronous .NET HttpWebRequest


                ManualResetEvent finished = new ManualResetEvent(false);
                Exception exception = null;

                long requestBytesTotal = requestBodySource != null ? requestBodySource.Length : 0;
                long requestBytesSentTotal = requestBodySource != null ? requestBodySource.Position : 0;
                long forceFailure = 0;

                AsyncCallback responseAction = delegate(IAsyncResult asyncResult)
                {
                    try
                    {
                        HttpWebRequest request = (HttpWebRequest)asyncResult.AsyncState;
                        using (HttpWebResponse response = (HttpWebResponse)request.EndGetResponse(asyncResult))
                        {
                            for (int i = 0; i < responseHeadersOut.Length; i++)
                            {
                                responseHeadersOut[i] = new KeyValuePair<string, string>(responseHeadersOut[i].Key, response.Headers[responseHeadersOut[i].Key]);
                            }

                            long? responseLengthExpected = null;
                            if (!String.IsNullOrEmpty(response.Headers[HttpResponseHeader.ContentLength]))
                            {
                                if (Logging.EnableLogging)
                                {
                                    Logging.WriteLine(" response Content-Length header={0}", response.Headers[HttpResponseHeader.ContentLength]);
                                }
                                responseLengthExpected = Int64.Parse(response.Headers[HttpResponseHeader.ContentLength]);
                            }

                            long responseLengthActual = 0;
                            if (responseBodyDestination != null)
                            {
                                using (Stream responseStream = response.GetResponseStream())
                                {
                                    byte[] buffer = new byte[Constants.BufferSize];
                                    int read;
                                    while ((read = responseStream.Read(buffer, 0, buffer.Length)) != 0)
                                    {
                                        responseBodyDestination.Write(buffer, 0, read);
                                    }
                                    responseLengthActual = responseBodyDestination.Length;
                                    if (Logging.EnableLogging)
                                    {
                                        Logging.WriteLine(" actual response length={0}", responseLengthActual);
                                    }

                                    if (responseLengthExpected.HasValue && (responseLengthExpected.Value != responseLengthActual))
                                    {
                                        webStatusCode = WebExceptionStatus.ReceiveFailure;
                                        return;
                                    }
                                }
                            }

                            webStatusCode = WebExceptionStatus.Success;
                            httpStatusCode = response.StatusCode;
                        }
                    }
                    catch (Exception localException)
                    {
                        exception = localException;
                    }
                    finally
                    {
                        finished.Set();
                    }
                };

                AsyncCallback requestAction = delegate(IAsyncResult asyncResult)
                {
                    try
                    {
                        HttpWebRequest request = (HttpWebRequest)asyncResult.AsyncState;
                        using (Stream requestStream = request.EndGetRequestStream(asyncResult))
                        {
                            if (requestBodySource != null)
                            {
                                // this permits testing of resumable upload
                                long requestBytesSentThisRequest = 0; // vs. "bytes thus far" over multiple requests of a resumable upload - which would be requestBytesSentTotal
                                const int MaxBytesPerWebRequest = 30 * 1024 * 1024;

                                byte[] buffer = new byte[Constants.BufferSize];
                                int read;
                                while ((read = requestBodySource.Read(buffer, 0, buffer.Length)) != 0)
                                {
                                    requestStream.Write(buffer, 0, read);
                                    Interlocked.Add(ref requestBytesSentTotal, read);
                                    requestBytesSentThisRequest += read;
                                    if (enableRestartableUploads)
                                    {
                                        if ((Interlocked.Read(ref forceFailure) != 0) || (requestBytesSentThisRequest > MaxBytesPerWebRequest))
                                        {
                                            throw new TimeoutException();
                                        }
                                    }
                                }
                            }
                        }
                        request.BeginGetResponse(responseAction, request);
                    }
                    catch (Exception localException)
                    {
                        exception = localException;
                        finished.Set();
                    }
                };

                // Request process begins here
                {
                    HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(url);
                    request.Method = verb;
                    request.UserAgent = UserAgent;

                    // Use of Authorization header is considered better than use of url query parameter
                    // because it avoids the possibility of access tokens being written to server/proxy logs
                    request.Headers["Authorization"] = String.Format("{0} {1}", "Bearer", remoteAccessControl.AccessToken);

                    // Is there any harm in always writing Content-Length header?
                    request.ContentLength = requestBodySource != null ? requestBodySource.Length - requestBodySource.Position : 0;
                    if ((requestBodySource != null) && (requestBodySource.Length >= Constants.BufferSize))
                    {
                        // Turn off .NET in-memory stream buffering if request body is large
                        request.AllowWriteStreamBuffering = false;
                    }

                    foreach (KeyValuePair<string, string> header in requestHeaders)
                    {
                        switch (header.Key)
                        {
                            default:
                                try
                                {
                                    request.Headers[header.Key] = header.Value;
                                }
                                catch (ArgumentException)
                                {
                                    throw;
                                }
                                break;

                            // These headers can't be written with the generic method
                            case "Accept":
                                request.Accept = header.Value;
                                break;
                            case "Content-Type":
                                request.ContentType = header.Value;
                                break;
                            case "Range":
                                {
                                    const string BytesPrefix = "bytes=";
                                    if (!header.Value.StartsWith(BytesPrefix))
                                    {
                                        throw new InvalidOperationException();
                                    }
                                    string[] parts = header.Value.Substring(BytesPrefix.Length).Split(new char[] { '-' });
                                    if (parts.Length != 2)
                                    {
                                        throw new InvalidOperationException();
                                    }
                                    long startPosition = Int64.Parse(parts[0]);
                                    long endPositionInclusive = Int64.Parse(parts[1]);
                                    if ((startPosition > Int32.MaxValue)
                                        || (endPositionInclusive > Int32.MaxValue))
                                    {
                                        throw new OverflowException("HTTP range request can't be done with HttpWebRequest - file range values exceed Int32 capacity");
                                    }

                                    request.AddRange("bytes", (int)startPosition, (int)endPositionInclusive);
                                }
                                break;
                        }
                    }

                    if (hasRequestBody)
                    {
                        request.BeginGetRequestStream(requestAction, request);
                    }
                    else
                    {
                        request.BeginGetResponse(responseAction, request);
                    }
                }

                const int UpdateIntervalSeconds = 5;
                const int MinimumFileSizeForProgress = 1024 * 1024;
                while (!finished.WaitOne(UpdateIntervalSeconds * 1000))
                {
                    if (enableRestartableUploads)
                    {
                        if (remoteAccessControl.AccessTokenExpirationImminant)
                        {
                            remoteAccessControl.InvalidateAccessToken();
                            Interlocked.CompareExchange(ref forceFailure, 1, 0);
                        }
                    }

                    if (requestBytesTotal >= MinimumFileSizeForProgress)
                    {
                        Console.Write("{0}%  ", Interlocked.Read(ref requestBytesSentTotal) * 100 / requestBytesTotal);
                        Console.CursorLeft = 0;
                    }
                }

                if (exception != null)
                {
                    if (Logging.EnableLogging)
                    {
                        Logging.WriteLine(" exception caught during asynchronous processing: {0}", exception);
                    }

                    WebException webException;
                    //IOException ioException;
                    if ((webException = exception as WebException) != null)
                    {
                        webStatusCode = webException.Status;

                        WebResponse response = webException.Response;
                        if (response != null)
                        {
                            HttpWebResponse httpWebResponse;
                            if ((httpWebResponse = response as HttpWebResponse) != null)
                            {
                                // make sure to capture response headers even for exceptions (non-2xx status codes)
                                for (int i = 0; i < responseHeadersOut.Length; i++)
                                {
                                    responseHeadersOut[i] = new KeyValuePair<string, string>(responseHeadersOut[i].Key, response.Headers[responseHeadersOut[i].Key]);
                                }

                                httpStatusCode = httpWebResponse.StatusCode;

                                if (httpStatusCode == HttpStatusCode.Unauthorized)
                                {
                                    if (!accessDeniedRetried)
                                    {
                                        if (Logging.EnableLogging)
                                        {
                                            Logging.WriteLine(" access denied - invalidating access token and trying again");
                                        }

                                        accessDeniedRetried = true;
                                        remoteAccessControl.InvalidateAccessToken();
                                        goto RetryForAccessDenied;
                                    }
                                }
                            }
                        }
                    }
                    //else if ((ioException = exception as IOException) != null)
                    //{
                    //    // anything meaningful to be done here?
                    //}
                    else
                    {
                        webStatusCode = WebExceptionStatus.UnknownError;
                    }

                    goto Error;
                }

            Error:
                ;
            }

            bool result = (webStatusCode == WebExceptionStatus.Success)
                && (((int)httpStatusCode >= 200) && ((int)httpStatusCode <= 299));
            if (Logging.EnableLogging)
            {
                if (responseBodyDestination != null)
                {
                    Logging.WriteLine(" response-body={0}", Logging.ToString(responseBodyDestination));
                }
                Logging.WriteLine("-DoWebAction result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
            }
            webStatusCodeOut = webStatusCode;
            httpStatusCodeOut = httpStatusCode;
            return result;
        }

        protected bool DoWebActionPostForm(string url, string formDataRequestBody, Stream responseBodyDestination, out WebExceptionStatus webStatusCodeOut, out HttpStatusCode httpStatusCodeOut)
        {
            KeyValuePair<string, string>[] requestHeadersExtra = new KeyValuePair<string, string>[]
            {
                new KeyValuePair<string, string>("Content-Type", "application/x-www-form-urlencoded"),
            };

            return DoWebAction(
                url,
                "POST",
                new MemoryStream(Encoding.ASCII.GetBytes(formDataRequestBody)),
                responseBodyDestination,
                requestHeadersExtra,
                null/*extraHeadersOut*/,
                out webStatusCodeOut,
                out httpStatusCodeOut);
        }

        protected bool DoWebActionPostJSON(string url, string jsonRequestBody, Stream responseBodyDestination, KeyValuePair<string, string>[] requestHeaders, KeyValuePair<string, string>[] responseHeadersExtraOut, out WebExceptionStatus webStatusCodeOut, out HttpStatusCode httpStatusCodeOut)
        {
            List<KeyValuePair<string, string>> requestHeadersExtra = new List<KeyValuePair<string, string>>(requestHeaders);
            if (jsonRequestBody != null)
            {
                requestHeadersExtra.Add(new KeyValuePair<string, string>("Content-Type", "application/json; charset=UTF-8"));
            }

            using (Stream requestStream = new MemoryStream(Encoding.UTF8.GetBytes(jsonRequestBody)))
            {
                return DoWebAction(
                    url,
                    "POST",
                    requestStream,
                    responseBodyDestination,
                    requestHeadersExtra.ToArray(),
                    responseHeadersExtraOut,
                    out webStatusCodeOut,
                    out httpStatusCodeOut);
            }
        }

        protected bool DoWebActionJSON2JSON(string url, string verb, string jsonRequestBody, out string jsonResponseBody, out WebExceptionStatus webStatusCodeOut, out HttpStatusCode httpStatusCodeOut)
        {
            List<KeyValuePair<string, string>> requestHeadersExtra = new List<KeyValuePair<string, string>>(1);
            if (!String.IsNullOrEmpty(jsonRequestBody))
            {
                requestHeadersExtra.Add(new KeyValuePair<string, string>("Content-Type", "application/json; charset=UTF-8"));
            }
            KeyValuePair<string, string>[] responseHeadersExtra = new KeyValuePair<string, string>[]
            {
                new KeyValuePair<string, string>("Content-Type", null),
            };

            using (Stream requestStream = new MemoryStream(jsonRequestBody != null ? Encoding.UTF8.GetBytes(jsonRequestBody) : new byte[0]))
            {
                using (MemoryStream responseStream = new MemoryStream())
                {
                    bool result = DoWebAction(
                        url,
                        verb,
                        requestStream,
                        responseStream,
                        requestHeadersExtra.ToArray(),
                        responseHeadersExtra,
                        out webStatusCodeOut,
                        out httpStatusCodeOut);

                    jsonResponseBody = null;
                    if (responseHeadersExtra[0].Value == "application/json; charset=UTF-8")
                    {
                        jsonResponseBody = Encoding.UTF8.GetString(responseStream.ToArray());
                    }
                    else
                    {
                        throw new InvalidDataException(String.Format("Unhandled response Content-Type: {0} (expected {1})", responseHeadersExtra[0].Value, "application/json; charset=UTF-8"));
                    }

                    return result;
                }
            }
        }

        protected bool DoWebActionGetBinary(string url, KeyValuePair<string, string>[] requestHeaders, Stream responseBodyBinary, KeyValuePair<string, string>[] responseHeadersOut, out WebExceptionStatus webStatusCodeOut, out HttpStatusCode httpStatusCodeOut)
        {
            List<KeyValuePair<string, string>> requestHeadersList = new List<KeyValuePair<string, string>>();
            if (requestHeaders != null)
            {
                requestHeadersList.AddRange(requestHeaders);
            }
            requestHeadersList.Add(new KeyValuePair<string, string>("Accept", "application/octet-stream"));

            using (MemoryStream responseStream = new MemoryStream())
            {
                bool result = DoWebAction(
                    url,
                    "GET",
                    null/*requestBodySource*/,
                    responseBodyBinary,
                    requestHeadersList.ToArray(),
                    responseHeadersOut,
                    out webStatusCodeOut,
                    out httpStatusCodeOut);
                return result;
            }
        }

        protected bool DownloadFileWithResume(string url, Stream streamDownloadInto)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+DownloadFileWithResume(url={0})", url);
            }

            KeyValuePair<string, string>[] responseHeaders = new KeyValuePair<string, string>[]
            {
                new KeyValuePair<string, string>("Content-Length", null),
                new KeyValuePair<string, string>("Accept-Ranges", null), // Microsoft
                new KeyValuePair<string, string>("Access-Control-Allow-Headers", null), // Google
            };
            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionGetBinary(
                url,
                null/*requestHeaders*/,
                streamDownloadInto,
                responseHeaders,
                out webStatusCode,
                out httpStatusCode);
            if (Logging.EnableLogging)
            {
                Logging.WriteLine(" DownloadFileWithResume result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
            }
            if (!result || (responseHeaders[0].Value == null) || (streamDownloadInto.Length != Int64.Parse(responseHeaders[0].Value)))
            {
                bool acceptRange = String.Equals(responseHeaders[1].Value, "bytes");
                bool acceptRange2 = false;
                if (responseHeaders[2].Value != null)
                {
                    string[] acceptedHeaders = responseHeaders[2].Value.Split(new char[] { ',' });
                    int i = Array.FindIndex(acceptedHeaders, delegate(string candidate) { return String.Equals(candidate.Trim(), "Range"); });
                    acceptRange2 = i >= 0;
                }
                if (acceptRange || acceptRange2)
                {
                    long contentLength = Int64.Parse(responseHeaders[0].Value);
                    long previousLengthSoFar = streamDownloadInto.Length;
                    const int MaxRetries = 5;
                    int retry = 0;
                    while ((retry <= MaxRetries)
                        && (streamDownloadInto.Length < contentLength))
                    {
                        // transport error - retry with range

                        retry++;
                        if (previousLengthSoFar < streamDownloadInto.Length)
                        {
                            retry = 0; // if we made progress then reset retry counter
                        }
                        previousLengthSoFar = streamDownloadInto.Length;

                        Debug.Assert(streamDownloadInto.Length == streamDownloadInto.Position);

                        KeyValuePair<string, string>[] requestHeaders = new KeyValuePair<string, string>[]
                        {
                            new KeyValuePair<string, string>("Range", String.Format("bytes={0}-{1}", streamDownloadInto.Length, contentLength - 1)),
                        };
                        result = DoWebActionGetBinary(
                            url,
                            requestHeaders,
                            streamDownloadInto,
                            null,
                            out webStatusCode,
                            out httpStatusCode);
                        if (Logging.EnableLogging)
                        {
                            Logging.WriteLine(" DownloadFileWithResume result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                        }
                    }

                    if (streamDownloadInto.Length == contentLength)
                    {
                        if (Logging.EnableLogging)
                        {
                            Logging.WriteLine("-DownloadFileWithResume returns True");
                        }
                        return true;
                    }
                }

                if (Logging.EnableLogging)
                {
                    Logging.WriteLine("-DownloadFileWithResume returns False");
                }
                return false;
            }

            return true;
        }
    }

    class MicrosoftOneDriveWebMethods : WebMethodsBase, IWebMethods
    {
        // Desktop application tutorial: http://msdn.microsoft.com/en-us/library/dn631817.aspx
        // REST API - Files: http://msdn.microsoft.com/en-us/library/dn631834.aspx
        // REST API - Folders: http://msdn.microsoft.com/en-us/library/dn631836.aspx

        public MicrosoftOneDriveWebMethods(RemoteAccessControl remoteAccessControl)
            : base(remoteAccessControl, false/*enableRestartableUploads*/)
        {
        }

        private const string UploadLocationUrlPrefix = "https://apis.live.net/v5.0/";
        private const string UploadLocationContentUrlSuffix = "/content/";
        private const string UploadLocationFilesUrlSuffix = "/files/";

        private static string FileIdToUploadLocation(string fileId, bool content)
        {
            if (String.IsNullOrEmpty(fileId))
            {
                if (content)
                {
                    throw new ArgumentException();
                }
                return "https://apis.live.net/v5.0/me/skydrive/files/"; // root folder alias
            }
            else
            {
                return String.Concat(UploadLocationUrlPrefix, fileId, content ? UploadLocationContentUrlSuffix : UploadLocationFilesUrlSuffix);
            }
        }

        private static string UploadLocationToFileId(string uploadLocation)
        {
            // only supports file content UploadLocation - don't use with folder files listing
            if (!uploadLocation.StartsWith(UploadLocationUrlPrefix)
                || !uploadLocation.EndsWith(UploadLocationContentUrlSuffix))
            {
                throw new InvalidDataException();
            }
            string fileId = uploadLocation.Substring(UploadLocationUrlPrefix.Length, uploadLocation.Length - UploadLocationUrlPrefix.Length - UploadLocationContentUrlSuffix.Length);
            if (fileId.IndexOfAny(new char[] { '/', '?', '&' }) >= 0)
            {
                throw new InvalidDataException();
            }
            return fileId;
        }

        private static RemoteFileSystemEntry FileSystemEntryFromJSON(JSONDictionary json)
        {
            string id, name, type, created_time, updated_time;
            long size;
            if (!json.TryGetValueAs("id", out id)
                || !json.TryGetValueAs("name", out name)
                || !json.TryGetValueAs("type", out type) // "folder" or "file"
                || !json.TryGetValueAs("created_time", out created_time)
                || !json.TryGetValueAs("updated_time", out updated_time)
                || !json.TryGetValueAs("size", out size))
            {
                throw new InvalidDataException();
            }
            return new RemoteFileSystemEntry(id, name, type == "folder", DateTime.Parse(created_time), DateTime.Parse(updated_time), size);
        }

        public RemoteFileSystemEntry[] RemoteGetFileSystemEntries(string folderId)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+RemoteGetFileSystemEntries(folderId={0})", folderId);
            }

            string url = String.Format("{0}?pretty=false", FileIdToUploadLocation(folderId, false/*content*/));

            string response;
            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionJSON2JSON(
                url,
                "GET",
                null/*jsonRequestBody*/,
                out response,
                out webStatusCode,
                out httpStatusCode);
            if (!result)
            {
                if (Logging.EnableLogging)
                {
                    Logging.WriteLine("-RemoteGetFileSystemEntries result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new WebException();
            }

            JSONDictionary json = new JSONDictionary(response);
            JSONDictionary[] entries;
            if (!json.TryGetValueAs("data", out entries))
            {
                throw new InvalidDataException();
            }
            RemoteFileSystemEntry[] items = new RemoteFileSystemEntry[entries.Length];
            for (int i = 0; i < entries.Length; i++)
            {
                items[i] = FileSystemEntryFromJSON(entries[i]);
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("  json={0}", response);
                Logging.WriteLine("  return {0} items", items.Length);
                for (int i = 0; i < items.Length; i++)
                {
                    Logging.WriteLine("  [{0}]: {1}", i, items[i]);
                }
                Logging.WriteLine("-RemoteGetFileSystemEntries");
                Logging.WriteLine();
            }

            return items;
        }

        public RemoteFileSystemEntry NavigateRemotePath(string remotePath, bool includeLast)
        {
            if (!(String.IsNullOrEmpty(remotePath) || remotePath.StartsWith("/")))
            {
                throw new ArgumentException();
            }

            if (remotePath == "/")
            {
                remotePath = String.Empty;
            }

            string[] remotePathParts = remotePath.Split(new char[] { '/' });
            int remotePathPartsLength = remotePathParts.Length + (includeLast ? 0 : -1);

            RemoteFileSystemEntry currentDirectory = new RemoteFileSystemEntry(String.Empty, null, true, default(DateTime), default(DateTime), -1);
            for (int i = 1; i < remotePathPartsLength; i++)
            {
                string remotePathPart = remotePathParts[i];
                RemoteFileSystemEntry[] entries = RemoteGetFileSystemEntries(currentDirectory.Id);
                int index = Array.FindIndex(entries, delegate(RemoteFileSystemEntry candidate) { return candidate.Name.Equals(remotePathPart); });
                if (index < 0)
                {
                    throw new FileNotFoundException(String.Format("remote:{0}", remotePathPart));
                }
                currentDirectory = entries[index];
            }
            return currentDirectory;
        }

        public void DownloadFile(string fileId, Stream streamDownloadInto)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+DownloadFile(fileId={0})", fileId);
            }

            string url = String.Format("{0}?pretty=false", FileIdToUploadLocation(fileId, true/*content*/));

            if (!DownloadFileWithResume(url, streamDownloadInto))
            {
                if (Logging.EnableLogging)
                {
                    Logging.WriteLine("-DownloadFile throw", fileId);
                }
                throw new WebException();
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("-DownloadFile", fileId);
            }
        }

        public RemoteFileSystemEntry UploadFile(string folderId, string remoteName, Stream streamUploadFrom)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+UploadFile(folderId={0}, name={1})", folderId, remoteName);
            }

            string response;

            // http://msdn.microsoft.com/en-us/library/dn659726.aspx

            string url = String.Format("{0}{1}?pretty=false", FileIdToUploadLocation(folderId, false/*content*/), remoteName);
            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            KeyValuePair<string, string>[] responseHeaders = new KeyValuePair<string, string>[]
            {
                new KeyValuePair<string, string>("Content-Type", null),
            };
            using (MemoryStream responseStream = new MemoryStream())
            {
                bool result = DoWebAction(
                    url,
                    "PUT",
                    streamUploadFrom,
                    responseStream,
                    null/*requestHeaders*/,
                    responseHeaders,
                    out webStatusCode,
                    out httpStatusCode);
                if (!result)
                {
                    if (Logging.EnableLogging)
                    {
                        Logging.WriteLine("-UploadFile result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                    }
                    throw new WebException();
                }

                if (responseHeaders[0].Value == "application/json; charset=UTF-8")
                {
                    response = Encoding.UTF8.GetString(responseStream.ToArray());
                }
                else
                {
                    throw new InvalidDataException(String.Format("Unhandled response Content-Type: {0} (expected {1})", responseHeaders[0].Value, "application/json; charset=UTF-8"));
                }
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("  json={0}", response);
            }

            JSONDictionary metadata = new JSONDictionary(response);
            string fileId, name;
            if (!metadata.TryGetValueAs("id", out fileId)
                || !metadata.TryGetValueAs("name", out name))
            {
                throw new InvalidDataException();
            }
            Debug.Assert(name == remoteName); // if fails then TODO handle remote auto name adjustment

            RemoteFileSystemEntry entry = GetFileMetadata(fileId);
            Debug.Assert(entry.Name == remoteName); // if fails then TODO handle remote auto name adjustment

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("-UploadFile returns {0}", entry);
                Logging.WriteLine();
            }
            return entry;
        }

        private RemoteFileSystemEntry GetFileMetadata(string fileId)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+GetFileMetadata(id={0})", fileId);
            }

            string url = String.Format("https://apis.live.net/v5.0/{0}?pretty=false", fileId);

            string response;

            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionJSON2JSON(
                url,
                "GET",
                null/*jsonRequestBody*/,
                out response,
                out webStatusCode,
                out httpStatusCode);
            if (!result)
            {
                if (Logging.EnableLogging)
                {
                    Logging.WriteLine("-GetFileMetadata result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new WebException();
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("  json={0}", response);
            }

            JSONDictionary metadata = new JSONDictionary(response);
            RemoteFileSystemEntry entry = FileSystemEntryFromJSON(metadata);

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("-GetFileMetadata returns {0}", entry);
                Logging.WriteLine();
            }

            return entry;
        }

        public void DeleteFile(string fileId)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+DeleteFile(id={0})", fileId);
            }

            // http://msdn.microsoft.com/en-us/library/dn659743.aspx#delete_a_file

            string url = String.Format("https://apis.live.net/v5.0/{0}", fileId);

            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebAction(
                url,
                "DELETE",
                null/*requestBodySource*/,
                null/*responseBodyDestination*/,
                null/*requestHeaders*/,
                null/*responseHeadersOut*/,
                out webStatusCode,
                out httpStatusCode);
            if (!result)
            {
                if (Logging.EnableLogging)
                {
                    Logging.WriteLine("-DeleteFile result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new WebException();
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("-DeleteFile");
                Logging.WriteLine();
            }
        }

        public RemoteFileSystemEntry RenameFile(string fileId, string newName)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+RenameFile(id={0}, newName={1})", fileId, newName);
            }

            if (newName.Contains("\""))
            {
                throw new ArgumentException();
            }

            string url = String.Format("https://apis.live.net/v5.0/{0}?pretty=false", fileId);
            string requestBody =
                "{" +
                String.Format("\"{0}\":\"{1}\"", "name", newName) +
                "}";
            new JSONDictionary(requestBody); // sanity check

            string response;
            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionJSON2JSON(
                url,
                "PUT",
                requestBody,
                out response,
                out webStatusCode,
                out httpStatusCode);
            if (!result)
            {
                if (Logging.EnableLogging)
                {
                    Logging.WriteLine("-RenameFile result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new WebException();
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("  json={0}", response);
            }

            JSONDictionary metadata = new JSONDictionary(response);
            RemoteFileSystemEntry entry = FileSystemEntryFromJSON(metadata);

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("-RenameFile returns {0}", entry);
                Logging.WriteLine();
            }

            return entry;
        }
    }

    class GoogleDriveWebMethods : WebMethodsBase, IWebMethods
    {
        // Desktop application tutorial: https://developers.google.com/accounts/docs/OAuth2InstalledApp
        // https://developers.google.com/drive/v2/reference/

        private Dictionary<string, List<GoogleDriveFile>> childrenMap;
        private string rootId;

        public GoogleDriveWebMethods(RemoteAccessControl remoteAccessControl)
            : base(remoteAccessControl, true/*enableRestartableUploads*/)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+GoogleDriveWebMethods constructor");
            }

            // Google doesn't have a method to get the listing of files for a given folder -
            // children listing only has IDs, requiring a separate HTTP request for each
            // child to find out the filename ("title") property.
            // So here we get the listing of *all* files and use the parent collections on
            // each file to construct the hierarchy. (Also, files can be put into multiple
            // folders - like hard links.)

            GoogleDriveFile[] files = GetRemoteFlatFilesList();

            childrenMap = new Dictionary<string, List<GoogleDriveFile>>(files.Length + 1);
            Dictionary<string, bool> roots = new Dictionary<string, bool>(1);
            foreach (GoogleDriveFile file in files)
            {
                childrenMap.Add(file.Id, new List<GoogleDriveFile>());
                foreach (GoogleDriveParent parent in file.Parents)
                {
                    if (parent.IsRoot)
                    {
                        if (!roots.ContainsKey(parent.Id))
                        {
                            roots.Add(parent.Id, false);
                            childrenMap.Add(parent.Id, new List<GoogleDriveFile>());
                        }
                    }
                }
            }

            if (roots.Count != 1)
            {
                throw new InvalidDataException("Multiple root folders not supported");
            }
            foreach (KeyValuePair<string, bool> root in roots)
            {
                rootId = root.Key;
                break;
            }

            foreach (GoogleDriveFile file in files)
            {
                foreach (GoogleDriveParent parent in file.Parents)
                {
                    childrenMap[parent.Id].Add(file);
                }
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+GoogleDriveWebMethods constructor");
            }
        }

        private class GoogleDriveFile
        {
            // https://developers.google.com/drive/v2/reference/files/list

            public readonly RemoteFileSystemEntry Entry;

            public string Id { get { return Entry.Id; } }
            public string Title { get { return Entry.Name; } }

            public readonly string MimeType;

            public readonly bool Hidden;
            public readonly bool Trashed;

            public readonly GoogleDriveParent[] Parents;

            public GoogleDriveFile(RemoteFileSystemEntry entry, string mimeType, bool hidden, bool trashed, GoogleDriveParent[] parents)
            {
                this.Entry = entry;
                this.MimeType = mimeType;
                this.Hidden = hidden;
                this.Trashed = trashed;
                this.Parents = parents;
            }

            public override string ToString()
            {
                StringBuilder parentString = new StringBuilder();
                foreach (GoogleDriveParent parent in Parents)
                {
                    if (parentString.Length != 0)
                    {
                        parentString.Append(", ");
                    }
                    parentString.Append(parent);
                }
                return String.Format("id={0} title={1} mimeType={2} parents=[{3}]", Entry.Id, Entry.Name, MimeType, parentString);
            }
        }

        private class GoogleDriveParent
        {
            public readonly string Id;
            public readonly string ParentLink;
            public readonly bool IsRoot;

            public GoogleDriveParent(string id, string parentLink, bool isRoot)
            {
                this.Id = id;
                this.ParentLink = parentLink;
                this.IsRoot = isRoot;
            }

            public override string ToString()
            {
                return String.Format("{{id={0} parentLink={1} isRoot={2}}}", Id, ParentLink, IsRoot);
            }
        }

        private const string SelfLinkUrlPrefix = "https://www.googleapis.com/drive/v2/files/";

        private static string FileIdToSelfLink(string fileId)
        {
            return SelfLinkUrlPrefix + fileId;
        }

        private static string SelfLinkToFileId(string selfLink)
        {
            if (!selfLink.StartsWith(SelfLinkUrlPrefix))
            {
                throw new InvalidDataException();
            }
            string fileId = selfLink.Substring(SelfLinkUrlPrefix.Length);
            if (fileId.IndexOfAny(new char[] { '/', '?', '&' }) >= 0)
            {
                throw new InvalidDataException();
            }
            return fileId;
        }

        // TODO:
        // https://developers.google.com/drive/web/performance#partial-response
        // Add the "fields" query parameter to reduce the amount of json fields returned
        // to just the relevant ones.

        private GoogleDriveFile[] GetRemoteFlatFilesList()
        {
            List<GoogleDriveFile> aggregateItems = new List<GoogleDriveFile>();

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+GetRemoteFlatFilesList()");
            }

            string pageToken = null;

            do
            {
                // see: https://developers.google.com/drive/v2/reference/files/list
                // ask for total files (flat), maximum page size (1000 per), omit trashed items
                string url = "https://www.googleapis.com/drive/v2/files?maxResults=1000&trashed=false";
                if (pageToken != null)
                {
                    url = String.Concat(url, url.IndexOf('?') < 0 ? "?" : "&", "pageToken=", pageToken);
                }

                string response;
                WebExceptionStatus webStatusCode;
                HttpStatusCode httpStatusCode;
                bool result = DoWebActionJSON2JSON(
                    url,
                    "GET",
                    null/*jsonRequestBody*/,
                    out response,
                    out webStatusCode,
                    out httpStatusCode);
                if (!result)
                {
                    if (Logging.EnableLogging)
                    {
                        Logging.WriteLine("-GetRemoteFlatFilesList result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                    }
                    throw new WebException();
                }


                // https://developers.google.com/drive/v2/reference/files
                // https://developers.google.com/drive/v2/reference/files/list
                // https://developers.google.com/drive/v2/reference/files#resource
                JSONDictionary json = new JSONDictionary(response);
                JSONDictionary[] entries;
                json.TryGetValueAs("nextPageToken", out pageToken);
                if (!json.TryGetValueAs("items", out entries))
                {
                    throw new InvalidDataException();
                }
                GoogleDriveFile[] items = new GoogleDriveFile[entries.Length];
                for (int i = 0; i < entries.Length; i++)
                {
                    RemoteFileSystemEntry entry = FileSystemEntryFromJSON(entries[i]);

                    string mimeType;
                    if (!entries[i].TryGetValueAs("mimeType", out mimeType))
                    {
                        throw new InvalidDataException();
                    }

                    bool hidden = false;
                    bool trashed = false;
                    JSONDictionary labels;
                    entries[i].TryGetValueAs("labels", out labels);
                    if (labels != null)
                    {
                        if (!labels.TryGetValueAs("hidden", out hidden)
                            || !labels.TryGetValueAs("trashed", out trashed))
                        {
                            throw new InvalidDataException();
                        }
                    }

                    JSONDictionary[] parents;
                    entries[i].TryGetValueAs("parents", out parents);
                    GoogleDriveParent[] parentsList = new GoogleDriveParent[parents != null ? parents.Length : 0];
                    for (int j = 0; j < parentsList.Length; j++)
                    {
                        string id2, parentLink;
                        bool isRoot;
                        if (!parents[j].TryGetValueAs("id", out id2)
                            || !parents[j].TryGetValueAs("parentLink", out parentLink)
                            || !parents[j].TryGetValueAs("isRoot", out isRoot))
                        {
                            throw new InvalidDataException();
                        }
                        parentsList[j] = new GoogleDriveParent(id2, parentLink, isRoot);
                    }

                    items[i] = new GoogleDriveFile(entry, mimeType, hidden, trashed, parentsList);
                }

                if (Logging.EnableLogging)
                {
                    Logging.WriteLine("  json={0}", response);
                    Logging.WriteLine("  create {0} items", items.Length);
                    for (int i = 0; i < items.Length; i++)
                    {
                        Logging.WriteLine("  [{0}]: {1}", i, items[i]);
                    }
                }

                aggregateItems.AddRange(items);

            } while (pageToken != null);


            if (Logging.EnableLogging)
            {
                Logging.WriteLine("-GetRemoteFlatFilesList total={0}", aggregateItems.Count);
                Logging.WriteLine();
            }

            return aggregateItems.ToArray();
        }

        private static RemoteFileSystemEntry FileSystemEntryFromJSON(JSONDictionary json)
        {
            string id, title, mimeType, createdDate, modifiedDate, fileSize;
            if (!json.TryGetValueAs("id", out id)
                || !json.TryGetValueAs("title", out title)
                || !json.TryGetValueAs("mimeType", out mimeType)
                || !json.TryGetValueAs("createdDate", out createdDate)
                || !json.TryGetValueAs("modifiedDate", out modifiedDate))
            {
                throw new InvalidDataException();
            }
            if (!json.TryGetValueAs("fileSize", out fileSize))
            {
                fileSize = "-1";
            }
            return new RemoteFileSystemEntry(id, title, mimeType == "application/vnd.google-apps.folder", DateTime.Parse(createdDate), DateTime.Parse(modifiedDate), Int64.Parse(fileSize));
        }

        public RemoteFileSystemEntry[] RemoteGetFileSystemEntries(string folderId)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+RemoteGetFileSystemEntries(folderId={0})", folderId);
            }

            if (String.IsNullOrEmpty(folderId))
            {
                folderId = rootId;
            }

            List<GoogleDriveFile> children = childrenMap[folderId];
            List<RemoteFileSystemEntry> items = new List<RemoteFileSystemEntry>(children.Count);
            Dictionary<string, RemoteFileSystemEntry> titles = new Dictionary<string, RemoteFileSystemEntry>(children.Count);
            foreach (GoogleDriveFile child in children)
            {
                if (/*child.Hidden || */child.Trashed)
                {
                    continue;
                }

                RemoteFileSystemEntry first;
                if (!titles.TryGetValue(child.Title, out first))
                {
                    first = child.Entry;
                    items.Add(first);
                    titles.Add(first.Name, first);
                }
                else
                {
                    RemoteFileSystemEntry duplicate = child.Entry;
                    first.Duplicates.Add(duplicate);
                }
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("  return {0} items", items.Count);
                for (int i = 0; i < items.Count; i++)
                {
                    Logging.WriteLine("  [{0}]: {1}", i, items[i]);
                }
                Logging.WriteLine("-RemoteGetFileSystemEntries");
                Logging.WriteLine();
            }

            return items.ToArray();
        }

        public RemoteFileSystemEntry NavigateRemotePath(string remotePath, bool includeLast)
        {
            if (!(String.IsNullOrEmpty(remotePath) || remotePath.StartsWith("/")))
            {
                throw new ArgumentException();
            }

            if (remotePath == "/")
            {
                remotePath = String.Empty;
            }

            string[] remotePathParts = remotePath.Split(new char[] { '/' });
            int remotePathPartsLength = remotePathParts.Length + (includeLast ? 0 : -1);

            RemoteFileSystemEntry currentDirectory = new RemoteFileSystemEntry(rootId, null, true, default(DateTime), default(DateTime), -1);
            for (int i = 1; i < remotePathPartsLength; i++)
            {
                string remotePathPart = remotePathParts[i];
                RemoteFileSystemEntry[] entries = RemoteGetFileSystemEntries(currentDirectory.Id);
                int index = Array.FindIndex(entries, delegate(RemoteFileSystemEntry candidate) { return candidate.Name.Equals(remotePathPart); });
                if (index < 0)
                {
                    throw new FileNotFoundException(String.Format("remote:{0}", remotePathPart));
                }
                currentDirectory = entries[index];
            }
            return currentDirectory;
        }

        public void DownloadFile(string fileId, Stream streamDownloadInto)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+DownloadFile(fileId={0})", fileId);
            }

            string url = FileIdToSelfLink(fileId);

            string response;
            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionJSON2JSON(
                url,
                "GET",
                null/*jsonRequestBody*/,
                out response,
                out webStatusCode,
                out httpStatusCode);
            if (!result)
            {
                if (Logging.EnableLogging)
                {
                    Logging.WriteLine("-DownloadFile result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new WebException();
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("  json={0}", response);
            }

            JSONDictionary metadata = new JSONDictionary(response);
            string downloadUrl;
            if (!metadata.TryGetValueAs("downloadUrl", out downloadUrl))
            {
                throw new InvalidDataException();
            }


            // https://developers.google.com/drive/web/manage-downloads

            if (!DownloadFileWithResume(downloadUrl, streamDownloadInto))
            {
                if (Logging.EnableLogging)
                {
                    Logging.WriteLine("-DownloadFile throw", fileId);
                }
                throw new WebException();
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("-DownloadFile", fileId);
            }
        }

        public RemoteFileSystemEntry UploadFile(string folderId, string remoteName, Stream streamUploadFrom)
        {
            if (remoteName.IndexOf('"') >= 0)
            {
                throw new ArgumentException();
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+UploadFile(folderId={0}, name={1})", folderId, remoteName);
            }

            // https://developers.google.com/drive/v2/reference/files/insert
            // https://developers.google.com/drive/web/manage-uploads

            const int MaxStartOvers = 5;
            int startOver = 0;
        // per documentation - 404 during resumable upload should be handled by starting over
        StartOver:
            startOver++;
            if (startOver > MaxStartOvers)
            {
                throw new ApplicationException();
            }

            // 1. initiate resumable upload session

            string response;

            string sessionLocation;

            {
                string url = "https://www.googleapis.com/upload/drive/v2/files?uploadType=resumable";
                string message =
                    "{" +
                    //String.Format("\"mimeType\":\"{0}\"", "application/octet-stream") +
                    String.Format("\"title\":\"{0}\"", remoteName) +
                    String.Format(",\"description\":\"{0}\"", String.Empty) +
                    (folderId != null
                    ? ",\"parents\":[{" +
                      "\"kind\":\"drive#parentReference\"" +
                      String.Format(",\"id\":\"{0}\"", folderId) +
                      "}]"
                    : null) +
                    "}";
                new JSONDictionary(message); // sanity check it's valid
                KeyValuePair<string, string>[] requestHeaders = new KeyValuePair<string, string>[]
                {
                    new KeyValuePair<string, string>("X-Upload-Content-Type", "application/octet-stream"),
                    new KeyValuePair<string, string>("X-Upload-Content-Length", streamUploadFrom.Length.ToString()),
                };
                KeyValuePair<string, string>[] responseHeaders = new KeyValuePair<string, string>[]
                {
                    new KeyValuePair<string, string>("Location", null),
                };
                WebExceptionStatus webStatusCode;
                HttpStatusCode httpStatusCode;
                bool result = DoWebActionPostJSON(
                    url,
                    message/*jsonRequestBody*/,
                    null/*responseBodyDestination*/,
                    requestHeaders,
                    responseHeaders,
                    out webStatusCode,
                    out httpStatusCode);
                if (!result)
                {
                    if (Logging.EnableLogging)
                    {
                        Logging.WriteLine("-UploadFile result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                    }
                    throw new WebException();
                }

                sessionLocation = responseHeaders[0].Value;
            }

            bool resuming = false;
            while (true)
            {
                if (!resuming)
                {
                    // 2a. put data to the session uri

                    {
                        string url = sessionLocation;
                        KeyValuePair<string, string>[] responseHeaders = new KeyValuePair<string, string>[]
                        {
                            new KeyValuePair<string, string>("Content-Type", null),
                        };
                        using (MemoryStream responseStream = new MemoryStream())
                        {
                            WebExceptionStatus webStatusCode;
                            HttpStatusCode httpStatusCode;
                            bool result = DoWebAction(
                                url,
                                "PUT",
                                streamUploadFrom,
                                responseStream,
                                null/*requestHeaders*/,
                                responseHeaders,
                                out webStatusCode,
                                out httpStatusCode);

                            if (result)
                            {
                                if (responseHeaders[0].Value == "application/json; charset=UTF-8")
                                {
                                    response = Encoding.UTF8.GetString(responseStream.ToArray());
                                }
                                else
                                {
                                    throw new InvalidDataException(String.Format("Unhandled response Content-Type: {0} (expected {1})", responseHeaders[0].Value, "application/json; charset=UTF-8"));
                                }

                                break;
                            }
                            else
                            {
                                if (Logging.EnableLogging)
                                {
                                    Logging.WriteLine(" DoWebAction failure - result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                                }

                                if (httpStatusCode == (HttpStatusCode)404)
                                {
                                    goto StartOver;
                                }

                                resuming = true; // trigger resume logic
                            }
                        }
                    }
                }
                else
                {
                    // 2b. handle upload resume

                    // https://developers.google.com/drive/web/manage-uploads#resume-upload

                    if (Logging.EnableLogging)
                    {
                        Logging.WriteLine(" attempting to resume upload");
                    }

                    // 2b-1&2. request status and number of bytes uploaded so far

                    string rangeResponseHeader;

                    using (MemoryStream responseStream = new MemoryStream())
                    {
                        string url = sessionLocation;
                        KeyValuePair<string, string>[] requestHeaders = new KeyValuePair<string, string>[]
                        {
                            new KeyValuePair<string, string>("Content-Range", String.Format("bytes */{0}", streamUploadFrom.Length)),
                            // Content-Length: 0 added by DoWebAction
                        };
                        KeyValuePair<string, string>[] responseHeaders = new KeyValuePair<string, string>[]
                        {
                            new KeyValuePair<string, string>("Content-Type", null), // for completed upload - expecting application/json
                            new KeyValuePair<string, string>("Range", null), // for resumed upload
                        };
                        WebExceptionStatus webStatusCode;
                        HttpStatusCode httpStatusCode;
                        DoWebAction(
                            url,
                            "PUT",
                            null,
                            responseStream,
                            requestHeaders,
                            responseHeaders,
                            out webStatusCode,
                            out httpStatusCode);

                        if (httpStatusCode == (HttpStatusCode)404)
                        {
                            goto StartOver;
                        }

                        if ((httpStatusCode == (HttpStatusCode)200)
                            || (httpStatusCode == (HttpStatusCode)200))
                        {
                            if (responseHeaders[0].Value == "application/json; charset=UTF-8")
                            {
                                response = Encoding.UTF8.GetString(responseStream.ToArray());
                            }
                            else
                            {
                                throw new InvalidDataException(String.Format("Unhandled response Content-Type: {0} (expected {1})", responseHeaders[0].Value, "application/json; charset=UTF-8"));
                            }

                            break; // actually done (all bytes managed to make it to the server)
                        }

                        if (httpStatusCode != (HttpStatusCode)308)
                        {
                            if (Logging.EnableLogging)
                            {
                                Logging.WriteLine("-DoWebAction throw: unexpected HTTP result code: webStatusCode={0} ({1}), httpStatusCode={2} ({3})", (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                            }
                            throw new InvalidDataException();
                        }

                        rangeResponseHeader = responseHeaders[1].Value;
                    }

                    // 2b-3. upload remaining data

                    if (Logging.EnableLogging)
                    {
                        Logging.WriteLine(" range response header={0}", rangeResponseHeader);
                    }

                    if (!String.IsNullOrEmpty(rangeResponseHeader))
                    {
                        const string BytesPrefix = "bytes=";
                        if (!rangeResponseHeader.StartsWith(BytesPrefix))
                        {
                            if (Logging.EnableLogging)
                            {
                                Logging.WriteLine("-DoWebAction throw: invalid range header format");
                            }
                            throw new InvalidDataException();
                        }
                        string[] parts = rangeResponseHeader.Substring(BytesPrefix.Length).Split(new char[] { '-' });
                        if (parts.Length != 2)
                        {
                            if (Logging.EnableLogging)
                            {
                                Logging.WriteLine("-DoWebAction throw: invalid range header format");
                            }
                            throw new InvalidDataException();
                        }
                        long rangeStart = Int64.Parse(parts[0]);
                        if (rangeStart != 0)
                        {
                            if (Logging.EnableLogging)
                            {
                                Logging.WriteLine("-DoWebAction throw: unexpected range header value");
                            }
                            throw new InvalidDataException();
                        }
                        long rangeEndInclusive = Int64.Parse(parts[1]);

                        streamUploadFrom.Position = rangeEndInclusive + 1;
                    }
                    else
                    {
                        // no range header - lost everything - start at beginning
                        streamUploadFrom.Position = 0;
                    }

                    using (MemoryStream responseStream = new MemoryStream())
                    {
                        string url = sessionLocation;
                        KeyValuePair<string, string>[] requestHeaders = new KeyValuePair<string, string>[]
                        {
                            new KeyValuePair<string, string>("Content-Range", String.Format("bytes {0}-{1}/{2}", streamUploadFrom.Position, streamUploadFrom.Length - 1, streamUploadFrom.Length)),
                            // Content-Length computed by DoWebAction based on stream length and position
                        };
                        KeyValuePair<string, string>[] responseHeaders = new KeyValuePair<string, string>[]
                        {
                            new KeyValuePair<string, string>("Content-Type", null),
                        };
                        WebExceptionStatus webStatusCode;
                        HttpStatusCode httpStatusCode;
                        bool result = DoWebAction(
                            url,
                            "PUT",
                            streamUploadFrom,
                            responseStream,
                            requestHeaders,
                            responseHeaders,
                            out webStatusCode,
                            out httpStatusCode);

                        if (result)
                        {
                            if (responseHeaders[0].Value == "application/json; charset=UTF-8")
                            {
                                response = Encoding.UTF8.GetString(responseStream.ToArray());
                            }
                            else
                            {
                                throw new InvalidDataException(String.Format("Unhandled response Content-Type: {0} (expected {1})", responseHeaders[0].Value, "application/json; charset=UTF-8"));
                            }

                            break;
                        }
                        else
                        {
                            if (Logging.EnableLogging)
                            {
                                Logging.WriteLine(" DoWebAction failure - result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                            }

                            if (httpStatusCode == (HttpStatusCode)404)
                            {
                                goto StartOver;
                            }

                            resuming = true; // trigger resume logic
                        }
                    }
                }
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("  json={0}", response);
            }

            JSONDictionary metadata = new JSONDictionary(response);
            RemoteFileSystemEntry entry = FileSystemEntryFromJSON(metadata);
            Debug.Assert(entry.Name == remoteName); // if fails then TODO handle remote auto name adjustment

            string md5Checksum;
            metadata.TryGetValueAs("md5Checksum", out md5Checksum);
            if (md5Checksum != null)
            {
                streamUploadFrom.Position = 0;
                HashAlgorithm md5 = MD5.Create();
                byte[] md5ChecksumLocal = md5.ComputeHash(streamUploadFrom);
                if (!Core.ArrayEqual(md5ChecksumLocal, Core.HexDecode(md5Checksum)))
                {
                    string error = String.Format("UploadFile md5 checksum does not match (name={0}, remote={1}, local={1})", remoteName, md5Checksum, Core.HexEncode(md5ChecksumLocal));
                    if (Logging.EnableLogging)
                    {
                        Logging.WriteLine("-UploadFile throw {0}", error);
                        Logging.WriteLine();
                    }
                    throw new InvalidDataException(error);
                }
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("-UploadFile returns {0}", entry);
                Logging.WriteLine();
            }
            return entry;
        }

#if false
        public RemoteFileSystemEntry GetFileMetadata(string fileId)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+GetFileMetadata(id={0})", fileId);
            }

            string url = String.Format("https://www.googleapis.com/drive/v2/files/{0}", fileId);

            string response;
            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionJSON2JSON(
                url,
                "GET",
                null/*jsonRequestBody*/,
                out response,
                out webStatusCode,
                out httpStatusCode);
            if (!result)
            {
                if (Logging.EnableLogging)
                {
                    Logging.WriteLine("-GetFileMetadata result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new WebException();
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("  json={0}", response);
            }

            JSONDictionary metadata = new JSONDictionary(response);
            RemoteFileSystemEntry entry = FileSystemEntryFromJSON(metadata);

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("-GetFileMetadata returns {0}", entry);
                Logging.WriteLine();
            }

            return entry;
        }
#endif

        public void DeleteFile(string fileId)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+DeleteFile(id={0})", fileId);
            }

            string url = String.Format("https://www.googleapis.com/drive/v2/files/{0}", fileId);

            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebAction(
                url,
                "DELETE",
                null/*requestBodySource*/,
                null/*responseBodyDestination*/,
                null/*requestHeaders*/,
                null/*responseHeadersOut*/,
                out webStatusCode,
                out httpStatusCode);
            if (!result)
            {
                if (Logging.EnableLogging)
                {
                    Logging.WriteLine("-DeleteFile result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new WebException();
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("-DeleteFile", fileId);
                Logging.WriteLine();
            }
        }

        public RemoteFileSystemEntry RenameFile(string fileId, string newName)
        {
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("+RenameFile(id={0}, newName={1})", fileId, newName);
            }

            if (newName.Contains("\""))
            {
                throw new ArgumentException();
            }

            // https://developers.google.com/drive/v2/reference/files/patch

            string url = String.Format("https://www.googleapis.com/drive/v2/files/{0}", fileId);
            string requestBody =
                "{" +
                String.Format("\"title\":\"{0}\"", newName) +
                "}";
            new JSONDictionary(requestBody); // sanity check

            string response;
            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionJSON2JSON(
                url,
                "PATCH",
                requestBody,
                out response,
                out webStatusCode,
                out httpStatusCode);
            if (!result)
            {
                if (Logging.EnableLogging)
                {
                    Logging.WriteLine("-RenameFile result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new WebException();
            }

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("  json={0}", response);
            }

            JSONDictionary metadata = new JSONDictionary(response);
            RemoteFileSystemEntry entry = FileSystemEntryFromJSON(metadata);

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("-RenameFile returns {0}", entry);
                Logging.WriteLine();
            }

            return entry;
        }
    }

    class RemoteArchiveFileManager : IArchiveFileManager
    {
        private Core.Context context;
        private RemoteAccessControl remoteAccessControl;
        private RemoteFileSystemEntry remoteDirectoryEntry; // for the folder we're writing into
        private RemoteDirectoryCache remoteDirectoryCache;
        private Dictionary<string, LocalFileCopy> uncommittedLocalTempFiles = new Dictionary<string, LocalFileCopy>(1);
        private IWebMethods remoteWebMethods;

        private class RemoteDirectoryCache : IEnumerable<RemoteFileSystemEntry>
        {
            private Dictionary<string, RemoteFileSystemEntry> entries = new Dictionary<string, RemoteFileSystemEntry>();

            public RemoteDirectoryCache(RemoteFileSystemEntry[] entries)
            {
                foreach (RemoteFileSystemEntry entry in entries)
                {
                    this.entries.Add(entry.Name, entry);
                }
            }

            public bool TryGetName(string name, out RemoteFileSystemEntry entry)
            {
                return entries.TryGetValue(name, out entry);
            }

            public int Count
            {
                get
                {
                    return entries.Count;
                }
            }

            public void Update(RemoteFileSystemEntry entry)
            {
                entries[entry.Name] = entry;
            }

            public void Remove(string name)
            {
                entries.Remove(name);
            }

            public IEnumerator<RemoteFileSystemEntry> GetEnumerator()
            {
                return entries.Values.GetEnumerator();
            }

            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            {
                return entries.Values.GetEnumerator();
            }
        }

        private delegate void WebActionMethod();
        private class WebActionTask
        {
            private WebActionMethod method;
            private bool finished;
            private Exception lastException;

            public WebActionTask(WebActionMethod method)
            {
                this.method = method;
            }

            public bool Try()
            {
                lastException = null;
                finished = false;

                try
                {
                    method();
                }
                catch (Exception exception)
                {
                    lastException = exception;
                }

                finished = true;
                return lastException == null;
            }

            public bool Finished
            {
                get
                {
                    return finished;
                }
            }

            public bool Succeeded
            {
                get
                {
                    if (!finished)
                    {
                        throw new InvalidOperationException();
                    }
                    return lastException == null;
                }
            }

            public Exception LastException
            {
                get
                {
                    return LastException;
                }
            }

            public void ThrowIfFailed()
            {
                if (!finished)
                {
                    throw new InvalidOperationException();
                }
                if (lastException != null)
                {
                    if (Logging.EnableLogging)
                    {
                        Logging.WriteLine("WebActionTask rethrow {0}", lastException);
                    }

                    throw new Exception(lastException.Message, lastException);
                }
            }
        }

        private RemoteArchiveFileManager()
        {
            throw new NotSupportedException();
        }


        private delegate IWebMethods CreateWebMethodsMethod(RemoteAccessControl remoteAccessControl);
        private static readonly KeyValuePair<string, CreateWebMethodsMethod>[] SupportedServices = new KeyValuePair<string, CreateWebMethodsMethod>[]
        {
            new KeyValuePair<string, CreateWebMethodsMethod>("onedrive.live.com", delegate(RemoteAccessControl remoteAccessControl) { return new MicrosoftOneDriveWebMethods(remoteAccessControl); }),
            new KeyValuePair<string, CreateWebMethodsMethod>("drive.google.com", delegate(RemoteAccessControl remoteAccessControl) { return new GoogleDriveWebMethods(remoteAccessControl); }),
        };

        public RemoteArchiveFileManager(string serviceUrl, string remoteDirectory, string refreshTokenPath, Core.Context context)
        {
            Uri serviceUri = new Uri(serviceUrl);
            if (!serviceUri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
                && !serviceUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException();
            }
            if (serviceUri.PathAndQuery != "/")
            {
                throw new ArgumentException();
            }
            int serviceSelector = Array.FindIndex(SupportedServices, delegate(KeyValuePair<string, CreateWebMethodsMethod> candidate) { return serviceUri.Host.Equals(candidate.Key, StringComparison.OrdinalIgnoreCase); });
            if (serviceSelector < 0)
            {
                throw new NotSupportedException(serviceUri.Host);
            }

            this.context = context;

            if (Logging.EnableLogging)
            {
                Logging.InitializeLog();
                Logging.WriteLine("Backup.OneDriveArchiveFileManager log");
                Logging.WriteLineTimestamp();
                Logging.WriteLine();
                Logging.WriteLine("RemoteArchiveFileManager constructor(service={0}, directory={1})", serviceUrl, remoteDirectory);
            }

            remoteAccessControl = new RemoteAccessControl(String.Concat("https://", SupportedServices[serviceSelector].Key), true/*enableRefreshToken*/, refreshTokenPath);

            remoteWebMethods = SupportedServices[serviceSelector].Value(remoteAccessControl);

            remoteDirectoryEntry = remoteWebMethods.NavigateRemotePath(remoteDirectory, true/*includeLast*/);
            if (Logging.EnableLogging)
            {
                Logging.WriteLine("Remote directory entry: {0}", remoteDirectoryEntry);
                Logging.WriteLine();
            }

            remoteDirectoryCache = new RemoteDirectoryCache(remoteWebMethods.RemoteGetFileSystemEntries(remoteDirectoryEntry.Id));
        }

        public void Dispose()
        {
            if (remoteAccessControl != null)
            {
                remoteAccessControl.Dispose();
                remoteAccessControl = null;
            }

            if (uncommittedLocalTempFiles != null)
            {
                foreach (KeyValuePair<string, LocalFileCopy> item in uncommittedLocalTempFiles)
                {
                    item.Value.Release();
                }
                uncommittedLocalTempFiles.Clear();
                uncommittedLocalTempFiles = null;
            }

            remoteDirectoryEntry = null;
            remoteDirectoryCache = null;

            if (Logging.EnableLogging)
            {
                Logging.WriteLine("OneDriveArchiveFileManager.Dispose()");
                Logging.WriteLineTimestamp();
            }
        }

        public ILocalFileCopy Read(string name)
        {
            string localPath;

            RemoteFileSystemEntry entry;
            if (!remoteDirectoryCache.TryGetName(name, out entry))
            {
                throw new FileNotFoundException(String.Format("remote:{0}", name));
            }

            LocalFileCopy localCopy = new LocalFileCopy();
            localPath = localCopy.LocalFilePath;

            WebActionTask task = new WebActionTask(
                delegate()
                {
                    using (Stream stream = localCopy.Write())
                    {
                        remoteWebMethods.DownloadFile(entry.Id, stream);
                    }
                });
            task.Try();
            task.ThrowIfFailed();
            return localCopy;
        }

        public ILocalFileCopy WriteTemp(string nameTemp)
        {
            LocalFileCopy localCopy = new LocalFileCopy();
            uncommittedLocalTempFiles.Add(nameTemp, localCopy);
            return localCopy.AddRef();
        }

        public void Commit(ILocalFileCopy localFile, string nameTemp, string name)
        {
            if (Exists(nameTemp))
            {
                throw new InvalidOperationException();
            }

            LocalFileCopy uncommitted;
            if (!uncommittedLocalTempFiles.TryGetValue(nameTemp, out uncommitted)
                || (uncommitted != localFile))
            {
                throw new InvalidOperationException();
            }
            uncommittedLocalTempFiles.Remove(nameTemp);
            uncommitted.Release();

            RemoteFileSystemEntry entry;
            using (Stream stream = uncommitted.Read())
            {
                entry = remoteWebMethods.UploadFile(remoteDirectoryEntry.Id, nameTemp, stream);
            }
            remoteDirectoryCache.Update(entry);

            if (!name.Equals(nameTemp))
            {
                if (Exists(name))
                {
                    Delete(name);
                }
                Rename(nameTemp, name);
            }
        }

        public void Abandon(ILocalFileCopy localFile, string nameTemp)
        {
            LocalFileCopy uncommitted;
            if (!uncommittedLocalTempFiles.TryGetValue(nameTemp, out uncommitted)
                || (uncommitted != localFile))
            {
                throw new InvalidOperationException();
            }
            uncommittedLocalTempFiles.Remove(nameTemp);
            uncommitted.Release();
        }

        public void Delete(string name)
        {
            RemoteFileSystemEntry entry;
            if (!remoteDirectoryCache.TryGetName(name, out entry))
            {
                throw new FileNotFoundException(String.Format("remote:{0}", name));
            }

            remoteWebMethods.DeleteFile(entry.Id);
            remoteDirectoryCache.Remove(name);

            if (entry.HasDuplicates)
            {
                foreach (RemoteFileSystemEntry duplicate in entry.Duplicates)
                {
                    remoteWebMethods.DeleteFile(duplicate.Id);
                }
            }
        }

        public void DeleteById(string id)
        {
            RemoteFileSystemEntry entry = null;
            foreach (RemoteFileSystemEntry candidate in remoteDirectoryCache)
            {
                if (candidate.Id.Equals(id))
                {
                    entry = candidate;
                    break;
                }
            }
            if (entry == null)
            {
                throw new FileNotFoundException(String.Format("remote-id:{0}", id));
            }

            remoteWebMethods.DeleteFile(entry.Id);
            remoteDirectoryCache.Remove(entry.Name);

            // do not delete duplicates in this method
        }

        public bool Exists(string name)
        {
            RemoteFileSystemEntry entry;
            return remoteDirectoryCache.TryGetName(name, out entry);
        }

        public void Rename(string oldName, string newName)
        {
            RemoteFileSystemEntry entry;
            if (!remoteDirectoryCache.TryGetName(oldName, out entry))
            {
                throw new FileNotFoundException(String.Format("remote:{0}", oldName));
            }

            RemoteFileSystemEntry newEntry = remoteWebMethods.RenameFile(entry.Id, newName);
            remoteDirectoryCache.Remove(oldName);
            if (newEntry != null)
            {
                remoteDirectoryCache.Update(newEntry);
            }
        }

        public void RenameById(string id, string newName)
        {
            RemoteFileSystemEntry entry = null;
            foreach (RemoteFileSystemEntry candidate in remoteDirectoryCache)
            {
                if (candidate.Id.Equals(id))
                {
                    entry = candidate;
                    break;
                }
            }
            if (entry == null)
            {
                throw new FileNotFoundException(String.Format("remote-id:{0}", id));
            }

            RemoteFileSystemEntry newEntry = remoteWebMethods.RenameFile(entry.Id, newName);
            remoteDirectoryCache.Remove(entry.Name);
            if (newEntry != null)
            {
                remoteDirectoryCache.Update(newEntry);
            }
        }

        public string[] GetFileNames(string prefix)
        {
            List<string> names = new List<string>(remoteDirectoryCache.Count);
            foreach (RemoteFileSystemEntry entry in remoteDirectoryCache)
            {
                if (entry.Name.StartsWith(prefix))
                {
                    names.Add(entry.Name);
                }
            }
            return names.ToArray();
        }

        public void GetFileInfo(string name, out string id, out bool directory, out DateTime created, out DateTime modified, out long size)
        {
            RemoteFileSystemEntry entry;
            if (!remoteDirectoryCache.TryGetName(name, out entry))
            {
                throw new FileNotFoundException(String.Format("remote:{0}", name));
            }

            id = entry.Id;
            directory = entry.Folder;
            created = entry.Created;
            modified = entry.Modified;
            size = entry.Size;
        }
    }

    // TODO: multi-threaded requests
}
