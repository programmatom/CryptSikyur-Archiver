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
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Web;

using Backup;
using Http;
using JSON;

namespace Backup
{
    ////////////////////////////////////////////////////////////////////////////
    //
    // Utilities
    //
    ////////////////////////////////////////////////////////////////////////////

    public static class RetryHelper
    {
        private static int maxRetries = 5;
        private static readonly Random random = new Random();

        public static int MaxRetries
        {
            get
            {
                return maxRetries;
            }
        }

        public static void SetMaxRetries(int newMaxRetries)
        {
            maxRetries = newMaxRetries;
        }

        public static int ThreadsafeRandomNext(int limit)
        {
            lock (random)
            {
                return random.Next(limit);
            }
        }

        public static void WaitExponentialBackoff(int retry, TextWriter trace)
        {
            if (retry > 0)
            {
                int w = 500 * (1 << retry);
                int delay = w + ThreadsafeRandomNext(w);

                if (trace != null)
                {
                    trace.WriteLine(" exponential backoff: waiting {0} milliseconds and retrying (#{1})", delay, retry);
                }

                Thread.Sleep(delay);
            }
        }
    }

    public class RateLimitHelper
    {
        private DateTime notBefore;
        private Random random = new Random();

        public RateLimitHelper()
        {
        }

        private const int DefaultRateLimitExceededBackoffMilliseconds = 5;
        private const int ExtraDelayMaxMilliseconds = 5000;
        private const int ScalingFactor = 2;

        public void WaitRateLimitExceededBackoff(TextWriter trace, HttpStatusCode rateLimitStatusCode, int? requestedDelaySeconds)
        {
            int delay = ScalingFactor * (requestedDelaySeconds.HasValue ? requestedDelaySeconds.Value * 1000 : DefaultRateLimitExceededBackoffMilliseconds);
            if (trace != null)
            {
                trace.WriteLine("Remote API rate limit exceeded (status={1}), delaying {0} msec", delay, rateLimitStatusCode);
            }

            lock (this)
            {
                DateTime currentBase = notBefore >= DateTime.Now ? notBefore : DateTime.Now;
                notBefore = currentBase.AddMilliseconds(delay);
            }

            Wait(null);
        }

        public void Wait(TextWriter trace)
        {
            bool lockedOut = false;
            while (true)
            {
                lock (this)
                {
                    if (notBefore < DateTime.Now)
                    {
                        break;
                    }
                    if (!lockedOut)
                    {
                        if (trace != null)
                        {
                            trace.WriteLine("(delaying because of rate limiting lock-out interval)");
                        }
                    }
                    lockedOut = true;
                }

                Thread.Sleep(1000);
            }

            if (lockedOut)
            {
                int extraDelay;
                lock (this)
                {
                    extraDelay = random.Next(ExtraDelayMaxMilliseconds);
                }
                Thread.Sleep(extraDelay);
            }
        }
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Resource Owner Authentication
    //
    ////////////////////////////////////////////////////////////////////////////

    public class RemoteAccessControl : IDisposable
    {
        private readonly string remoteServiceUrl;

        private readonly bool enableRefreshToken;

        private string accessToken; // null if not initialized or invalidated
        // The refresh token is never used by this process but only ever handed back
        // to RemoteDriveAuth.exe to obtain new access token. Therefore, it is always
        // in its encrypted & encoded state in this process
        private string refreshTokenProtected; // protected with CryptProtectMemory and hex-encoded; null if not enabled

        private DateTime accessTokenExpiration;

        // All accesses are through critical section to prevent multiple re-authorizations
        // from occurring simultaneously if access token has expired.

        private RemoteAccessControl()
        {
            throw new NotSupportedException();
        }

        public RemoteAccessControl(string remoteServiceUrl, bool enableRefreshToken, string refreshTokenProtected, TextWriter trace)
        {
            if (!enableRefreshToken && !String.IsNullOrEmpty(refreshTokenProtected))
            {
                throw new ArgumentException();
            }

            lock (this) // not actually needed in constructor
            {
                this.remoteServiceUrl = remoteServiceUrl;

                this.enableRefreshToken = enableRefreshToken;
                this.refreshTokenProtected = refreshTokenProtected;

                Authenticate(trace);
            }
        }

        public void Dispose()
        {
            lock (this)
            {
                accessToken = null;
                refreshTokenProtected = null;
            }
        }

        public string GetAccessToken(TextWriter trace)
        {
            lock (this)
            {
                if (trace != null)
                {
                    trace.WriteLine("+RemoteAccessControl.GetAccessToken");
                }

                if (accessTokenExpiration < DateTime.Now)
                {
                    accessToken = null;
                    trace.WriteLine(" expiration time reached - reauthorizing");
                }

                if (accessToken == null)
                {
                    Authenticate(trace);
                }

                if (trace != null)
                {
                    trace.WriteLine("-RemoteAccessControl.GetAccessToken returns {0}", LogWriter.ScrubSecuritySensitiveValue(accessToken));
                }
                return accessToken;
            }
        }

        public void InvalidateAccessToken(string callerAccessToken, TextWriter trace)
        {
            lock (this)
            {
                if (trace != null)
                {
                    trace.WriteLine("+RemoteAccessControl.InvalidateOldAccessToken: {0}", LogWriter.ScrubSecuritySensitiveValue(callerAccessToken));
                }

                if (String.Equals(callerAccessToken, accessToken))
                {
                    accessToken = null;

                    if (trace != null)
                    {
                        trace.WriteLine(" caller posesses current token - marking expired");
                    }
                }
                else
                {
                    if (trace != null)
                    {
                        trace.WriteLine(" doing nothing - not the current token {0}", LogWriter.ScrubSecuritySensitiveValue(accessToken));
                    }
                }

                if (trace != null)
                {
                    trace.WriteLine("-RemoteAccessControl.InvalidateOldAccessToken");
                }
            }
        }

        private const string LoginProgramName = "RemoteDriveAuth.exe";
        private const int SecondaryEntropyLengthBytes = 256 / 8;
        private void Authenticate(TextWriter trace)
        {
            // caller should have already locked object for this invocation

            if (trace != null)
            {
                trace.WriteLine("+RemoteAccessControl.Authenticate() - {0}", DateTime.Now);
            }

            int retries = 0;
        Retry:
            string arg0 = "-auth";
            string arg1 = "-refreshtoken";
            string arg2 = enableRefreshToken ? "yes" : "no";
            string arg3 = enableRefreshToken && !String.IsNullOrEmpty(refreshTokenProtected) ? refreshTokenProtected : "\"\"";
            string arg4 = remoteServiceUrl;
            string args = String.Concat(arg0, " ", arg1, " ", arg2, " ", arg3, " ", arg4);
            int exitCode;
            string output;
            Exec(LoginProgramName, args, null, null/*timeout*/, out exitCode, out output);
            if (output.EndsWith(Environment.NewLine))
            {
                output = output.Substring(0, output.Length - Environment.NewLine.Length);
            }
            if (trace != null)
            {
                trace.WriteLine("call {0} {1} {2} {3} {4} {5}", LoginProgramName, arg0, arg1, arg2, arg3.Length > 2 ? LogWriter.ScrubSecuritySensitiveValue(arg3) : arg3, arg4);
                trace.WriteLine("exit code: {0}", exitCode);
                trace.WriteLine("output:");
                trace.WriteLine(exitCode == 0 ? LogWriter.ScrubSecuritySensitiveValue(output) : output);
                trace.WriteLine();
            }

            if (exitCode != 0)
            {
                if (exitCode == 2)
                {
                    throw new ApplicationException(String.Format("Authentication to remote service failed with message: {0}", output));
                }
                if (exitCode == 3)
                {
                    retries++;
                    if (retries <= RetryHelper.MaxRetries)
                    {
                        RetryHelper.WaitExponentialBackoff(retries, trace);
                        goto Retry;
                    }
                }
                throw new ApplicationException(String.Format("Unable to authenticate to remote service \"{0}\"", remoteServiceUrl));
            }

            string oldRefreshTokenProtected = refreshTokenProtected;

            // RemoteDriveAuth.exe returns as little information as is needed for the main
            // process to do it's job. Therefore, properties such as user_id are not returned.

            string[] outputParts = output.Split(new char[] { ',' });
            if (outputParts.Length != 3)
            {
                throw new ApplicationException(String.Format("Unable to authenticate to remote service \"{0}\"", remoteServiceUrl));
            }
            refreshTokenProtected = outputParts[0].Trim();
            using (ProtectedArray<byte> accessTokenDecrypted = ProtectedArray<byte>.DecryptEphemeral(HexUtility.HexDecode(outputParts[1]), ProtectedDataStorage.EphemeralScope.SameLogon))
            {
                if (ProtectedArray<byte>.IsNullOrEmpty(accessTokenDecrypted))
                {
                    throw new InvalidDataException(String.Format("Unable to authenticate to remote service \"{0}\"", remoteServiceUrl));
                }
                accessTokenDecrypted.Reveal();
                accessToken = Encoding.UTF8.GetString(accessTokenDecrypted.ExposeArray());
            }
            long expires_in;
            using (ProtectedArray<byte> expiresIn = ProtectedArray<byte>.DecryptEphemeral(HexUtility.HexDecode(outputParts[2]), ProtectedDataStorage.EphemeralScope.SameLogon))
            {
                expiresIn.Reveal();
                expires_in = Int64.Parse(Encoding.UTF8.GetString(expiresIn.ExposeArray()));
                // expire in 1/2 the given window, to allow plenty of time for large file
                // uploads to complete without receiving an unauthorized error.
                accessTokenExpiration = DateTime.Now.AddSeconds(expires_in / 2);
            }
            if (trace != null)
            {
                trace.WriteLine("Acquired tokens:");
                trace.WriteLine("  access_token={0}", LogWriter.ScrubSecuritySensitiveValue(accessToken));
                trace.WriteLine("  refresh_token={0}", LogWriter.ScrubSecuritySensitiveValue(refreshTokenProtected));
                trace.WriteLine("  other: expires_in={0}", expires_in);
                trace.WriteLine();
            }

            if (String.IsNullOrEmpty(refreshTokenProtected))
            {
                refreshTokenProtected = oldRefreshTokenProtected;
            }

            if (trace != null)
            {
                trace.WriteLine(" [expiration set to [{0}]", accessTokenExpiration);
                trace.WriteLine("-RemoteAccessControl.Authenticate - {0}", DateTime.Now);
            }
        }

        private static bool Exec(string program, string arguments, string input, int? commandTimeoutSeconds, out int exitCode, out string output)
        {
            bool killed = false;

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

    // TODO: implement dropbox support: https://www.dropbox.com/developers/core/docs
    // TODO: implement AWS support: (S3- http://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html, Glacier- http://docs.aws.amazon.com/amazonglacier/latest/dev/amazon-glacier-api.html)
    // TODO: implement Azure support: http://msdn.microsoft.com/library/azure/dd179355.aspx

    public class RemoteFileSystemEntry
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


    public interface IWebMethods
    {
        RemoteFileSystemEntry[] RemoteGetFileSystemEntries(string folderId, TextWriter trace, IFaultInstance faultInstanceContext);
        RemoteFileSystemEntry NavigateRemotePath(string remotePath, bool includeLast, TextWriter trace, IFaultInstance faultInstanceContext);
        void DownloadFile(string fileId, Stream streamDownloadInto, ProgressTracker progressTracker, TextWriter trace, IFaultInstance faultInstanceContext);
        RemoteFileSystemEntry UploadFile(string folderId, string remoteName, Stream streamUploadFrom, ProgressTracker progressTracker, TextWriter trace, IFaultInstance faultInstanceContext);
        void DeleteFile(string fileId, TextWriter trace, IFaultInstance faultInstanceContext);
        RemoteFileSystemEntry RenameFile(string fileId, string newName, TextWriter trace, IFaultInstance faultInstanceContext);
        void GetQuota(out long quotaTotal, out long quotaUsed, TextWriter trace, IFaultInstance faultInstanceContext);
    }

    public abstract class WebMethodsBase : ICertificatePinning
    {
        private const int MaxBytesPerWebRequest = 50 * 1024 * 1024; // force upload fail & resumable after this many bytes (to exercise the resume code)
        private const string UserAgent = "Backup (CryptSikyur-Archiver) v0 [github.com/programmatom/CryptSikyur-Archiver]";
        private const int SendTimeout = 60 * 1000;
        private const int ReceiveTimeout = 60 * 1000;

        private HttpSettings settings;

        protected readonly RemoteAccessControl remoteAccessControl;

        protected readonly Random random = new Random(); // for exponential backoff retry delays

        private bool certificatePinningEnabled;
#if false
        private KeyValuePair<string, string[]>[] certificatePinningPublicKeys;
#endif

        private static RateLimitHelper rateLimitHelper = new RateLimitHelper();
        private static INetworkThrottle networkThrottle = new NetworkThrottle(); // not changeable after creation

        private WebMethodsBase()
        {
            throw new NotSupportedException();
        }

        protected WebMethodsBase(RemoteAccessControl remoteAccessControl, bool enableResumableUploads, IPAddress socks5Address, int socks5Port)
        {
            this.remoteAccessControl = remoteAccessControl;

            settings = new HttpSettings(
                enableResumableUploads,
                MaxBytesPerWebRequest,
                this/*certificatePinning*/,
                networkThrottle,
                SendTimeout,
                ReceiveTimeout,
                socks5Address,
                socks5Port);
        }


        // Global controls

        private class NetworkThrottle : INetworkThrottle
        {
            public void WaitBytes(int count)
            {
            }
        }

        private class ActiveNetworkThrottle : INetworkThrottle
        {
            private const int MinApproximateBytesPerSecond = 100;
            private int approximateBytesPerSecond;

            public ActiveNetworkThrottle(int approximateBytesPerSecond)
            {
                if (approximateBytesPerSecond < MinApproximateBytesPerSecond)
                {
                    throw new ArgumentException();
                }
                this.approximateBytesPerSecond = approximateBytesPerSecond;
            }

            public void WaitBytes(int count)
            {
                lock (this)
                {
                    long milliseconds = (1000L * count) / approximateBytesPerSecond;
                    Thread.Sleep((int)milliseconds);
                }
            }
        }

        public static void SetThrottle(int approximateBytesPerSecond)
        {
            if (approximateBytesPerSecond == 0)
            {
                networkThrottle = new NetworkThrottle();
            }
            else
            {
                networkThrottle = new ActiveNetworkThrottle(approximateBytesPerSecond);
            }
        }

        public static void ThrottleOff()
        {
            SetThrottle(0);
        }


        // Certificate pinning

        // Certificate pinning pre-registers the public key of well-known services and requires
        // an actual TLS connection to present a validated certificate using the same public key,
        // as proof that the service has the correct private key. This defeats certain MITM
        // attacks mounted by, e.g. corrupt/inept CAs.
        // https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning
        // also,
        // TODO: monitor RFC for acceptance and adopt for servers that begin supporting it
        // (so far: http://tools.ietf.org/html/draft-ietf-websec-key-pinning-21)

        public bool CertificatePinningEnabled
        {
            get
            {
#if false
                return certificatePinningEnabled;
#else
                return false;
#endif
            }
        }

        public bool ValidatePinnedCertificate(string host, IPAddress hostAddress, X509Certificate certificate, TextWriter trace)
        {
#if false
            // TODO: this code is not flexible enough. Use X509Chain to allow ancestor certs to be pinned
            // see:
            // https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning
            // https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning/Implementation_Details
            // also
            // https://src.chromium.org/viewvc/chrome/trunk/src/net/http/transport_security_state_static.json

            string publicKey = ExtractPublicKey(certificate);

            if (trace != null)
            {
                trace.WriteLine("*ValidatePinnedCertificate: validating host={0} addr={1} publicKey={2}", host, hostAddress, publicKey);
            }

            if (!certificatePinningEnabled)
            {
                return true;
            }

            foreach (KeyValuePair<string, string[]> candidate in certificatePinningPublicKeys)
            {
                if (candidate.Key.StartsWith("*.") ? host.EndsWith("." + candidate.Key.Substring(2)) : host.Equals(candidate.Key))
                {
                    foreach (string candidatePublicKey in candidate.Value)
                    {
                        if (String.Equals(publicKey, candidatePublicKey))
                        {
                            return true;
                        }
                    }
                }
            }
#endif

            return false;
        }

#if false
        protected static string ExtractPublicKey(X509Certificate certificate)
        {
            return certificate.GetPublicKeyString();
        }

        protected void RegisterPinnedCertificates(bool enable, KeyValuePair<string, string[]>[] hostsPublicKeys, TextWriter trace)
        {
            if (!enable && (hostsPublicKeys != null) && (hostsPublicKeys.Length != 0))
            {
                throw new ArgumentException();
            }

            if (trace != null)
            {
                trace.WriteLine("*RegisterPinnedCertificates: enable={0}", enable);
                foreach (KeyValuePair<string, string[]> item in hostsPublicKeys)
                {
                    string publicKeys = null;
                    foreach (string key in item.Value)
                    {
                        publicKeys = String.Concat(publicKeys != null ? ", " : null, key);
                    }
                    trace.WriteLine("  {{host={0}, publicKeys[]={{{1}}}}}", item.Key, publicKeys);
                }
            }

            certificatePinningEnabled = enable;
            certificatePinningPublicKeys = hostsPublicKeys;
        }
#endif


        // Configurable methods

        public abstract HttpStatusCode RateLimitStatusCode { get; }
        public abstract string RateLimitRetryAfterHeader { get; }


        // Implementation

        // Throws exceptions for program defects and unrecoverable errors
        // Returns false + (WebExceptionStatus, HttpStatusCode) for potentially recoverable errors
        private static readonly string[] SupportedVerbs = new string[] { "GET", "PUT", "POST", "DELETE", "PATCH" };
        private static readonly string[] ForbiddenRequestHeaders = new string[] { "Host", "Content-Length", "Accept-Encoding", "Expect", "Authorization" };
        protected bool DoWebActionOnce(string url, string verb, Stream requestBodySource, Stream responseBodyDestination, KeyValuePair<string, string>[] requestHeaders, KeyValuePair<string, string>[] responseHeadersOut, out WebExceptionStatus webStatusCodeOut, out HttpStatusCode httpStatusCodeOut, ProgressTracker progressTrackerUpload, ProgressTracker progressTrackerDownload, string accessTokenOverride, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (requestHeaders == null)
            {
                requestHeaders = new KeyValuePair<string, string>[0];
            }
            if (responseHeadersOut == null)
            {
                responseHeadersOut = new KeyValuePair<string, string>[0];
            }

            if (trace != null)
            {
                trace.WriteLine("+DoWebActionOnce(url={0}, verb={1}, request-body={2}, response-body={3})", url, verb, LogWriter.ToString(requestBodySource), LogWriter.ToString(responseBodyDestination));
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
            if (wantsResponseBody && ((verb != "GET") && (verb != "PUT") && (verb != "PATCH") && (verb != "DELETE")))
            {
                throw new ArgumentException(verb);
            }
            if (hasRequestBody && ((verb != "PUT") && (verb != "POST") && (verb != "PATCH")))
            {
                throw new ArgumentException();
            }


            bool accessDeniedRetried = false;
            long requestBodySourcePosition = requestBodySource != null ? requestBodySource.Position : 0;
            long responseBodyDestinationPosition = responseBodyDestination != null ? responseBodyDestination.Position : 0;
        RetryAuthFailure:
            // clear all out params
            WebExceptionStatus webStatusCode = WebExceptionStatus.UnknownError;
            HttpStatusCode httpStatusCode = (HttpStatusCode)0;
            for (int i = 0; i < responseHeadersOut.Length; i++)
            {
                responseHeadersOut[i] = new KeyValuePair<string, string>(responseHeadersOut[i].Key, null);
            }
            // rewind streams (for retry)
            if ((requestBodySource != null) && (requestBodySource.Position != requestBodySourcePosition))
            {
                if (trace != null)
                {
                    trace.WriteLine(" [retry prep] rewinding requestBodySource from {0} to {1} (current length={2})", requestBodySource.Position, requestBodySourcePosition, requestBodySource.Length);
                }
                requestBodySource.Position = requestBodySourcePosition;
            }
            if (responseBodyDestination != null)
            {
                if (responseBodyDestination.Position != responseBodyDestinationPosition)
                {
                    if (trace != null)
                    {
                        trace.WriteLine(" [retry prep] rewinding responseBodyDestination from {0} to {1} (current length={2})", responseBodyDestination.Position, responseBodyDestinationPosition, responseBodyDestination.Length);
                    }
                    responseBodyDestination.Position = responseBodyDestinationPosition;
                }
                if (responseBodyDestination.Length != responseBodyDestination.Position)
                {
                    if (trace != null)
                    {
                        trace.WriteLine(" [retry prep] resetting length of responseBodyDestination from {0} to {1}", responseBodyDestination.Length, responseBodyDestination.Position);
                    }
                    responseBodyDestination.SetLength(responseBodyDestination.Position);
                }
            }
            // other headers
            int? retryAfterSeconds = null;

            string accessToken;
            if (accessTokenOverride == null)
            {
                if (trace != null)
                {
                    trace.WriteLine("Acquiring access token (RemoteAccessControl.AccessToken)");
                }
                accessToken = remoteAccessControl.GetAccessToken(trace);
                if (trace != null)
                {
                    trace.WriteLine("Acquired access token (RemoteAccessControl.AccessToken): {0}", LogWriter.ScrubSecuritySensitiveValue(accessToken));
                }
            }
            else
            {
                accessToken = accessTokenOverride;
                if (trace != null)
                {
                    trace.WriteLine("Acquiring access token (using same token for all requests): {0}", LogWriter.ScrubSecuritySensitiveValue(accessToken));
                }
            }


            // Custom HTTP request implementation

            rateLimitHelper.Wait(trace); // do not make request if rate limit epoch is in effect

            Uri uri = new Uri(url);
            IPAddress hostAddress = null;
            if (settings.Socks5Address == null)
            {
                // Only resolve remote host address if not using socks5, to avoid DNS leaks

                webStatusCode = HttpMethods.DNSLookupName(uri.Host, out hostAddress, trace, faultInstanceContext);
                if (webStatusCode != WebExceptionStatus.Success)
                {
                    if (trace != null)
                    {
                        trace.WriteLine("DNSLookupName returned error: {0} ({1})", (int)webStatusCode, webStatusCode);
                    }
                    goto Error;
                }
            }

            // generally, headers in ForbiddenRequestHeaders[] are managed by SocketHttpRequest
            Dictionary<string, bool> requestHeadersSeen = new Dictionary<string, bool>();
            List<KeyValuePair<string, string>> requestHeadersList = new List<KeyValuePair<string, string>>();
            requestHeadersList.Add(new KeyValuePair<string, string>("Authorization", String.Format("{0} {1}", "Bearer", accessToken)));
            foreach (KeyValuePair<string, string> header in requestHeaders)
            {
                Debug.Assert(!HttpMethods.IsHeaderForbidden(header.Key));
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
            webStatusCode = HttpMethods.SocketHttpRequest(
                uri,
                hostAddress,
                verb,
                requestHeadersList.ToArray(),
                requestBodySource,
                out httpStatusCode,
                out responseHeaders,
                responseBodyDestination,
                out finalUrl,
                progressTrackerUpload,
                progressTrackerDownload,
                trace,
                faultInstanceContext,
                settings);

            for (int i = 0; i < responseHeadersOut.Length; i++)
            {
                int index = Array.FindIndex(responseHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, responseHeadersOut[i].Key); });
                if (index >= 0)
                {
                    responseHeadersOut[i] = new KeyValuePair<string, string>(responseHeadersOut[i].Key, responseHeaders[index].Value);
                }
            }
            if (RateLimitRetryAfterHeader != null)
            {
                int index = Array.FindIndex(responseHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, RateLimitRetryAfterHeader); });
                if (index >= 0)
                {
                    retryAfterSeconds = Int32.Parse(responseHeaders[index].Value);
                }
            }

            if ((httpStatusCode == (HttpStatusCode)401) && !accessDeniedRetried)
            {
                if (accessTokenOverride == null)
                {
                    if (trace != null)
                    {
                        trace.WriteLine("Received access denied (401); invalidating access token and retrying");
                    }
                    accessDeniedRetried = true; // retry only once for failed auth
                    remoteAccessControl.InvalidateAccessToken(accessToken, trace);
                    goto RetryAuthFailure;
                }
                else
                {
                    if (trace != null)
                    {
                        trace.WriteLine("Received access denied (401); accessTokenOverride exists, so failing to caller");
                    }
                }
            }


        Error:

            if (httpStatusCode == RateLimitStatusCode)
            {
                rateLimitHelper.WaitRateLimitExceededBackoff(trace, RateLimitStatusCode, retryAfterSeconds);
            }

            bool result = (webStatusCode == WebExceptionStatus.Success)
                && (((int)httpStatusCode >= 200) && ((int)httpStatusCode <= 299));
            if (trace != null)
            {
                if (responseBodyDestination != null)
                {
                    trace.WriteLine(" response-body={0}", LogWriter.ToString(responseBodyDestination));
                }
                trace.WriteLine("-DoWebActionOnce result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
            }
            webStatusCodeOut = webStatusCode;
            httpStatusCodeOut = httpStatusCode;
            return result;
        }

        // Throws exceptions for program defects and unrecoverable errors
        // Returns false + (WebExceptionStatus, HttpStatusCode) for potentially recoverable errors
        protected bool DoWebActionWithRetry(string url, string verb, Stream requestBodySource, Stream responseBodyDestination, KeyValuePair<string, string>[] requestHeaders, KeyValuePair<string, string>[] responseHeadersOut, out WebExceptionStatus webStatusCodeOut, out HttpStatusCode httpStatusCodeOut, ProgressTracker progressTrackerUpload, string accessTokenOverride, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (trace != null)
            {
                trace.WriteLine("+DoWebActionWithRetry(url={0}, verb={1}, request-body={2}, response-body={3})", url, verb, LogWriter.ToString(requestBodySource), LogWriter.ToString(responseBodyDestination));
            }

            long requestBodySourcePosition = requestBodySource != null ? requestBodySource.Position : 0;
            long responseBodyDestinationPosition = responseBodyDestination != null ? responseBodyDestination.Position : 0;


            int networkErrorRetries = 0;
        Retry:

            DoWebActionOnce(url, verb, requestBodySource, responseBodyDestination, requestHeaders, responseHeadersOut, out webStatusCodeOut, out httpStatusCodeOut, progressTrackerUpload, null/*progressTrackerDownload*/, accessTokenOverride, trace, faultInstanceContext);

            if ((webStatusCodeOut != WebExceptionStatus.Success) ||
                (httpStatusCodeOut == RateLimitStatusCode) ||
                (((int)httpStatusCodeOut >= 500) && ((int)httpStatusCodeOut <= 599)))
            {
                networkErrorRetries++;
                if (networkErrorRetries <= RetryHelper.MaxRetries)
                {
                    RetryHelper.WaitExponentialBackoff(networkErrorRetries, trace);

                    // reset state
                    if ((requestBodySource != null) && (requestBodySource.Position != requestBodySourcePosition))
                    {
                        if (trace != null)
                        {
                            trace.WriteLine(" [retry prep] rewinding requestBodySource from {0} to {1} (current length={2})", requestBodySource.Position, requestBodySourcePosition, requestBodySource.Length);
                        }
                        requestBodySource.Position = requestBodySourcePosition;
                    }
                    if (responseBodyDestination != null)
                    {
                        if (responseBodyDestination.Position != responseBodyDestinationPosition)
                        {
                            if (trace != null)
                            {
                                trace.WriteLine(" [retry prep] rewinding responseBodyDestination from {0} to {1} (current length={2})", responseBodyDestination.Position, responseBodyDestinationPosition, responseBodyDestination.Length);
                            }
                            responseBodyDestination.Position = responseBodyDestinationPosition;
                        }
                        if (responseBodyDestination.Length != responseBodyDestination.Position)
                        {
                            if (trace != null)
                            {
                                trace.WriteLine(" [retry prep] resetting length of responseBodyDestination from {0} to {1}", responseBodyDestination.Length, responseBodyDestination.Position);
                            }
                            responseBodyDestination.SetLength(responseBodyDestination.Position);
                        }
                    }

                    goto Retry;
                }
            }


            bool result = (webStatusCodeOut == WebExceptionStatus.Success)
                && (((int)httpStatusCodeOut >= 200) && ((int)httpStatusCodeOut <= 299));
            if (trace != null)
            {
                if (responseBodyDestination != null)
                {
                    trace.WriteLine(" response-body={0}", LogWriter.ToString(responseBodyDestination));
                }
                trace.WriteLine("-DoWebActionWithRetry result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCodeOut, webStatusCodeOut, (int)httpStatusCodeOut, httpStatusCodeOut);
            }
            return result;
        }

        protected bool DoWebActionPostJSONOnce(string url, string jsonRequestBody, Stream responseBodyDestination, KeyValuePair<string, string>[] requestHeaders, KeyValuePair<string, string>[] responseHeadersExtraOut, out WebExceptionStatus webStatusCodeOut, out HttpStatusCode httpStatusCodeOut, string accessTokenOverride, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            List<KeyValuePair<string, string>> requestHeadersExtra = new List<KeyValuePair<string, string>>(requestHeaders);
            if (jsonRequestBody != null)
            {
                requestHeadersExtra.Add(new KeyValuePair<string, string>("Content-Type", "application/json; charset=UTF-8"));
            }

            using (Stream requestStream = new MemoryStream(Encoding.UTF8.GetBytes(jsonRequestBody)))
            {
                return DoWebActionOnce(
                    url,
                    "POST",
                    requestStream,
                    responseBodyDestination,
                    requestHeadersExtra.ToArray(),
                    responseHeadersExtraOut,
                    out webStatusCodeOut,
                    out httpStatusCodeOut,
                    null/*progressTrackerUpload*/,
                    null/*progressTrackerDownload*/,
                    accessTokenOverride,
                    trace,
                    faultInstanceContext);
            }
        }

        protected bool DoWebActionJSON2JSONWithRetry(string url, string verb, string jsonRequestBody, out string jsonResponseBody, out WebExceptionStatus webStatusCodeOut, out HttpStatusCode httpStatusCodeOut, TextWriter trace, IFaultInstance faultInstanceContext)
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
                    bool result = DoWebActionWithRetry(
                        url,
                        verb,
                        requestStream,
                        responseStream,
                        requestHeadersExtra.ToArray(),
                        responseHeadersExtra,
                        out webStatusCodeOut,
                        out httpStatusCodeOut,
                        null/*progressTracker*/,
                        null/*accessTokenOverride*/,
                        trace,
                        faultInstanceContext);

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

        protected bool DoWebActionGetBinaryOnce(string url, KeyValuePair<string, string>[] requestHeaders, Stream responseBodyBinary, KeyValuePair<string, string>[] responseHeadersOut, out WebExceptionStatus webStatusCodeOut, out HttpStatusCode httpStatusCodeOut, ProgressTracker progressTrackerDownload, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            List<KeyValuePair<string, string>> requestHeadersList = new List<KeyValuePair<string, string>>();
            if (requestHeaders != null)
            {
                requestHeadersList.AddRange(requestHeaders);
            }
            requestHeadersList.Add(new KeyValuePair<string, string>("Accept", "application/octet-stream"));

            using (MemoryStream responseStream = new MemoryStream())
            {
                bool result = DoWebActionOnce(
                    url,
                    "GET",
                    null/*requestBodySource*/,
                    responseBodyBinary,
                    requestHeadersList.ToArray(),
                    responseHeadersOut,
                    out webStatusCodeOut,
                    out httpStatusCodeOut,
                    null/*progressTrackerUpload*/,
                    progressTrackerDownload,
                    null/*accessTokenOverride*/,
                    trace,
                    faultInstanceContext);
                return result;
            }
        }

        protected bool DownloadFileWithResume(string url, Stream streamDownloadInto, long? expectedFileSize, ProgressTracker progressTracker, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            // ProgressTracker is problematic here because we don't have the download target
            // length until response headers are recieved. Callee has to update for us.

            if (trace != null)
            {
                trace.WriteLine("+DownloadFileWithResume(url={0})", url);
            }

            long? totalContentLength = null;
            int retry = 0;
            long previousLengthSoFar = 0;
        Retry:
            List<KeyValuePair<string, string>> requestHeaders = new List<KeyValuePair<string, string>>(1);
            if (totalContentLength.HasValue)
            {
                requestHeaders.Add(new KeyValuePair<string, string>("Range", String.Format("bytes={0}-{1}", streamDownloadInto.Position, totalContentLength.Value - 1)));
            }
            KeyValuePair<string, string>[] responseHeaders = new KeyValuePair<string, string>[]
            {
                new KeyValuePair<string, string>("Content-Length", null),
            };
            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionGetBinaryOnce(
                url,
                requestHeaders.ToArray(),
                streamDownloadInto,
                responseHeaders,
                out webStatusCode,
                out httpStatusCode,
                progressTracker,
                trace,
                faultInstanceContext);

            if ((httpStatusCode == (HttpStatusCode)200) && !totalContentLength.HasValue && (responseHeaders[0].Value != null))
            {
                totalContentLength = Int64.Parse(responseHeaders[0].Value);
                if (trace != null)
                {
                    trace.WriteLine("setting totalContentLength to {0}", totalContentLength.Value);
                }
            }
            if (!totalContentLength.HasValue && expectedFileSize.HasValue)
            {
                // If no Content-Length header was returned (e.g. because of failed chunked transfer),
                // caller may know the expected file length (due to metadata) and can override that
                // by passing in value for expectedFileSize.
                totalContentLength = expectedFileSize.Value;
            }
            if (!totalContentLength.HasValue)
            {
                streamDownloadInto.Position = 0;
                streamDownloadInto.SetLength(0); // must restart if received no content length header
                if (trace != null)
                {
                    trace.WriteLine("content length unknown, resetting target stream");
                }
            }

            if (!result || !totalContentLength.HasValue || (streamDownloadInto.Position != totalContentLength.Value))
            {
                if (totalContentLength.HasValue && (streamDownloadInto.Position > totalContentLength.Value))
                {
                    if (trace != null)
                    {
                        trace.WriteLine("-DownloadFileWithResume throws - stream position exceeds content length");
                    }
                    throw new InvalidOperationException();
                }

                retry++;
                if (previousLengthSoFar < streamDownloadInto.Position)
                {
                    retry = 0; // if we made progress then reset retry counter
                    previousLengthSoFar = streamDownloadInto.Position;
                }
                if (retry > RetryHelper.MaxRetries)
                {
                    if (trace != null)
                    {
                        trace.WriteLine("-DownloadFileWithResume returns False");
                    }
                    return false;
                }

                RetryHelper.WaitExponentialBackoff(retry, trace);

                goto Retry;
            }

            if (trace != null)
            {
                trace.WriteLine("-DownloadFileWithResume returns True");
            }
            return true;
        }
    }

    class MicrosoftOneDriveWebMethods : WebMethodsBase, IWebMethods
    {
        // Desktop application tutorial: http://msdn.microsoft.com/en-us/library/dn631817.aspx
        // REST API - Files: http://msdn.microsoft.com/en-us/library/dn631834.aspx
        // REST API - Folders: http://msdn.microsoft.com/en-us/library/dn631836.aspx

        public MicrosoftOneDriveWebMethods(RemoteAccessControl remoteAccessControl, IPAddress socks5Address, int socks5Port, TextWriter trace, IFaultInstance faultInstanceContext)
            : base(remoteAccessControl, false/*enableResumableUploads*/, socks5Address, socks5Port)
        {
            if (trace != null)
            {
                trace.WriteLine("*MicrosoftOneDriveWebMethods constructor");
            }

#if false
            RegisterPinnedCertificates(
                true/*enable*/,
                new KeyValuePair<string, string[]>[]
                {
                    new KeyValuePair<string, string[]>("storage.live.com", new string [] { "3082010A0282010100B28A747C7A57775A4E67CDCDA0380167AEE06E34261DDF2FBE8BB954C9CB506E380ECE9A2FEA8F00442AA2B539835AC8F30C92E29D9CF26110109D775E39C07C8322F6CE4D10DA5DA08BA48311BE0F4E49113E9DE4D75CE1E4FEE39AD58351B8AE7F8EB750653DF5F8E439B9D040ABC570EFBD4454FA96B87D74149E5768D3375EDFFE531476038A28A73E5660B7205C1257397A74440E688D1BE0BA5AC8841ABBB2EE6B2164A62C7329E148DDD1389C7C20DD6CFF2D1ECEF07D2369062DD80C1AB7F06638703C36730BC1FFEEB434A09C535BDEC2EB95ECB8676672326327B3CB15F326814CD3803DA0AC2F0835D4BC04FA6183FE4B2D680F20EDDFDFF4F76F0203010001" }),
                    new KeyValuePair<string, string[]>("apis.live.net", new string [] { "3082010A0282010100B28A747C7A57775A4E67CDCDA0380167AEE06E34261DDF2FBE8BB954C9CB506E380ECE9A2FEA8F00442AA2B539835AC8F30C92E29D9CF26110109D775E39C07C8322F6CE4D10DA5DA08BA48311BE0F4E49113E9DE4D75CE1E4FEE39AD58351B8AE7F8EB750653DF5F8E439B9D040ABC570EFBD4454FA96B87D74149E5768D3375EDFFE531476038A28A73E5660B7205C1257397A74440E688D1BE0BA5AC8841ABBB2EE6B2164A62C7329E148DDD1389C7C20DD6CFF2D1ECEF07D2369062DD80C1AB7F06638703C36730BC1FFEEB434A09C535BDEC2EB95ECB8676672326327B3CB15F326814CD3803DA0AC2F0835D4BC04FA6183FE4B2D680F20EDDFDFF4F76F0203010001" }),
                },
                trace);
#endif
        }

        public override HttpStatusCode RateLimitStatusCode { get { return (HttpStatusCode)420; } }
        public override string RateLimitRetryAfterHeader { get { return "Retry-After"; } }

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

        public RemoteFileSystemEntry[] RemoteGetFileSystemEntries(string folderId, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (trace != null)
            {
                trace.WriteLine("+RemoteGetFileSystemEntries(folderId={0})", folderId);
            }

            string url = String.Format("{0}?pretty=false", FileIdToUploadLocation(folderId, false/*content*/));

            string response;
            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionJSON2JSONWithRetry(
                url,
                "GET",
                null/*jsonRequestBody*/,
                out response,
                out webStatusCode,
                out httpStatusCode,
                trace,
                faultInstanceContext);
            if (!result)
            {
                if (trace != null)
                {
                    trace.WriteLine("-RemoteGetFileSystemEntries result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new ApplicationException("Failure occurred accessing remote service");
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

            if (trace != null)
            {
                trace.WriteLine("  return {0} items", items.Length);
                for (int i = 0; i < items.Length; i++)
                {
                    trace.WriteLine("  [{0}]: {1}", i, items[i]);
                }
                trace.WriteLine("-RemoteGetFileSystemEntries");
                trace.WriteLine();
            }

            return items;
        }

        public RemoteFileSystemEntry NavigateRemotePath(string remotePath, bool includeLast, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (trace != null)
            {
                trace.WriteLine("+NavigateRemotePath(remotePath={0}, includeLast={1})", remotePath, includeLast);
            }

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
                RemoteFileSystemEntry[] entries = RemoteGetFileSystemEntries(currentDirectory.Id, trace, faultInstanceContext);
                int index = Array.FindIndex(entries, delegate(RemoteFileSystemEntry candidate) { return candidate.Name.Equals(remotePathPart); });
                if (index < 0)
                {
                    throw new FileNotFoundException(String.Format("remote:{0}", remotePathPart));
                }
                currentDirectory = entries[index];
            }
            return currentDirectory;
        }

        public void DownloadFile(string fileId, Stream streamDownloadInto, ProgressTracker progressTracker, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (trace != null)
            {
                trace.WriteLine("+DownloadFile(fileId={0})", fileId);
            }

            string url = String.Format("{0}?pretty=false", FileIdToUploadLocation(fileId, true/*content*/));

            if (!DownloadFileWithResume(url, streamDownloadInto, null/*expectedFileSize*/, progressTracker, trace, faultInstanceContext))
            {
                if (trace != null)
                {
                    trace.WriteLine("-DownloadFile throw", fileId);
                }
                throw new ApplicationException("Failure occurred accessing remote service");
            }

            if (trace != null)
            {
                trace.WriteLine("-DownloadFile", fileId);
            }
        }

        public RemoteFileSystemEntry UploadFile(string folderId, string remoteName, Stream streamUploadFrom, ProgressTracker progressTracker, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            // TODO: figure out if there is support yet for resumable uploads on OneDrive Live
            // API (doesn't appear so as of 2014-09-01).

            if (trace != null)
            {
                trace.WriteLine("+UploadFile(folderId={0}, name={1})", folderId, remoteName);
            }

            if (progressTracker != null)
            {
                progressTracker.UpdateTotal(streamUploadFrom.Length);
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
                bool result = DoWebActionWithRetry(
                    url,
                    "PUT",
                    streamUploadFrom,
                    responseStream,
                    null/*requestHeaders*/,
                    responseHeaders,
                    out webStatusCode,
                    out httpStatusCode,
                    progressTracker,
                    null/*accessTokenOverride*/,
                    trace,
                    faultInstanceContext);
                if (!result)
                {
                    if (trace != null)
                    {
                        trace.WriteLine("-UploadFile result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                    }

                    if (httpStatusCode == (HttpStatusCode)413)
                    {
                        throw new ApplicationException("The file is larger than permitted by the remote service. Reduce the target segment size or turn off the -nosplitlargefiles option if enabled.");
                    }

                    throw new ApplicationException("Failure occurred accessing remote service");
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

            JSONDictionary metadata = new JSONDictionary(response);
            string fileId, name;
            if (!metadata.TryGetValueAs("id", out fileId)
                || !metadata.TryGetValueAs("name", out name))
            {
                throw new InvalidDataException();
            }
            Debug.Assert(name == remoteName); // if fails then TODO handle remote auto name adjustment

            RemoteFileSystemEntry entry = GetFileMetadata(fileId, trace, faultInstanceContext);
            Debug.Assert(entry.Name == remoteName); // if fails then TODO handle remote auto name adjustment

            if (trace != null)
            {
                trace.WriteLine("-UploadFile returns {0}", entry);
                trace.WriteLine();
            }
            return entry;
        }

        private RemoteFileSystemEntry GetFileMetadata(string fileId, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (trace != null)
            {
                trace.WriteLine("+GetFileMetadata(id={0})", fileId);
            }

            string url = String.Format("https://apis.live.net/v5.0/{0}?pretty=false", fileId);

            string response;

            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionJSON2JSONWithRetry(
                url,
                "GET",
                null/*jsonRequestBody*/,
                out response,
                out webStatusCode,
                out httpStatusCode,
                trace,
                faultInstanceContext);
            if (!result)
            {
                if (trace != null)
                {
                    trace.WriteLine("-GetFileMetadata result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new ApplicationException("Failure occurred accessing remote service");
            }

            JSONDictionary metadata = new JSONDictionary(response);
            RemoteFileSystemEntry entry = FileSystemEntryFromJSON(metadata);

            if (trace != null)
            {
                trace.WriteLine("-GetFileMetadata returns {0}", entry);
                trace.WriteLine();
            }

            return entry;
        }

        public void DeleteFile(string fileId, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (trace != null)
            {
                trace.WriteLine("+DeleteFile(id={0})", fileId);
            }

            // http://msdn.microsoft.com/en-us/library/dn659743.aspx#delete_a_file

            string url = String.Format("https://apis.live.net/v5.0/{0}", fileId);

            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionWithRetry(
                url,
                "DELETE",
                null/*requestBodySource*/,
                null/*responseBodyDestination*/,
                null/*requestHeaders*/,
                null/*responseHeadersOut*/,
                out webStatusCode,
                out httpStatusCode,
                null/*progressTracker*/,
                null/*accessTokenOverride*/,
                trace,
                faultInstanceContext);
            if (!result)
            {
                if (trace != null)
                {
                    trace.WriteLine("-DeleteFile result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new ApplicationException("Failure occurred accessing remote service");
            }

            if (trace != null)
            {
                trace.WriteLine("-DeleteFile");
                trace.WriteLine();
            }
        }

        public RemoteFileSystemEntry RenameFile(string fileId, string newName, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (trace != null)
            {
                trace.WriteLine("+RenameFile(id={0}, newName={1})", fileId, newName);
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
            bool result = DoWebActionJSON2JSONWithRetry(
                url,
                "PUT",
                requestBody,
                out response,
                out webStatusCode,
                out httpStatusCode,
                trace,
                faultInstanceContext);
            if (!result)
            {
                if (trace != null)
                {
                    trace.WriteLine("-RenameFile result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new ApplicationException("Failure occurred accessing remote service");
            }

            JSONDictionary metadata = new JSONDictionary(response);
            RemoteFileSystemEntry entry = FileSystemEntryFromJSON(metadata);

            if (trace != null)
            {
                trace.WriteLine("-RenameFile returns {0}", entry);
                trace.WriteLine();
            }

            return entry;
        }

        public void GetQuota(out long quotaTotal, out long quotaUsed, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (trace != null)
            {
                trace.WriteLine("+GetQuota()");
            }

            string url = "https://apis.live.net/v5.0/me/skydrive/quota?pretty=false";

            string response;
            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionJSON2JSONWithRetry(
                url,
                "GET",
                null/*requestBody*/,
                out response,
                out webStatusCode,
                out httpStatusCode,
                trace,
                faultInstanceContext);
            if (!result)
            {
                if (trace != null)
                {
                    trace.WriteLine("-GetQuota result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new ApplicationException("Failure occurred accessing remote service");
            }

            JSONDictionary metadata = new JSONDictionary(response);
            long total, available;
            if (!metadata.TryGetValueAs("quota", out total)
                || !metadata.TryGetValueAs("available", out available))
            {
                throw new InvalidDataException();
            }

            quotaTotal = total;
            quotaUsed = total - available;

            if (trace != null)
            {
                trace.WriteLine("-GetQuota total={0} used={1}", quotaTotal, quotaUsed);
                trace.WriteLine();
            }
        }
    }

    class GoogleDriveWebMethods : WebMethodsBase, IWebMethods
    {
        // Desktop application tutorial: https://developers.google.com/accounts/docs/OAuth2InstalledApp
        // https://developers.google.com/drive/v2/reference/

        public GoogleDriveWebMethods(RemoteAccessControl remoteAccessControl, IPAddress socks5Address, int socks5Port, TextWriter trace, IFaultInstance faultInstanceContext)
            : base(remoteAccessControl, true/*enableResumableUploads*/, socks5Address, socks5Port)
        {
            if (trace != null)
            {
                trace.WriteLine("*GoogleDriveWebMethods constructor");
            }

#if false
            RegisterPinnedCertificates(
                true/*enable*/,
                new KeyValuePair<string, string[]>[]
                {
                    new KeyValuePair<string, string[]>("*.googleapis.com", new string [] { "3082010A0282010100871681B4AD11115CA845C7B1E2E71AAC60E567384D74BD8D5F2B021BEBBD71DCAA43C0F60E27F54C74882E0196467CCE256A6DA51012FA4545EA1B0E79D418FD98B763B8997FE7B0361235E31D52BDCC56808D6BA50AF3DA093EE6B96C866D0A9017AF77DE92D9C2FBB68AC5A27129ECE8258CA19AADD78BD1FAC89FE98998AAB1580B13B6A06864CFA02FEADBF88F6F329D4FFDE7017377CBA12CB6DFB2B9DFD28008CC77A1C82F5EAD25DAA126BFF8F5F2E1C20B57E4D12A2285A4CF4D195E2624B898824D881C7E6ED25B9186BFA2CEB8311133F3A561F8CF2053159C142673BFFB3122835FB4688BF9E71215E1D00FE8F8B8D71C95FE14F741491BD6F45D0203010001", "3082010A0282010100A2F3015AA21CB61F435E979B7E5412B9FF0EBCA529A2F3EB0B5EE8231F0A7E7FEEC14ECC5E728F81201E26FBE5491E7306432C62A2A5ED460481ADAF3528FAB5D18C1921F972A4B15FBAA718BB746FE613AF32B1C53F02945023378F3CBDD9554C5DFE5A4979B5092D3D779F170C9A0458B39FCB0367C44C350172850ABB5D2511A561FE679BE4AAD8EFE9224B81DEC84B8BE8F50E595F6E1B0D27503CF78CBDD330DF9B899AE8B50F1A3A8580987559E514DCDFB5CD045B2C4E84D1DD5EE3738231CC41F45D8BC3ECB0C5380934A8C5C14BDCC72DE803CBAB19B13F61BA108A0F1DD95F4DCB2E026F96587DBE6BE910A9CA6EA821FC58C9E0E54F3DC5D428930203010001" }),
                    new KeyValuePair<string, string[]>("*.googleusercontent.com", new string [] { "3082010A0282010100BFD0A9D3BD4C7F491A17E831F1A506CFCF45D44F397D614112C9D922739D927435586CCE731BDE2D41C29CD0933EBF4A151F818AAD2689B1A868233FA75164C9F58EC620E3D77B4E591D14607A987580634220862083EAF9FCBA5A7A5C8A65D13CF7D5B926B17BE82540D7FADE62E5FBBDB8296AB02230A951178241D6CC82D3716A6675E7BC5E4B448549AC0A16238A171A8B3455FDCB7DDB83DF2A4B1852FD31DBC864C7B63B273C43FF85C796D631E8AD142CBDAE0DB893AB345950F5CA6F5C5371E6411CD4CF51E6380E9AA712861CE30D27FEEB0C63DD4C6802E469D03E07F9E9B4B312AF658A75C831A807A4CAD59DB2B42900424CC7E79807279D09F30203010001", "040832C5DD28F7CB7E5AC3E6ED87F359474DC80C86FA3816EA6E4418B0254A0FCF6439D668FA99D8A2165924765582F553B2C43B99B5617F0A3D1BEAB5308CD621", "048064BE97D4F87254BFD7A2F480E94F15B2A480408CCB3FDD13DC242923607A31D840B7689CE9579EA03F204718F4081804D330A041C718CE3B5951F26A05DB0A" }),
                },
                trace);
#endif
        }

        public override HttpStatusCode RateLimitStatusCode { get { return (HttpStatusCode)403; } }
        public override string RateLimitRetryAfterHeader { get { return null; } }

        private const string SelfLinkUrlPrefix = "https://www.googleapis.com/drive/v2/files/";

        private static string FileIdToSelfLink(string fileId)
        {
            return SelfLinkUrlPrefix + fileId;
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

        public RemoteFileSystemEntry[] RemoteGetFileSystemEntries(string folderId, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            List<RemoteFileSystemEntry> aggregateItems = new List<RemoteFileSystemEntry>();

            if (trace != null)
            {
                trace.WriteLine("+RemoteGetFileSystemEntries(folderId={0})", folderId);
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
                // Add the "q" query search parameter to restrict set of items to search criteria
                // (either root folder or specified folderId)
                // (see https://developers.google.com/drive/web/search-parameters)
                string search = String.Format("'{0}' in parents", String.IsNullOrEmpty(folderId) ? "root" : folderId);
                if (!String.IsNullOrEmpty(search))
                {
                    url = String.Concat(url, url.IndexOf('?') < 0 ? "?" : "&", "q=", HttpUtility.UrlEncode(search));
                }
                // Add the "fields" query parameter to reduce the amount of json fields returned
                // to just the relevant ones. These are consumed in the code below in this method,
                // but see also GoogleDriveWebMethods.FileSystemEntryFromJSON().
                // (see https://developers.google.com/drive/web/performance#partial-response)
                const string fields = "nextPageToken,items(id,title,mimeType,createdDate,modifiedDate,fileSize,labels/hidden,labels/trashed,parents(id,parentLink,isRoot))";
                if (!String.IsNullOrEmpty(fields))
                {
                    url = String.Concat(url, url.IndexOf('?') < 0 ? "?" : "&", "fields=", fields);
                }


                string response;
                WebExceptionStatus webStatusCode;
                HttpStatusCode httpStatusCode;
                bool result = DoWebActionJSON2JSONWithRetry(
                    url,
                    "GET",
                    null/*jsonRequestBody*/,
                    out response,
                    out webStatusCode,
                    out httpStatusCode,
                    trace,
                    faultInstanceContext);
                if (!result)
                {
                    if (trace != null)
                    {
                        trace.WriteLine("-GetRemoteFlatFilesList result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                    }
                    throw new ApplicationException("Failure occurred accessing remote service");
                }


                // NOTICE: if you change the fields being accessed (including in FileSystemEntryFromJSON()
                // or relating to GoogleDriveParent) make sure to change the "fields" restriction
                // above in this method or the json won't have your fields!

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
                RemoteFileSystemEntry[] items = new RemoteFileSystemEntry[entries.Length];
                for (int i = 0; i < entries.Length; i++)
                {
                    RemoteFileSystemEntry entry = FileSystemEntryFromJSON(entries[i]);

                    items[i] = entry;
                }

                if (trace != null)
                {
                    trace.WriteLine("  create {0} items", items.Length);
                    for (int i = 0; i < items.Length; i++)
                    {
                        trace.WriteLine("  [{0}]: {1}", i, items[i]);
                    }
                }

                aggregateItems.AddRange(items);

            } while (pageToken != null);


            if (trace != null)
            {
                trace.WriteLine("-RemoteGetFileSystemEntries total={0}", aggregateItems.Count);
                trace.WriteLine();
            }

            return aggregateItems.ToArray();
        }

        public RemoteFileSystemEntry NavigateRemotePath(string remotePath, bool includeLast, TextWriter trace, IFaultInstance faultInstanceContext)
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

            RemoteFileSystemEntry currentDirectory = new RemoteFileSystemEntry(null/*folderId*/, null, true, default(DateTime), default(DateTime), -1);
            for (int i = 1; i < remotePathPartsLength; i++)
            {
                string remotePathPart = remotePathParts[i];
                RemoteFileSystemEntry[] entries = RemoteGetFileSystemEntries(currentDirectory.Id, trace, faultInstanceContext);
                int index = Array.FindIndex(entries, delegate(RemoteFileSystemEntry candidate) { return candidate.Name.Equals(remotePathPart); });
                if (index < 0)
                {
                    throw new FileNotFoundException(String.Format("remote:{0}", remotePathPart));
                }
                currentDirectory = entries[index];
            }
            return currentDirectory;
        }

        public void DownloadFile(string fileId, Stream streamDownloadInto, ProgressTracker progressTracker, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (trace != null)
            {
                trace.WriteLine("+DownloadFile(fileId={0})", fileId);
            }

            string url = FileIdToSelfLink(fileId);

            string response;
            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionJSON2JSONWithRetry(
                url,
                "GET",
                null/*jsonRequestBody*/,
                out response,
                out webStatusCode,
                out httpStatusCode,
                trace,
                faultInstanceContext);
            if (!result)
            {
                if (trace != null)
                {
                    trace.WriteLine("-DownloadFile result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new ApplicationException("Failure occurred accessing remote service");
            }

            JSONDictionary metadata = new JSONDictionary(response);
            string downloadUrl;
            if (!metadata.TryGetValueAs("downloadUrl", out downloadUrl))
            {
                throw new InvalidDataException();
            }

            // Google sometimes uses chunked transfer, which would prevent resumption of
            // failed transfer because Content-Length can't be known in that case. However,
            // the metadata has the "fileSize" property which can be used to override the
            // lack of a header.
            string fileSize;
            if (!metadata.TryGetValueAs("fileSize", out fileSize))
            {
                throw new InvalidDataException();
            }
            long fileSizeBytes = Int64.Parse(fileSize);


            // https://developers.google.com/drive/web/manage-downloads

            if (!DownloadFileWithResume(downloadUrl, streamDownloadInto, fileSizeBytes, progressTracker, trace, faultInstanceContext))
            {
                if (trace != null)
                {
                    trace.WriteLine("-DownloadFile throw", fileId);
                }
                throw new ApplicationException("Failure occurred accessing remote service");
            }

            if (trace != null)
            {
                trace.WriteLine("-DownloadFile", fileId);
            }
        }

        public RemoteFileSystemEntry UploadFile(string folderId, string remoteName, Stream streamUploadFrom, ProgressTracker progressTrackerUpload, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (remoteName.IndexOf('"') >= 0)
            {
                throw new ArgumentException();
            }

            if (trace != null)
            {
                trace.WriteLine("+UploadFile(folderId={0}, name={1})", folderId, remoteName);
            }

            if (progressTrackerUpload != null)
            {
                progressTrackerUpload.UpdateTotal(streamUploadFrom.Length);
            }

            // https://developers.google.com/drive/v2/reference/files/insert
            // https://developers.google.com/drive/web/manage-uploads

            string accessTokenOverride = null;
            WebExceptionStatus webStatusCode = (WebExceptionStatus)0;
            HttpStatusCode httpStatusCode = (HttpStatusCode)0;
            bool result = false;

            int startOver = -1;
        StartOver:
            // per documentation - 404 during resumable upload should be handled by starting over
            startOver++;
            if (trace != null)
            {
                trace.WriteLine(" entering StartOver region (startOver={0})", startOver);
            }
            if (startOver > RetryHelper.MaxRetries)
            {
                const string SurrenderMessage = "Upload failed to finish after max start-overs; giving up.";
                if (trace != null)
                {
                    trace.WriteLine("-UploadFile throws: {0}", SurrenderMessage);
                }
                throw new ApplicationException(SurrenderMessage);
            }
            else
            {
                RetryHelper.WaitExponentialBackoff(startOver, trace);
            }

            if (httpStatusCode == (HttpStatusCode)401)
            {
                if (trace != null)
                {
                    trace.WriteLine("Last http response was 401; asking to invalidating access token");
                }
                remoteAccessControl.InvalidateAccessToken(accessTokenOverride, trace);
            }
            if (trace != null)
            {
                trace.WriteLine("Acquiring access token (RemoteAccessControl.AccessToken)");
            }
            accessTokenOverride = remoteAccessControl.GetAccessToken(trace);
            if (trace != null)
            {
                trace.WriteLine("Acquired access token (RemoteAccessControl.AccessToken): {0}", LogWriter.ScrubSecuritySensitiveValue(accessTokenOverride));
            }

            streamUploadFrom.Position = 0;


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
                result = DoWebActionPostJSONOnce(
                    url,
                    message/*jsonRequestBody*/,
                    null/*responseBodyDestination*/,
                    requestHeaders,
                    responseHeaders,
                    out webStatusCode,
                    out httpStatusCode,
                    accessTokenOverride,
                    trace,
                    faultInstanceContext.Select("UploadFile", "1"));
                if (!result)
                {
                    if (trace != null)
                    {
                        trace.WriteLine(" DoWebActionPostJSONOnce failed: result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                    }
                    goto StartOver;
                }

                sessionLocation = responseHeaders[0].Value;
            }

            bool resuming = false;
            long previousLengthSoFar = 0;
            int retry = -1;
        Retry:
            retry++;
            if (trace != null)
            {
                trace.WriteLine(" entering Retry region (retry={0})", retry);
            }
            if (retry > RetryHelper.MaxRetries)
            {
                const string SurrenderMessage = "Upload failed to make progress after max retries; giving up.";
                if (trace != null)
                {
                    trace.WriteLine("-UploadFile throws: {0}", SurrenderMessage);
                }
                throw new ApplicationException(SurrenderMessage);
            }
            else
            {
                RetryHelper.WaitExponentialBackoff(retry, trace);
            }
            if (!resuming)
            {
                // 2a. put data to the session uri (unranged)

                {
                    string url = sessionLocation;
                    KeyValuePair<string, string>[] responseHeaders = new KeyValuePair<string, string>[]
                    {
                        new KeyValuePair<string, string>("Content-Type", null),
                    };
                    using (MemoryStream responseStream = new MemoryStream())
                    {
                        result = DoWebActionOnce(
                            url,
                            "PUT",
                            streamUploadFrom,
                            responseStream,
                            null/*requestHeaders*/,
                            responseHeaders,
                            out webStatusCode,
                            out httpStatusCode,
                            progressTrackerUpload,
                            null/*progressTrackerDownload*/,
                            accessTokenOverride,
                            trace,
                            faultInstanceContext.Select("UploadFile", "2a"));

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
                        }
                        else
                        {
                            if (trace != null)
                            {
                                trace.WriteLine(" DoWebActionOnce failure - result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                            }

                            if ((httpStatusCode >= (HttpStatusCode)400) && (httpStatusCode <= (HttpStatusCode)499))
                            {
                                goto StartOver;
                            }

                            resuming = true; // trigger resume logic
                            goto Retry;
                        }
                    }
                }
            }
            else
            {
                // 2b. handle upload resume

                // https://developers.google.com/drive/web/manage-uploads#resume-upload

                if (trace != null)
                {
                    trace.WriteLine(" attempting to resume upload");
                }

                // 2b-1&2. request status and number of bytes uploaded so far

                string rangeResponseHeader;

                KeyValuePair<string, string>[] responseHeaders = new KeyValuePair<string, string>[]
                {
                    new KeyValuePair<string, string>("Content-Type", null), // for completed upload - expecting application/json
                    new KeyValuePair<string, string>("Range", null), // for resumed upload
                };
                using (MemoryStream responseStream = new MemoryStream())
                {
                    string url = sessionLocation;
                    KeyValuePair<string, string>[] requestHeaders = new KeyValuePair<string, string>[]
                    {
                        new KeyValuePair<string, string>("Content-Range", String.Format("bytes */{0}", streamUploadFrom.Length)),
                        // Content-Length: 0 added by DoWebAction
                    };
                    result = DoWebActionOnce(
                        url,
                        "PUT",
                        null,
                        responseStream,
                        requestHeaders,
                        responseHeaders,
                        out webStatusCode,
                        out httpStatusCode,
                        null/*progressTrackerUpload*/,
                        null/*progressTrackerDownload*/,
                        accessTokenOverride,
                        trace,
                        faultInstanceContext.Select("UploadFile", "2b-1"));

                    response = Encoding.UTF8.GetString(responseStream.ToArray());
                }

                if ((httpStatusCode == (HttpStatusCode)0) || ((httpStatusCode >= (HttpStatusCode)500) && (httpStatusCode <= (HttpStatusCode)599)))
                {
                    goto Retry;
                }
                if ((httpStatusCode >= (HttpStatusCode)400) && (httpStatusCode <= (HttpStatusCode)499))
                {
                    goto StartOver;
                }
                else if ((httpStatusCode == (HttpStatusCode)200) || (httpStatusCode == (HttpStatusCode)201))
                {
                    if (responseHeaders[0].Value == "application/json; charset=UTF-8")
                    {
                        // "response" variable already set above
                    }
                    else
                    {
                        throw new InvalidDataException(String.Format("Unhandled response Content-Type: {0} (expected {1})", responseHeaders[0].Value, "application/json; charset=UTF-8"));
                    }

                    // actually done (all bytes managed to make it to the server)
                }
                else if (httpStatusCode != (HttpStatusCode)308)
                {
                    try
                    {
                        JSONDictionary json = new JSONDictionary(response);
                        JSONDictionary error;
                        long code;
                        if (json.TryGetValueAs("error", out error)
                            && error.TryGetValueAs("code", out code))
                        {
                            if ((code >= 500) && (code <= 599))
                            {
                                goto StartOver;
                            }
                            else
                            {
                                httpStatusCode = (HttpStatusCode)code;
                            }
                        }
                    }
                    catch (Exception)
                    {
                    }

                    if (trace != null)
                    {
                        trace.WriteLine("-DoWebAction throw: unexpected HTTP result code: webStatusCode={0} ({1}), httpStatusCode={2} ({3})", (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                    }
                    throw new InvalidDataException();
                }
                else // httpStatusCode == (HttpStatusCode)308
                {
                    rangeResponseHeader = responseHeaders[1].Value;

                    // 2b-3. upload remaining data

                    if (trace != null)
                    {
                        trace.WriteLine(" range response header={0}", rangeResponseHeader);
                    }

                    if (!String.IsNullOrEmpty(rangeResponseHeader))
                    {
                        const string BytesPrefix = "bytes=";
                        if (!rangeResponseHeader.StartsWith(BytesPrefix))
                        {
                            if (trace != null)
                            {
                                trace.WriteLine("-DoWebAction throw: invalid range header format");
                            }
                            throw new InvalidDataException();
                        }
                        string[] parts = rangeResponseHeader.Substring(BytesPrefix.Length).Split(new char[] { '-' });
                        if (parts.Length != 2)
                        {
                            if (trace != null)
                            {
                                trace.WriteLine("-DoWebAction throw: invalid range header format");
                            }
                            throw new InvalidDataException();
                        }
                        long rangeStart = Int64.Parse(parts[0]);
                        if (rangeStart != 0)
                        {
                            if (trace != null)
                            {
                                trace.WriteLine("-DoWebAction throw: unexpected range header value");
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

                    if (previousLengthSoFar < streamUploadFrom.Position)
                    {
                        // made progress
                        previousLengthSoFar = streamUploadFrom.Position;
                        retry = 0;
                    }

                    responseHeaders = new KeyValuePair<string, string>[]
                    {
                        new KeyValuePair<string, string>("Content-Type", null),
                    };
                    using (MemoryStream responseStream = new MemoryStream())
                    {
                        string url = sessionLocation;
                        KeyValuePair<string, string>[] requestHeaders = new KeyValuePair<string, string>[]
                        {
                            new KeyValuePair<string, string>("Content-Range", String.Format("bytes {0}-{1}/{2}", streamUploadFrom.Position, streamUploadFrom.Length - 1, streamUploadFrom.Length)),
                            // Content-Length computed by DoWebAction based on stream length and position
                        };
                        result = DoWebActionOnce(
                            url,
                            "PUT",
                            streamUploadFrom,
                            responseStream,
                            requestHeaders,
                            responseHeaders,
                            out webStatusCode,
                            out httpStatusCode,
                            progressTrackerUpload,
                            null/*progressTrackerDownload*/,
                            accessTokenOverride,
                            trace,
                            faultInstanceContext.Select("UploadFile", "2b-3"));
                        response = Encoding.UTF8.GetString(responseStream.ToArray());
                    }

                    if (result)
                    {
                        if (responseHeaders[0].Value == "application/json; charset=UTF-8")
                        {
                            // response variable set above
                        }
                        else
                        {
                            throw new InvalidDataException(String.Format("Unhandled response Content-Type: {0} (expected {1})", responseHeaders[0].Value, "application/json; charset=UTF-8"));
                        }

                        // finished
                    }
                    else
                    {
                        if (trace != null)
                        {
                            trace.WriteLine(" DoWebAction failure - result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                        }

                        if (httpStatusCode == (HttpStatusCode)404)
                        {
                            goto StartOver;
                        }

                        resuming = true; // trigger resume logic
                        goto Retry;
                    }
                }
            }


            if (trace != null)
            {
                trace.WriteLine(" entering post-processing region");
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
                if (!Core.ArrayEqual(md5ChecksumLocal, HexUtility.HexDecode(md5Checksum)))
                {
                    string error = String.Format("UploadFile md5 checksum does not match (name={0}, remote={1}, local={1})", remoteName, md5Checksum, HexUtility.HexEncode(md5ChecksumLocal));
                    if (trace != null)
                    {
                        trace.WriteLine("-UploadFile throw {0}", error);
                        trace.WriteLine();
                    }
                    throw new InvalidDataException(error);
                }
            }

            if (trace != null)
            {
                trace.WriteLine("-UploadFile returns {0}", entry);
                trace.WriteLine();
            }
            return entry;
        }

        public void DeleteFile(string fileId, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (trace != null)
            {
                trace.WriteLine("+DeleteFile(id={0})", fileId);
            }

            string url = String.Format("https://www.googleapis.com/drive/v2/files/{0}", fileId);

            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionWithRetry(
                url,
                "DELETE",
                null/*requestBodySource*/,
                null/*responseBodyDestination*/,
                null/*requestHeaders*/,
                null/*responseHeadersOut*/,
                out webStatusCode,
                out httpStatusCode,
                null/*progressTracker*/,
                null/*accessTokenOverride*/,
                trace,
                faultInstanceContext);
            if (!result)
            {
                if (trace != null)
                {
                    trace.WriteLine("-DeleteFile result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new ApplicationException("Failure occurred accessing remote service");
            }

            if (trace != null)
            {
                trace.WriteLine("-DeleteFile", fileId);
                trace.WriteLine();
            }
        }

        public RemoteFileSystemEntry RenameFile(string fileId, string newName, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (trace != null)
            {
                trace.WriteLine("+RenameFile(id={0}, newName={1})", fileId, newName);
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
            bool result = DoWebActionJSON2JSONWithRetry(
                url,
                "PATCH",
                requestBody,
                out response,
                out webStatusCode,
                out httpStatusCode,
                trace,
                faultInstanceContext);
            if (!result)
            {
                if (trace != null)
                {
                    trace.WriteLine("-RenameFile result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new ApplicationException("Failure occurred accessing remote service");
            }

            JSONDictionary metadata = new JSONDictionary(response);
            RemoteFileSystemEntry entry = FileSystemEntryFromJSON(metadata);

            if (trace != null)
            {
                trace.WriteLine("-RenameFile returns {0}", entry);
                trace.WriteLine();
            }

            return entry;
        }

        public void GetQuota(out long quotaTotal, out long quotaUsed, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (trace != null)
            {
                trace.WriteLine("+GetQuota()");
            }

            string url = "https://www.googleapis.com/drive/v2/about";

            string response;
            WebExceptionStatus webStatusCode;
            HttpStatusCode httpStatusCode;
            bool result = DoWebActionJSON2JSONWithRetry(
                url,
                "GET",
                null/*requestBody*/,
                out response,
                out webStatusCode,
                out httpStatusCode,
                trace,
                faultInstanceContext);
            if (!result)
            {
                if (trace != null)
                {
                    trace.WriteLine("-GetQuota result={0}, webStatusCode={1} ({2}), httpStatusCode={3} ({4})", result, (int)webStatusCode, webStatusCode, (int)httpStatusCode, httpStatusCode);
                }
                throw new ApplicationException("Failure occurred accessing remote service");
            }

            JSONDictionary metadata = new JSONDictionary(response);
            string quotaBytesTotal, quotaBytesUsed;
            if (!metadata.TryGetValueAs("quotaBytesTotal", out quotaBytesTotal)
                || !metadata.TryGetValueAs("quotaBytesUsed", out quotaBytesUsed))
            {
                throw new InvalidDataException();
            }

            quotaTotal = Int64.Parse(quotaBytesTotal);
            quotaUsed = Int64.Parse(quotaBytesUsed);

            if (trace != null)
            {
                trace.WriteLine("-GetQuota total={0} used={1}", quotaTotal, quotaUsed);
                trace.WriteLine();
            }
        }
    }

    public class RemoteArchiveFileManager : IArchiveFileManager
    {
        // all members should be threadsafe or read-only
        private Core.Context context;
        private RemoteAccessControl remoteAccessControl;
        private RemoteFileSystemEntry remoteDirectoryEntry; // for the folder we're writing into
        private RemoteDirectoryCache remoteDirectoryCache;
        private UncommittedList uncommittedLocalTempFiles = new UncommittedList();
        private IWebMethods remoteWebMethods;
        private readonly TextWriter masterTrace; // this is the master (root) tracelog instance

        private readonly IFaultInstance faultInstanceRoot;

        private class UncommittedList : IEnumerable<KeyValuePair<string, LocalFileCopy>>
        {
            private Dictionary<string, LocalFileCopy> uncommittedLocalTempFiles = new Dictionary<string, LocalFileCopy>(1);

            public void Clear()
            {
                lock (this)
                {
                    uncommittedLocalTempFiles.Clear();
                }
            }

            public void Add(string key, LocalFileCopy value)
            {
                lock (this)
                {
                    uncommittedLocalTempFiles.Add(key, value);
                }
            }

            public void Remove(string key)
            {
                lock (this)
                {
                    uncommittedLocalTempFiles.Remove(key);
                }
            }

            public bool TryGetValue(string key, out LocalFileCopy value)
            {
                lock (this)
                {
                    return uncommittedLocalTempFiles.TryGetValue(key, out value);
                }
            }

            public IEnumerator<KeyValuePair<string, LocalFileCopy>> GetEnumerator()
            {
                List<KeyValuePair<string, LocalFileCopy>> copy;
                lock (this)
                {
                    copy = new List<KeyValuePair<string, LocalFileCopy>>(uncommittedLocalTempFiles);
                }
                return copy.GetEnumerator();
            }

            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            {
                return GetEnumerator();
            }
        }

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
                lock (this)
                {
                    return entries.TryGetValue(name, out entry);
                }
            }

            public int Count
            {
                get
                {
                    lock (this)
                    {
                        return entries.Count;
                    }
                }
            }

            public void Update(RemoteFileSystemEntry entry)
            {
                lock (this)
                {
                    entries[entry.Name] = entry;
                }
            }

            public void Remove(string name)
            {
                lock (this)
                {
                    entries.Remove(name);
                }
            }

            public IEnumerator<RemoteFileSystemEntry> GetEnumerator()
            {
                List<RemoteFileSystemEntry> copy;
                lock (this)
                {
                    copy = new List<RemoteFileSystemEntry>(entries.Values);
                }
                return copy.GetEnumerator();
            }

            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            {
                return GetEnumerator();
            }
        }

        private RemoteArchiveFileManager()
        {
            throw new NotSupportedException();
        }


        private delegate IWebMethods CreateWebMethodsMethod(RemoteAccessControl remoteAccessControl, IPAddress socks5Address, int socks5Port, TextWriter trace, IFaultInstance faultInstanceContext);
        private static readonly KeyValuePair<string, CreateWebMethodsMethod>[] SupportedServices = new KeyValuePair<string, CreateWebMethodsMethod>[]
            {
                new KeyValuePair<string, CreateWebMethodsMethod>("onedrive.live.com", delegate(RemoteAccessControl remoteAccessControl, IPAddress socks5Address, int socks5Port, TextWriter trace, IFaultInstance faultInstanceContext) { return new MicrosoftOneDriveWebMethods(remoteAccessControl, socks5Address, socks5Port, trace, faultInstanceContext); }),
                new KeyValuePair<string, CreateWebMethodsMethod>("drive.google.com", delegate(RemoteAccessControl remoteAccessControl, IPAddress socks5Address, int socks5Port, TextWriter trace, IFaultInstance faultInstanceContext) { return new GoogleDriveWebMethods(remoteAccessControl, socks5Address, socks5Port, trace, faultInstanceContext); }),
            };

        private const string TraceFilePrefix = "remotestoragetrace";

        public RemoteArchiveFileManager(string serviceUrl, string remoteDirectory, string refreshTokenProtected, Core.Context context)
        {
            faultInstanceRoot = context.faultInjectionRoot.Select("RemoteArchiveFileManager", String.Format("serviceUrl={0}|remoteDirectory={1}", serviceUrl, remoteDirectory));

            if (context.traceEnabled)
            {
                masterTrace = LogWriter.CreateLogFile(TraceFilePrefix);
            }

            try
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

                if (masterTrace != null)
                {
                    masterTrace.WriteLine("Backup.OneDriveArchiveFileManager log - {0}", DateTime.Now);
                    masterTrace.WriteLine();
                    masterTrace.WriteLine();
                    masterTrace.WriteLine("*RemoteArchiveFileManager constructor(service={0}, directory={1})", serviceUrl, remoteDirectory);
                }

                remoteAccessControl = new RemoteAccessControl(String.Concat("https://", SupportedServices[serviceSelector].Key), true/*enableRefreshToken*/, refreshTokenProtected, masterTrace);

                remoteWebMethods = SupportedServices[serviceSelector].Value(remoteAccessControl, context.socks5Address, context.socks5Port, masterTrace, faultInstanceRoot);

                remoteDirectoryEntry = remoteWebMethods.NavigateRemotePath(remoteDirectory, true/*includeLast*/, masterTrace, faultInstanceRoot);
                if (masterTrace != null)
                {
                    masterTrace.WriteLine("Remote directory entry: {0}", remoteDirectoryEntry);
                    masterTrace.WriteLine();
                }

                remoteDirectoryCache = new RemoteDirectoryCache(remoteWebMethods.RemoteGetFileSystemEntries(remoteDirectoryEntry.Id, masterTrace, faultInstanceRoot));
            }
            catch (Exception exception)
            {
                if (masterTrace != null)
                {
                    masterTrace.WriteLine("RemoteArchiveFileManager constructor failed with exception: {0}", exception);

                    // object creation failed, Dispose() will never be called, so do it here on the
                    // trace log object to commit error message to the file.
                    masterTrace.Dispose();
                    masterTrace = null;
                }
                throw;
            }
        }

        public void Dispose()
        {
            try
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
            }
            catch (Exception exception)
            {
                if (masterTrace != null)
                {
                    masterTrace.WriteLine("RemoteArchiveFileManager.Dispose() caught exception - rethrowing: {0}", exception);
                }
                throw;
            }

            if (masterTrace != null)
            {
                masterTrace.WriteLine("*OneDriveArchiveFileManager.Dispose() - {0}", DateTime.Now);
                masterTrace.WriteLine("Goodbye!");
                masterTrace.Dispose();
            }
        }

        public ILocalFileCopy Read(string name, ProgressTracker progressTracker, TextWriter trace)
        {
            try
            {
                IFaultInstance faultInstanceMethod = faultInstanceRoot.Select("Read", name);

                RemoteFileSystemEntry entry;
                if (!remoteDirectoryCache.TryGetName(name, out entry))
                {
                    throw new FileNotFoundException(String.Format("remote:{0}", name));
                }

                LocalFileCopy localCopy = new LocalFileCopy(); // refcount==1
                using (Stream stream = localCopy.Write())
                {
                    remoteWebMethods.DownloadFile(entry.Id, stream, progressTracker, trace, faultInstanceMethod);
                }
                return localCopy; // callee calls Dispose()
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteArchiveFileManager.Read() caught exception - rethrowing: {0}", exception);
                }
                throw;
            }
        }

        public ILocalFileCopy WriteTemp(string nameTemp, TextWriter trace)
        {
            try
            {
                IFaultInstance faultInstanceMethod = faultInstanceRoot.Select("WriteTemp", nameTemp);

                using (LocalFileCopy localCopy = new LocalFileCopy())
                {
                    // refcount == 1, owned by using()

                    // Could throw if nameTemp is already used
                    uncommittedLocalTempFiles.Add(nameTemp, localCopy);
                    localCopy.AddRef(); // refcount++ for uncommittedLocalTempFiles's reference

                    return localCopy.AddRef(); // refcount++ for callee's using() reference
                }
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteArchiveFileManager.WriteTemp() caught exception - rethrowing: {0}", exception);
                }
                throw;
            }
        }

        public ILocalFileCopy GetTempExisting(string localPath, string nameTemp, TextWriter trace)
        {
            try
            {
                IFaultInstance faultInstanceMethod = faultInstanceRoot.Select("GetTempExisting", nameTemp);

                using (LocalFileCopy localCopy = new LocalFileCopy(localPath, false/*writable*/, false/*delete*/))
                {
                    // refcount == 1, owned by using()

                    // Could throw if nameTemp is already used
                    uncommittedLocalTempFiles.Add(nameTemp, localCopy);
                    localCopy.AddRef(); // refcount++ for uncommittedLocalTempFiles's reference

                    return localCopy.AddRef(); // refcount++ for callee's using() reference
                }
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteArchiveFileManager.GetTempExisting() caught exception - rethrowing: {0}", exception);
                }
                throw;
            }
        }

        public void Commit(ILocalFileCopy localFile, string nameTemp, string name, bool overwrite, ProgressTracker progressTracker, TextWriter trace)
        {
            try
            {
                IFaultInstance faultInstanceMethod = faultInstanceRoot.Select("Commit", String.Format("{0}|{1}", nameTemp, name));

                if (Exists(nameTemp, trace))
                {
                    throw new IOException(String.Format("file exists - remote:{0}", nameTemp));
                }
                if (!overwrite && Exists(name, trace))
                {
                    throw new IOException(String.Format("file exists - remote:{0}", name));
                }

                LocalFileCopy uncommitted;
                if (!uncommittedLocalTempFiles.TryGetValue(nameTemp, out uncommitted)
                    || (uncommitted != localFile))
                {
                    throw new InvalidOperationException();
                }

                uncommittedLocalTempFiles.Remove(nameTemp); // transfer ownership to using()
                using (uncommitted) // refcount-- at end of scope
                {

                    RemoteFileSystemEntry entry;
                    using (Stream stream = uncommitted.Read())
                    {
                        entry = remoteWebMethods.UploadFile(remoteDirectoryEntry.Id, nameTemp, stream, progressTracker, trace, faultInstanceMethod);
                    }
                    remoteDirectoryCache.Update(entry);

                    if (!name.Equals(nameTemp))
                    {
                        if (Exists(name, trace))
                        {
                            Delete(name, trace);
                        }

                        Rename(nameTemp, name, trace);
                    }
                }
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteArchiveFileManager.Commit() caught exception - rethrowing: {0}", exception);
                }
                throw;
            }
        }

        public void Abandon(ILocalFileCopy localFile, string nameTemp, TextWriter trace)
        {
            try
            {
                IFaultInstance faultInstanceMethod = faultInstanceRoot.Select("Abandon", nameTemp);

                LocalFileCopy uncommitted;
                if (!uncommittedLocalTempFiles.TryGetValue(nameTemp, out uncommitted)
                    || (uncommitted != localFile))
                {
                    throw new InvalidOperationException();
                }
                uncommittedLocalTempFiles.Remove(nameTemp);
                uncommitted.Release();
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteArchiveFileManager.Abandon() caught exception - rethrowing: {0}", exception);
                }
                throw;
            }
        }

        public void Delete(string name, TextWriter trace)
        {
            try
            {
                IFaultInstance faultInstanceMethod = faultInstanceRoot.Select("Delete", name);

                RemoteFileSystemEntry entry;
                if (!remoteDirectoryCache.TryGetName(name, out entry))
                {
                    throw new FileNotFoundException(String.Format("remote:{0}", name));
                }

                remoteWebMethods.DeleteFile(entry.Id, trace, faultInstanceMethod);
                remoteDirectoryCache.Remove(name);

                if (entry.HasDuplicates)
                {
                    foreach (RemoteFileSystemEntry duplicate in entry.Duplicates)
                    {
                        remoteWebMethods.DeleteFile(duplicate.Id, trace, faultInstanceMethod);
                    }
                }
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteArchiveFileManager.Delete() caught exception - rethrowing: {0}", exception);
                }
                throw;
            }
        }

        public void DeleteById(string id, TextWriter trace)
        {
            try
            {
                IFaultInstance faultInstanceMethod = faultInstanceRoot.Select("DeleteById", id);

                RemoteFileSystemEntry entry = null;
                int duplicateIndex = -1;
                RemoteFileSystemEntry duplicateBaseEntry = null;
                foreach (RemoteFileSystemEntry candidate in remoteDirectoryCache)
                {
                    if (candidate.Id.Equals(id))
                    {
                        entry = candidate;
                        break;
                    }
                    if (candidate.HasDuplicates)
                    {
                        for (int i = 0; i < candidate.Duplicates.Count; i++)
                        {
                            RemoteFileSystemEntry duplicate = candidate.Duplicates[i];
                            if (duplicate.Id.Equals(id))
                            {
                                duplicateBaseEntry = candidate;
                                duplicateIndex = i;
                                entry = duplicate;
                                break;
                            }
                        }
                    }
                }
                if (entry == null)
                {
                    throw new FileNotFoundException(String.Format("remote-id:{0}", id));
                }

                remoteWebMethods.DeleteFile(entry.Id, trace, faultInstanceMethod);
                if (duplicateBaseEntry == null)
                {
                    remoteDirectoryCache.Remove(entry.Name);
                    if (entry.HasDuplicates)
                    {
                        List<RemoteFileSystemEntry> duplicates = entry.Duplicates;
                        entry = duplicates[0];
                        entry.Duplicates.AddRange(duplicates.GetRange(1, duplicates.Count - 1));
                        remoteDirectoryCache.Update(entry);
                    }
                }
                else
                {
                    duplicateBaseEntry.Duplicates.RemoveAt(duplicateIndex);
                }

                // do not delete duplicates in this method
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteArchiveFileManager.DeleteById() caught exception - rethrowing: {0}", exception);
                }
                throw;
            }
        }

        public bool Exists(string name, TextWriter trace)
        {
            try
            {
                IFaultInstance faultInstanceMethod = faultInstanceRoot.Select("Exists", name);

                RemoteFileSystemEntry entry;
                return remoteDirectoryCache.TryGetName(name, out entry);
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteArchiveFileManager.Exists() caught exception - rethrowing: {0}", exception);
                }
                throw;
            }
        }

        public void Rename(string oldName, string newName, TextWriter trace)
        {
            try
            {
                IFaultInstance faultInstanceMethod = faultInstanceRoot.Select("Rename", String.Format("{0}|{1}", oldName, newName));

                RemoteFileSystemEntry entry;
                if (!remoteDirectoryCache.TryGetName(oldName, out entry))
                {
                    throw new FileNotFoundException(String.Format("remote:{0}", oldName));
                }

                RemoteFileSystemEntry newEntry = remoteWebMethods.RenameFile(entry.Id, newName, trace, faultInstanceMethod);
                remoteDirectoryCache.Remove(oldName);
                if (newEntry != null)
                {
                    remoteDirectoryCache.Update(newEntry);
                }
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteArchiveFileManager.Rename() caught exception - rethrowing: {0}", exception);
                }
                throw;
            }
        }

        public void RenameById(string id, string newName, TextWriter trace)
        {
            try
            {
                IFaultInstance faultInstanceMethod = faultInstanceRoot.Select("RenameById", String.Format("{0}|{1}", id, newName));

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

                RemoteFileSystemEntry newEntry = remoteWebMethods.RenameFile(entry.Id, newName, trace, faultInstanceMethod);
                remoteDirectoryCache.Remove(entry.Name);
                if (newEntry != null)
                {
                    remoteDirectoryCache.Update(newEntry);
                }
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteArchiveFileManager.RenameById() caught exception - rethrowing: {0}", exception);
                }
                throw;
            }
        }

        public string[] GetFileNames(string prefix, TextWriter trace)
        {
            try
            {
                IFaultInstance faultInstanceMethod = faultInstanceRoot.Select("GetFileNames", prefix);

                if (prefix == null)
                {
                    prefix = String.Empty;
                }
                if (prefix.IndexOfAny(new char[] { '*', '?' }) >= 0)
                {
                    throw new ArgumentException();
                }

                List<string> names = new List<string>(remoteDirectoryCache.Count);
                foreach (RemoteFileSystemEntry entry in remoteDirectoryCache)
                {
                    if (entry.Name.StartsWith(prefix))
                    {
                        names.Add(entry.Name);
                    }
                }

                names.Sort(delegate(string l, string r) { return String.Compare(l, r, StringComparison.OrdinalIgnoreCase); });
                return names.ToArray();
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteArchiveFileManager.GetFileNames() caught exception - rethrowing: {0}", exception);
                }
                throw;
            }
        }

        public void GetFileInfo(string name, out string id, out bool directory, out DateTime created, out DateTime modified, out long size, TextWriter trace)
        {
            try
            {
                IFaultInstance faultInstanceMethod = faultInstanceRoot.Select("GetFileInfo", name);

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
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteArchiveFileManager.GetFileInfo() caught exception - rethrowing: {0}", exception);
                }
                throw;
            }
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
            IFaultInstance faultInstanceMethod = faultInstanceRoot.Select("GetQuota");

            remoteWebMethods.GetQuota(out quotaTotal, out  quotaUsed, trace, faultInstanceMethod);
        }

        public TextWriter GetMasterTrace() // TextWriter is threadsafe; remains owned - do not Dispose()
        {
            return masterTrace;
        }
    }
}
