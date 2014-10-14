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

        private const int RateLimitExceededBackoffMilliseconds = 5000;
        public static void WaitRateLimitExceededBackoff(TextWriter trace, HttpStatusCode rateLimitStatusCode)
        {
            if (trace != null)
            {
                trace.WriteLine("Remote API rate limit exceeded (status={1}), delaying {0} msec", RateLimitExceededBackoffMilliseconds, rateLimitStatusCode);
            }
            Thread.Sleep(RateLimitExceededBackoffMilliseconds); // remote API calls/second exceeded
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

                if (accessToken == null)
                {
                    Authenticate(trace);
                }

                if (trace != null)
                {
                    trace.WriteLine("-RemoteAccessControl.GetAccessToken returns {0}", Logging.ScrubSecuritySensitiveValue(accessToken));
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
                    trace.WriteLine("+RemoteAccessControl.InvalidateOldAccessToken: {0}", Logging.ScrubSecuritySensitiveValue(callerAccessToken));
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
                        trace.WriteLine(" doing nothing - not the current token {0}", Logging.ScrubSecuritySensitiveValue(accessToken));
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
                trace.WriteLine("call {0} {1} {2} {3} {4} {5}", LoginProgramName, arg0, arg1, arg2, arg3.Length > 2 ? Logging.ScrubSecuritySensitiveValue(arg3) : arg3, arg4);
                trace.WriteLine("exit code: {0}", exitCode);
                trace.WriteLine("output:");
                trace.WriteLine(exitCode == 0 ? Logging.ScrubSecuritySensitiveValue(output) : output);
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
            }
            if (trace != null)
            {
                trace.WriteLine("Acquired tokens:");
                trace.WriteLine("  access_token={0}", Logging.ScrubSecuritySensitiveValue(accessToken));
                trace.WriteLine("  refresh_token={0}", Logging.ScrubSecuritySensitiveValue(refreshTokenProtected));
                trace.WriteLine("  other: expires_in={0}", expires_in);
                trace.WriteLine();
            }

            if (String.IsNullOrEmpty(refreshTokenProtected))
            {
                refreshTokenProtected = oldRefreshTokenProtected;
            }

            if (trace != null)
            {
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

    public abstract class WebMethodsBase
    {
        private const int MaxBytesPerWebRequest = 50 * 1024 * 1024; // force upload fail & resumable after this many bytes (to exercise the resume code)
        private const string UserAgent = "Backup (CryptSikyur-Archiver) v0 [github.com/programmatom/CryptSikyur-Archiver]";

        protected readonly RemoteAccessControl remoteAccessControl;
        protected readonly bool enableResumableUploads;

        protected readonly Random random = new Random(); // for exponential backoff retry delays

        private static NetworkThrottle networkThrottle = new NetworkThrottle();

        private WebMethodsBase()
        {
            throw new NotSupportedException();
        }

        protected WebMethodsBase(RemoteAccessControl remoteAccessControl, bool enableResumableUploads)
        {
            this.remoteAccessControl = remoteAccessControl;
            this.enableResumableUploads = enableResumableUploads;
        }


        // Global controls

        public static void EnsureConcurrency(int threadCount)
        {
            // It seems that System.Net.HttpWebRequest is hanging because the concurrency
            // exceeds the number of connections permitted to a given remote host. Ensure here
            // that the system will allow the number of threads we'll be using.
            if (ServicePointManager.DefaultConnectionLimit < threadCount)
            {
                ServicePointManager.DefaultConnectionLimit = threadCount;
            }
        }

        private class NetworkThrottle
        {
            public virtual void WaitBytes(int count)
            {
            }
        }

        private class ActiveNetworkThrottle : NetworkThrottle
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

            public override void WaitBytes(int count)
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


        // Configurable methods

        public abstract HttpStatusCode RateLimitStatusCode { get; }


        // Implementation


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
        private WebExceptionStatus SocketRequest(Uri uri, string verb, IPAddress hostAddress, bool twoStageRequest, byte[] requestHeaderBytes, Stream requestBodySource, out HttpStatusCode httpStatus, out string[] responseHeaders, Stream responseBodyDestinationNormal, Stream responseBodyDestinationExceptional, ProgressTracker progressTrackerUpload, ProgressTracker progressTrackerDownload, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            byte[] buffer = new byte[Core.Constants.BufferSize];

            bool useTLS = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);

            httpStatus = (HttpStatusCode)0;
            responseHeaders = new string[0];

            try
            {
                IFaultInstance faultInstanceMethod = faultInstanceContext.Select("SocketHttpRequest", String.Format("{0}|{1}", verb, uri));

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

                            ssl.AuthenticateAsClient(uri.Host);

                            if (trace != null)
                            {
                                trace.WriteLine("SSL/TLS connection properties:");
                                trace.WriteLine("  ssl protocol: {0} ({1})", ssl.SslProtocol, (int)ssl.SslProtocol);
                                trace.WriteLine("  key exchange algorithm: {0} ({1})", ssl.KeyExchangeAlgorithm, (int)ssl.KeyExchangeAlgorithm);
                                trace.WriteLine("  key exchange strength: {0}", ssl.KeyExchangeStrength);
                                trace.WriteLine("  cipher algorithm: {0} ({1})", ssl.CipherAlgorithm, (int)ssl.CipherAlgorithm);
                                trace.WriteLine("  cipher strength: {0}", ssl.CipherStrength);
                                trace.WriteLine("  hash algorithm: {0} ({1})", ssl.HashAlgorithm, (int)ssl.HashAlgorithm);
                                trace.WriteLine("  hash strength: {0}", ssl.HashStrength);
                                trace.WriteLine("  is authenticated: {0}", ssl.IsAuthenticated);
                                trace.WriteLine("  is encrypted: {0}", ssl.IsEncrypted);
                                trace.WriteLine("  is mutually authenticated: {0}", ssl.IsMutuallyAuthenticated);
                                //trace.WriteLine("  is server: {0}", ssl.IsServer);
                                trace.WriteLine("  is signed: {0}", ssl.IsSigned);
                                trace.WriteLine("  remote certificate: {0}", ssl.RemoteCertificate != null ? ssl.RemoteCertificate.ToString(true/*verbose*/).Replace(Environment.NewLine, ";") : null);
                                //trace.WriteLine("  local certificate: {0}", ssl.LocalCertificate != null ? ssl.LocalCertificate.ToString(true/*verbose*/).Replace(Environment.NewLine, ";") : null);
                            }

                            if (!ssl.IsAuthenticated || !ssl.IsEncrypted || !ssl.IsSigned/* || !(ssl.SslProtocol >= SslProtocols.Tls)*/)
                            {
                                throw new ApplicationException("TLS Unsecure");
                            }
                        }


                        // write request header

                        socketStream.Write(requestHeaderBytes, 0, requestHeaderBytes.Length);
                        networkThrottle.WaitBytes(requestHeaderBytes.Length);

                        // wait for 100-continue if two-stage request in use

                        if (twoStageRequest)
                        {
                            if (trace != null)
                            {
                                trace.WriteLine("two-stage request - waiting for 100-Continue:");
                            }

                            string line2;
                            List<string> headers2 = new List<string>();
                            while (!String.IsNullOrEmpty(line2 = StreamReadLine(socketStream)))
                            {
                                headers2.Add(line2);
                                if (trace != null)
                                {
                                    trace.WriteLine("  {0}", line2);
                                }
                            }
                            string[] line2Parts;
                            int code = -1;
                            if ((headers2.Count < 1)
                                || String.IsNullOrEmpty(headers2[0])
                                || ((line2Parts = headers2[0].Split(new char[] { ' ' })).Length < 2)
                                || (!line2Parts[0].StartsWith("HTTP"))
                                || !Int32.TryParse(line2Parts[1], out code)
                                || (code != 100))
                            {
                                if (trace != null)
                                {
                                    trace.WriteLine("did not receive 100-Continue, aborting.");
                                }

                                if (code != -1)
                                {
                                    if (trace != null)
                                    {
                                        trace.WriteLine("  server returned status code: {0} ({1})", (int)code, (HttpStatusCode)code);
                                    }

                                    responseHeaders = headers2.ToArray();
                                    return WebExceptionStatus.Success; // caller will handle header
                                }

                                return WebExceptionStatus.ServerProtocolViolation; // unintelligible response
                            }
                        }


                        // write request body

                        IFaultPredicate faultPredicateWriteRequest = faultInstanceMethod.SelectPredicate("RequestBodyBytes");

                        if (requestBodySource != null)
                        {
                            long requestBytesSent = 0;
                            int read;
                            while ((read = requestBodySource.Read(buffer, 0, buffer.Length)) != 0)
                            {
                                networkThrottle.WaitBytes(read);

                                socketStream.Write(buffer, 0, read);
                                requestBytesSent += read;

                                if (progressTrackerUpload != null)
                                {
                                    progressTrackerUpload.Current = requestBodySource.Position;
                                }

                                faultPredicateWriteRequest.Test(requestBytesSent); // may throw FaultInjectionException or FaultInjectionPayloadException

                                if (enableResumableUploads)
                                {
                                    // If the remote service supports restartable uploads (indicated by the
                                    // subclass constructor setting enableRestartableUploads), then we can do
                                    // the following:
                                    // 1. The upload can be aborted as a matter of course after a decent number
                                    //    of bytes for the purpose of exercising the resume branch of the code.

                                    if (requestBytesSent > MaxBytesPerWebRequest)
                                    {
                                        if (trace != null)
                                        {
                                            trace.WriteLine("Sent {0} bytes this request, more than MaxBytesPerWebRequest ({1}); simulating connection break for resume testing", requestBytesSent, MaxBytesPerWebRequest);
                                        }
                                        return WebExceptionStatus.ReceiveFailure;
                                    }
                                }
                            }
                        }


                        // read response header and body

                        Stream responseBodyDestination;
                        long contentLength;
                        bool chunked = false;
                        {
                            string line;
                            while (!String.IsNullOrEmpty(line = StreamReadLine(socketStream)))
                            {
                                headers.Add(line);
                            }
                            responseHeaders = headers.ToArray();

                            if (headers.Count < 1)
                            {
                                return WebExceptionStatus.ServerProtocolViolation;
                            }

                            string[] parts = headers[0].Split((char)32);
                            if ((parts.Length < 2)
                                || (!parts[0].Equals("HTTP/1.1") && !parts[0].Equals("HTTP/1.0")))
                            {
                                return WebExceptionStatus.ServerProtocolViolation;
                            }
                            httpStatus = (HttpStatusCode)Int32.Parse(parts[1]);

                            if ((verb == "GET") && (httpStatus != (HttpStatusCode)200/*OK*/) && (httpStatus != (HttpStatusCode)206/*PartialContent*/))
                            {
                                // For GET, if not 200 or 206, then do not modify normal response stream as this
                                // is not data from the requested object but rather error details.
                                responseBodyDestination = responseBodyDestinationExceptional != null ? responseBodyDestinationExceptional : responseBodyDestinationNormal;
                            }
                            else
                            {
                                // For all other verbs, or successful GET, put data in normal response stream.
                                responseBodyDestination = responseBodyDestinationNormal;
                            }

                            chunked = false;
                            const string TransferEncodingHeaderPrefix = "Transfer-Encoding:";
                            int transferEncodingHeaderIndex = Array.FindIndex(responseHeaders, delegate(string candidate) { return candidate.StartsWith(TransferEncodingHeaderPrefix); });
                            if (transferEncodingHeaderIndex >= 0)
                            {
                                chunked = responseHeaders[transferEncodingHeaderIndex].Substring(TransferEncodingHeaderPrefix.Length).Trim().Equals("chunked");
                            }

                            if (httpStatus == (HttpStatusCode)204)
                            {
                                contentLength = 0; // "204 No Content" response code - do not try to read
                            }
                            else
                            {
                                const string ContentLengthHeaderPrefix = "Content-Length:";
                                int contentLengthIndex = Array.FindIndex(responseHeaders, delegate(string candidate) { return candidate.StartsWith(ContentLengthHeaderPrefix); });
                                if (contentLengthIndex >= 0)
                                {
                                    contentLength = Int64.Parse(responseHeaders[contentLengthIndex].Substring(ContentLengthHeaderPrefix.Length));
                                }
                                else
                                {
                                    contentLength = responseBodyDestination != null ? Int64.MaxValue : 0;
                                }
                            }
                        }

                        // only needs to be approximate
                        {
                            int approximateResponseHeadersBytes = 0;
                            foreach (string header in responseHeaders)
                            {
                                approximateResponseHeadersBytes += header.Length + Environment.NewLine.Length;
                            }
                            networkThrottle.WaitBytes(approximateResponseHeadersBytes);
                        }

                        IFaultPredicate faultPredicateReadResponse = faultInstanceMethod.SelectPredicate("ResponseBodyBytes");

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
                            networkThrottle.WaitBytes(read);
                            responseBodyDestination.Write(buffer, 0, read);
                            chunkRemaining -= read;
                            responseBodyTotalRead += read;

                            if (progressTrackerDownload != null)
                            {
                                progressTrackerDownload.Current = responseBodyDestination.Position;
                            }

                            faultPredicateReadResponse.Test(responseBodyTotalRead); // may throw FaultInjectionException or FaultInjectionPayloadException
                        }
                    }
                }
            }
            catch (FaultTemplateNode.FaultInjectionPayloadException exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("FaultInjectionPayloadException: {0} [{1}] " + Environment.NewLine + "{2}", exception.Message, exception.Payload, exception.StackTrace);
                }
                const string webPrefix = "web=";
                const string statusPrefix = "status=";
                if (exception.Payload.StartsWith(webPrefix))
                {
                    return (WebExceptionStatus)Int32.Parse(exception.Payload.Substring(webPrefix.Length));
                }
                else if (exception.Payload.StartsWith(statusPrefix))
                {
                    httpStatus = (HttpStatusCode)Int32.Parse(exception.Payload.Substring(statusPrefix.Length));
                    if ((responseHeaders != null) && (responseHeaders.Length > 0))
                    {
                        responseHeaders[0] = String.Format("{0} {1}", responseHeaders[0].Substring(0, responseHeaders[0].IndexOf(' ')), (int)httpStatus);
                    }
                    return WebExceptionStatus.ProtocolError;
                }
                else
                {
                    throw new InvalidOperationException("Invalid fault injection payload");
                }
            }
            catch (Exception exception) // expect IOException, SocketException, at least...
            {
                if (trace != null)
                {
                    trace.WriteLine("Exception: {0}", exception);
                }
                return WebExceptionStatus.ReceiveFailure;
            }

            return WebExceptionStatus.Success;
        }

        private static readonly string[] SecuritySensitiveHeaders = new string[] { "Authorization" };
        private static void WriteHeader(string key, string value, TextWriter headersWriter, TextWriter trace)
        {
            headersWriter.WriteLine("{0}: {1}", key, value);

            if (trace != null)
            {
                string traceValue1 = null;
                string traceValue2 = value;
                if (Array.IndexOf(SecuritySensitiveHeaders, key) >= 0)
                {
                    traceValue2 = !String.IsNullOrEmpty(traceValue2) ? traceValue2 : String.Empty;
                    const string BearerPrefix = "Bearer ";
                    if (traceValue2.StartsWith(BearerPrefix))
                    {
                        traceValue1 = traceValue2.Substring(0, BearerPrefix.Length);
                        traceValue2 = traceValue2.Substring(BearerPrefix.Length);
                    }
                    traceValue2 = Logging.ScrubSecuritySensitiveValue(traceValue2.Trim());
                }
                trace.WriteLine("  {0}: {1}{2}", key, traceValue1, traceValue2);
            }
        }

        private static readonly string[] ForbiddenHeaders = new string[] { "Accept-Encoding", "Content-Length", "Expect", "Connection" };
        private WebExceptionStatus SocketHttpRequest(Uri uri, IPAddress hostAddress, string verb, KeyValuePair<string, string>[] requestHeaders, Stream requestBodySource, out HttpStatusCode httpStatus, out KeyValuePair<string, string>[] responseHeaders, Stream responseBodyDestination, out string finalUrl, ProgressTracker progressTrackerUpload, ProgressTracker progressTrackerDownload, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            if (trace != null)
            {
                trace.WriteLine("+SocketHttpRequest(url={0}, hostAddress={1}, verb={2}, request-body={3}, response-body={4})", uri, hostAddress, verb, Logging.ToString(requestBodySource), Logging.ToString(responseBodyDestination, true/*omitContent*/));
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

            // Use "Expect: 100-continue" method if larger than this - gives remote server a chance
            // to reject request if Content-Length is exceeds service's max file size.
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
                    string firstLine = String.Format("{0} {1} HTTP/1.1", verb, uri.PathAndQuery);
                    writer.WriteLine(firstLine);
                    if (trace != null)
                    {
                        trace.WriteLine("Request headers:");
                        trace.WriteLine("  {0}", firstLine);
                    }

                    WriteHeader("Host", uri.Host, writer, trace);
                    foreach (KeyValuePair<string, string> header in requestHeaders)
                    {
                        WriteHeader(header.Key, header.Value, writer, trace);
                    }
                    WriteHeader("Accept-Encoding", "gzip, deflate", writer, trace);
                    // Is there any harm in always writing Content-Length header?
                    WriteHeader("Content-Length", ((requestBodySource != null) && (requestBodySource.Length > requestBodySource.Position) ? requestBodySource.Length - requestBodySource.Position : 0).ToString(), writer, trace);
                    if (twoStageRequest)
                    {
                        WriteHeader("Expect", "100-continue", writer, trace);
                    }
                    WriteHeader("Connection", "keep-alive", writer, trace); // HTTP 1.0 superstition
                    writer.WriteLine();
                }
                requestHeaderBytes = stream.ToArray();
            }


            WebExceptionStatus result;
            string[] responseHeadersLines;
            long responseBodyDestinationStart, responseBodyDestinationEnd, responseBodyBytesReceived;
            using (MemoryStream responseBodyDestinationExceptional = new MemoryStream())
            {
                responseBodyDestinationStart = (responseBodyDestination != null) ? responseBodyDestination.Position : 0;

                result = SocketRequest(
                    uri,
                    verb,
                    hostAddress,
                    twoStageRequest,
                    requestHeaderBytes,
                    requestBodySource,
                    out httpStatus,
                    out responseHeadersLines,
                    responseBodyDestination,
                    responseBodyDestinationExceptional,
                    progressTrackerUpload,
                    progressTrackerDownload,
                    trace,
                    faultInstanceContext);

                responseBodyDestinationEnd = (responseBodyDestination != null) ? responseBodyDestination.Position : 0;
                responseBodyBytesReceived = responseBodyDestinationEnd - responseBodyDestinationStart;

                if (trace != null)
                {
                    trace.WriteLine("Socket request result: {0} ({1})", (int)result, result);
                    trace.WriteLine("Response headers:");
                    foreach (string s in responseHeadersLines)
                    {
                        trace.WriteLine("  {0}", s);
                    }
                }

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

                if (responseBodyDestinationExceptional.Length != 0)
                {
                    DecompressStreamInPlace(responseBodyDestinationExceptional, responseHeaders, true/*updateHeaders*/);
                    if (trace != null)
                    {
                        trace.WriteLine("unsuccessful GET (not 200 and not 206) response body: {0}", Logging.ToString(responseBodyDestinationExceptional));
                    }
                }
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

            if (responseBodyDestination != null)
            {
                DecompressStreamInPlace(responseBodyDestination, ref responseBodyDestinationStart, ref responseBodyDestinationEnd, ref responseBodyBytesReceived, responseHeaders, true/*updateHeaders*/);
            }

            if ((httpStatus >= (HttpStatusCode)300) && (httpStatus <= (HttpStatusCode)307))
            {
                int locationHeaderIndex = Array.FindIndex(responseHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, "Location"); });
                if (locationHeaderIndex >= 0)
                {
                    if (trace != null)
                    {
                        if (Array.FindAll(responseHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, "Location"); }).Length > 1)
                        {
                            trace.WriteLine(" NOTICE: multiple Location response headers present - using first one (http status was {0} {1})", (int)httpStatus, httpStatus);
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

                    if (trace != null)
                    {
                        trace.WriteLine("auto-redirecting to {0}", uri);
                    }

                    goto Restart;
                }
            }


            finalUrl = uri.ToString();

        Exit:
            if (trace != null)
            {
                trace.WriteLine("-SocketHttpRequest returns {0} ({1})", (int)result, result);
            }
            return result;
        }

        private static void DecompressStreamInPlace(Stream responseBodyDestination, ref long responseBodyDestinationStart, ref long responseBodyDestinationEnd, ref long responseBodyBytesReceived, KeyValuePair<string, string>[] responseHeaders, bool updateHeaders)
        {
            int contentEncodingHeaderIndex = Array.FindIndex(responseHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, "Content-Encoding"); });
            if (contentEncodingHeaderIndex >= 0)
            {
                bool gzip = responseHeaders[contentEncodingHeaderIndex].Value.Equals("gzip", StringComparison.OrdinalIgnoreCase);
                bool deflate = responseHeaders[contentEncodingHeaderIndex].Value.Equals("deflate", StringComparison.OrdinalIgnoreCase);
                if (!gzip && !deflate)
                {
                    throw new NotSupportedException(String.Format("Content-Encoding: {0}", responseHeaders[contentEncodingHeaderIndex].Value));
                }

                byte[] buffer = new byte[Core.Constants.BufferSize];

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

                    if (updateHeaders)
                    {
                        int contentLengthHeaderIndex = Array.FindIndex(responseHeaders, delegate(KeyValuePair<string, string> candidate) { return String.Equals(candidate.Key, "Content-Length"); });
                        if (contentLengthHeaderIndex >= 0)
                        {
                            responseHeaders[contentLengthHeaderIndex] = new KeyValuePair<string, string>("Content-Length", responseBodyBytesReceived.ToString());
                        }
                    }
                }
                File.Delete(tempPath);

                if (updateHeaders)
                {
                    responseHeaders[contentEncodingHeaderIndex] = new KeyValuePair<string, string>();
                }
            }
        }

        private static void DecompressStreamInPlace(Stream responseBodyDestination, KeyValuePair<string, string>[] responseHeaders, bool updateHeaders)
        {
            long responseBodyDestinationStart, responseBodyDestinationEnd, responseBodyBytesReceived;
            responseBodyDestinationStart = 0;
            responseBodyDestinationEnd = responseBodyBytesReceived = responseBodyDestination.Length;
            DecompressStreamInPlace(responseBodyDestination, ref responseBodyDestinationStart, ref responseBodyDestinationEnd, ref responseBodyBytesReceived, responseHeaders, updateHeaders);
        }

        private static WebExceptionStatus DNSLookupName(string hostName, out IPAddress hostAddress, TextWriter trace, IFaultInstance faultInstanceContext)
        {
            hostAddress = null;
            try
            {
                IPHostEntry hostInfo = Dns.GetHostEntry(hostName);
                if (hostInfo.AddressList.Length < 1)
                {
                    return WebExceptionStatus.NameResolutionFailure;
                }
                hostAddress = hostInfo.AddressList[0];
                return WebExceptionStatus.Success;
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("DNSLookupName caught exception: {0}", exception);
                }
                return WebExceptionStatus.NameResolutionFailure;
            }
        }

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
                trace.WriteLine("+DoWebActionOnce(url={0}, verb={1}, request-body={2}, response-body={3})", url, verb, Logging.ToString(requestBodySource), Logging.ToString(responseBodyDestination));
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
                    trace.WriteLine("Acquired access token (RemoteAccessControl.AccessToken): {0}", Logging.ScrubSecuritySensitiveValue(accessToken));
                }
            }
            else
            {
                accessToken = accessTokenOverride;
                if (trace != null)
                {
                    trace.WriteLine("Acquiring access token (using same token for all requests): {0}", Logging.ScrubSecuritySensitiveValue(accessToken));
                }
            }


            // Custom HTTP request implementation

            Uri uri = new Uri(url);
            IPAddress hostAddress;
            webStatusCode = DNSLookupName(uri.Host, out hostAddress, trace, faultInstanceContext);
            if (webStatusCode != WebExceptionStatus.Success)
            {
                if (trace != null)
                {
                    trace.WriteLine("DNSLookupName returned error: {0} ({1})", (int)webStatusCode, webStatusCode);
                }
                goto Error;
            }

            // generally, headers in ForbiddenRequestHeaders[] are managed by SocketHttpRequest
            Dictionary<string, bool> requestHeadersSeen = new Dictionary<string, bool>();
            List<KeyValuePair<string, string>> requestHeadersList = new List<KeyValuePair<string, string>>();
            requestHeadersList.Add(new KeyValuePair<string, string>("Authorization", String.Format("{0} {1}", "Bearer", accessToken)));
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
            webStatusCode = SocketHttpRequest(
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
                faultInstanceContext);

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

            bool result = (webStatusCode == WebExceptionStatus.Success)
                && (((int)httpStatusCode >= 200) && ((int)httpStatusCode <= 299));
            if (trace != null)
            {
                if (responseBodyDestination != null)
                {
                    trace.WriteLine(" response-body={0}", Logging.ToString(responseBodyDestination));
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
                trace.WriteLine("+DoWebActionWithRetry(url={0}, verb={1}, request-body={2}, response-body={3})", url, verb, Logging.ToString(requestBodySource), Logging.ToString(responseBodyDestination));
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
                    if (httpStatusCodeOut == RateLimitStatusCode)
                    {
                        RetryHelper.WaitRateLimitExceededBackoff(trace, RateLimitStatusCode); // remote API calls/second exceeded
                    }

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
                    trace.WriteLine(" response-body={0}", Logging.ToString(responseBodyDestination));
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

        protected bool DownloadFileWithResume(string url, Stream streamDownloadInto, ProgressTracker progressTracker, TextWriter trace, IFaultInstance faultInstanceContext)
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
                if (httpStatusCode == RateLimitStatusCode)
                {
                    RetryHelper.WaitRateLimitExceededBackoff(trace, RateLimitStatusCode); // remote API calls/second exceeded
                }

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

        public MicrosoftOneDriveWebMethods(RemoteAccessControl remoteAccessControl, TextWriter trace, IFaultInstance faultInstanceContext)
            : base(remoteAccessControl, false/*enableResumableUploads*/)
        {
            if (trace != null)
            {
                trace.WriteLine("*MicrosoftOneDriveWebMethods constructor");
            }
        }

        public override HttpStatusCode RateLimitStatusCode { get { return (HttpStatusCode)(-99); } } // Microsoft is not rate-limited

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

            if (!DownloadFileWithResume(url, streamDownloadInto, progressTracker, trace, faultInstanceContext))
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

        public GoogleDriveWebMethods(RemoteAccessControl remoteAccessControl, TextWriter trace, IFaultInstance faultInstanceContext)
            : base(remoteAccessControl, true/*enableResumableUploads*/)
        {
            if (trace != null)
            {
                trace.WriteLine("*GoogleDriveWebMethods constructor");
            }
        }

        public override HttpStatusCode RateLimitStatusCode { get { return (HttpStatusCode)403; } }

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


            // https://developers.google.com/drive/web/manage-downloads

            if (!DownloadFileWithResume(downloadUrl, streamDownloadInto, progressTracker, trace, faultInstanceContext))
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
                if (httpStatusCode == RateLimitStatusCode)
                {
                    RetryHelper.WaitRateLimitExceededBackoff(trace, RateLimitStatusCode); // remote API calls/second exceeded
                }
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
                trace.WriteLine("Acquired access token (RemoteAccessControl.AccessToken): {0}", Logging.ScrubSecuritySensitiveValue(accessTokenOverride));
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
                if (httpStatusCode == RateLimitStatusCode)
                {
                    RetryHelper.WaitRateLimitExceededBackoff(trace, RateLimitStatusCode); // remote API calls/second exceeded
                }
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

    class RemoteArchiveFileManager : IArchiveFileManager
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


        private delegate IWebMethods CreateWebMethodsMethod(RemoteAccessControl remoteAccessControl, TextWriter trace, IFaultInstance faultInstanceContext);
        private static readonly KeyValuePair<string, CreateWebMethodsMethod>[] SupportedServices = new KeyValuePair<string, CreateWebMethodsMethod>[]
        {
            new KeyValuePair<string, CreateWebMethodsMethod>("onedrive.live.com", delegate(RemoteAccessControl remoteAccessControl, TextWriter trace, IFaultInstance faultInstanceContext) { return new MicrosoftOneDriveWebMethods(remoteAccessControl, trace, faultInstanceContext); }),
            new KeyValuePair<string, CreateWebMethodsMethod>("drive.google.com", delegate(RemoteAccessControl remoteAccessControl, TextWriter trace, IFaultInstance faultInstanceContext) { return new GoogleDriveWebMethods(remoteAccessControl, trace, faultInstanceContext); }),
        };

        private const string TraceFilePrefix = "remotestoragetrace";

        public RemoteArchiveFileManager(string serviceUrl, string remoteDirectory, string refreshTokenProtected, Core.Context context)
        {
            faultInstanceRoot = context.faultInjectionRoot.Select("RemoteArchiveFileManager", String.Format("serviceUrl={0}|remoteDirectory={1}", serviceUrl, remoteDirectory));

            if (context.traceEnabled)
            {
                masterTrace = Logging.CreateLogFile(TraceFilePrefix);
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

                remoteWebMethods = SupportedServices[serviceSelector].Value(remoteAccessControl, masterTrace, faultInstanceRoot);

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
