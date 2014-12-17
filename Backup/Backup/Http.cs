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
using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Backup;

namespace Http
{
    ////////////////////////////////////////////////////////////////////////////
    //
    // Http Implementation
    //
    ////////////////////////////////////////////////////////////////////////////

    public class InsecureConnectionException : ApplicationException
    {
        public const string DefaultMessage = "The connection to the remote server is insecure. For your safety, the application must terminate the connection and cannot continue.";

        public InsecureConnectionException()
            : base(DefaultMessage)
        {
        }
    }

    public interface ICertificatePinning
    {
        bool CertificatePinningEnabled { get; }
        bool ValidatePinnedCertificate(string host, IPAddress hostAddress, X509Certificate certificate, TextWriter trace);
    }

    public interface INetworkThrottle
    {
        void WaitBytes(int count);
    }

    public class HttpSettings
    {
        public bool EnableResumableUploads;
        public int? MaxBytesPerWebRequest; // force upload fail & resumable after this many bytes (to exercise the resume code)

        public ICertificatePinning CertificatePinning;

        public INetworkThrottle NetworkThrottle;

        public int? SendTimeout; // milliseconds; 0 or -1 is infinite
        public int? ReceiveTimeout; // milliseconds; 0 or -1 is infinite

        public HttpSettings(bool enableResumableUploads, int? maxBytesPerWebRequest, ICertificatePinning certificatePinning, INetworkThrottle networkThrottle, int? sendTimeout, int? receiveTimeout)
        {
            this.EnableResumableUploads = enableResumableUploads;
            this.MaxBytesPerWebRequest = maxBytesPerWebRequest;
            this.CertificatePinning = certificatePinning;
            this.NetworkThrottle = networkThrottle;
            this.SendTimeout = sendTimeout;
            this.ReceiveTimeout = receiveTimeout;
        }
    }

    public static class HttpMethods
    {
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

        private static WebExceptionStatus SocketRequest(Uri uriInitial, Uri uri, string verb, IPAddress hostAddress, bool twoStageRequest, byte[] requestHeaderBytes, Stream requestBodySource, out HttpStatusCode httpStatus, out string[] responseHeaders, Stream responseBodyDestinationNormal, Stream responseBodyDestinationExceptional, ProgressTracker progressTrackerUpload, ProgressTracker progressTrackerDownload, TextWriter trace, IFaultInstance faultInstanceContext, HttpSettings settings)
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

                    if (settings.SendTimeout.HasValue)
                    {
                        socket.SendTimeout = settings.SendTimeout.Value;
                    }
                    if (settings.ReceiveTimeout.HasValue)
                    {
                        socket.ReceiveTimeout = settings.ReceiveTimeout.Value;
                    }

                    List<string> headers = new List<string>();
                    using (Stream socketStream = !useTLS ? (Stream)new NetworkStream(socket, false/*ownsSocket*/) : (Stream)new SslStream(new NetworkStream(socket, false/*ownsSocket*/)))
                    {
                        if (useTLS)
                        {
                            SslStream ssl = (SslStream)socketStream;

                            // TODO: When moving out of the stone-age (i.e. to .NET 4.0+), update call
                            // below to use TLS 1.2 or higher only.
                            ssl.AuthenticateAsClient(
                                uri.Host,
                                new X509CertificateCollection()/*no client certs*/,
                                System.Security.Authentication.SslProtocols.Tls/*no ssl2/3*/,
                                true/*checkCertificateRevocation*/);

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
                                trace.WriteLine("  check cert revocation: {0}", ssl.CheckCertRevocationStatus);
                            }

                            if (!ssl.IsAuthenticated || !ssl.IsEncrypted || !ssl.IsSigned || !(ssl.SslProtocol >= System.Security.Authentication.SslProtocols.Tls))
                            {
                                throw new InsecureConnectionException();
                            }

                            // If pinning is not enabled, the host name still needs to be verified vs. the certificate's
                            // signed host names. This is a bit of a fussy operation. Since the host name is passed into
                            // SslSteam.AuthenticateAsClient, it is assumed that the host name is validated vs. the
                            // certificate (verified via http://referencesource.microsoft.com). If a different TLS
                            // implementation is used, it should be checked to make sure the host name is verified.

                            if ((settings.CertificatePinning != null)
                                && settings.CertificatePinning.CertificatePinningEnabled
                                && !settings.CertificatePinning.ValidatePinnedCertificate(uriInitial.Host, hostAddress, ssl.RemoteCertificate, trace))
                            {
                                if (trace != null)
                                {
                                    trace.WriteLine("Remote certificate rejected because public key does not match expected value for pinned certificate (actual=\"{0}\").", ssl.RemoteCertificate.GetPublicKeyString());
                                }

                                throw new InsecureConnectionException();
                            }
                        }


                        // write request header

                        socketStream.Write(requestHeaderBytes, 0, requestHeaderBytes.Length);
                        if (settings.NetworkThrottle != null)
                        {
                            settings.NetworkThrottle.WaitBytes(requestHeaderBytes.Length);
                        }

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
                                if (settings.NetworkThrottle != null)
                                {
                                    settings.NetworkThrottle.WaitBytes(read);
                                }

                                socketStream.Write(buffer, 0, read);
                                requestBytesSent += read;

                                if (progressTrackerUpload != null)
                                {
                                    progressTrackerUpload.Current = requestBodySource.Position;
                                }

                                faultPredicateWriteRequest.Test(requestBytesSent); // may throw FaultInjectionException or FaultInjectionPayloadException

                                if (settings.EnableResumableUploads && settings.MaxBytesPerWebRequest.HasValue)
                                {
                                    // If the remote service supports restartable uploads (indicated by the
                                    // subclass constructor setting enableRestartableUploads), then we can do
                                    // the following:
                                    // 1. The upload can be aborted as a matter of course after a decent number
                                    //    of bytes for the purpose of exercising the resume branch of the code.

                                    if (requestBytesSent > settings.MaxBytesPerWebRequest.Value)
                                    {
                                        if (trace != null)
                                        {
                                            trace.WriteLine("Sent {0} bytes this request, more than MaxBytesPerWebRequest ({1}); simulating connection break for resume testing", requestBytesSent, settings.MaxBytesPerWebRequest.Value);
                                        }
                                        return WebExceptionStatus.ReceiveFailure;
                                    }
                                }
                            }
                        }


                        // read response header and body

                        const string ContentLengthHeaderPrefix = "Content-Length:";
                        Stream responseBodyDestination;
                        long contentLength;
                        int contentLengthIndex = -1;
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

                            if (((verb == "GET") && (httpStatus != (HttpStatusCode)200/*OK*/) && (httpStatus != (HttpStatusCode)206/*PartialContent*/))
                                || ((verb == "DELETE") && (httpStatus != (HttpStatusCode)204/*No Content*/)))
                            {
                                // For GET, if not 200 or 206, then do not modify normal response stream as this
                                // is not data from the requested object but rather error details.
                                // For DELETE, if not 204, then try to use exceptional response stream because
                                // normal stream is usually null since typically no response is expected.
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
                                contentLengthIndex = Array.FindIndex(responseHeaders, delegate(string candidate) { return candidate.StartsWith(ContentLengthHeaderPrefix); });
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
                            if (settings.NetworkThrottle != null)
                            {
                                settings.NetworkThrottle.WaitBytes(approximateResponseHeadersBytes);
                            }
                        }

                        IFaultPredicate faultPredicateReadResponse = faultInstanceMethod.SelectPredicate("ResponseBodyBytes");

                        long responseBodyTotalRead = 0;
                        int chunkRemaining = 0;
                        bool chunkedTransferTerminatedNormally = false;
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
                                        chunkedTransferTerminatedNormally = true;
                                    }
                                }

                                needed = Math.Min(needed, chunkRemaining);
                            }

                            needed = Math.Min(buffer.Length, needed);
                            Debug.Assert(needed >= 0);
                            int read = socketStream.Read(buffer, 0, (int)needed);
                            if (settings.NetworkThrottle != null)
                            {
                                settings.NetworkThrottle.WaitBytes(read);
                            }
                            responseBodyDestination.Write(buffer, 0, read);
                            chunkRemaining -= read;
                            responseBodyTotalRead += read;

                            if (progressTrackerDownload != null)
                            {
                                progressTrackerDownload.Current = responseBodyDestination.Position;
                            }

                            faultPredicateReadResponse.Test(responseBodyTotalRead); // may throw FaultInjectionException or FaultInjectionPayloadException
                        }

                        if (chunked && chunkedTransferTerminatedNormally)
                        {
                            // synthesize a Content-Length header from chunked transfer
                            if (contentLengthIndex < 0)
                            {
                                contentLengthIndex = responseHeaders.Length;
                                Array.Resize(ref responseHeaders, responseHeaders.Length + 1);
                            }
                            responseHeaders[contentLengthIndex] = String.Format("{0} {1}", ContentLengthHeaderPrefix, contentLength);
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
            catch (InsecureConnectionException)
            {
                throw;
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
                    traceValue2 = LogWriter.ScrubSecuritySensitiveValue(traceValue2.Trim());
                }
                trace.WriteLine("  {0}: {1}{2}", key, traceValue1, traceValue2);
            }
        }

        private static readonly string[] ForbiddenHeaders = new string[] { "Accept-Encoding", "Content-Length", "Expect", "Connection" };

        public static bool IsHeaderForbidden(string header)
        {
            return Array.IndexOf(HttpMethods.ForbiddenHeaders, header) >= 0;
        }

        public static WebExceptionStatus SocketHttpRequest(Uri uriInitial, IPAddress hostAddress, string verb, KeyValuePair<string, string>[] requestHeaders, Stream requestBodySource, out HttpStatusCode httpStatus, out KeyValuePair<string, string>[] responseHeaders, Stream responseBodyDestination, out string finalUrl, ProgressTracker progressTrackerUpload, ProgressTracker progressTrackerDownload, TextWriter trace, IFaultInstance faultInstanceContext, HttpSettings settings)
        {
            Uri uri = uriInitial;

            if (trace != null)
            {
                trace.WriteLine("+SocketHttpRequest(url={0}, hostAddress={1}, verb={2}, request-body={3}, response-body={4})", uri, hostAddress, verb, LogWriter.ToString(requestBodySource), LogWriter.ToString(responseBodyDestination, true/*omitContent*/));
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
                    uriInitial,
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
                    faultInstanceContext,
                    settings);

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
                        trace.WriteLine("unsuccessful GET (not 200 and not 206) response body: {0}", LogWriter.ToString(responseBodyDestinationExceptional));
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

        public static WebExceptionStatus DNSLookupName(string hostName, out IPAddress hostAddress, TextWriter trace, IFaultInstance faultInstanceContext)
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
    }
}
