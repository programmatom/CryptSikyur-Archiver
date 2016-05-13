/*
 *  Copyright © 2014-2016 Thomas R. Lawrence
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
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using ComTypes = System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.Text;
using System.Threading;
using System.Web;
using System.Windows.Forms;

using Diagnostics;
using Exceptions;
using HexUtil;
using Http;
using JSON;
using ProtectedData;

namespace RemoteDriveAuth
{
    public class Constants
    {
        public const int SecondaryEntropyLengthBytes = 256 / 8;
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // OAuth2.0 remote service definitions
    //
    ////////////////////////////////////////////////////////////////////////////

    public abstract class OAuth20RemoteService
    {
        public abstract Uri ServiceUri { get; }

        public virtual ClientIdentities.ClientIdentity GetDefaultClientIdentity()
        {
            throw new ExitCodeException(
                (int)ExitCodeException.ExitCodes.ErrorUserMessage,
                String.Format(
                    "Service \"{0}\" has no default registration record (client-id and client-secret). " +
                    "To use this service, you must obtain and register an identification record using " +
                    "the \"{1} -memorize\" option. Registration for client id and secret can be done " +
                    "at \"{2}\". See documentation for further guidance.",
                    ServiceUri,
                    Path.GetFileName(Process.GetCurrentProcess().MainModule.FileName),
                    DeveloperConsoleUri));
        }

        public abstract string DeveloperConsoleUri { get; } // for registering application to obtain client-id and client-secret

        public abstract string Scopes(bool enableRefreshToken);

        public abstract string RequestAuthorizationUrl(ClientIdentities.ClientIdentity clientIdentity, bool enableRefreshToken);
        public abstract string AuthorizedRedirectUrl { get; }
        public abstract string AuthorizedRedirectUrlBrowser { get; }

        public abstract string TokenExchangeProviderUrl { get; }

        public abstract ICertificatePinning CertificatePinning { get; }
    }

    class MicrosoftOneDriveRemoteService : OAuth20RemoteService
    {
        // Walkthrough of desktop application authentication for Microsoft
        // http://msdn.microsoft.com/en-us/library/dn631817.aspx

        // Microsoft: manage client application registration at:
        // https://account.live.com/developers/applications/index (http://go.microsoft.com/fwlink/p/?LinkId=193157)

        public override Uri ServiceUri { get { return new Uri("https://onedrive.live.com"); } }

        public override string DeveloperConsoleUri { get { return "https://account.live.com/developers/applications/index"; } }

        // Scopes: http://msdn.microsoft.com/en-us/library/dn631845.aspx
        // wl.offline_access - use this if a refresh token is desired
        // wl.skydrive_update - use for read & write access to skydrive files
        private const string ScopesRefreshToken = "wl.skydrive_update wl.offline_access";
        private const string ScopesNoRefreshToken = "wl.skydrive_update";
        public override string Scopes(bool enableRefreshToken) { return enableRefreshToken ? ScopesRefreshToken : ScopesNoRefreshToken; }

        public override string RequestAuthorizationUrl(ClientIdentities.ClientIdentity clientIdentity, bool enableRefreshToken) { return "https://login.live.com/oauth20_authorize.srf?client_id=" + clientIdentity.ClientId + "&scope=" + Scopes(enableRefreshToken) + "&response_type=code&redirect_uri=https://login.live.com/oauth20_desktop.srf"; }
        public override string AuthorizedRedirectUrl { get { return "https://login.live.com/oauth20_desktop.srf"; } }
        public override string AuthorizedRedirectUrlBrowser { get { return AuthorizedRedirectUrl; } }

        public override string TokenExchangeProviderUrl { get { return "https://login.live.com/oauth20_token.srf"; } }

        public override ICertificatePinning CertificatePinning { get { return null; } }
    }

    class GoogleDriveRemoteService : OAuth20RemoteService
    {
        // Walkthrough of deskop application authentication for Google
        // https://developers.google.com/accounts/docs/OAuth2InstalledApp

        // Google: manage client application registration at:
        // https://console.developers.google.com/

        public override Uri ServiceUri { get { return new Uri("https://drive.google.com"); } }

        public override string DeveloperConsoleUri { get { return "https://console.developers.google.com/"; } }

        // Scopes: https://developers.google.com/drive/web/scopes
        // openid - required
        // profile email - docs claim at least one is required, but apparently not
        // https://www.googleapis.com/auth/drive - full, permissive access 
        public override string Scopes(bool enableRefreshToken) { return "openid " + /*"profile " +*/ "https://www.googleapis.com/auth/drive"; }

        public override string RequestAuthorizationUrl(ClientIdentities.ClientIdentity clientIdentity, bool enableRefreshToken) { return String.Concat("https://accounts.google.com/o/oauth2/auth?client_id=", clientIdentity.ClientId, "&scope=", HttpUtility.UrlEncode(Scopes(enableRefreshToken)), "&response_type=code", enableRefreshToken ? "&access_type=offline" : String.Empty, "&redirect_uri=", AuthorizedRedirectUrl); }
        // HACK for Google: "http://localhost" should have worked, but isn't. Instead, using urn:ietf:wg:oauth:2.0:oob:
        // AuthorizedRedirectUrl is the redirect url, but AuthorizedRedirectUrlBrowser is what actually happens
        // The page content must be inspected to recover authorization code.
        public override string AuthorizedRedirectUrl { get { return "urn:ietf:wg:oauth:2.0:oob"; } }
        public override string AuthorizedRedirectUrlBrowser { get { return "https://accounts.google.com/o/oauth2/approval"; } }

        public override string TokenExchangeProviderUrl { get { return "https://accounts.google.com/o/oauth2/token"; } }

        public override ICertificatePinning CertificatePinning { get { return new Backup.CertificatePinning(X509CertificateKeyPinning.Google.RootPublicKeyHashes); } }
    }

    class Services
    {
        private static readonly OAuth20RemoteService[] SupportedServices = new OAuth20RemoteService[]
        {
            new MicrosoftOneDriveRemoteService(),
            new GoogleDriveRemoteService(),
        };

        public static IEnumerator<OAuth20RemoteService> EnumerateServices()
        {
            return ((IEnumerable<OAuth20RemoteService>)SupportedServices).GetEnumerator();
        }

        public IEnumerator<OAuth20RemoteService> GetEnumerator()
        {
            return ((IEnumerable<OAuth20RemoteService>)SupportedServices).GetEnumerator();
        }

        public static OAuth20RemoteService FindService(Uri requestedServiceUri)
        {
            return Array.Find(Services.SupportedServices, delegate (OAuth20RemoteService candidate) { return requestedServiceUri.Host.Equals(candidate.ServiceUri.Host, StringComparison.OrdinalIgnoreCase); });
        }
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Client Identity memorization (encrypted with user-credential protected storage)
    //
    ////////////////////////////////////////////////////////////////////////////

    public class ClientIdentities
    {
        private Dictionary<string, ClientIdentity> identities = new Dictionary<string, ClientIdentity>();

        public class ClientIdentity
        {
            public readonly Uri ServiceUri;
            public readonly string ClientId;
            public readonly string ClientSecret;

            public ClientIdentity(Uri serviceUri, string clientId, string clientSecret)
            {
                this.ServiceUri = serviceUri;
                this.ClientId = clientId;
                this.ClientSecret = clientSecret;
            }

            public ClientIdentity(byte[] encryptedBlob, byte[] secondaryEntropy)
            {
                using (ProtectedArray<byte> decryptedBlob = ProtectedDataStorage.DecryptPersistent(encryptedBlob, 0, encryptedBlob.Length, secondaryEntropy))
                {
                    decryptedBlob.Reveal();
                    using (TextReader reader = new StringReader(Encoding.ASCII.GetString(decryptedBlob.ExposeArray())))
                    {
                        this.ServiceUri = new Uri(reader.ReadLine());
                        this.ClientId = reader.ReadLine();
                        this.ClientSecret = reader.ReadLine();
                    }
                }
            }

            public byte[] Serialize(byte[] secondaryEntropy)
            {
                byte[] decryptedBlob;
                using (MemoryStream stream = new MemoryStream())
                {
                    using (TextWriter writer = new StreamWriter(stream))
                    {
                        writer.WriteLine(ServiceUri);
                        writer.WriteLine(ClientId);
                        writer.WriteLine(ClientSecret);
                    }
                    decryptedBlob = stream.ToArray();
                }
                return ProtectedDataStorage.EncryptPersistent(decryptedBlob, 0, decryptedBlob.Length, secondaryEntropy);
            }
        }

        public ClientIdentities(string path)
        {
            if (File.Exists(path))
            {
                using (TextReader reader = new StreamReader(new FileStream(path, FileMode.Open, FileAccess.Read)))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        string[] parts = line.Split(new char[] { ';' });
                        ClientIdentity identity = new ClientIdentity(HexUtility.HexDecode(parts[1]), HexUtility.HexDecode(parts[0]));
                        identities.Add(identity.ServiceUri.Host, identity);
                    }
                }
            }
        }

        public void Save(string path)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

            Directory.CreateDirectory(Path.GetDirectoryName(path));
            using (TextWriter writer = new StreamWriter(new FileStream(path, FileMode.Create, FileAccess.Write)))
            {
                foreach (ClientIdentity identity in identities.Values)
                {
                    const int SecondaryEntropyLengthBytes = 256 / 8;
                    byte[] secondaryEntropy = new byte[SecondaryEntropyLengthBytes];
                    rng.GetBytes(secondaryEntropy);
                    writer.WriteLine("{0};{1}", HexUtility.HexEncode(secondaryEntropy), HexUtility.HexEncode(identity.Serialize(secondaryEntropy)));
                }
            }
        }

        public ClientIdentity GetClientIdentity(Uri serviceUri)
        {
            ClientIdentity identity;
            identities.TryGetValue(serviceUri.Host, out identity);
            return identity;
        }

        public void Memorize(ClientIdentity identity)
        {
            identities[identity.ServiceUri.Host] = identity; // overwrite any existing
        }

        public void Forget(Uri serviceUri)
        {
            string host = serviceUri.Host;
            if (identities.ContainsKey(host))
            {
                identities.Remove(host);
            }
        }

        public void Forget()
        {
            identities.Clear();
        }
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Exit codes
    //
    ////////////////////////////////////////////////////////////////////////////

    public class ExitCodeException : MyApplicationException
    {
        public enum ExitCodes
        {
            Success = 0,
            Error = 1,
            ErrorUserMessage = 2, // used to notify invoking process to show exception.Message to user
            RetriableError = 3,
        }

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
    // Windows .NET Form hosting WebBrowser control (for OAuth2.0 delegated log-in)
    // (modified from boilerplate example at http://msdn.microsoft.com/en-us/library/3s8ys666.aspx
    // as recommended on http://msdn.microsoft.com/en-us/library/dn631817.aspx)
    //
    ////////////////////////////////////////////////////////////////////////////

    // TODO: clean this up - most menu items and buttons aren't needed

    // from http://blogs.msdn.com/b/jpsanders/archive/2011/04/26/how-to-set-the-proxy-for-the-webbrowser-control-in-net.aspx
    #region WinInet Proxy Configuration
    public static class WinInetInterop
    {
        public static string applicationName;

        [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr InternetOpen(string lpszAgent, int dwAccessType, string lpszProxyName, string lpszProxyBypass, int dwFlags);

        [DllImport("wininet.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InternetCloseHandle(IntPtr hInternet);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct INTERNET_PER_CONN_OPTION_LIST
        {
            public int Size;

            // The connection to be set. NULL means LAN.
            public IntPtr Connection;

            public int OptionCount;
            public int OptionError;

            // List of INTERNET_PER_CONN_OPTIONs.
            public IntPtr pOptions;
        }

        private enum INTERNET_OPTION
        {
            // Sets or retrieves an INTERNET_PER_CONN_OPTION_LIST structure that specifies
            // a list of options for a particular connection.
            INTERNET_OPTION_PER_CONNECTION_OPTION = 75,

            // Notify the system that the registry settings have been changed so that
            // it verifies the settings on the next call to InternetConnect.
            INTERNET_OPTION_SETTINGS_CHANGED = 39,

            // Causes the proxy data to be reread from the registry for a handle.
            INTERNET_OPTION_REFRESH = 37,
        }

        private enum INTERNET_PER_CONN_OptionEnum
        {
            INTERNET_PER_CONN_FLAGS = 1,
            INTERNET_PER_CONN_PROXY_SERVER = 2,
            INTERNET_PER_CONN_PROXY_BYPASS = 3,
            INTERNET_PER_CONN_AUTOCONFIG_URL = 4,
            INTERNET_PER_CONN_AUTODISCOVERY_FLAGS = 5,
            INTERNET_PER_CONN_AUTOCONFIG_SECONDARY_URL = 6,
            INTERNET_PER_CONN_AUTOCONFIG_RELOAD_DELAY_MINS = 7,
            INTERNET_PER_CONN_AUTOCONFIG_LAST_DETECT_TIME = 8,
            INTERNET_PER_CONN_AUTOCONFIG_LAST_DETECT_URL = 9,
            INTERNET_PER_CONN_FLAGS_UI = 10,
        }

        private const int INTERNET_OPEN_TYPE_DIRECT = 1;  // direct to net
        private const int INTERNET_OPEN_TYPE_PRECONFIG = 0; // read registry

        // Constants used in INTERNET_PER_CONN_OPTON struct.
        private enum INTERNET_OPTION_PER_CONN_FLAGS
        {
            PROXY_TYPE_DIRECT = 0x00000001,   // direct to net
            PROXY_TYPE_PROXY = 0x00000002,   // via named proxy
            PROXY_TYPE_AUTO_PROXY_URL = 0x00000004,   // autoproxy URL
            PROXY_TYPE_AUTO_DETECT = 0x00000008,   // use autoproxy detection
        }

        // Used in INTERNET_PER_CONN_OPTION.
        // When create a instance of OptionUnion, only one filed will be used.
        // The StructLayout and FieldOffset attributes could help to decrease the struct size.
        [StructLayout(LayoutKind.Explicit)]
        private struct INTERNET_PER_CONN_OPTION_OptionUnion
        {
            // A value in INTERNET_OPTION_PER_CONN_FLAGS.
            [FieldOffset(0)]
            public int dwValue;
            [FieldOffset(0)]
            public IntPtr pszValue;
            [FieldOffset(0)]
            public ComTypes.FILETIME ftValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct INTERNET_PER_CONN_OPTION
        {
            // A value in INTERNET_PER_CONN_OptionEnum.
            public int dwOption;
            public INTERNET_PER_CONN_OPTION_OptionUnion Value;
        }

        // Sets an Internet option.
        [DllImport("wininet.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern bool InternetSetOption(
            IntPtr hInternet,
            INTERNET_OPTION dwOption,
            IntPtr lpBuffer,
            int lpdwBufferLength);

        // Queries an Internet option on the specified handle. The Handle will be always 0.
        [DllImport("wininet.dll", CharSet = CharSet.Ansi, SetLastError = true, EntryPoint = "InternetQueryOption")]
        private extern static bool InternetQueryOptionList(
            IntPtr Handle,
            INTERNET_OPTION OptionFlag,
            ref INTERNET_PER_CONN_OPTION_LIST OptionList,
            ref int size);

        // Set the proxy server for LAN connection.
        public static bool SetConnectionProxy(string proxySpecification)
        {
            IntPtr hInternet = InternetOpen(applicationName, INTERNET_OPEN_TYPE_DIRECT, null, null, 0);

            //// Create 3 options.
            //INTERNET_PER_CONN_OPTION[] Options = new INTERNET_PER_CONN_OPTION[3];

            // Create 2 options.
            INTERNET_PER_CONN_OPTION[] Options = new INTERNET_PER_CONN_OPTION[2];

            // Set PROXY flags.
            Options[0] = new INTERNET_PER_CONN_OPTION();
            Options[0].dwOption = (int)INTERNET_PER_CONN_OptionEnum.INTERNET_PER_CONN_FLAGS;
            Options[0].Value.dwValue = (int)INTERNET_OPTION_PER_CONN_FLAGS.PROXY_TYPE_PROXY;

            // Set proxy name.
            Options[1] = new INTERNET_PER_CONN_OPTION();
            Options[1].dwOption = (int)INTERNET_PER_CONN_OptionEnum.INTERNET_PER_CONN_PROXY_SERVER;
            Options[1].Value.pszValue = Marshal.StringToHGlobalAnsi(proxySpecification);

            //// Set proxy bypass.
            //Options[2] = new INTERNET_PER_CONN_OPTION();
            //Options[2].dwOption = (int)INTERNET_PER_CONN_OptionEnum.INTERNET_PER_CONN_PROXY_BYPASS;
            //Options[2].Value.pszValue = Marshal.StringToHGlobalAnsi("local");

            //// Allocate a block of memory of the options.
            //System.IntPtr buffer = Marshal.AllocCoTaskMem(Marshal.SizeOf(Options[0]) + Marshal.SizeOf(Options[1]) + Marshal.SizeOf(Options[2]));

            // Allocate a block of memory of the options.
            System.IntPtr buffer = Marshal.AllocCoTaskMem(Marshal.SizeOf(Options[0]) + Marshal.SizeOf(Options[1]));

            System.IntPtr current = buffer;

            // Marshal data from a managed object to an unmanaged block of memory.
            for (int i = 0; i < Options.Length; i++)
            {
                Marshal.StructureToPtr(Options[i], current, false);
                current = (System.IntPtr)((int)current + Marshal.SizeOf(Options[i]));
            }

            // Initialize a INTERNET_PER_CONN_OPTION_LIST instance.
            INTERNET_PER_CONN_OPTION_LIST option_list = new INTERNET_PER_CONN_OPTION_LIST();

            // Point to the allocated memory.
            option_list.pOptions = buffer;

            // Return the unmanaged size of an object in bytes.
            option_list.Size = Marshal.SizeOf(option_list);

            // IntPtr.Zero means LAN connection.
            option_list.Connection = IntPtr.Zero;

            option_list.OptionCount = Options.Length;
            option_list.OptionError = 0;
            int size = Marshal.SizeOf(option_list);

            // Allocate memory for the INTERNET_PER_CONN_OPTION_LIST instance.
            IntPtr intptrStruct = Marshal.AllocCoTaskMem(size);

            // Marshal data from a managed object to an unmanaged block of memory.
            Marshal.StructureToPtr(option_list, intptrStruct, true);

            // Set internet settings.
            bool bReturn = InternetSetOption(hInternet, INTERNET_OPTION.INTERNET_OPTION_PER_CONNECTION_OPTION, intptrStruct, size);

            // Free the allocated memory.
            Marshal.FreeCoTaskMem(buffer);
            Marshal.FreeCoTaskMem(intptrStruct);
            InternetCloseHandle(hInternet);

            // Throw an exception if this operation failed.
            if (!bReturn)
            {
                throw new MyApplicationException(" Set Internet Option Failed!");
            }

            return bReturn;
        }

        // Backup the current options for LAN connection.
        // Make sure free the memory after restoration.
        private static INTERNET_PER_CONN_OPTION_LIST GetSystemProxy()
        {
            // Query following options.
            INTERNET_PER_CONN_OPTION[] Options = new INTERNET_PER_CONN_OPTION[3];

            Options[0] = new INTERNET_PER_CONN_OPTION();
            Options[0].dwOption = (int)INTERNET_PER_CONN_OptionEnum.INTERNET_PER_CONN_FLAGS;
            Options[1] = new INTERNET_PER_CONN_OPTION();
            Options[1].dwOption = (int)INTERNET_PER_CONN_OptionEnum.INTERNET_PER_CONN_PROXY_SERVER;
            Options[2] = new INTERNET_PER_CONN_OPTION();
            Options[2].dwOption = (int)INTERNET_PER_CONN_OptionEnum.INTERNET_PER_CONN_PROXY_BYPASS;

            // Allocate a block of memory of the options.
            System.IntPtr buffer = Marshal.AllocCoTaskMem(Marshal.SizeOf(Options[0]) + Marshal.SizeOf(Options[1]) + Marshal.SizeOf(Options[2]));

            System.IntPtr current = (System.IntPtr)buffer;

            // Marshal data from a managed object to an unmanaged block of memory.
            for (int i = 0; i < Options.Length; i++)
            {
                Marshal.StructureToPtr(Options[i], current, false);
                current = (System.IntPtr)((int)current + Marshal.SizeOf(Options[i]));
            }

            // Initialize a INTERNET_PER_CONN_OPTION_LIST instance.
            INTERNET_PER_CONN_OPTION_LIST Request = new INTERNET_PER_CONN_OPTION_LIST();

            // Point to the allocated memory.
            Request.pOptions = buffer;

            Request.Size = Marshal.SizeOf(Request);

            // IntPtr.Zero means LAN connection.
            Request.Connection = IntPtr.Zero;

            Request.OptionCount = Options.Length;
            Request.OptionError = 0;
            int size = Marshal.SizeOf(Request);

            // Query internet options.
            bool result = InternetQueryOptionList(IntPtr.Zero, INTERNET_OPTION.INTERNET_OPTION_PER_CONNECTION_OPTION, ref Request, ref size);
            if (!result)
            {
                throw new MyApplicationException(" Set Internet Option Failed! ");
            }

            return Request;
        }

        // Restore the options for LAN connection.
        public static bool RestoreSystemProxy()
        {
            IntPtr hInternet = InternetOpen(applicationName, INTERNET_OPEN_TYPE_DIRECT, null, null, 0);

            INTERNET_PER_CONN_OPTION_LIST request = GetSystemProxy();
            int size = Marshal.SizeOf(request);

            // Allocate memory.
            IntPtr intptrStruct = Marshal.AllocCoTaskMem(size);

            // Convert structure to IntPtr
            Marshal.StructureToPtr(request, intptrStruct, true);

            // Set internet options.
            bool bReturn = InternetSetOption(hInternet, INTERNET_OPTION.INTERNET_OPTION_PER_CONNECTION_OPTION, intptrStruct, size);

            // Free the allocated memory.
            Marshal.FreeCoTaskMem(request.pOptions);
            Marshal.FreeCoTaskMem(intptrStruct);

            if (!bReturn)
            {
                throw new MyApplicationException(" Set Internet Option Failed! ");
            }

            // Notify the system that the registry settings have been changed and cause
            // the proxy data to be reread from the registry for a handle.
            InternetSetOption(hInternet, INTERNET_OPTION.INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(hInternet, INTERNET_OPTION.INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);

            InternetCloseHandle(hInternet);

            return bReturn;
        }

        // Disable saving cookies for current session
        // http://stackoverflow.com/questions/912741/how-to-delete-cookies-from-windows-form
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa385114%28v=vs.85%29.aspx
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa385328%28v=vs.85%29.aspx
        public static void SetCookiesPolicy()
        {
            IntPtr hInternet = InternetOpen(applicationName, INTERNET_OPEN_TYPE_DIRECT, null, null, 0);

            const int INTERNET_OPTION_SUPPRESS_BEHAVIOR = 81;

            const int INTERNET_SUPPRESS_COOKIE_POLICY = 1;
            const int INTERNET_SUPPRESS_COOKIE_PERSIST = 3;

            Int32[] option = new Int32[1];
            GCHandle optionsH = GCHandle.Alloc(option, GCHandleType.Pinned);
            try
            {
                option[0] = INTERNET_SUPPRESS_COOKIE_POLICY;
                bool result = InternetSetOption(hInternet, (INTERNET_OPTION)INTERNET_OPTION_SUPPRESS_BEHAVIOR, optionsH.AddrOfPinnedObject(), sizeof(Int32) * option.Length);
                int error = Marshal.GetLastWin32Error();
                if (!result)
                {
                    throw new MyApplicationException(String.Format("SetCookiesPolicy: ::InternetSetOption() failed with error {0}", error)); // search WinInet.h for INTERNET_ERROR_BASE
                }

                option[0] = INTERNET_SUPPRESS_COOKIE_PERSIST;
                result = InternetSetOption(hInternet, (INTERNET_OPTION)INTERNET_OPTION_SUPPRESS_BEHAVIOR, optionsH.AddrOfPinnedObject(), sizeof(Int32) * option.Length);
                error = Marshal.GetLastWin32Error();
                if (!result)
                {
                    throw new MyApplicationException(String.Format("SetCookiesPolicy: ::InternetSetOption() failed with error {0}", error)); // search WinInet.h for INTERNET_ERROR_BASE
                }
            }
            finally
            {
                optionsH.Free();
            }
        }
    }
    #endregion

    [PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
    public class WebBrowserHostingForm : Form
    {
        private const int DefaultWidth = 768;
        private const int DefaultHeight = 600;

        private readonly OAuth20RemoteService authService;
        private readonly TextWriter trace;

        public WebBrowserHostingForm(
            OAuth20RemoteService authService,
            ClientIdentities.ClientIdentity clientIdentity,
            bool enableRefreshToken,
            IPAddress socks5Address,
            int socks5Port,
            TextWriter trace)
        {
            this.authService = authService;
            this.trace = trace;

            // Configure socks5 proxying for WebBrowser control.
            // WARNING: It is believed that the WebBrowser control leaks DNS requests, so if proxying is intended
            // for anonymity (e.g. Tor), that usage may be dangerous here.
            if (socks5Address != null)
            {
                WinInetInterop.SetConnectionProxy(String.Format("socks={0}:{1}", socks5Address, socks5Port));
            }

            // Enable cookies, but disable persisting cookies, for this process only
            WinInetInterop.SetCookiesPolicy();

            // Create the form layout. If you are using Visual Studio,  
            // you can replace this code with code generated by the designer. 
            InitializeForm();

            // The following events are not visible in the designer, so  
            // you must associate them with their event-handlers in code.
            webBrowser1.CanGoBackChanged += new EventHandler(webBrowser1_CanGoBackChanged);
            webBrowser1.CanGoForwardChanged += new EventHandler(webBrowser1_CanGoForwardChanged);
            webBrowser1.DocumentTitleChanged += new EventHandler(webBrowser1_DocumentTitleChanged);
            webBrowser1.StatusTextChanged += new EventHandler(webBrowser1_StatusTextChanged);

            // Load the initial authentication page for the remote service
            webBrowser1.Navigate(authService.RequestAuthorizationUrl(clientIdentity, enableRefreshToken));
        }

        private string authorizationCode;
        internal string AuthorizationCode { get { return authorizationCode; } }

        // Displays the Properties dialog box. 
        private void propertiesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            webBrowser1.ShowPropertiesDialog();
        }

        // Selects all the text in the text box when the user clicks it.  
        private void toolStripTextBox1_Click(object sender, EventArgs e)
        {
            toolStripTextBox1.SelectAll();
        }

        // Navigates to the URL in the address box when  
        // the ENTER key is pressed while the ToolStripTextBox has focus. 
        private void toolStripTextBox1_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                Navigate(toolStripTextBox1.Text);
            }
        }

        // Navigates to the URL in the address box when  
        // the Go button is clicked. 
        private void goButton_Click(object sender, EventArgs e)
        {
            Navigate(toolStripTextBox1.Text);
        }

        // Navigates to the given URL if it is valid. 
        private void Navigate(String address)
        {
            if (String.IsNullOrEmpty(address)) return;
            if (address.Equals("about:blank")) return;
            if (!address.StartsWith("http://") &&
                !address.StartsWith("https://"))
            {
                address = "http://" + address;
            }
            try
            {
                webBrowser1.Navigate(new Uri(address));
            }
            catch (UriFormatException)
            {
                return;
            }
        }

        // Updates the URL in TextBoxAddress upon navigation. 
        private void webBrowser1_Navigated(object sender, WebBrowserNavigatedEventArgs e)
        {
            string url = webBrowser1.Url.ToString();
            toolStripTextBox1.Text = url;

            if (trace != null)
            {
                trace.WriteLine("webBrowser1_Navigated: {0}", url);
            }

            if (url.StartsWith(authService.AuthorizedRedirectUrlBrowser, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    // localhost redirect method

                    if (trace != null)
                    {
                        trace.WriteLine("webBrowser1_Navigated: localhost redirect method (url-embedded)");
                    }

                    authorizationCode = Program.ExtractAuthorizationCode(e.Url.Query.Substring(1), "code");

                    if (trace != null)
                    {
                        trace.WriteLine("webBrowser1_Navigated: authorization code obtained via localhost redirect method (url-embedded)");
                    }
                }
                catch (Exception exception)
                {
                    // urn:ietf:wg:oauth:2.0:oob redirect method

                    if (trace != null)
                    {
                        trace.WriteLine("webBrowser1_Navigated: exception [will reparse using urn:ietf:wg:oauth:2.0:oob redirect method (content-embedded)]: {0}", exception);
                    }

                    HtmlDocument htmlDoc = webBrowser1.Document;
                    if (trace != null)
                    {
                        HtmlElementCollection htmls = htmlDoc.GetElementsByTagName("HTML");
                        foreach (HtmlElement element in htmls)
                        {
                            using (TextReader reader = new StringReader(element.OuterHtml))
                            {
                                string line;
                                while ((line = reader.ReadLine()) != null)
                                {
                                    trace.WriteLine("[html]: {0}", line);
                                }
                            }
                        }
                    }
                    HtmlElementCollection titles = htmlDoc.GetElementsByTagName("TITLE");
                    foreach (HtmlElement element in titles)
                    {
                        string innerText = element.InnerText;
                        try
                        {
                            authorizationCode = Program.ExtractAuthorizationCode(innerText, "code");

                            if (trace != null)
                            {
                                trace.WriteLine("webBrowser1_Navigated: authorization code obtained via urn:ietf:wg:oauth:2.0:oob redirect method (content-embedded)");
                            }

                            break;
                        }
                        catch (Exception exception2)
                        {
                            if (trace != null)
                            {
                                trace.WriteLine("webBrowser1_Navigated: exception {0}", exception2);
                            }
                        }
                    }
                }
                finally
                {
                    if (trace != null)
                    {
                        trace.WriteLine("webBrowser1_Navigated: closing window");
                    }

                    this.Close();
                }
            }
        }

        // Navigates webBrowser1 to the previous page in the history. 
        private void backButton_Click(object sender, EventArgs e)
        {
            webBrowser1.GoBack();
        }

        // Disables the Back button at the beginning of the navigation history. 
        private void webBrowser1_CanGoBackChanged(object sender, EventArgs e)
        {
            backButton.Enabled = webBrowser1.CanGoBack;
        }

        // Navigates webBrowser1 to the next page in history. 
        private void forwardButton_Click(object sender, EventArgs e)
        {
            webBrowser1.GoForward();
        }

        // Disables the Forward button at the end of navigation history. 
        private void webBrowser1_CanGoForwardChanged(object sender, EventArgs e)
        {
            forwardButton.Enabled = webBrowser1.CanGoForward;
        }

        // Halts the current navigation and any sounds or animations on  
        // the page. 
        private void stopButton_Click(object sender, EventArgs e)
        {
            webBrowser1.Stop();
        }

        // Reloads the current page. 
        private void refreshButton_Click(object sender, EventArgs e)
        {
            // Skip refresh if about:blank is loaded to avoid removing 
            // content specified by the DocumentText property. 
            if (!webBrowser1.Url.Equals("about:blank"))
            {
                webBrowser1.Refresh();
            }
        }

        // Navigates webBrowser1 to the home page of the current user. 
        private void homeButton_Click(object sender, EventArgs e)
        {
            webBrowser1.GoHome();
        }

        // Updates the status bar with the current browser status text. 
        private void webBrowser1_StatusTextChanged(object sender, EventArgs e)
        {
            toolStripStatusLabel1.Text = webBrowser1.StatusText;
        }

        // Updates the title bar with the current document title. 
        private void webBrowser1_DocumentTitleChanged(object sender, EventArgs e)
        {
            this.Text = String.Format("{0}: {1}", ProductName, webBrowser1.DocumentTitle);
        }

        // Exits the application. 
        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        // Ensures focus is in the WebOC when window is brought to front. This recovers
        // focus to the input control when a user is using something like, e.g.
        // Password Safe (https://www.schneier.com/passsafe.html) to enter passwords,
        // which usually involve changing focus and immediately using SendKeys. Without
        // this event handler, focus is lost when window is raised and approach fails.
        void Form1_Activated(object sender, EventArgs e)
        {
            if (webBrowser1.Document != null)
            {
                webBrowser1.Document.Focus();
            }
        }

        // The remaining code in this file provides basic form initialization and  
        // includes a Main method. If you use the Visual Studio designer to create 
        // your form, you can use the designer generated code instead of this code,  
        // but be sure to use the names shown in the variable declarations here, 
        // and be sure to attach the event handlers to the associated events.  

        private WebBrowser webBrowser1;

        private MenuStrip menuStrip1;
        private ToolStripMenuItem fileToolStripMenuItem, exitToolStripMenuItem, propertiesToolStripMenuItem;
        private ToolStripSeparator toolStripSeparator1;

        private ToolStrip toolStrip1, toolStrip2;
        private ToolStripTextBox toolStripTextBox1;
        private ToolStripButton goButton, backButton, forwardButton, stopButton, refreshButton, homeButton;

        private StatusStrip statusStrip1;
        private ToolStripStatusLabel toolStripStatusLabel1;

        private void InitializeForm()
        {
            this.Width = DefaultWidth;
            this.Height = DefaultHeight;

            this.Icon = RemoteDriveAuth.Properties.Resources.Icon1;

            webBrowser1 = new WebBrowser();

            menuStrip1 = new MenuStrip();
            fileToolStripMenuItem = new ToolStripMenuItem();
            toolStripSeparator1 = new ToolStripSeparator();
            exitToolStripMenuItem = new ToolStripMenuItem();
            propertiesToolStripMenuItem = new ToolStripMenuItem();

            toolStrip1 = new ToolStrip();
            goButton = new ToolStripButton();
            backButton = new ToolStripButton();
            forwardButton = new ToolStripButton();
            stopButton = new ToolStripButton();
            refreshButton = new ToolStripButton();
            homeButton = new ToolStripButton();

            toolStrip2 = new ToolStrip();
            toolStripTextBox1 = new ToolStripTextBox();

            statusStrip1 = new StatusStrip();
            toolStripStatusLabel1 = new ToolStripStatusLabel();

            menuStrip1.Items.Add(fileToolStripMenuItem);

            fileToolStripMenuItem.DropDownItems.AddRange(new ToolStripItem[] { propertiesToolStripMenuItem, toolStripSeparator1, exitToolStripMenuItem });

            fileToolStripMenuItem.Text = "&File";
            propertiesToolStripMenuItem.Text = "Properties";
            exitToolStripMenuItem.Text = "E&xit";

            propertiesToolStripMenuItem.Click += new EventHandler(propertiesToolStripMenuItem_Click);
            exitToolStripMenuItem.Click += new EventHandler(exitToolStripMenuItem_Click);

            toolStrip1.Items.AddRange(new ToolStripItem[] { goButton, backButton, forwardButton, stopButton, refreshButton, homeButton });

            goButton.Text = "Go";
            backButton.Text = "Back";
            forwardButton.Text = "Forward";
            stopButton.Text = "Stop";
            refreshButton.Text = "Refresh";
            homeButton.Text = "Home";

            backButton.Enabled = false;
            forwardButton.Enabled = false;

            goButton.Click += new EventHandler(goButton_Click);
            backButton.Click += new EventHandler(backButton_Click);
            forwardButton.Click += new EventHandler(forwardButton_Click);
            stopButton.Click += new EventHandler(stopButton_Click);
            refreshButton.Click += new EventHandler(refreshButton_Click);
            homeButton.Click += new EventHandler(homeButton_Click);

            toolStrip2.Items.Add(toolStripTextBox1);
            toolStripTextBox1.Size = new Size(Width - 50, 25); // TODO: magic width???
            toolStripTextBox1.KeyDown += new KeyEventHandler(toolStripTextBox1_KeyDown);
            toolStripTextBox1.Click += new EventHandler(toolStripTextBox1_Click);

            statusStrip1.Items.Add(toolStripStatusLabel1);

            webBrowser1.Dock = DockStyle.Fill;
            webBrowser1.Navigated += new WebBrowserNavigatedEventHandler(webBrowser1_Navigated);

            this.Activated += new EventHandler(Form1_Activated);

            Controls.AddRange(new Control[] { webBrowser1, toolStrip2, toolStrip1, menuStrip1, statusStrip1, menuStrip1 });
        }
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Windows .NET Form for password entry
    //
    ////////////////////////////////////////////////////////////////////////////

    [PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
    public class PasswordEntryForm : Form
    {
        public PasswordEntryForm(string prompt)
        {
            this.prompt = prompt;

            InitializeForm();
        }

        private string prompt;

        // Selects all the text in the text box when the user clicks it.  
        private void PasswordTextBox_Click(object sender, EventArgs e)
        {
            passwordTextBox.SelectAll();
        }

        // TODO: WARNING: although the password property is protected, then Windows.Forms
        // control for text entry is not, so it may leak plaintext copies of the password
        // being entered to the heap or swap/hibernation file.
        // Remedy this with a custom control employing protection internally.

        private ProtectedArray<byte> password;
        internal ProtectedArray<byte> Password { get { return password; } }

        // Captures password text and closes box when
        // the ENTER key is pressed while the ToolStripTextBox has focus. 
        private void PasswordTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                password = ProtectedArray<byte>.CreateUtf8FromUtf16(passwordTextBox.Text);
                this.Close();
                return;
            }
        }

        // Captures password text and closes box when
        // the Go button is clicked. 
        private void AcceptButton_Click(object sender, EventArgs e)
        {
            password = ProtectedArray<byte>.CreateUtf8FromUtf16(passwordTextBox.Text);
            this.Close();
        }

        // Ensures focus is in the textbox when window is brought to front. This recovers
        // focus to the input control when a user is using something like, e.g.
        // Password Safe (https://www.schneier.com/passsafe.html) to enter passwords,
        // which usually involve changing focus and immediately using SendKeys. Without
        // this event handler, focus is lost when window is raised and approach fails.
        void Form_Activated(object sender, EventArgs e)
        {
            passwordTextBox.Focus();
        }

        // The remaining code in this file provides basic form initialization and  
        // includes a Main method. If you use the Visual Studio designer to create 
        // your form, you can use the designer generated code instead of this code,  
        // but be sure to use the names shown in the variable declarations here, 
        // and be sure to attach the event handlers to the associated events.  

        private Label passwordLabel;
        private TextBox passwordTextBox;
        private Button acceptButton;

        private void InitializeForm()
        {
            this.Icon = RemoteDriveAuth.Properties.Resources.Icon1;


            this.passwordLabel = new Label();
            this.passwordTextBox = new TextBox();
            this.acceptButton = new Button();
            this.SuspendLayout();


            this.passwordLabel.AutoSize = true;
            this.passwordLabel.Location = new Point(12, 15);
            this.passwordLabel.Size = new Size(56, 13);
            this.passwordLabel.TabIndex = 0;
            this.passwordLabel.Text = "Password:";


            this.passwordTextBox.Location = new Point(74, 12);
            this.passwordTextBox.Size = new Size(324, 20);
            this.passwordTextBox.TabIndex = 1;

            this.passwordTextBox.KeyDown += new KeyEventHandler(PasswordTextBox_KeyDown);
            this.passwordTextBox.Click += new EventHandler(PasswordTextBox_Click);

            this.passwordTextBox.PasswordChar = '\x25cf'; // bullet: '\x2022', large black circle: '\x25cf'


            this.acceptButton.Location = new Point(174, 49);
            this.acceptButton.Size = new Size(75, 23);
            this.acceptButton.TabIndex = 2;
            this.acceptButton.Text = "OK";
            this.acceptButton.UseVisualStyleBackColor = true;

            this.acceptButton.Click += new EventHandler(AcceptButton_Click);


            this.AutoScaleDimensions = new SizeF(6F, 13F);
            this.AutoScaleMode = AutoScaleMode.Font;
            this.ClientSize = new Size(423, 91);
            this.Controls.Add(this.acceptButton);
            this.Controls.Add(this.passwordTextBox);
            this.Controls.Add(this.passwordLabel);
            this.Name = String.IsNullOrEmpty(prompt) ? ProductName : String.Format("{0} - {1}", ProductName, prompt);
            this.Text = this.Name;
            this.ResumeLayout(false);
            this.PerformLayout();


            this.Activated += new EventHandler(Form_Activated);
        }
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Implementation of command line arguments and main auth flow.
    //
    ////////////////////////////////////////////////////////////////////////////

    class Program
    {
        internal static string ExtractAuthorizationCode(string query, string authCodeArg)
        {
            // HACKHACK 2015-06-16 Google adding "Success " to content of title element
            int space;
            while ((space = query.IndexOf(' ')) >= 0)
            {
                query = query.Substring(space + 1);
            }

            string[] args = query.Split(new char[] { '&' });
            foreach (string arg in args)
            {
                int eq = arg.IndexOf('=');
                if (eq < 0)
                {
                    continue;
                }
                string key = arg.Substring(0, eq);
                if (key.Equals(authCodeArg))
                {
                    string value = arg.Substring(eq + 1);
                    return value;
                }
            }
            throw new InvalidDataException("Unable to obtain authorization code from login service redirect url");
        }

        private class MyWebException : MyApplicationException
        {
            public readonly WebExceptionStatus WebExceptionStatus;
            public readonly HttpStatusCode HttpStatus;

            public MyWebException(WebExceptionStatus webExceptionStatus, HttpStatusCode httpStatus)
            {
                this.WebExceptionStatus = webExceptionStatus;
                this.HttpStatus = httpStatus;
            }

            public override string ToString()
            {
                return String.Format("Web Exception {0} ({1}) {2} ({3}) - {4}", WebExceptionStatus, (int)WebExceptionStatus, HttpStatus, (int)HttpStatus, base.ToString());
            }
        }

        private static void DoWebRequest(
            Uri uri,
            string verb,
            byte[] requestStream,
            string requestStreamContentType,
            Stream responseBody,
            IPAddress socks5Address,
            int socks5Port,
            ICertificatePinning certificatePinning)
        {
            IPAddress[] hostAddress = null;
            if (socks5Address == null)
            {
                HttpMethods.DNSLookupName(uri.Host, out hostAddress, null, Diagnostics.FaultInstanceNode.Null);
            }

            List<KeyValuePair<string, string>> requestHeaders = new List<KeyValuePair<string, string>>();
            if (requestStreamContentType != null)
            {
                requestHeaders.Add(new KeyValuePair<string, string>("Content-Type", requestStreamContentType));
            }
            KeyValuePair<string, string>[] responseHeaders;
            const int TimeoutSeconds = 30;
            HttpSettings settings = new HttpSettings(false, null, certificatePinning, TimeoutSeconds * 1000, TimeoutSeconds * 1000, true/*autoRedirect*/, socks5Address, socks5Port);
            HttpStatusCode httpStatus;
            string finalUrl;
            WebExceptionStatus result = HttpMethods.SocketHttpRequest(
                uri,
                hostAddress,
                verb,
                requestHeaders.ToArray(),
                new MemoryStream(requestStream),
                out httpStatus,
                out responseHeaders,
                responseBody,
                out finalUrl,
                null,
                null,
                null,
                Diagnostics.FaultInstanceNode.Null,
                settings,
                null/*autoRedirect*/);
            if ((result != WebExceptionStatus.Success) || (httpStatus != HttpStatusCode.OK))
            {
                throw new MyWebException(result, httpStatus);
            }
        }

        private static void GetTokensFromAuthCode(
            OAuth20RemoteService authService,
            ClientIdentities.ClientIdentity clientIdentity,
            string authorizationCode,
            out string tokensJSON,
            IPAddress socks5Address,
            int socks5Port,
            TextWriter trace)
        {
            if (trace != null)
            {
                trace.WriteLine("GetTokensFromAuthCode");
            }

            tokensJSON = null;

            byte[] requestBody;
            using (MemoryStream requestBodyStream = new MemoryStream())
            {
                using (TextWriter requestWriter = new StreamWriter(requestBodyStream, Encoding.ASCII))
                {
                    string message = String.Format("client_id={0}&client_secret={1}&code={2}&grant_type=authorization_code&redirect_uri={3}", clientIdentity.ClientId, clientIdentity.ClientSecret, authorizationCode, authService.AuthorizedRedirectUrl);
                    requestWriter.Write(message);
                }
                requestBody = requestBodyStream.ToArray();
            }

            using (MemoryStream responseBodyStream = new MemoryStream())
            {
                DoWebRequest(
                    new Uri(authService.TokenExchangeProviderUrl),
                    "POST",
                    requestBody,
                    "application/x-www-form-urlencoded",
                    responseBodyStream,
                    socks5Address,
                    socks5Port,
                    authService.CertificatePinning);

                responseBodyStream.Position = 0;
                using (TextReader reader = new StreamReader(responseBodyStream, Encoding.UTF8))
                {
                    tokensJSON = reader.ReadToEnd();
                }
            }
        }

        private static void GetTokensByRefresh(
            OAuth20RemoteService authService,
            ClientIdentities.ClientIdentity clientIdentity,
            string refreshToken,
            out string tokensJSON,
            IPAddress socks5Address,
            int socks5Port,
            TextWriter trace)
        {
            if (trace != null)
            {
                trace.WriteLine("GetTokensByRefresh");
            }

            tokensJSON = null;

            byte[] requestBody;
            using (MemoryStream requestBodyStream = new MemoryStream())
            {
                using (TextWriter requestWriter = new StreamWriter(requestBodyStream, Encoding.ASCII))
                {
                    string message = String.Format("client_id={0}&client_secret={1}&grant_type=refresh_token&refresh_token={2}", clientIdentity.ClientId, clientIdentity.ClientSecret, refreshToken);
                    requestWriter.Write(message);
                }
                requestBody = requestBodyStream.ToArray();
            }

            using (MemoryStream responseBodyStream = new MemoryStream())
            {
                DoWebRequest(
                    new Uri(authService.TokenExchangeProviderUrl),
                    "POST",
                    requestBody,
                    "application/x-www-form-urlencoded",
                    responseBodyStream,
                    socks5Address,
                    socks5Port,
                    authService.CertificatePinning);

                responseBodyStream.Position = 0;
                using (TextReader reader = new StreamReader(responseBodyStream, Encoding.UTF8))
                {
                    tokensJSON = reader.ReadToEnd();
                }
            }
        }

        private const string SettingsFileName = "client-identities.txt";
        private const string SettingsDirectoryName = "Backup-RemoteDriveAuth";
        private static string GetSettingsPath(bool create)
        {
            string root = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.None);
            string dir = Path.Combine(root, SettingsDirectoryName);
            if (create)
            {
                Directory.CreateDirectory(dir);
            }
            string path = Path.Combine(dir, SettingsFileName);
            return path;
        }

        [STAThread]
        static int Main(string[] args)
        {
            int exitCode = 1;

            if ((args.Length > 0) && args[0].Equals("-waitdebugger"))
            {
                Array.Copy(args, 1, args, 0, args.Length - 1);
                Array.Resize(ref args, args.Length - 1);
                Console.Write("Attach debugger... ");
                while (!Debugger.IsAttached)
                {
                    Thread.Sleep(100);
                }
                Console.WriteLine("found");
            }

            if ((args.Length > 0) && args[0].Equals("-break"))
            {
                Array.Copy(args, 1, args, 0, args.Length - 1);
                Array.Resize(ref args, args.Length - 1);

                Debugger.Break();
            }

            TextWriter trace = null;
            if ((args.Length > 0) && args[0].Equals("-trace"))
            {
                Array.Copy(args, 1, args, 0, args.Length - 1);
                Array.Resize(ref args, args.Length - 1);

                string logPath;
                trace = LogWriter.CreateLogFile("remotedriveauth", out logPath);
                trace.WriteLine("RemoteDriveAuth started - {0}", DateTime.Now);
            }

            IPAddress socks5Address = null;
            int socks5Port = 0;
            if ((args.Length >= 2) && args[0].Equals("-socks5"))
            {
                string proxy = args[1];
                int colon = proxy.IndexOf(':');
                if (colon < 0)
                {
                    socks5Address = new IPAddress(new byte[] { 127, 0, 0, 1 });
                }
                else
                {
                    socks5Address = IPAddress.Parse(proxy.Substring(0, colon));
                    proxy = proxy.Substring(colon + 1);
                }
                socks5Port = Int32.Parse(proxy);

                Array.Copy(args, 2, args, 0, args.Length - 2);
                Array.Resize(ref args, args.Length - 2);
            }

            string clientIdentitiesPath = GetSettingsPath(false/*create*/);
            ClientIdentities clientIdentities = new ClientIdentities(clientIdentitiesPath);

            try
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

                if (trace != null)
                {
                    if (args.Length != 0)
                    {
                        trace.WriteLine("args[0]==\"{0}\"", args[0]);
                    }
                }

                if (args.Length == 0)
                {
                    Console.WriteLine("Usage:");
                    // TODO: usage
                    Console.WriteLine();
                }
                else if (args[0].Equals("-memorize"))
                {
                    if ((args.Length != 6)
                        || !args[1].Equals("-clientid")
                        || !args[3].Equals("-clientsecret"))
                    {
                        throw new ArgumentException("Invalid program arguments");
                    }
                    string clientId = args[2];
                    string clientSecret = args[4];
                    string serviceUrl = args[5];
                    Uri serviceUri = new Uri(serviceUrl);
                    if (null == Services.FindService(serviceUri))
                    {
                        throw new ArgumentException(String.Format("Unsupported remote service: {0}", serviceUrl));
                    }

                    clientIdentities.Memorize(new ClientIdentities.ClientIdentity(serviceUri, clientId, clientSecret));
                    clientIdentities.Save(clientIdentitiesPath);
                }
                else if (args[0].Equals("-forget"))
                {
                    if (args.Length == 1)
                    {
                        clientIdentities.Forget(); // forget all
                    }
                    else if (args.Length == 2)
                    {
                        string serviceUrl = args[1];
                        Uri serviceUri = new Uri(serviceUrl);
                        if (null == Services.FindService(serviceUri))
                        {
                            Console.WriteLine("Not a supported remote service: {0}", serviceUrl);
                        }

                        clientIdentities.Forget(serviceUri);
                    }
                    else
                    {
                        throw new ArgumentException("Invalid program arguments");
                    }

                    clientIdentities.Save(clientIdentitiesPath);
                }
                else if (args[0].Equals("-promptpassword"))
                {
                    // This option enables shell scripts to prompt for password in a way that is
                    // compatible with applications like Password Safe, and without displaying the
                    // entered text on screen. The password is written to stdout in a way that
                    // shell scripts can read into a variable, which can then be passed in as an
                    // argument to Backup.exe. It uses the -protected option which uses the Windows
                    // data protection api to encrypt the password text with the user's login
                    // credential so that if the output is leaked an attacker would need to
                    // compromise the user's Windows login or OS credentials store in order to
                    // decrypt the password.

                    string prompt = null;
                    for (int i = 1; i < args.Length; i++)
                    {
                        prompt = String.Concat(prompt, prompt != null ? " " : null, args[i]);
                    }

                    ProtectedArray<byte> password;
                    using (PasswordEntryForm form = new PasswordEntryForm(prompt))
                    {
                        Application.EnableVisualStyles();
                        Application.Run(form);

                        password = form.Password;
                    }
                    using (password)
                    {
                        if (!ProtectedArray<byte>.IsNullOrEmpty(password))
                        {
                            password.Reveal();
                            byte[] encryptedPassword = ProtectedDataStorage.EncryptEphemeral(password.ExposeArray(), 0, password.Length, ProtectedDataStorage.EphemeralScope.SameLogon);

                            Console.WriteLine("-protected \"{0}\"", HexUtility.HexEncode(encryptedPassword));
                        }
                    }
                }
                else if (args[0].Equals("-auth"))
                {
                    bool refreshTokenOnly = false;
                    bool enableRefreshToken = false;
                    ProtectedArray<byte> refreshToken = null;
                    Uri remoteService = null;

                    OAuth20RemoteService authService;

                    if (args.Length != 5)
                    {
                        throw new ArgumentException("Invalid program arguments");
                    }

                    if (!args[1].Equals("-refreshtoken"))
                    {
                        throw new ArgumentException("args[1]: expected -refreshtoken");
                    }

                    if (args[2].Equals("yes"))
                    {
                        enableRefreshToken = true;
                    }
                    else if (args[2].Equals("no"))
                    {
                    }
                    else if (args[2].Equals("only"))
                    {
                        refreshTokenOnly = true;
                        enableRefreshToken = true;
                    }
                    else
                    {
                        throw new ArgumentException("args[2]: -refreshtoken option");
                    }

                    try
                    {
                        if (!args[3].Equals("-") && !String.IsNullOrEmpty(args[3]))
                        {
                            refreshToken = ProtectedArray<byte>.DecryptEphemeral(HexUtility.HexDecode(args[3]), ProtectedDataStorage.EphemeralScope.SameLogon);
                        }
                    }
                    catch (Exception)
                    {
                        throw new ArgumentException("args[3]: old refresh-token");
                    }

                    try
                    {
                        remoteService = new Uri(args[4]);
                        if (!remoteService.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
                            && !remoteService.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                        {
                            throw new ArgumentException("args[4]: remote-service");
                        }
                        authService = Services.FindService(remoteService);
                        if (authService == null)
                        {
                            throw new ArgumentException("args[4]: remote-service");
                        }
                        remoteService = authService.ServiceUri;
                    }
                    catch (UriFormatException)
                    {
                        throw new ArgumentException("args[4]: remote-service");
                    }


                    // register certificate pinning validation for service point, in case HttpWebRequest is used.
                    if (authService.CertificatePinning != null)
                    {
                        ServicePointManager.ServerCertificateValidationCallback = new HttpMethods.CertificatePinningDelegate(authService.CertificatePinning, null/*trace*/).RemoteCertificateValidationCallback;
                    }


                    ClientIdentities.ClientIdentity clientIdentity = clientIdentities.GetClientIdentity(remoteService);
                    if (clientIdentity == null)
                    {
                        clientIdentity = authService.GetDefaultClientIdentity();
                    }

                    // In the code below it is very difficult to ensure that memory is scrubbed or
                    // protected (to prevent page/hibernation leaks) regarding the refresh token.
                    // In addition to the complexities of implementing secure JSON parsing,
                    // System.Net.HttpWebRequest does not make any provision and leaves copies of
                    // plaintext all over the heap.
                    //
                    // The problem is somewhat mitigated by the very short lifetime of the
                    // RemoteDriveAuth.exe process instance.

                    string tokensJSON;
                    if (!ProtectedArray<byte>.IsNullOrEmpty(refreshToken))
                    {
                        string refreshTokenExposed; // TODO: protect this
                        try
                        {
                            refreshToken.Reveal();
                            refreshTokenExposed = Encoding.UTF8.GetString(refreshToken.ExposeArray());
                        }
                        finally
                        {
                            refreshToken.Protect();
                        }
                        GetTokensByRefresh(
                            authService,
                            clientIdentity,
                            refreshTokenExposed,
                            out tokensJSON,
                            socks5Address,
                            socks5Port,
                            trace);
                        if (String.IsNullOrEmpty(tokensJSON))
                        {
                            throw new MyApplicationException("Unable to convert refresh token to access token");
                        }
                        // TODO: fails for now to catch bugs, but ultimlately fall through to log-in case for robustness
                    }
                    else
                    {
                        // Create window asking user to log in.
                        string authorizationCode;
                        using (WebBrowserHostingForm form = new WebBrowserHostingForm(
                            authService,
                            clientIdentity,
                            enableRefreshToken,
                            socks5Address,
                            socks5Port,
                            trace))
                        {
                            Application.EnableVisualStyles();
                            Application.Run(form);

                            authorizationCode = form.AuthorizationCode;
                            if (String.IsNullOrEmpty(authorizationCode))
                            {
                                throw new InvalidDataException("Unable to obtain authorization code from login service redirect url");
                            }
                        }

                        GetTokensFromAuthCode(
                            authService,
                            clientIdentity,
                            authorizationCode,
                            out tokensJSON,
                            socks5Address,
                            socks5Port,
                            trace);
                        if (String.IsNullOrEmpty(tokensJSON))
                        {
                            throw new MyApplicationException("Unable to convert authorization code to access token");
                        }
                    }


                    JSONDictionary json = new JSONDictionary(tokensJSON);
                    if (refreshTokenOnly)
                    {
                        string refresh_token;
                        if (!json.TryGetValueAs("refresh_token", out refresh_token))
                        {
                            throw new MyApplicationException("Unable to obtain refresh token");
                        }

                        byte[] refreshTokenBytes = Encoding.ASCII.GetBytes(refresh_token);
                        byte[] refreshTokenBytesEncrypted = ProtectedDataStorage.EncryptEphemeral(refreshTokenBytes, 0, refreshTokenBytes.Length, ProtectedDataStorage.EphemeralScope.SameLogon);

                        Console.WriteLine(
                            "{0}",
                            HexUtility.HexEncode(refreshTokenBytesEncrypted));
                    }
                    else
                    {
                        // TODO: protect these:

                        string refresh_token;
                        json.TryGetValueAs("refresh_token", out refresh_token);
                        string access_token;
                        json.TryGetValueAs("access_token", out access_token);
                        long expires_in;
                        json.TryGetValueAs("expires_in", out expires_in);

                        // invoking process validates existence or absense of any of the above

                        byte[] refreshTokenBytes = Encoding.ASCII.GetBytes(refresh_token != null ? refresh_token : String.Empty);
                        byte[] refreshTokenBytesEncrypted = ProtectedDataStorage.EncryptEphemeral(refreshTokenBytes, 0, refreshTokenBytes.Length, ProtectedDataStorage.EphemeralScope.SameLogon);

                        byte[] accessTokenBytes = Encoding.ASCII.GetBytes(access_token != null ? access_token : String.Empty);
                        byte[] accessTokenBytesEncrypted = ProtectedDataStorage.EncryptEphemeral(accessTokenBytes, 0, accessTokenBytes.Length, ProtectedDataStorage.EphemeralScope.SameLogon);

                        byte[] expiresInBytes = Encoding.ASCII.GetBytes(expires_in.ToString());
                        byte[] expiresInBytesEncrypted = ProtectedDataStorage.EncryptEphemeral(expiresInBytes, 0, expiresInBytes.Length, ProtectedDataStorage.EphemeralScope.SameLogon);

                        Console.WriteLine(
                            "{0},{1},{2}",
                            // some services do not reissue the refresh token - since the encrypted version can't be checked, to make it clear empty string is returned
                            refreshTokenBytes.Length > 0 ? HexUtility.HexEncode(refreshTokenBytesEncrypted) : String.Empty,
                            HexUtility.HexEncode(accessTokenBytesEncrypted),
                            HexUtility.HexEncode(expiresInBytesEncrypted));
                    }
                }
                else
                {
                    throw new ArgumentException("Invalid program arguments");
                }


                exitCode = 0;
                if (trace != null)
                {
                    trace.WriteLine("RemoteDriveAuth.Main() execution reached end of primary try block without exception");
                }
            }
            catch (ExitCodeException exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteDriveAuth.Main() caught exit code exception: {0}", exception);
                }
                Console.Error.WriteLine(exception.Message);
                exitCode = exception.ExitCode;
            }
            catch (MyWebException exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteDriveAuth.Main() caught web access exception: {0}", exception);
                }
                Console.Error.WriteLine(exception);
                if (exception.WebExceptionStatus != WebExceptionStatus.ProtocolError)
                {
                    exitCode = (int)ExitCodeException.ExitCodes.RetriableError;
                }
                else if (exception.WebExceptionStatus == WebExceptionStatus.ProtocolError)
                {
                    if ((exception.HttpStatus >= (HttpStatusCode)500)
                        && (exception.HttpStatus < (HttpStatusCode)599))
                    {
                        exitCode = (int)ExitCodeException.ExitCodes.RetriableError;
                    }
                }
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteDriveAuth.Main() caught fatal exception: {0}", exception);
                }
                Console.Error.WriteLine(exception);
            }
            finally
            {
                if (trace != null)
                {
                    trace.WriteLine("RemoteDriveAuth exiting with result code {0} - {1}", exitCode, DateTime.Now);
                    trace.Close();
                    trace = null;
                }
            }

            return exitCode;
        }
    }
}
