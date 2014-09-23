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
using System.Drawing;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;
using System.Threading;
using System.Web;
using System.Windows.Forms;

using Backup;
using JSON;

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

        public static OAuth20RemoteService FindService(Uri requestedServiceUri)
        {
            return Array.Find(Services.SupportedServices, delegate(OAuth20RemoteService candidate) { return requestedServiceUri.Host.Equals(candidate.ServiceUri.Host, StringComparison.OrdinalIgnoreCase); });
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
                using (TextReader reader = new StreamReader(path))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        string[] parts = line.Split(new char[] { ';' });
                        ClientIdentity identity = new ClientIdentity(HexUtility.HexDecode(parts[1]), HexUtility.HexDecode(parts[0]));
                        identities.Add(identity.ServiceUri.ToString(), identity);
                    }
                }
            }
        }

        public void Save(string path)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

            Directory.CreateDirectory(Path.GetDirectoryName(path));
            using (TextWriter writer = new StreamWriter(path))
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
            identities.TryGetValue(serviceUri.ToString(), out identity);
            return identity;
        }

        public void Memorize(ClientIdentity identity)
        {
            identities[identity.ServiceUri.ToString()] = identity; // overwrite any existing
        }

        public void Forget(Uri serviceUri)
        {
            string serviceUrl = serviceUri.ToString();
            if (identities.ContainsKey(serviceUrl))
            {
                identities.Remove(serviceUrl);
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

    public class ExitCodeException : ApplicationException
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

    [PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
    public class WebBrowserHostingForm : Form
    {
        private const int DefaultWidth = 768;
        private const int DefaultHeight = 600;

        private OAuth20RemoteService authService;

        public WebBrowserHostingForm(OAuth20RemoteService authService, ClientIdentities.ClientIdentity clientIdentity, bool enableRefreshToken)
        {
            this.authService = authService;

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

        // Displays the Save dialog box. 
        private void saveAsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            webBrowser1.ShowSaveAsDialog();
        }

        // Displays the Page Setup dialog box. 
        private void pageSetupToolStripMenuItem_Click(object sender, EventArgs e)
        {
            webBrowser1.ShowPageSetupDialog();
        }

        // Displays the Print dialog box. 
        private void printToolStripMenuItem_Click(object sender, EventArgs e)
        {
            webBrowser1.ShowPrintDialog();
        }

        // Displays the Print Preview dialog box. 
        private void printPreviewToolStripMenuItem_Click(object sender, EventArgs e)
        {
            webBrowser1.ShowPrintPreviewDialog();
        }

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

            if (url.StartsWith(authService.AuthorizedRedirectUrlBrowser, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    // localhost redirect method

                    authorizationCode = Program.ExtractAuthorizationCode(e.Url.Query.Substring(1), "code");
                }
                catch (Exception)
                {
                    // urn:ietf:wg:oauth:2.0:oob redirect method

                    HtmlDocument htmlDoc = webBrowser1.Document;
                    HtmlElementCollection titles = htmlDoc.GetElementsByTagName("TITLE");
                    foreach (HtmlElement element in titles)
                    {
                        string innerText = element.InnerText;
                        try
                        {
                            authorizationCode = Program.ExtractAuthorizationCode(innerText, "code");
                            break;
                        }
                        catch (Exception)
                        {
                        }
                    }
                }
                finally
                {
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

        // Navigates webBrowser1 to the search page of the current user. 
        private void searchButton_Click(object sender, EventArgs e)
        {
            webBrowser1.GoSearch();
        }

        // Prints the current document using the current print settings. 
        private void printButton_Click(object sender, EventArgs e)
        {
            webBrowser1.Print();
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
        private ToolStripMenuItem fileToolStripMenuItem, saveAsToolStripMenuItem, printToolStripMenuItem, printPreviewToolStripMenuItem, exitToolStripMenuItem, pageSetupToolStripMenuItem, propertiesToolStripMenuItem;
        private ToolStripSeparator toolStripSeparator1, toolStripSeparator2;

        private ToolStrip toolStrip1, toolStrip2;
        private ToolStripTextBox toolStripTextBox1;
        private ToolStripButton goButton, backButton, forwardButton, stopButton, refreshButton, homeButton, searchButton, printButton;

        private StatusStrip statusStrip1;
        private ToolStripStatusLabel toolStripStatusLabel1;

        private void InitializeForm()
        {
            this.Width = DefaultWidth;
            this.Height = DefaultHeight;

            webBrowser1 = new WebBrowser();

            menuStrip1 = new MenuStrip();
            fileToolStripMenuItem = new ToolStripMenuItem();
            saveAsToolStripMenuItem = new ToolStripMenuItem();
            toolStripSeparator1 = new ToolStripSeparator();
            printToolStripMenuItem = new ToolStripMenuItem();
            printPreviewToolStripMenuItem = new ToolStripMenuItem();
            toolStripSeparator2 = new ToolStripSeparator();
            exitToolStripMenuItem = new ToolStripMenuItem();
            pageSetupToolStripMenuItem = new ToolStripMenuItem();
            propertiesToolStripMenuItem = new ToolStripMenuItem();

            toolStrip1 = new ToolStrip();
            goButton = new ToolStripButton();
            backButton = new ToolStripButton();
            forwardButton = new ToolStripButton();
            stopButton = new ToolStripButton();
            refreshButton = new ToolStripButton();
            homeButton = new ToolStripButton();
            searchButton = new ToolStripButton();
            printButton = new ToolStripButton();

            toolStrip2 = new ToolStrip();
            toolStripTextBox1 = new ToolStripTextBox();

            statusStrip1 = new StatusStrip();
            toolStripStatusLabel1 = new ToolStripStatusLabel();

            menuStrip1.Items.Add(fileToolStripMenuItem);

            fileToolStripMenuItem.DropDownItems.AddRange(new ToolStripItem[] { saveAsToolStripMenuItem, toolStripSeparator1, pageSetupToolStripMenuItem, printToolStripMenuItem, printPreviewToolStripMenuItem, toolStripSeparator2, propertiesToolStripMenuItem, exitToolStripMenuItem });

            fileToolStripMenuItem.Text = "&File";
            saveAsToolStripMenuItem.Text = "Save &As...";
            pageSetupToolStripMenuItem.Text = "Page Set&up...";
            printToolStripMenuItem.Text = "&Print...";
            printPreviewToolStripMenuItem.Text = "Print Pre&view...";
            propertiesToolStripMenuItem.Text = "Properties";
            exitToolStripMenuItem.Text = "E&xit";

            printToolStripMenuItem.ShortcutKeys = Keys.Control | Keys.P;

            saveAsToolStripMenuItem.Click += new EventHandler(saveAsToolStripMenuItem_Click);
            pageSetupToolStripMenuItem.Click += new EventHandler(pageSetupToolStripMenuItem_Click);
            printToolStripMenuItem.Click += new EventHandler(printToolStripMenuItem_Click);
            printPreviewToolStripMenuItem.Click += new EventHandler(printPreviewToolStripMenuItem_Click);
            propertiesToolStripMenuItem.Click += new EventHandler(propertiesToolStripMenuItem_Click);
            exitToolStripMenuItem.Click += new EventHandler(exitToolStripMenuItem_Click);

            toolStrip1.Items.AddRange(new ToolStripItem[] { goButton, backButton, forwardButton, stopButton, refreshButton, homeButton, searchButton, printButton });

            goButton.Text = "Go";
            backButton.Text = "Back";
            forwardButton.Text = "Forward";
            stopButton.Text = "Stop";
            refreshButton.Text = "Refresh";
            homeButton.Text = "Home";
            searchButton.Text = "Search";
            printButton.Text = "Print";

            backButton.Enabled = false;
            forwardButton.Enabled = false;

            goButton.Click += new EventHandler(goButton_Click);
            backButton.Click += new EventHandler(backButton_Click);
            forwardButton.Click += new EventHandler(forwardButton_Click);
            stopButton.Click += new EventHandler(stopButton_Click);
            refreshButton.Click += new EventHandler(refreshButton_Click);
            homeButton.Click += new EventHandler(homeButton_Click);
            searchButton.Click += new EventHandler(searchButton_Click);
            printButton.Click += new EventHandler(printButton_Click);

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

        private static void GetTokensFromAuthCode(OAuth20RemoteService authService, ClientIdentities.ClientIdentity clientIdentity, string authorizationCode, out string tokensJSON)
        {
            tokensJSON = null;

            HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(authService.TokenExchangeProviderUrl);
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            using (Stream requestStream = request.GetRequestStream())
            {
                using (TextWriter requestWriter = new StreamWriter(requestStream, Encoding.ASCII))
                {
                    string message = String.Format("client_id={0}&client_secret={1}&code={2}&grant_type=authorization_code&redirect_uri={3}", clientIdentity.ClientId, clientIdentity.ClientSecret, authorizationCode, authService.AuthorizedRedirectUrl);
                    requestWriter.Write(message);
                }
            }
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                HttpStatusCode responseCode = response.StatusCode;
                Uri responseUri = response.ResponseUri;

                using (Stream stream = response.GetResponseStream())
                {
                    using (TextReader reader = new StreamReader(stream))
                    {
                        tokensJSON = reader.ReadToEnd();
                    }
                }
            }
        }

        private static void GetTokensByRefresh(OAuth20RemoteService authService, ClientIdentities.ClientIdentity clientIdentity, string refreshToken, out string tokensJSON)
        {
            tokensJSON = null;

            HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(authService.TokenExchangeProviderUrl);
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            using (Stream requestStream = request.GetRequestStream())
            {
                using (TextWriter requestWriter = new StreamWriter(requestStream, Encoding.ASCII))
                {
                    string message = String.Format("client_id={0}&client_secret={1}&grant_type=refresh_token&refresh_token={2}", clientIdentity.ClientId, clientIdentity.ClientSecret, refreshToken);
                    requestWriter.Write(message);
                }
            }
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                HttpStatusCode responseCode = response.StatusCode;
                Uri responseUri = response.ResponseUri;

                using (Stream stream = response.GetResponseStream())
                {
                    using (TextReader reader = new StreamReader(stream))
                    {
                        tokensJSON = reader.ReadToEnd();
                    }
                }
            }
        }

        const string LocalApplicationDirectoryName = "Backup-RemoteDriveAuth";
        static string GetLocalAppDataPath(bool create, bool roaming)
        {
            string localAppDataPath = Environment.GetEnvironmentVariable(roaming ? "APPDATA" : "LOCALAPPDATA");
            if (localAppDataPath == null)
            {
                localAppDataPath = Environment.ExpandEnvironmentVariables("%USERPROFILE%\\Application Data"); // Windows XP fallback
            }
            localAppDataPath = Path.Combine(localAppDataPath, LocalApplicationDirectoryName);
            if (create && !Directory.Exists(localAppDataPath))
            {
                Directory.CreateDirectory(localAppDataPath);
            }
            return localAppDataPath;
        }

        [STAThread]
        static void Main(string[] args)
        {
            Environment.ExitCode = 1;

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

            string localAppDataPath = GetLocalAppDataPath(false/*create*/, true/*roaming*/);
            string clientIdentitiesPath = Path.Combine(localAppDataPath, "client-identities.txt");
            ClientIdentities clientIdentities = new ClientIdentities(clientIdentitiesPath);

            try
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

                if (args.Length == 0)
                {
                    Console.WriteLine("Usage:");
                    Console.WriteLine();
                    return;
                }

                if (args[0].Equals("-memorize"))
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
                        if (!args[3].Equals("-"))
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
                        GetTokensByRefresh(authService, clientIdentity, refreshTokenExposed, out tokensJSON);
                        if (String.IsNullOrEmpty(tokensJSON))
                        {
                            throw new ApplicationException("Unable to convert refresh token to access token");
                        }
                        // TODO: fails for now to catch bugs, but ultimlately fall through to log-in case for robustness
                    }
                    else
                    {
                        // Create window asking user to log in.
                        string authorizationCode;
                        using (WebBrowserHostingForm form = new WebBrowserHostingForm(authService, clientIdentity, enableRefreshToken))
                        {
                            Application.EnableVisualStyles();
                            Application.Run(form);

                            authorizationCode = form.AuthorizationCode;
                            if (String.IsNullOrEmpty(authorizationCode))
                            {
                                throw new InvalidDataException("Unable to obtain authorization code from login service redirect url");
                            }
                        }

                        GetTokensFromAuthCode(authService, clientIdentity, authorizationCode, out tokensJSON);
                        if (String.IsNullOrEmpty(tokensJSON))
                        {
                            throw new ApplicationException("Unable to convert authorization code to access token");
                        }
                    }


                    JSONDictionary json = new JSONDictionary(tokensJSON);
                    if (refreshTokenOnly)
                    {
                        string refresh_token;
                        if (!json.TryGetValueAs("refresh_token", out refresh_token))
                        {
                            throw new ApplicationException("Unable to obtain refresh token");
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
                            HexUtility.HexEncode(refreshTokenBytesEncrypted),
                            HexUtility.HexEncode(accessTokenBytesEncrypted),
                            HexUtility.HexEncode(expiresInBytesEncrypted));
                    }
                }

                Environment.ExitCode = 0;
            }
            catch (ExitCodeException exception)
            {
                Console.Error.WriteLine(exception.Message);
                Environment.ExitCode = exception.ExitCode;
            }
            catch (WebException exception)
            {
                Console.Error.WriteLine(exception);
                if (exception.Status != WebExceptionStatus.ProtocolError)
                {
                    Environment.ExitCode = (int)ExitCodeException.ExitCodes.RetriableError;
                }
                else if (exception.Status == WebExceptionStatus.ProtocolError)
                {
                    WebResponse response = exception.Response;
                    if (response != null)
                    {
                        HttpWebResponse httpWebResponse;
                        if ((httpWebResponse = response as HttpWebResponse) != null)
                        {
                            if ((httpWebResponse.StatusCode >= (HttpStatusCode)500)
                                && (httpWebResponse.StatusCode < (HttpStatusCode)599))
                            {
                                Environment.ExitCode = (int)ExitCodeException.ExitCodes.RetriableError;
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine(exception);
            }
        }
    }
}
