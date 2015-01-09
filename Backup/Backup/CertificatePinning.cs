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
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using HexUtil;
using Http;

namespace Backup
{
    public class CertificatePinning : ICertificatePinning
    {
        // Certificate pinning

        // Certificate pinning pre-registers the public key of well-known services and requires
        // an actual TLS connection to present a validated certificate using the same public key,
        // as proof that the service has the correct private key. This defeats certain MITM
        // attacks mounted by, e.g. corrupt/inept CAs.
        // https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning
        // also,
        // TODO: monitor RFC for acceptance and adopt for servers that begin supporting it
        // (so far: http://tools.ietf.org/html/draft-ietf-websec-key-pinning-21)

        // Use X509Chain to allow ancestor certificates to be pinned:
        // see:
        // https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning
        // https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning/Implementation_Details
        // also
        // https://src.chromium.org/viewvc/chrome/trunk/src/net/http/transport_security_state_static.json

        private readonly Dictionary<string, string[]> hashToPrincipal = new Dictionary<string, string[]>();

        public CertificatePinning(KeyValuePair<string, string>[] certHashes)
        {
            foreach (KeyValuePair<string, string> certHash in certHashes)
            {
                string[] principals;
                if (!hashToPrincipal.TryGetValue(certHash.Value, out principals))
                {
                    principals = new string[0];
                    hashToPrincipal.Add(certHash.Value, principals);
                }
                Array.Resize(ref principals, principals.Length + 1);
                principals[principals.Length - 1] = certHash.Key;
                hashToPrincipal[certHash.Value] = principals;
            }
        }

        public bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors, TextWriter trace)
        {
            if (trace != null)
            {
                trace.WriteLine("+RemoteCertificateValidationCallback: sslPolicyErrors={0}", sslPolicyErrors);
            }

            if (sslPolicyErrors != SslPolicyErrors.None)
            {
                if (trace != null)
                {
                    trace.WriteLine("-RemoteCertificateValidationCallback: return false due to sslPolicyErrors");
                }
                return false;
            }

            for (int i = 0; i < chain.ChainElements.Count; i++)
            {
                X509ChainElement element = chain.ChainElements[i];
                X509Certificate chainCert = element.Certificate;

                byte[] publicKeyQualified = chainCert.GetPublicKey(); // full ASN.1 (der) key incl. type and parameters
                string publicKeyHash = Convert.ToBase64String(SHA256.Create().ComputeHash(publicKeyQualified));

                if (trace != null)
                {
                    trace.WriteLine(" RemoteCertificateValidationCallback: [{2}/{3}] publicKey={0} hash={1}", HexUtility.HexEncode(publicKeyQualified), publicKeyHash, i + 1, chain.ChainElements.Count);
                }

                if (hashToPrincipal.ContainsKey(publicKeyHash))
                {
                    if (trace != null)
                    {
                        trace.WriteLine("-RemoteCertificateValidationCallback: return true - certificate key recognized");
                    }
                    return true;
                }
            }

            if (trace != null)
            {
                trace.WriteLine("-RemoteCertificateValidationCallback: return false - certificate key not found");
            }
            return false;
        }
    }
}
