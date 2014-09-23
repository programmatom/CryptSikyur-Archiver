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
using System.IO;
using System.Text;

namespace Backup
{
    public static class HexUtility
    {
        ////////////////////////////////////////////////////////////////////////////
        //
        // Hex encode/decode functions
        //
        ////////////////////////////////////////////////////////////////////////////

        private const string Hex = "0123456789abcdef";

        public static string HexEncode(byte[] data)
        {
            StringBuilder encoded = new StringBuilder(data.Length * 2);
            foreach (byte b in data)
            {
                encoded.Append(Hex[(b >> 4) & 0x0f]);
                encoded.Append(Hex[b & 0x0f]);
            }
            return encoded.ToString();
        }

        public static string HexEncodeASCII(string s)
        {
            byte[] b = Encoding.ASCII.GetBytes(s);
            return HexEncode(b);
        }

        public static byte[] HexDecode(string s)
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
    }
}
