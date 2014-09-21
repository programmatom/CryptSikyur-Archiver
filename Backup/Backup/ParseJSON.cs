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

namespace Backup
{
    ////////////////////////////////////////////////////////////////////////////
    //
    // JSON Parsing
    //
    ////////////////////////////////////////////////////////////////////////////

    // http://json.org or http://www.ietf.org/rfc/rfc4627.txt
    public class JSONDictionary
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

        private const string Delimiters = "[{]}:,";
        private const string ExtraLiteralDelimiters = ".+-";
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
                while (true)
                {
                    i++;
                    if (s[i] == '"')
                    {
                        sb.Append(s[i]);
                        break;
                    }
                    else if (s[i] != '\\')
                    {
                        sb.Append(s[i]);
                    }
                    else
                    {
                        i++;
                        switch (s[i])
                        {
                            default:
                                throw new InvalidDataException();
                            case '"':
                            case '\\':
                            case '/':
                                sb.Append(s[i]);
                                break;
                            case 'b':
                                sb.Append((char)0x0008);
                                break;
                            case 'f':
                                sb.Append((char)0x000c);
                                break;
                            case 'n':
                                sb.Append((char)0x000a);
                                break;
                            case 'r':
                                sb.Append((char)0x000d);
                                break;
                            case 't':
                                sb.Append((char)0x0009);
                                break;
                            case 'u':
                                char c = (char)0;
                                for (int j = 1; j <= 4; j++)
                                {
                                    int k = "0123456789abcdef".IndexOf(Char.ToLowerInvariant(s[i + j]));
                                    if (k < 0)
                                    {
                                        throw new InvalidDataException();
                                    }
                                    c = (char)((c << 4) | k);
                                }
                                sb.Append(c);
                                i += 4;
                                break;
                        }
                    }
                }
                i++;
                return sb.ToString();
            }
            else if (Delimiters.IndexOf(s[i]) >= 0)
            {
                string r = new String(s[i], 1);
                i++;
                return r;
            }
            else if (Char.IsLetterOrDigit(s[i]) || (ExtraLiteralDelimiters.IndexOf(s[i]) >= 0))
            {
                StringBuilder sb = new StringBuilder();
                while (Char.IsLetterOrDigit(s[i]) || (ExtraLiteralDelimiters.IndexOf(s[i]) >= 0))
                {
                    sb.Append(s[i]);
                    i++;
                }
                return sb.ToString();
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
            long l;
            double d;

            int oldi = i;
            string t = NextToken(s, ref i);

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
            else if (t == "null")
            {
                return null;
            }
            else if (Int64.TryParse(t, out l))
            {
                return l;
            }
            else if (Double.TryParse(t, out d))
            {
                return d;
            }
            else
            {
                throw new InvalidDataException();
            }
        }
    }
}
