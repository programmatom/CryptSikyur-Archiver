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
using System.Runtime.InteropServices;
using System.Text;

namespace Backup
{
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
}
