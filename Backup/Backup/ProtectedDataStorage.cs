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
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Backup
{
    ////////////////////////////////////////////////////////////////////////////
    //
    // Protected in-memory objects
    //
    ////////////////////////////////////////////////////////////////////////////

    // The ProtectedArray class uses CryptProtectMemory to store sensitive data
    // in an encrypted form in memory. The key used by the system is stored in
    // non-paged kernel memory, never saved (except perhaps during hibernation -
    // hopefully in a secure form!), and regenerated randomly on each reboot.
    // The configuration option CRYPTPROTECTMEMORY_SAME_PROCESS ensures each
    // process has a unique key, protecting against memory-exposure bugs (of the
    // type that Heartbleed was) and making life more difficult (but not
    // impossible) for debugger-style exploits.
    // When the internal data is "revealed", the plaintext buffer is pinned on
    // the heap to prevent the garbage collector from leaving copies around.
    //
    // Use this class to protect data in the following ways:
    // - Allow garbage collection to leave [protected] copies of buffers around
    //   for potentially long durations without increasing attack surface.
    // - Allow pages to be written to page file or hibernation file without
    //   worry of data being recovered.
    // - Allow process memory dumps or system memory dumps to occur without
    //   worry of data being recovered (except in case of a system dump where
    //   the attacker can manage to extract the key used for protecting data
    //   by CryptProtectMemory)
    //
    // It is meant that the data will be in the "revealed" state for very short
    // periods of time and spend most of its time in repose in the "protected"
    // state. It reduces but DOES NOT ELIMINATE the chance that plaintext
    // copies of sensitive data may make it out of the process onto disk.
    // It also increases the complexity of a debugger-style attack, but does
    // not prevent it, since knowledge of the program code structure can lead
    // to waiting for opportune moments to capture a "revealed" buffer. Also,
    // an attacker who gains local execution permission can force the process
    // to execute the "reveal" code, as well as do any number of other very
    // bad things that cannot be mitigated.
    //
    // Note: VirtualLock is not used to pin pages in memory, because contrary to
    // MSDN documentation, it apparently does not actually guarrantee that, and
    // what it does do is redundant to what the garbage collector does to ensure
    // that the active heap data is in the working set. (see http://blogs.msdn.com/b/oldnewthing/archive/2007/11/06/5924058.aspx)
    // And it is very likely that a briefly "revealed" buffer will be in the
    // working set due to active and recent use. Therefore, encrypting to protect
    // against write-out is considered more comprehensive and protective against a
    // wider variety of attacks.
    public class ProtectedArray<T> : IDisposable
        where T : struct
    {
        private readonly T[] revealedArray;
        private readonly byte[] protectedArray;
        private readonly int revealedArrayLengthBytes;
        private GCHandle revealedPinner;
        private State state;
        private readonly RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

        private enum State
        {
            Invalid,
            Revealed,
            Protected,
        }

        private ProtectedArray()
        {
            throw new NotSupportedException();
        }

        public ProtectedArray(int length, bool leaveRevealed)
        {
            this.revealedArray = new T[length];
            revealedArrayLengthBytes = Buffer.ByteLength(revealedArray);
            this.protectedArray = new byte[(Math.Max(revealedArrayLengthBytes, ProtectedDataStorage.CRYPTPROTECTMEMORY_BLOCK_SIZE) + ProtectedDataStorage.CRYPTPROTECTMEMORY_BLOCK_SIZE - 1) & ~(ProtectedDataStorage.CRYPTPROTECTMEMORY_BLOCK_SIZE - 1)];
            this.revealedPinner = GCHandle.Alloc(this.revealedArray, GCHandleType.Pinned);
            this.state = State.Revealed;
            if (!leaveRevealed)
            {
                Protect();
            }
        }

        public ProtectedArray(int length)
            : this(length, false/*leaveRevealed*/)
        {
        }

        public ProtectedArray(ProtectedArray<T> source)
        {
            if (source.state != State.Protected)
            {
                throw new InvalidOperationException();
            }

            this.revealedArray = new T[source.revealedArray.Length];
            this.protectedArray = new byte[source.protectedArray.Length];
            this.revealedArrayLengthBytes = source.revealedArrayLengthBytes;
            Buffer.BlockCopy(source.revealedArray, 0, this.revealedArray, 0, this.revealedArray.Length);
            Buffer.BlockCopy(source.protectedArray, 0, this.protectedArray, 0, this.protectedArray.Length);
            this.state = source.state;
            Protect();
        }

        public static ProtectedArray<byte> CreateFromProtectedData(byte[] encrypted, byte[] secondaryEntropy)
        {
            byte[] decrypted = ProtectedDataStorage.Decrypt(encrypted, 0, encrypted.Length, secondaryEntropy);
            GCHandle decryptedPinner = GCHandle.Alloc(decrypted, GCHandleType.Pinned);
            try
            {
                ProtectedArray<byte> array = new ProtectedArray<byte>(decrypted.Length, true/*leaveRevealed*/);
                Buffer.BlockCopy(decrypted, 0, array.ExposeByteArray(), 0, decrypted.Length);
                array.Protect();
                return array;
            }
            finally
            {
                Array.Clear(decrypted, 0, decrypted.Length);
                decryptedPinner.Free();
            }
        }

        public static ProtectedArray<byte> CreateFromUnicode(char[] unicode)
        {
            ProtectedArray<byte> array = new ProtectedArray<byte>(Encoding.UTF8.GetByteCount(unicode), true/*leaveRevealed*/);
            Encoding.UTF8.GetBytes(unicode, 0, unicode.Length, array.ExposeByteArray(), 0);
            array.Protect();
            return array;
        }

        public static ProtectedArray<byte> CreateFromUnicode(string unicode)
        {
            ProtectedArray<byte> array = new ProtectedArray<byte>(Encoding.UTF8.GetByteCount(unicode), true/*leaveRevealed*/);
            Encoding.UTF8.GetBytes(unicode, 0, unicode.Length, array.ExposeByteArray(), 0);
            array.Protect();
            return array;
        }

        public void Scrub<V>(V[] array) where V : struct
        {
            byte[] random = new byte[Buffer.ByteLength(array)];
            rng.GetBytes(random);
            Buffer.BlockCopy(random, 0, array, 0, random.Length);
        }

        ~ProtectedArray()
        {
            if (state == State.Revealed)
            {
                throw new InvalidOperationException("Leaked a clear-text ProtectedArray object!");
            }
        }

        public void Dispose()
        {
            if (state != State.Invalid)
            {
                if (protectedArray != null)
                {
                    rng.GetBytes(protectedArray);
                }
                if (revealedArray != null)
                {
                    Scrub(revealedArray);
                }

                if (revealedPinner.IsAllocated)
                {
                    revealedPinner.Free();
                }

                state = State.Invalid;
            }

            GC.SuppressFinalize(this);
        }

        public void Protect()
        {
            if (state == State.Revealed)
            {
                GCHandle protectedPinner = GCHandle.Alloc(protectedArray, GCHandleType.Pinned);
                Buffer.BlockCopy(revealedArray, 0, protectedArray, 0, revealedArrayLengthBytes);
                ProtectedDataStorage.WrappedCryptProtectMemory(protectedArray, ProtectedDataStorage.CryptProtectMemoryFlags.CRYPTPROTECTMEMORY_SAME_PROCESS);
                Scrub(revealedArray);
                protectedPinner.Free();

                revealedPinner.Free();
                state = State.Protected;

                GC.SuppressFinalize(this);
            }
            else if (state == State.Protected)
            {
            }
            else
            {
                throw new InvalidOperationException();
            }
        }

        public void Reveal()
        {
            if (state == State.Protected)
            {
                revealedPinner = GCHandle.Alloc(revealedArray, GCHandleType.Pinned);
                state = State.Revealed;

                GCHandle protectedPinner = GCHandle.Alloc(protectedArray, GCHandleType.Pinned);
                ProtectedDataStorage.WrappedCryptUnprotectMemory(protectedArray, ProtectedDataStorage.CryptProtectMemoryFlags.CRYPTPROTECTMEMORY_SAME_PROCESS);
                Buffer.BlockCopy(protectedArray, 0, revealedArray, 0, revealedArrayLengthBytes);
                rng.GetBytes(protectedArray);
                protectedPinner.Free();

                GC.ReRegisterForFinalize(this);
            }
            else if (state == State.Revealed)
            {
            }
            else
            {
                throw new InvalidOperationException();
            }
        }

        public void AbsorbRevealedAndScrub(T[] source)
        {
            GCHandle sourcePinner = GCHandle.Alloc(source, GCHandleType.Pinned);

            try
            {
                if (state != State.Revealed)
                {
                    Scrub(source);
                    throw new InvalidOperationException();
                }

                if (source.Length != revealedArray.Length)
                {
                    Scrub(source);
                    throw new IndexOutOfRangeException();
                }

                Buffer.BlockCopy(source, 0, revealedArray, 0, revealedArrayLengthBytes);
                Scrub(source);
            }
            finally
            {
                sourcePinner.Free();
            }
        }

        public void AbsorbProtectAndScrub(T[] source)
        {
            GCHandle sourcePinner = GCHandle.Alloc(source, GCHandleType.Pinned);

            try
            {
                if (state != State.Protected)
                {
                    Scrub(source);
                    throw new InvalidOperationException();
                }

                if (source.Length != revealedArray.Length)
                {
                    Scrub(source);
                    throw new IndexOutOfRangeException();
                }

                revealedPinner = GCHandle.Alloc(revealedArray, GCHandleType.Pinned);
                state = State.Revealed;
                Buffer.BlockCopy(source, 0, revealedArray, 0, revealedArrayLengthBytes);
                Scrub(source);
                Protect();
            }
            finally
            {
                sourcePinner.Free();
            }
        }

        public int Length { get { return revealedArray.Length; } }

        public T this[int index]
        {
            get
            {
                if (state != State.Revealed)
                {
                    throw new InvalidOperationException();
                }
                return revealedArray[index];
            }
            set
            {
                if (state != State.Revealed)
                {
                    throw new InvalidOperationException();
                }
                revealedArray[index] = value;
            }
        }

        public T[] ExposeByteArray()
        {
            if (state != State.Revealed)
            {
                throw new InvalidOperationException();
            }
            return revealedArray;
        }

        public static ProtectedArray<T> Append(ProtectedArray<T> prefix, T item)
        {
            ProtectedArray<T> combined = new ProtectedArray<T>(prefix.Length + 1);
            combined.Reveal();
            prefix.Reveal();
            Array.Copy(prefix.revealedArray, 0, combined.revealedArray, 0, prefix.Length);
            prefix.Protect();
            combined.revealedArray[prefix.Length] = item;
            combined.Protect();
            return combined;
        }

        public static ProtectedArray<T> RemoveLast(ProtectedArray<T> source)
        {
            ProtectedArray<T> reduced = new ProtectedArray<T>(source.Length - 1);
            reduced.Reveal();
            source.Reveal();
            Array.Copy(source.revealedArray, 0, reduced.revealedArray, 0, reduced.Length);
            source.Protect();
            reduced.Protect();
            return reduced;
        }
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Windows Protected Storage (DPAPI)
    //
    ////////////////////////////////////////////////////////////////////////////

    public static class ProtectedDataStorage
    {
        // http://www.pinvoke.net/default.aspx/crypt32/CryptProtectData.html
        // http://msdn.microsoft.com/en-us/library/ms995355.aspx

        // From WinCrypt.h

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;

            public byte[] GetData()
            {
                byte[] data = new byte[cbData];
                if (pbData != IntPtr.Zero)
                {
                    Marshal.Copy(pbData, data, 0, cbData);
                }
                return data;
            }

            public void SetData(byte[] data, int index, int count)
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

            public void Clear()
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
            CRYPTPROTECT_VERIFY_PROTECTION = 0x40,

            // Regenerate the local machine protection
            CRYPTPROTECT_CRED_REGENERATE = 0x80,
        }

        [Flags]
        private enum CryptProtectPromptFlags
        {
            // prompt on unprotect
            CRYPTPROTECT_PROMPT_ON_UNPROTECT = 0x1,

            // prompt on protect
            CRYPTPROTECT_PROMPT_ON_PROTECT = 0x2,

            // default to strong variant UI protection (user supplied password currently).
            CRYPTPROTECT_PROMPT_STRONG = 0x08,

            // require strong variant UI protection (user supplied password currently).
            CRYPTPROTECT_PROMPT_REQUIRE_STRONG = 0x10,
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


        public const Int32 CRYPTPROTECTMEMORY_BLOCK_SIZE = 16;

        [Flags]
        public enum CryptProtectMemoryFlags
        {
            // Encrypt/Decrypt within current process context.
            CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00,

            // Encrypt/Decrypt across process boundaries.
            // eg: encrypted buffer passed across LPC to another process which calls CryptUnprotectMemory.
            CRYPTPROTECTMEMORY_CROSS_PROCESS = 0x01,

            // Encrypt/Decrypt across callers with same LogonId.
            // eg: encrypted buffer passed across LPC to another process which calls CryptUnprotectMemory whilst impersonating.
            CRYPTPROTECTMEMORY_SAME_LOGON = 0x02,
        }

        [DllImport("Crypt32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptProtectMemory(
            byte[] pData,
            Int32 cbData,
            CryptProtectMemoryFlags dwFlags);

        [DllImport("Crypt32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptUnprotectMemory(
            byte[] pData,
            Int32 cbData,
            CryptProtectMemoryFlags dwFlags);

        [DllImport("advapi32.dll", SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int SystemFunction040(
            byte[] pDataIn,
            int cbDataIn,
            CryptProtectMemoryFlags dwFlags);

        [DllImport("advapi32.dll", SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int SystemFunction041(
            byte[] pDataIn,
            int cbDataIn,
            CryptProtectMemoryFlags dwFlags);

        public static void WrappedCryptProtectMemory(byte[] data, CryptProtectMemoryFlags flags)
        {
            try
            {
                // Windows Vista and later
                CryptProtectMemory(data, data.Length, flags);
                if (Marshal.GetLastWin32Error() != 0)
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }
            }
            catch (EntryPointNotFoundException)
            {
                // Windows XP fallback
                // RTL_ENCRYPT_MEMORY_SIZE == 8, which is covered by CRYPTPROTECTMEMORY_BLOCK_SIZE == 16
                // Flags also the same
                int result = SystemFunction040(data, data.Length, flags);
                if (result != 0)
                {
                    Marshal.ThrowExceptionForHR(result);
                }
            }
        }

        public static void WrappedCryptUnprotectMemory(byte[] data, CryptProtectMemoryFlags flags)
        {
            try
            {
                // Windows Vista and later
                CryptUnprotectMemory(data, data.Length, flags);
                if (Marshal.GetLastWin32Error() != 0)
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }
            }
            catch (EntryPointNotFoundException)
            {
                // Windows XP fallback
                // RTL_ENCRYPT_MEMORY_SIZE == 8, which is covered by CRYPTPROTECTMEMORY_BLOCK_SIZE == 16
                // Flags also the same
                int result = SystemFunction041(data, data.Length, flags);
                if (result != 0)
                {
                    Marshal.ThrowExceptionForHR(result);
                }
            }
        }


        public static byte[] Encrypt(byte[] plaintext, int index, int count, byte[] secondaryEntropy)
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
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }
            encrypted = savedProtected.GetData();
            savedPlaintext.Clear();
            entropyOptional.Clear();
            savedProtected.Clear();
            return encrypted;
        }

        public static byte[] Decrypt(byte[] encrypted, int index, int count, byte[] secondaryEntropy)
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
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }
            plaintext = savedPlaintext.GetData();
            savedProtected.Clear();
            entropyOptional.Clear();
            savedPlaintext.Clear();
            return plaintext;
        }
    }
}
