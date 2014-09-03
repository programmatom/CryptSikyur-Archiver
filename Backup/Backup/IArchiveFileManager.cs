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
using System.IO;
using System.Threading;

namespace Backup
{
    public interface IArchiveFileManager : IDisposable
    {
        // File content access methods
        ILocalFileCopy Read(string name, ProgressTracker progressTracker, TextWriter trace);
        ILocalFileCopy WriteTemp(string nameTemp, TextWriter trace);
        void Commit(ILocalFileCopy localFile, string nameTemp, string name, bool overwrite, ProgressTracker progressTracker, TextWriter trace);
        void Abandon(ILocalFileCopy localFile, string nameTemp, TextWriter trace);

        // File management methods
        void Delete(string name, TextWriter trace);
        void DeleteById(string id, TextWriter trace);
        bool Exists(string name, TextWriter trace);
        void Rename(string oldName, string newName, TextWriter trace);
        void RenameById(string id, string newName, TextWriter trace);

        // Enumeration methods
        string[] GetFileNames(string prefix, TextWriter trace);
        void GetFileInfo(string name, out string id, out bool directory, out DateTime created, out DateTime modified, out long size, TextWriter trace);

        // Tracing methods
        TextWriter GetMasterTrace(); // TextWriter is threadsafe; remains owned - do not Dispose()
    }

    public class ProgressTracker
    {
        private long current;
        private long total = -1; // during download, HttpWebRequest has to update this once Content-Length header is received
        public readonly string Tag;

        public long Current
        {
            get
            {
                return Interlocked.Read(ref current);
            }
            set
            {
                Interlocked.Exchange(ref current, value);
            }
        }

        public long Total
        {
            get
            {
                return Interlocked.Read(ref total);
            }
        }

        public void UpdateTotal(long newTotal)
        {
            Interlocked.CompareExchange(ref total, newTotal, -1);
        }

        public ProgressTracker(long total, long current, string tag)
        {
            this.current = current;
            this.total = total;
            this.Tag = tag;
        }

        public ProgressTracker(string tag)
        {
            this.Tag = tag;
        }
    }

    public interface ILocalFileCopy : IDisposable
    {
        ILocalFileCopy AddRef();
        void Release();

        Stream Read();
        Stream Write();
        Stream ReadWrite();

        void CopyLocal(string localPathTarget, bool overwrite);
    }

    public class LocalFileCopy : ILocalFileCopy
    {
        private string localFilePath;
        private Stream keeper; // holds lock to prevent deletion of temp file
        private int refCount;
        private bool writable;
        private bool delete;

        public LocalFileCopy(string localFilePath, bool writable, bool delete)
        {
            AddRef();
            this.localFilePath = localFilePath;
            this.writable = writable;
            this.delete = delete;
            using (Stream stream = !File.Exists(LocalFilePath) ? new FileStream(localFilePath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite, 1) : null)
            {
                this.keeper = new FileStream(localFilePath, FileMode.Open, FileAccess.Read, writable ? FileShare.ReadWrite : FileShare.Read, 1);
            }
        }

        public LocalFileCopy()
        {
            AddRef();
            this.localFilePath = Path.GetTempFileName();
            this.writable = true;
            this.delete = true;
            using (Stream stream = new FileStream(localFilePath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite, 1))
            {
                this.keeper = new FileStream(localFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1);
            }
        }

        // TODO: switch clients to use stream - then get rid of this exposure of implementation
        public string LocalFilePath { get { return localFilePath; } }

        public ILocalFileCopy AddRef()
        {
            refCount++;
            return this;
        }

        public void Release()
        {
            refCount--;
            if (refCount == 0)
            {
                if (keeper != null)
                {
                    keeper.Close();
                    keeper = null;
                }
                if (delete && (localFilePath != null))
                {
                    try
                    {
                        File.Delete(localFilePath);
                    }
                    catch (Exception)
                    {
                    }
                }
                localFilePath = null;
            }
        }

        public void Dispose()
        {
            Release();
        }

        public string Vacate()
        {
            string result = localFilePath;

            keeper.Close();
            keeper = null;
            localFilePath = null;

            return result;
        }

        public Stream Read()
        {
            return new FileStream(localFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        }

        public Stream Write()
        {
            if (!writable)
            {
                throw new InvalidOperationException();
            }
            return new FileStream(localFilePath, FileMode.Open, FileAccess.Write, FileShare.Read);
        }

        public Stream ReadWrite()
        {
            if (!writable)
            {
                throw new InvalidOperationException();
            }
            return new FileStream(localFilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
        }

        public void CopyLocal(string localPathTarget, bool overwrite)
        {
            File.Copy(localFilePath, localPathTarget, overwrite);
        }
    }
}
