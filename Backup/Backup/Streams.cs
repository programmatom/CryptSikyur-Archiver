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
using System.IO;
using System.IO.Compression;
using System.Text;

namespace Backup
{
    ////////////////////////////////////////////////////////////////////////////
    //
    // Stream primitives 
    //
    ////////////////////////////////////////////////////////////////////////////

    // A pass-through stream that is completely transparent except that it refuses
    // to Close() the underlying stream - used as a work-around for framework-provided
    // streams that always close the underlying even when not desired (e.g. CryptoStream)
    public class CloseBarrierStream : Stream
    {
        private Stream inner;

        public CloseBarrierStream(Stream inner)
        {
            this.inner = inner;
        }

        public override bool CanRead { get { return inner.CanRead; } }
        public override bool CanSeek { get { return inner.CanSeek; } }
        public override bool CanTimeout { get { return inner.CanTimeout; } }
        public override bool CanWrite { get { return inner.CanWrite; } }
        public override long Length { get { return inner.Length; } }
        public override long Position { get { return inner.Position; } set { inner.Position = value; } }

        public override void Close()
        {
            inner = null;
        }

        protected override void Dispose(bool disposing)
        {
            Close();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return inner.Read(buffer, offset, count);
        }

        public override int ReadByte()
        {
            return inner.ReadByte();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return inner.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            inner.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            inner.Write(buffer, offset, count);
        }
    }

    public interface ICheckValueGenerator : IDisposable
    {
        void ProcessBlock(byte[] buffer, int start, int count);
        byte[] GetCheckValueAndClose();
        int CheckValueLength { get; }
    }

    // A read pass-through stream that, as a side effect, generates a check value
    // on all data that passes through.
    public class CheckedReadStream : Stream
    {
        private Stream inner;
        private ICheckValueGenerator check;
        private byte[] checkValue;

        public CheckedReadStream(Stream inner, ICheckValueGenerator check)
        {
            this.inner = inner;
            this.check = check;
        }

        // It is not permitted to ask for the CheckValue before Close() is called.
        // After Close(), CheckValue can be queried any number of times.
        public byte[] CheckValue
        {
            get
            {
                if (inner != null)
                {
                    throw new InvalidOperationException();
                }
                return (byte[])checkValue.Clone();
            }
        }

        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }

        public override void Close()
        {
            if (inner != null)
            {
                checkValue = check.GetCheckValueAndClose();
            }
            inner = null;
            check = null;
        }

        protected override void Dispose(bool disposing)
        {
            Close();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (inner == null)
            {
                throw new InvalidOperationException();
            }
            int read = inner.Read(buffer, offset, count);
            check.ProcessBlock(buffer, offset, read);
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }

    // A write pass-through stream that, as a side effect, generates a check value
    // on all data that passes through.
    public class CheckedWriteStream : Stream
    {
        private Stream inner;
        private ICheckValueGenerator check;
        private byte[] checkValue;

        public CheckedWriteStream(Stream inner, ICheckValueGenerator check)
        {
            this.inner = inner;
            this.check = check;
        }

        // It is not permitted to ask for the CheckValue before Close() is called.
        // After Close(), CheckValue can be queried any number of times.
        public byte[] CheckValue
        {
            get
            {
                if (inner != null)
                {
                    throw new InvalidOperationException();
                }
                return (byte[])checkValue.Clone();
            }
        }

        public override bool CanRead { get { return false; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return true; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }

        public override void Close()
        {
            if (inner != null)
            {
                checkValue = check.GetCheckValueAndClose();
            }
            inner = null;
            check = null;
        }

        protected override void Dispose(bool disposing)
        {
            Close();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (inner == null)
            {
                throw new InvalidOperationException();
            }
            inner.Write(buffer, offset, count);
            check.ProcessBlock(buffer, offset, count);
        }
    }


    // signed streams

    // Pass-through stream that reads all bytes except for the last "reserved"
    // bytes which are held aside. Stream behaves as EOF as soon as position reaches
    // length - reserved. PostReserved() is called upon normal closing of the stream.
    public class ReadStreamHoldShort : Stream, IAbortable
    {
        private const int WorkspaceLength = Core.Constants.BufferSize;

        private Stream inner;
        private int reserved;
        private byte[] workspace;
        private int index;

        internal class NotEndOfStreamException : ApplicationException
        {
            public NotEndOfStreamException()
            {
            }
        }

        public ReadStreamHoldShort(Stream inner, int reserved)
        {
            if (!(reserved < WorkspaceLength))
            {
                throw new ArgumentException();
            }

            this.inner = inner;
            this.reserved = reserved;
            workspace = new byte[WorkspaceLength];

            PreloadWorkspace();
        }

        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new NotImplementedException(); } }
        public override long Position { get { throw new NotImplementedException(); } set { throw new NotImplementedException(); } }

        public override void Close()
        {
            inner = null;
        }

        public void Abort()
        {
            inner = null;

            // if read is aborted, stream can't provide last part of data -
            // cause GetReserved() it to return empty result
            index = 0;
            reserved = 0;
            workspace = new byte[0];
        }

        public byte[] GetReserved()
        {
            if (inner != null)
            {
                throw new InvalidOperationException();
            }

            if (index + reserved != workspace.Length)
            {
                throw new NotEndOfStreamException();
            }

            byte[] data = new byte[reserved];
            Buffer.BlockCopy(workspace, index, data, 0, reserved);
            return data;
        }

        public override void Flush()
        {
        }

        private void PreloadWorkspace()
        {
            int read = inner.Read(workspace, 0, workspace.Length);
            if (read < workspace.Length)
            {
                Array.Resize(ref workspace, read);
            }
            if (read < reserved)
            {
                throw new InvalidDataException("Unexpected end of stream");
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (inner == null)
            {
                throw new InvalidOperationException();
            }

            int i;
            for (i = 0; i < count; i++)
            {
                if (index == workspace.Length - reserved)
                {
                    Buffer.BlockCopy(workspace, index, workspace, 0, reserved);
                    index = 0;
                    int read = inner.Read(workspace, reserved, workspace.Length - reserved);
                    if (reserved + read < workspace.Length)
                    {
                        Array.Resize(ref workspace, reserved + read);
                    }

                    if (index == workspace.Length - reserved)
                    {
                        break;
                    }
                }
                Debug.Assert(index <= workspace.Length - reserved);

                buffer[i + offset] = workspace[index++];
            }

            return i;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }

    // A pass-through stream that reads all underlying data except for some
    // reserved N bytes at end which constitute a tag and are checked against the
    // value generated by a check value generator.
    public class TaggedReadStream : Stream, IAbortable
    {
        private ReadStreamHoldShort holdShortInner;
        private CheckedReadStream wrappedInner;
        private string failureMessage;

        public class TagInvalidException : Core.ExitCodeException
        {
            public TagInvalidException()
                : base((int)Core.ExitCodes.ConditionNotSatisfied)
            {
            }

            public TagInvalidException(string message)
                : base((int)Core.ExitCodes.ConditionNotSatisfied, message)
            {
            }
        }

        public TaggedReadStream(Stream inner, ICheckValueGenerator check, string failureMessage)
        {
            this.holdShortInner = new ReadStreamHoldShort(inner, check.CheckValueLength);
            this.wrappedInner = new CheckedReadStream(this.holdShortInner, check);
            this.failureMessage = failureMessage;
        }

        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new NotImplementedException(); } }
        public override long Position { get { throw new NotImplementedException(); } set { throw new NotImplementedException(); } }

        public override void Close()
        {
            if (wrappedInner != null)
            {
                wrappedInner.Close();
                byte[] computedCheckValue = wrappedInner.CheckValue;

                holdShortInner.Close();
                byte[] storedCheckValue = holdShortInner.GetReserved();

                holdShortInner = null;
                wrappedInner = null;

                if (!Core.ArrayEqual(computedCheckValue, storedCheckValue))
                {
                    throw new TagInvalidException(failureMessage);
                }
            }
        }

        public void Abort()
        {
            // prevent Close() from attempting to validate stored and computed value

            if (holdShortInner is IAbortable)
            {
                ((IAbortable)holdShortInner).Abort();
            }
            holdShortInner.Close();
            holdShortInner = null;

            if (wrappedInner is IAbortable)
            {
                ((IAbortable)wrappedInner).Abort();
            }
            wrappedInner.Close();
            wrappedInner = null;
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (wrappedInner == null)
            {
                throw new InvalidOperationException();
            }

            return wrappedInner.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }

    // A pass-through stream that generates a check value of all data that passes
    // through, and appends the check value to the end of the underlying stream
    // when finished.
    public class TaggedWriteStream : Stream, IAbortable
    {
        private Stream underlyingInner;
        private CheckedWriteStream wrappedInner;

        public TaggedWriteStream(Stream inner, ICheckValueGenerator check)
        {
            this.underlyingInner = inner;
            this.wrappedInner = new CheckedWriteStream(inner, check);
        }

        public override bool CanRead { get { return false; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return true; } }
        public override long Length { get { throw new NotImplementedException(); } }
        public override long Position { get { throw new NotImplementedException(); } set { throw new NotImplementedException(); } }

        public override void Close()
        {
            if (wrappedInner != null)
            {
                wrappedInner.Close();
                byte[] checkValue = wrappedInner.CheckValue;

                underlyingInner.Write(checkValue, 0, checkValue.Length);

                wrappedInner = null;
                underlyingInner = null;
            }
        }

        public void Abort()
        {
            if (wrappedInner != null)
            {
                wrappedInner.Close();
                // do not write check value

                underlyingInner = null;
                wrappedInner = null;
            }
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (wrappedInner == null)
            {
                throw new InvalidOperationException();
            }

            wrappedInner.Write(buffer, offset, count);
        }
    }


    // block formatting

    public abstract class BlockFormattedWriteStream : Stream
    {
        private const int MinimumBlockSize = 1;
        private const int MaximumBlockSize = 0x00ffffff; // lowest 3 bytes only
        private const int DefaultBlockSize = 65536;

        private Stream inner;

        private readonly byte[] headerToken;

        private byte[] workspace;
        private int index;

        protected abstract void ProcessBlock(byte[] input, int start, int count, out byte[] output, out int outputLength, out bool optOut);

        public BlockFormattedWriteStream(Stream inner, int blockSize, byte[] headerToken)
        {
            if (blockSize == 0)
            {
                blockSize = DefaultBlockSize;
            }
            if ((blockSize < MinimumBlockSize) || (blockSize > MaximumBlockSize))
            {
                throw new ArgumentException();
            }

            this.headerToken = headerToken;

            this.inner = inner;

            workspace = new byte[blockSize];
        }

        public BlockFormattedWriteStream(Stream inner, byte[] headerToken)
            : this(inner, DefaultBlockSize, headerToken)
        {
        }

        public override bool CanRead { get { return false; } }

        public override bool CanSeek { get { return false; } }

        public override bool CanWrite { get { return true; } }

        public override long Length { get { throw new NotSupportedException(); } }

        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }

        public override void Close()
        {
            if (inner != null)
            {
                WriteBufferedData();
                inner = null;
            }
        }

        public override void Flush()
        {
        }

        private void WriteBufferedData()
        {
            if (inner == null)
            {
                throw new InvalidOperationException();
            }

            if (index > 0)
            {
                byte[] data;
                int dataLength;
                byte[] checkValue;
                bool optOut;

                {
                    byte[] processed;
                    int processedLength;
                    ProcessBlock(workspace, 0, index, out processed, out processedLength, out optOut);

                    // processor can opt-out in which case unprocessed data is written to the stream
                    // (for example, in a data compression application if block was uncompressible)
                    if (!optOut)
                    {
                        data = processed;
                        dataLength = processedLength;
                    }
                    else
                    {
                        data = workspace;
                        dataLength = index;
                    }

                    CRC32 checkValueGenerator = new CRC32();
                    checkValueGenerator.ProcessBlock(data, 0, dataLength);
                    checkValue = checkValueGenerator.GetCheckValueAndClose();
                }

                Debug.Assert(dataLength <= 0x00ffffff); // must fit in 3 bytes, as decomposed below
                byte[] header = new byte[4]
                    {
                        // bit 0x80 is set if saved data was processed but cleared if saved data was unprocessed
                        (byte)((!optOut ? 0x80 : 0x00) | (headerToken != null ? 0x40 : 0x00)),
                        (byte)(dataLength >> 16),
                        (byte)((dataLength >> 8) & 0xff),
                        (byte)(dataLength & 0xff),
                    };
                if (headerToken != null)
                {
                    inner.Write(headerToken, 0, headerToken.Length);
                }
                inner.Write(header, 0, header.Length);
                inner.Write(data, 0, dataLength);
                inner.Write(checkValue, 0, checkValue.Length);

                index = 0;
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (inner == null)
            {
                throw new InvalidOperationException();
            }

            for (int i = 0; i < count; i++)
            {
                workspace[index++] = buffer[i + offset];
                if (index == workspace.Length)
                {
                    WriteBufferedData();
                }
            }
        }
    }

    public abstract class BlockFormattedReadStream : Stream
    {
        private Stream inner;

        private readonly byte[] headerToken;

        private byte[] workspace;
        private int workspaceLength;
        private int index;

        protected abstract void ProcessBlock(byte[] input, int start, int count, out byte[] output, out int outputLength);

        public BlockFormattedReadStream(Stream inner, byte[] headerToken)
        {
            this.headerToken = headerToken;

            this.inner = inner;

            workspace = new byte[0];
        }

        public override bool CanRead { get { return true; } }

        public override bool CanSeek { get { return false; } }

        public override bool CanWrite { get { return false; } }

        public override long Length { get { throw new NotSupportedException(); } }

        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }

        public override void Close()
        {
            inner = null;
            workspace = null;
        }

        public override void Flush()
        {
            throw new NotSupportedException();
        }

        private int ReadFromInner(byte[] buffer, int offset, int count)
        {
            int total = 0;
            while (count > 0)
            {
                int read = inner.Read(buffer, offset, count);
                if (read == 0)
                {
                    break; // end of file
                }
                // stream is permitted to return less than count bytes even if count bytes are available
                offset += read;
                count -= read;
                total += read;
            }
            return total;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (inner == null)
            {
                throw new InvalidOperationException();
            }

            int total = 0;
            while (count > 0)
            {
                Debug.Assert(index <= workspaceLength);
                if (index == workspaceLength)
                {
                    int read;

                    byte[] header = new byte[4];
                    read = ReadFromInner(header, 0, header.Length);
                    if (read == 0)
                    {
                        break;
                    }
                    if (read != header.Length)
                    {
                        throw new Core.ExitCodeException((int)Core.ExitCodes.ConditionNotSatisfied, "Formatted stream block header is incomplete");
                    }

                    bool optOut = (header[0] & 0x80) == 0;
                    bool hasHeaderToken = (header[0] & 0x40) != 0;
                    int length = ((int)header[1] << 16) | ((int)header[2] << 8) | header[3];

                    if (hasHeaderToken)
                    {
                        if (headerToken == null)
                        {
                            throw new InvalidDataException();
                        }
                        byte[] token = new byte[headerToken.Length];
                        read = ReadFromInner(token, 0, token.Length);
                        if (read != token.Length)
                        {
                            throw new Core.ExitCodeException((int)Core.ExitCodes.ConditionNotSatisfied, "Formatted stream block header is incomplete");
                        }
                        if (!Core.ArrayEqual(token, headerToken))
                        {
                            throw new Core.ExitCodeException((int)Core.ExitCodes.ConditionNotSatisfied, "Formatted stream block header token has invalid value");
                        }
                    }

                    if (workspace.Length < length)
                    {
                        workspace = new byte[length];
                    }
                    read = ReadFromInner(workspace, 0, length);
                    if (read != length)
                    {
                        throw new Core.ExitCodeException((int)Core.ExitCodes.ConditionNotSatisfied, "Formatted stream block is incomplete");
                    }
                    workspaceLength = length;

                    CRC32 checkValueGenerator = new CRC32();
                    checkValueGenerator.ProcessBlock(workspace, 0, workspaceLength);
                    byte[] checkValue = checkValueGenerator.GetCheckValueAndClose();

                    byte[] savedCheckValue = new byte[checkValueGenerator.CheckValueLength];
                    read = ReadFromInner(savedCheckValue, 0, savedCheckValue.Length);
                    if (read != savedCheckValue.Length)
                    {
                        throw new Core.ExitCodeException((int)Core.ExitCodes.ConditionNotSatisfied, "Formatted stream check value is incomplete");
                    }
                    if (!Core.ArrayEqual(checkValue, savedCheckValue))
                    {
                        throw new Core.ExitCodeException((int)Core.ExitCodes.ConditionNotSatisfied, "Formatted stream check values do not match");
                    }

                    if (!optOut)
                    {
                        byte[] processed;
                        int processedLength;
                        ProcessBlock(workspace, 0, workspaceLength, out  processed, out processedLength);

                        if (processed.Length < workspace.Length)
                        {
                            Buffer.BlockCopy(processed, 0, workspace, 0, processedLength);
                        }
                        else
                        {
                            workspace = processed;
                        }
                        workspaceLength = processedLength;
                    }

                    index = 0;
                }

                buffer[offset++] = workspace[index++];
                count--;
                total++;
            }
            return total;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Binary stream utilities
    //
    ////////////////////////////////////////////////////////////////////////////

    public static class BinaryReadUtils
    {
        public static int Read(Stream stream, byte[] buffer, int start, int count)
        {
            int total = 0;
            int read;
            while ((read = stream.Read(buffer, start, count)) != 0)
            {
                total += read;
                start += read;
                count -= read;
                if (count == 0)
                {
                    break;
                }
            }
            return total;
        }

        public static byte[] ReadBytes(Stream stream, int count)
        {
            byte[] b = new byte[count];
            int read = Read(stream, b, 0, b.Length);
            if (read != b.Length)
            {
                throw new IOException("Unexpected end of stream");
            }
            return b;
        }

        //public static void ReadBytesOrEOF(Stream stream, byte[] b, out bool eof)
        //{
        //    eof = false;
        //
        //    int read = stream.Read(b, 0, b.Length);
        //    if (read == 0)
        //    {
        //        eof = true;
        //        return;
        //    }
        //    if (read != b.Length)
        //    {
        //        throw new IOException("Unexpected end of stream");
        //    }
        //}

        public static string ReadStringUtf8(Stream stream)
        {
            return Encoding.UTF8.GetString(ReadVariableLengthByteArray(stream));
        }

        public static byte[] ReadVariableLengthByteArray(Stream stream)
        {
            int byteCount = ReadVariableLengthQuantityAsInt32(stream);
            byte[] data = ReadBytes(stream, byteCount);
            return data;
        }

        public static ulong ReadVariableLengthQuantity(Stream stream)
        {
            ulong number = 0;
            byte[] b;
            do
            {
                b = ReadBytes(stream, 1);
                if (number > number << 7)
                {
                    throw new OverflowException();
                }
                number = (number << 7) | (b[0] & (ulong)0x7f);
            } while ((b[0] & 0x80) != 0);
            return number;
        }

        public static ulong ReadVariableLengthQuantityAsUInt64(Stream stream)
        {
            return ReadVariableLengthQuantity(stream);
        }

        public static long ReadVariableLengthQuantityAsInt64(Stream stream)
        {
            ulong v = ReadVariableLengthQuantity(stream);
            if (v > (ulong)Int64.MaxValue)
            {
                throw new OverflowException();
            }
            return (long)v;
        }

        public static int ReadVariableLengthQuantityAsInt32(Stream stream)
        {
            ulong v = ReadVariableLengthQuantity(stream);
            if (v > (ulong)Int32.MaxValue)
            {
                throw new OverflowException();
            }
            return (int)v;
        }

        public static void RequireAtEOF(Stream stream)
        {
            byte[] buffer = new byte[1];
            int read = stream.Read(buffer, 0, buffer.Length);
            if (read != 0)
            {
                throw new InvalidDataException("Stream contains data beyond expected end");
            }
        }

        //public static byte[] PeekBytes(Stream stream, int count)
        //{
        //    long position = stream.Position;
        //    byte[] result = new byte[count];
        //    int read = Read(stream, result, 0, result.Length);
        //    if (read != result.Length)
        //    {
        //        throw new InvalidDataException("Unexpected end of stream");
        //    }
        //    stream.Position = position;
        //    return result;
        //}

        public delegate void Reader(Stream steam);
        public static void Read(Stream stream, bool peek, Reader[] readers)
        {
            long position = 0;
            if (peek)
            {
                position = stream.Position;
            }

            foreach (Reader reader in readers)
            {
                reader(stream);
            }

            if (peek)
            {
                stream.Position = position;
            }
        }
    }

    public static class BinaryWriteUtils
    {
        public static void WriteBytes(Stream stream, byte[] b)
        {
            stream.Write(b, 0, b.Length);
        }

        public static void WriteStringUtf8(Stream stream, string value)
        {
            byte[] encoded = Encoding.UTF8.GetBytes(value);
            WriteVariableLengthByteArray(stream, encoded);
        }

        public static void WriteVariableLengthByteArray(Stream stream, byte[] data)
        {
            WriteVariableLengthQuantity(stream, data.Length);
            WriteBytes(stream, data);
        }

        public static void WriteVariableLengthQuantity(Stream stream, ulong number)
        {
            byte[] b = new byte[10]; // Ceil(64 / 7)
            int i = b.Length;
            while ((i == b.Length) || (number != 0))
            {
                i--;
                b[i] = (byte)(number & 0x7f);
                if (i < b.Length - 1)
                {
                    b[i] |= 0x80;
                }
                number = number >> 7;
            }
            stream.Write(b, i, b.Length - i);
        }

        public static void WriteVariableLengthQuantity(Stream stream, long number)
        {
            if (number < 0)
            {
                throw new ArgumentException();
            }
            WriteVariableLengthQuantity(stream, (ulong)number);
        }

        public static void WriteVariableLengthQuantity(Stream stream, int number)
        {
            if (number < 0)
            {
                throw new ArgumentException();
            }
            WriteVariableLengthQuantity(stream, (ulong)number);
        }
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Stream check value generators
    //
    ////////////////////////////////////////////////////////////////////////////

    // CRC32 [Castagnoli polynomial] implementation adapted from here:
    // http://www.pdl.cmu.edu/mailinglists/ips/mail/msg04669.html
    // for a high performance one, investigate:
    // http://stackoverflow.com/questions/17645167/implementing-sse-4-2s-crc32c-in-software/17646775#17646775
    public class CRC32 : ICheckValueGenerator, IDisposable
    {
        private static readonly UInt32[] crcTable = MakeCRCTable();

        private UInt32 checkValue = 0;
        private bool closed;

        // Update a running crc with the bytes buf[start..start+count-1] and return
        // the updated crc. The crc should be initialized to zero. Pre- and
        // post-conditioning (one's complement) is performed within this
        // function so it shouldn't be done by the caller. Usage example:
        //
        // ulong crc = 0UL;
        // while (read_buffer(buffer, length) != EOF) {
        //   crc = UpdateCRC(crc, buffer, 0, length);
        // }
        // if (crc != original_crc) error();
        private static UInt32 UpdateCRC(UInt32 checkValueStart, byte[] buffer, int start, int count)
        {
            UInt32 c = checkValueStart ^ 0xffffffffU;
            for (int i = start; i < start + count; i++)
            {
                c = crcTable[(c ^ buffer[i]) & 0xff] ^ (c >> 8);
            }
            return c ^ 0xffffffffU;
        }

        public void ProcessBlock(byte[] buffer, int start, int count)
        {
            if (closed)
            {
                throw new InvalidOperationException();
            }
            checkValue = UpdateCRC(checkValue, buffer, start, count);
        }

        public byte[] GetCheckValueAndClose()
        {
            if (closed)
            {
                throw new InvalidOperationException();
            }
            closed = true;
            byte[] b = new byte[4];
            b[0] = (byte)(checkValue & 0x0ff);
            b[1] = (byte)((checkValue >> 8) & 0x0ff);
            b[2] = (byte)((checkValue >> 16) & 0x0ff);
            b[3] = (byte)((checkValue >> 24) & 0x0ff);
            Debug.Assert(b.Length == CheckValueLength);
            return b;
        }

        public UInt32 LastCheckValue
        {
            get
            {
                return checkValue;
            }
        }

        public int CheckValueLength
        {
            get
            {
                return 4;
            }
        }

        private static UInt32[] MakeCRCTable()
        {
            const UInt32 P = 0x82f63b78U; // CRC-32C (Castagnoli) polynomial

            UInt32[] t = new UInt32[256];
            UInt32 c;

            int n, k;
            for (n = 0; n < 256; n++)
            {
                c = (UInt32)n;
                for (k = 0; k < 8; k++)
                {
                    if ((c & 1) != 0)
                    {
                        c = P ^ (c >> 1);
                    }
                    else
                    {
                        c = c >> 1;
                    }
                }
                t[n] = c;
            }

            return t;
        }

        public static void Test()
        {
            byte[] data = Encoding.ASCII.GetBytes("123456789");
            CRC32 crc32 = new CRC32();
            crc32.ProcessBlock(data, 0, data.Length);
            if (crc32.LastCheckValue != 0xE3069283U)
            {
                throw new InvalidOperationException();
            }
        }

        public void Dispose()
        {
        }
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Compression and encryption stream functions
    //
    ////////////////////////////////////////////////////////////////////////////

    // Compressed streams are "blocked" (divided into blocks that may be individually
    // compressed or not) because DeflateStream was observed to pathologically expand
    // the data size for uncompressible data (e.g. previously compressed or encrypted).
    // Blocks that don't get smaller are written to the output uncompressed.
    public class BlockedCompressStream : BlockFormattedWriteStream
    {
        public BlockedCompressStream(Stream inner, int blockSize)
            : base(inner, blockSize, null)
        {
        }

        public BlockedCompressStream(Stream inner)
            : base(inner, null)
        {
        }

        protected override void ProcessBlock(byte[] input, int start, int count, out byte[] output, out int outputLength, out bool optOut)
        {
            using (MemoryStream compressedStream = new MemoryStream())
            {
                using (DeflateStream compressor = new DeflateStream(compressedStream, CompressionMode.Compress, true/*leaveOpen*/))
                {
                    compressor.Write(input, start, count);
                }

                outputLength = (int)compressedStream.Position;
                output = compressedStream.GetBuffer();
                optOut = (outputLength >= count);
            }
        }
    }

    public class BlockedDecompressStream : BlockFormattedReadStream
    {
        public BlockedDecompressStream(Stream inner)
            : base(inner, null)
        {
        }

        protected override void ProcessBlock(byte[] input, int start, int count, out byte[] output, out int outputLength)
        {
            using (MemoryStream compressedStream = new MemoryStream(input, start, count))
            {
                using (DeflateStream decompressor = new DeflateStream(compressedStream, CompressionMode.Decompress))
                {
                    using (MemoryStream decompressed = new MemoryStream())
                    {
                        int read;
                        byte[] localBuffer = new byte[Core.Constants.BufferSize];
                        do
                        {
                            read = decompressor.Read(localBuffer, 0, localBuffer.Length);
                            decompressed.Write(localBuffer, 0, read);
                        } while (read > 0);

                        outputLength = (int)decompressed.Position;
                        output = decompressed.GetBuffer();
                    }
                }
            }
        }
    }


    ////////////////////////////////////////////////////////////////////////////
    //
    // Stream Stack Utility
    //
    ////////////////////////////////////////////////////////////////////////////

    public interface IAbortable
    {
        void Abort();
    }

    public static class StreamStack
    {
        public delegate Stream StreamWrapMethod(Stream steam);
        public delegate void StreamProcessor(Stream stream);
        public static void DoWithStreamStack(Stream underlyingStream, StreamWrapMethod[] cascades, StreamProcessor processor)
        {
            Stack<Stream> cascadedStreams = new Stack<Stream>(cascades.Length);
            bool fault = false;

            try
            {
                Stream stream;

                stream = underlyingStream;

                foreach (StreamWrapMethod cascade in cascades)
                {
                    if (cascade != null)
                    {
                        Stream cascadedStream = cascade(stream);
                        if (cascadedStream != null)
                        {
                            if ((cascadedStream == underlyingStream) || cascadedStreams.Contains(cascadedStream))
                            {
                                throw new ArgumentException();
                            }
                            cascadedStreams.Push(cascadedStream);
                            stream = cascadedStream;
                        }
                    }
                }

                processor(stream);
            }
            catch (Exception)
            {
                fault = true;
                throw;
            }
            finally
            {
                while (cascadedStreams.Count > 0)
                {
                    Stream cascadedStream = cascadedStreams.Pop();
                    if (fault && (cascadedStream is IAbortable))
                    {
                        ((IAbortable)cascadedStream).Abort();
                    }
                    cascadedStream.Dispose();
                }
            }
        }
    }
}
