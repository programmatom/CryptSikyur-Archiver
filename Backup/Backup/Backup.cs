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
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Text;
using System.Text.RegularExpressions;
using Serpent;
using SkeinFish;

namespace Backup
{
    class Core
    {
        ////////////////////////////////////////////////////////////////////////////
        //
        // Constants & globals
        //
        ////////////////////////////////////////////////////////////////////////////

        public static class Constants
        {
            private const int MaxSmallObjectHeapObjectSize = 85000; // http://msdn.microsoft.com/en-us/magazine/cc534993.aspx, http://blogs.msdn.com/b/dotnet/archive/2011/10/04/large-object-heap-improvements-in-net-4-5.aspx
            private const int PageSize = 4096;
            private const int MaxSmallObjectPageDivisibleSize = MaxSmallObjectHeapObjectSize & ~(PageSize - 1);

            public const int BufferSize = MaxSmallObjectPageDivisibleSize;

            // concurrency tuning parameters for various scenarios
            internal const int ConcurrencyForDiskBound = 0;
            internal const int ConcurrencyForComputeBound = 2;
            internal const int ConcurrencyForNetworkBound = 3;
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Logging, debugging, and testing utilities
        //
        ////////////////////////////////////////////////////////////////////////////

        public class Logging
        {
            public static TextWriter CreateLogFile(string prefix)
            {
                DateTime now = DateTime.Now; // use actual time, not context.now time, for the trace file name
                Stream traceStream = null;
                int i = 1;
                while (traceStream == null)
                {
                    string tracePath = Path.Combine(Path.GetTempPath(), String.Format("{0}-{1:yyyy-MM-ddTHH-mm-ss}+{2}.log", prefix, now, i++));
                    try
                    {
                        traceStream = new FileStream(tracePath, FileMode.Create, FileAccess.Write, FileShare.Read, 1/*smallest possible buffer*/);
                    }
                    catch (IOException)
                    {
                        // file in use - try another name
                    }
                }
                return StreamWriter.Synchronized(new StreamWriter(traceStream, Encoding.UTF8, 1/*smallest possible buffer*/));
            }

            public static string ScrubSecuritySensitiveValue(byte[] value)
            {
                string hashText;
                if (value != null)
                {
                    SHA1 sha1 = SHA1.Create();
                    hashText = String.Format("length={0} sha1={1}", value.Length, HexEncode(sha1.ComputeHash(value)));
                }
                else
                {
                    hashText = "null";
                }
                return String.Format("[scrubbed, {0}]", hashText);
            }

            public static string ScrubSecuritySensitiveValue(string value)
            {
                return ScrubSecuritySensitiveValue(value != null ? Encoding.UTF8.GetBytes(value) : null);
            }
        }

        public class TaskWriter : TextWriter
        {
            private static int taskSerialNumberGenerator;
            private int taskSerialNumber = Interlocked.Increment(ref taskSerialNumberGenerator);
            private TextWriter finalDestination;
            private List<string> lines = new List<string>();
            private string current = String.Empty;
            private string lastTimestamp;
            private int lastTimestampSequenceNumber;

            public TaskWriter(TextWriter finalDestination)
            {
                this.finalDestination = finalDestination;
                this.WriteLine("*** TASK LOG BEGIN ***");
            }

            public static TextWriter Create(TextWriter finalDestination)
            {
                return finalDestination != null ? new TaskWriter(finalDestination) : null;
            }

            public override Encoding Encoding
            {
                get
                {
                    return Encoding.Unicode;
                }
            }

            protected override void Dispose(bool disposing)
            {
                this.WriteLine("*** TASK LOG END ***");
                lines.Add(String.Empty);
                base.Dispose(disposing);

                StringBuilder sb = new StringBuilder();
                foreach (string line in lines)
                {
                    sb.AppendLine(line);
                }
                finalDestination.Write(sb.ToString());
                finalDestination.Flush();
            }

            private void FlushLine(int oldEnd)
            {
                string timestamp = null;

                int start = Math.Max(0, oldEnd - Environment.NewLine.Length);
                int index;
                while ((index = current.IndexOf(Environment.NewLine, start)) >= 0)
                {
                    if (timestamp == null)
                    {
                        timestamp = DateTime.Now.ToString("HH:mm:ss+ffff");
                        if (!String.Equals(timestamp, lastTimestamp))
                        {
                            lastTimestamp = timestamp;
                            lastTimestampSequenceNumber = 0;
                        }
                    }

                    string prefix = String.Format(" {0}.{1:0000} {2} ", timestamp, lastTimestampSequenceNumber++, taskSerialNumber);
                    lines.Add(String.Concat(prefix, current.Substring(0, index)));
                    index += Environment.NewLine.Length;
                    current = current.Substring(index, current.Length - index);
                    start = 0;
                }
            }

            public override void Write(char value)
            {
                int oldEnd = current.Length;
                current = current + new String(value, 1);
                FlushLine(oldEnd);
            }

            public override void Write(char[] buffer, int index, int count)
            {
                int oldEnd = current.Length;
                current = current + new String(buffer, index, count);
                FlushLine(oldEnd);
            }

            public override void Write(string value)
            {
                int oldEnd = current.Length;
                current = current + value;
                FlushLine(oldEnd);
            }
        }


        // Fault injection framework

        public abstract class FaultPredicate
        {
            public abstract FaultPredicate Clone();
            public abstract bool Test();
            public abstract bool Test(long l);
            public abstract bool Test(string s);
        }

        public class NullFaultPredicate : FaultPredicate
        {
            public static readonly NullFaultPredicate Null = new NullFaultPredicate();

            public override FaultPredicate Clone()
            {
                return Null;
            }

            public override bool Test()
            {
                return true;
            }

            public override bool Test(long l)
            {
                return true;
            }

            public override bool Test(string s)
            {
                return true;
            }

            public override string ToString()
            {
                return String.Empty;
            }
        }

        public class CountFaultPredicate : FaultPredicate
        {
            private long count;
            private long trigger;

            public CountFaultPredicate(long trigger)
            {
                this.trigger = trigger;
            }

            public CountFaultPredicate(CountFaultPredicate original)
            {
                this.count = original.count;
                this.trigger = original.trigger;
            }

            public override FaultPredicate Clone()
            {
                return new CountFaultPredicate(this);
            }

            public override bool Test()
            {
                long current = Interlocked.Increment(ref count);
                return current == trigger;
            }

            public override bool Test(long l)
            {
                return Test();
            }

            public override bool Test(string s)
            {
                return Test();
            }

            public override string ToString()
            {
                return String.Format("[count:{0}]", trigger);
            }
        }

        public class LimitFaultPredicate : FaultPredicate
        {
            private long limit;

            public LimitFaultPredicate(long limit)
            {
                this.limit = limit;
            }

            public LimitFaultPredicate(LimitFaultPredicate original)
            {
                this.limit = original.limit;
            }

            public override FaultPredicate Clone()
            {
                return new LimitFaultPredicate(this);
            }

            public override bool Test()
            {
                return false;
            }

            public override bool Test(long l)
            {
                return l >= limit;
            }

            public override bool Test(string s)
            {
                return false;
            }

            public override string ToString()
            {
                return String.Format("[limit:{0}]", limit);
            }
        }

        public class SumLimitFaultPredicate : FaultPredicate
        {
            private long sum;
            private long limit;

            public SumLimitFaultPredicate(long limit)
            {
                this.limit = limit;
            }

            public SumLimitFaultPredicate(SumLimitFaultPredicate original)
            {
                this.sum = original.sum;
                this.limit = original.limit;
            }

            public override FaultPredicate Clone()
            {
                return new SumLimitFaultPredicate(this);
            }

            public override bool Test()
            {
                return false;
            }

            public override bool Test(long l)
            {
                long current = Interlocked.Add(ref sum, l);
                return current >= limit;
            }

            public override bool Test(string s)
            {
                return false;
            }

            public override string ToString()
            {
                return String.Format("[sumlimit:{0}]", limit);
            }
        }

        public class StringEqualFaultPredicate : FaultPredicate
        {
            private string equals;

            public StringEqualFaultPredicate(string match)
            {
                this.equals = match;
            }

            public StringEqualFaultPredicate(StringEqualFaultPredicate original)
            {
                this.equals = original.equals;
            }

            public override FaultPredicate Clone()
            {
                return new StringEqualFaultPredicate(this);
            }

            public override bool Test()
            {
                return false;
            }

            public override bool Test(long l)
            {
                return Test(l.ToString());
            }

            public override bool Test(string s)
            {
                return String.Equals(s, equals);
            }

            public override string ToString()
            {
                return String.Format("[stringequal:{0}]", equals);
            }
        }

        public class StringMatchFaultPredicate : FaultPredicate
        {
            private string pattern;
            private Regex match;

            public StringMatchFaultPredicate(string pattern)
            {
                this.pattern = pattern;
                this.match = new Regex(pattern);
            }

            public StringMatchFaultPredicate(StringMatchFaultPredicate original)
            {
                this.pattern = original.pattern;
                this.match = original.match;
            }

            public override FaultPredicate Clone()
            {
                return new StringMatchFaultPredicate(this);
            }

            public override bool Test()
            {
                return false;
            }

            public override bool Test(long l)
            {
                return Test(l.ToString());
            }

            public override bool Test(string s)
            {
                return match.IsMatch(s);
            }

            public override string ToString()
            {
                return String.Format("[regex:{0}]", pattern);
            }
        }

        public class FaultInjectionException : ApplicationException
        {
            public FaultInjectionException(string message)
                : base(message)
            {
            }
        }

        public enum FaultMethod
        {
            None = 0,

            Throw,
            Kill,
        }

        public class FaultInstanceNode
        {
            private readonly KeyValuePair<FaultPredicate, FaultTemplateNode>[] predicates;

            public static readonly FaultInstanceNode Null = new FaultInstanceNode((KeyValuePair<FaultPredicate, FaultTemplateNode>[])null);

            public FaultInstanceNode(FaultTemplateNode templateNode)
            {
                this.predicates = new KeyValuePair<FaultPredicate, FaultTemplateNode>[1];
                this.predicates[0] = new KeyValuePair<FaultPredicate, FaultTemplateNode>(NullFaultPredicate.Null, templateNode);
            }

            private FaultInstanceNode(KeyValuePair<FaultPredicate, FaultTemplateNode>[] predicates)
            {
                this.predicates = predicates;
            }


            // Use Select() to descend one path step and match predicates either by count or explicit value test

            public FaultInstanceNode Select(string tag)
            {
                if (predicates == null)
                {
                    return Null;
                }
                return Select(tag, delegate(FaultPredicate predicate) { return predicate.Test(); });
            }

            public FaultInstanceNode Select(string tag, long l)
            {
                if (predicates == null)
                {
                    return Null;
                }
                return Select(tag, delegate(FaultPredicate predicate) { return predicate.Test(l); });
            }

            public FaultInstanceNode Select(string tag, string s)
            {
                if (predicates == null)
                {
                    return Null;
                }
                return Select(tag, delegate(FaultPredicate predicate) { return predicate.Test(s); });
            }


            // Use SelectPredicate() to descend a path without evaluating predicates. Evaluation is
            // performed by explicit invocation of Test() on the returned FaultPredicate object.
            // Use this approach for performance-sensitive code in order to hoist path string match
            // portion of operation out of loops.

            public FaultPredicate SelectPredicate(string tag)
            {
                if (predicates == null)
                {
                    return FaultInstancePredicate.Null;
                }

                KeyValuePair<FaultPredicate, FaultTemplateNode>[] matchingPredicates = null;
                for (int i = 0; i < predicates.Length; i++)
                {
                    if (String.Equals(tag, predicates[i].Value.Tag))
                    {
                        if (matchingPredicates == null)
                        {
                            matchingPredicates = new KeyValuePair<FaultPredicate, FaultTemplateNode>[1];
                        }
                        else
                        {
                            Array.Resize(ref matchingPredicates, matchingPredicates.Length + 1);
                        }
                        matchingPredicates[matchingPredicates.Length - 1] = predicates[i];
                    }
                }
                return new FaultInstancePredicate(matchingPredicates, this);
            }


            // Internals

            private delegate bool TestMethod(FaultPredicate predicate);
            private FaultInstanceNode Select(string tag, TestMethod testMethod)
            {
                // caller optimizes case where predicates == null

                KeyValuePair<FaultPredicate, FaultTemplateNode>[] childPredicates = null;
                FaultTemplateNode[] throwing = null;
                for (int i = 0; i < predicates.Length; i++)
                {
                    if (String.Equals(tag, predicates[i].Value.Tag) && testMethod(predicates[i].Key))
                    {
                        if (predicates[i].Value.Terminal)
                        {
                            switch (predicates[i].Value.Method)
                            {
                                default:
                                    throw new InvalidOperationException();

                                case FaultMethod.None:
                                    break;

                                case FaultMethod.Throw:
                                    if (throwing == null)
                                    {
                                        throwing = new FaultTemplateNode[1];
                                    }
                                    else
                                    {
                                        Array.Resize(ref throwing, throwing.Length + 1);
                                    }
                                    throwing[throwing.Length - 1] = predicates[i].Value;
                                    break;

                                case FaultMethod.Kill:
                                    Environment.ExitCode = (int)ExitCodes.ProgramFailure;
                                    Process.GetCurrentProcess().Kill(); // no finalizers!
                                    break;
                            }
                        }
                        else
                        {
                            KeyValuePair<FaultTemplateNode, FaultPredicate>[] children = predicates[i].Value.Children;
                            for (int j = 0; j < children.Length; j++)
                            {
                                if (childPredicates == null)
                                {
                                    childPredicates = new KeyValuePair<FaultPredicate, FaultTemplateNode>[1];
                                }
                                else
                                {
                                    Array.Resize(ref childPredicates, childPredicates.Length + 1);
                                }
                                childPredicates[childPredicates.Length - 1] = new KeyValuePair<FaultPredicate, FaultTemplateNode>(children[j].Value.Clone(), children[j].Key);
                            }
                        }
                    }
                }

                if (throwing != null)
                {
                    Throw(throwing);
                }

                return new FaultInstanceNode(childPredicates);
            }

            private void Throw(FaultTemplateNode[] throwing)
            {
                StringBuilder message = new StringBuilder();
                foreach (FaultTemplateNode node in throwing)
                {
                    string path = null;
                    FaultTemplateNode walk = node;
                    while (walk != null)
                    {
                        FaultTemplateNode parent = walk.Parent;
                        string predicateString = null;
                        if (parent != null)
                        {
                            KeyValuePair<FaultTemplateNode, FaultPredicate> item = Array.Find(parent.Children, delegate(KeyValuePair<FaultTemplateNode, FaultPredicate> candidate) { return candidate.Key == walk; });
                            predicateString = item.Value.ToString();
                        }
                        path = String.Concat(walk.Tag, predicateString, path != null ? "/" : null, path);
                        walk = parent;
                    }
                    if (message.Length != 0)
                    {
                        message.Append(", ");
                    }
                    message.Append(path);
                }
                throw new FaultInjectionException(message.ToString());
            }


            // Fast predicate evaluator for performance-sensitive code
            private class FaultInstancePredicate : FaultPredicate
            {
                private readonly KeyValuePair<FaultPredicate, FaultTemplateNode>[] predicates;
                private readonly FaultInstanceNode owner;

                public static readonly FaultInstancePredicate Null = new FaultInstancePredicate(null, null);

                public FaultInstancePredicate(KeyValuePair<FaultPredicate, FaultTemplateNode>[] predicates, FaultInstanceNode owner)
                {
                    this.predicates = predicates;
                    this.owner = owner;
                }

                public override FaultPredicate Clone()
                {
                    throw new InvalidOperationException();
                }

                private const bool TestReturnValue = true; // implementing FaultPredicate iterface means having to return a value, but it means nothing in the use-case for FaultInstancePredicate

                private bool Test(TestMethod testMethod)
                {
                    // caller optimizes case where predicates == null

                    FaultTemplateNode[] throwing = null;
                    for (int i = 0; i < predicates.Length; i++)
                    {
                        if (testMethod(predicates[i].Key))
                        {
                            if (predicates[i].Value.Terminal)
                            {
                                switch (predicates[i].Value.Method)
                                {
                                    default:
                                        throw new InvalidOperationException();

                                    case FaultMethod.None:
                                        break;

                                    case FaultMethod.Throw:
                                        if (throwing == null)
                                        {
                                            throwing = new FaultTemplateNode[1];
                                        }
                                        else
                                        {
                                            Array.Resize(ref throwing, throwing.Length + 1);
                                        }
                                        throwing[throwing.Length - 1] = predicates[i].Value;
                                        break;

                                    case FaultMethod.Kill:
                                        Environment.ExitCode = (int)ExitCodes.ProgramFailure;
                                        Process.GetCurrentProcess().Kill(); // no finalizers!
                                        break;
                                }
                            }
                        }
                    }

                    if (throwing != null)
                    {
                        owner.Throw(throwing);
                    }

                    return TestReturnValue;
                }

                public override bool Test()
                {
                    if (predicates == null)
                    {
                        return TestReturnValue;
                    }
                    return Test(delegate(FaultPredicate predicate) { return predicate.Test(); });
                }

                public override bool Test(long l)
                {
                    if (predicates == null)
                    {
                        return TestReturnValue;
                    }
                    return Test(delegate(FaultPredicate predicate) { return predicate.Test(l); });
                }

                public override bool Test(string s)
                {
                    if (predicates == null)
                    {
                        return TestReturnValue;
                    }
                    return Test(delegate(FaultPredicate predicate) { return predicate.Test(s); });
                }
            }
        }

        public class FaultTemplateNode
        {
            private string tag;
            private FaultTemplateNode parent;
            private FaultMethod method;
            private KeyValuePair<FaultTemplateNode, FaultPredicate>[] children = new KeyValuePair<FaultTemplateNode, FaultPredicate>[0];

            public FaultTemplateNode()
            {
            }

            public FaultTemplateNode(string tag, FaultTemplateNode parent, FaultMethod method)
            {
                this.tag = tag;
                this.parent = parent;
                this.method = method;
            }

            public string Tag { get { return tag; } }
            public FaultTemplateNode Parent { get { return parent; } }
            public KeyValuePair<FaultTemplateNode, FaultPredicate>[] Children { get { return children; } }
            public bool Terminal { get { return children.Length == 0; } }
            public FaultMethod Method { get { return method; } }

            public void Add(FaultTemplateNode child, FaultPredicate childPredicate)
            {
                Array.Resize(ref children, children.Length + 1);
                children[children.Length - 1] = new KeyValuePair<FaultTemplateNode, FaultPredicate>(child, childPredicate);
            }
        }

        public static void ParseFaultInjectionPath(FaultTemplateNode root, string method, string arg)
        {
            if (String.IsNullOrEmpty(arg) || (arg[0] != '/'))
            {
                throw new ArgumentException();
            }
            FaultMethod faultMethod;
            switch (method)
            {
                default:
                    throw new ArgumentException();
                case "throw":
                    faultMethod = FaultMethod.Throw;
                    break;
                case "kill":
                    faultMethod = FaultMethod.Kill;
                    break;
            }

            int start = 1;
            while (start < arg.Length)
            {
                int predicateStart = -1;
                int predicateEnd = -1;

                int end = start;
                bool scope = false;
                while (end < arg.Length)
                {
                    if (!scope && (arg[end] == '/'))
                    {
                        break;
                    }
                    else if (arg[end] == '[')
                    {
                        predicateStart = end;
                        scope = true;
                    }
                    else if (arg[end] == ']')
                    {
                        predicateEnd = end;
                        scope = false;
                    }
                    end++;
                }

                if (((predicateStart < 0) != (predicateEnd < 0))
                    || (predicateStart > predicateEnd)
                    || ((predicateEnd >= 0) && (predicateEnd != end - 1)))
                {
                    throw new ArgumentException();
                }
                if (predicateStart < 0)
                {
                    predicateStart = end;
                    predicateEnd = end + 1;
                }

                string tag = arg.Substring(start, predicateStart - start);
                string predicateString = predicateStart + 1 <= arg.Length ? arg.Substring(predicateStart + 1, predicateEnd - predicateStart - 1) : String.Empty;
                int colon = predicateString.IndexOf(':');
                FaultPredicate predicate = NullFaultPredicate.Null;
                if (colon > 0)
                {
                    switch (predicateString.Substring(0, colon))
                    {
                        default:
                            throw new ArgumentException();
                        case "count":
                            predicate = new CountFaultPredicate(Int64.Parse(predicateString.Substring(colon + 1)));
                            break;
                        case "limit":
                            predicate = new LimitFaultPredicate(Int64.Parse(predicateString.Substring(colon + 1)));
                            break;
                        case "sumlimit":
                            predicate = new SumLimitFaultPredicate(Int64.Parse(predicateString.Substring(colon + 1)));
                            break;
                        case "stringequal":
                            predicate = new StringEqualFaultPredicate(predicateString.Substring(colon + 1));
                            break;
                        case "regex":
                            predicate = new StringMatchFaultPredicate(predicateString.Substring(colon + 1));
                            break;
                    }
                }

                int nextStart = end + 1;

                FaultTemplateNode node = new FaultTemplateNode(tag, root, nextStart < arg.Length ? FaultMethod.None : faultMethod);
                root.Add(node, predicate);

                root = node;

                start = nextStart;
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Exit codes
        //
        ////////////////////////////////////////////////////////////////////////////

        public enum ExitCodes
        {
            Success = 0,
            ProgramFailure = 1,
            Usage = 2,
            ConditionNotSatisfied = 3, // e.g. CompareFile finds differences
        }

        public class ExitCodeException : ApplicationException
        {
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
        // Composable cryptographic ciphersuites
        //
        ////////////////////////////////////////////////////////////////////////////

        // Interface defines a "crypto system" which includes:
        // - a key derivation method (from passphrase)
        // - a cipher applicable to byte streams
        // - a signed key hash (HMAC) provider
        // - encrypt and decrypt streams
        // - key lengths of various keys used by above components
        public interface ICryptoSystem
        {
            string Name { get; }
            string Description { get; }

            // Password salt is used during password to master key derivation.
            // It may be the same value in several different files, to ensure the same master
            // key is derived (which improves multi-file archive performance).
            int PasswordSaltLengthBytes { get; }

            int CipherBlockLengthBytes { get; }
            int MasterKeyLengthBytes { get; }
            int CipherKeyLengthBytes { get; }
            int SigningKeyLengthBytes { get; }
            // The per-file salt is used during session (file) key derivation.
            // It must be different for each individual file, to ensure session (file) keys
            // are unique for each file. (This derivation is faster.)
            int FileSaltLengthBytes { get; }
            int InitialVectorLengthBytes { get; }

            int DefaultRfc2898Rounds { get; }

            void DeriveMasterKey(ProtectedArray<byte> password, byte[] passwordSalt, int rounds, out ProtectedArray<byte> masterKey);
            void DeriveSessionKeys(ProtectedArray<byte> masterKey, byte[] salt, out CryptoKeygroup sessionKeys);
            void DeriveNewSessionKeys(ProtectedArray<byte> masterKey, out byte[] salt, out CryptoKeygroup sessionKeys);

            byte[] CreateRandomBytes(int count);

            int MACLengthBytes { get; }
            ICheckValueGenerator CreateMACGenerator(byte[] signingKey);

            Stream CreateEncryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter);
            Stream CreateDecryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter);

            string UniquePersistentCiphersuiteIdentifier { get; }

            void Test();
        }

        public class CryptoKeygroupLengths
        {
            public readonly int CipherKeyLengthBytes;
            public readonly int SigningKeyLengthBytes;
            public readonly int InitialCounterLengthBytes;

            public CryptoKeygroupLengths(int cipherKeyLengthBytes, int signingKeyLengthBytes, int initialCounterLengthBytes)
            {
                this.CipherKeyLengthBytes = cipherKeyLengthBytes;
                this.SigningKeyLengthBytes = signingKeyLengthBytes;
                this.InitialCounterLengthBytes = initialCounterLengthBytes;
            }
        }

        public class CryptoKeygroup : IDisposable
        {
            public readonly byte[] CipherKey;
            public readonly byte[] SigningKey;
            public readonly byte[] InitialCounter;

            public CryptoKeygroup(byte[] cipherKey, byte[] signingKey, byte[] initialCounter)
            {
                this.CipherKey = cipherKey;
                this.SigningKey = signingKey;
                this.InitialCounter = initialCounter;
            }

            public void Dispose()
            {
            }
        }

        // ICryptoSystem is built from composable crypto system components:

        public interface ICryptoSystemRandomNumberGeneration
        {
            byte[] CreateRandomBytes(int count);

            void Test();
        }

        public interface ICryptoSystemBlockCipher
        {
            int CipherBlockLengthBytes { get; }
            int CipherKeyLengthBytes { get; }
            int InitialVectorLengthBytes { get; }

            Stream CreateEncryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter);
            Stream CreateDecryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter);

            void Test();
        }

        public interface ICryptoSystemAuthentication
        {
            int SigningKeyLengthBytes { get; }

            int MACLengthBytes { get; }
            ICheckValueGenerator CreateMACGenerator(byte[] signingKey);

            void Test();
        }

        public interface ICryptoSystemKeyGeneration
        {
            int PasswordSaltLengthBytes { get; }
            int MasterKeyLengthBytes { get; }
            int FileSaltLengthBytes { get; }

            int DefaultRfc2898Rounds { get; }

            void DeriveMasterKey(ProtectedArray<byte> password, byte[] passwordSalt, int rounds, out ProtectedArray<byte> masterKey);
            void DeriveSessionKeys(ProtectedArray<byte> masterKey, byte[] salt, CryptoKeygroupLengths sessionKeyLengths, out CryptoKeygroup sessionKeys);
            void DeriveNewSessionKeys(ICryptoSystemRandomNumberGeneration rng, ProtectedArray<byte> masterKey, out byte[] salt, CryptoKeygroupLengths sessionKeyLengths, out CryptoKeygroup sessionKeys);

            void Test();
        }

        // Crypto system component composition class

        public abstract class CryptoSystemComposable : ICryptoSystem
        {
            private bool firstEncrypt = true;
            private ICryptoSystemRandomNumberGeneration rng;
            private ICryptoSystemBlockCipher cipher;
            private ICryptoSystemAuthentication auth;
            private ICryptoSystemKeyGeneration keygen;

            public CryptoSystemComposable(
                ICryptoSystemRandomNumberGeneration rng,
                ICryptoSystemBlockCipher cipher,
                ICryptoSystemAuthentication auth,
                ICryptoSystemKeyGeneration keygen)
            {
                this.rng = rng;
                this.cipher = cipher;
                this.auth = auth;
                this.keygen = keygen;
            }

            public abstract string Name { get; }
            public abstract string Description { get; }

            public abstract bool Weak { get; }

            public int PasswordSaltLengthBytes { get { return keygen.PasswordSaltLengthBytes; } }

            public int CipherBlockLengthBytes { get { return cipher.CipherBlockLengthBytes; } }
            public int MasterKeyLengthBytes { get { return keygen.MasterKeyLengthBytes; } }
            public int CipherKeyLengthBytes { get { return cipher.CipherKeyLengthBytes; } }
            public int SigningKeyLengthBytes { get { return auth.SigningKeyLengthBytes; } }
            public int FileSaltLengthBytes { get { return keygen.FileSaltLengthBytes; } }
            public int InitialVectorLengthBytes { get { return cipher.InitialVectorLengthBytes; } }

            public int DefaultRfc2898Rounds { get { return keygen.DefaultRfc2898Rounds; } }

            public void DeriveMasterKey(ProtectedArray<byte> password, byte[] passwordSalt, int rounds, out ProtectedArray<byte> masterKey)
            {
                keygen.DeriveMasterKey(password, passwordSalt, rounds, out masterKey);
            }

            public void DeriveSessionKeys(ProtectedArray<byte> masterKey, byte[] salt, out CryptoKeygroup sessionKeys)
            {
                keygen.DeriveSessionKeys(masterKey, salt, new CryptoKeygroupLengths(CipherKeyLengthBytes, SigningKeyLengthBytes, InitialVectorLengthBytes), out sessionKeys);
            }

            public void DeriveNewSessionKeys(ProtectedArray<byte> masterKey, out byte[] salt, out CryptoKeygroup sessionKeys)
            {
                keygen.DeriveNewSessionKeys(rng, masterKey, out salt, new CryptoKeygroupLengths(CipherKeyLengthBytes, SigningKeyLengthBytes, InitialVectorLengthBytes), out sessionKeys);
            }

            public byte[] CreateRandomBytes(int count)
            {
                return rng.CreateRandomBytes(count);
            }

            public int MACLengthBytes { get { return auth.MACLengthBytes; } }

            public ICheckValueGenerator CreateMACGenerator(byte[] signingKey)
            {
                return auth.CreateMACGenerator(signingKey);
            }

            public Stream CreateEncryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
            {
                if (firstEncrypt)
                {
                    firstEncrypt = false;
                    if (Weak)
                    {
                        ConsoleWriteLineColor(ConsoleColor.Yellow, "Ciphersuite {0} is considered weak. Encrypting new data with it is not recommended", Name);
                    }
                }

                return cipher.CreateEncryptStream(stream, cipherKey, initialCounter);
            }

            public Stream CreateDecryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
            {
                return cipher.CreateDecryptStream(stream, cipherKey, initialCounter);
            }

            public abstract string UniquePersistentCiphersuiteIdentifier { get; }

            public void Test()
            {
                rng.Test();
                cipher.Test();
                auth.Test();
                keygen.Test();
            }
        }

        // Supported crypto system configurations

        public class CryptoSystemAES128 : CryptoSystemComposable
        {
            // why not 256? see https://www.schneier.com/blog/archives/2009/07/another_new_aes.html

            public CryptoSystemAES128()
                : base(new CryptoSystemDefaultRNG(), new CryptoSystemBlockCipherAES128(), new CryptoSystemAuthenticationHMACSHA256(), new CryptoSystemKeyGenerationRfc2898Rfc5869())
            {
            }

            public override string Name { get { return "aes128"; } }
            public override string Description { get { return "AES-128 CTR, HMAC-SHA-256"; } }

            public override bool Weak { get { return false; } }

            public override string UniquePersistentCiphersuiteIdentifier { get { return "\x02"; } }
        }

        public class CryptoSystemSerpent256 : CryptoSystemComposable
        {
            public CryptoSystemSerpent256()
                : base(new CryptoSystemDefaultRNG(), new CryptoSystemBlockCipherSerpent256(), new CryptoSystemAuthenticationHMACSHA256(), new CryptoSystemKeyGenerationRfc2898Rfc5869())
            {
            }

            public override string Name { get { return "serpent256"; } }
            public override string Description { get { return "Serpent-256 (128 bit blocks) CTR, HMAC-SHA-256"; } }

            public override bool Weak { get { return false; } }

            public override string UniquePersistentCiphersuiteIdentifier { get { return "\x03"; } }
        }

        // Threefish is a block cipher underlying Skein, a NIST SHA-3 hash competition
        // finalist. The Skein/ThreeFish information portal is at:
        // https://www.schneier.com/skein.html
        // which provides reference source code, papers, test vectors, optimized code, etc.
        public class CryptoSystemThreefish1024 : CryptoSystemComposable
        {
            public CryptoSystemThreefish1024()
                : base(new CryptoSystemDefaultRNG(), new CryptoSystemBlockCipherThreefish1024(), new CryptoSystemAuthenticationHMACSkein1024(), new CryptoSystemKeyGenerationRfc2898Rfc5869())
            {
            }

            public override string Name { get { return "3fish1024"; } }
            public override string Description { get { return "ThreeFish-1024 CTR, HMAC-Skein-1024"; } }

            public override bool Weak { get { return false; } }

            public override string UniquePersistentCiphersuiteIdentifier { get { return "\x04"; } }
        }

        // Ferguson, Schneier, and Kohno [Cryptography Engineering, 2010, page 129]
        // are rather critical of systems that provide huge numbers of cipher suites.
        // In that spirit, our goal is to keep the list here to a minimum, trying to
        // provide just a few options to cover most goals.
        private readonly static ICryptoSystem[] CryptoSystems = new ICryptoSystem[]
        {
            // AES128 may not be the strongest cipher but has a lot going for it
            // - standardized, and probably the *primary* standard today (2014)
            // - certainly the most scrutinized and attacked cipher today
            // - sufficient security with high performance (and hardware acceleration) available if needed
            new CryptoSystemAES128(),

            // Serpent was a runner-up in the AES competition. It is arguably more secure,
            // especially now, more than 10 years after Rijndael was selected, when it is showing
            // it's age. In particular, Rijndael with 256 bit keys is seen to be flawed.
            // Therefore, Serpent-256 is included here to provide a conservative option for
            // doubling the key length.
            // Interesting for testing because block length (128 bits) is different from key
            // length (256 bits).
            new CryptoSystemSerpent256(),

            // Threefish 1024 is the only very large block size cipher available at this time
            // that (as a SHA3 finalist) has undergone more than cursory scrutiny.
            new CryptoSystemThreefish1024(),


            // Eventually there will be a large-block cipher from NIST that would be
            // suitable to replace ThreeFish-1024
            // Also, once Keccak hash gets more scrutiny, that might make an appropriate
            // replacement for keyed-MAC.
        };


        ////////////////////////////////////////////////////////////////////////////
        //
        // Cryptographic primitives
        //
        ////////////////////////////////////////////////////////////////////////////

        // Miscellaneous references:
        //
        // Phillip Rogaway's 2011 review of block cipher modes of operation
        // http://cs.ucdavis.edu/~rogaway/papers/modes.pdf
        //
        // NIST AES description
        // from http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
        //
        // Other NIST links
        // http://csrc.nist.gov/groups/STM/cavp/index.html

        // On modes of operation:
        // Ferguson and Schneier preferred CTR and CBC
        // [ http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29
        // Niels Ferguson, Bruce Schneier, Tadayoshi Kohno, Cryptography Engineering, page 71, 2010]
        // however, acrording to this: http://crypto.stackexchange.com/questions/1849/why-not-use-ctr-with-a-randomized-iv
        // they prefer CBC because CTR requires a nonce used at most once per key, ever,
        // which is hard to get right.
        //
        // On Authenticated Encryption (AE) by generic composition:
        // Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text.
        // http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html
        // with reference: M. Bellare and C. Namprempre, Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm, July 2007
        // (http://cseweb.ucsd.edu/users/mihir/papers/oem.pdf)
        // However, then there is C. Namprempre, P. Rogaway, and T. Shrimpton
        // claiming that it is not so clearcut:
        // http://eprint.iacr.org/2014/206 (or http://eprint.iacr.org/2014/206.pdf )
        // Also related is Hugo Krawczyk:
        // The Order of Encryption and Authentication for Protecting Communications
        // http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.106.5488&rep=rep1&type=pdf
        // Ferguson, Schneier, Kohno, Cryptography Engineering, 2010, Wiley Publishing
        // warn about the risk of omitting meta information (request header fields, file format
        // versions, etc) from the MAC with encrypt-then-MAC, which is easy to do since it
        // may be located somewhere other than the "plaintext stream" - but also easy to
        // do in MAC-first schemes (e.g. forgetting to include IVs in the MAC). Also, there is
        // no detection of using the wrong message key to decrypt (unless the MAC key is derived
        // in tandem with the message key in such a way that you would have both or neither).
        // Also, the risk with Encrypt-then-MAC of authenticating, but decrypting with the wrong
        // session key (because it's not in the MAC). One solution is to derive both session
        // and MAC key from one master key, but they complain that increases system complexity.
        // See chapter 7, section 7.2, page 102-104 in the above.
        // Why to verify MAC before decrypting (Moxie Marlinspike):
        // http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/
        // Ultimately, random-initialized AES-CTR followed by SHA-256 HMAC on the entire encrypted stream (including random start value) is still a good choice.
        //
        // Brief discussion of Padding Oracle Attack, with references.
        // http://www.limited-entropy.com/padding-oracle-attacks/
        //
        // Short summary of HMAC
        // http://en.wikipedia.org/wiki/HMAC
        // http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf

        // Implementations

        // Important note:
        // The implementations below are designed to be simple, in order to amke it easier
        // to ensure correctness. This may come at the cost of some efficiency.
        // In particular, there are several implementations of .NET's ICryptoTransform.
        // These implementations are simplified and do not provide full functionality,
        // particularly around object reusability. This means some classes (in particular,
        // the keyed hash functions) destroy themselves upon TransformFinalBlock() and must
        // be re-created for each use, even if the key does not change across uses.


        // Implementation of "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)",
        // as described in RFC 5869, using HMAC-SHA-256 as the hash function
        public class CryptoPrimitiveHKDFSHA256 : CryptoPrimitiveHKDF
        {
            public const int HashLen = 32;

            public CryptoPrimitiveHKDFSHA256()
                : base(new CryptoPrimitiveIteratedHashProviderSHA256())
            {
                Debug.Assert(HashLen == base.hashProvider.OutputLengthBytes);
                Debug.Assert(HashLen == base.hashLen);
            }

            private sealed class HKDFTestVector
            {
                internal readonly byte[] ikm;
                internal readonly byte[] salt;
                internal readonly byte[] info;
                internal readonly int l;

                internal readonly byte[] prk;
                internal readonly byte[] okm;

                internal HKDFTestVector(string ikm, string salt, string info, int l, string prk, string okm)
                {
                    this.ikm = HexDecode(ikm);
                    this.salt = salt != null ? HexDecode(salt) : null;
                    this.info = info != null ? HexDecode(info) : null;
                    this.l = l;
                    this.prk = HexDecode(prk);
                    this.okm = HexDecode(okm);
                }
            }

            private readonly static HKDFTestVector[] TestVectorsHKDFSHA256 = new HKDFTestVector[]
            {
                // A.1. Test Case 1 - Basic test case with SHA-256
                new HKDFTestVector("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
                // A.2. Test Case 2 - Test with SHA-256 and longer inputs/outputs
                new HKDFTestVector("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", 82, "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"),
                // A.3. Test Case 3 - Test with SHA-256 and zero-length salt/info
                new HKDFTestVector("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", null, null, 42, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
            };

            public static void Test()
            {
                CryptoPrimitiveHKDF hkdf = new CryptoPrimitiveHKDF(new CryptoPrimitiveIteratedHashProviderSHA256());

                foreach (HKDFTestVector testVector in TestVectorsHKDFSHA256)
                {
                    byte[] prk;
                    ProtectedArray<byte> ikmProtected = new ProtectedArray<byte>(testVector.ikm.Length);
                    ikmProtected.Reveal();
                    Buffer.BlockCopy(testVector.ikm, 0, ikmProtected.ExposeByteArray(), 0, testVector.ikm.Length);
                    ikmProtected.Protect();
                    hkdf.Extract(testVector.salt, ikmProtected, out prk);
                    if (!ArrayEqual(prk, testVector.prk))
                    {
                        throw new ApplicationException("HKDF-SHA256 implementation defect");
                    }

                    byte[] okm;
                    hkdf.Expand(prk, testVector.info, testVector.l, out okm);
                    if (!ArrayEqual(okm, testVector.okm))
                    {
                        throw new ApplicationException("HKDF-SHA256 implementation defect");
                    }
                }
            }
        }

        // Generic implementation of "HMAC-based Extract-and-Expand Key Derivation
        // Function (HKDF)", described in RFC 5869.
        // see http://tools.ietf.org/html/rfc5869
        // The HKDF is a generalization of earlier methods, including the PRF+ method
        // described in section 2.13 of RFC 4306 and others:
        // http://tools.ietf.org/html/rfc4306#section-2.13
        // http://tools.ietf.org/html/rfc5996#section-2.13
        public class CryptoPrimitiveHKDF
        {
            protected readonly ICryptoPrimitiveIteratedHashProvider hashProvider;
            protected readonly int hashLen;

            public CryptoPrimitiveHKDF(ICryptoPrimitiveIteratedHashProvider hashProvider)
            {
                this.hashProvider = hashProvider;
                this.hashLen = hashProvider.OutputLengthBytes;
            }

            // Extract a key from salt (ideally HashLen bytes), IKM ("initial key material")
            // which may be non-uniformly distributed, producing PRK ("pseudo-random key")
            // Salt is optional; in that case it is replaced by HashLen bytes of zero.
            public void Extract(byte[] salt, ProtectedArray<byte> ikm, out byte[] prk)
            {
                if (salt == null)
                {
                    salt = new byte[hashLen];
                }

                try
                {
                    ikm.Reveal();
                    using (CryptoPrimitiveHMAC hmac = new CryptoPrimitiveHMAC(hashProvider, salt/*key*/))
                    {
                        prk = hmac.ComputeHash(ikm.ExposeByteArray());
                    }
                }
                finally
                {
                    ikm.Protect();
                }
            }

            // Expand a pseudo-random key (PRK), optional info (which may be null), into
            // key material of length l, in OKM ("output key material")
            public void Expand(byte[] prk, byte[] info, int l, out byte[] okm)
            {
                if (prk == null)
                {
                    throw new ArgumentNullException();
                }
                if (!(l <= 255 * hashLen))
                {
                    throw new ArgumentException();
                }

                if (info == null)
                {
                    info = new byte[0];
                }

                byte counter = 1;

                byte[] t = new byte[hashLen + info.Length + 1];
                int tLen = 0;

                okm = new byte[l];
                int i = 0;
                while (i < okm.Length)
                {
                    Buffer.BlockCopy(info, 0, t, tLen, info.Length);
                    tLen += info.Length;
                    Debug.Assert(counter != 0);
                    t[tLen++] = counter++;
                    byte[] output;
                    using (CryptoPrimitiveHMAC hmac = new CryptoPrimitiveHMAC(hashProvider, prk/*key*/)) // inefficient to recreate, but my super-simple implementation of HMAC doesn't support reuse
                    {
                        output = hmac.ComputeHash(t, 0, tLen);
                    }
                    Debug.Assert(output.Length == hashLen);
                    Buffer.BlockCopy(output, 0, t, 0, output.Length);
                    tLen = output.Length;

                    int needed = Math.Min(okm.Length - i, tLen);
                    Buffer.BlockCopy(t, 0, okm, i, needed);
                    i += needed;
                }
            }
        }


        public interface ICryptoPrimitiveIteratedHashProvider
        {
            HashAlgorithm GetHash();
            int BlockLengthBytes { get; } // iterated hash algorithm internal block length
            int OutputLengthBytes { get; } // hash algorithm final result length
        }

        public sealed class CryptoPrimitiveIteratedHashProviderSHA256 : ICryptoPrimitiveIteratedHashProvider
        {
            public HashAlgorithm GetHash()
            {
                HashAlgorithm hash = SHA256.Create();
                Debug.Assert(hash.HashSize == OutputLengthBytes * 8);
                return hash;
            }

            public int BlockLengthBytes { get { return 64; } } // iterated hash algorithm internal block length
            public int OutputLengthBytes { get { return 32; } } // hash algorithm final result length
        }

        public sealed class CryptoPrimitiveIteratedHashProviderSkein1024 : ICryptoPrimitiveIteratedHashProvider
        {
            public HashAlgorithm GetHash()
            {
                HashAlgorithm hash = new Skein(BlockLengthBytes * 8, OutputLengthBytes * 8);
                Debug.Assert(hash.HashSize == OutputLengthBytes * 8);
                return hash;
            }

            public int BlockLengthBytes { get { return 1024 / 8; } } // iterated hash algorithm internal block length
            public int OutputLengthBytes { get { return 1024 / 8; } } // hash algorithm final result length
        }


        // Notes on keying the HMAC function (in this application):
        //
        // There is no provision for explicitly validating the cipher key in the HMAC
        // scheme used here. However, the cipher key and signing key are derived from
        // the same passphrase using the same process, so one would expect to have both
        // or neither.
        //
        // Ordinarily, the HMAC on very short messages (empty file or a couple of bytes)
        // would seem to risk divulging information about the key, since the length of
        // plaintext is known from the ciphertext, and the HMAC would depend mostly on the
        // signing key. If the HMAC is weak in some way, there could be an attack.
        // Using salt at the start of a file would mitigate that. However, in practice,
        // with the 32-byte session-key salt at the top of each stream, there are 2 blocks
        // (with AES128) of essentially random data that impacts the HMAC, so it is
        // considered unnecessary to add additional salt.

        // Generic HMAC implementation
        // Described by RFC 2104 "HMAC: Keyed-Hashing for Message Authentication":
        // http://tools.ietf.org/html/rfc2104
        // for use with iterated hash functions.
        public class CryptoPrimitiveHMAC : ICryptoTransform, IDisposable
        {
            private ICryptoPrimitiveIteratedHashProvider hashProvider;
            private HashAlgorithm innerHash;
            private int B; // RFC 2104 constant: hash function internal block length [SHA256]
            private int L; // RFC 2104 constant: hash function output length [SHA256]
            private byte[] key;

            private const byte ipad = 0x36;
            private const byte opad = 0x5C;

            private const int WorkspaceCapacityTarget = Constants.BufferSize;
            private byte[] workspace;
            private int index;
            private bool started;

            private byte[] hash;

            public CryptoPrimitiveHMAC(ICryptoPrimitiveIteratedHashProvider hashProvider, byte[] key)
            {
                B = hashProvider.BlockLengthBytes;
                L = hashProvider.OutputLengthBytes;

#if false // causes short key test case to fail
                // per RFC 2104: minimum recommended key length is L. As we generate keys
                // by an expansion function, there is no need for us to risk supporting short keys here.
                if (key.Length < L)
                {
                    throw new ArgumentException();
                }
#endif

                // per RFC 2014: keys longer than internal block length are hashed once
                if (key.Length > B)
                {
                    using (HashAlgorithm keyHash = hashProvider.GetHash())
                    {
                        key = keyHash.ComputeHash(key);
                    }
                }

                // RFC 2104, section 2: Definition of HMAC
                // Step (1)
                if (key.Length < B)
                {
                    // short keys are padded with zeroes
                    Array.Resize(ref key, B);
                }

                this.hashProvider = hashProvider;
                this.innerHash = hashProvider.GetHash();
                this.key = key;

                int WorkspaceCapacity = WorkspaceCapacityTarget / B;
                WorkspaceCapacity *= B;
                this.workspace = new byte[WorkspaceCapacity];

                PrepareWorkspace(ipad);
            }

            private void PrepareWorkspace(byte pad)
            {
                // RFC 2104, section 2: Definition of HMAC
                // Step (2)
                index = 0;
                for (int i = 0; i < B; i++)
                {
                    workspace[index++] = (byte)(pad ^ key[i]);
                }
            }

            public int HashSize { get { return hashProvider.OutputLengthBytes * 8; } }

            public bool CanReuseTransform { get { return false; } }
            public bool CanTransformMultipleBlocks { get { return true; } }
            public int InputBlockSize { get { return 1; } } // NOT the hash internal block size, but the transform's block size
            public int OutputBlockSize { get { return 1; } } // NOT the hash internal block size, but the transform's block size

            public byte[] Hash
            {
                get
                {
                    if (hash == null)
                    {
                        throw new InvalidOperationException();
                    }
                    return hash;
                }
            }

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                if (innerHash == null)
                {
                    throw new InvalidOperationException();
                }

                started = true;

                for (int i = 0; i < inputCount; i++)
                {
                    workspace[index++] = inputBuffer[i + inputOffset];

                    if (index == workspace.Length)
                    {
                        // RFC 2104, section 2: Definition of HMAC
                        // Step (3): append text to stream
                        // Step (4): apply H (iteratively)
                        int transformed = innerHash.TransformBlock(workspace, 0, index, null, 0);
                        if (transformed != index)
                        {
                            throw new InvalidOperationException();
                        }

                        index = 0;
                    }
                }
                return inputCount;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                if (innerHash == null)
                {
                    throw new InvalidOperationException();
                }

                this.TransformBlock(inputBuffer, inputOffset, inputCount, null, 0);
                if (index != 0)
                {
                    // RFC 2104, section 2: Definition of HMAC
                    // Step (4): apply H (iteratively) - flush remaining input
                    int transformed = innerHash.TransformBlock(workspace, 0, index, null, 0);
                    if (transformed != index)
                    {
                        throw new InvalidOperationException();
                    }
                    index = 0;
                }

                // RFC 2104, section 2: Definition of HMAC
                // Step (4): apply H (iteratively) - final
                innerHash.TransformFinalBlock(workspace, 0, 0);
                byte[] innerHashResult = innerHash.Hash;

                ((IDisposable)innerHash).Dispose();
                innerHash = null;

                // RFC 2104, section 2: Definition of HMAC
                // Step (5)
                PrepareWorkspace(opad);
                // Step (6)
                Buffer.BlockCopy(innerHashResult, 0, workspace, index, innerHashResult.Length);
                index += innerHashResult.Length;
                // Step (7)
                using (HashAlgorithm outerHash = hashProvider.GetHash())
                {
                    outerHash.TransformFinalBlock(workspace, 0, index);
                    hash = outerHash.Hash;
                }

                Dispose(); // reuse is forbidden

                return null;
            }

            public byte[] ComputeHash(byte[] input)
            {
                if (started)
                {
                    throw new InvalidOperationException();
                }
                TransformFinalBlock(input, 0, input.Length);
                return hash;
            }

            public byte[] ComputeHash(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                if (started)
                {
                    throw new InvalidOperationException();
                }
                TransformFinalBlock(inputBuffer, inputOffset, inputCount);
                return hash;
            }

            public void Dispose()
            {
                if (innerHash != null)
                {
                    ((IDisposable)innerHash).Dispose();
                    innerHash = null;
                }
                workspace = null;
            }

            private sealed class KeyedHashTestVector
            {
                internal byte[] key;
                internal byte[] data;
                internal byte[] digest;

                internal KeyedHashTestVector(string key, string data, string digest)
                {
                    this.key = HexDecode(key);
                    this.data = HexDecode(data);
                    this.digest = HexDecode(digest);
                }
            }

            // Private internal, for checking the test vectors provided in RFC 2104.
            // MD5 is weak, so we do not want to expose it beyond here.
            private sealed class MD5Provider : ICryptoPrimitiveIteratedHashProvider
            {
                public HashAlgorithm GetHash()
                {
                    return MD5.Create();
                }

                public int BlockLengthBytes { get { return 64; } } // iterated hash algorithm internal block length
                public int OutputLengthBytes { get { return 16; } } // hash algorithm final result length
            }

            private readonly static KeyedHashTestVector[] TestVectorsMD5 = new KeyedHashTestVector[]
            {
                // RFC 2104 appendix "Test Vectors"
                new KeyedHashTestVector("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", HexEncodeASCII("Hi There"), "9294727a3638bb1c13f48ef8158bfc9d"),
                new KeyedHashTestVector(HexEncodeASCII("Jefe"), HexEncodeASCII("what do ya want for nothing?"), "750c783e6ab0b503eaa86e310a5db738"),
                new KeyedHashTestVector("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", "56be34521d144c88dbb8c733f0e8b3f6"),
            };

            public static void Test()
            {
                foreach (KeyedHashTestVector testVector in TestVectorsMD5)
                {
                    using (CryptoPrimitiveHMAC hmac = new CryptoPrimitiveHMAC(new MD5Provider(), testVector.key))
                    {
                        hmac.TransformFinalBlock(testVector.data, 0, testVector.data.Length);
                        byte[] digest = hmac.Hash;
                        if (!ArrayEqual(digest, testVector.digest))
                        {
                            throw new ApplicationException("HMAC implementation defect");
                        }
                    }
                }
            }
        }


        // TODO: consider providing a more modern key derivation algorithm. RFC 2898 is susceptable
        // to hardware-accelerated attacks. One possible replacement is "scrypt", developed
        // by Colin Percival for Tarsnap (http://www.tarsnap.com/, http://www.tarsnap.com/scrypt.html).
        // However, "scrypt" has it's own concerns, in particular that it is new and has not
        // been standardized, therefore has undergone insufficient scrutiny by the security community.

        // Composable bey derivation module implementing RFC 2898 (to expand passphrase into
        // a master key) and RFC 5869 [HKDF] (to convert master key & salt into session keys).
        public class CryptoSystemKeyGenerationRfc2898Rfc5869 : ICryptoSystemKeyGeneration
        {
            // !These values cannot be changed without breaking compatibility!

            // Password salt of 512 bits should be more than enough uniqueness for the
            // foreseeable future.
            private const int DefaultPasswordSaltLengthBits = 512;

            // Master key of 1024 bits is enough to incorporate the entropy from the password salt
            // and any entropy for the password itself, which is likely to be lower. In addition,
            // it provides room for exapansion in case a keyfile feature is added.
            private const int DefaultMasterKeyLengthBits = 1024;

            // Per RFC 5869: salt is optimally at least "HashLen",
            // which is 256 bits (32 bytes) for HMAC-SHA-256.
            // We have chosen a larger number for posterity (to make all suites contain
            // the same number of random bytes), even though some systems aren't able to
            // take advantage of that much entropy. (This application isn't starved for
            // data space.)
            // File salt should be larger than password salt since a lot more unique
            // instances will be used.
            private const int DefaultFileSaltLengthBits = 1024;

            private const int DefaultDefaultRfc2898Rounds = 20000;

            private int passwordSaltLengthBits;
            private int masterKeyLengthBits;
            private int fileSaltLengthBits;
            private int defaultRfc2898Rounds;

            public CryptoSystemKeyGenerationRfc2898Rfc5869(int? passwordSaltLengthBits, int? masterKeyLengthBits, int? fileSaltLengthBits, int? defaultRfc2898Rounds)
            {
                this.passwordSaltLengthBits = passwordSaltLengthBits.HasValue ? passwordSaltLengthBits.Value : DefaultPasswordSaltLengthBits;
                this.masterKeyLengthBits = masterKeyLengthBits.HasValue ? masterKeyLengthBits.Value : DefaultMasterKeyLengthBits;
                this.fileSaltLengthBits = fileSaltLengthBits.HasValue ? fileSaltLengthBits.Value : DefaultFileSaltLengthBits;
                this.defaultRfc2898Rounds = defaultRfc2898Rounds.HasValue ? defaultRfc2898Rounds.Value : DefaultDefaultRfc2898Rounds;
            }

            public CryptoSystemKeyGenerationRfc2898Rfc5869(int defaultRfc2898Rounds)
                : this(DefaultPasswordSaltLengthBits, DefaultMasterKeyLengthBits, DefaultFileSaltLengthBits, defaultRfc2898Rounds)
            {
            }

            public CryptoSystemKeyGenerationRfc2898Rfc5869()
                : this(DefaultPasswordSaltLengthBits, DefaultMasterKeyLengthBits, DefaultFileSaltLengthBits, DefaultDefaultRfc2898Rounds)
            {
            }

            public int DefaultRfc2898Rounds { get { return defaultRfc2898Rounds; } }

            public int PasswordSaltLengthBytes { get { return passwordSaltLengthBits / 8; } }
            public int MasterKeyLengthBytes { get { return masterKeyLengthBits / 8; } }
            public int FileSaltLengthBytes { get { return fileSaltLengthBits / 8; } }

            // See this article for a survey of key derivation functions:
            // http://tools.ietf.org/html/draft-irtf-cfrg-kdf-uses-00
            // in this implementation two are used:
            // 1. RFC 2898 is used for [password --> master key]
            // see PKCS #5: Password-Based Cryptography Specification:
            // http://tools.ietf.org/html/rfc2898
            // 2. RFC 5869 HKDF method is used for [master key + salt --> session keys]
            // see HMAC-based Extract-and-Expand Key Derivation Function (HKDF):
            // http://tools.ietf.org/html/rfc5869

            public void DeriveMasterKey(ProtectedArray<byte> password, byte[] passwordSalt, int rounds, out ProtectedArray<byte> masterKey)
            {
                password.Reveal();
                try
                {
                    // 2014-09-21: Review of Rfc2898DeriveBytes (http://referencesource.microsoft.com/#mscorlib/system/security/cryptography/rfc2898derivebytes.cs)
                    // It is prefereable to use the constructor that takes byte[] as first argument (rather
                    // than any string argument) because underlying implementation converts to bytes using
                    // "new UTF8Encoding(false).GetBytes()" and discards the resulting byte array after use
                    // without scrubbing, so it is left as cleartext in the heap for an undetermined length
                    // of time.
                    // Another problem is that underlying Rfc2898DeriveBytes, the HMACSHA1 that it uses (http://referencesource.microsoft.com/#mscorlib/system/security/cryptography/hmac.cs)
                    // (based on KeyedHashAlgorithm) calls HMAC.InitializeKey() which clones the key and
                    // makes no attempt to pin it in memory, so copies may be left lying around by the
                    // garbage collector for an indefinite amount of time. The Dispose() method does try to
                    // zero the copied key array, but that's not enough.
                    // This is also true of the internal buffers used by Rfc2898DeriveBytes, but it would be
                    // harder for an attacker to reconstruct the master key from those buffers.
                    // TODO: consider writing our own Rfc2898DeriveBytes.
                    Rfc2898DeriveBytes keyMaker = new Rfc2898DeriveBytes(password.ExposeByteArray(), passwordSalt, rounds);
                    masterKey = new ProtectedArray<byte>(MasterKeyLengthBytes);
                    byte[] masterKeyBytes = keyMaker.GetBytes(MasterKeyLengthBytes);
                    masterKey.AbsorbProtectAndScrub(masterKeyBytes);
                }
                finally
                {
                    password.Protect();
                }
            }

            public void DeriveSessionKeys(ProtectedArray<byte> masterKey, byte[] salt, CryptoKeygroupLengths sessionKeyLengths, out CryptoKeygroup sessionKeys)
            {
                byte[] cipherKey = new byte[sessionKeyLengths.CipherKeyLengthBytes];
                byte[] signingKey = new byte[sessionKeyLengths.SigningKeyLengthBytes];
                byte[] initialCounter = new byte[sessionKeyLengths.InitialCounterLengthBytes];
                DeriveKeys(masterKey, salt, new byte[][] { cipherKey, signingKey, initialCounter }, Rfc5869DeriveBytes);
                sessionKeys = new CryptoKeygroup(cipherKey, signingKey, initialCounter);
            }

            public void DeriveNewSessionKeys(ICryptoSystemRandomNumberGeneration rng, ProtectedArray<byte> masterKey, out byte[] salt, CryptoKeygroupLengths sessionKeyLengths, out CryptoKeygroup sessionKeys)
            {
                salt = rng.CreateRandomBytes(FileSaltLengthBytes);
                DeriveSessionKeys(masterKey, salt, sessionKeyLengths, out sessionKeys);
            }

            private delegate void DeriveBytesMethod(ProtectedArray<byte> masterKey, byte[] sessionSalt, int sessionKeyMaterialLength, out byte[] sessionKeyMaterial);
            private static void DeriveKeys(ProtectedArray<byte> masterKey, byte[] salt, byte[][] keys, DeriveBytesMethod deriveBytes)
            {
                int aggregateLength = 0;
                for (int i = 0; i < keys.Length; i++)
                {
                    aggregateLength += keys[i].Length;
                }

                byte[] sessionKeyMaterial;
                deriveBytes(masterKey, salt, aggregateLength, out sessionKeyMaterial);

                int offset = 0;
                for (int i = 0; i < keys.Length; i++)
                {
                    Buffer.BlockCopy(sessionKeyMaterial, offset, keys[i], 0, keys[i].Length);
                    offset += keys[i].Length;
                }
                Debug.Assert(offset == sessionKeyMaterial.Length);
            }

            // use RFC 5869 HKDF method
            private static void Rfc5869DeriveBytes(ProtectedArray<byte> masterKey, byte[] sessionSalt, int sessionKeyMaterialLength, out byte[] sessionKeyMaterial)
            {
                CryptoPrimitiveHKDF hkdf = new CryptoPrimitiveHKDFSHA256();
                byte[] prk;
                hkdf.Extract(sessionSalt, masterKey, out prk);
                hkdf.Expand(prk, null/*info*/, sessionKeyMaterialLength, out sessionKeyMaterial);
            }

            public virtual void Test()
            {
                CryptoPrimitiveHKDFSHA256.Test();
            }
        }


        // Composable module providing access to .NET default random number generator
        public class CryptoSystemDefaultRNG : ICryptoSystemRandomNumberGeneration
        {
            private RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

            public byte[] CreateRandomBytes(int count)
            {
                byte[] data = new byte[count];
                rng.GetBytes(data);
                return data;
            }

            public void Test()
            {
            }
        }


        // Composable module implementing ThreeFish family of block ciphers
        public abstract class CryptoSystemBlockCipherThreefish : ICryptoSystemBlockCipher
        {
            protected abstract int BlockLengthBits { get; }

            public int CipherBlockLengthBytes { get { return BlockLengthBits / 8; } }
            public int CipherKeyLengthBytes { get { return CipherBlockLengthBytes; } }
            public int InitialVectorLengthBytes { get { return CipherBlockLengthBytes; } }

            private SymmetricAlgorithm GetAlgorithm()
            {
                Threefish fish = new Threefish();
                fish.KeySize = CipherKeyLengthBytes * 8;
                fish.BlockSize = CipherKeyLengthBytes * 8;
                fish.Mode = CipherMode.ECB;
                fish.Padding = PaddingMode.None;
                return fish;
            }

            public Stream CreateEncryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
            {
                return new CryptoPrimitiveCounterModeEncryptStream(stream, this, GetAlgorithm(), cipherKey, initialCounter);
            }

            public Stream CreateDecryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
            {
                return new CryptoPrimitiveCounterModeDecryptStream(stream, this, GetAlgorithm(), cipherKey, initialCounter);
            }

            public void Test()
            {
                if (!SkeinTesting.TestHash())
                {
                    throw new ApplicationException("Implementation fault: internal Skein hash test failed");
                }
            }
        }

        // Specific composable ThreeFish-1024 block cipher
        private sealed class CryptoSystemBlockCipherThreefish1024 : CryptoSystemBlockCipherThreefish
        {
            protected override int BlockLengthBits { get { return 1024; } }
        }


        // Composable module implementing AES family of block ciphers
        public abstract class CryptoSystemBlockCipherAES : ICryptoSystemBlockCipher
        {
            protected const int BlockLengthBits = 128;
            protected abstract int KeyLengthBits { get; }

            public int CipherBlockLengthBytes { get { return BlockLengthBits / 8; } }
            public int CipherKeyLengthBytes { get { return KeyLengthBits / 8; } }
            public int InitialVectorLengthBytes { get { return CipherBlockLengthBytes; } }

            protected SymmetricAlgorithm GetAlgorithm()
            {
                // AES is Rijndael with fixed block size and key size (128, 192, or 256)
                Rijndael rijndael = Rijndael.Create();
                rijndael.KeySize = KeyLengthBits;
                rijndael.BlockSize = BlockLengthBits;
                rijndael.Mode = CipherMode.ECB;
                rijndael.Padding = PaddingMode.None;
                return rijndael;
            }

            public Stream CreateEncryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
            {
                using (SymmetricAlgorithm algorithm = GetAlgorithm())
                {
                    return new CryptoPrimitiveCounterModeEncryptStream(stream, this, algorithm, cipherKey, initialCounter);
                }
            }

            public Stream CreateDecryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
            {
                using (SymmetricAlgorithm algorithm = GetAlgorithm())
                {
                    return new CryptoPrimitiveCounterModeDecryptStream(stream, this, algorithm, cipherKey, initialCounter);
                }
            }

            public virtual void Test()
            {
            }
        }

        // Composable module implementing AES-128 block cipher
        public sealed class CryptoSystemBlockCipherAES128 : CryptoSystemBlockCipherAES
        {
            protected override int KeyLengthBits { get { return 128; } }

            private sealed class CipherTestVector
            {
                internal readonly byte[] key;
                internal readonly byte[] iv;
                internal readonly byte[] plainText;
                internal readonly byte[] cipherText;

                internal CipherTestVector(string key, string iv, string plainText, string cipherText)
                {
                    this.key = HexDecode(key);
                    this.iv = HexDecode(iv);
                    this.plainText = HexDecode(plainText);
                    this.cipherText = HexDecode(cipherText);
                }
            }

            // from http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
            // see also http://csrc.nist.gov/groups/STM/cavp/index.html
            private readonly static CipherTestVector[] TestVectorsAES128ECB = new CipherTestVector[]
            {
                // ECB-AES128.Encrypt (appendix A section F.1.1 of above, page 24)
                new CipherTestVector("2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"),
            };
            private readonly static CipherTestVector[] TestVectorsAES128CTR = new CipherTestVector[]
            {
                // CTR-AES128.Encrypt (appendix A section F.5.1 of above, page 55)
                new CipherTestVector("2b7e151628aed2a6abf7158809cf4f3c", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"),
            };

            public override void Test()
            {
                base.Test();

                foreach (CipherTestVector test in TestVectorsAES128ECB)
                {
                    ICryptoTransform transform;
                    byte[] result;

                    using (transform = GetAlgorithm().CreateEncryptor(test.key, test.iv))
                    {
                        result = transform.TransformFinalBlock(test.plainText, 0, test.plainText.Length);
                        if (!ArrayEqual(test.cipherText, result))
                        {
                            throw new ApplicationException("AES128-ECB implementation defect");
                        }
                    }

                    using (transform = GetAlgorithm().CreateDecryptor(test.key, test.iv))
                    {
                        result = transform.TransformFinalBlock(test.cipherText, 0, test.cipherText.Length);
                        if (!ArrayEqual(test.plainText, result))
                        {
                            throw new ApplicationException("AES128-ECB implementation defect");
                        }
                    }
                }

                foreach (CipherTestVector test in TestVectorsAES128CTR)
                {
                    using (SymmetricAlgorithm algorithm = GetAlgorithm())
                    {
                        ICryptoTransform transform;
                        byte[] result;

                        algorithm.IV = test.iv;
                        algorithm.Key = test.key;

                        using (transform = new CryptoPrimitiveCounterModeTransform(algorithm, test.iv.Length * 8))
                        {
                            result = transform.TransformFinalBlock(test.plainText, 0, test.plainText.Length);
                            if (!ArrayEqual(test.cipherText, result))
                            {
                                throw new ApplicationException("AES128-CTR implementation defect");
                            }
                        }

                        using (transform = new CryptoPrimitiveCounterModeTransform(algorithm, test.iv.Length * 8))
                        {
                            result = transform.TransformFinalBlock(test.cipherText, 0, test.cipherText.Length);
                            if (!ArrayEqual(test.plainText, result))
                            {
                                throw new ApplicationException("AES128-CTR implementation defect");
                            }
                        }
                    }
                }
            }
        }


        // Composable module implementing Serpent family of block ciphers
        public abstract class CryptoSystemBlockCipherSerpent : ICryptoSystemBlockCipher
        {
            protected const int BlockLengthBits = 128;
            protected abstract int KeyLengthBits { get; }

            public int CipherBlockLengthBytes { get { return BlockLengthBits / 8; } }
            public int CipherKeyLengthBytes { get { return KeyLengthBits / 8; } }
            public int InitialVectorLengthBytes { get { return CipherBlockLengthBytes; } }

            protected SymmetricAlgorithm GetAlgorithm()
            {
                SymmetricAlgorithm serpent = new SerpentAlgorithm();
                serpent.KeySize = KeyLengthBits;
                serpent.BlockSize = BlockLengthBits;
                serpent.Mode = CipherMode.ECB;
                serpent.Padding = PaddingMode.None;
                return serpent;
            }

            public Stream CreateEncryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
            {
                return new CryptoPrimitiveCounterModeEncryptStream(stream, this, GetAlgorithm(), cipherKey, initialCounter);
            }

            public Stream CreateDecryptStream(Stream stream, byte[] cipherKey, byte[] initialCounter)
            {
                return new CryptoPrimitiveCounterModeDecryptStream(stream, this, GetAlgorithm(), cipherKey, initialCounter);
            }

            public virtual void Test()
            {
            }
        }

        // Composable module implementing Serpent-256 block cipher
        public sealed class CryptoSystemBlockCipherSerpent256 : CryptoSystemBlockCipherSerpent
        {
            protected override int KeyLengthBits { get { return 256; } }

            private sealed class CipherTestVector
            {
                internal readonly byte[] key;
                internal readonly byte[] iv;
                internal readonly byte[] plainText;
                internal readonly byte[] cipherText;
                internal readonly byte[] cipherText100;
                internal readonly byte[] cipherText1000;

                internal CipherTestVector(string key, string iv, string plainText, string cipherText, string cipherText100, string cipherText1000)
                {
                    this.key = HexDecode(key);
                    this.iv = iv != null ? HexDecode(iv) : null;
                    this.plainText = HexDecode(plainText);
                    this.cipherText = HexDecode(cipherText);
                    this.cipherText100 = cipherText100 != null ? HexDecode(cipherText100) : null;
                    this.cipherText1000 = cipherText1000 != null ? HexDecode(cipherText1000) : null;
                }

                internal CipherTestVector(string key, string iv, string plainText, string cipherText)
                    : this(key, iv, plainText, cipherText, null, null)
                {
                }
            }

            // test vectors from http://www.cs.technion.ac.il/~biham/Reports/Serpent/
            private readonly static CipherTestVector[] TestVectorsSerpentMultiKeylenECB = new CipherTestVector[]
            {
                // http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors
                // Set 4, vector#  0
                new CipherTestVector("000102030405060708090A0B0C0D0E0F", null, "00112233445566778899AABBCCDDEEFF", "563E2CF8740A27C164804560391E9B27", "70795D35DEC6561F8AD83B2F454F9CC5", "4EA3765A7C3A94786850DF4812249718"),
                // Set 4, vector#  1
                new CipherTestVector("2BD6459F82C5B300952C49104881FF48", null, "EA024714AD5C4D84EA024714AD5C4D84", "92D7F8EF2C36C53409F275902F06539F", "180B795EAD8C6CB128348093A7E8E442", "C5F9E521F5FC7D9BB0C4674C48525460"),

                // http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-192-128.verified.test-vectors
                // Set 4, vector#  0
                new CipherTestVector("000102030405060708090A0B0C0D0E0F1011121314151617", null, "00112233445566778899AABBCCDDEEFF", "6AB816C82DE53B93005008AFA2246A02", "D8789291A6307A1DFCFB310CB5CEE8E1", "D4D1005991ACF56FDD6C45ED867CD679"),
                // Set 4, vector#  1
                new CipherTestVector("2BD6459F82C5B300952C49104881FF482BD6459F82C5B300", null, "EA024714AD5C4D84EA024714AD5C4D84", "827B18C2678A239DFC5512842000E204", "696E45B38A8181D1B07F1D311A6F4CFE", "7ECD356D2BE7B1FB7971A1A94BC7BE49"),

                // http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors
                // Set 4, vector#  0
                new CipherTestVector("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", null, "00112233445566778899AABBCCDDEEFF", "2868B7A2D28ECD5E4FDEFAC3C4330074", "8BF56992354F3F1A0F4E49DCBA82CBC0", "9B1D8B34845DF9BFD36AAAD0CDA1C8FE"),
                // Set 4, vector#  1
                new CipherTestVector("2BD6459F82C5B300952C49104881FF482BD6459F82C5B300952C49104881FF48", null, "EA024714AD5C4D84EA024714AD5C4D84", "3E507730776B93FDEA661235E1DD99F0", "3B5462E5D87A40C4BE745E3994D5E373", "99D5D067EF7C787E6A764EB47DAC59AD"),
            };

            public override void Test()
            {
                {
                    Type serpentTestClass = Type.GetType("Serpent.SerpentTest");
                    if (serpentTestClass != null)
                    {
                        MethodInfo serpentTestMethod = serpentTestClass.GetMethod("RunTests");
                        serpentTestMethod.Invoke(null, null);
                    }
                }

                base.Test();

                foreach (CipherTestVector test in TestVectorsSerpentMultiKeylenECB)
                {
                    ICryptoTransform transform;
                    byte[] result;

                    using (transform = GetAlgorithm().CreateEncryptor(test.key, test.iv))
                    {
                        result = transform.TransformFinalBlock(test.plainText, 0, test.plainText.Length);
                        if (!ArrayEqual(test.cipherText, result))
                        {
                            throw new ApplicationException("Serpent-ECB implementation defect");
                        }
                    }

                    using (transform = GetAlgorithm().CreateDecryptor(test.key, test.iv))
                    {
                        result = transform.TransformFinalBlock(test.cipherText, 0, test.cipherText.Length);
                        if (!ArrayEqual(test.plainText, result))
                        {
                            throw new ApplicationException("Serpent-ECB implementation defect");
                        }
                    }

                    using (transform = GetAlgorithm().CreateEncryptor(test.key, test.iv))
                    {
                        if (test.cipherText100 != null)
                        {
                            result = test.plainText;
                            for (int i = 0; i < 100; i++)
                            {
                                result = transform.TransformFinalBlock(result, 0, result.Length);
                            }
                            if (!ArrayEqual(test.cipherText100, result))
                            {
                                throw new ApplicationException("Serpent-ECB implementation defect");
                            }
                        }
                        if (test.cipherText1000 != null)
                        {
                            result = test.plainText;
                            for (int i = 0; i < 1000; i++)
                            {
                                result = transform.TransformFinalBlock(result, 0, result.Length);
                            }
                            if (!ArrayEqual(test.cipherText1000, result))
                            {
                                throw new ApplicationException("Serpent-ECB implementation defect");
                            }
                        }
                    }
                }
            }
        }


        // from NIST AES description - Counter (CTR) mode
        // http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
        // Counter mode has the unique property that encrypting and decrypting are
        // identical. In addition, padding is trivial, which eliminates padding oracle
        // attacks and reduces stream-wrapper complexity.
        // The difficulty is in the use of a (nonce, counter) that is non-repeating
        // over all uses of a particular key, ever, which necessitates careful choice
        // of the nonce when to rekey.
        public class CryptoPrimitiveCounterModeTransform : ICryptoTransform, IDisposable
        {
            private ICryptoTransform encryptor;
            private byte[] counter;
            private byte[] counterSequence;
            private byte[] counterSequenceEncrypted;
            private ulong blockLimit;
            private ulong blockCount;
            private int blockLengthBytes;

            // Use care in selecting initialCounter. All counter values must be forever
            // unique with a given key. Internally counters are generated significantly
            // by incrementing, in little-endian order. Various amounts of the highest-order
            // bytes may be a nonce, depending on how many messages are to be encrypted
            // under a given key, and how long each message will be, which must not exceed
            // 2^(bits-reserved-for-counter) * bytes-per-block
            private CryptoPrimitiveCounterModeTransform(SymmetricAlgorithm algorithm, byte[] initialCounter, int counterBits)
            {
                encryptor = algorithm.CreateEncryptor();

                if ((algorithm.Mode != CipherMode.ECB)
                    || (algorithm.Padding != PaddingMode.None)
                    || (encryptor.OutputBlockSize != encryptor.InputBlockSize)
                    || ((encryptor.OutputBlockSize & (encryptor.OutputBlockSize - 1)) != 0))
                {
                    throw new ArgumentException();
                }

                blockLengthBytes = algorithm.BlockSize / 8;

                if (initialCounter.Length != blockLengthBytes)
                {
                    throw new ArgumentException();
                }

                this.blockLimit = 1UL << Math.Min(63, counterBits);

                this.counter = (byte[])initialCounter.Clone();
                this.counterSequence = new byte[blockLengthBytes];
                this.counterSequenceEncrypted = new byte[blockLengthBytes];
            }

            public CryptoPrimitiveCounterModeTransform(SymmetricAlgorithm algorithm, int counterBits)
                : this(algorithm, algorithm.IV, counterBits)
            {
            }

            public CryptoPrimitiveCounterModeTransform(SymmetricAlgorithm algorithm)
                : this(algorithm, algorithm.IV, algorithm.BlockSize)
            {
            }

            //public static byte[] CreateInitialCounter(int blockLengthBytes)
            //{
            //    byte[] b = new byte[blockLengthBytes];
            //    b[blockLengthBytes - 1] = 1;
            //    return b;
            //}

            public bool CanReuseTransform { get { return false; } }
            public bool CanTransformMultipleBlocks { get { return true; } }
            public int InputBlockSize { get { return blockLengthBytes; } }
            public int OutputBlockSize { get { return blockLengthBytes; } }

            private void GenerateCounterBlock(byte[] buffer, int offset)
            {
                if (blockLimit != 0)
                {
                    blockCount++;
                    if (blockCount >= blockLimit)
                    {
                        throw new ApplicationException("Stream to encrypt is too long - CounterModeCryptoTransform counter limit exceeded");
                    }
                }

                Debug.Assert(blockLengthBytes == counter.Length);
                Buffer.BlockCopy(counter, 0, buffer, offset, blockLengthBytes);

                for (int i = counter.Length - 1; i >= 0; i--)
                {
                    counter[i]++;
                    if (counter[i] != 0)
                    {
                        break;
                    }
                }
            }

            // input and output ranges are permitted to be overlapping.
            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                if ((inputCount & (blockLengthBytes - 1)) != 0)
                {
                    throw new ArgumentException();
                }

                // create counter vector
                if (counterSequence.Length < inputCount)
                {
                    Array.Resize(ref counterSequence, inputCount);
                    Array.Resize(ref counterSequenceEncrypted, inputCount);
                }
                for (int i = 0; i < inputCount; i += blockLengthBytes)
                {
                    GenerateCounterBlock(counterSequence, i);
                }

                // use separate counter array and pad array, in case some pluggable
                // ICryptoTransform can't handle overlap - better safe than sorry.

                // encrypt counter sequence to create pad
                int transformed = encryptor.TransformBlock(counterSequence, 0, inputCount, counterSequenceEncrypted, 0);
                if (transformed != inputCount)
                {
                    throw new InvalidOperationException();
                }

                // xor with plaintext
                for (int i = 0; i < inputCount; i++)
                {
                    outputBuffer[i + outputOffset] = (byte)(inputBuffer[i + inputOffset] ^ counterSequenceEncrypted[i]);
                }

                return inputCount;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                int internalLength = (inputCount | (blockLengthBytes - 1)) + 1;
                byte[] internalInput = new byte[internalLength];
                Buffer.BlockCopy(inputBuffer, inputOffset, internalInput, 0, inputCount);

                TransformBlock(internalInput, 0, internalLength, internalInput, 0);

                byte[] final = new byte[inputCount];
                Buffer.BlockCopy(internalInput, 0, final, 0, inputCount);
                return final;
            }

            public void Dispose()
            {
                if (encryptor != null)
                {
                    encryptor.Dispose();
                    encryptor = null;
                }
                counter = null;
                counterSequence = null;
                counterSequenceEncrypted = null;
            }
        }

        // Provide a secure mechanism for CTR mode encryption. The limitation of CTR is that
        // counter||nonce values must be unique for any given key, globally, forever.
        // For realistic file sizes, this leaves only around 96 to 64 bits (for a 128 bit
        // block cipher, depending on counter range). Randomly chosen nonces are warned against
        // because of the likelihood of collisions, which would be after 2^(48 or 32) bits, because of
        // the birthday bound problem. In addition, a file backup program doesn't have
        // the necessary state for providing an ongoing nonce (such as an incremented message
        // identifier in a network messaging system).
        //
        // As a replacement for CBC with a one block initial vector, randomly chosen,
        // (e.g. 128 bits for AES128), our solution is to use a different session cipher
        // key for each stream. The key is derived using random salt (stored clear in the
        // stream header) and the HKDF-Expand function.
        // 
        // The proper choice of initial counter value is uncertain. The initial design called
        // for using the canonical value 1 as the initial counter value. However, since
        // there is plenty of entropy available in the session salt, the current
        // implementation derives the initial counter value alongside the session key in
        // the key expansion process. It may not help, but it can't hurt.
        //
        // This method should be roughly equivalent to CBC with random IV and the same key
        // across all streams. In the case of CBC random IV, IV collisions are expected in
        // 2^(blocksize/2), i.e. the birthday bound, which is around 2^(64) for AES. For
        // CTR as configured here, random-derived keys are expected to collide in the same
        // time bound of 2^(blocksize/2). Thus this scheme is no worse than CBC + random IV.
        //
        // Alternative methods:
        // An alternative method is to generate a random session key and random start counter
        // value for each stream and encrypt the key using the master key before writing it
        // to the stream header. The ic would be written in the clear, as it would be needed to
        // decrypt the session key. Since the master key would be used for each file, and all
        // individual encryptions would be on a single block (the session key) there would be
        // the same expectation of a counter collision after around 2^(blocksize/2) individual
        // session key encryptions, making this scheme equivalent to the above but requiring
        // an additional block of random data (the ic) to be written to each stream.
        //
        // Other options involve using esoteric constructions, such as:
        // "Luby-Rackoff backwards: Increasing security by making block ciphers non-invertible", Mihir Bellare, Ted Krovetz and Phillip Rogaway, Advances in Cryptology - EUROCRYPT '98, Lecture Notes in Computer Science, Vol. 1403, K. Nyberg, ed., Springer-Verlag, 1998
        // http://www.cs.ucdavis.edu/~rogaway/papers/p2f-abstract.html (http://http://www.cs.ucdavis.edu/~rogaway/papers/p2f.ps)
        // (originally referenced from: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ctr/ctr-spec.pdf)
        // There are a host of schemes besides this one that have been suggested by the
        // theoretical community, most involving conversion of PRPs (pseudo-random
        // permutators, which block ciphers are) into PRFs (pseudo-random functions) by
        // various machinations. See, for example, referenced works from
        // http://www.nuee.nagoya-u.ac.jp/labs/tiwata/cenc/docs/cenc-fse2006full.pdf
        // in particular, citations  [2], [4], [10], and [16]. They look promising -
        // eventually. These constructions are not favored at this time because:
        // - It is not determined how they hold up if the underlying block cipher falls
        //   short of ideal in some way.
        // - They are not well vetted theoretically or practically; they have not gone
        //   through a standards scrutiny process and there are no known widely used
        //   implementations.
        public class CryptoPrimitiveCounterModeDecryptStream : Stream
        {
            private const int DefaultWorkspaceLength = Constants.BufferSize;

            private Stream inner;
            private ICryptoTransform decryptor;
            private byte[] workspace;
            private int index;

            public CryptoPrimitiveCounterModeDecryptStream(Stream inner, ICryptoSystemBlockCipher system, SymmetricAlgorithm algorithm, byte[] cipherKey, byte[] initialCounter)
            {
                if ((algorithm.Mode != CipherMode.ECB)
                    || (algorithm.Padding != PaddingMode.None)
                    || (system.CipherKeyLengthBytes != cipherKey.Length)
                    || (system.InitialVectorLengthBytes != initialCounter.Length)
                    || (algorithm.KeySize / 8 != system.CipherKeyLengthBytes)
                    || (algorithm.BlockSize / 8 != system.InitialVectorLengthBytes))
                {
                    throw new ArgumentException();
                }

                algorithm.IV = initialCounter;
                algorithm.Key = cipherKey;
                this.decryptor = new CryptoPrimitiveCounterModeTransform(algorithm);
                if ((decryptor.OutputBlockSize != decryptor.InputBlockSize)
                    || ((decryptor.OutputBlockSize & (decryptor.OutputBlockSize - 1)) != 0))
                {
                    throw new ArgumentException();
                }

                this.inner = inner;
                this.workspace = new byte[DefaultWorkspaceLength > decryptor.OutputBlockSize ? DefaultWorkspaceLength : decryptor.OutputBlockSize];

                LoadAndDecrypt();
            }

            public override bool CanRead { get { return false; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return true; } }
            public override long Length { get { throw new NotImplementedException(); } }
            public override long Position { get { throw new NotImplementedException(); } set { throw new NotImplementedException(); } }

            public override void Flush()
            {
            }

            public override void Close()
            {
                if (inner != null)
                {
                    inner = null;
                    decryptor.Dispose();
                    decryptor = null;
                    workspace = null;
                }
            }

            private void LoadAndDecrypt()
            {
                int read = inner.Read(workspace, 0, workspace.Length);
                if (read < workspace.Length)
                {
                    Array.Resize(ref workspace, read);
                }

                if (workspace.Length > 0)
                {
                    if ((workspace.Length & (decryptor.OutputBlockSize - 1)) == 0)
                    {
                        Debug.Assert(decryptor is CryptoPrimitiveCounterModeTransform); // ours guarrantees TransformBlock works on overlapped input/output arrays
                        int transformed = decryptor.TransformBlock(workspace, 0, workspace.Length, workspace, 0);
                        if (transformed != workspace.Length)
                        {
                            throw new InvalidOperationException();
                        }
                    }
                    else
                    {
                        workspace = decryptor.TransformFinalBlock(workspace, 0, workspace.Length);
                    }
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
                    if (index == workspace.Length)
                    {
                        index = 0;
                        LoadAndDecrypt();
                    }

                    if (index == workspace.Length)
                    {
                        break;
                    }

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

        // See security note at header of CounterModeDecryptStream
        public class CryptoPrimitiveCounterModeEncryptStream : Stream
        {
            private const int DefaultWorkspaceLength = Constants.BufferSize;

            private Stream inner;
            private ICryptoTransform encryptor;
            private byte[] workspace;
            private int index;

            public CryptoPrimitiveCounterModeEncryptStream(Stream inner, ICryptoSystemBlockCipher system, SymmetricAlgorithm algorithm, byte[] cipherKey, byte[] initialCounter)
            {
                if ((algorithm.Mode != CipherMode.ECB)
                    || (algorithm.Padding != PaddingMode.None)
                    || (system.CipherKeyLengthBytes != cipherKey.Length)
                    || (system.InitialVectorLengthBytes != initialCounter.Length)
                    || (algorithm.KeySize / 8 != system.CipherKeyLengthBytes)
                    || (algorithm.BlockSize / 8 != system.InitialVectorLengthBytes))
                {
                    throw new ArgumentException();
                }

                algorithm.IV = initialCounter;
                algorithm.Key = cipherKey;
                this.encryptor = new CryptoPrimitiveCounterModeTransform(algorithm);
                if ((encryptor.OutputBlockSize != encryptor.InputBlockSize)
                    || ((encryptor.OutputBlockSize & (encryptor.OutputBlockSize - 1)) != 0))
                {
                    throw new ArgumentException();
                }

                this.inner = inner;
                this.workspace = new byte[DefaultWorkspaceLength > encryptor.OutputBlockSize ? DefaultWorkspaceLength : encryptor.OutputBlockSize];
            }

            public override bool CanRead { get { return false; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return true; } }
            public override long Length { get { throw new NotImplementedException(); } }
            public override long Position { get { throw new NotImplementedException(); } set { throw new NotImplementedException(); } }

            public override void Flush()
            {
            }

            public override void Close()
            {
                if (inner != null)
                {
                    byte[] final = encryptor.TransformFinalBlock(workspace, 0, index);
                    inner.Write(final, 0, final.Length);

                    inner = null;
                    encryptor.Dispose();
                    encryptor = null;
                    workspace = null;
                }
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
                if (inner == null)
                {
                    throw new InvalidOperationException();
                }

                for (int i = 0; i < count; i++)
                {
                    workspace[index++] = buffer[i + offset];
                    if (index == workspace.Length)
                    {
                        Debug.Assert(encryptor is CryptoPrimitiveCounterModeTransform); // ours guarrantees TransformBlock works on overlapped input/output arrays
                        int transformed = encryptor.TransformBlock(workspace, 0, workspace.Length, workspace, 0);
                        if (transformed != workspace.Length)
                        {
                            throw new InvalidOperationException();
                        }
                        inner.Write(workspace, 0, workspace.Length);
                        index = 0;
                    }
                }
            }
        }


        // Simple hash functions (ICheckValueGenerator)

        // Specific implementation of a check value generator via SHA-256 hash function,
        // as standardized by NIST:
        // http://en.wikipedia.org/wiki/SHA256
        // http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf
        // http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf [2012]
        // https://www.cosic.esat.kuleuven.be/nessie/testvectors/hash/sha/index.html [test vectors]
        // http://csrc.nist.gov/groups/STM/cavp/index.html#03 [test vectors]
        public class CryptoPrimitiveHashCheckValueGeneratorSHA256 : CryptoPrimitiveHashCheckValueGenerator
        {
            public CryptoPrimitiveHashCheckValueGeneratorSHA256()
                : base(new CryptoPrimitiveIteratedHashProviderSHA256())
            {
            }
        }

        // Specific implementation of a check value generator via Skein-1024 hash function,
        // see http://www.skein-hash.info/ or https://www.schneier.com/skein.html
        public class CryptoPrimitiveHashCheckValueGeneratorSkein1024 : CryptoPrimitiveHashCheckValueGenerator
        {
            public CryptoPrimitiveHashCheckValueGeneratorSkein1024()
                : base(new CryptoPrimitiveIteratedHashProviderSkein1024())
            {
            }
        }

        // Generic cryptographic hash check value generator.
        // Using a caller-provided implementation of HashAlgorithm, it will compute
        // the hash of the total stream seen through ProcessBlock.
        public class CryptoPrimitiveHashCheckValueGenerator : ICheckValueGenerator, IDisposable
        {
            private HashAlgorithm hash;
            private int checkValueLength;

            public CryptoPrimitiveHashCheckValueGenerator(ICryptoPrimitiveIteratedHashProvider hashProvider)
            {
                this.hash = hashProvider.GetHash();
                this.checkValueLength = hash.HashSize / 8;
                Debug.Assert(hashProvider.OutputLengthBytes == checkValueLength);
            }

            public void ProcessBlock(byte[] buffer, int start, int count)
            {
                if (hash == null)
                {
                    throw new InvalidOperationException();
                }

                hash.TransformBlock(buffer, start, count, buffer, start);
            }

            public byte[] GetCheckValueAndClose()
            {
                if (hash == null)
                {
                    throw new InvalidOperationException();
                }

                hash.TransformFinalBlock(new byte[0], 0, 0);
                byte[] hashResult = hash.Hash;
                Debug.Assert(hashResult.Length == CheckValueLength);

                Dispose(); // reuse is forbidden

                return hashResult;
            }

            public int CheckValueLength
            {
                get
                {
                    return checkValueLength;
                }
            }

            public void Dispose()
            {
                if (hash != null)
                {
                    ((IDisposable)hash).Dispose();
                    hash = null;
                }
            }
        }


        // MAC implementations (ICryptoSystemAuthentication), mostly keyed-hash

        // Composable authentication module implementing HMAC-SHA-256
        public class CryptoSystemAuthenticationHMACSHA256 : ICryptoSystemAuthentication
        {
            public int SigningKeyLengthBytes { get { return 256 / 8; /* HMAC-SHA-256 */ } }

            public CryptoSystemAuthenticationHMACSHA256()
            {
                Debug.Assert(SigningKeyLengthBytes == CreateMACGenerator(new byte[0]).CheckValueLength);
            }

            public int MACLengthBytes { get { return 256 / 8; /* HMAC-SHA-256 */ } }

            public ICheckValueGenerator CreateMACGenerator(byte[] signingKey)
            {
                return new CryptoPrimitiveHMACSHA256CheckValueGenerator(signingKey);
            }

            public void Test()
            {
                CryptoPrimitiveHMACSHA256CheckValueGenerator.Test();
                CryptoPrimitiveHMAC.Test();
            }
        }

        // Specific implementation of HMAC check value generator, using SHA-256 hash.
        public class CryptoPrimitiveHMACSHA256CheckValueGenerator : CryptoPrimitiveHMACCheckValueGenerator
        {
            public const int CheckValueLengthBytes = 256 / 8;
            public const int KeyLengthBytes = 512 / 8; // recommended key length (== iterated hash internal block size)

            public CryptoPrimitiveHMACSHA256CheckValueGenerator(byte[] signingKey)
                : base(new CryptoPrimitiveIteratedHashProviderSHA256(), signingKey)
            {
                Debug.Assert(CheckValueLength == CheckValueLengthBytes);
                Debug.Assert(new CryptoPrimitiveIteratedHashProviderSHA256().BlockLengthBytes == KeyLengthBytes);
                Debug.Assert(new CryptoPrimitiveIteratedHashProviderSHA256().OutputLengthBytes == CheckValueLengthBytes);
            }

            private sealed class TestVector
            {
                internal readonly byte[] key;
                internal readonly byte[] message;
                internal readonly byte[] mac;

                internal TestVector(string key, string message, string mac)
                {
                    this.key = HexDecode(key);
                    this.message = HexDecode(message);
                    this.mac = HexDecode(mac);
                }
            }

            // HMAC-SHA-256 test vectors from http://www.rfc-archive.org/getrfc.php?rfc=4231
            private readonly static TestVector[] TestVectorsSHA256 = new TestVector[]
            {
                // Test Case 1 (section 4.2)
                new TestVector("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
                // Test Case 2 (section 4.3) - short key
                new TestVector("4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
                // Test Case 6 (section 4.7) - overlong key
                new TestVector("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
                // Test Case 7 (section 4.8) - overlong all
                new TestVector("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
            };

            public static void Test()
            {
                foreach (TestVector testVector in TestVectorsSHA256)
                {
                    using (CryptoPrimitiveHMACSHA256CheckValueGenerator hmac = new CryptoPrimitiveHMACSHA256CheckValueGenerator(testVector.key))
                    {
                        hmac.ProcessBlock(testVector.message, 0, testVector.message.Length);
                        byte[] mac = hmac.GetCheckValueAndClose();
                        if (!ArrayEqual(mac, testVector.mac))
                        {
                            throw new ApplicationException("HMAC-SHA-256 implementation defect");
                        }
                    }
                }
            }
        }

        // Composable authentication module implementing HMAC-Skein-1024
        //
        // Strictly speaking, Skein is designed to be uased as a MAC without the HMAC
        // construction (it solves weaknesses in SHA-2 and earlier primitives that the
        // HMAC construction is designed to get around). However, as "messages" are
        // mostly large with this system, overhead is not a problem, so a more conservative
        // approach of retaining HMAC was chosen.
        public class CryptoSystemAuthenticationHMACSkein1024 : ICryptoSystemAuthentication
        {
            public int SigningKeyLengthBytes { get { return 1024 / 8; /* HMAC-Skein-1024 */ } }

            public CryptoSystemAuthenticationHMACSkein1024()
            {
                Debug.Assert(SigningKeyLengthBytes == CreateMACGenerator(new byte[0]).CheckValueLength);
            }

            public int MACLengthBytes { get { return 1024 / 8; /* HMAC-Skein-1024 */ } }

            public ICheckValueGenerator CreateMACGenerator(byte[] signingKey)
            {
                return new CryptoPrimitiveHMACSkein1024CheckValueGenerator(signingKey);
            }

            public void Test()
            {
                CryptoPrimitiveHMACSkein1024CheckValueGenerator.Test();
                CryptoPrimitiveHMAC.Test();
            }
        }

        // Specific implementation of HMAC check value generator, using Skein-1024 hash.
        public class CryptoPrimitiveHMACSkein1024CheckValueGenerator : CryptoPrimitiveHMACCheckValueGenerator
        {
            public const int CheckValueLengthBytes = 1024 / 8;
            public const int KeyLengthBytes = 1024 / 8; // recommended key length (== iterated hash internal block size)

            public CryptoPrimitiveHMACSkein1024CheckValueGenerator(byte[] signingKey)
                : base(new CryptoPrimitiveIteratedHashProviderSkein1024(), signingKey)
            {
                Debug.Assert(CheckValueLength == CheckValueLengthBytes);
                Debug.Assert(new CryptoPrimitiveIteratedHashProviderSkein1024().BlockLengthBytes == KeyLengthBytes);
                Debug.Assert(new CryptoPrimitiveIteratedHashProviderSkein1024().OutputLengthBytes == CheckValueLengthBytes);
            }

            public static void Test()
            {
                if (!SkeinTesting.TestHash())
                {
                    throw new ApplicationException("Implementation fault: internal Skein hash test failed");
                }
            }
        }

        // Generic keyed hash message authentication code (HMAC) implementation
        // of ICheckValueGenerator. See:
        // http://en.wikipedia.org/wiki/HMAC
        // http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf
        // http://www.ietf.org/rfc/rfc2104.txt
        public class CryptoPrimitiveHMACCheckValueGenerator : ICheckValueGenerator, IDisposable
        {
            private CryptoPrimitiveHMAC hmac;
            private int checkValueLength; // permit queries after hmac is disposed

            public CryptoPrimitiveHMACCheckValueGenerator(ICryptoPrimitiveIteratedHashProvider hashProvider, byte[] signingKey)
            {
                this.hmac = new CryptoPrimitiveHMAC(hashProvider, signingKey);
                this.checkValueLength = hmac.HashSize / 8;
            }

            public void ProcessBlock(byte[] buffer, int start, int count)
            {
                if (hmac == null)
                {
                    throw new InvalidOperationException();
                }

                hmac.TransformBlock(buffer, start, count, buffer, start);
            }

            public byte[] GetCheckValueAndClose()
            {
                if (hmac == null)
                {
                    throw new InvalidOperationException();
                }

                hmac.TransformFinalBlock(new byte[0], 0, 0);
                byte[] hash = hmac.Hash;
                Debug.Assert(hash.Length == CheckValueLength);

                Dispose(); // reuse is forbidden

                return hash;
            }

            public int CheckValueLength
            {
                get
                {
                    return checkValueLength;
                }
            }

            public void Dispose()
            {
                if (hmac != null)
                {
                    ((IDisposable)hmac).Dispose();
                    hmac = null;
                }
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Display/console functions
        //
        ////////////////////////////////////////////////////////////////////////////

        private static bool? interactive;
        public static bool Interactive()
        {
            if (interactive.HasValue)
            {
                return interactive.Value;
            }
            try
            {
                using (TextWriter writer = new StreamWriter(Stream.Null))
                {
                    writer.Write(Console.BufferWidth);
                    writer.Write(Console.CursorTop);
                    Console.CursorTop = Console.CursorTop;
                }
                interactive = true;
            }
            catch (Exception)
            {
                interactive = false;
            }
            return interactive.Value;
        }

        public static void ConsoleWriteLineColor(ConsoleColor color, string line)
        {
            ConsoleColor colorOld = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine(line);
            Console.ForegroundColor = colorOld;
        }

        public static void ConsoleWriteLineColor(ConsoleColor color, string format, params object[] arg)
        {
            ConsoleColor colorOld = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine(format, arg);
            Console.ForegroundColor = colorOld;
        }

        public static void WriteStatusLine(string line)
        {
            if (Interactive())
            {
                if (line.Length > Console.BufferWidth - 1)
                {
                    line = line.Substring(0, Console.BufferWidth / 2 - 2) + "..." + line.Substring(line.Length - (Console.BufferWidth / 2 - 2));
                }
                line = line + new String(' ', Math.Max(0, Console.BufferWidth - 1 - line.Length));

                Console.WriteLine(line);

                Console.CursorTop -= 1;
            }
            else
            {
                Console.WriteLine(line);
            }
        }

        internal static void EraseStatusLine()
        {
            if (Interactive())
            {
                string line = new String(' ', Console.BufferWidth - 1);
                Console.WriteLine(line);
                Console.CursorTop -= 1;
            }
        }

        internal static char WaitReadKey(bool intercept, int timeout)
        {
            DateTime started = DateTime.Now;
            if (Interactive())
            {
                while (!Console.KeyAvailable)
                {
                    Thread.Sleep(50);
                    if ((timeout >= 0) && ((DateTime.Now - started).TotalMilliseconds >= timeout))
                    {
                        return (char)0;
                    }
                }
                ConsoleKeyInfo info = Console.ReadKey(intercept);
                return info.KeyChar;
            }
            else
            {
                while (Console.In.Peek() < 0)
                {
                    Thread.Sleep(50);
                    if ((timeout >= 0) && ((DateTime.Now - started).TotalMilliseconds >= timeout))
                    {
                        return (char)0;
                    }
                }
                return (char)Console.In.Read();
            }
        }

        internal static char WaitReadKey(bool intercept)
        {
            return WaitReadKey(intercept, -1/*wait forever*/);
        }

        internal static void Windiff(string oldPath, string newPath, bool waitForExit)
        {
            try
            {
                using (Process scriptCmd = new Process())
                {
                    scriptCmd.StartInfo.Arguments = String.Format(" \"{0}\" \"{1}\" ", oldPath, newPath);
                    scriptCmd.StartInfo.CreateNoWindow = true;
                    scriptCmd.StartInfo.FileName = "windiff.exe";
                    scriptCmd.StartInfo.RedirectStandardOutput = true;
                    scriptCmd.StartInfo.UseShellExecute = false;
                    scriptCmd.StartInfo.WorkingDirectory = Path.GetTempPath();
                    scriptCmd.Start();
                    if (waitForExit)
                    {
                        scriptCmd.WaitForExit();
                    }
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine("Windiff failed: {0}", exception.Message);
            }
        }

        // a proof-of-concept, but not very usable in practice (mouse-based schemes are much better)
        internal static ProtectedArray<byte> PromptPasswordRandomized()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            char[] letters = new char[127 - 32 + 1];
            byte[] randoms = new byte[letters.Length];
            rng.GetBytes(randoms);
            for (int i = 32; i < 127; i++)
            {
                letters[i - 32] = (char)i;
            }
            Array.Sort(randoms, letters);

            const int Columns = 16;
            byte[] b = new byte[1];
            rng.GetBytes(b);
            for (int i = 0; i < (b[0] & 0x03); i++)
            {
                Console.WriteLine();
            }
            rng.GetBytes(b);
            string prefix = new String(' ', b[0] & 0x0f);
            Console.WriteLine();
            Console.Write(prefix + "    ");
            for (int j = 0; j < Columns; j++)
            {
                Console.Write("{0}  ", (char)(j + 'A'));
            }
            Console.WriteLine();
            Console.Write(prefix + "    ");
            for (int j = 0; j < Columns; j++)
            {
                Console.Write("-  ");
            }
            Console.WriteLine();
            int count = 0;
            for (int i = 0; (i < 9) && (count < letters.Length); i++)
            {
                Console.Write(prefix + "{0} : ", i + 1);
                for (int j = 0; (j < Columns) && (count < letters.Length); j++)
                {
                    Console.Write("{0}  ", letters[i * Columns + j]);
                    count++;
                }
                Console.WriteLine();
            }
            rng.GetBytes(b);
            for (int i = 0; i < (b[0] & 0x03); i++)
            {
                Console.WriteLine();
            }

            bool interactive = true;
            try
            {
                Console.CursorLeft++;
                Console.CursorLeft--;
            }
            catch (IOException)
            {
                interactive = false;
            }

            ProtectedArray<char> passwordUnicode = new ProtectedArray<char>(0);
            while (true)
            {
                char column = WaitReadKey(true/*intercept*/);
                if (column == (char)ConsoleKey.Enter)
                {
                    break;
                }
                else if (column == (char)ConsoleKey.Backspace)
                {
                    if (passwordUnicode.Length > 0)
                    {
                        ProtectedArray<char> passwordTemp = ProtectedArray<char>.RemoveLast(passwordUnicode);
                        passwordUnicode.Dispose();
                        passwordUnicode = passwordTemp;
                        if (interactive)
                        {
                            Console.CursorLeft--;
                            Console.Write(" ");
                            Console.CursorLeft--;
                        }
                    }
                    continue;
                }
                else if (!((column >= '1') && (column <= '9')))
                {
                    continue;
                }

                char row = WaitReadKey(true/*intercept*/);
                row = Char.ToLower(row);
                if (row == (char)ConsoleKey.Enter)
                {
                    break;
                }
                else if ((row == (char)ConsoleKey.Backspace) || (row == (char)ConsoleKey.Escape))
                {
                    continue;
                }
                else if (!((row >= 'a') && (row <= 'z')))
                {
                    continue;
                }

                int index = (column - '1') * Columns + (row - 'a');
                if ((index >= 0) && (index < letters.Length))
                {
                    ProtectedArray<char> passwordTemp = ProtectedArray<char>.Append(passwordUnicode, letters[index]);
                    passwordUnicode.Dispose();
                    passwordUnicode = passwordTemp;
                    if (interactive)
                    {
                        //Console.Write(".");
                        Console.Write(letters[index]);
                    }
                }
            }
            Console.WriteLine();

            passwordUnicode.Reveal();
            ProtectedArray<byte> password = ProtectedArray<byte>.CreateFromUnicode(passwordUnicode.ExposeByteArray());
            passwordUnicode.Dispose();
            return password;
        }

        internal static ProtectedArray<byte> PromptPassword(string prompt)
        {
            Console.Write(prompt);

            ProtectedArray<char> passwordUnicode = new ProtectedArray<char>(0);
            while (true)
            {
                char key = WaitReadKey(true/*intercept*/);
                if (key == (char)ConsoleKey.Enter)
                {
                    break;
                }
                else if (key == (char)ConsoleKey.Backspace)
                {
                    if (passwordUnicode.Length > 0)
                    {
                        ProtectedArray<char> passwordTemp = ProtectedArray<char>.RemoveLast(passwordUnicode);
                        passwordUnicode.Dispose();
                        passwordUnicode = passwordTemp;
                        if (Interactive())
                        {
                            Console.CursorLeft--;
                            Console.Write(" ");
                            Console.CursorLeft--;
                        }
                    }
                }
                else if (key == (char)ConsoleKey.Escape)
                {
                    return PromptPasswordRandomized();
                }
                else if (key >= 32)
                {
                    ProtectedArray<char> passwordTemp = ProtectedArray<char>.Append(passwordUnicode, key);
                    passwordUnicode.Dispose();
                    passwordUnicode = passwordTemp;
                    if (Interactive())
                    {
                        Console.Write(".");
                    }
                }
            }
            Console.WriteLine();

            passwordUnicode.Reveal();
            ProtectedArray<byte> password = ProtectedArray<byte>.CreateFromUnicode(passwordUnicode.ExposeByteArray());
            passwordUnicode.Dispose();
            return password;
        }

        private static readonly string[] FileSizeSuffixes = new string[] { "B", "KB", "MB", "GB", "TB" };
        internal static string FileSizeString(long length)
        {
            double scaled = length;
            foreach (string suffix in FileSizeSuffixes)
            {
                if (scaled < 1000)
                {
                    return scaled.ToString(scaled >= 1 ? "G3" : "G2") + suffix;
                }
                scaled /= 1024;
            }
            return (scaled * 1024).ToString("N0") + FileSizeSuffixes[FileSizeSuffixes.Length - 1];
        }

        internal static string FileSizeString(string path)
        {
            return FileSizeString(GetFileLength(path));
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Shared utility functions
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

        public class StringSet : ICollection<string>, IEnumerable<string>
        {
            private Dictionary<string, bool> dictionary = new Dictionary<string, bool>();
            private bool caseInsensitive;

            public StringSet()
            {
            }

            public StringSet(bool caseInsensitive)
            {
                this.caseInsensitive = caseInsensitive;
            }

            // specialized methods

            public bool CaseInsensitive { get { return caseInsensitive; } }

            public void Set(string key)
            {
                if (caseInsensitive)
                {
                    key = key.ToLowerInvariant();
                }
                dictionary[key] = false;
            }

            public bool StartsWithAny(string value, string suffix)
            {
                if (caseInsensitive)
                {
                    value = value.ToLowerInvariant();
                    if (suffix != null)
                    {
                        suffix = suffix.ToLowerInvariant();
                    }
                }
                foreach (KeyValuePair<string, bool> item in dictionary)
                {
                    if (value.StartsWith(item.Key + suffix))
                    {
                        return true;
                    }
                }
                return false;
            }

            public bool EndsWithAny(string value, string prefix)
            {
                if (caseInsensitive)
                {
                    value = value.ToLowerInvariant();
                    if (prefix != null)
                    {
                        prefix = prefix.ToLowerInvariant();
                    }
                }
                foreach (KeyValuePair<string, bool> item in dictionary)
                {
                    if (value.EndsWith(prefix + item.Key))
                    {
                        return true;
                    }
                }
                return false;
            }

            // ICollection

            public void Add(string key)
            {
                if (caseInsensitive)
                {
                    key = key.ToLowerInvariant();
                }
                dictionary.Add(key, false);
            }

            public void Clear()
            {
                dictionary.Clear();
            }

            public bool Contains(string key)
            {
                if (caseInsensitive)
                {
                    key = key.ToLowerInvariant();
                }
                return dictionary.ContainsKey(key);
            }

            public void CopyTo(string[] array, int arrayIndex)
            {
                throw new NotImplementedException();
            }

            public int Count
            {
                get { return dictionary.Count; }
            }

            public bool IsReadOnly
            {
                get { return false; }
            }

            public bool Remove(string key)
            {
                if (caseInsensitive)
                {
                    key = key.ToLowerInvariant();
                }
                return dictionary.Remove(key);
            }

            // IEnumerable

            public IEnumerator<string> GetEnumerator()
            {
                return dictionary.Keys.GetEnumerator();
            }

            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            {
                return dictionary.Keys.GetEnumerator();
            }
        }

        public class InvariantStringSet : StringSet
        {
            public InvariantStringSet()
                : base(true/*caseInsensitive*/)
            {
            }
        }

        internal static long GetFileLength(string path)
        {
            using (Stream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                return stream.Length;
            }
        }

        internal static long GetFileLengthRetriable(string path, Context context)
        {
            return DoRetryable<long>(
                delegate { return GetFileLength(path); },
                delegate { return -1; },
                null,
                context);
        }

        internal static long GetFileLengthNoError(string path)
        {
            try
            {
                return GetFileLength(path);
            }
            catch
            {
                return -1;
            }
        }

        internal static void ReadAndDiscardEntireStream(Stream stream)
        {
            byte[] buffer = new byte[Constants.BufferSize];
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) != 0)
            {
            }
        }

        internal static bool ArrayEqual<T>(T[] l, int lStart, T[] r, int rStart, int count) where T : IComparable
        {
            for (int i = 0; i < count; i++)
            {
                if (!l[i + lStart].Equals(r[i + rStart]))
                {
                    return false;
                }
            }
            return true;
        }

        internal static bool ArrayEqual<T>(T[] l, T[] r) where T : IComparable
        {
            if (l.Length != r.Length)
            {
                return false;
            }
            return ArrayEqual(l, 0, r, 0, l.Length);
        }

        internal static void ArrayRemoveAt<T>(ref T[] a, int index, int count)
        {
            Array.Copy(a, index + count, a, index, a.Length - (index + count));
            Array.Resize(ref a, a.Length - count);
        }

        internal static bool IsDriveRoot(string path)
        {
            Debug.Assert(Path.IsPathRooted(path));
            bool driveRoot = Path.GetPathRoot(path) == path;
            return driveRoot;
        }

        // (fileName, isDirectory)
        internal static readonly KeyValuePair<string, bool>[] ExcludedDriveRootItems = new KeyValuePair<string, bool>[]
        {
            //                              fileName,                   isDirectory
            new KeyValuePair<string, bool>("$RECYCLE.BIN",              true),
            new KeyValuePair<string, bool>("hiberfil.sys",              false),
            new KeyValuePair<string, bool>("pagefile.sys",              false),
            new KeyValuePair<string, bool>("RECYCLER",                  true),
            new KeyValuePair<string, bool>("System Volume Information", true),
        };

        internal static bool IsExcludedDriveRootItem(string file)
        {
            string directory = Path.GetDirectoryName(file);
            if (IsDriveRoot(directory))
            {
                string itemName = Path.GetFileName(file);
                if (Array.FindIndex(ExcludedDriveRootItems, delegate(KeyValuePair<string, bool> candidate) { return candidate.Key.Equals(itemName, StringComparison.OrdinalIgnoreCase); }) >= 0)
                {
                    FileAttributes attributes = File.GetAttributes(file);
                    if (((attributes & FileAttributes.Hidden) != 0) &&
                        ((attributes & FileAttributes.System) != 0))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        internal delegate ResultType TryFunctionType<ResultType>();
        internal delegate void ResetFunctionType();
        internal static ResultType DoRetryable<ResultType>(TryFunctionType<ResultType> tryFunction, TryFunctionType<ResultType> continueFunction, ResetFunctionType resetFunction, bool enable, Context context)
        {
            bool tried = false;
            while (true)
            {
                if (tried && (resetFunction != null))
                {
                    resetFunction();
                }
                try
                {
                    return tryFunction();
                }
                catch (Exception exception)
                {
                    tried = true;
                    Console.WriteLine("EXCEPTION: {0}", exception.Message);

                    if (context.continueOnAccessDenied &&
                        (exception is UnauthorizedAccessException) &&
                        (continueFunction != null))
                    {
                        return continueFunction();
                    }

                    if (context.beepEnabled)
                    {
                        Console.Beep(440, 500);
                        Thread.Sleep(200);
                        Console.Beep(440, 500);
                        Thread.Sleep(200);
                        Console.Beep(440, 500);
                    }
                    if (continueFunction == null)
                    {
                        Console.Write("r)etry or q)uit: ");
                    }
                    else
                    {
                        Console.Write("r)etry, q)uit, or c)ontinue: ");
                    }
                    while (true)
                    {
                        char key = WaitReadKey(false/*intercept*/);
                        Console.WriteLine();
                        if (key == 'q')
                        {
                            throw;
                        }
                        else if (key == 'r')
                        {
                            break;
                        }
                        else if ((key == 'c') && (continueFunction != null))
                        {
                            return continueFunction();
                        }
                    }
                }
            }
        }

        internal static ResultType DoRetryable<ResultType>(TryFunctionType<ResultType> tryFunction, TryFunctionType<ResultType> continueFunction, ResetFunctionType resetFunction, Context context)
        {
            return DoRetryable(tryFunction, continueFunction, resetFunction, true/*enable*/, context);
        }

        internal static void GetExclusionArguments(string[] args, out InvariantStringSet excludedExtensions, bool relative, out InvariantStringSet excludedItems)
        {
            excludedExtensions = new InvariantStringSet();
            excludedItems = new InvariantStringSet(); // directories and files
            try
            {
                for (int i = 0; i < args.Length; )
                {
                    switch (args[i])
                    {
                        default:
                            throw new ArgumentException();

                        case "-skip":
                            if (i + 1 >= args.Length)
                            {
                                throw new ArgumentException();
                            }
                            string excludedExtension = args[i + 1];
                            if (!excludedExtension.StartsWith("."))
                            {
                                throw new ArgumentException();
                            }
                            if (excludedExtensions.Contains(excludedExtension))
                            {
                                throw new ArgumentException();
                            }
                            excludedExtensions.Add(excludedExtension);

                            i += 2;
                            break;

                        case "-exclude":
                            if (i + 1 >= args.Length)
                            {
                                throw new ArgumentException();
                            }
                            string excludedPath = args[i + 1];
                            if (excludedPath.StartsWith("\"") && excludedPath.EndsWith("\""))
                            {
                                excludedPath = excludedPath.Substring(1, excludedPath.Length - 2);
                            }
                            if (!relative)
                            {
                                excludedPath = Path.GetFullPath(excludedPath);
                            }
                            else
                            {
                                if (Path.IsPathRooted(excludedPath))
                                {
                                    throw new ArgumentException("excluded path must be relative to root");
                                }
                            }
                            if (excludedItems.Contains(excludedPath))
                            {
                                throw new ArgumentException();
                            }
                            excludedItems.Add(excludedPath);

                            i += 2;
                            break;
                    }
                }
            }
            catch (ArgumentException)
            {
                throw new UsageException();
            }
        }

        internal static bool GetAdHocArgument<T>(ref string[] args, string literal, T defaultValue, T explicitValue, out T value)
        {
            value = defaultValue;
            if ((args.Length >= 1) && String.Equals(args[0], literal, StringComparison.Ordinal))
            {
                value = explicitValue;
                ArrayRemoveAt(ref args, 0, 1);
                return true;
            }
            return false;
        }

        internal delegate T ParseArgument<T>(string s);
        internal static bool GetAdHocArgument<T>(ref string[] args, string literal, T defaultValue, ParseArgument<T> parse, out T value)
        {
            value = defaultValue;
            if ((args.Length >= 2) && String.Equals(args[0], literal, StringComparison.Ordinal))
            {
                value = parse(args[1]);
                ArrayRemoveAt(ref args, 0, 2);
                return true;
            }
            return false;
        }

        internal static void GetPasswordArgument(string[] args, ref int i, string prompt, out ICryptoSystem algorithm, out ProtectedArray<byte> password)
        {
            if (i < args.Length)
            {
                string name = args[i];
                algorithm = Array.Find(CryptoSystems, delegate(ICryptoSystem candidate) { return candidate.Name.Equals(name, StringComparison.Ordinal); });
                if (algorithm == null)
                {
                    throw new UsageException();
                }
            }
            else
            {
                throw new UsageException();
            }
            i++;

            if (i < args.Length)
            {
                if (String.Equals(args[i], "-protected"))
                {
                    // most secure method (passed in as CryptProtectData blob)
                    i++;
                    if (i < args.Length)
                    {
                        string[] parts = args[i].Split(new char[] { ';' });
                        if (parts.Length != 2)
                        {
                            throw new UsageException();
                        }
                        byte[] salt = HexDecode(parts[0]);
                        byte[] encryptedPassword = HexDecode(parts[1]);
                        password = ProtectedArray<byte>.CreateFromProtectedData(encryptedPassword, salt);
                    }
                    else
                    {
                        throw new UsageException();
                    }
                }
                else
                {
                    if (String.IsNullOrEmpty(args[i]) || String.Equals(args[i], "-prompt"))
                    {
                        // somewhat secure method (prompt for password in console)
                        password = PromptPassword(prompt);
                    }
                    else
                    {
                        // insecure method (password passed plaintext as program argument)
                        password = ProtectedArray<byte>.CreateFromUnicode(args[i]);
                        args[i] = null; // does not help much
                    }
                }
            }
            else
            {
                throw new UsageException();
            }
        }

        public class OneWaySwitch
        {
            private bool status = false;

            public OneWaySwitch()
            {
            }

            public void Set()
            {
                status = true;
            }

            public bool Value
            {
                get
                {
                    return status;
                }
            }
        }

        private class FileNamePatternMatch
        {
            private Regex regex;

            public FileNamePatternMatch(string pattern)
            {
                string regexPattern = pattern;

                regexPattern = regexPattern.Replace(".", @"\.");
                regexPattern = regexPattern.Replace("*", ".*");
                regexPattern = regexPattern.Replace("?", ".");
                regexPattern = "^" + regexPattern + "$";

                regex = new Regex(regexPattern);
            }

            public bool IsMatch(string candidate)
            {
                return regex.IsMatch(candidate);
            }

            public static bool ContainsWildcards(string path)
            {
                return path.IndexOfAny(new char[] { '*', '?' }) >= 0;
            }
        }


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
            private const int WorkspaceLength = Constants.BufferSize;

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

            public class TagInvalidException : ExitCodeException
            {
                public TagInvalidException()
                    : base((int)ExitCodes.ConditionNotSatisfied)
                {
                }

                public TagInvalidException(string message)
                    : base((int)ExitCodes.ConditionNotSatisfied, message)
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

                    if (!ArrayEqual(computedCheckValue, storedCheckValue))
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
                            throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied, "Formatted stream block header is incomplete");
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
                                throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied, "Formatted stream block header is incomplete");
                            }
                            if (!ArrayEqual(token, headerToken))
                            {
                                throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied, "Formatted stream block header token has invalid value");
                            }
                        }

                        if (workspace.Length < length)
                        {
                            workspace = new byte[length];
                        }
                        read = ReadFromInner(workspace, 0, length);
                        if (read != length)
                        {
                            throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied, "Formatted stream block is incomplete");
                        }
                        workspaceLength = length;

                        CRC32 checkValueGenerator = new CRC32();
                        checkValueGenerator.ProcessBlock(workspace, 0, workspaceLength);
                        byte[] checkValue = checkValueGenerator.GetCheckValueAndClose();

                        byte[] savedCheckValue = new byte[checkValueGenerator.CheckValueLength];
                        read = ReadFromInner(savedCheckValue, 0, savedCheckValue.Length);
                        if (read != savedCheckValue.Length)
                        {
                            throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied, "Formatted stream check value is incomplete");
                        }
                        if (!ArrayEqual(checkValue, savedCheckValue))
                        {
                            throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied, "Formatted stream check values do not match");
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
                            byte[] localBuffer = new byte[Constants.BufferSize];
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

        [FlagsAttribute]
        public enum CompressionOption
        {
            None = 0,
            Compress = 0x01,
            Decompress = 0x02,
            Recompress = Compress | Decompress,
        }

        [FlagsAttribute]
        public enum EncryptionOption
        {
            None = 0,
            Encrypt = 0x01,
            Decrypt = 0x02,
            Recrypt = Encrypt | Decrypt,
        }

        public class CryptoMasterKeyCacheEntry : IDisposable
        {
            public readonly byte[] passwordSalt;
            public readonly ProtectedArray<byte> masterKey;

            private CryptoMasterKeyCacheEntry()
            {
                throw new NotSupportedException();
            }

            public CryptoMasterKeyCacheEntry(byte[] passwordSalt, ProtectedArray<byte> masterKey)
            {
                this.passwordSalt = passwordSalt;
                this.masterKey = new ProtectedArray<byte>(masterKey);
            }

            public byte[] PasswordSalt { get { return passwordSalt; } }
            public ProtectedArray<byte> MasterKey { get { return new ProtectedArray<byte>(masterKey); } }

            public void Dispose()
            {
                masterKey.Dispose();
            }
        }

        // this object may be accessed from multiple threads
        public class CryptoMasterKeyCache
        {
            private const int MaxCacheEntries = 10;
            private List<CryptoMasterKeyCacheEntry> masterKeys = new List<CryptoMasterKeyCacheEntry>(MaxCacheEntries);

            public CryptoMasterKeyCacheEntry Find(byte[] passwordSalt)
            {
                lock (this)
                {
                    return masterKeys.Find(delegate(CryptoMasterKeyCacheEntry candidate) { return ArrayEqual(candidate.PasswordSalt, passwordSalt); });
                }
            }

            public void Add(CryptoMasterKeyCacheEntry entry)
            {
                lock (this)
                {
                    if (null != Find(entry.PasswordSalt))
                    {
                        throw new ArgumentException();
                    }

                    if (masterKeys.Count >= MaxCacheEntries)
                    {
                        // always keep the first one (the default key)
                        for (int i = 0; i < masterKeys.Count / 2; i++)
                        {
                            masterKeys[1 + i].Dispose();
                        }
                        masterKeys.RemoveRange(1, masterKeys.Count / 2);
                    }

                    masterKeys.Add(entry);
                }
            }

            public CryptoMasterKeyCacheEntry Get(ProtectedArray<byte> password, byte[] passwordSalt, int rounds, ICryptoSystem system)
            {
                lock (this)
                {
                    CryptoMasterKeyCacheEntry entry = Find(passwordSalt);
                    if (entry != null)
                    {
                        return entry;
                    }

                    ProtectedArray<byte> masterKey;
                    system.DeriveMasterKey(password, passwordSalt, rounds, out masterKey);
                    entry = new CryptoMasterKeyCacheEntry(passwordSalt, masterKey);
                    Add(entry);
                    return entry;
                }
            }

            public CryptoMasterKeyCacheEntry GetDefault(ProtectedArray<byte> password, ICryptoSystem system, bool forceNewKeys)
            {
                lock (this)
                {
                    if (!forceNewKeys && (masterKeys.Count > 0))
                    {
                        return masterKeys[0];
                    }

                    byte[] passwordSalt = system.CreateRandomBytes(system.PasswordSaltLengthBytes);
                    ProtectedArray<byte> masterKey;
                    system.DeriveMasterKey(password, passwordSalt, system.DefaultRfc2898Rounds, out masterKey);
                    CryptoMasterKeyCacheEntry entry = new CryptoMasterKeyCacheEntry(passwordSalt, masterKey);
                    Add(entry);
                    return entry;
                }
            }
        }

        public class CryptoContext
        {
            public ICryptoSystem algorithm;
            public ProtectedArray<byte> password;
            // forceNewKeys will make multi-file archives run slower because it forces a new
            // random salt in each file, causing (slow) master key derivation to have to be
            // done again for each file.
            public bool forceNewKeys;
            private CryptoMasterKeyCache masterKeys = new CryptoMasterKeyCache();

            public CryptoMasterKeyCacheEntry GetMasterKeyEntry(byte[] passwordSalt, int rounds)
            {
                return masterKeys.Get(password, passwordSalt, rounds, algorithm);
            }

            public CryptoMasterKeyCacheEntry GetDefaultMasterKeyEntry()
            {
                return masterKeys.GetDefault(password, algorithm, forceNewKeys);
            }
        }

        public struct Context
        {
            public CompressionOption compressionOption;
            public bool doNotPreValidateMAC;
            public bool dirsOnly;
            public bool continueOnAccessDenied;
            public bool zeroLengthSpecial;
            public bool beepEnabled;
            public bool traceEnabled;

            public EncryptionOption cryptoOption;
            public CryptoContext encrypt;
            public CryptoContext decrypt;

            public string logPath;

            public DateTime now;

            public string refreshTokenProtected;
            public bool overrideRemoteSecurityBlock;

            public int? explicitConcurrency;

            public FaultTemplateNode faultInjectionTemplateRoot;
            public FaultInstanceNode faultInjectionRoot;

            public Context(Context original)
            {
                this.compressionOption = original.compressionOption;
                this.doNotPreValidateMAC = original.doNotPreValidateMAC;
                this.dirsOnly = original.dirsOnly;
                this.continueOnAccessDenied = original.continueOnAccessDenied;
                this.zeroLengthSpecial = original.zeroLengthSpecial;
                this.beepEnabled = original.beepEnabled;
                this.traceEnabled = original.traceEnabled;

                this.cryptoOption = original.cryptoOption;
                this.encrypt = original.encrypt;
                this.decrypt = original.decrypt;

                this.logPath = original.logPath;

                this.now = original.now;

                this.refreshTokenProtected = original.refreshTokenProtected;
                this.overrideRemoteSecurityBlock = original.overrideRemoteSecurityBlock;

                this.explicitConcurrency = original.explicitConcurrency;

                this.faultInjectionTemplateRoot = original.faultInjectionTemplateRoot;
                this.faultInjectionRoot = original.faultInjectionRoot;
            }
        }

        internal class EncryptedFileContainerHeader
        {
            public const byte EncryptedFileContainerHeaderNumber = 0x81;

            public byte headerNumber;
            public string uniquePersistentCiphersuiteIdentifier;
            public byte[] passwordSalt;
            public byte[] fileSalt;
            public int rfc2898Rounds;
            public byte[] extra;

            public EncryptedFileContainerHeader(CryptoContext crypto)
            {
                headerNumber = EncryptedFileContainerHeaderNumber;

                uniquePersistentCiphersuiteIdentifier = crypto.algorithm.UniquePersistentCiphersuiteIdentifier;
                rfc2898Rounds = crypto.algorithm.DefaultRfc2898Rounds;
            }

            public EncryptedFileContainerHeader(Stream stream2, bool peek, CryptoContext crypto)
            {
                BinaryReadUtils.Read(
                    stream2,
                    peek,
                    new BinaryReadUtils.Reader[]
                    {
                        delegate(Stream stream) { headerNumber = BinaryReadUtils.ReadBytes(stream, 1)[0]; },
                        delegate(Stream stream) { uniquePersistentCiphersuiteIdentifier = BinaryReadUtils.ReadStringUtf8(stream); },
                        delegate(Stream stream) { passwordSalt = BinaryReadUtils.ReadVariableLengthByteArray(stream); },
                        delegate(Stream stream) { fileSalt = BinaryReadUtils.ReadVariableLengthByteArray(stream); },
                        delegate(Stream stream) { rfc2898Rounds = BinaryReadUtils.ReadVariableLengthQuantityAsInt32(stream); },
                        delegate(Stream stream)
                        {
                            extra = BinaryReadUtils.ReadVariableLengthByteArray(stream);
                            if (extra.Length == 0)
                            {
                                extra = null;
                            }
                        },
                    });

                bool valid = (headerNumber == EncryptedFileContainerHeaderNumber)
                    && String.Equals(uniquePersistentCiphersuiteIdentifier, crypto.algorithm.UniquePersistentCiphersuiteIdentifier)
                    && (passwordSalt.Length == crypto.algorithm.PasswordSaltLengthBytes)
                    && (fileSalt.Length == crypto.algorithm.FileSaltLengthBytes)
                    // but rfc2898Rounds is allowed to vary
                    && (extra == null);
                if (!valid)
                {
                    throw new InvalidDataException("Unrecognized encrypted file header - wrong ciphersuite specified?");
                }
            }

            public void Write(Stream stream)
            {
                BinaryWriteUtils.WriteBytes(stream, new byte[1] { EncryptedFileContainerHeaderNumber });
                BinaryWriteUtils.WriteStringUtf8(stream, uniquePersistentCiphersuiteIdentifier);
                BinaryWriteUtils.WriteVariableLengthByteArray(stream, passwordSalt);
                BinaryWriteUtils.WriteVariableLengthByteArray(stream, fileSalt);
                BinaryWriteUtils.WriteVariableLengthQuantity(stream, rfc2898Rounds);

                BinaryWriteUtils.WriteVariableLengthByteArray(stream, extra != null ? extra : new byte[0]);
            }

            public override bool Equals(object obj)
            {
                EncryptedFileContainerHeader other = (EncryptedFileContainerHeader)obj;
                return (this.headerNumber == other.headerNumber)
                    && ArrayEqual(this.passwordSalt, other.passwordSalt)
                    && ArrayEqual(this.fileSalt, other.fileSalt)
                    && (this.rfc2898Rounds == other.rfc2898Rounds)
                    && ((this.extra == null) == (other.extra == null))
                    && ((this.extra == null) || ArrayEqual(this.extra, other.extra));
            }

            public override int GetHashCode()
            {
                throw new NotSupportedException();
            }
        }

        public interface IAbortable
        {
            void Abort();
        }

        internal delegate Stream StreamWrapMethod(Stream steam);
        internal delegate void StreamProcessor(Stream stream);
        internal static void DoWithStreamStack(Stream underlyingStream, StreamWrapMethod[] cascades, StreamProcessor processor)
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

        internal static void CopyStream(Stream inputStream, Stream outputStream, bool macValidated, EncryptedFileContainerHeader fchInput, CryptoKeygroup inputKeys, Context context)
        {
            DoWithStreamStack(
                inputStream,
                new StreamWrapMethod[]
                {
                    delegate(Stream stream)
                    {
                        // see note and references about
                        // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                        if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                            (context.cryptoOption == EncryptionOption.Recrypt))
                        {
                            if (!macValidated)
                            {
                                return new TaggedReadStream(stream, context.decrypt.algorithm.CreateMACGenerator(inputKeys.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                            }
                            else
                            {
                                return new ReadStreamHoldShort(stream, context.decrypt.algorithm.MACLengthBytes);
                            }
                        }
                        return null;
                    },
                    delegate(Stream stream)
                    {
                        if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                            (context.cryptoOption == EncryptionOption.Recrypt))
                        {
                            // why re-read here? need to read salt within HMAC container
                            EncryptedFileContainerHeader fch2 = new EncryptedFileContainerHeader(stream, false/*peek*/, context.decrypt);
                            if (!fch2.Equals(fchInput))
                            {
                                throw new InvalidOperationException();
                            }
                        }
                        return null;
                    },
                    delegate(Stream stream)
                    {
                        if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                            (context.cryptoOption == EncryptionOption.Recrypt))
                        {
                            return context.decrypt.algorithm.CreateDecryptStream(stream, inputKeys.CipherKey, inputKeys.InitialCounter);
                        }
                        return null;
                    },
                    delegate(Stream stream)
                    {
                        if (context.compressionOption == CompressionOption.Decompress)
                        {
                            return new BlockedDecompressStream(stream);
                        }
                        return null;
                    }
                },
                delegate(Stream finalInputStream)
                {
                    CryptoKeygroup outputKeys = null;
                    EncryptedFileContainerHeader fchOutput = null;
                    if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                        (context.cryptoOption == EncryptionOption.Recrypt))
                    {
                        CryptoMasterKeyCacheEntry entry = context.encrypt.GetDefaultMasterKeyEntry();
                        fchOutput = new EncryptedFileContainerHeader(context.encrypt);
                        fchOutput.passwordSalt = entry.PasswordSalt;
                        context.encrypt.algorithm.DeriveNewSessionKeys(entry.MasterKey, out fchOutput.fileSalt, out outputKeys);
                    }

                    DoWithStreamStack(
                        outputStream,
                        new StreamWrapMethod[]
                        {
                            delegate(Stream stream)
                            {
                                // see note and references about
                                // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                                    (context.cryptoOption == EncryptionOption.Recrypt))
                                {
                                    return new TaggedWriteStream(stream, context.encrypt.algorithm.CreateMACGenerator(outputKeys.SigningKey));
                                }
                                return null;
                            },
                            delegate(Stream stream)
                            {
                                if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                                    (context.cryptoOption == EncryptionOption.Recrypt))
                                {
                                    // why write here? need to write salt within HMAC container
                                    fchOutput.Write(stream);
                                }
                                return null;
                            },
                            delegate(Stream stream)
                            {
                                if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                                    (context.cryptoOption == EncryptionOption.Recrypt))
                                {
                                    return context.encrypt.algorithm.CreateEncryptStream(stream, outputKeys.CipherKey, outputKeys.InitialCounter);
                                }
                                return null;
                            },
                            delegate(Stream stream)
                            {
                                if (context.compressionOption == CompressionOption.Compress)
                                {
                                    return new BlockedCompressStream(stream);
                                }
                                return null;
                            }
                        },
                        delegate(Stream finalOutputStream)
                        {
                            byte[] buffer = new byte[Constants.BufferSize];
                            while (true)
                            {
                                int bytesRead = finalInputStream.Read(buffer, 0, buffer.Length);
                                if (bytesRead == 0)
                                {
                                    break;
                                }
                                finalOutputStream.Write(buffer, 0, bytesRead);
                            }
                        });
                });
        }

        internal static void CopyFile(string source, string target, Context context)
        {
            DoRetryable<int>(
                delegate
                {
                    try
                    {
                        if ((context.cryptoOption == EncryptionOption.None) && (context.compressionOption == CompressionOption.None))
                        {
                            File.Copy(source, target);
                            File.SetAttributes(target, File.GetAttributes(target) & ~(FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System));
                        }
                        else
                        {
                            using (Stream sourceStream = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                            {
                                CryptoKeygroup sourceKeys = null;
                                EncryptedFileContainerHeader fchSource = null;
                                if (sourceStream.Length != 0)
                                {
                                    if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                                        (context.cryptoOption == EncryptionOption.Recrypt))
                                    {
                                        fchSource = new EncryptedFileContainerHeader(sourceStream, true/*peek*/, context.decrypt);
                                        context.decrypt.algorithm.DeriveSessionKeys(context.decrypt.GetMasterKeyEntry(fchSource.passwordSalt, fchSource.rfc2898Rounds).MasterKey, fchSource.fileSalt, out sourceKeys);
                                    }
                                }

                                // Using Moxie Marlinspike's "doom principle": validate the MAC before ANY other
                                // action is taken. (http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/)
                                bool macValidated = false;
                                if (!context.doNotPreValidateMAC
                                    && ((context.cryptoOption == EncryptionOption.Decrypt)
                                    || (context.cryptoOption == EncryptionOption.Recrypt)))
                                {
                                    // zero-length "encrypted" files are considered valid (because backup creates them in checkpoints)
                                    if (sourceStream.Length != 0)
                                    {
                                        DoWithStreamStack(
                                            sourceStream,
                                            new StreamWrapMethod[]
                                            {
                                                delegate(Stream stream)
                                                {
                                                    // see note and references about
                                                    // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                                    return new TaggedReadStream(stream, context.decrypt.algorithm.CreateMACGenerator(sourceKeys.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                                },
                                            },
                                            delegate(Stream stream)
                                            {
                                                ReadAndDiscardEntireStream(stream);
                                            });
                                    }

                                    macValidated = true;
                                }

                                sourceStream.Position = 0;

                                using (Stream targetStream = new FileStream(target, FileMode.CreateNew))
                                {
                                    if (!context.zeroLengthSpecial || (sourceStream.Length != 0))
                                    {
                                        CopyStream(sourceStream, targetStream, macValidated, fchSource, sourceKeys, context);
                                    }
                                    else
                                    {
                                        // leave created target stream empty
                                        // provides work around for decrypting older archive points being unable to copy the zero length placeholders
                                    }
                                }
                            }
                        }
                    }
                    catch (PathTooLongException exception)
                    {
                        throw new PathTooLongException(String.Format("{0} (length={2}, path=\'{1}\')", exception.Message, target, target.Length));
                    }
                    catch (Exception exception)
                    {
                        throw new Exception(String.Format("{0} ({1})", exception.Message, source), exception);
                    }
                    return 0;
                },
                delegate { return 0; },
                delegate
                {
                    try
                    {
                        File.Delete(target);
                    }
                    catch (Exception)
                    {
                    }
                },
                context);

            try
            {
                File.SetCreationTime(target, File.GetCreationTime(source));
                File.SetLastWriteTime(target, File.GetLastWriteTime(source));
            }
            catch (Exception)
            {
            }
        }

        internal static bool CompareStreams(Stream firstStream, Stream secondStream, Context context)
        {
            bool result = false;

            CryptoKeygroup keysFirst = null;
            EncryptedFileContainerHeader fchFirst = null;
            if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                (context.cryptoOption == EncryptionOption.Recrypt))
            {
                fchFirst = new EncryptedFileContainerHeader(firstStream, true/*peek*/, context.decrypt);
                context.decrypt.algorithm.DeriveSessionKeys(context.decrypt.GetMasterKeyEntry(fchFirst.passwordSalt, fchFirst.rfc2898Rounds).MasterKey, fchFirst.fileSalt, out keysFirst);
            }

            CryptoKeygroup keysSecond = null;
            EncryptedFileContainerHeader fchSecond = null;
            if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                (context.cryptoOption == EncryptionOption.Recrypt))
            {
                fchSecond = new EncryptedFileContainerHeader(secondStream, true/*peek*/, context.encrypt);
                context.encrypt.algorithm.DeriveSessionKeys(context.encrypt.GetMasterKeyEntry(fchSecond.passwordSalt, fchSecond.rfc2898Rounds).MasterKey, fchSecond.fileSalt, out keysSecond);
            }

            try
            {
                DoWithStreamStack(
                    firstStream,
                    new StreamWrapMethod[]
                    {
                        delegate(Stream stream)
                        {
                            // see note and references about
                            // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                            if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                                (context.cryptoOption == EncryptionOption.Recrypt))
                            {
                                return new TaggedReadStream(stream, context.decrypt.algorithm.CreateMACGenerator(keysFirst.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                                (context.cryptoOption == EncryptionOption.Recrypt))
                            {
                                // why re-read here? need to read salt within HMAC container
                                EncryptedFileContainerHeader fch2 = new EncryptedFileContainerHeader(stream, false/*peek*/, context.decrypt);
                                if (!fch2.Equals(fchFirst))
                                {
                                    throw new InvalidOperationException();
                                }
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if ((context.cryptoOption == EncryptionOption.Decrypt) ||
                                (context.cryptoOption == EncryptionOption.Recrypt))
                            {
                                return context.decrypt.algorithm.CreateDecryptStream(stream, keysFirst.CipherKey, keysFirst.InitialCounter);
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if ((context.compressionOption == CompressionOption.Decompress)
                                || (context.compressionOption == CompressionOption.Recompress))
                            {
                                return new BlockedDecompressStream(stream);
                            }
                            return null;
                        }
                    },
                    delegate(Stream finalFirstStream)
                    {
                        DoWithStreamStack(
                            secondStream,
                            new StreamWrapMethod[]
                            {
                                delegate(Stream stream)
                                {
                                    // see note and references about
                                    // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                    if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                                        (context.cryptoOption == EncryptionOption.Recrypt))
                                    {
                                        return new TaggedReadStream(stream, context.encrypt.algorithm.CreateMACGenerator(keysSecond.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                    }
                                    return null;
                                },
                                delegate(Stream stream)
                                {
                                    if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                                        (context.cryptoOption == EncryptionOption.Recrypt))
                                    {
                                        // why re-read here? need to read salt within HMAC container
                                        EncryptedFileContainerHeader fch2 = new EncryptedFileContainerHeader(stream, false/*peek*/, context.encrypt);
                                        if (!fch2.Equals(fchSecond))
                                        {
                                            throw new InvalidOperationException();
                                        }
                                    }
                                    return null;
                                },
                                delegate(Stream stream)
                                {
                                    if ((context.cryptoOption == EncryptionOption.Encrypt) ||
                                        (context.cryptoOption == EncryptionOption.Recrypt))
                                    {
                                        return context.encrypt.algorithm.CreateDecryptStream(stream, keysSecond.CipherKey, keysSecond.InitialCounter);
                                    }
                                    return null;
                                },
                                delegate(Stream stream)
                                {
                                    if ((context.compressionOption == CompressionOption.Compress)
                                        || (context.compressionOption == CompressionOption.Recompress))
                                    {
                                        return new BlockedDecompressStream(stream);
                                    }
                                    return null;
                                }
                            },
                            delegate(Stream finalSecondStream)
                            {
                                byte[] bufferFirst = new byte[Constants.BufferSize];
                                byte[] bufferSecond = new byte[Constants.BufferSize];
                                result = true;
                                while (true)
                                {
                                    while (true)
                                    {
                                        int bytesReadFirst = finalFirstStream.Read(bufferFirst, 0, bufferFirst.Length);
                                        int bytesReadSecond = finalSecondStream.Read(bufferSecond, 0, bufferSecond.Length);
                                        if (bytesReadFirst != bytesReadSecond)
                                        {
                                            throw new ExitCodeException(0);
                                        }
                                        if (bytesReadFirst == 0)
                                        {
                                            Debug.Assert(bytesReadSecond == 0);
                                            return;
                                        }

                                        if (!ArrayEqual(bufferFirst, 0, bufferSecond, 0, bytesReadFirst))
                                        {
                                            throw new ExitCodeException(0);
                                        }
                                    }
                                }
                            });
                    });
            }
            catch (CryptographicException)
            {
                // hack because .NET 2.0 has a bug where stream throws exception if
                // it isn't at the end when closed. (Specifically: "Padding is invalid and cannot be removed.")
                result = false;
            }
            catch (ExitCodeException)
            {
                result = false;
            }

            return result;
        }

        internal static bool CompareFile(string source, string target, Context context)
        {
            using (Stream sourceStream = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                using (Stream targetStream = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    return CompareStreams(sourceStream, targetStream, context);
                }
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Copy
        //
        ////////////////////////////////////////////////////////////////////////////

        internal static void CopyRecursive(string sourceRootDirectory, string targetRootDirectory, Context context, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems)
        {
            WriteStatusLine(sourceRootDirectory);

            Directory.CreateDirectory(targetRootDirectory);

            List<string> subdirectories = new List<string>();
            bool driveRoot = IsDriveRoot(sourceRootDirectory);
            foreach (string file in DoRetryable<string[]>(delegate { return Directory.GetFileSystemEntries(sourceRootDirectory); }, delegate { return new string[0]; }, null, context))
            {
                if (!driveRoot || !IsExcludedDriveRootItem(file))
                {
                    FileAttributes fileAttributes = DoRetryable<FileAttributes>(delegate { return File.GetAttributes(file); }, delegate { return FileAttributes.Normal; }, null, context);
                    if ((fileAttributes & FileAttributes.Directory) != 0)
                    {
                        subdirectories.Add(file);
                    }
                    else
                    {
                        if (!context.dirsOnly)
                        {
                            if (!excludedItems.Contains(file.ToLowerInvariant()) &&
                                !excludedExtensions.Contains(Path.GetExtension(file).ToLowerInvariant()))
                            {
                                CopyFile(file, Path.Combine(targetRootDirectory, Path.GetFileName(file)), context);
                            }
                            else
                            {
                                EraseStatusLine();
                                Console.WriteLine("  SKIPPED FILE: {0}", file);
                            }
                        }
                    }
                }
            }

            foreach (string subdirectory in subdirectories)
            {
                if (!excludedItems.Contains(subdirectory.ToLowerInvariant()))
                {
                    CopyRecursive(subdirectory, Path.Combine(targetRootDirectory, Path.GetFileName(subdirectory)), context, excludedExtensions, excludedItems);
                }
                else
                {
                    EraseStatusLine();
                    Console.WriteLine("  SKIPPED SUBDIRECTORY: {0}", subdirectory);
                }
            }

            try
            {
                Directory.SetCreationTime(targetRootDirectory, Directory.GetCreationTime(sourceRootDirectory));
                Directory.SetLastWriteTime(targetRootDirectory, Directory.GetLastWriteTime(sourceRootDirectory));
            }
            catch (Exception)
            {
            }
        }

        internal static void Copy(string source, string target, Context context, string[] args)
        {
            InvariantStringSet excludedExtensions;
            InvariantStringSet excludedItems;
            GetExclusionArguments(args, out excludedExtensions, false/*relative*/, out excludedItems);

            FileAttributes sourceAttributes = DoRetryable<FileAttributes>(delegate { return File.GetAttributes(source); }, delegate { return FileAttributes.Normal; }, null, context);
            if ((sourceAttributes & FileAttributes.Directory) == 0)
            {
                CopyFile(
                    source,
                    Directory.Exists(target)
                        ? Path.Combine(target, Path.GetFileName(source))
                        : target,
                    context);
            }
            else
            {
                CopyRecursive(source, target, context, excludedExtensions, excludedItems);
            }

            EraseStatusLine();
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Compare
        //
        ////////////////////////////////////////////////////////////////////////////

        internal static void CompareRecursive(string sourceRootDirectory, string targetRootDirectory, Context context, OneWaySwitch different, bool red)
        {
            WriteStatusLine(sourceRootDirectory);

            SortedList<string, bool> allFiles = new SortedList<string, bool>();

            try
            {
                bool header = false;

                foreach (string file in Directory.GetFileSystemEntries(sourceRootDirectory))
                {
                    string message = null;
                    string fileName = Path.GetFileName(file);
                    FileAttributes fileAttributes = File.GetAttributes(file);
                    bool isDirectory = ((fileAttributes & FileAttributes.Directory) != 0);
                    allFiles.Add(fileName, isDirectory);
                    string targetFile = Path.Combine(targetRootDirectory, fileName);
                    if (!isDirectory)
                    {
                        if (!File.Exists(targetFile))
                        {
                            message = String.Format("Missing file: {0}", fileName);
                        }
                        else if (!CompareFile(file, targetFile, context))
                        {
                            message = String.Format("Different: {0}", fileName);
                        }
                    }
                    else
                    {
                        if (!Directory.Exists(targetFile))
                        {
                            bool empty = Directory.GetFileSystemEntries(file).Length == 0;
                            message = String.Format("Missing {1} directory: {0}", fileName, empty ? "empty" : "nonempty");
                        }
                    }
                    if (message != null)
                    {
                        EraseStatusLine();
                        different.Set();
                        if (!header)
                        {
                            header = true;
                            Console.WriteLine(targetRootDirectory);
                        }
                        if (red)
                        {
                            ConsoleWriteLineColor(ConsoleColor.Red, "  " + message);
                        }
                        else
                        {
                            Console.WriteLine("  " + message);
                        }
                    }
                }

                foreach (string file in Directory.GetFileSystemEntries(targetRootDirectory))
                {
                    string message = null;
                    string fileName = Path.GetFileName(file);
                    FileAttributes fileAttributes = File.GetAttributes(file);
                    bool isDirectory = ((fileAttributes & FileAttributes.Directory) != 0);
                    if (!allFiles.ContainsKey(fileName) || (allFiles[fileName] != isDirectory))
                    {
                        if (isDirectory)
                        {
                            bool empty = Directory.GetFileSystemEntries(file).Length == 0;
                            message = String.Format("Added {1} directory: {0}", fileName, empty ? "empty" : "nonempty");
                        }
                        else
                        {
                            message = String.Format("Added file: {0}", fileName);
                        }
                    }
                    if (message != null)
                    {
                        EraseStatusLine();
                        different.Set();
                        if (!header)
                        {
                            header = true;
                            Console.WriteLine(targetRootDirectory);
                        }
                        if (red)
                        {
                            ConsoleWriteLineColor(ConsoleColor.Red, "  " + message);
                        }
                        else
                        {
                            Console.WriteLine("  " + message);
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                EraseStatusLine();
                different.Set();
                Console.WriteLine("  Exception processing directory '{0}': {1}", sourceRootDirectory, exception.Message);
            }

            foreach (KeyValuePair<string, bool> item in allFiles)
            {
                if (item.Value && Directory.Exists(Path.Combine(targetRootDirectory, item.Key)))
                {
                    CompareRecursive(Path.Combine(sourceRootDirectory, item.Key), Path.Combine(targetRootDirectory, item.Key), context, different, red);
                }
            }
        }

        internal static void Compare(string source, string target, Context context)
        {
            OneWaySwitch different = new OneWaySwitch();

            FileAttributes sourceAttributes = File.GetAttributes(source);
            FileAttributes targetAttributes = File.GetAttributes(target);
            bool sourceIsFile = ((sourceAttributes & FileAttributes.Directory) == 0);
            bool targetIsFile = ((targetAttributes & FileAttributes.Directory) == 0);
            if (sourceIsFile != targetIsFile)
            {
                different.Set();
                Console.WriteLine("Different");
            }
            else if (sourceIsFile)
            {
                if (CompareFile(source, target, context))
                {
                    Console.WriteLine("Identical");
                }
                else
                {
                    different.Set();
                    Console.WriteLine("Different");
                }
            }
            else
            {
                CompareRecursive(source, target, context, different, false/*red*/);
            }

            EraseStatusLine();

            if (different.Value)
            {
                throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied);
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Sync
        //
        ////////////////////////////////////////////////////////////////////////////

        public interface IEnumerateHierarchy
        {
            bool Valid { get; }
            bool MoveNext();
            string Current { get; }
            string CurrentFullPath { get; }
            FileAttributes CurrentAttributes { get; }
            bool CurrentIsDirectory { get; }
            DateTime CurrentLastWrite { get; }
            void Close();
        }

        internal class EnumerateHierarchy : IEnumerateHierarchy
        {
            private struct Level
            {
                internal readonly string path;
                internal readonly string[] entries;
                internal int index;

                internal Level(string path, string[] entries, int index)
                {
                    this.path = path;
                    this.entries = entries;
                    this.index = index;
                }
            }

            private readonly string root;
            private readonly Stack<Level> stack = new Stack<Level>();
            private Level top;
            private string current;
            private FileAttributes? currentAttributes;
            private DateTime? currentLastWrite;

            internal EnumerateHierarchy(string root)
            {
                this.root = root;
                this.top = new Level(String.Empty, this.GetFileSystemEntries(String.Empty), -1);
            }

            internal EnumerateHierarchy(EnumerateHierarchy original)
            {
                this.root = original.root;
                this.stack = new Stack<Level>(original.stack);
                this.top = original.top;
                this.current = original.current;
            }

            public bool Valid
            {
                get
                {
                    return current != null;
                }
            }

            public bool MoveNext()
            {
                current = null;
                currentAttributes = null;
                currentLastWrite = null;

                string previous = null;
                bool previousIsDirectory = false;
                if (top.index >= 0)
                {
                    previous = !String.IsNullOrEmpty(top.path) ? Path.Combine(top.path, top.entries[top.index]) : top.entries[top.index];
                    try
                    {
                        previousIsDirectory = (File.GetAttributes(Path.Combine(root, previous)) & FileAttributes.Directory) != 0;
                    }
                    catch (FileNotFoundException)
                    {
                    }
                }

                top.index++;

                if (previousIsDirectory)
                {
                    Level newTop = new Level(previous, this.GetFileSystemEntries(previous), 0);
                    stack.Push(top);
                    top = newTop;
                }
                while ((top.index >= top.entries.Length) && (stack.Count > 0))
                {
                    top = stack.Pop();
                }

                if (top.index >= top.entries.Length)
                {
                    return false;
                }

                current = !String.IsNullOrEmpty(top.path) ? Path.Combine(top.path, top.entries[top.index]) : top.entries[top.index];

                return true;
            }

            public string Current
            {
                get
                {
                    if (!Valid)
                    {
                        throw new ApplicationException();
                    }
                    return current;
                }
            }

            public string CurrentFullPath
            {
                get
                {
                    return Path.Combine(root, Current);
                }
            }

            public FileAttributes CurrentAttributes
            {
                get
                {
                    if (!Valid)
                    {
                        throw new ApplicationException();
                    }
                    if (!currentAttributes.HasValue)
                    {
                        currentAttributes = File.GetAttributes(Path.Combine(root, current));
                    }
                    return currentAttributes.Value;
                }
            }

            public bool CurrentIsDirectory
            {
                get
                {
                    return (CurrentAttributes & FileAttributes.Directory) != 0;
                }
            }

            public DateTime CurrentLastWrite
            {
                get
                {
                    if (!Valid)
                    {
                        throw new ApplicationException();
                    }
                    if (!currentLastWrite.HasValue)
                    {
                        currentLastWrite = File.GetLastWriteTime(Path.Combine(root, current));
                    }
                    return currentLastWrite.Value;
                }
            }

            public void Close()
            {
            }

            private string[] GetFileSystemEntries(string path)
            {
                if (Array.FindIndex(ExcludedDriveRootItems, delegate(KeyValuePair<string, bool> candidate) { return candidate.Value/*isDir*/ && candidate.Key.Equals(path, StringComparison.OrdinalIgnoreCase); }) >= 0)
                {
                    return new string[0];
                }

                path = !String.IsNullOrEmpty(path) ? Path.Combine(root, path) : root;
                string[] entries = Directory.GetFileSystemEntries(path);
                for (int i = 0; i < entries.Length; i++)
                {
                    entries[i] = Path.GetFileName(entries[i]);
                }
                Array.Sort(entries, delegate(string l, string r) { return SyncPathCompare(l, r); });
                return entries;
            }
        }

        internal class EnumerateFile : IEnumerateHierarchy, IDisposable
        {
            private readonly string root;
            private readonly string path;
            private Stream stream;
            private string current;
            private FileAttributes currentAttributes;
            private DateTime currentLastWrite;

            internal EnumerateFile(string root, string path)
            {
                this.root = root;
                this.path = path;
                this.stream = new FileStream(this.path, FileMode.Open, FileAccess.Read, FileShare.Read);
                byte[] b = new byte[3];
                int c = this.stream.Read(b, 0, 3);
                if ((c < 3) || (b[0] != 0xEF) || (b[1] != 0xBB) || (b[2] != 0xBF))
                {
                    this.stream.Position = 0;
                }
            }

            internal EnumerateFile(string root)
            {
                this.root = root;
            }

            internal EnumerateFile(EnumerateFile original)
            {
                this.root = original.root;
                this.path = original.path;
                this.stream = new FileStream(this.path, FileMode.Open, FileAccess.Read, FileShare.Read);
                this.stream.Position = original.stream.Position;
                this.current = original.current;
                this.currentAttributes = original.currentAttributes;
                this.currentLastWrite = original.currentLastWrite;
            }

            public bool Valid
            {
                get
                {
                    return current != null;
                }
            }

            public bool MoveNext()
            {
                current = null;

                if (stream == null)
                {
                    return false;
                }

                string line = ReadLineUTF8(stream);
                if (line == null)
                {
                    stream.Close();
                    stream = null;
                    return false;
                }

                string[] parts = line.Split(new char[] { '\t' });
                current = parts[2];
                currentAttributes = (FileAttributes)Int32.Parse(parts[0]);
                currentLastWrite = DateTime.FromBinary(Int64.Parse(parts[1]));

                return true;
            }

            public string Current
            {
                get
                {
                    if (!Valid)
                    {
                        throw new ApplicationException();
                    }
                    return current;
                }
            }

            public string CurrentFullPath
            {
                get
                {
                    return Path.Combine(root, Current);
                }
            }

            public FileAttributes CurrentAttributes
            {
                get
                {
                    if (!Valid)
                    {
                        throw new ApplicationException();
                    }
                    return currentAttributes;
                }
            }

            public bool CurrentIsDirectory
            {
                get
                {
                    return (CurrentAttributes & FileAttributes.Directory) != 0;
                }
            }

            public DateTime CurrentLastWrite
            {
                get
                {
                    if (!Valid)
                    {
                        throw new ApplicationException();
                    }
                    return currentLastWrite;
                }
            }

            public void Close()
            {
                if (stream != null)
                {
                    stream.Close();
                    stream = null;
                }
            }

            void IDisposable.Dispose()
            {
                Close();
            }

            private const string SyncFileNewLine = "\r\n";
            internal static void WriteLine(TextWriter writer, string path, FileAttributes attributes, DateTime lastWrite)
            {
                writer.Write(String.Format("{0}\t{1}\t{2}" + SyncFileNewLine, (Int32)attributes, lastWrite.ToBinary(), path));
            }

            private static string ReadLineUTF8(Stream stream)
            {
                List<byte> encoded = new List<byte>();
                while ((encoded.Count < 2) || !((encoded[encoded.Count - 2] == '\r') && (encoded[encoded.Count - 1] == '\n')))
                {
                    int c = stream.ReadByte();
                    if (c == -1)
                    {
                        break;
                    }
                    encoded.Add((byte)c);
                }
                if ((encoded.Count >= 2) && (encoded[encoded.Count - 2] == '\r') && (encoded[encoded.Count - 1] == '\n'))
                {
                    encoded.RemoveRange(encoded.Count - 2, 2);
                }
                return encoded.Count > 0 ? new String(Encoding.UTF8.GetChars(encoded.ToArray())) : null;
            }
        }

        private static int SyncPathCompare(string l, string r)
        {
            int len = Math.Max(l.Length, r.Length);
            for (int i = 0; i < len; i++)
            {
                char cl = (i < l.Length ? l[i] : (char)0);
                if (cl == '\\')
                {
                    cl = (char)0;
                }
                char cr = (i < r.Length ? r[i] : (char)0);
                if (cr == '\\')
                {
                    cr = (char)0;
                }
                int c = Char.ToLowerInvariant(cl).CompareTo(Char.ToLowerInvariant(cr));
                if (c != 0)
                {
                    return c;
                }
            }
            return 0;
        }

        private static void SyncChange(string sourceRoot, string targetRoot, string path, int codePath, TextWriter log, bool l2r)
        {
            try
            {
                if (log != null)
                {
                    string sizeLPath = Path.Combine(l2r ? sourceRoot : targetRoot, path);
                    string sizeRPath = Path.Combine(l2r ? targetRoot : sourceRoot, path);
                    string sizePart = String.Empty;
                    if (File.Exists(sizeLPath) && File.Exists(sizeRPath))
                    {
                        sizePart = String.Format("{0}, {1} ", FileSizeString(sizeLPath), FileSizeString(sizeRPath));
                    }
                    log.WriteLine("{1}{2}{3} \"{0}\" {5}[codePath={4}]", path, l2r ? sourceRoot : targetRoot, l2r ? "==>" : "<==", l2r ? targetRoot : sourceRoot, codePath, sizePart);
                }

                string sourcePath = Path.Combine(sourceRoot, path);
                string targetPath = Path.Combine(targetRoot, path);

                if (File.Exists(targetPath))
                {
                    if (log != null)
                    {
                        log.WriteLine("  {0,-8} {1,-3} \"{2}\"", "del", String.Empty, targetPath);
                    }
                    File.SetAttributes(targetPath, File.GetAttributes(targetPath) & ~FileAttributes.ReadOnly);
                    File.Delete(targetPath);
                }
                else if (Directory.Exists(targetPath))
                {
                    if (log != null)
                    {
                        log.WriteLine("  {0,-8} {1,-3} \"{2}\"", "rmdir /s", String.Empty, targetPath);
                    }
                    bool retry = false;
                    try
                    {
                        Directory.Delete(targetPath, true/*recursive*/);
                    }
                    catch (IOException)
                    {
                        retry = true;
                    }
                    catch (UnauthorizedAccessException)
                    {
                        retry = true;
                    }
                    if (retry)
                    {
                        EnumerateHierarchy enumSubdir = new EnumerateHierarchy(targetPath);
                        while (enumSubdir.MoveNext())
                        {
                            File.SetAttributes(enumSubdir.CurrentFullPath, File.GetAttributes(enumSubdir.CurrentFullPath) & ~FileAttributes.ReadOnly);
                        }
                        Directory.Delete(targetPath, true/*recursive*/);
                    }
                }

                if (File.Exists(sourcePath))
                {
                    if (log != null)
                    {
                        log.WriteLine("  {0,-8} {1,-3} \"{2}\"", "copy", "to", targetPath);
                    }
                    try
                    {
                        File.Copy(sourcePath, targetPath);
                    }
                    catch (PathTooLongException exception)
                    {
                        throw new PathTooLongException(String.Format("{0} (length={2}, path=\'{1}\')", exception.Message, targetPath, targetPath.Length));
                    }

                    FileAttributes fa = File.GetAttributes(targetPath);
                    File.SetAttributes(targetPath, fa & ~FileAttributes.ReadOnly);
                    File.SetCreationTime(targetPath, File.GetCreationTime(sourcePath));
                    File.SetLastWriteTime(targetPath, File.GetLastWriteTime(sourcePath));
                    File.SetAttributes(targetPath, fa);

                    File.SetAttributes(targetPath, (File.GetAttributes(sourcePath) & ~(FileAttributes.Compressed | FileAttributes.Encrypted)) | (File.GetAttributes(targetPath) & (FileAttributes.Compressed | FileAttributes.Encrypted)));
                }
                else if (Directory.Exists(sourcePath))
                {
                    if (log != null)
                    {
                        log.WriteLine("  {0,-8} {1,-3} \"{2}\"", "mkdir", String.Empty, targetPath);
                    }
                    try
                    {
                        Directory.CreateDirectory(targetPath);
                    }
                    catch (PathTooLongException exception)
                    {
                        throw new PathTooLongException(String.Format("{0} (length={2}, path=\'{1}\')", exception.Message, targetPath, targetPath.Length));
                    }
                    Directory.SetCreationTime(targetPath, Directory.GetCreationTime(sourcePath));
                    Directory.SetLastWriteTime(targetPath, Directory.GetLastWriteTime(sourcePath));
                }
            }
            catch (Exception exception)
            {
                if (log != null)
                {
                    log.WriteLine("  {0} {2}", "EXCEPTION", String.Empty, exception.Message);
                }
                ConsoleWriteLineColor(ConsoleColor.Red, "EXCEPTION at \"{0}\": {1}", path, exception.Message);
                throw;
            }
        }

        const FileAttributes SyncPropagatedAttributes = FileAttributes.ReadOnly | FileAttributes.Directory;

        private static bool SyncSubdirChanged(string root, EnumerateHierarchy currentEntries, EnumerateFile previousEntries, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems)
        {
            currentEntries = new EnumerateHierarchy(currentEntries);
            using (previousEntries = new EnumerateFile(previousEntries))
            {
            Loop:
                while (currentEntries.Valid)
                {
                    if (!currentEntries.Current.Equals(root, StringComparison.OrdinalIgnoreCase) && !currentEntries.Current.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }

                    if (currentEntries.Valid
                        && ((excludedItems.Contains(currentEntries.Current) || excludedItems.StartsWithAny(currentEntries.Current, "\\"))
                        || (!currentEntries.CurrentIsDirectory && excludedExtensions.EndsWithAny(currentEntries.Current, null))))
                    {
                        currentEntries.MoveNext();
                        goto Loop;
                    }

                    string selected = currentEntries.Current;

                    while (previousEntries.Valid && (SyncPathCompare(previousEntries.Current, selected) < 0))
                    {
                        previousEntries.MoveNext();
                    }
                    bool previousExisted = previousEntries.Valid && (SyncPathCompare(previousEntries.Current, selected) == 0);

                    bool changed = !previousExisted || ((previousEntries.CurrentAttributes & SyncPropagatedAttributes) != (currentEntries.CurrentAttributes & SyncPropagatedAttributes)) || (!previousEntries.CurrentIsDirectory && (previousEntries.CurrentLastWrite != currentEntries.CurrentLastWrite));

                    if (changed)
                    {
                        return true;
                    }

                    currentEntries.MoveNext();
                }
            }

            return false;
        }

        private const string SyncSavedManifestName = "sync.txt";
        private const string SyncSavedManifestNewName = "sync0.txt";
        internal static void Sync(string rootL, string rootR, Context context, string[] args)
        {
            bool resolveSkip = false;

            string diagnosticPath;
            GetAdHocArgument(ref args, "-logpath", null/*default*/, delegate(string s) { return s; }, out diagnosticPath);
            TextWriter log = null;
            if (diagnosticPath != null)
            {
                log = new StreamWriter(diagnosticPath, false, Encoding.UTF8);
                log.WriteLine("Sync log");
                log.WriteLine();
            }

            InvariantStringSet excludedExtensions;
            InvariantStringSet excludedItems;
            GetExclusionArguments(args, out excludedExtensions, true/*relative*/, out excludedItems);
            if (IsDriveRoot(Path.GetFullPath(rootL)) || IsDriveRoot(Path.GetFullPath(rootR)))
            {
                foreach (KeyValuePair<string, bool> item in ExcludedDriveRootItems)
                {
                    excludedItems.Set(item.Key);
                }
            }
            excludedItems.Set(SyncSavedManifestName);
            excludedItems.Set(SyncSavedManifestNewName);
            InvariantStringSet suppressLoggingItems = new InvariantStringSet();
            suppressLoggingItems.Set(SyncSavedManifestName);
            suppressLoggingItems.Set(SyncSavedManifestNewName);

            EnumerateHierarchy currentEntriesL = new EnumerateHierarchy(rootL);
            currentEntriesL.MoveNext();
            EnumerateFile previousEntriesL = new EnumerateFile(rootL);
            if (File.Exists(Path.Combine(rootL, SyncSavedManifestName)))
            {
                previousEntriesL = new EnumerateFile(rootL, Path.Combine(rootL, SyncSavedManifestName));
            }
            previousEntriesL.MoveNext();
            TextWriter newEntriesL = new StreamWriter(Path.Combine(rootL, SyncSavedManifestNewName), false/*append*/, Encoding.UTF8);

            EnumerateHierarchy currentEntriesR = new EnumerateHierarchy(rootR);
            currentEntriesR.MoveNext();
            EnumerateFile previousEntriesR = new EnumerateFile(rootR);
            if (File.Exists(Path.Combine(rootR, SyncSavedManifestName)))
            {
                previousEntriesR = new EnumerateFile(rootR, Path.Combine(rootR, SyncSavedManifestName));
            }
            previousEntriesR.MoveNext();
            TextWriter newEntriesR = new StreamWriter(Path.Combine(rootR, SyncSavedManifestNewName), false/*append*/, Encoding.UTF8);

            try
            {
            Loop:
                while (currentEntriesL.Valid || currentEntriesR.Valid)
                {
                    int codePath = -1;

                    bool rootExclusion = false;
                    bool extensionExclusion = false;
                    if (currentEntriesL.Valid
                        && (((rootExclusion = excludedItems.Contains(currentEntriesL.Current)) || excludedItems.StartsWithAny(currentEntriesL.Current, "\\"))
                        || (!currentEntriesL.CurrentIsDirectory && (extensionExclusion = excludedExtensions.EndsWithAny(currentEntriesL.Current, null)))))
                    {
                        if (log != null)
                        {
                            if (!suppressLoggingItems.Contains(currentEntriesL.Current) && (rootExclusion || extensionExclusion))
                            {
                                log.WriteLine("SKIP \"{0}{1}\"", currentEntriesL.Current, Directory.Exists(Path.Combine(rootL, currentEntriesL.Current)) ? "\\" : String.Empty);
                            }
                        }
                        currentEntriesL.MoveNext();
                        goto Loop;
                    }
                    rootExclusion = false;
                    extensionExclusion = false;
                    if (currentEntriesR.Valid
                        && (((rootExclusion = excludedItems.Contains(currentEntriesR.Current)) || excludedItems.StartsWithAny(currentEntriesR.Current, "\\"))
                        || (!currentEntriesR.CurrentIsDirectory && (extensionExclusion = excludedExtensions.EndsWithAny(currentEntriesR.Current, null)))))
                    {
                        if (log != null)
                        {
                            if (!suppressLoggingItems.Contains(currentEntriesR.Current) && (rootExclusion || extensionExclusion))
                            {
                                log.WriteLine("SKIP \"{0}{1}\"", currentEntriesR.Current, Directory.Exists(Path.Combine(rootR, currentEntriesR.Current)) ? "\\" : String.Empty);
                            }
                        }
                        currentEntriesR.MoveNext();
                        goto Loop;
                    }

                    try
                    {
                        int c;
                        if (!currentEntriesR.Valid)
                        {
                            c = -1;
                        }
                        else if (!currentEntriesL.Valid)
                        {
                            c = 1;
                        }
                        else
                        {
                            c = SyncPathCompare(currentEntriesL.Current, currentEntriesR.Current);
                        }

                        string selected = (c <= 0) ? currentEntriesL.Current : currentEntriesR.Current;

                        if (c <= 0 ? Directory.Exists(Path.Combine(rootL, currentEntriesL.Current)) : Directory.Exists(Path.Combine(rootR, currentEntriesR.Current)))
                        {
                            if (log != null)
                            {
                                log.Flush();
                            }
                            WriteStatusLine(selected);
                        }

                        while (previousEntriesL.Valid && (SyncPathCompare(previousEntriesL.Current, selected) < 0))
                        {
                            previousEntriesL.MoveNext();
                        }
                        bool previousLExisted = previousEntriesL.Valid && (SyncPathCompare(previousEntriesL.Current, selected) == 0);
                        while (previousEntriesR.Valid && (SyncPathCompare(previousEntriesR.Current, selected) < 0))
                        {
                            previousEntriesR.MoveNext();
                        }
                        bool previousRExisted = previousEntriesR.Valid && (SyncPathCompare(previousEntriesR.Current, selected) == 0);

                        if (c < 0)
                        {
                            bool changedL = !previousLExisted || ((previousEntriesL.CurrentAttributes & SyncPropagatedAttributes) != (currentEntriesL.CurrentAttributes & SyncPropagatedAttributes)) || (!previousEntriesL.CurrentIsDirectory && (previousEntriesL.CurrentLastWrite != currentEntriesL.CurrentLastWrite));
                            bool changedR = previousRExisted;

                            if (!changedL && previousRExisted && Directory.Exists(Path.Combine(rootL, selected)))
                            {
                                changedL = SyncSubdirChanged(selected, currentEntriesL, previousEntriesL, excludedExtensions, excludedItems);
                            }

                        Conflict100Restart:
                            if (changedL && changedR)
                            {
                                codePath = 100;
                                if (log != null)
                                {
                                    log.WriteLine("CONFLICT '{0}' modified '{2}', deleted '{3}' [codePath={1}]", selected, codePath, rootL, rootR);
                                    log.Flush();
                                }
                                Console.WriteLine();
                                ConsoleWriteLineColor(ConsoleColor.Red, "CONFLICT '{0}' modified '{1}', deleted '{2}'", selected, rootL, rootR);
                                if (!resolveSkip)
                                {
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  L: keep \"{0}\"", Path.Combine(rootL, selected));
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  R: delete \"{0}\"", Path.Combine(rootL, selected));
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  I: ignore");
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  N: ignore all");
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  W: windiff");
                                    while (true)
                                    {
                                        char key = WaitReadKey(true/*intercept*/);
                                        if (key == 'l')
                                        {
                                            ConsoleWriteLineColor(ConsoleColor.Red, "L: keep \"{0}\"", Path.Combine(rootL, selected));
                                            codePath = 121;
                                            if (log != null)
                                            {
                                                log.WriteLine("  USER KEEPS L '{0}' [codePath={1}]", Path.Combine(rootL, selected), codePath);
                                            }
                                            changedL = true;
                                            changedR = false;
                                            goto Conflict100Restart;
                                        }
                                        else if (key == 'r')
                                        {
                                            ConsoleWriteLineColor(ConsoleColor.Red, "R: delete \"{0}\"", Path.Combine(rootL, selected));
                                            codePath = 122;
                                            if (log != null)
                                            {
                                                log.WriteLine("  USER DELETES L '{0}' [codePath={1}]", Path.Combine(rootR, selected), codePath);
                                            }
                                            changedL = false;
                                            changedR = true;
                                            goto Conflict100Restart;
                                        }
                                        else if (key == 'i')
                                        {
                                            break;
                                        }
                                        else if (key == 'n')
                                        {
                                            resolveSkip = true;
                                            break;
                                        }
                                        else if (Char.ToLowerInvariant(key) == 'w')
                                        {
                                            bool flip = key == 'W';
                                            Windiff(Path.Combine(!flip ? rootL : rootR, selected), Path.Combine(!flip ? rootR : rootL, selected), true/*waitForExit*/);
                                        }
                                    }
                                }

                                bool dirL = currentEntriesL.CurrentIsDirectory;
                                currentEntriesL.MoveNext();
                                if (dirL)
                                {
                                    while (currentEntriesL.Valid && currentEntriesL.Current.StartsWith(selected, StringComparison.OrdinalIgnoreCase))
                                    {
                                        currentEntriesL.MoveNext();
                                    }
                                }
                            }
                            else if (changedL)
                            {
                                if (codePath != 121)
                                {
                                    codePath = 101;
                                }
                                if (DoRetryable<bool>(delegate() { SyncChange(rootL, rootR, selected, codePath, log, true/*l2r*/); return true; }, delegate() { return false; }, delegate() { }, context))
                                {
                                    EnumerateFile.WriteLine(newEntriesL, currentEntriesL.Current, currentEntriesL.CurrentAttributes, currentEntriesL.CurrentLastWrite);
                                    EnumerateFile.WriteLine(newEntriesR, currentEntriesL.Current, currentEntriesL.CurrentAttributes, currentEntriesL.CurrentLastWrite);
                                }
                                currentEntriesL.MoveNext();
                            }
                            else if (changedR)
                            {
                                codePath = 102;
                                DoRetryable<bool>(delegate() { SyncChange(rootR, rootL, selected, codePath, log, false/*l2r*/); return true; }, delegate() { return false; }, delegate() { }, context);
                                currentEntriesL.MoveNext();
                            }
                            else
                            {
                                codePath = 103;
                                throw new ApplicationException("Differing names does not accord with no changes");
                            }
                        }
                        else if (c > 0)
                        {
                            bool changedL = previousLExisted;
                            bool changedR = !previousRExisted || ((previousEntriesR.CurrentAttributes & SyncPropagatedAttributes) != (currentEntriesR.CurrentAttributes & SyncPropagatedAttributes)) || (!previousEntriesR.CurrentIsDirectory && (previousEntriesR.CurrentLastWrite != currentEntriesR.CurrentLastWrite));

                            if (!changedR && previousLExisted && Directory.Exists(Path.Combine(rootR, selected)))
                            {
                                changedR = SyncSubdirChanged(selected, currentEntriesR, previousEntriesR, excludedExtensions, excludedItems);
                            }

                        Conflict200Restart:
                            if (changedL && changedR)
                            {
                                codePath = 200;
                                if (log != null)
                                {
                                    log.WriteLine("CONFLICT '{0}' deleted '{2}', modified '{3}' [codePath={1}]", selected, codePath, rootL, rootR);
                                    log.Flush();
                                }
                                Console.WriteLine();
                                ConsoleWriteLineColor(ConsoleColor.Red, "CONFLICT '{0}' deleted '{1}', modified '{2}'", selected, rootL, rootR);
                                if (!resolveSkip)
                                {
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  L: delete \"{0}\"", Path.Combine(rootR, selected));
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  R: keep \"{0}\"", Path.Combine(rootR, selected));
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  I: ignore");
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  N: ignore all");
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  W: windiff");
                                    while (true)
                                    {
                                        char key = WaitReadKey(true/*intercept*/);
                                        if (key == 'l')
                                        {
                                            ConsoleWriteLineColor(ConsoleColor.Red, "L: delete \"{0}\"", Path.Combine(rootR, selected));
                                            codePath = 221;
                                            if (log != null)
                                            {
                                                log.WriteLine("  USER DELETES R '{0}' [codePath={1}]", Path.Combine(rootR, selected), codePath);
                                            }
                                            changedL = true;
                                            changedR = false;
                                            goto Conflict200Restart;
                                        }
                                        else if (key == 'r')
                                        {
                                            ConsoleWriteLineColor(ConsoleColor.Red, "R: keep \"{0}\"", Path.Combine(rootR, selected));
                                            codePath = 222;
                                            if (log != null)
                                            {
                                                log.WriteLine("  USER KEEPS R '{0}' [codePath={1}]", Path.Combine(rootR, selected), codePath);
                                            }
                                            changedL = false;
                                            changedR = true;
                                            goto Conflict200Restart;
                                        }
                                        else if (key == 'i')
                                        {
                                            break;
                                        }
                                        else if (key == 'n')
                                        {
                                            resolveSkip = true;
                                            break;
                                        }
                                        else if (Char.ToLowerInvariant(key) == 'w')
                                        {
                                            bool flip = key == 'W';
                                            Windiff(Path.Combine(!flip ? rootL : rootR, selected), Path.Combine(!flip ? rootR : rootL, selected), true/*waitForExit*/);
                                        }
                                    }
                                }

                                bool dirR = currentEntriesR.CurrentIsDirectory;
                                currentEntriesR.MoveNext();
                                if (dirR)
                                {
                                    while (currentEntriesR.Valid && currentEntriesR.Current.StartsWith(selected, StringComparison.OrdinalIgnoreCase))
                                    {
                                        currentEntriesR.MoveNext();
                                    }
                                }
                            }
                            else if (changedL)
                            {
                                if (codePath != 221)
                                {
                                    codePath = 201;
                                }
                                DoRetryable<bool>(delegate() { SyncChange(rootL, rootR, selected, codePath, log, true/*l2r*/); return true; }, delegate() { return false; }, delegate() { }, context);
                                currentEntriesR.MoveNext();
                            }
                            else if (changedR)
                            {
                                if (codePath != 222)
                                {
                                    codePath = 202;
                                }
                                if (DoRetryable<bool>(delegate() { SyncChange(rootR, rootL, selected, codePath, log, false/*l2r*/); return true; }, delegate() { return false; }, delegate() { }, context))
                                {
                                    EnumerateFile.WriteLine(newEntriesL, currentEntriesR.Current, currentEntriesR.CurrentAttributes, currentEntriesR.CurrentLastWrite);
                                    EnumerateFile.WriteLine(newEntriesR, currentEntriesR.Current, currentEntriesR.CurrentAttributes, currentEntriesR.CurrentLastWrite);
                                }
                                currentEntriesR.MoveNext();
                            }
                            else
                            {
                                codePath = 203;
                                throw new ApplicationException("Differing names does not accord with no changes");
                            }
                        }
                        else
                        {
                            bool changedL = !previousLExisted || !String.Equals(Path.GetFileName(previousEntriesL.Current), Path.GetFileName(currentEntriesL.Current)) || ((previousEntriesL.CurrentAttributes & SyncPropagatedAttributes) != (currentEntriesL.CurrentAttributes & SyncPropagatedAttributes)) || (!previousEntriesL.CurrentIsDirectory && (previousEntriesL.CurrentLastWrite != currentEntriesL.CurrentLastWrite));
                            bool changedR = !previousRExisted || !String.Equals(Path.GetFileName(previousEntriesR.Current), Path.GetFileName(currentEntriesR.Current)) || ((previousEntriesR.CurrentAttributes & SyncPropagatedAttributes) != (currentEntriesR.CurrentAttributes & SyncPropagatedAttributes)) || (!previousEntriesR.CurrentIsDirectory && (previousEntriesR.CurrentLastWrite != currentEntriesR.CurrentLastWrite));

                            if (!changedL && previousRExisted && Directory.Exists(Path.Combine(rootL, selected)) && File.Exists(Path.Combine(rootR, selected)))
                            {
                                changedL = SyncSubdirChanged(selected, currentEntriesL, previousEntriesL, excludedExtensions, excludedItems);
                            }
                            if (!changedR && previousLExisted && Directory.Exists(Path.Combine(rootR, selected)) && File.Exists(Path.Combine(rootL, selected)))
                            {
                                changedR = SyncSubdirChanged(selected, currentEntriesR, previousEntriesR, excludedExtensions, excludedItems);
                            }

                        Conflict300Restart:
                            if (changedL && changedR)
                            {
                                codePath = 300;
                                if (log != null)
                                {
                                    const string TimeStampFormat = "s";
                                    log.WriteLine("CONFLICT '{0}' L:{1},{2} R:{3},{4} [codePath={5}]", selected, (int)currentEntriesL.CurrentAttributes, !currentEntriesL.CurrentIsDirectory ? currentEntriesL.CurrentLastWrite.ToString(TimeStampFormat) : "0", (int)currentEntriesR.CurrentAttributes, !currentEntriesR.CurrentIsDirectory ? currentEntriesR.CurrentLastWrite.ToString(TimeStampFormat) : "0", codePath);
                                    log.Flush();
                                }
                                bool? same = null;
                                try
                                {
                                    same = CompareFile(Path.Combine(rootL, currentEntriesL.Current), Path.Combine(rootR, currentEntriesR.Current), new Context());
                                }
                                catch (Exception)
                                {
                                }
                                Console.WriteLine();
                                ConsoleWriteLineColor(ConsoleColor.Red, "CONFLICT '{0}' modified both, {1}", selected, same.HasValue ? (same.Value ? "identical" : "different") : "unreadable");
                                if (!resolveSkip)
                                {
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  L: keep \"{0}\"{1}", Path.Combine(rootL, currentEntriesL.Current), currentEntriesL.CurrentLastWrite > currentEntriesR.CurrentLastWrite ? " [more recent]" : String.Empty);
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  R: keep \"{0}\"{1}", Path.Combine(rootR, currentEntriesR.Current), currentEntriesL.CurrentLastWrite < currentEntriesR.CurrentLastWrite ? " [more recent]" : String.Empty);
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  I: ignore");
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  N: ignore all");
                                    ConsoleWriteLineColor(ConsoleColor.Red, "  W: windiff (Shift-W to reverse)");
                                    while (true)
                                    {
                                        char key = WaitReadKey(true/*intercept*/);
                                        if (key == 'l')
                                        {
                                            ConsoleWriteLineColor(ConsoleColor.Red, "L: keep \"{0}\"", Path.Combine(rootL, currentEntriesL.Current));
                                            codePath = 321;
                                            if (log != null)
                                            {
                                                log.WriteLine("  USER KEEPS L '{0}' [codePath={1}]", Path.Combine(rootL, currentEntriesL.Current), codePath);
                                            }
                                            changedL = true;
                                            changedR = false;
                                            goto Conflict300Restart;
                                        }
                                        else if (key == 'r')
                                        {
                                            ConsoleWriteLineColor(ConsoleColor.Red, "R: keep \"{0}\"", Path.Combine(rootR, currentEntriesR.Current));
                                            codePath = 322;
                                            if (log != null)
                                            {
                                                log.WriteLine("  USER KEEPS R '{0}' [codePath={1}]", Path.Combine(rootR, currentEntriesR.Current), codePath);
                                            }
                                            changedL = false;
                                            changedR = true;
                                            goto Conflict300Restart;
                                        }
                                        else if (key == 'i')
                                        {
                                            break;
                                        }
                                        else if (key == 'n')
                                        {
                                            resolveSkip = true;
                                            break;
                                        }
                                        else if (Char.ToLowerInvariant(key) == 'w')
                                        {
                                            bool flip = key == 'W';
                                            Windiff(Path.Combine(!flip ? rootL : rootR, selected), Path.Combine(!flip ? rootR : rootL, selected), true/*waitForExit*/);
                                        }
                                    }
                                }

                                bool dirL = currentEntriesL.CurrentIsDirectory;
                                currentEntriesL.MoveNext();
                                if (dirL)
                                {
                                    while (currentEntriesL.Valid && currentEntriesL.Current.StartsWith(selected, StringComparison.OrdinalIgnoreCase))
                                    {
                                        currentEntriesL.MoveNext();
                                    }
                                }

                                bool dirR = currentEntriesR.CurrentIsDirectory;
                                currentEntriesR.MoveNext();
                                if (dirR)
                                {
                                    while (currentEntriesR.Valid && currentEntriesR.Current.StartsWith(selected, StringComparison.OrdinalIgnoreCase))
                                    {
                                        currentEntriesR.MoveNext();
                                    }
                                }
                            }
                            else if (changedL)
                            {
                                if (codePath != 321)
                                {
                                    codePath = 301;
                                }
                                bool dirR = currentEntriesR.CurrentIsDirectory;
                                if (DoRetryable<bool>(delegate() { SyncChange(rootL, rootR, currentEntriesL.Current, codePath, log, true/*l2r*/); return true; }, delegate() { return false; }, delegate() { }, context))
                                {
                                    EnumerateFile.WriteLine(newEntriesL, currentEntriesL.Current, currentEntriesL.CurrentAttributes, currentEntriesL.CurrentLastWrite);
                                    EnumerateFile.WriteLine(newEntriesR, currentEntriesL.Current, currentEntriesL.CurrentAttributes, currentEntriesL.CurrentLastWrite);
                                }
                                currentEntriesL.MoveNext();
                                currentEntriesR.MoveNext();
                                if (dirR)
                                {
                                    while (currentEntriesR.Valid && currentEntriesR.Current.StartsWith(selected, StringComparison.OrdinalIgnoreCase))
                                    {
                                        currentEntriesR.MoveNext();
                                    }
                                }
                            }
                            else if (changedR)
                            {
                                if (codePath != 322)
                                {
                                    codePath = 302;
                                }
                                bool dirL = currentEntriesL.CurrentIsDirectory;
                                if (DoRetryable<bool>(delegate() { SyncChange(rootR, rootL, currentEntriesR.Current, codePath, log, false/*l2r*/); return true; }, delegate() { return false; }, delegate() { }, context))
                                {
                                    EnumerateFile.WriteLine(newEntriesL, currentEntriesR.Current, currentEntriesR.CurrentAttributes, currentEntriesR.CurrentLastWrite);
                                    EnumerateFile.WriteLine(newEntriesR, currentEntriesR.Current, currentEntriesR.CurrentAttributes, currentEntriesR.CurrentLastWrite);
                                }
                                currentEntriesL.MoveNext();
                                if (dirL)
                                {
                                    while (currentEntriesL.Valid && currentEntriesL.Current.StartsWith(selected, StringComparison.OrdinalIgnoreCase))
                                    {
                                        currentEntriesL.MoveNext();
                                    }
                                }
                                currentEntriesR.MoveNext();
                            }
                            else
                            {
                                codePath = 303;
                                EnumerateFile.WriteLine(newEntriesL, currentEntriesL.Current, currentEntriesL.CurrentAttributes, currentEntriesL.CurrentLastWrite);
                                EnumerateFile.WriteLine(newEntriesR, currentEntriesR.Current, currentEntriesR.CurrentAttributes, currentEntriesR.CurrentLastWrite);
                                currentEntriesL.MoveNext();
                                currentEntriesR.MoveNext();
                            }
                        }
                    }
                    catch (Exception exception)
                    {
                        if (log != null)
                        {
                            log.WriteLine("EXCEPTION: {0} [codePath={1}]", exception.Message, codePath);
                        }
                        throw;
                    }
                }

                EraseStatusLine();
                Console.WriteLine();
            }
            finally
            {
                previousEntriesL.Close();
                currentEntriesL.Close();
                newEntriesL.Close();

                previousEntriesR.Close();
                currentEntriesR.Close();
                newEntriesR.Close();

                if (log != null)
                {
                    log.WriteLine();
                    log.WriteLine("Finished");

                    log.Close();
                    log = null;
                }
            }


            if (File.Exists(Path.Combine(rootL, SyncSavedManifestName)))
            {
                File.Delete(Path.Combine(rootL, SyncSavedManifestName));
            }
            if (File.Exists(Path.Combine(rootR, SyncSavedManifestName)))
            {
                File.Delete(Path.Combine(rootR, SyncSavedManifestName));
            }
            File.Move(Path.Combine(rootL, SyncSavedManifestNewName), Path.Combine(rootL, SyncSavedManifestName));
            File.Move(Path.Combine(rootR, SyncSavedManifestNewName), Path.Combine(rootR, SyncSavedManifestName));
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Backup
        //
        ////////////////////////////////////////////////////////////////////////////

        private static void CreateZeroLengthFile(string path, Context context)
        {
            DoRetryable<int>(
                delegate
                {
                    using (Stream placeholder = File.Create(path))
                    {
                    }
                    return 0;
                },
                delegate { return 0; },
                delegate
                {
                    try
                    {
                        File.Delete(path);
                    }
                    catch (Exception)
                    {
                    }
                },
                context);
        }

        private static void DeleteFile(string path, Context context)
        {
            DoRetryable<int>(
                delegate
                {
                    File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
                    File.Delete(path);
                    return 0;
                },
                delegate { return 0; },
                null,
                context);
        }

        private static void MoveFile(string sourcePath, string targetPath, Context context)
        {
            DoRetryable<int>(
                delegate
                {
                    DateTime created = File.GetCreationTime(sourcePath);
                    DateTime lastWritten = File.GetLastWriteTime(sourcePath);
                    File.Move(sourcePath, targetPath);
                    File.SetCreationTime(targetPath, created);
                    File.SetLastWriteTime(targetPath, lastWritten);
                    return 0;
                },
                delegate { return 0; },
                null,
                context);
        }

        private static string FormatArchivePointName(DateTime timestamp)
        {
            return timestamp.ToString("s").Replace(':', '+');
        }

        private static DateTime ParseArchivePointName(string name)
        {
            DateTime timestamp;
            if (!DateTime.TryParse(name.Replace('+', ':'), out timestamp))
            {
                throw new ApplicationException(String.Format("Invalid archive point '{0}'", name));
            }
            return timestamp;
        }

        private static readonly byte[] EncryptionCheckBytes = new byte[16] { 0xA6, 0x87, 0xDF, 0xB6, 0x75, 0x64, 0xDE, 0x14, 0x8D, 0x2C, 0x0C, 0x24, 0xA6, 0x16, 0x22, 0x2F };
        private const int EncryptionCheckSaltLength = 8;
        private static void EnsureCheck(string archiveFolder, bool firstRun, Context context, DateTime now)
        {
            bool checkExists = false;
            bool checkC = false;
            foreach (string file in Directory.GetFileSystemEntries(archiveFolder))
            {
                string name = Path.GetFileName(file);
                if (name == "check.bin")
                {
                    checkExists = true;
                }
                else if (name == "checkc.bin")
                {
                    checkExists = true;
                    checkC = true;
                }
                else if (name == "nocheckc.bin")
                {
                    checkC = true;
                }
            }

            if (!firstRun)
            {
                if (checkC != (context.compressionOption == CompressionOption.Compress))
                {
                    throw new ApplicationException("Previous backups have compression setting incompatible with current setting");
                }

                if (context.cryptoOption != EncryptionOption.None)
                {
                    CryptoContext cryptoContext;
                    if (context.cryptoOption == EncryptionOption.Encrypt)
                    {
                        cryptoContext = context.encrypt;
                    }
                    else if (context.cryptoOption == EncryptionOption.Decrypt)
                    {
                        cryptoContext = context.decrypt;
                    }
                    else
                    {
                        throw new InvalidOperationException();
                    }

                    if (!checkExists)
                    {
                        throw new ApplicationException("Previous backups prevent encryption from being allowed");
                    }
                    else
                    {
                        try
                        {
                            using (FileStream fileStream = File.Open(Path.Combine(archiveFolder, (context.compressionOption == CompressionOption.Compress) ? "checkc.bin" : "check.bin"), FileMode.Open))
                            {
                                EncryptedFileContainerHeader fch = new EncryptedFileContainerHeader(fileStream, true/*peek*/, cryptoContext);
                                CryptoKeygroup keys;
                                cryptoContext.algorithm.DeriveSessionKeys(cryptoContext.GetMasterKeyEntry(fch.passwordSalt, fch.rfc2898Rounds).MasterKey, fch.fileSalt, out keys);

                                DoWithStreamStack(
                                    fileStream,
                                    new StreamWrapMethod[]
                                    {
                                        delegate(Stream stream)
                                        {
                                            // see note and references about
                                            // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                            return new TaggedReadStream(stream, cryptoContext.algorithm.CreateMACGenerator(keys.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                        },
                                        delegate(Stream stream)
                                        {
                                            // why re-read here? need to read salt within HMAC container
                                            EncryptedFileContainerHeader fch2 = new EncryptedFileContainerHeader(stream, false/*peek*/, cryptoContext);
                                            if (!fch2.Equals(fch))
                                            {
                                                throw new InvalidOperationException();
                                            }
                                            return null;
                                        },
                                        delegate(Stream stream)
                                        {
                                            return context.encrypt.algorithm.CreateDecryptStream(stream, keys.CipherKey, keys.InitialCounter);
                                        },
                                    },
                                    delegate(Stream stream)
                                    {
                                        BinaryReadUtils.ReadBytes(stream, EncryptionCheckSaltLength); // check string's salt
                                        byte[] checkBytes = BinaryReadUtils.ReadBytes(stream, EncryptionCheckBytes.Length);

                                        if (!ArrayEqual(EncryptionCheckBytes, checkBytes))
                                        {
                                            throw new ApplicationException("Encryption key does not match key from previous run");
                                        }
                                    });
                            }
                        }
                        catch (ExitCodeException)
                        {
                            throw new ApplicationException("Encryption key does not match key from previous run");
                        }
                    }
                }
                else
                {
                    if (checkExists)
                    {
                        throw new ApplicationException("Previous backups require encryption to be specified");
                    }
                }
            }
            else
            {
                if (checkExists)
                {
                    throw new ApplicationException("Check shouldn't exist on first run!");
                }
                if (context.cryptoOption != EncryptionOption.None)
                {
                    if (context.cryptoOption != EncryptionOption.Encrypt)
                    {
                        throw new InvalidOperationException(); // firstRun can't ever be an extract/restore operation
                    }

                    CryptoMasterKeyCacheEntry entry = context.encrypt.GetDefaultMasterKeyEntry();
                    EncryptedFileContainerHeader fch = new EncryptedFileContainerHeader(context.encrypt);
                    fch.passwordSalt = entry.PasswordSalt;
                    CryptoKeygroup keys;
                    context.encrypt.algorithm.DeriveNewSessionKeys(entry.MasterKey, out fch.fileSalt, out keys);

                    string checkFilePath = Path.Combine(archiveFolder, (context.compressionOption == CompressionOption.Compress) ? "checkc.bin" : "check.bin");
                    using (FileStream fileStream = File.Open(checkFilePath, FileMode.Create))
                    {
                        DoWithStreamStack(
                            fileStream,
                            new StreamWrapMethod[]
                            {
                                delegate(Stream stream)
                                {
                                    // see note and references about
                                    // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                    return new TaggedWriteStream(stream, context.encrypt.algorithm.CreateMACGenerator(keys.SigningKey));
                                },
                                delegate(Stream stream)
                                {
                                    // why write here? need to write salt within HMAC container
                                    fch.Write(stream);
                                    return null;
                                },
                                delegate(Stream stream)
                                {
                                    return context.encrypt.algorithm.CreateEncryptStream(stream, keys.CipherKey, keys.InitialCounter);
                                },
                            },
                            delegate(Stream stream)
                            {
                                BinaryWriteUtils.WriteBytes(stream, context.encrypt.algorithm.CreateRandomBytes(EncryptionCheckSaltLength)); // yet more salt before check string
                                BinaryWriteUtils.WriteBytes(stream, EncryptionCheckBytes);
                            });
                    }
                    File.SetCreationTime(checkFilePath, now);
                    File.SetLastWriteTime(checkFilePath, now);
                }
                else
                {
                    if (context.compressionOption == CompressionOption.Compress)
                    {
                        string checkFilePath = Path.Combine(archiveFolder, "nocheckc.bin");
                        using (FileStream file = File.Open(checkFilePath, FileMode.Create))
                        {
                        }
                        File.SetCreationTime(checkFilePath, now);
                        File.SetLastWriteTime(checkFilePath, now);
                    }
                }
            }
        }

#if false // EXPERIMENTAL: iterative implementation of Backup()
        private class EnumerateHierarchyN
        {
            private IEnumerateHierarchy[] ehs;
            private int[] earliestSet;
            private bool[] finished;

            internal EnumerateHierarchyN(string[] roots)
            {
                ehs = new EnumerateHierarchy[roots.Length];
                earliestSet = new int[roots.Length];
                finished = new bool[roots.Length];
                for (int i = 0; i < roots.Length; i++)
                {
                    ehs[i] = new EnumerateHierarchy(roots[i]);
                    earliestSet[i] = i;
                }
            }

            private static int[] SelectEarliest(IEnumerateHierarchy[] ehs)
            {
                int[] earliestSet = new int[0];
                int first = -1;
                for (int i = 0; i < ehs.Length; i++)
                {
                    if (ehs[i].Valid)
                    {
                        if (first == -1)
                        {
                            first = i;
                            Array.Resize(ref earliestSet, earliestSet.Length + 1);
                            earliestSet[earliestSet.Length - 1] = i;
                        }
                        else
                        {
                            string[] firstParts = ehs[first].Current.Split(new char[] { '\\' });
                            string[] iParts = ehs[i].Current.Split(new char[] { '\\' });

                            // compare algorithm:
                            // root dir of given name comes first, then contained items inside that dir, and last a file of that name
                            int c = 0;
                            int commonPrefix = Math.Min(firstParts.Length, iParts.Length);
                            for (int j = 0; j < commonPrefix; j++)
                            {
                                c = String.Compare(firstParts[j], iParts[j], StringComparison.OrdinalIgnoreCase);
                                if (c != 0)
                                {
                                    break;
                                }
                            }
                            if (c == 0)
                            {
                                c = firstParts.Length - iParts.Length;
                            }

                            if (c == 0)
                            {
                                Array.Resize(ref earliestSet, earliestSet.Length + 1);
                                earliestSet[earliestSet.Length - 1] = i;
                            }
                            else if (c > 0)
                            {
                                first = i;
                                earliestSet = new int[1];
                                earliestSet[0] = i;
                            }
                        }
                    }
                }
                return earliestSet;
            }

            public int[] EarliestSet()
            {
                return (int[])earliestSet.Clone();
            }

            public bool Valid
            {
                get
                {
                    return earliestSet.Length > 0;
                }
            }

            public bool MoveNext()
            {
                if (earliestSet.Length == 0)
                {
                    throw new InvalidOperationException();
                }

                bool result = false;
                foreach (int i in earliestSet)
                {
                    bool result1 = !finished[i] && ehs[i].MoveNext();
                    finished[i] = !result1;
                    result = result || result1;
                }
                earliestSet = SelectEarliest(ehs);
                return result;
            }

            public string Current
            {
                get
                {
                    if (earliestSet.Length == 0)
                    {
                        throw new InvalidOperationException();
                    }

                    return ehs[earliestSet[0]].Current;
                }
            }

            public string GetCurrent(int index)
            {
                if (Array.IndexOf(earliestSet, index) < 0)
                {
                    throw new InvalidOperationException();
                }
                return ehs[index].Current;
            }

            public void Close()
            {
                ehs = null;
                earliestSet = null;
                finished = null;
            }
        }

        private static void BackupProcess(string source, string previous, string current, Context context, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems, TextWriter log)
        {
            string lastStatus = String.Empty;

            const int SourceIndex = 0, CurrentIndex = 1, PreviousIndex = 2;
            EnumerateHierarchyN eh = new EnumerateHierarchyN(new string[] { source, current, previous });
            string deepRollbackRoot = null;
            bool deferredCopy = false;
            while (deferredCopy || (eh.Valid && eh.MoveNext() ? true : (deepRollbackRoot != null))) // awkward logic around eh.MoveNext() and deepRollbackRoot is because eh.MoveNext() terminates one step too early when the last item was a directory undergoing deep rollback - one more cycle needed to finialize rollback and apply any deferred copy
            {
                deferredCopy = false;

                string sourcePath = null, currentPath = null, previousPath = null;
                int[] earliestSet = null;

                if (eh.Valid)
                {
                    earliestSet = eh.EarliestSet();
                    sourcePath = Path.Combine(source, Array.IndexOf(earliestSet, SourceIndex) >= 0 ? eh.GetCurrent(SourceIndex) : eh.Current);
                    currentPath = Path.Combine(current, Array.IndexOf(earliestSet, CurrentIndex) >= 0 ? eh.GetCurrent(CurrentIndex) : eh.Current);
                    previousPath = Path.Combine(previous, Array.IndexOf(earliestSet, PreviousIndex) >= 0 ? eh.GetCurrent(PreviousIndex) : eh.Current);

                    if (Directory.Exists(sourcePath) && (lastStatus != eh.Current))
                    {
                        lastStatus = eh.Current;
                        WriteStatusLine(lastStatus);
                    }
                }

                if ((deepRollbackRoot != null) && (!eh.Valid || !eh.Current.StartsWith(deepRollbackRoot, StringComparison.OrdinalIgnoreCase)))
                {
                    sourcePath = Path.Combine(source, deepRollbackRoot);
                    currentPath = Path.Combine(current, deepRollbackRoot);
                    previousPath = Path.Combine(previous, deepRollbackRoot);
                    deepRollbackRoot = null;
                    deferredCopy = true;

                    Directory.Delete(currentPath, true/*recursive*/); // will fail if read-only attributes in archive becomes supported
                }

                // roll back anything found already in checkpoint
                if (!deferredCopy)
                {
                    if (deepRollbackRoot == null)
                    {
                        if (Directory.Exists(currentPath) && File.Exists(sourcePath))
                        {
                            deepRollbackRoot = eh.Current;
                        }
                    }

                    if (File.Exists(previousPath))
                    {
                        if (GetFileLengthRetriable(previousPath, context) == 0)
                        {
                            // previous item was carried to current during prior incompleted pass - move it back.
                            if (File.Exists(currentPath))
                            {
                                DeleteFile(previousPath, context);
                                MoveFile(currentPath, previousPath, context);
                            }
                        }
                    }
                    if (File.Exists(currentPath))
                    {
                        DeleteFile(currentPath, context);
                    }
                }

                // create checkpoint of source
                if (deepRollbackRoot == null)
                {
                    bool excluded = false;
                    {
                        bool driveRoot = Directory.Exists(sourcePath) && IsDriveRoot(sourcePath);
                        if (driveRoot && IsExcludedDriveRootItem(sourcePath))
                        {
                            excluded = true;
                        }
                        else
                        {
                            if (excludedItems.Count > 0)
                            {
                                string[] parts = sourcePath.ToLowerInvariant().Split(new char[] { '\\' });
                                StringBuilder sb = new StringBuilder(sourcePath.Length);
                                for (int i = parts.Length - 1; i >= 0; i--)
                                {
                                    sb.Length = 0;
                                    for (int j = 0; j <= i; j++)
                                    {
                                        if (j > 0)
                                        {
                                            sb.Append('\\');
                                        }
                                        sb.Append(parts[j]);
                                    }
                                    if (excludedItems.Contains(sb.ToString()))
                                    {
                                        excluded = true;
                                        EraseStatusLine();
                                        Console.WriteLine(String.Format("  SKIPPED SUBDIRECTORY: {0}", sourcePath));
                                    }
                                }
                            }

                            if (!excluded && File.Exists(sourcePath) && excludedExtensions.Contains(Path.GetExtension(sourcePath).ToLowerInvariant()))
                            {
                                excluded = true;
                                EraseStatusLine();
                                Console.WriteLine(String.Format("  SKIPPED FILE: {0}", sourcePath));
                            }
                        }
                    }

                    if (!excluded)
                    {
                        // filename case handling: make current take on case of source
                        // (but enumerator no longer valid if deferredCopy is set - decided to be acceptable to miss any filename case change in this case)
                        if (!deferredCopy && (File.Exists(sourcePath) || Directory.Exists(sourcePath)))
                        {
                            currentPath = Path.Combine(current, Array.IndexOf(earliestSet, SourceIndex) >= 0 ? eh.GetCurrent(SourceIndex) : eh.Current);
                        }

                        if (Directory.Exists(sourcePath))
                        {
                            Directory.CreateDirectory(currentPath);
                            if (log != null)
                            {
                                log.WriteLine("added {0}\\", sourcePath);
                            }
                        }
                        else if (File.Exists(sourcePath))
                        {
                            if (File.Exists(previousPath))
                            {
                                bool unchanged = true;

                                DateTime sourceItemCreationTime = DoRetryable<DateTime>(delegate { return File.GetCreationTime(sourcePath); }, delegate { return DateTime.MaxValue; }, null, context);
                                DateTime previousItemCreationTime = DoRetryable<DateTime>(delegate { return File.GetCreationTime(previousPath); }, delegate { return DateTime.MinValue; }, null, context);
                                unchanged = unchanged && (sourceItemCreationTime == previousItemCreationTime);
                                DateTime sourceItemLastWriteTime = DoRetryable<DateTime>(delegate { return File.GetLastWriteTime(sourcePath); }, delegate { return DateTime.MaxValue; }, null, context);
                                DateTime previousItemLastWriteTime = DoRetryable<DateTime>(delegate { return File.GetLastWriteTime(previousPath); }, delegate { return DateTime.MinValue; }, null, context);
                                unchanged = unchanged && (sourceItemLastWriteTime == previousItemLastWriteTime);

                                if (unchanged)
                                {
                                    MoveFile(previousPath, currentPath, context);
                                    CreateZeroLengthFile(previousPath, context);

                                    try
                                    {
                                        File.SetCreationTime(previousPath, File.GetCreationTime(currentPath));
                                        File.SetLastWriteTime(previousPath, File.GetLastWriteTime(currentPath));
                                    }
                                    catch (Exception)
                                    {
                                    }
                                }
                                else
                                {
                                    if (log != null)
                                    {
                                        log.WriteLine("modified {0}", sourcePath);
                                    }
                                    CopyFile(sourcePath, currentPath, context);
                                }
                            }
                            else
                            {
                                if (log != null)
                                {
                                    log.WriteLine("added {0}", sourcePath);
                                }
                                CopyFile(sourcePath, currentPath, context);
                            }
                        }
                        else
                        {
                            bool wasDir = false;
                            if (File.Exists(previousPath) || (wasDir = Directory.Exists(previousPath)))
                            {
                                if (log != null)
                                {
                                    log.WriteLine("removed {1}{0}", previousPath, wasDir ? "/s " : String.Empty);
                                }
                            }
                        }
                    }
                }

                deferredCopy = deferredCopy && eh.Valid; // no deferred next pass needed if at end
            }

            EraseStatusLine();
        }
#else // TESTED: recursive implementation of Backup()
        private class TriEntry
        {
            internal string source;
            internal string current;
            internal string previous;
        }

        delegate int MergeCompare<T>(T left, T right);
        private static T[] MergeSorted<T>(IList<T> a, IList<T> b, MergeCompare<T> compare)
        {
            T[] c = new T[a.Count + b.Count];
            int ia = 0;
            int ib = 0;
            int ic = 0;
            while ((ia < a.Count) || (ib < b.Count))
            {
                if ((ia < a.Count) && (ib < b.Count))
                {
                    if (compare(a[ia], b[ib]) <= 0)
                    {
                        c[ic++] = a[ia++];
                    }
                    else
                    {
                        c[ic++] = b[ib++];
                    }
                }
                else if (ia < a.Count)
                {
                    c[ic++] = a[ia++];
                }
                else if (ib < b.Count)
                {
                    c[ic++] = b[ib++];
                }
                else
                {
                    throw new InvalidDataException();
                }
            }
            return c;
        }

        private static int CompareEntries(KeyValuePair<string, int> l, KeyValuePair<string, int> r)
        {
            int c = String.Compare(l.Key, r.Key, StringComparison.OrdinalIgnoreCase);
            if (c == 0)
            {
                c = l.Value.CompareTo(r.Value);
            }
            return c;
        }

        internal static void BackupRecursive(string source, string previous, string current, Context context, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems, TextWriter log, bool deepRollback)
        {
            Debug.Assert(Directory.Exists(source) == !deepRollback);

            WriteStatusLine(source);

            bool driveRoot = IsDriveRoot(source);

            List<TriEntry> combined = new List<TriEntry>();
            {
                const int SourceIndex = 0, CurrentIndex = 1, PreviousIndex = 2;

                List<KeyValuePair<string, int>> aggregateCurrent = new List<KeyValuePair<string, int>>();
                if (Directory.Exists(current))
                {
                    foreach (string currentPath in Directory.GetFileSystemEntries(current))
                    {
                        aggregateCurrent.Add(new KeyValuePair<string, int>(Path.GetFileName(currentPath), CurrentIndex));
                    }
                }
                List<KeyValuePair<string, int>> aggregatePrevious = new List<KeyValuePair<string, int>>();
                if (Directory.Exists(previous))
                {
                    foreach (string previousPath in Directory.GetFileSystemEntries(previous))
                    {
                        aggregatePrevious.Add(new KeyValuePair<string, int>(Path.GetFileName(previousPath), PreviousIndex));
                    }
                }
                List<KeyValuePair<string, int>> aggregateSource = new List<KeyValuePair<string, int>>();
                if (!deepRollback && Directory.Exists(source))
                {
                    foreach (string sourcePath in Directory.GetFileSystemEntries(source))
                    {
                        bool excluded = false;
                        {
                            if (driveRoot && IsExcludedDriveRootItem(sourcePath))
                            {
                                excluded = true;
                            }
                            else
                            {
                                if (excludedItems.Count > 0)
                                {
                                    if (excludedItems.Contains(sourcePath.ToLowerInvariant()))
                                    {
                                        excluded = true;
                                        EraseStatusLine();
                                        Console.WriteLine("  SKIPPED {1}: {0}", sourcePath, Directory.Exists(sourcePath) ? "SUBDIRECTORY" : "FILE");
                                    }
                                }

                                if (!excluded && !Directory.Exists(sourcePath) && excludedExtensions.Contains(Path.GetExtension(sourcePath).ToLowerInvariant()))
                                {
                                    excluded = true;
                                    EraseStatusLine();
                                    Console.WriteLine("  SKIPPED FILE: {0}", sourcePath);
                                }
                            }
                        }

                        if (!excluded)
                        {
                            aggregateSource.Add(new KeyValuePair<string, int>(Path.GetFileName(sourcePath), SourceIndex));
                        }
                    }
                }

                KeyValuePair<string, int>[] aggregate;
                aggregate = MergeSorted(aggregateSource, aggregateCurrent, CompareEntries);
                aggregate = MergeSorted(aggregatePrevious, aggregate, CompareEntries);

                int index = -1;
                string last = null;
                foreach (KeyValuePair<string, int> entry in aggregate)
                {
                    if (!String.Equals(entry.Key, last, StringComparison.OrdinalIgnoreCase))
                    {
                        last = entry.Key;
                        index++;
                        combined.Add(new TriEntry());
                    }
                    switch (entry.Value)
                    {
                        default:
                            throw new InvalidDataException();
                        case SourceIndex:
                            combined[index].source = entry.Key;
                            break;
                        case CurrentIndex:
                            combined[index].current = entry.Key;
                            break;
                        case PreviousIndex:
                            combined[index].previous = entry.Key;
                            break;
                    }
                }
            }

            foreach (TriEntry entry in combined)
            {
                string sourcePath, currentPath, previousPath;
                {
                    string canonical = (entry.source != null) ? entry.source : (entry.current != null) ? entry.current : entry.previous;
                    Debug.Assert(canonical != null);
                    sourcePath = Path.Combine(source, entry.source != null ? entry.source : canonical);
                    currentPath = Path.Combine(current, entry.current != null ? entry.current : canonical);
                    previousPath = Path.Combine(previous, entry.previous != null ? entry.previous : canonical);
                }

                // roll back anything found already in checkpoint
                if (File.Exists(previousPath) && (GetFileLengthRetriable(previousPath, context) == 0))
                {
                    if (File.Exists(currentPath))
                    {
                        // previous item was carried to current during prior incompleted pass - move it back.
                        DeleteFile(previousPath, context);
                        MoveFile(currentPath, previousPath, context);
                    }
                    // else item is missing in current and really was zero length
                }
                else if (File.Exists(currentPath))
                {
                    // item added/modified during prior incompleted pass - remove
                    DeleteFile(currentPath, context);
                }
                else if (Directory.Exists(currentPath))
                {
                    // directory may have existed during prior incompleted pass but gone now - push back all forwarded contained items and then remove
                    if (!Directory.Exists(sourcePath))
                    {
                        // deep rollback
                        BackupRecursive(
                            Path.Combine(source, entry.current),
                            Path.Combine(previous, entry.current),
                            Path.Combine(current, entry.current),
                            context,
                            excludedExtensions,
                            excludedItems,
                            log,
                            true/*deepRollback*/);

                        Directory.Delete(currentPath, true/*recursive*/);
                    }
                }

                // create checkpoint of source
                if (!deepRollback)
                {
                    // filename case handling: make current take on case of source
                    try
                    {
                        currentPath = Path.Combine(Path.GetDirectoryName(currentPath), Path.GetFileName(sourcePath));
                    }
                    catch (PathTooLongException)
                    {
                        // if path too long, don't change case and allow subsequent code to fail on copy attempts
                    }

                    if (Directory.Exists(sourcePath) && (entry.source != null/*not excluded*/))
                    {
                        if (log != null)
                        {
                            if (!Directory.Exists(previousPath))
                            {
                                log.WriteLine("added {0}\\", sourcePath);
                            }
                        }

                        if (DoRetryable<bool>(
                            delegate()
                            {
                                try
                                {
                                    Directory.CreateDirectory(currentPath);
                                    return true;
                                }
                                catch (PathTooLongException exception)
                                {
                                    throw new PathTooLongException(String.Format("{0} (length={2}, path=\'{1}\')", exception.Message, currentPath, currentPath.Length));
                                }
                            },
                            delegate() { return false; },
                            delegate() { },
                            context))
                        {
                            BackupRecursive(
                                Path.Combine(source, entry.source),
                                Path.Combine(previous, entry.source),
                                Path.Combine(current, entry.source),
                                context,
                                excludedExtensions,
                                excludedItems,
                                log,
                                false/*deepRollback*/);
                        }
                    }
                    else if (File.Exists(sourcePath) && (entry.source != null/*not excluded*/))
                    {
                        if (File.Exists(previousPath))
                        {
                            bool unchanged = true;

                            DateTime sourceItemCreationTime = DoRetryable<DateTime>(delegate { return File.GetCreationTime(sourcePath); }, delegate { return DateTime.MaxValue; }, null, context);
                            DateTime previousItemCreationTime = DoRetryable<DateTime>(delegate { return File.GetCreationTime(previousPath); }, delegate { return DateTime.MinValue; }, null, context);
                            unchanged = unchanged && (sourceItemCreationTime == previousItemCreationTime);
                            DateTime sourceItemLastWriteTime = DoRetryable<DateTime>(delegate { return File.GetLastWriteTime(sourcePath); }, delegate { return DateTime.MaxValue; }, null, context);
                            DateTime previousItemLastWriteTime = DoRetryable<DateTime>(delegate { return File.GetLastWriteTime(previousPath); }, delegate { return DateTime.MinValue; }, null, context);
                            unchanged = unchanged && (sourceItemLastWriteTime == previousItemLastWriteTime);

                            if (unchanged)
                            {
                                MoveFile(previousPath, currentPath, context);
                                CreateZeroLengthFile(previousPath, context);

                                try
                                {
                                    File.SetCreationTime(previousPath, File.GetCreationTime(currentPath));
                                    File.SetLastWriteTime(previousPath, File.GetLastWriteTime(currentPath));
                                }
                                catch (Exception)
                                {
                                }
                            }
                            else
                            {
                                if (log != null)
                                {
                                    log.WriteLine("modified {0}", sourcePath);
                                }
                                CopyFile(sourcePath, currentPath, context);
                            }
                        }
                        else
                        {
                            if (log != null)
                            {
                                log.WriteLine("added {0}", sourcePath);
                            }
                            CopyFile(sourcePath, currentPath, context);
                        }
                    }
                    else
                    {
                        bool wasDir = false;
                        if (File.Exists(previousPath) || (wasDir = Directory.Exists(previousPath)))
                        {
                            if (log != null)
                            {
                                log.WriteLine("removed {1}{0}{2}", sourcePath, wasDir ? "/s " : String.Empty, wasDir ? "\\" : String.Empty);
                            }
                        }
                    }
                }
            }
        }

        private static void BackupProcess(string source, string previous, string current, Context context, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems, TextWriter log)
        {
            BackupRecursive(source, previous, current, context, excludedExtensions, excludedItems, log, false/*deepRollback*/);
        }
#endif

        internal static void Backup(string source, string archiveFolder, Context context, string[] args)
        {
            if (!Directory.Exists(source))
            {
                Console.WriteLine("source directory \"{0}\" does not exist", source);
                throw new UsageException();
            }

            bool finish;
            GetAdHocArgument(ref args, "-nofinish", true/*default*/, false/*explicit*/, out finish);

            InvariantStringSet excludedExtensions;
            InvariantStringSet excludedItems;
            GetExclusionArguments(args, out excludedExtensions, false/*relative*/, out excludedItems);


            string workingArchivePoint = FormatArchivePointName(DateTime.MaxValue);
            string currentArchivePoint = FormatArchivePointName(context.now);

            SortedList<string, bool> archivePoints = new SortedList<string, bool>();
            foreach (string file in Directory.GetFileSystemEntries(archiveFolder))
            {
                string name = Path.GetFileName(file);
                if (!((name == "check.bin") || (name == "checkc.bin") || (name == "nocheckc.bin")))
                {
                    archivePoints.Add(name, false);
                }
            }
            DateTime mostRecentArchivePointDate = DateTime.MinValue;
            string mostRecentArchivePoint = null;
            foreach (string archivePoint in archivePoints.Keys)
            {
                if (!archivePoint.Equals(workingArchivePoint))
                {
                    DateTime date = ParseArchivePointName(archivePoint);
                    if (mostRecentArchivePointDate < date)
                    {
                        mostRecentArchivePointDate = date;
                        mostRecentArchivePoint = archivePoint;
                    }
                }
            }
            if ((mostRecentArchivePoint != null) && (mostRecentArchivePointDate.CompareTo(context.now) >= 0))
            {
                throw new ApplicationException(String.Format("Archive point '{0}' is more recent than now {0}", mostRecentArchivePoint, currentArchivePoint));
            }

            if (File.Exists(Path.Combine(archiveFolder, currentArchivePoint)))
            {
                throw new ApplicationException(String.Format("Archive point '{0}' already exists", context.now));
            }

            EnsureCheck(archiveFolder, mostRecentArchivePoint == null, context, context.now);

            Directory.CreateDirectory(Path.Combine(archiveFolder, workingArchivePoint));


            TextWriter log = null;
            if (context.logPath != null)
            {
                log = new StreamWriter(context.logPath, false/*append*/, Encoding.UTF8);
                log.WriteLine("Backup of {0} to {1}", source, Path.Combine(archiveFolder, currentArchivePoint));
                log.WriteLine();
            }


            bool fakeMostRecentArchivePoint = (mostRecentArchivePoint == null);
            if (fakeMostRecentArchivePoint)
            {
                mostRecentArchivePoint = FormatArchivePointName(DateTime.MinValue);
                string mostRecentArchivePointPath = Path.Combine(archiveFolder, mostRecentArchivePoint);
                Directory.CreateDirectory(mostRecentArchivePointPath);
                if (Directory.GetDirectories(mostRecentArchivePointPath).Length > 0)
                {
                    throw new ApplicationException(String.Format("Temporary archive workspace \"{0}\" is nonempty!", mostRecentArchivePointPath));
                }
            }

            BackupProcess(
                source,
                Path.Combine(archiveFolder, mostRecentArchivePoint),
                Path.Combine(archiveFolder, workingArchivePoint),
                context,
                excludedExtensions,
                excludedItems,
                log);

            if (fakeMostRecentArchivePoint)
            {
                Directory.Delete(Path.Combine(archiveFolder, mostRecentArchivePoint));
            }

            if (finish)
            {
                Directory.Move(Path.Combine(archiveFolder, workingArchivePoint), Path.Combine(archiveFolder, currentArchivePoint));
            }


            if (log != null)
            {
                log.WriteLine();
                log.WriteLine("Finished.");
                log.Close();
                log = null;
            }

            EraseStatusLine();
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Verify
        //
        ////////////////////////////////////////////////////////////////////////////

        private static void VerifyRecursive(string sourceRootDirectory, string targetRootDirectory, Context context, OneWaySwitch different)
        {
            WriteStatusLine(sourceRootDirectory);

            SortedList<string, bool> allFiles = new SortedList<string, bool>();

            try
            {
                bool header = false;

                foreach (string file in Directory.GetFileSystemEntries(sourceRootDirectory))
                {
                    string message = null;
                    string fileName = Path.GetFileName(file);
                    bool isDirectory = ((File.GetAttributes(file) & FileAttributes.Directory) != 0);
                    allFiles.Add(fileName, isDirectory);
                    string targetFile = Path.Combine(targetRootDirectory, fileName);
                    if (!isDirectory)
                    {
                        if (!File.Exists(targetFile))
                        {
                            message = String.Format("Missing file: {0}", fileName);
                        }
                        else if (!CompareFile(file, targetFile, context))
                        {
                            message = String.Format("Different: {0}", fileName);
                        }
                    }
                    else
                    {
                        if (!Directory.Exists(targetFile))
                        {
                            message = String.Format("Missing directory: {0}", fileName);
                        }
                    }
                    if (message != null)
                    {
                        EraseStatusLine();
                        different.Set();
                        if (!header)
                        {
                            header = true;
                            Console.WriteLine(targetRootDirectory);
                        }
                        ConsoleWriteLineColor(ConsoleColor.Red, "  " + message);
                    }
                }

                foreach (string file in Directory.GetFileSystemEntries(targetRootDirectory))
                {
                    string message = null;
                    string fileName = Path.GetFileName(file);
                    bool isDirectory = ((File.GetAttributes(file) & FileAttributes.Directory) != 0);
                    if (!allFiles.ContainsKey(fileName) || (allFiles[fileName] != isDirectory))
                    {
                        if (isDirectory)
                        {
                            message = String.Format("Added directory: {0}", fileName);
                        }
                        else
                        {
                            message = String.Format("Added file: {0}", fileName);
                        }
                    }
                    if (message != null)
                    {
                        EraseStatusLine();
                        different.Set();
                        if (!header)
                        {
                            header = true;
                            Console.WriteLine(targetRootDirectory);
                        }
                        ConsoleWriteLineColor(ConsoleColor.Red, "  " + message);
                    }
                }
            }
            catch (Exception exception)
            {
                different.Set();
                ConsoleWriteLineColor(ConsoleColor.Red, "Exception processing directory '{0}': {1}", sourceRootDirectory, exception.Message);
            }

            foreach (KeyValuePair<string, bool> item in allFiles)
            {
                if (item.Value && Directory.Exists(Path.Combine(targetRootDirectory, item.Key)))
                {
                    CompareRecursive(Path.Combine(sourceRootDirectory, item.Key), Path.Combine(targetRootDirectory, item.Key), context, different, true/*red*/);
                }
            }
        }

        internal static void Verify(string source, string archiveFolder, Context context)
        {
            OneWaySwitch different = new OneWaySwitch();

            DateTime mostRecentArchivePointDate = DateTime.MinValue;
            string mostRecentArchivePoint = null;
            foreach (string file in Directory.GetFileSystemEntries(archiveFolder))
            {
                string name = Path.GetFileName(file);
                if (!((name == "check.bin") || (name == "checkc.bin") || (name == "nocheckc.bin")))
                {
                    DateTime date = ParseArchivePointName(name);
                    if (mostRecentArchivePointDate < date)
                    {
                        mostRecentArchivePointDate = date;
                        mostRecentArchivePoint = name;
                    }
                }
            }
            if (mostRecentArchivePoint == null)
            {
                throw new ApplicationException("No archive points found");
            }

            EnsureCheck(archiveFolder, false, context, context.now);

            VerifyRecursive(
                source,
                Path.Combine(archiveFolder, mostRecentArchivePoint),
                context,
                different);

            EraseStatusLine();

            if (different.Value)
            {
                throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied);
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Purge
        //
        ////////////////////////////////////////////////////////////////////////////

        private static void PurgeRecursive(string earlySaveRootDirectory, string latePurgeRootDirectory, Context context, out int movedFiles, out int discardedFiles, out int discardedRoots)
        {
            movedFiles = 0;
            discardedFiles = 0;
            discardedRoots = 0;

            // walk only items in early save directory. any items in late that are not in
            // early were created newly with late and therefore are not propagated back.
            foreach (string earlySaveFile in Directory.GetFiles(earlySaveRootDirectory))
            {
                string earlySaveFileName = Path.GetFileName(earlySaveFile);
                string latePurgeFile = Path.Combine(latePurgeRootDirectory, earlySaveFileName);

                long earlySaveLength = DoRetryable<long>(
                    delegate
                    {
                        using (Stream earlySaveStream = new FileStream(earlySaveFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        {
                            return earlySaveStream.Length;
                        }
                    },
                    delegate { return -1; },
                    null,
                    context);
                long latePurgeLength = DoRetryable<long>(
                    delegate
                    {
                        if (!File.Exists(latePurgeFile))
                        {
                            // missing (deleted) in late is equivalent to no change to propagate back
                            return 0;
                        }
                        using (Stream latePurgeStream = new FileStream(latePurgeFile, FileMode.Open, FileAccess.Read))
                        {
                            return latePurgeStream.Length;
                        }
                    },
                    delegate { return -1; },
                    null,
                    context);

                if (earlySaveLength != 0)
                {
                    // early is real: keep unchanged (was either change-terminal, placeholder, or removed in late)

                    if (latePurgeLength != 0)
                    {
                        discardedFiles++;
                    }
                }
                else
                {
                    // early is placeholder

                    if (latePurgeLength == 0)
                    {
                        // early is placeholder, late is placeholder: keep unchanged
                        // (real file is post-late and placeholder relationship in early remains)
                    }
                    else
                    {
                        // late is real, early is placeholder: propagate late back to early

                        movedFiles++;

                        Console.WriteLine("  {0}", earlySaveFile);

                        DoRetryable<int>(
                            delegate
                            {
                                File.Delete(earlySaveFile);
                                return 0;
                            },
                            delegate { return 0; },
                            null,
                            context);
                        DoRetryable<int>(
                            delegate
                            {
                                File.Move(latePurgeFile, earlySaveFile);
                                return 0;
                            },
                            delegate { return 0; },
                            null,
                            context);
                    }
                }
            }

            // note: if a directory existed in checkpoint 1, then was removed in checkpoint 2,
            // and a new one created of same name in checkpoint 3, when checkpoint 2 is purged
            // that information is lost. if checkpoint 3 is subsequently purged, any zero-length
            // items in checkpoint 1 will erroneously receive propagation from checkpoint 3.

            foreach (string earlySaveSubdirectory in Directory.GetDirectories(earlySaveRootDirectory))
            {
                string earlySaveSubdirectoryName = Path.GetFileName(earlySaveSubdirectory);
                string latePurgeSubdirectory = Path.Combine(latePurgeRootDirectory, earlySaveSubdirectoryName);

                if (Directory.Exists(latePurgeSubdirectory))
                {
                    // propagate all late subdirectory items and remove late subdirectory
                    int movedFilesInner, discardedFilesInner, discardedRootsInner;
                    PurgeRecursive(earlySaveSubdirectory, latePurgeSubdirectory, context, out movedFilesInner, out discardedFilesInner, out discardedRootsInner);
                    movedFiles += movedFilesInner;
                    discardedFiles += discardedFilesInner;
                    discardedRoots += discardedRootsInner;
                }
                else
                {
                    // missing in late means removed in late: no change needed (keep early)
                }
            }

            foreach (string latePurgeSubdirectory in Directory.GetDirectories(latePurgeRootDirectory))
            {
                string latePurgeSubdirectoryName = Path.GetFileName(latePurgeSubdirectory);
                string earlySaveSubdirectory = Path.Combine(earlySaveRootDirectory, latePurgeSubdirectoryName);

                if (!Directory.Exists(earlySaveSubdirectory))
                {
                    discardedRoots++;
                }
            }

            // propagation finished: remove late root
            Directory.Delete(latePurgeRootDirectory, true/*recursive*/);
        }

        internal static void Purge(string archiveRoot, string beginCheckpoint, string endCheckpoint, Context context)
        {
            if (!Directory.Exists(Path.Combine(archiveRoot, beginCheckpoint)))
            {
                throw new ApplicationException(String.Format("Archive point {0} does not exist", beginCheckpoint));
            }
            if (!Directory.Exists(Path.Combine(archiveRoot, endCheckpoint)))
            {
                throw new ApplicationException(String.Format("Archive point {0} does not exist", endCheckpoint));
            }
            DateTime beginDate;
            if (!DateTime.TryParse(beginCheckpoint.Replace('+', ':'), out beginDate))
            {
                throw new ApplicationException(String.Format("Invalid archive point '{0}'", beginCheckpoint));
            }
            DateTime endDate;
            if (!DateTime.TryParse(endCheckpoint.Replace('+', ':'), out endDate))
            {
                throw new ApplicationException(String.Format("Invalid archive point '{0}'", endCheckpoint));
            }
            if (endDate < beginDate)
            {
                throw new ApplicationException("End checkpoint is earlier then begin checkpoint");
            }

            List<string> toPurge = new List<string>();
            foreach (string file in Directory.GetFileSystemEntries(archiveRoot))
            {
                string name = Path.GetFileName(file);
                if (!((name == "check.bin") || (name == "checkc.bin") || (name == "nocheckc.bin")))
                {
                    DateTime date;
                    if (!DateTime.TryParse(name.Replace('+', ':'), out date))
                    {
                        throw new ApplicationException(String.Format("Invalid archive point '{0}' found in archive folder", name));
                    }
                    if ((date > beginDate) && (date < endDate))
                    {
                        Debug.Assert((toPurge.Count == 0) || (String.Compare(toPurge[toPurge.Count - 1], name, StringComparison.OrdinalIgnoreCase) < 0));
                        toPurge.Add(name);
                    }
                }
            }
            toPurge.Sort();

            foreach (string name in toPurge)
            {
                bool quit = false;
                while (Console.KeyAvailable)
                {
                    if (Char.ToLower(Console.ReadKey().KeyChar) == 'q')
                    {
                        quit = true;
                    }
                }
                if (quit)
                {
                    break;
                }

                ConsoleWriteLineColor(ConsoleColor.Yellow, "Purging {0}", name);
                int movedFiles, discardedFiles, discardedRoots;
                PurgeRecursive(
                    Path.Combine(archiveRoot, beginCheckpoint),
                    Path.Combine(archiveRoot, name),
                    context,
                    out movedFiles,
                    out discardedFiles,
                    out discardedRoots);
                Console.WriteLine("moved files {0}, discarded files {1}, discarded roots {2}", movedFiles, discardedFiles, discardedRoots);
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Prune
        //
        ////////////////////////////////////////////////////////////////////////////

        private const int PreserveFull = 2; // in months
        private const int PreserveMonthly = 3; // in months
        private const int PreserveQuarterly = 6; // in months
        internal static void Prune(string archiveRoot, Context context)
        {
            List<string> checkpoints = new List<string>();
            foreach (string file in Directory.GetFileSystemEntries(archiveRoot))
            {
                string name = Path.GetFileName(file);
                if (!((name == "check.bin") || (name == "checkc.bin") || (name == "nocheckc.bin")))
                {
                    DateTime date;
                    if (!DateTime.TryParse(name.Replace('+', ':'), out date))
                    {
                        throw new ApplicationException(String.Format("Invalid archive point '{0}' found in archive folder", name));
                    }
                    checkpoints.Add(name);
                }
            }
            checkpoints.Sort();

            Console.WriteLine("All checkpoints:");
            foreach (string checkpoint in checkpoints)
            {
                Console.WriteLine("  {0}", checkpoint);
            }
            Console.WriteLine();

            SortedList<string, string> purgeSeries = new SortedList<string, string>();
            int i = checkpoints.Count;
            int j, l;
            DateTime stop;
            // no change
            stop = (new DateTime(context.now.Year, context.now.Month, 1)).AddMonths(-PreserveFull);
            while ((i > 0) && (DateTime.Parse(checkpoints[i - 1].Replace('+', ':')) >= stop))
            {
                i--;
            }
            // preserve once a month
            stop = stop.AddMonths(-PreserveMonthly);
            stop = stop.AddMonths(-((stop.Month - 1) % 3)); // round up to previous end of quarter
            j = i;
            while ((i > 0) && (DateTime.Parse(checkpoints[i - 1].Replace('+', ':')) >= stop))
            {
                i--;
            }
            l = i;
            for (int k = i; k <= Math.Min(j, checkpoints.Count - 1); k++)
            {
                if (DateTime.Parse(checkpoints[l].Replace('+', ':')).Month != DateTime.Parse(checkpoints[k].Replace('+', ':')).Month)
                {
                    if (l + 1 < k)
                    {
                        purgeSeries.Add(checkpoints[l], checkpoints[k]);
                    }
                    l = k;
                }
            }
            // preserve once a quarter
            stop = stop.AddMonths(-PreserveQuarterly);
            stop = stop.AddMonths(-((stop.Month - 1) % 12)); // round up to previous end of year
            j = i;
            while ((i > 0) && (DateTime.Parse(checkpoints[i - 1].Replace('+', ':')) >= stop))
            {
                i--;
            }
            l = i;
            for (int k = i; k <= Math.Min(j, checkpoints.Count - 1); k++)
            {
                DateTime lDate = DateTime.Parse(checkpoints[l].Replace('+', ':'));
                DateTime kDate = DateTime.Parse(checkpoints[k].Replace('+', ':'));
                if ((lDate.Year * 12 + lDate.Month - 1) / 3 != (kDate.Year * 12 + kDate.Month - 1) / 3)
                {
                    if (l + 1 < k)
                    {
                        purgeSeries.Add(checkpoints[l], checkpoints[k]);
                    }
                    l = k;
                }
            }
            // remainder -- preserve once a year
            j = i;
            i = 0;
            l = i;
            for (int k = i; k <= Math.Min(j, checkpoints.Count - 1); k++)
            {
                DateTime lDate = DateTime.Parse(checkpoints[l].Replace('+', ':'));
                DateTime kDate = DateTime.Parse(checkpoints[k].Replace('+', ':'));
                if ((lDate.Year != kDate.Year) || (l == 0))
                {
                    if (l + 1 < k)
                    {
                        purgeSeries.Add(checkpoints[l], checkpoints[k]);
                    }
                    l = k;
                }
            }

            Console.WriteLine("Pending purge command sequence:");
            foreach (KeyValuePair<string, string> purge in purgeSeries)
            {
                Console.WriteLine("  purge {0} {1}", purge.Key, purge.Value);
            }
            Console.WriteLine();
            while (true)
            {
                Console.Write("c)ontinue or q)uit?  ");
                string answer = Console.ReadLine();
                if (answer == "q")
                {
                    return;
                }
                else if (answer == "c")
                {
                    break;
                }
            }

            foreach (KeyValuePair<string, string> purge in purgeSeries)
            {
                bool quit = false;
                while (Console.KeyAvailable)
                {
                    if (Char.ToLower(Console.ReadKey().KeyChar) == 'q')
                    {
                        quit = true;
                    }
                }
                if (quit)
                {
                    break;
                }
                Purge(archiveRoot, purge.Key, purge.Value, context);
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Restore
        //
        ////////////////////////////////////////////////////////////////////////////

        private static void RestoreFile(string archiveRoot, string checkpointPart, string target, string[] checkpoints, Context context, string checkpointPartName)
        {
            string checkpointTerminal = null;
            foreach (string checkpointCandidate in checkpoints)
            {
                string candidateCheckpointPartFilePath = Path.Combine(Path.Combine(Path.Combine(archiveRoot, checkpointCandidate), checkpointPart), checkpointPartName);

                long candidateLength = GetFileLengthNoError(candidateCheckpointPartFilePath);
                if (candidateLength > 0)
                {
                    // change-terminal found
                    checkpointTerminal = checkpointCandidate;
                    break;
                }
                else if (candidateLength < 0)
                {
                    // file was deleted: use last known checkpoint
                    break;
                }
                else
                {
                    // placeholder: keep exploring, or end with this zero-length file as change-terminal
                    checkpointTerminal = checkpointCandidate;
                }
            }
            Debug.Assert(checkpointTerminal != null);

            string sourceFilePath = Path.Combine(Path.Combine(Path.Combine(archiveRoot, checkpointTerminal), checkpointPart), checkpointPartName);
            string targetFilePath = target; // directory restore caller needs to do this (because it may not always be appropriate): Path.Combine(target, checkpointPartName);
            CopyFile(sourceFilePath, target, context);
        }

        private static void RestoreRecursive(string archiveRoot, string checkpointPart, string target, string[] checkpoints, Context context)
        {
            Console.WriteLine(target);

            if (File.Exists(target) || Directory.Exists(target))
            {
                throw new ApplicationException(String.Format("Target {0} already exists", target));
            }
            Directory.CreateDirectory(target);

            foreach (string checkpointPartFile in Directory.GetFiles(Path.Combine(Path.Combine(archiveRoot, checkpoints[0]), checkpointPart)))
            {
                string checkpointPartName = Path.GetFileName(checkpointPartFile);
                RestoreFile(archiveRoot, checkpointPart, Path.Combine(target, checkpointPartName), checkpoints, context, checkpointPartName);
            }

            foreach (string checkpointPartSubdirectory in Directory.GetDirectories(Path.Combine(Path.Combine(archiveRoot, checkpoints[0]), checkpointPart)))
            {
                string checkpointPartSubdirectoryName = Path.GetFileName(checkpointPartSubdirectory);
                RestoreRecursive(archiveRoot, Path.Combine(checkpointPart, checkpointPartSubdirectoryName), Path.Combine(target, checkpointPartSubdirectoryName), checkpoints, context);
            }
        }

        internal static void Restore(string archiveRoot, string checkpointPath, string target, Context context)
        {
            context.zeroLengthSpecial = true;

            string checkpoint = checkpointPath;
            string checkpointPart = String.Empty;
            while (Path.GetDirectoryName(checkpoint) != String.Empty)
            {
                checkpointPart = Path.Combine(Path.GetFileName(checkpoint), checkpointPart);
                checkpoint = Path.GetDirectoryName(checkpoint);
            }

            DateTime checkpointDate = ParseArchivePointName(checkpoint);
            if (!Directory.Exists(Path.Combine(archiveRoot, checkpoint)))
            {
                throw new ApplicationException(String.Format("Archive point \"{0}\" does not exist", checkpoint));
            }

            List<string> checkpoints = new List<string>();
            foreach (string file in Directory.GetFileSystemEntries(archiveRoot))
            {
                string name = Path.GetFileName(file);
                if (!((name == "check.bin") || (name == "checkc.bin") || (name == "nocheckc.bin")))
                {
                    DateTime date = ParseArchivePointName(name);
                    if (date >= checkpointDate)
                    {
                        Debug.Assert((checkpoints.Count == 0) || (String.Compare(checkpoints[checkpoints.Count - 1], name, StringComparison.OrdinalIgnoreCase) < 0));
                        checkpoints.Add(name);
                    }
                }
            }

            if (File.Exists(Path.Combine(archiveRoot, checkpointPath)))
            {
                if (File.Exists(Path.Combine(target, Path.GetFileName(checkpointPart))))
                {
                    throw new ApplicationException(String.Format("Target \"{0}\" already exists", target));
                }
                RestoreFile(archiveRoot, Path.GetDirectoryName(checkpointPart), target, checkpoints.ToArray(), context, Path.GetFileName(checkpointPart));
            }
            else if (Directory.Exists(Path.Combine(archiveRoot, checkpointPath)))
            {
                if (File.Exists(target) || Directory.Exists(target))
                {
                    throw new ApplicationException(String.Format("Target \"{0}\" already exists", target));
                }
                RestoreRecursive(archiveRoot, checkpointPart, target, checkpoints.ToArray(), context);
            }
            else
            {
                throw new ApplicationException(String.Format("Checkpoint \"{0}\" does not exist", Path.Combine(archiveRoot, checkpointPath)));
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Split, Unsplit
        //
        ////////////////////////////////////////////////////////////////////////////

        internal static void Split(string sourceFile, string destinationTemplate, long size, Context context)
        {
            if (size < 0)
            {
                if (size == -1)
                {
                    size = Int64.MaxValue;
                }
                else
                {
                    throw new ApplicationException();
                }
            }

            byte[] hash;

            using (Stream stream = File.Open(sourceFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                long length = stream.Length;

                using (CheckedReadStream checkedStream = new CheckedReadStream(stream, new CryptoPrimitiveHashCheckValueGeneratorSHA256()))
                {
                    int parts = (int)((length + size - 1) / size);
                    int digits = parts.ToString().Length;
                    long position = 0;
                    while (position < length)
                    {
                        Debug.Assert(position % size == 0);
                        string destinationFile = String.Concat(destinationTemplate, ".", (position / size).ToString("D" + digits.ToString()));
                        Console.WriteLine("Generating {0}", destinationFile);
                        using (Stream destinationStream = File.Open(destinationFile, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        {
                            byte[] buffer = new byte[Constants.BufferSize];
                            long toReadOne = Math.Min(size, length - position);
                            while (toReadOne > 0)
                            {
                                int toRead = (int)Math.Min(toReadOne, buffer.Length);
                                int read = checkedStream.Read(buffer, 0, toRead);
                                if (read != toRead)
                                {
                                    throw new ApplicationException("Read failure");
                                }
                                destinationStream.Write(buffer, 0, read);
                                position += read;
                                toReadOne -= read;
                            }
                        }
                        File.SetCreationTime(destinationFile, context.now);
                        File.SetLastWriteTime(destinationFile, context.now);
                    }

                    checkedStream.Close();
                    hash = checkedStream.CheckValue;
                }
            }

            string destinationFileHash = String.Concat(destinationTemplate, ".sha256");
            Console.WriteLine("Generating {0}", destinationFileHash);
            using (Stream destinationStreamHash = File.Open(destinationFileHash, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                using (TextWriter writer = new StreamWriter(destinationStreamHash))
                {
                    string hashText = HexEncode(hash);
                    writer.WriteLine(hashText);
                    Console.WriteLine("SHA256={0}", hashText);
                }
            }
            File.SetCreationTime(destinationFileHash, context.now);
            File.SetLastWriteTime(destinationFileHash, context.now);
        }

        internal static void Unsplit(string sourcePrefix, string destinationFile, Context context)
        {
            bool hashValid = false;

            SortedList<string, bool> files = new SortedList<string, bool>();
            foreach (string file in Directory.GetFiles(Path.GetDirectoryName(sourcePrefix), String.Concat(Path.GetFileName(sourcePrefix), ".*")))
            {
                files.Add(file, false);
            }

            byte[] hash;
            string sha256OriginalHashText = null;

            using (Stream stream = File.Open(destinationFile, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                using (CheckedWriteStream checkedStream = new CheckedWriteStream(stream, new CryptoPrimitiveHashCheckValueGeneratorSHA256()))
                {
                    foreach (KeyValuePair<string, bool> file1 in files)
                    {
                        string path = file1.Key;
                        string extension = Path.GetExtension(file1.Key);
                        int sequence;

                        Console.WriteLine("Incorporating {0}", path);

                        if (extension.StartsWith(".") && Int32.TryParse(extension.Substring(1), out sequence))
                        {
                            using (Stream segmentStream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                            {
                                byte[] buffer = new byte[Constants.BufferSize];
                                while (true)
                                {
                                    int read = segmentStream.Read(buffer, 0, buffer.Length);
                                    if (read == 0)
                                    {
                                        break;
                                    }
                                    checkedStream.Write(buffer, 0, read);
                                }
                            }
                        }
                        else if (extension.Equals(".sha256", StringComparison.OrdinalIgnoreCase))
                        {
                            using (TextReader reader = new StreamReader(path))
                            {
                                sha256OriginalHashText = reader.ReadLine();
                            }
                        }
                        else
                        {
                            Console.WriteLine("  UNKNOWN FILE EXTENSION -- IGNORED");
                        }
                    }

                    checkedStream.Close();
                    hash = checkedStream.CheckValue;
                }
            }

            string sha256HashText = HexEncode(hash);
            Console.WriteLine("SHA256={0}", sha256HashText);
            hashValid = sha256HashText.Equals(sha256OriginalHashText, StringComparison.OrdinalIgnoreCase);
            Console.WriteLine(hashValid
                ? "  SHA256 hashes match"
                : "  SHA256 hashes do not match, FILE IS DAMAGED");

            File.SetCreationTime(destinationFile, context.now);
            File.SetLastWriteTime(destinationFile, context.now);
            if (!hashValid)
            {
                throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied);
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Validate
        //
        ////////////////////////////////////////////////////////////////////////////

        private static void ValidateEncryptionRecursive(string file, OneWaySwitch invalid, Context context)
        {
            if (File.Exists(file))
            {
                bool valid = true;
                try
                {
                    // validate HMAC
                    using (Stream fileStream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        // zero-length "encrypted" files are considered valid because backup creates them in checkpoints
                        if (fileStream.Length != 0)
                        {
                            CryptoKeygroup keys;
                            EncryptedFileContainerHeader fch = null;
                            try
                            {
                                fch = new EncryptedFileContainerHeader(fileStream, true/*peek*/, context.decrypt);
                            }
                            catch (InvalidDataException)
                            {
                                // function-local escape
                                throw new TaggedReadStream.TagInvalidException();
                            }
                            context.decrypt.algorithm.DeriveSessionKeys(context.decrypt.GetMasterKeyEntry(fch.passwordSalt, fch.rfc2898Rounds).MasterKey, fch.fileSalt, out keys);

                            // zero-length files are considered valid because backup creates them in checkpoints
                            // when a file has not changed when the next checkpoint is created.
                            if (fileStream.Length > 0)
                            {
                                DoWithStreamStack(
                                    fileStream,
                                    new StreamWrapMethod[]
                                    {
                                        delegate(Stream stream)
                                        {
                                            // see note and references about
                                            // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                            return new TaggedReadStream(stream, context.decrypt.algorithm.CreateMACGenerator(keys.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                        },
                                    },
                                    delegate(Stream stream)
                                    {
                                        ReadAndDiscardEntireStream(stream);
                                    });
                            }
                        }
                    }
                }
                catch (TaggedReadStream.TagInvalidException)
                {
                    valid = false;
                }

                string message = String.Format("{0,-7} {1}", valid ? "valid" : "INVALID", file);
                if (valid)
                {
                    Console.WriteLine(message);
                }
                else
                {
                    invalid.Set();
                    ConsoleWriteLineColor(ConsoleColor.Yellow, message);
                }
            }
            else
            {
                foreach (string contained in Directory.GetFileSystemEntries(file))
                {
                    ValidateEncryptionRecursive(contained, invalid, context);
                }
            }
        }

        internal static void ValidateEncryption(string sourcePattern, Context context)
        {
            string[] sourceFileList = new string[] { sourcePattern };
            if (FileNamePatternMatch.ContainsWildcards(sourcePattern))
            {
                sourceFileList = Directory.GetFiles(Path.GetDirectoryName(sourcePattern), Path.GetFileName(sourcePattern));
            }

            OneWaySwitch invalid = new OneWaySwitch();
            foreach (string sourceFile in sourceFileList)
            {
                ValidateEncryptionRecursive(sourceFile, invalid, context);
            }

            if (invalid.Value)
            {
                throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied);
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Pack, Unpack, DynamicPack
        //
        ////////////////////////////////////////////////////////////////////////////

        public const byte PackArchiveFixedHeaderNumber = 0x01;

        private const int PackRandomSignatureLengthBytes = 256 / 8;

        public const int PackArchiveStructureTypeManifest = 1;
        public const int PackArchiveStructureTypeFiles = 2;

        internal class PackedFileHeaderRecord
        {
            internal enum Fields
            {
                Terminator = 0,

                // file data fields
                Version = 1, // reserved & optional; must come first
                Subpath = 2,
                CreationTimeUtc = 3,
                LastWriteTimeUtc = 4,
                Attributes = 5,

                // these fields used only for manifest; 
                // - these fields must occur both or neither
                // - if present, no other fields may be set and data stream must be zero length
                // - if present implies PackArchiveStructureTypeManifest, if absent implies PackArchiveStructureTypeFiles
                SegmentName = 6,
                SegmentSerialNumber = 7,

                // used for large files split across multiple segments - optional
                Range = 8,
            }

            internal const int SupportedVersionNumber = 1;

            [Flags]
            internal enum HeaderAttributes : ulong
            {
                None = 0,

                Directory = 1,
                ReadOnly = 2,
            }

            internal static readonly KeyValuePair<HeaderAttributes, FileAttributes>[] AttributeMapping = new KeyValuePair<HeaderAttributes, FileAttributes>[]
            {
                new KeyValuePair<HeaderAttributes, FileAttributes>(HeaderAttributes.Directory,  FileAttributes.Directory),
                new KeyValuePair<HeaderAttributes, FileAttributes>(HeaderAttributes.ReadOnly,   FileAttributes.ReadOnly),
            };

            internal static readonly KeyValuePair<HeaderAttributes, char>[] AttributeSymbolMapping = new KeyValuePair<HeaderAttributes, char>[]
            {
                new KeyValuePair<HeaderAttributes, char>(HeaderAttributes.ReadOnly,     'r'),
                new KeyValuePair<HeaderAttributes, char>(HeaderAttributes.Directory,    'd'),
            };

            internal static FileAttributes ToFileAttributes(HeaderAttributes a)
            {
                FileAttributes r = (FileAttributes)0;
                foreach (KeyValuePair<HeaderAttributes, FileAttributes> i in AttributeMapping)
                {
                    if ((i.Key & a) != 0)
                    {
                        r |= i.Value;
                    }
                }
                if (r == (FileAttributes)0)
                {
                    r = FileAttributes.Normal;
                }
                return r;
            }

            internal static HeaderAttributes ToHeaderAttributes(FileAttributes a)
            {
                HeaderAttributes r = HeaderAttributes.None;
                foreach (KeyValuePair<HeaderAttributes, FileAttributes> i in AttributeMapping)
                {
                    if ((i.Value & a) != 0)
                    {
                        r |= i.Key;
                    }
                }
                return r;
            }

            public class RangeRecord
            {
                public readonly long Start;
                public readonly long End;
                public readonly long TotalFileLength;

                public RangeRecord(long start, long end, long totalFileLength)
                {
                    this.Start = start;
                    this.End = end;
                    this.TotalFileLength = totalFileLength;
                }

                public long Length { get { return End + 1 - Start; } }

                public override string ToString()
                {
                    return String.Format("{0}-{1}/{2}", Start, End, TotalFileLength);
                }

                public static RangeRecord Parse(string value)
                {
                    string[] parts = value.Split(new char[] { '-', '/' });
                    if (parts.Length != 3)
                    {
                        throw new InvalidDataException();
                    }
                    long start = Int64.Parse(parts[0]);
                    long end = Int64.Parse(parts[1]);
                    long totalFileLength = Int64.Parse(parts[2]);
                    return new RangeRecord(start, end, totalFileLength);
                }

                public static bool Equals(RangeRecord l, RangeRecord r)
                {
                    if (l == null)
                    {
                        if (r == null)
                        {
                            return true;
                        }
                        return false;
                    }
                    return (l.Start == r.Start) && (l.End == r.End) && (l.TotalFileLength == r.TotalFileLength);
                }
            }

            internal const int HeaderTokenLength = 4;
            private static readonly byte[] PackedFileHeaderToken = new byte[HeaderTokenLength] { 0x81, 0x72, 0x63, 0x54 };

            public static readonly PackedFileHeaderRecord NullHeaderRecord = new PackedFileHeaderRecord();

            private object subpath;
            private DateTime creationTimeUtc;
            private DateTime lastWriteTimeUtc;
            private HeaderAttributes attributes;
            private long embeddedStreamLength; // if range==null: orig. file & embedded data length, else embedded data length only

            private string segmentName;
            private ulong segmentSerialNumber;

            private RangeRecord range; // null if file is not split

            private PackedFileHeaderRecord()
            {
            }

            internal PackedFileHeaderRecord(object subpath, DateTime creationTimeUtc, DateTime lastWriteTimeUtc, HeaderAttributes attributes, long embeddedStreamLength, string segmentName, ulong segmentSerialNumber, RangeRecord range)
            {
                if (range != null)
                {
                    if (embeddedStreamLength != range.Length)
                    {
                        throw new ArgumentException();
                    }
                }

                this.subpath = subpath;
                this.creationTimeUtc = creationTimeUtc;
                this.lastWriteTimeUtc = lastWriteTimeUtc;
                this.attributes = attributes;
                this.embeddedStreamLength = embeddedStreamLength;

                this.segmentName = segmentName;
                this.segmentSerialNumber = segmentSerialNumber;

                this.range = range;
            }

            internal PackedFileHeaderRecord(object subpath, DateTime creationTimeUtc, DateTime lastWriteTimeUtc, HeaderAttributes attributes, long embeddedStreamLength, string segmentName, ulong segmentSerialNumber)
                : this(subpath, creationTimeUtc, lastWriteTimeUtc, attributes, embeddedStreamLength, segmentName, segmentSerialNumber, null/*range*/)
            {
            }

            internal PackedFileHeaderRecord(object subpath, DateTime creationTimeUtc, DateTime lastWriteTimeUtc, HeaderAttributes attributes, long embeddedStreamLength)
                : this(subpath, creationTimeUtc, lastWriteTimeUtc, attributes, embeddedStreamLength, null/*segmentName*/, 0/*segmentSerialNumber*/, null/*range*/)
            {
            }

            internal PackedFileHeaderRecord(object subpath, DateTime creationTimeUtc, DateTime lastWriteTimeUtc, HeaderAttributes attributes, long embeddedStreamLength, RangeRecord range)
                : this(subpath, creationTimeUtc, lastWriteTimeUtc, attributes, embeddedStreamLength, null/*segmentName*/, 0/*segmentSerialNumber*/, range)
            {
            }

            private const string PackedFileDateTimeFormat = "O"; // "round-trip"

            internal static DateTime ParseDateTime(string datetime)
            {
                return DateTime.ParseExact(datetime, PackedFileDateTimeFormat, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind);
            }

            internal static string FormatDateTime(DateTime datetimeUtc)
            {
                if (datetimeUtc.Kind != DateTimeKind.Utc)
                {
                    throw new InvalidDataException();
                }
                return datetimeUtc.ToString(PackedFileDateTimeFormat, System.Globalization.CultureInfo.InvariantCulture);
            }

            internal void Write(Stream stream)
            {
                byte[] checkValue;

                ValidateRecordInvariants(false/*nullHeader*/); // writing null header is not permitted with this method, use WriteNullHeader

                stream.Write(PackedFileHeaderToken, 0, PackedFileHeaderToken.Length);

                using (CheckedWriteStream checkedStream = new CheckedWriteStream(stream, new CRC32()))
                {
                    // header fields section start

                    if (subpath != null)
                    {
                        Debug.Assert(!String.IsNullOrEmpty(subpath.ToString()));
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.Subpath);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, subpath.ToString());
                    }

                    if (creationTimeUtc != default(DateTime))
                    {
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.CreationTimeUtc);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, FormatDateTime(creationTimeUtc));
                    }

                    if (lastWriteTimeUtc != default(DateTime))
                    {
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.LastWriteTimeUtc);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, FormatDateTime(lastWriteTimeUtc));
                    }

                    if (attributes != default(HeaderAttributes))
                    {
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.Attributes);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, ((ulong)attributes).ToString());
                    }

                    if ((segmentName != null) != (segmentSerialNumber != 0))
                    {
                        throw new InvalidOperationException();
                    }
                    if (segmentName != null)
                    {
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.SegmentName);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, segmentName);
                    }
                    if (segmentSerialNumber != 0)
                    {
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.SegmentSerialNumber);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, segmentSerialNumber.ToString());
                    }

                    if (range != null)
                    {
                        BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.Range);
                        BinaryWriteUtils.WriteStringUtf8(checkedStream, range.ToString());
                    }

                    BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.Terminator);

                    // header fields section end

                    BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, embeddedStreamLength);

                    checkedStream.Close();
                    checkValue = checkedStream.CheckValue;
                }

                stream.Write(checkValue, 0, checkValue.Length);
            }

            // Null header contains only a terminator field and zero for file length.
            internal static void WriteNullHeader(Stream stream)
            {
                byte[] checkValue;

                stream.Write(PackedFileHeaderToken, 0, PackedFileHeaderToken.Length);

                using (CheckedWriteStream checkedStream = new CheckedWriteStream(stream, new CRC32()))
                {
                    BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, (int)Fields.Terminator);

                    BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, 0); // file length field

                    checkedStream.Close();
                    checkValue = checkedStream.CheckValue;
                }

                stream.Write(checkValue, 0, checkValue.Length);
            }

            internal static PackedFileHeaderRecord Read(Stream stream, bool strict, DateTime now)
            {
                PackedFileHeaderRecord header = new PackedFileHeaderRecord();
                bool nullHeader;
                header.ReadInternal(stream, strict, now, out nullHeader);
                return !nullHeader ? header : NullHeaderRecord;
            }

            private void ReadInternal(Stream stream, bool strict, DateTime now, out bool nullHeader)
            {
                nullHeader = false;

                byte[] checkValue;

                using (CheckedReadStream checkedStream = new CheckedReadStream(stream, new CRC32()))
                {
                    int count = 0;
                    while (true)
                    {
                        int field = BinaryReadUtils.ReadVariableLengthQuantityAsInt32(checkedStream);
                        if ((Fields)field == Fields.Terminator)
                        {
                            break;
                        }
                        string value = BinaryReadUtils.ReadStringUtf8(checkedStream);
                        count++;
                        switch ((Fields)field)
                        {
                            default:
                                if (strict)
                                {
                                    throw new InvalidDataException();
                                }
                                // ignore unrecognized header fields
                                break;

                            case Fields.Version:
                                // version field is optional, but must be first
                                if (count != 1)
                                {
                                    throw new InvalidDataException();
                                }
                                if (Int32.Parse(value) != SupportedVersionNumber)
                                {
                                    throw new InvalidDataException();
                                }
                                break;

                            case Fields.Subpath:
                                subpath = value; // must be validated at time of use
                                break;

                            case Fields.CreationTimeUtc:
                                try
                                {
                                    creationTimeUtc = ParseDateTime(value);
                                }
                                catch (Exception)
                                {
                                    if (strict)
                                    {
                                        throw;
                                    }
                                    creationTimeUtc = now;
                                }
                                break;

                            case Fields.LastWriteTimeUtc:
                                try
                                {
                                    lastWriteTimeUtc = ParseDateTime(value);
                                }
                                catch (Exception)
                                {
                                    if (strict)
                                    {
                                        throw;
                                    }
                                    lastWriteTimeUtc = now;
                                }
                                break;

                            case Fields.Attributes:
                                try
                                {
                                    attributes = (HeaderAttributes)UInt64.Parse(value);
                                }
                                catch (Exception)
                                {
                                    if (strict)
                                    {
                                        throw;
                                    }
                                }
                                break;

                            case Fields.SegmentName:
                                segmentName = value;
                                break;

                            case Fields.SegmentSerialNumber:
                                segmentSerialNumber = UInt64.Parse(value);
                                break;

                            case Fields.Range:
                                try
                                {
                                    range = RangeRecord.Parse(value);
                                }
                                catch (Exception)
                                {
                                    if (strict)
                                    {
                                        throw;
                                    }
                                    else
                                    {
                                        // invalid range - problem dealt with elsewhere
                                        range = new RangeRecord(-1, -1, -1);
                                    }
                                }
                                break;
                        }
                    }

                    embeddedStreamLength = BinaryReadUtils.ReadVariableLengthQuantityAsInt64(checkedStream);

                    nullHeader = (count == 0) && (embeddedStreamLength == 0);

                    checkedStream.Close();
                    checkValue = checkedStream.CheckValue;
                }

                byte[] savedCheckValue = BinaryReadUtils.ReadBytes(stream, checkValue.Length);
                if (!ArrayEqual(checkValue, savedCheckValue))
                {
                    throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied, "Individual archived file header check values do not match");
                }

                try
                {
                    ValidateRecordInvariants(nullHeader);
                }
                catch (InvalidOperationException)
                {
                    throw new InvalidDataException(); // makes more sense when reading a file
                }
            }

            // Validate invariant conditions on the structure of a record. This conceptually
            // violates the layer of abstraction (should be done by clients of the struct),
            // but is more reliable to do it here, in one place, for all clients.
            private void ValidateRecordInvariants(bool nullHeader)
            {
                // special case for null header
                if (nullHeader)
                {
                    // (everything must be null)
                    if (!((subpath == null)
                        && (creationTimeUtc == default(DateTime))
                        && (lastWriteTimeUtc == default(DateTime))
                        && (attributes == default(HeaderAttributes))
                        && (embeddedStreamLength == 0)
                        && (segmentName == null)
                        && (segmentSerialNumber == 0)))
                    {
                        throw new InvalidOperationException();
                    }

                    return;
                }

                // require segmentName and segmentSerialNumber be coexistant
                if (!((segmentName != null) == (segmentSerialNumber != 0)))
                {
                    throw new InvalidOperationException();
                }

                // require exactly one of {either file, segment header}
                if (!((segmentName != null) != (subpath != null)))
                {
                    throw new InvalidOperationException();
                }

                // require no other values for segment header (implies file length == 0)
                if (segmentName != null)
                {
                    if (!((subpath == null)
                        && (creationTimeUtc == default(DateTime))
                        && (lastWriteTimeUtc == default(DateTime))
                        && (attributes == default(HeaderAttributes))
                        && (embeddedStreamLength == 0)))
                    {
                        throw new InvalidOperationException();
                    }
                }

                // directories never have a stream associated with them
                if (!(!((attributes & HeaderAttributes.Directory) != 0) || (embeddedStreamLength == 0)))
                {
                    throw new InvalidOperationException();
                }

                // range invariant
                if ((range != null) && (range.Length != embeddedStreamLength))
                {
                    throw new InvalidOperationException();
                }
            }

            internal static bool ValidFileHeaderToken(byte[] buffer)
            {
                return ArrayEqual(buffer, PackedFileHeaderToken);
            }

            internal int GetHeaderLength()
            {
                using (MemoryStream stream = new MemoryStream())
                {
                    Write(stream);
                    return (int)stream.Length;
                }
            }

            internal string Subpath
            {
                get
                {
                    return subpath.ToString();
                }
            }

            internal object SubpathObject
            {
                get
                {
                    return subpath;
                }
            }

            internal DateTime CreationTimeUtc
            {
                get
                {
                    return creationTimeUtc;
                }
            }

            internal DateTime LastWriteTimeUtc
            {
                get
                {
                    return lastWriteTimeUtc;
                }
            }

            internal HeaderAttributes Attributes
            {
                get
                {
                    return attributes;
                }
            }

            internal long EmbeddedStreamLength
            {
                get
                {
                    return embeddedStreamLength;
                }
            }

            internal string SegmentName
            {
                get
                {
                    return segmentName;
                }

                set
                {
                    segmentName = value;
                }
            }

            internal ulong SegmentSerialNumber
            {
                get
                {
                    return segmentSerialNumber;
                }

                set
                {
                    segmentSerialNumber = value;
                }
            }

            internal RangeRecord Range
            {
                get
                {
                    return range;
                }
            }

            internal long TotalFileLength
            {
                get
                {
                    return range == null ? embeddedStreamLength : range.TotalFileLength;
                }
            }
        }

        private static void PackOne(string file, Stream stream, string partialPathPrefix, PackedFileHeaderRecord.RangeRecord range, bool enableRetry, Context context)
        {
            bool directory = false;

            using (Stream inputStream = DoRetryable<Stream>(
                delegate
                {
                    try
                    {
                        if (Directory.Exists(file))
                        {
                            directory = true;
                            return null;
                        }
                        return new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    }
                    catch (PathTooLongException exception)
                    {
                        throw new PathTooLongException(String.Format("{0} (length={2}, path=\'{1}\')", exception.Message, file, file.Length));
                    }
                },
                delegate { return null; },
                delegate { },
                enableRetry,
                context))
            {
                if ((inputStream != null) || directory)
                {
                    // write header

                    long embeddedStreamLength = 0;
                    if (!directory)
                    {
                        if (range == null)
                        {
                            embeddedStreamLength = inputStream.Length;
                            if (inputStream.Position != 0)
                            {
                                throw new InvalidOperationException(); // program defect
                            }
                        }
                        else
                        {
                            embeddedStreamLength = range.Length;
                            inputStream.Position = range.Start;
                        }
                    }
                    else
                    {
                        if (range != null)
                        {
                            throw new InvalidOperationException(); // program defect
                        }
                    }

                    PackedFileHeaderRecord header = new PackedFileHeaderRecord(
                        Path.Combine(partialPathPrefix, Path.GetFileName(file)),
                        !directory ? File.GetCreationTimeUtc(file) : default(DateTime),
                        !directory ? File.GetLastWriteTimeUtc(file) : default(DateTime),
                        PackedFileHeaderRecord.ToHeaderAttributes(File.GetAttributes(file)),
                        embeddedStreamLength,
                        range);
                    header.Write(stream);


                    // write data

                    byte[] fileDataCheckValue;
                    using (CheckedWriteStream checkedStream = new CheckedWriteStream(stream, new CRC32()))
                    {
                        if (!directory)
                        {
                            byte[] buffer = new byte[Constants.BufferSize];
                            long bytesRemaining = embeddedStreamLength;
                            while (bytesRemaining > 0)
                            {
                                int bytesRead;
                                try
                                {
                                    int needed = (int)Math.Min(buffer.Length, bytesRemaining);
                                    bytesRead = inputStream.Read(buffer, 0, needed);
                                }
                                catch (Exception exception)
                                {
                                    throw new Exception(String.Format("{0} [file \"{1}\"]", exception.Message, file), exception);
                                }
                                checkedStream.Write(buffer, 0, bytesRead);
                                bytesRemaining -= bytesRead;
                            }
                        }

                        checkedStream.Close();
                        fileDataCheckValue = checkedStream.CheckValue;
                    }

                    stream.Write(fileDataCheckValue, 0, fileDataCheckValue.Length);
                }
            }
        }

        private static void PackRecursive(string sourceRootDirectory, Stream stream, Context context, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems, string partialPathPrefix, ref long addedCount)
        {
            WriteStatusLine(sourceRootDirectory);

            List<string> subdirectories = new List<string>();
            bool driveRoot = IsDriveRoot(sourceRootDirectory);
            foreach (string file in DoRetryable<string[]>(delegate { return Directory.GetFileSystemEntries(sourceRootDirectory); }, delegate { return new string[0]; }, null, context))
            {
                if (!driveRoot || !IsExcludedDriveRootItem(file))
                {
                    FileAttributes fileAttributes = DoRetryable<FileAttributes>(delegate { return File.GetAttributes(file); }, delegate { return FileAttributes.Normal; }, null, context);
                    if ((fileAttributes & FileAttributes.Directory) != 0)
                    {
                        subdirectories.Add(file);
                    }
                    else
                    {
                        if (!excludedItems.Contains(file.ToLowerInvariant())
                            && !excludedExtensions.Contains(Path.GetExtension(file).ToLowerInvariant()))
                        {
                            PackOne(file, stream, partialPathPrefix, null/*range*/, true/*enableRetry*/, context);
                            addedCount++;
                        }
                        else
                        {
                            Console.WriteLine("  SKIPPED FILE: {0}", file);
                        }
                    }
                }
            }

            foreach (string subdirectory in subdirectories)
            {
                if (!excludedItems.Contains(subdirectory.ToLowerInvariant()))
                {
                    long initialAddedCount = addedCount;

                    PackRecursive(subdirectory, stream, context, excludedExtensions, excludedItems, Path.Combine(partialPathPrefix, Path.GetFileName(subdirectory)), ref addedCount);

                    // for subdirectories, only if it is empty add it explicitly
                    if (addedCount == initialAddedCount)
                    {
                        PackOne(subdirectory, stream, partialPathPrefix, null/*range*/, true/*enableRetry*/, context);
                        addedCount++;
                    }
                }
                else
                {
                    Console.WriteLine("  SKIPPED SUBDIRECTORY: {0}", subdirectory);
                }
            }
        }

        internal static void Pack(string source, string targetFile, Context context, string[] args)
        {
            byte[] randomArchiveSignature = new byte[PackRandomSignatureLengthBytes];
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                rng.GetBytes(randomArchiveSignature);
            }

            InvariantStringSet excludedExtensions;
            InvariantStringSet excludedItems;
            GetExclusionArguments(args, out excludedExtensions, false/*relative*/, out excludedItems);

            if (!Directory.Exists(source))
            {
                throw new UsageException();
            }

            using (Stream fileStream = new FileStream(targetFile, FileMode.CreateNew, FileAccess.Write))
            {
                CryptoKeygroup keys = null;
                EncryptedFileContainerHeader fch = null;
                if (context.cryptoOption == EncryptionOption.Encrypt)
                {
                    CryptoMasterKeyCacheEntry entry = context.encrypt.GetDefaultMasterKeyEntry();
                    fch = new EncryptedFileContainerHeader(context.encrypt);
                    fch.passwordSalt = entry.PasswordSalt;
                    context.encrypt.algorithm.DeriveNewSessionKeys(entry.MasterKey, out fch.fileSalt, out keys);
                }

                DoWithStreamStack(
                    fileStream,
                    new StreamWrapMethod[]
                    {
                        delegate(Stream stream)
                        {
                            // see note and references about
                            // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                            if (context.cryptoOption == EncryptionOption.Encrypt)
                            {
                                return new TaggedWriteStream(stream, context.encrypt.algorithm.CreateMACGenerator(keys.SigningKey));
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if (context.cryptoOption == EncryptionOption.Encrypt)
                            {
                                // why write here? need to write salt within HMAC container
                                fch.Write(stream);
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if (context.cryptoOption == EncryptionOption.Encrypt)
                            {
                                return context.encrypt.algorithm.CreateEncryptStream(stream, keys.CipherKey, keys.InitialCounter);
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if (context.compressionOption == CompressionOption.Compress)
                            {
                                return new BlockedCompressStream(stream);
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            // total file CRC32 check value
                            return new TaggedWriteStream(stream, new CRC32());
                        }
                    },
                    delegate(Stream stream)
                    {
                        BinaryWriteUtils.WriteBytes(stream, new byte[1] { PackArchiveFixedHeaderNumber });

                        BinaryWriteUtils.WriteVariableLengthByteArray(stream, randomArchiveSignature);

                        BinaryWriteUtils.WriteVariableLengthQuantity(stream, 1); // single pack files have fixed sequence number

                        BinaryWriteUtils.WriteVariableLengthQuantity(stream, PackArchiveStructureTypeFiles);

                        long addedCount = 0;
                        PackRecursive(
                            source,
                            stream,
                            context,
                            excludedExtensions,
                            excludedItems,
                            ".",
                            ref addedCount);

                        PackedFileHeaderRecord.WriteNullHeader(stream);
                    });
            }

            EraseStatusLine();

            File.SetCreationTime(targetFile, context.now);
            File.SetLastWriteTime(targetFile, context.now);
        }

        internal struct UnpackedFileRecord
        {
            private string fullPath;
            private PackedFileHeaderRecord header;

            internal UnpackedFileRecord(string fullPath, PackedFileHeaderRecord header)
            {
                this.fullPath = fullPath;
                this.header = header;
            }

            internal string FullPath
            {
                get
                {
                    return fullPath;
                }
            }


            internal string ArchivePath
            {
                get
                {
                    return header.Subpath;
                }
            }

            internal DateTime CreationTimeUtc
            {
                get
                {
                    return header.CreationTimeUtc;
                }
            }

            internal DateTime LastWriteTimeUtc
            {
                get
                {
                    return header.LastWriteTimeUtc;
                }
            }

            internal long EmbeddedStreamLength
            {
                get
                {
                    return header.EmbeddedStreamLength;
                }
            }

            internal PackedFileHeaderRecord.HeaderAttributes Attributes
            {
                get
                {
                    return header.Attributes;
                }
            }

            internal string SegmentName
            {
                get
                {
                    return header.SegmentName;
                }
            }

            internal ulong SegmentSerialNumber
            {
                get
                {
                    return header.SegmentSerialNumber;
                }
            }

            internal PackedFileHeaderRecord.RangeRecord Range
            {
                get
                {
                    return header.Range;
                }
            }

            internal long TotalFileLength
            {
                get
                {
                    return header.TotalFileLength;
                }
            }
        }

        private class RangeSequenceException : ApplicationException
        {
            public RangeSequenceException(string message)
                : base(message)
            {
            }
        }

        private class DeferredMultiException : ApplicationException
        {
            private Exception[] innerExceptions = new Exception[0];

            public DeferredMultiException(Exception[] innerExceptions)
            {
                if (innerExceptions != null)
                {
                    this.innerExceptions = innerExceptions;
                }
            }

            public override string Message
            {
                get
                {
                    StringBuilder sb = new StringBuilder();
                    foreach (Exception exception in innerExceptions)
                    {
                        string one = exception.ToString().Replace(Environment.NewLine, ";");
                        sb.AppendLine(one);
                    }
                    return sb.ToString();
                }
            }
        }

        [Flags]
        internal enum UnpackMode
        {
            Parse = 0, // always implied

            SignatureOnly = 1 << 0,

            Unpack = 1 << 1,
            Resume = 1 << 2,
            ShowProgress = 1 << 3,
        }

        private static UnpackedFileRecord[] UnpackInternal(Stream fileStream, string targetDirectory, Context context, UnpackMode mode, out ulong segmentSerialNumberOut, out byte[] randomArchiveSignatureOut, TextWriter trace, FaultInstanceNode faultContainer, out ApplicationException[] deferredExceptions)
        {
            List<ApplicationException> deferredExceptionsList = new List<ApplicationException>();

            try
            {
                bool writeFiles = (mode & UnpackMode.Unpack) == UnpackMode.Unpack;
                bool displayProgress = (mode & UnpackMode.ShowProgress) == UnpackMode.ShowProgress;
                bool resume = (mode & UnpackMode.Resume) == UnpackMode.Resume;
                bool signatureOnly = (mode & UnpackMode.SignatureOnly) == UnpackMode.SignatureOnly;
                if (signatureOnly && writeFiles)
                {
                    throw new ArgumentException();
                }

                FaultInstanceNode faultUnpackInternal = faultContainer.Select("UnpackInternal");

                ulong segmentSerialNumber = 0;
                byte[] randomArchiveSignature = new byte[0];

                List<UnpackedFileRecord> unpackedFileRecords = new List<UnpackedFileRecord>();

                if (fileStream.Position != 0)
                {
                    throw new InvalidOperationException();
                }


                CryptoKeygroup keys = null;
                EncryptedFileContainerHeader fch = null;
                if (context.cryptoOption == EncryptionOption.Decrypt)
                {
                    fch = new EncryptedFileContainerHeader(fileStream, true/*peek*/, context.decrypt);
                    context.decrypt.algorithm.DeriveSessionKeys(context.decrypt.GetMasterKeyEntry(fch.passwordSalt, fch.rfc2898Rounds).MasterKey, fch.fileSalt, out keys);
                }

                // Using Moxie Marlinspike's "doom principle": validate the MAC before ANY other
                // action is taken. (http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/)
                bool macValidated = false;
                if (!context.doNotPreValidateMAC && (context.cryptoOption != EncryptionOption.None))
                {
                    DoWithStreamStack(
                        fileStream,
                        new StreamWrapMethod[]
                        {
                            delegate(Stream stream)
                            {
                                // see note and references about
                                // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                return new TaggedReadStream(stream, context.decrypt.algorithm.CreateMACGenerator(keys.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                            },
                        },
                        delegate(Stream stream)
                        {
                            ReadAndDiscardEntireStream(stream);
                        });

                    macValidated = true;
                }

                fileStream.Position = 0;

                DoWithStreamStack(
                    fileStream,
                    new StreamWrapMethod[]
                    {
                        delegate(Stream stream)
                        {
                            // see note and references about
                            // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                            if (context.cryptoOption == EncryptionOption.Decrypt)
                            {
                                if (!macValidated)
                                {
                                    return new TaggedReadStream(stream, context.decrypt.algorithm.CreateMACGenerator(keys.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                }
                                else
                                {
                                    return new ReadStreamHoldShort(stream, context.decrypt.algorithm.MACLengthBytes);
                                }
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if (context.cryptoOption == EncryptionOption.Decrypt)
                            {
                                // why re-read here? need to read salt within HMAC container
                                EncryptedFileContainerHeader fch2 = new EncryptedFileContainerHeader(stream, false/*peek*/, context.decrypt);
                                if (!fch2.Equals(fch))
                                {
                                    throw new InvalidOperationException();
                                }
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if (context.cryptoOption == EncryptionOption.Decrypt)
                            {
                                return context.decrypt.algorithm.CreateDecryptStream(stream, keys.CipherKey, keys.InitialCounter);
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            if (context.compressionOption == CompressionOption.Decompress)
                            {
                                return new BlockedDecompressStream(stream);
                            }
                            return null;
                        },
                        delegate(Stream stream)
                        {
                            // total file CRC32 check value
                            return new TaggedReadStream(stream, new CRC32(), "File check values do not match - file is damaged");
                        }
                    },
                    delegate(Stream stream)
                    {
                        if (trace != null)
                        {
                            trace.WriteLine("UnpackInternal writeFiles={0}, resume={1}", writeFiles, resume);
                        }

                        byte[] headerNumber = BinaryReadUtils.ReadBytes(stream, 1);
                        if (trace != null)
                        {
                            trace.WriteLine("HeaderNumber: {0}", headerNumber[0]);
                        }
                        if (headerNumber[0] != PackArchiveFixedHeaderNumber)
                        {
                            throw new InvalidDataException(); // unrecognized format
                        }

                        randomArchiveSignature = BinaryReadUtils.ReadVariableLengthByteArray(stream);
                        if (trace != null)
                        {
                            trace.WriteLine("Signature: {0}", Logging.ScrubSecuritySensitiveValue(randomArchiveSignature));
                        }

                        segmentSerialNumber = BinaryReadUtils.ReadVariableLengthQuantityAsUInt64(stream);
                        if (trace != null)
                        {
                            trace.WriteLine("SerialNumber: {0}", segmentSerialNumber);
                        }

                        if (signatureOnly)
                        {
                            ReadAndDiscardEntireStream(stream);
                            return;
                        }

                        int structureType = BinaryReadUtils.ReadVariableLengthQuantityAsInt32(stream);
                        if (trace != null)
                        {
                            trace.WriteLine("StructureType: {0}", structureType);
                        }
                        if ((structureType != PackArchiveStructureTypeManifest)
                            && (structureType != PackArchiveStructureTypeFiles))
                        {
                            throw new InvalidDataException(); // unrecognized format
                        }

                        if (writeFiles)
                        {
                            Directory.CreateDirectory(targetDirectory);
                        }

                        bool fileDataOmitted = false;
                        string currentSegmentName = null;
                        ulong currentSegmentSerialNumber = 0;
                        bool firstHeader = true;
                        bool firstHeaderWasSegment = false;
                        string currentDisplayDirectory = null;
                        //
                        string lastSubpath = null;
                        PackedFileHeaderRecord.RangeRecord lastRange = null;
                        //
                        while (true)
                        {
                            byte[] startToken = BinaryReadUtils.ReadBytes(stream, PackedFileHeaderRecord.HeaderTokenLength);
                            if (!PackedFileHeaderRecord.ValidFileHeaderToken(startToken))
                            {
                                throw new InvalidDataException("Unexpected value for start token");
                            }

                            PackedFileHeaderRecord header = PackedFileHeaderRecord.Read(stream, false/*strict*/, context.now);
                            if (header == PackedFileHeaderRecord.NullHeaderRecord)
                            {
                                if (trace != null)
                                {
                                    trace.WriteLine("Header[Terminator]");
                                }
                                break;
                            }

                            // if any segment headers exist (== manifest file), the first record in file must be one
                            if (firstHeader)
                            {
                                if (header.SegmentName != null)
                                {
                                    firstHeaderWasSegment = true;
                                }
                            }
                            else
                            {
                                if (!firstHeaderWasSegment && (header.SegmentName != null))
                                {
                                    throw new InvalidDataException();
                                }
                            }
                            firstHeader = false;

                            // process segment header records differently
                            if (header.SegmentName != null)
                            {
                                if (trace != null)
                                {
                                    trace.WriteLine("Header[SegmetName={0}, SegmentSerialNumber={1}]", header.SegmentName, header.SegmentSerialNumber);
                                }

                                if (structureType != PackArchiveStructureTypeManifest)
                                {
                                    throw new InvalidDataException(); // segment records not permitted in files structure
                                }

                                // do not write any files "archived" in the manifest
                                writeFiles = false;
                                fileDataOmitted = true;

                                currentSegmentName = header.SegmentName;
                                currentSegmentSerialNumber = header.SegmentSerialNumber;

                                continue;
                            }

                            // normal file header record processing

                            if (trace != null)
                            {
                                trace.WriteLine("Header[Path=\"{0}\", ESL={1}, Created={2}, LastWrite={3}, Attr={4}, Range={5}]", header.Subpath, header.EmbeddedStreamLength, header.CreationTimeUtc, header.LastWriteTimeUtc, (int)header.Attributes, header.Range);
                            }

                            FaultInstanceNode faultFileHeader = faultUnpackInternal.Select("FileHeader", header.Subpath);

                            // segment name and serial are written as a special header record.
                            // this is not exposed to caller; instead, each proper file record is
                            // annotated with the segment name and serial number.
                            header.SegmentName = currentSegmentName;
                            header.SegmentSerialNumber = currentSegmentSerialNumber;

                            string[] pathParts = header.Subpath.Split(new char[] { '\\' });
                            if (!pathParts[0].Equals("."))
                            {
                                throw new ApplicationException("Invalid relative path found in stream");
                            }
                            string fullPath = targetDirectory;
                            for (int i = 1; i < pathParts.Length; i++)
                            {
                                string pathPart = pathParts[i];
                                if (String.IsNullOrEmpty(pathPart) || (pathPart == ".") || (pathPart == ".."))
                                {
                                    throw new ApplicationException("Illegal step found in path");
                                }
                                fullPath = Path.Combine(fullPath, pathPart);
                                if (i == pathParts.Length - 2) // last directory component
                                {
                                    if (displayProgress)
                                    {
                                        if (!String.Equals(currentDisplayDirectory, fullPath))
                                        {
                                            currentDisplayDirectory = fullPath;
                                            WriteStatusLine(currentDisplayDirectory);
                                        }
                                    }

                                    if (writeFiles)
                                    {
                                        Directory.CreateDirectory(fullPath);
                                    }
                                }
                            }

                            if (String.Equals(header.Subpath, lastSubpath, StringComparison.OrdinalIgnoreCase))
                            {
                                // a file split into multiple ranges must have consistent range information
                                // for each entry.
                                if (((lastRange == null) != (header.Range == null))
                                    || (lastRange.TotalFileLength != header.Range.TotalFileLength)
                                    || (lastRange.End + 1 != header.Range.Start))
                                {
                                    if (trace != null)
                                    {
                                        trace.WriteLine("Error: inconsistent ranges, last={0}, current={1} (lastSubpath={2}, currentSubpath={3})", lastRange, header.Range, lastSubpath, header.Subpath);
                                    }
                                    throw new InvalidDataException();
                                }
                            }
                            lastSubpath = header.Subpath;
                            lastRange = header.Range;

                            if (!fileDataOmitted) // i.e. not a manifest
                            {
                                byte[] fileDataCheckValue;
                                using (CheckedReadStream checkedStream = new CheckedReadStream(stream, new CRC32()))
                                {
                                    bool directory = (header.Attributes & PackedFileHeaderRecord.HeaderAttributes.Directory) != 0;
                                    if (writeFiles && directory)
                                    {
                                        Directory.CreateDirectory(fullPath);
                                    }

                                    Stream output;
                                    if (writeFiles && !directory)
                                    {
                                        if (header.Range == null)
                                        {
                                            output = null;

                                            // for simple files - always create (fail if it exists)
                                            try
                                            {
                                                output = new FileStream(fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                                                if (trace != null)
                                                {
                                                    trace.WriteLine("  [simple] created \"{0}\"", fullPath);
                                                }
                                            }
                                            catch (Exception exception)
                                            {
                                                // permit file to exist if "resume" specified - do nothing (outputX remains null)
                                                if (resume)
                                                {
                                                    long length = GetFileLengthNoError(fullPath);
                                                    if (length != header.EmbeddedStreamLength)
                                                    {
                                                        // File may have been written incompletely - rewrite
                                                        // (It could also be some old or updated version fo the file -
                                                        // but we're assuming user knows what he's doing of specifying
                                                        // "resume" mode.)
                                                        output = new FileStream(fullPath, FileMode.Create, FileAccess.Write, FileShare.None);
                                                        if (trace != null)
                                                        {
                                                            trace.WriteLine("  [simple] replaced \"{0}\" (old length {1}) [resume mode]", fullPath, length);
                                                        }
                                                    }
                                                    else
                                                    {
                                                        if (trace != null)
                                                        {
                                                            trace.WriteLine("  [simple] skipped preexisting \"{0}\" (old length={1}) [resume mode]", fullPath, length);
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    if (trace != null)
                                                    {
                                                        trace.WriteLine("  [simple] failed: \"{0}\"", exception.Message);
                                                    }
                                                    throw; // for non-"resume": always an error if file already exists
                                                }
                                            }
                                        }
                                        else
                                        {
                                            // for ranged files - create if needed or open existing.
                                            // it would be nice to use FileMode.CreateNew for the first segment and
                                            // FileMode.Open for subsequent ones, since that would be more precise,
                                            // but since ranges span archive segments, this method will exit and be
                                            // reinvoked between ranges, and plumbing the state up to the top level
                                            // caller to check for this is not worth it.

                                            // IMPORTANT: for the following to work, all ranged segments applying to a
                                            // given target file must be done SERIALIZED and IN ORDER, so that the
                                            // file length is always a correct indicator of what has not been done yet.
                                            // This is the responsibility of the caller that has specified
                                            // UnpackMode.Unpack, which is currently ValidateOrUnpackDynamicInternal().

                                            // if "resume" specified, we detect whether the file was completely
                                            // written by comparing the file's length with the range length.
                                            // (do not check timestamps because they may be incorrect if code was aborted
                                            // while in the loop below, i.e. before timestamp setting part is reached.
                                            // we assume the user knows what he's doing specifying "resume".)
                                            long length = GetFileLengthNoError(fullPath);
                                            if (length == header.Range.TotalFileLength)
                                            {
                                                if (trace != null)
                                                {
                                                    trace.WriteLine("  [ranged] skipped: \"{0}\" (old length={1})", fullPath, length);
                                                }
                                                output = null;
                                            }
                                            else
                                            {
                                                if (File.Exists(fullPath))
                                                {
                                                    if ((File.GetAttributes(fullPath) & FileAttributes.ReadOnly) != 0)
                                                    {
                                                        File.SetAttributes(fullPath, File.GetAttributes(fullPath) & ~FileAttributes.ReadOnly);
                                                        // will be restored again at end of this range write pass
                                                    }
                                                }

                                                if (trace != null)
                                                {
                                                    trace.WriteLine("  [ranged] updating: \"{0}\" (old length={1})", fullPath, length);
                                                }
                                                output = new FileStream(fullPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        output = null;
                                    }

                                    if (writeFiles && (header.Range != null) && (output != null))
                                    {
                                        if (output.Length < header.Range.Start)
                                        {
                                            if (trace != null)
                                            {
                                                trace.WriteLine("Range update failed: file length {0} less than range start {1} [probably previous segment missing or defect in sequencing code]", output.Length, header.Range.Start);
                                            }
                                            deferredExceptionsList.Add(new RangeSequenceException(String.Format("Update to file \"{0}\" failed - part of file content is missing", fullPath)));

                                            // cancel writing of this file
                                            output.Close();
                                            output = null;
                                        }
                                    }

                                    FaultInstanceNode faultWrite = faultFileHeader.Select("Write");
                                    FaultPredicate faultWritePosition = faultWrite.SelectPredicate("Position");

                                    using (output)
                                    {
                                        byte[] buffer = new byte[Constants.BufferSize];
                                        long length = header.EmbeddedStreamLength;
                                        if (directory && (length != 0))
                                        {
                                            throw new InvalidDataException();
                                        }
                                        if (writeFiles && (header.Range != null))
                                        {
                                            if (length != header.Range.Length)
                                            {
                                                throw new InvalidDataException();
                                            }
                                            if (output != null)
                                            {
                                                // Do not set file length [output.SetLength(header.Range.TotalFileLength);]
                                                // that is how we know how much has been written (for "resume" mode - see above)
                                                output.Position = header.Range.Start;
                                            }
                                        }
                                        while (length > 0)
                                        {
                                            long lengthOne = Math.Min(length, buffer.Length);
                                            int read = checkedStream.Read(buffer, 0, (int)lengthOne);
                                            if (read != lengthOne)
                                            {
                                                throw new IOException("Unexpected end of stream");
                                            }
                                            if (output != null)
                                            {
                                                output.Write(buffer, 0, (int)lengthOne);

                                                faultWritePosition.Test(output.Position);
                                            }
                                            length -= lengthOne;
                                        }

                                        if (output != null)
                                        {
                                            if (trace != null)
                                            {
                                                trace.WriteLine("  final: length={0}", output.Length);
                                            }
                                        }
                                    }

                                    checkedStream.Close();
                                    fileDataCheckValue = checkedStream.CheckValue;
                                }

                                if (writeFiles)
                                {
                                    try
                                    {
                                        if (header.CreationTimeUtc != default(DateTime))
                                        {
                                            File.SetCreationTimeUtc(fullPath, header.CreationTimeUtc);
                                        }
                                        if (header.LastWriteTimeUtc != default(DateTime))
                                        {
                                            File.SetLastWriteTime(fullPath, header.LastWriteTimeUtc);
                                        }
                                        // do this last - may include read-only
                                        File.SetAttributes(fullPath, File.GetAttributes(fullPath) | (PackedFileHeaderRecord.ToFileAttributes(header.Attributes) & ~FileAttributes.Directory));
                                    }
                                    catch (Exception exception)
                                    {
                                        if (trace != null)
                                        {
                                            trace.WriteLine("  exception updating timestamps and attributes: {0}", exception);
                                        }
                                    }
                                }

                                byte[] savedFileDataCheckValue = BinaryReadUtils.ReadBytes(stream, fileDataCheckValue.Length);
                                if (!ArrayEqual(fileDataCheckValue, savedFileDataCheckValue))
                                {
                                    throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied, "Individual archived file data check values do not match");
                                }
                            }

                            unpackedFileRecords.Add(new UnpackedFileRecord(fullPath, header));
                        }

                        BinaryReadUtils.RequireAtEOF(stream);
                    });


                if (displayProgress)
                {
                    EraseStatusLine();
                }

                segmentSerialNumberOut = segmentSerialNumber;
                randomArchiveSignatureOut = randomArchiveSignature;
                return unpackedFileRecords.ToArray();
            }
            catch (Exception exception)
            {
                if (trace != null)
                {
                    trace.Write("UnpackInternal exception occurred: {0}", exception);
                }
                throw;
            }
            finally
            {
                deferredExceptions = deferredExceptionsList.Count > 0 ? deferredExceptionsList.ToArray() : null;
            }
        }

        internal static void Unpack(string sourceFile, string targetDirectory, Context context)
        {
            ulong segmentSerialNumber;
            byte[] randomArchiveSignature;
            ApplicationException[] deferredExceptions;
            using (Stream fileStream = new FileStream(sourceFile, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                UnpackInternal(fileStream, targetDirectory, context, UnpackMode.Unpack | UnpackMode.ShowProgress, out segmentSerialNumber, out randomArchiveSignature, null/*trace*/, context.faultInjectionRoot.Select("UnpackInternal"), out deferredExceptions);
            }
            if (deferredExceptions != null)
            {
                throw new DeferredMultiException(deferredExceptions);
            }
        }

        internal static void Dumppack(string sourcePattern, Context context)
        {
            FaultInstanceNode faultDumppack = context.faultInjectionRoot.Select("Dumppack");

            string fileName;
            bool remote;
            using (IArchiveFileManager fileManager = GetArchiveFileManager(sourcePattern, out fileName, out remote, context))
            {
                List<string> sourceFileList = new List<string>();
                if (FileNamePatternMatch.ContainsWildcards(sourcePattern))
                {
                    FileNamePatternMatch matcher = new FileNamePatternMatch(Path.GetFileName(sourcePattern));
                    foreach (string file in fileManager.GetFileNames(null, fileManager.GetMasterTrace()))
                    {
                        if (matcher.IsMatch(file))
                        {
                            sourceFileList.Add(file);
                        }
                    }
                }
                else
                {
                    sourceFileList.Add(fileName);
                }

                foreach (string sourceFile in sourceFileList)
                {
                    if (sourceFileList.Count > 1)
                    {
                        Console.WriteLine("FILE: \"{0}\"", sourceFile);
                    }

                    ulong serialNumber;
                    byte[] randomArchiveSignature;
                    UnpackedFileRecord[] files;
                    using (ILocalFileCopy fileRef = fileManager.Read(sourceFile, null/*progressTracker*/, fileManager.GetMasterTrace()))
                    {
                        using (Stream stream = fileRef.Read())
                        {
                            ApplicationException[] deferredExceptions;
                            files = UnpackInternal(stream, ".", context, UnpackMode.Parse, out serialNumber, out randomArchiveSignature, null/*trace*/, faultDumppack, out deferredExceptions);
                            if (deferredExceptions != null)
                            {
                                throw new DeferredMultiException(deferredExceptions);
                            }
                        }
                    }

                    Console.WriteLine("SERIAL: {0}; SIGNATURE: {1}", serialNumber, Logging.ScrubSecuritySensitiveValue(randomArchiveSignature));

                    int index = 0;
                    string lastSegment = null;
                    foreach (UnpackedFileRecord file in files)
                    {
                        if (!String.Equals(lastSegment, file.SegmentName))
                        {
                            lastSegment = file.SegmentName;
                            Console.WriteLine(" [{0}: {1}]", lastSegment, file.SegmentSerialNumber);
                        }

                        string attrs = String.Empty;
                        foreach (KeyValuePair<PackedFileHeaderRecord.HeaderAttributes, char> symbol in PackedFileHeaderRecord.AttributeSymbolMapping)
                        {
                            attrs = attrs + ((file.Attributes & symbol.Key) != 0 ? new String(symbol.Value, 1) : "-");
                        }

                        const string TimeStampFormat = "s";

                        Console.WriteLine(" {5,8} {0,-6} {1} {2} {3} {4}",
                            FileSizeString(file.TotalFileLength),
                            file.CreationTimeUtc.ToLocalTime().ToString(TimeStampFormat),
                            file.LastWriteTimeUtc.ToLocalTime().ToString(TimeStampFormat),
                            attrs,
                            file.ArchivePath,
                            ++index);
                        if (file.Range != null)
                        {
                            Console.WriteLine("   {0}", file.Range);
                        }
                    }

                    if (sourceFileList.Count > 1)
                    {
                        Console.WriteLine();
                    }
                }
            }
        }

        private const string DynPackManifestName = "0";
        private const string DynPackManifestNameOld = "-0";

        private const string DynPackFileExtension = ".dynpack";
        private const string DynPackTempFileExtension = ".tmp";

        private const string DynPackTraceFilePrefix = "dynpacktrace";
        private const string DynUnpackTraceFilePrefix = "dynunpacktrace";
        private const string DynPackManifestLogFileExtension = ".log";
        private const string DynPackManifestLogFileExtensionOld = ".previous.log";

        public abstract class FilePath /*: IComparable<FilePath>, IEquatable<FilePath>*/
        {
            public abstract string Step { get; }
            public abstract FilePath Parent { get; }

            private const int StepsToReserve = 8;
            public override string ToString()
            {
                string[] steps = Steps();

                int chars = -1; // no separator at start of path
                for (int i = 0; i < steps.Length; i++)
                {
                    chars = chars + 1/*separator*/ + steps[i].Length;
                }

                StringBuilder builder = new StringBuilder(chars);
                builder.Append(steps[0]);
                for (int i = 1; i < steps.Length; i++)
                {
                    builder.Append('\\');
                    builder.Append(steps[i]);
                }
                if (chars != builder.Length)
                {
                    throw new InvalidOperationException("Defect in FilePathBase.ToString()");
                }
                return builder.ToString();
            }

            //public static implicit operator string(FilePath path)
            //{
            //    return path.ToString();
            //}

            //public override int GetHashCode()
            //{
            //    return ToString().GetHashCode();
            //}

            //public override bool Equals(object obj)
            //{
            //    FilePath other;
            //    if ((other = obj as FilePath) != null)
            //    {
            //        return String.Equals(this.ToString(), other.ToString());
            //    }
            //    return base.Equals(obj);
            //}

            //int IComparable<FilePath>.CompareTo(FilePath other)
            //{
            //    List<FilePath> leftSteps = new List<FilePath>(StepsToReserve);
            //    List<FilePath> rightSteps = new List<FilePath>(StepsToReserve);
            //    FilePath step;
            //    step = this;
            //    while (step != null)
            //    {
            //        leftSteps.Add(step);
            //        step = step.Parent();
            //    }
            //    step = other;
            //    while (step != null)
            //    {
            //        rightSteps.Add(step);
            //        step = step.Parent();
            //    }
            //    int left = leftSteps.Count - 1;
            //    int right = rightSteps.Count - 1;
            //    while ((left >= 0) && (right >= 0))
            //    {
            //        int stepCompare = String.Compare(leftSteps[left].Step(), rightSteps[right].Step(), StringComparison.OrdinalIgnoreCase);
            //        if (stepCompare != 0)
            //        {
            //            return stepCompare;
            //        }
            //    }
            //    if (left > 0)
            //    {
            //        return 1;
            //    }
            //    else if (right > 0)
            //    {
            //        return -1;
            //    }
            //    return 0;
            //}

            //bool IEquatable<FilePath>.Equals(FilePath other)
            //{
            //    return 0 == ((IComparable<FilePath>)this).CompareTo(other);
            //}

            public string[] Steps()
            {
                int stepCount = 0;

                FilePath step = this;
                while (step != null)
                {
                    stepCount++;
                    step = step.Parent;
                }

                string[] steps = new string[stepCount];

                int i = stepCount - 1;
                step = this;
                while (step != null)
                {
                    steps[i--] = step.Step;
                    step = step.Parent;
                }

                return steps;
            }

            public static FilePath Create(FilePath parent, string file)
            {
                return new FilePathItem(parent, file);
            }

            public static FilePath Create(string path)
            {
                return (new FilePathItem.Factory()).Create(path); // create one-off
            }

            public static FilePath Create(FilePathItem.Factory factory, string path)
            {
                return factory.Create(path);
            }
        }

        private class FilePathRoot : FilePath
        {
            private readonly string file;

            public FilePathRoot(string file)
            {
                this.file = file;
            }

            public override string Step { get { return file; } }
            public override FilePath Parent { get { return null; } }
        }

        public class FilePathItem : FilePath
        {
            private readonly FilePath parent;
            private readonly string file;

            public FilePathItem(FilePath parent, string file)
            {
                this.parent = parent;
                this.file = file;
            }

            public override string Step { get { return file; } }
            public override FilePath Parent { get { return parent; } }

            public class Factory // last used item
            {
                private List<FilePath> current = new List<FilePath>();

                public FilePath Create(string path)
                {
                    string[] steps = path.Split(new char[] { '\\' });

                    int i;
                    for (i = 0; (i < current.Count) && (i < steps.Length); i++)
                    {
                        if (!steps[i].Equals(current[i].Step, StringComparison.OrdinalIgnoreCase))
                        {
                            break;
                        }
                    }

                    FilePath step = null;
                    if (i > 0)
                    {
                        step = current[i - 1];
                    }

                    current.RemoveRange(i, current.Count - i);
                    for (; i < steps.Length; i++)
                    {
                        step = i == 0 ? (FilePath)new FilePathRoot(steps[i]) : (FilePath)new FilePathItem(step, steps[i]);
                        current.Add(step);
                    }

                    if (!step.ToString().Equals(path, StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException("Defect in FilePathItem.Factory.Create(string)");
                    }

                    return step;
                }
            }
        }

        private static int dynpackDiagnosticSerialNumberGenerator;

        private class SegmentRecord
        {
            private string name;
            private OneWaySwitch dirty = new OneWaySwitch();
            internal int? start;
            private readonly int diagnosticSerialNumber = Interlocked.Increment(ref dynpackDiagnosticSerialNumberGenerator);
            private ulong serialNumber;

            internal SegmentRecord()
            {
                dirty.Set();
            }

            internal SegmentRecord(string Name, ulong serialNumber)
            {
                this.name = Name;
                this.serialNumber = serialNumber;
            }

            internal string Name
            {
                get
                {
                    return name;
                }

                set
                {
                    name = value;
                    dirty.Set();
                }
            }

            internal OneWaySwitch Dirty
            {
                get
                {
                    return dirty;
                }
            }

            internal ulong SerialNumber
            {
                get
                {
                    if (serialNumber == 0)
                    {
                        // program defect - number was never set properly
                        throw new InvalidOperationException();
                    }
                    return serialNumber;
                }
                set
                {
                    serialNumber = value;
                }
            }

            internal string DiagnosticSerialNumber
            {
                get
                {
                    byte[] four = new byte[4];
                    four[0] = (byte)(diagnosticSerialNumber >> 24);
                    four[1] = (byte)(diagnosticSerialNumber >> 16);
                    four[2] = (byte)(diagnosticSerialNumber >> 8);
                    four[3] = (byte)diagnosticSerialNumber;
                    return String.Concat("seg0x", HexEncode(four));
                }
            }
        }

        private class FileRecord
        {
            private SegmentRecord segment;
            private readonly PackedFileHeaderRecord header;
            private readonly int headerOverhead;

            private readonly int diagnosticSerialNumber = Interlocked.Increment(ref dynpackDiagnosticSerialNumberGenerator);

            internal FileRecord(SegmentRecord segment, FilePath partialPath, DateTime creationTimeUtc, DateTime lastWriteTimeUtc, PackedFileHeaderRecord.HeaderAttributes attributes, long embeddedStreamLength, PackedFileHeaderRecord.RangeRecord range)
            {
                this.segment = segment;
                this.header = new PackedFileHeaderRecord(partialPath, creationTimeUtc, lastWriteTimeUtc, attributes, embeddedStreamLength, range);
                headerOverhead = header.GetHeaderLength();
            }

            internal FileRecord(FileRecord original)
                : this(original.Segment, original.PartialPath, original.CreationTimeUtc, original.LastWriteTimeUtc, original.Attributes, original.EmbeddedStreamLength, original.Range)
            {
            }

            private FileRecord()
            {
                throw new NotSupportedException();
            }

            internal SegmentRecord Segment
            {
                get
                {
                    return segment;
                }

                set
                {
                    segment = value;
                }
            }

            internal FilePath PartialPath
            {
                get
                {
                    return (FilePath)header.SubpathObject;
                }
            }

            internal DateTime CreationTimeUtc
            {
                get
                {
                    return header.CreationTimeUtc;
                }
            }

            internal DateTime LastWriteTimeUtc
            {
                get
                {
                    return header.LastWriteTimeUtc;
                }
            }

            internal PackedFileHeaderRecord.HeaderAttributes Attributes
            {
                get
                {
                    return header.Attributes;
                }
            }

            internal long EmbeddedStreamLength
            {
                get
                {
                    return header.EmbeddedStreamLength;
                }
            }

            internal int HeaderOverhead
            {
                get
                {
                    return headerOverhead;
                }
            }

            internal PackedFileHeaderRecord.RangeRecord Range
            {
                get
                {
                    return header.Range;
                }
            }

            internal void WriteHeader(Stream stream)
            {
                header.SegmentName = null;
                header.SegmentSerialNumber = 0;

                header.Write(stream);
            }

            internal string DiagnosticSerialNumber
            {
                get
                {
                    byte[] four = new byte[4];
                    four[0] = (byte)(diagnosticSerialNumber >> 24);
                    four[1] = (byte)(diagnosticSerialNumber >> 16);
                    four[2] = (byte)(diagnosticSerialNumber >> 8);
                    four[3] = (byte)diagnosticSerialNumber;
                    return String.Concat("file0x", HexEncode(four));
                }
            }
        }

        private static void ItemizeFilesRecursive(List<FileRecord> files, string sourceRootDirectory, long? largeFileSegmentSize, Context context, InvariantStringSet excludedExtensions, InvariantStringSet excludedItems, FilePath partialPathPrefix)
        {
            WriteStatusLine(sourceRootDirectory);

            List<string> subdirectories = new List<string>();
            bool driveRoot = IsDriveRoot(sourceRootDirectory);
            foreach (string file in DoRetryable<string[]>(delegate { return Directory.GetFileSystemEntries(sourceRootDirectory); }, delegate { return new string[0]; }, null, context))
            {
                if (!driveRoot || !IsExcludedDriveRootItem(file))
                {
                    FileAttributes fileAttributes = DoRetryable<FileAttributes>(delegate { return File.GetAttributes(file); }, delegate { return FileAttributes.Normal; }, null, context);
                    if ((fileAttributes & FileAttributes.Directory) != 0)
                    {
                        subdirectories.Add(file);
                    }
                    else
                    {
                        if (!excludedItems.Contains(file.ToLowerInvariant())
                            && !excludedExtensions.Contains(Path.GetExtension(file).ToLowerInvariant()))
                        {
                            long inputStreamLength = GetFileLengthRetriable(file, context);
                            if (inputStreamLength >= 0)
                            {
                                FilePath partialPath = FilePathItem.Create(partialPathPrefix, Path.GetFileName(file));
                                DateTime creationTimeUtc = File.GetCreationTimeUtc(file);
                                DateTime lastWriteTimeUtc = File.GetLastWriteTimeUtc(file);
                                PackedFileHeaderRecord.HeaderAttributes attributes = PackedFileHeaderRecord.ToHeaderAttributes(File.GetAttributes(file));
                                Debug.Assert((creationTimeUtc == PackedFileHeaderRecord.ParseDateTime(PackedFileHeaderRecord.FormatDateTime(creationTimeUtc)))
                                    && (lastWriteTimeUtc == PackedFileHeaderRecord.ParseDateTime(PackedFileHeaderRecord.FormatDateTime(lastWriteTimeUtc))));

                                if (!largeFileSegmentSize.HasValue || (inputStreamLength <= largeFileSegmentSize.Value))
                                {
                                    files.Add(new FileRecord(null/*segment*/, partialPath, creationTimeUtc, lastWriteTimeUtc, attributes, inputStreamLength, null/*range*/));
                                }
                                else
                                {
                                    // split file into ranges
                                    long currentStart = 0;
                                    while (currentStart < inputStreamLength)
                                    {
                                        long currentLength = Math.Min(inputStreamLength - currentStart, largeFileSegmentSize.Value);
                                        long currentEnd = currentStart + currentLength - 1;
                                        files.Add(new FileRecord(null/*segment*/, partialPath, creationTimeUtc, lastWriteTimeUtc, attributes, currentLength, new PackedFileHeaderRecord.RangeRecord(currentStart, currentEnd, inputStreamLength)));
                                        currentStart += largeFileSegmentSize.Value;
                                    }
                                }
                            }
                            else
                            {
                                EraseStatusLine();
                                Console.WriteLine("  SKIPPED FILE - UNREADABLE: {0}", file);
                            }
                        }
                        else
                        {
                            EraseStatusLine();
                            Console.WriteLine("  SKIPPED FILE: {0}", file);
                        }
                    }
                }
            }

            foreach (string subdirectory in subdirectories)
            {
                if (!excludedItems.Contains(subdirectory.ToLowerInvariant()))
                {
                    int initialFilesCount = files.Count;

                    ItemizeFilesRecursive(files, subdirectory, largeFileSegmentSize, context, excludedExtensions, excludedItems, FilePathItem.Create(partialPathPrefix, Path.GetFileName(subdirectory)));

                    // for subdirectories, only if it is empty add it explicitly
                    if (initialFilesCount == files.Count)
                    {
                        files.Add(new FileRecord(null/*segment*/, FilePathItem.Create(partialPathPrefix, Path.GetFileName(subdirectory)), default(DateTime), default(DateTime), PackedFileHeaderRecord.ToHeaderAttributes(File.GetAttributes(subdirectory)), 0, null/*range*/));
                    }
                }
                else
                {
                    EraseStatusLine();
                    Console.WriteLine("  SKIPPED SUBDIRECTORY: {0}", subdirectory);
                }
            }
        }

        private static int DynPackPathComparePartialPathOnly(FileRecord l, FileRecord r)
        {
            int c;

            string[] lParts = l.PartialPath.Steps();
            string[] rParts = r.PartialPath.Steps();
            int i;
            for (i = 0; i < Math.Min(lParts.Length, rParts.Length) - 1; i++)
            {
                c = String.Compare(lParts[i], rParts[i], StringComparison.OrdinalIgnoreCase);
                if (c != 0)
                {
                    return c;
                }
            }

            c = lParts.Length.CompareTo(rParts.Length);
            if (c != 0)
            {
                return c;
            }

            for (; i < lParts.Length; i++)
            {
                c = String.Compare(lParts[i], rParts[i], StringComparison.OrdinalIgnoreCase);
                if (c != 0)
                {
                    return c;
                }
            }

            return 0;
        }

        private static int DynPackPathCompareWithRange(FileRecord l, FileRecord r)
        {
            int c;

            c = DynPackPathComparePartialPathOnly(l, r);
            if (c != 0)
            {
                return c;
            }

            if (r.Range != null)
            {
                if (l.Range == null)
                {
                    return -1;
                }
                c = l.Range.Start.CompareTo(r.Range.Start);
                if (c != 0)
                {
                    return c;
                }
            }

            return 0;
        }

        private static int DynPackSegmentNameCompare(string l, string r)
        {
            while (l.Length < r.Length)
            {
                l = l + 'a';
            }
            while (r.Length < l.Length)
            {
                r = r + 'a';
            }
            return l.CompareTo(r);
        }

        // segment names are like the fractional part of a decimal number, but base 26 (letters)
        private static string DynPackMakeSegmentNameBetween(string l, string r)
        {
            if (!(DynPackSegmentNameCompare(l, r) < 0))
            {
                throw new ApplicationException(String.Format("Segment order error: {0} {1}", l, r));
            }
            while (l.Length < r.Length)
            {
                l = l + 'a';
            }
            while (r.Length < l.Length)
            {
                r = r + 'a';
            }

            string s = String.Empty;
            {
                int[] s2 = new int[l.Length + 1];

                // add
                bool carry = false;
                for (int i = l.Length - 1; i >= 0; i--)
                {
                    int l1 = l[i] - 'a';
                    int r1 = r[i] - 'a';
                    int lr1 = l1 + r1 + (carry ? 1 : 0);
                    carry = lr1 >= 26;
                    if (carry)
                    {
                        lr1 -= 26;
                    }
                    s2[i + 1] = lr1;
                }
                s2[0] = carry ? 1 : 0;

                // divide by 2
                bool borrow = false;
                for (int i = 0; i < s2.Length; i++)
                {
                    bool borrow2 = s2[i] % 2 != 0;
                    s2[i] = (s2[i] + (borrow ? 26 : 0)) / 2;
                    borrow = borrow2;
                }

                for (int i = 1; i < s2.Length; i++)
                {
                    s = s + (char)('a' + s2[i]);
                }
            }

            if (s.Equals(r))
            {
                throw new ApplicationException(String.Format("Impossible: {0} {1} {2}", l, r, s));
            }
            if (s.Equals(l))
            {
                s = s + 'm';
            }

            while (s.Length > 1)
            {
                string ss = s.Substring(0, s.Length - 1);
                if (!(DynPackSegmentNameCompare(l, ss) < 0))
                {
                    break;
                }
                s = ss;
            }
            while ((s.Length > 1) && (s[s.Length - 1] == 'a'))
            {
                s = s.Substring(0, s.Length - 1);
            }

            return s;
        }

        private static void DynPackMakeSegmentNamesBetweenRecursive(string[] s, int first, int last)
        {
            int mid = (first + last) / 2;
            if (first < mid)
            {
                s[mid] = DynPackMakeSegmentNameBetween(s[first], s[last]);
                DynPackMakeSegmentNamesBetweenRecursive(s, first, mid);
                DynPackMakeSegmentNamesBetweenRecursive(s, mid, last);
            }
        }

        private static string[] DynPackMakeSegmentNamesBetween(string l, string r, int count)
        {
            string[] s = new string[count + 2];
            s[0] = l;
            s[count + 2 - 1] = r;
            DynPackMakeSegmentNamesBetweenRecursive(s, 0, count + 2 - 1);
            string[] ss = new string[count];
            Array.Copy(s, 1, ss, 0, count);
            return ss;
        }

        private static bool FatalPromptContinue(ConcurrentTasks concurrent, ConcurrentMessageLog messagesLog, ConcurrentTasks.WaitIntervalMethod waitIntervalMethod, int waitInterval, ConcurrentMessageLog.PrepareConsoleMethod prepareConsole)
        {
            concurrent.Drain(waitIntervalMethod, waitInterval);
            if (prepareConsole != null)
            {
                prepareConsole();
            }
            messagesLog.Flush();

            ConsoleColor oldColor = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("q)uit or c)ontinue: ");
            Console.ForegroundColor = oldColor;
            while (true)
            {
                char key = WaitReadKey(false/*intercept*/);
                Console.WriteLine();
                if (key == 'q')
                {
                    return false;
                }
                else if (key == 'c')
                {
                    return true;
                }
            }
        }

        internal static void DynamicPack(string source, string targetArchivePathTemplate, long segmentSizeTarget, Context context, string[] args)
        {
            const int WaitInterval = 2000; // milliseconds
            const string DynPackDiagnosticDateTimeFormat = "yyyy-MM-ddTHH:mm:ss";
            const int SegmentFixedOverhead = (256 / 8/*SHA256 length*/) + PackedFileHeaderRecord.HeaderTokenLength;

            FaultInstanceNode faultDynamicPack = context.faultInjectionRoot.Select("DynamicPack");

            ulong segmentSerialNumbering = 0;
            byte[] randomArchiveSignature = new byte[PackRandomSignatureLengthBytes];
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                rng.GetBytes(randomArchiveSignature);
            }

            segmentSizeTarget -= SegmentFixedOverhead;
            // segmentSizeTarget is only approximate anyway and may be exceeded due to
            // encryption/validation and compression potential compression overhead.


            // options (and their defaults)
            bool safe = true;
            long? largeFileSegmentSize = segmentSizeTarget;
            bool verifyNonDirtyMetadata = false;
            string diagnosticPath = null;
            bool windiff = false;

            {
                bool parsed = true;
                while (parsed && (args.Length > 0))
                {
                    parsed = true;
                    switch (args[0])
                    {
                        default:
                            parsed = false;
                            break;
                        case "-nosplitlargefiles":
                            {
                                largeFileSegmentSize = null;

                                bool split;
                                GetAdHocArgument(ref args, "-nosplitlargefiles", true/*default*/, false/*explicit*/, out split);
                                if (split)
                                {
                                    largeFileSegmentSize = segmentSizeTarget;
                                }
                            }
                            break;
                        case "-unsafe":
                            GetAdHocArgument(ref args, "-unsafe", true/*default*/, false/*explicit*/, out safe);
                            break;
                        case "-verify":
                            GetAdHocArgument(ref args, "-verify", false/*default*/, true/*explicit*/, out verifyNonDirtyMetadata);
                            break;
                        case "-logpath":
                            GetAdHocArgument(ref args, "-logpath", null/*default*/, delegate(string s) { return s; }, out diagnosticPath);
                            break;
                        case "-windiff":
                            GetAdHocArgument(ref args, "-windiff", false/*default*/, true/*explicit*/, out windiff);
                            break;
                    }
                }
            }

            InvariantStringSet excludedExtensions;
            InvariantStringSet excludedItems;
            GetExclusionArguments(args, out excludedExtensions, false/*relative*/, out excludedItems);

            if (!Directory.Exists(source))
            {
                throw new UsageException();
            }


            TextWriter traceDynpack = context.traceEnabled ? Logging.CreateLogFile(DynPackTraceFilePrefix) : null;


            // build current file list
            List<FileRecord> currentFiles = new List<FileRecord>();
            ItemizeFilesRecursive(currentFiles, source, largeFileSegmentSize, context, excludedExtensions, excludedItems, FilePathItem.Create("."));
            EraseStatusLine();
            if (traceDynpack != null)
            {
                traceDynpack.WriteLine("Current Files:");
                for (int i = 0; i < currentFiles.Count; i++)
                {
                    FileRecord record = currentFiles[i];
                    traceDynpack.WriteLine("    {5,-8} {6} {0}{4} {1} {2} {3}", record.EmbeddedStreamLength, record.CreationTimeUtc, record.LastWriteTimeUtc, record.PartialPath, record.Range != null ? String.Format("[{0}]", record.Range) : String.Empty, i, record.DiagnosticSerialNumber);
                }
                traceDynpack.WriteLine();
                traceDynpack.Flush();
            }

            string targetArchiveFileNameTemplate;
            bool remote;
            using (IArchiveFileManager fileManager = GetArchiveFileManager(targetArchivePathTemplate, out targetArchiveFileNameTemplate, out remote, context))
            {
                if (remote && (context.cryptoOption != EncryptionOption.Encrypt) && !context.overrideRemoteSecurityBlock)
                {
                    throw new ApplicationException("You have specified storage on a remote service without any encryption. This is regarded as insecure and dangerous and is blocked by default. If you really mean to do this (and if so we suggest you reconsider), use the -overridesecurityblock option to bypass this block.");
                }

                // Read old manifest (if any)
                //
                // Note: there's a two-phase commit process that occurs with respect to the manifest
                // throughout this code.
                //  1. old segments incl. manifest are renamed, e.g. foo.0.dynpack --> foo.-0.dynpack
                //  2. new files are generated
                //  3. old files (foo.-*.dynpack) are deleted.
                // Even if "!safe", the manifest will still be backed up to foo.-0.dynpack.
                // This means if the code or system fails after backing up but before writing the new
                // manifest, the next time the program is run, the old manifest (foo.-0.dynpack) can
                // be loaded if the new file is missing.
                List<SegmentRecord> segments = new List<SegmentRecord>();
                List<FileRecord> previousFiles = new List<FileRecord>();
                string manifestFileName = String.Concat(targetArchiveFileNameTemplate, ".", DynPackManifestName, DynPackFileExtension);
                {
                    string manifestFileNameOld = String.Concat(targetArchiveFileNameTemplate, ".", DynPackManifestNameOld, DynPackFileExtension);
                    bool manifestFileNameExists = fileManager.Exists(manifestFileName, fileManager.GetMasterTrace());
                    bool manifestFileNameOldExists = fileManager.Exists(manifestFileNameOld, fileManager.GetMasterTrace());
                    if (manifestFileNameExists || manifestFileNameOldExists)
                    {
                        string manifestFileNameActual = manifestFileName;
                        Console.WriteLine("Reading: {0}", manifestFileName);
                        if (!manifestFileNameExists)
                        {
                            manifestFileNameActual = manifestFileNameOld;
                            Console.WriteLine("Manifest file {0} does not exist, reading backup copy {1}", manifestFileName, manifestFileNameOld);
                        }

                        Dictionary<string, SegmentRecord> segmentMap = new Dictionary<string, SegmentRecord>();

                        using (ILocalFileCopy fileRef = fileManager.Read(manifestFileNameActual, null/*progressTracker*/, fileManager.GetMasterTrace()))
                        {
                            using (Stream fileStream = fileRef.Read())
                            {
                                CryptoKeygroup keysManifest = null;
                                EncryptedFileContainerHeader fchManifest = null;
                                if (context.cryptoOption == EncryptionOption.Encrypt)
                                {
                                    fchManifest = new EncryptedFileContainerHeader(fileStream, true/*peek*/, context.encrypt);
                                    context.encrypt.algorithm.DeriveSessionKeys(context.encrypt.GetMasterKeyEntry(fchManifest.passwordSalt, fchManifest.rfc2898Rounds).MasterKey, fchManifest.fileSalt, out keysManifest);
                                }

                                // Using Moxie Marlinspike's "doom principle": validate the MAC before ANY other
                                // action is taken. (http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/)
                                bool macValidated = false;
                                if (!context.doNotPreValidateMAC && (context.cryptoOption != EncryptionOption.None))
                                {
                                    DoWithStreamStack(
                                        fileStream,
                                        new StreamWrapMethod[]
                                        {
                                            delegate(Stream stream)
                                            {
                                                // see note and references about
                                                // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                                return new TaggedReadStream(stream, context.encrypt.algorithm.CreateMACGenerator(keysManifest.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                            },
                                        },
                                        delegate(Stream stream)
                                        {
                                            ReadAndDiscardEntireStream(stream);
                                        });

                                    macValidated = true;
                                }

                                fileStream.Position = 0;

                                DoWithStreamStack(
                                    fileStream,
                                    new StreamWrapMethod[]
                                    {
                                        delegate(Stream stream)
                                        {
                                            // see note and references about
                                            // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                            if (context.cryptoOption == EncryptionOption.Encrypt)
                                            {
                                                if (!macValidated)
                                                {
                                                    return new TaggedReadStream(stream, context.encrypt.algorithm.CreateMACGenerator(keysManifest.SigningKey), "File cryptographic signature values do not match - data is either corrupt or tampered with. Do not trust contents!");
                                                }
                                                else
                                                {
                                                    return new ReadStreamHoldShort(stream, context.encrypt.algorithm.MACLengthBytes);
                                                }
                                            }
                                            return null;
                                        },
                                        delegate(Stream stream)
                                        {
                                            if (context.cryptoOption == EncryptionOption.Encrypt)
                                            {
                                                // why re-read here? need to read salt within HMAC container
                                                EncryptedFileContainerHeader fch2 = new EncryptedFileContainerHeader(stream, false/*peek*/, context.encrypt);
                                                if (!fch2.Equals(fchManifest))
                                                {
                                                    throw new InvalidOperationException();
                                                }
                                            }
                                            return null;
                                        },
                                        delegate(Stream stream)
                                        {
                                            if (context.cryptoOption == EncryptionOption.Encrypt)
                                            {
                                                return context.encrypt.algorithm.CreateDecryptStream(stream, keysManifest.CipherKey, keysManifest.InitialCounter);
                                            }
                                            return null;
                                        },
                                        delegate(Stream stream)
                                        {
                                            if (context.compressionOption == CompressionOption.Compress)
                                            {
                                                return new BlockedDecompressStream(stream);
                                            }
                                            return null;
                                        },
                                        delegate(Stream stream)
                                        {
                                            // total file CRC32 check value
                                            return new TaggedReadStream(stream, new CRC32(), "File check values do not match - file is damaged");
                                        }
                                    },
                                    delegate(Stream stream)
                                    {
                                        byte[] headerNumber = BinaryReadUtils.ReadBytes(stream, 1);
                                        if (headerNumber[0] != PackArchiveFixedHeaderNumber)
                                        {
                                            throw new InvalidDataException(); // unrecognized format
                                        }

                                        randomArchiveSignature = BinaryReadUtils.ReadVariableLengthByteArray(stream);

                                        segmentSerialNumbering = BinaryReadUtils.ReadVariableLengthQuantityAsUInt64(stream);

                                        int structureType = BinaryReadUtils.ReadVariableLengthQuantityAsInt32(stream);
                                        if (structureType != PackArchiveStructureTypeManifest)
                                        {
                                            throw new InvalidDataException(); // must be manifest structure
                                        }

                                        FilePathItem.Factory pathFactory = new FilePathItem.Factory();
                                        string currentSegmentName = null;
                                        ulong currentSegmentSerialNumber = 0;
                                        bool firstHeader = true;
                                        bool firstHeaderWasSegment = false;
                                        while (true)
                                        {
                                            byte[] startToken = BinaryReadUtils.ReadBytes(stream, PackedFileHeaderRecord.HeaderTokenLength);
                                            if (!PackedFileHeaderRecord.ValidFileHeaderToken(startToken))
                                            {
                                                throw new InvalidDataException("Unexpected value for start token");
                                            }

                                            PackedFileHeaderRecord header = PackedFileHeaderRecord.Read(stream, false/*strict*/, context.now);
                                            if (header == PackedFileHeaderRecord.NullHeaderRecord)
                                            {
                                                break;
                                            }

                                            // if any segment headers exist (== manifest file), the first record in file must be one
                                            if (firstHeader)
                                            {
                                                if (header.SegmentName != null)
                                                {
                                                    firstHeaderWasSegment = true;
                                                }
                                            }
                                            else
                                            {
                                                if (!firstHeaderWasSegment && (header.SegmentName != null))
                                                {
                                                    throw new InvalidDataException();
                                                }
                                            }
                                            firstHeader = false;

                                            // process segment header records differently
                                            if (header.SegmentName != null)
                                            {
                                                currentSegmentName = header.SegmentName;
                                                currentSegmentSerialNumber = header.SegmentSerialNumber;

                                                continue;
                                            }

                                            // normal file header record processing

                                            // segment name and serial are written as a special header record.
                                            // this is not exposed to caller; instead, each proper file record is
                                            // annotated with the segment name and serial number.
                                            header.SegmentName = currentSegmentName;
                                            header.SegmentSerialNumber = currentSegmentSerialNumber;

                                            const string ExpectedPathPrefix = @".\";
                                            if (!header.Subpath.StartsWith(ExpectedPathPrefix))
                                            {
                                                throw new InvalidDataException("Invalid relative path found in manifest");
                                            }

                                            // this code really ought to be folded in with "currentSegmentName"
                                            // code above, but has been tested, so is left unchanged for now.
                                            string segmentName = header.SegmentName;
                                            if (segmentName == null)
                                            {
                                                throw new InvalidDataException("Missing segment name in manifest");
                                            }
                                            ulong segmentSerialNumber = header.SegmentSerialNumber;
                                            if (segmentSerialNumber == 0)
                                            {
                                                throw new InvalidDataException("Segment serial number not initialized");
                                            }
                                            if (segmentSerialNumber >= segmentSerialNumbering)
                                            {
                                                throw new InvalidDataException("Invalid segment serial number");
                                            }
                                            SegmentRecord segment;
                                            if (!segmentMap.TryGetValue(segmentName, out segment))
                                            {
                                                segment = new SegmentRecord(segmentName, segmentSerialNumber);
                                                segments.Add(segment);
                                                segmentMap.Add(segmentName, segment);
                                            }
                                            if (segment.SerialNumber != segmentSerialNumber)
                                            {
                                                throw new InvalidDataException("Segment serial number inconsistent");
                                            }

                                            previousFiles.Add(new FileRecord(segment, pathFactory.Create(header.Subpath), header.CreationTimeUtc, header.LastWriteTimeUtc, header.Attributes, header.EmbeddedStreamLength, header.Range));
                                        }

                                        BinaryReadUtils.RequireAtEOF(stream);
                                    });
                            }
                        }
                    }
                }
                if (traceDynpack != null)
                {
                    traceDynpack.WriteLine("Previous Files:");
                    for (int i = 0; i < previousFiles.Count; i++)
                    {
                        FileRecord record = previousFiles[i];
                        traceDynpack.WriteLine("    {5,-8} {6} {7}({8})  {0}{4} {1} {2} {3}", record.EmbeddedStreamLength, record.CreationTimeUtc, record.LastWriteTimeUtc, record.PartialPath, record.Range != null ? String.Format("[{0}]", record.Range) : String.Empty, i, record.DiagnosticSerialNumber, record.Segment.DiagnosticSerialNumber, record.Segment.Name);
                    }
                    traceDynpack.WriteLine();
                    traceDynpack.Flush();
                }

                // Sort and merge
                List<FileRecord> mergedFiles = new List<FileRecord>();
                {
                    int iCurrent;
                    int iPrevious;

                    currentFiles.Sort(DynPackPathCompareWithRange);
                    previousFiles.Sort(DynPackPathCompareWithRange); // ensure sorted - do not trust old manifest
                    // detect flaws in comparison algorithm
                    for (int i = 0; i < currentFiles.Count - 1; i++)
                    {
                        if (!(DynPackPathCompareWithRange(currentFiles[i], currentFiles[i + 1]) < 0))
                        {
                            Debugger.Break();
                            throw new ApplicationException(String.Format("Sort defect: {0} {1}", currentFiles[i].PartialPath, currentFiles[i + 1].PartialPath));
                        }
                    }
                    for (int i = 0; i < previousFiles.Count - 1; i++)
                    {
                        if (!(DynPackPathCompareWithRange(previousFiles[i], previousFiles[i + 1]) < 0))
                        {
                            Debugger.Break();
                            throw new ApplicationException(String.Format("Sort defect: {0} {1}", previousFiles[i].PartialPath, previousFiles[i + 1].PartialPath));
                        }
                    }

                    // Here is a hack to ensure that range-split files are not gratuitously
                    // rearchived if the segment target size changes. (This also affects the case
                    // where an archive containing unsplit large file, i.e. length > segment target size,
                    // is run with the split option enabled, where the file has not changed).
                    // Find all ranged files in currentFiles or previousFiles and if the
                    // underlying file has not changed, ensure that the structure from previousFiles
                    // is retained.
                    iCurrent = 0;
                    iPrevious = 0;
                    while ((iCurrent < currentFiles.Count) && (iPrevious < previousFiles.Count))
                    {
                        int c = DynPackPathComparePartialPathOnly(currentFiles[iCurrent], previousFiles[iPrevious]);
                        if (c < 0)
                        {
                            iCurrent++;
                        }
                        else if (c > 0)
                        {
                            iPrevious++;
                        }
                        else
                        {
                            int iPreviousStart = iPrevious;
                            int iCurrentStart = iCurrent;
                            bool range = false;
                            do
                            {
                                range = range || (previousFiles[iPrevious].Range != null);
                                iPrevious++;
                            } while ((iPrevious < previousFiles.Count)
                                && (0 == DynPackPathComparePartialPathOnly(previousFiles[iPrevious - 1], previousFiles[iPrevious])));
                            do
                            {
                                range = range || (currentFiles[iCurrent].Range != null);
                                iCurrent++;
                            } while ((iCurrent < currentFiles.Count)
                                && (0 == DynPackPathComparePartialPathOnly(currentFiles[iCurrent - 1], currentFiles[iCurrent])));

                            if (range
                                && previousFiles[iPreviousStart].CreationTimeUtc.Equals(currentFiles[iCurrentStart].CreationTimeUtc)
                                && previousFiles[iPreviousStart].LastWriteTimeUtc.Equals(currentFiles[iCurrentStart].LastWriteTimeUtc))
                            {
                                bool notDirty = true;
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("[gratuitous re-ranging suppression dirty check begins: previous=(start={0}, length={1}) current=(start={2}, length={3})]", iPreviousStart, iPrevious - iPreviousStart, iCurrentStart, iCurrent - iCurrentStart);
                                }
                                for (int i = iPreviousStart; notDirty && (i < iPrevious); i++)
                                {
                                    bool segmentAssigned = previousFiles[i].Segment != null;
                                    bool segmentExist = segmentAssigned && fileManager.Exists(String.Concat(targetArchiveFileNameTemplate, ".", previousFiles[i].Segment.Name, DynPackFileExtension), fileManager.GetMasterTrace());
                                    bool thisNotDirty = segmentAssigned && segmentExist;
                                    if (!thisNotDirty)
                                    {
                                        if (traceDynpack != null)
                                        {
                                            traceDynpack.WriteLine("[gratuitous re-ranging suppression: {0} dirty; segmentAssigned={1}, segmentExist={2}]", previousFiles[i].DiagnosticSerialNumber, segmentAssigned, segmentExist);
                                        }
                                    }
                                    notDirty = notDirty && segmentAssigned && segmentExist;
                                }

                                if (notDirty)
                                {
                                    // unchanged, and ranges involved in either previous or current

                                    if (traceDynpack != null)
                                    {
                                        traceDynpack.WriteLine("Gratuitous re-ranging of large files suppressed: previous=(start={0}, length={1}) current=(start={2}, length={3})", iPreviousStart, iPrevious - iPreviousStart, iCurrentStart, iCurrent - iCurrentStart);
                                        traceDynpack.Write("  previous={");
                                        for (int i = iPreviousStart; i < iPrevious; i++)
                                        {
                                            traceDynpack.Write("{0},", previousFiles[i].DiagnosticSerialNumber);
                                        }
                                        traceDynpack.Write("}  current={");
                                        for (int i = iCurrentStart; i < iCurrent; i++)
                                        {
                                            traceDynpack.Write("{0},", currentFiles[i].DiagnosticSerialNumber);
                                        }
                                        traceDynpack.WriteLine("}");
                                        traceDynpack.Flush();
                                    }

                                    FileRecord[] currentSequenceReplacement = new FileRecord[iPrevious - iPreviousStart];
                                    for (int i = 0; i < iPrevious - iPreviousStart; i++)
                                    {
                                        FileRecord previous = previousFiles[i + iPreviousStart];
                                        currentSequenceReplacement[i] = new FileRecord(previous);
                                    }
                                    currentFiles.RemoveRange(iCurrentStart, iCurrent - iCurrentStart);
                                    currentFiles.InsertRange(iCurrentStart, currentSequenceReplacement);
                                    iCurrent = iCurrentStart + (iPrevious - iPreviousStart);
                                }
                            }
                        }
                    }
                    if (traceDynpack != null)
                    {
                        traceDynpack.WriteLine();
                        traceDynpack.Flush();
                    }

                    // main merge occurs here
                    iCurrent = 0;
                    iPrevious = 0;
                    while ((iCurrent < currentFiles.Count) || (iPrevious < previousFiles.Count))
                    {
                        if (!(iCurrent < currentFiles.Count))
                        {
                            if (traceDynpack != null)
                            {
                                traceDynpack.WriteLine("Deleted(1): {5} {0}{4} {1} {2} {3}", previousFiles[iPrevious].EmbeddedStreamLength, previousFiles[iPrevious].CreationTimeUtc, previousFiles[iPrevious].LastWriteTimeUtc, previousFiles[iPrevious].PartialPath, previousFiles[iPrevious].Range != null ? String.Format("[{0}]", previousFiles[iPrevious].Range) : String.Empty, previousFiles[iPrevious].DiagnosticSerialNumber);
                            }

                            previousFiles[iPrevious].Segment.Dirty.Set(); // segment modified by deletion
                            iPrevious++;
                        }
                        else if (!(iPrevious < previousFiles.Count))
                        {
                            if (traceDynpack != null)
                            {
                                traceDynpack.WriteLine("Added(1): {5} {0}{4} {1} {2} {3}", currentFiles[iCurrent].EmbeddedStreamLength, currentFiles[iCurrent].CreationTimeUtc, currentFiles[iCurrent].LastWriteTimeUtc, currentFiles[iCurrent].PartialPath, currentFiles[iCurrent].Range != null ? String.Format("[{0}]", currentFiles[iCurrent].Range) : String.Empty, currentFiles[iCurrent].DiagnosticSerialNumber);
                            }

                            // Addition MAY or MAY NOT cause segment to be dirty:
                            // - If files are added between segments, the code tries to avoid modifying those
                            // segments, so they do not need to be marked dirty (unless the segments are small
                            // enough to be merged during the join phase, which marks them dirty).
                            // - If new files are inserted into the middle of an existing segment, the segment
                            // must be split in two and the second half renamed, during a fixup pass that
                            // occurs after merging.
                            // Therefore, marking dirty is not done here in any case.

                            mergedFiles.Add(currentFiles[iCurrent]);
                            iCurrent++;
                        }
                        else
                        {
                            int c = DynPackPathCompareWithRange(currentFiles[iCurrent], previousFiles[iPrevious]);
                            if (c < 0)
                            {
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Added(2): {5} {0}{4} {1} {2} {3}", currentFiles[iCurrent].EmbeddedStreamLength, currentFiles[iCurrent].CreationTimeUtc, currentFiles[iCurrent].LastWriteTimeUtc, currentFiles[iCurrent].PartialPath, currentFiles[iCurrent].Range != null ? String.Format("[{0}]", currentFiles[iCurrent].Range) : String.Empty, currentFiles[iCurrent].DiagnosticSerialNumber);
                                }

                                // IMPORTANT: see comment in "Added(1)" clause about marking dirty

                                mergedFiles.Add(currentFiles[iCurrent]);
                                iCurrent++;
                            }
                            else if (c > 0)
                            {
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Deleted(2): {5} {0}{4} {1} {2} {3}", previousFiles[iPrevious].EmbeddedStreamLength, previousFiles[iPrevious].CreationTimeUtc, previousFiles[iPrevious].LastWriteTimeUtc, previousFiles[iPrevious].PartialPath, previousFiles[iPrevious].Range != null ? String.Format("[{0}]", previousFiles[iPrevious].Range) : String.Empty, previousFiles[iPrevious].DiagnosticSerialNumber);
                                }

                                previousFiles[iPrevious].Segment.Dirty.Set(); // segment modified by deletion
                                iPrevious++;
                            }
                            else
                            {
                                FileRecord record = currentFiles[iCurrent];
                                record.Segment = previousFiles[iPrevious].Segment;
                                mergedFiles.Add(record);

                                bool creationChanged = !previousFiles[iPrevious].CreationTimeUtc.Equals(currentFiles[iCurrent].CreationTimeUtc);
                                bool lastWriteChanged = !previousFiles[iPrevious].LastWriteTimeUtc.Equals(currentFiles[iCurrent].LastWriteTimeUtc);
                                bool rangeChanged = !PackedFileHeaderRecord.RangeRecord.Equals(previousFiles[iPrevious].Range, currentFiles[iCurrent].Range);
                                if (creationChanged || lastWriteChanged || rangeChanged)
                                {
                                    if (traceDynpack != null)
                                    {
                                        traceDynpack.WriteLine("Changed: {5} {0}{4} {1} {2} {3}", previousFiles[iPrevious].EmbeddedStreamLength, previousFiles[iPrevious].CreationTimeUtc, previousFiles[iPrevious].LastWriteTimeUtc, previousFiles[iPrevious].PartialPath, previousFiles[iPrevious].Range != null ? String.Format("[{0}]", previousFiles[iPrevious].Range) : String.Empty, previousFiles[iPrevious].DiagnosticSerialNumber);
                                        traceDynpack.WriteLine("       : {5} {0}{4} {1} {2} {3}", currentFiles[iCurrent].EmbeddedStreamLength, currentFiles[iCurrent].CreationTimeUtc, currentFiles[iCurrent].LastWriteTimeUtc, currentFiles[iCurrent].PartialPath, currentFiles[iCurrent].Range != null ? String.Format("[{0}]", currentFiles[iCurrent].Range) : String.Empty, currentFiles[iCurrent].DiagnosticSerialNumber);
                                        traceDynpack.WriteLine("       (reason: creation-changed={0} lastwrite-changed={1} range-changed={2})", creationChanged, lastWriteChanged, rangeChanged);
                                    }

                                    previousFiles[iPrevious].Segment.Dirty.Set(); // segment modified because file changed
                                }
                                else
                                {
                                    if (traceDynpack != null)
                                    {
                                        traceDynpack.WriteLine("Unchanged: {5} {0}{4} {1} {2} {3}", currentFiles[iCurrent].EmbeddedStreamLength, currentFiles[iCurrent].CreationTimeUtc, currentFiles[iCurrent].LastWriteTimeUtc, currentFiles[iCurrent].PartialPath, currentFiles[iCurrent].Range != null ? String.Format("[{0}]", currentFiles[iCurrent].Range) : String.Empty, currentFiles[iCurrent].DiagnosticSerialNumber);
                                    }
                                }

                                iPrevious++;
                                iCurrent++;
                            }
                        }
                    }

                    currentFiles = null;
                    previousFiles = null;
                }
                if (traceDynpack != null)
                {
                    traceDynpack.WriteLine();
                    traceDynpack.WriteLine("Merged Files:");
                    for (int i = 0; i < mergedFiles.Count; i++)
                    {
                        FileRecord record = mergedFiles[i];
                        traceDynpack.WriteLine("    {5,-8} {6} {7}  {0}{4} {1} {2} {3}", record.EmbeddedStreamLength, record.CreationTimeUtc, record.LastWriteTimeUtc, record.PartialPath, record.Range != null ? String.Format("[{0}]", record.Range) : String.Empty, i, record.DiagnosticSerialNumber, record.Segment != null ? record.Segment.DiagnosticSerialNumber : "null");
                    }
                    traceDynpack.WriteLine();
                    traceDynpack.Flush();
                }

                // Fixup pass for files inserted into the middle of segments (breaking segment
                // ordering invariants) - see also comment in "Added(1)" clause above.
                {
                    Dictionary<string, bool> usedSegmentNames = new Dictionary<string, bool>();
                    string currentSegmentName = String.Empty;
                    SegmentRecord currentSegment = null;
                    bool splitSegment = false;
                    for (int i = 0; i < mergedFiles.Count - 1; i++)
                    {
                        if (mergedFiles[i].Segment == null)
                        {
                            splitSegment = true;
                            continue;
                        }

                        string candidateSegmentName = mergedFiles[i].Segment.Name;
                        if (splitSegment || !String.Equals(currentSegmentName, candidateSegmentName))
                        {
                            int c = DynPackSegmentNameCompare(currentSegmentName, candidateSegmentName);
                            if ((c > 0) || (splitSegment && (c == 0)))
                            {
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Insertion: segment name sequence violation:  {0} {5} {2}  [{1},{3}]  ({4})", currentSegmentName, currentSegment.DiagnosticSerialNumber, mergedFiles[i].Segment.Name, mergedFiles[i].Segment.DiagnosticSerialNumber, mergedFiles[i].DiagnosticSerialNumber, splitSegment ? ">=" : ">");
                                    traceDynpack.WriteLine("  marking segment dirty, then voiding segment from {0}", mergedFiles[i].DiagnosticSerialNumber);
                                }
                                mergedFiles[i].Segment.Dirty.Set();
                                mergedFiles[i].Segment = null;
                                continue;
                            }

                            if (usedSegmentNames.ContainsKey(mergedFiles[i].Segment.Name))
                            {
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Insertion: segment name used more than once for separated regions:  {0} [{1}]  ({2})", mergedFiles[i].Segment.Name, mergedFiles[i].Segment.DiagnosticSerialNumber, mergedFiles[i].DiagnosticSerialNumber);
                                    traceDynpack.WriteLine("  marking segment dirty, then voiding segment from {0}", mergedFiles[i].DiagnosticSerialNumber);
                                }
                                mergedFiles[i].Segment.Dirty.Set();
                                mergedFiles[i].Segment = null;
                                continue;
                            }

                            currentSegment = mergedFiles[i].Segment;
                            currentSegmentName = mergedFiles[i].Segment.Name;
                            usedSegmentNames[currentSegmentName] = false;
                            splitSegment = false;
                        }
                    }

                    if (traceDynpack != null)
                    {
                        traceDynpack.WriteLine();
                        traceDynpack.Flush();
                    }
                }

                // Ensure segment contiguity and uniqueness
                {
                    Dictionary<SegmentRecord, bool> usedSegments = new Dictionary<SegmentRecord, bool>();
                    SegmentRecord currentSegment = null;

                    // first, ensure first file and first segment assignment are valid
                    if (mergedFiles.Count > 0)
                    {
                        currentSegment = mergedFiles[0].Segment;
                        if (currentSegment == null)
                        {
                            // special case - first file is a new file - create new first segment for it
                            currentSegment = new SegmentRecord();
                            if (traceDynpack != null)
                            {
                                traceDynpack.WriteLine("New segment: {0}", currentSegment.DiagnosticSerialNumber);
                            }
                            segments.Add(currentSegment);
                            mergedFiles[0].Segment = currentSegment;
                            if (traceDynpack != null)
                            {
                                traceDynpack.WriteLine("Segment assign: {0} {2} {1}", currentSegment.DiagnosticSerialNumber, mergedFiles[0].PartialPath, mergedFiles[0].Range != null ? String.Format("[{0}]", mergedFiles[0].Range) : String.Empty);
                            }
                        }
                        usedSegments.Add(currentSegment, false);
                        currentSegment.start = 0;
                    }

                    for (int i = 1; i < mergedFiles.Count; i++)
                    {
                        if (mergedFiles[i].Segment == null)
                        {
                            // unnassigned file
                            if (currentSegment.Dirty.Value)
                            {
                                // only append new unnassigned file to the previous segment if it
                                // is already dirty - if segment is already full, we'll end up splitting
                                // it and quite likely having to rewrite a segment that didn't actually
                                // change
                                mergedFiles[i].Segment = currentSegment;
                            }
                            else
                            {
                                // create new segment if previous segment is not dirty
                                mergedFiles[i].Segment = currentSegment = new SegmentRecord();
                                usedSegments.Add(currentSegment, false);
                                currentSegment.start = i;
                                segments.Add(currentSegment);
                                Debug.Assert(currentSegment.Dirty.Value);
                            }
                            if (traceDynpack != null)
                            {
                                traceDynpack.WriteLine("Segment assign: {0} {2} {1}", currentSegment.DiagnosticSerialNumber, mergedFiles[i].PartialPath, mergedFiles[i].Range != null ? String.Format("[{0}]", mergedFiles[i].Range) : String.Empty);
                            }
                        }
                        else if (mergedFiles[i].Segment != currentSegment)
                        {
                            // file is in a segment other than current segment (just crossed boundary)
                            if (!usedSegments.ContainsKey(mergedFiles[i].Segment))
                            {
                                // if this segment hasn't been seen, it becomes the current segment
                                currentSegment = mergedFiles[i].Segment;
                            }
                            else
                            {
                                // if it has been seen, then segments have become interleaved.
                                // create new segment and reassign file to it
                                currentSegment = new SegmentRecord();
                                segments.Add(currentSegment);
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("New segment: {0}", currentSegment.DiagnosticSerialNumber);
                                }
                            }
                            usedSegments.Add(currentSegment, false);
                            currentSegment.start = i;
                        }
                        else
                        {
                            // file is in same segment as previous file - no action needed
                        }
                    }
                }
                segments.RemoveAll(delegate(SegmentRecord a) { return !a.start.HasValue; });
                segments.Sort(delegate(SegmentRecord l, SegmentRecord r) { return l.start.Value.CompareTo(r.start.Value); });
                if (traceDynpack != null)
                {
                    traceDynpack.WriteLine();
                    traceDynpack.WriteLine("Segments:");
                    foreach (SegmentRecord segment in segments)
                    {
                        traceDynpack.WriteLine("    {0} {1}", segment.DiagnosticSerialNumber, segment.Name != null ? segment.Name : "<>");
                    }
                    traceDynpack.WriteLine();
                    traceDynpack.Flush();
                }

                // First scan (before splitting or merging) - ensure missing segments are dirty
                foreach (SegmentRecord segment in segments)
                {
                    string segmentFileName = targetArchiveFileNameTemplate + "." + segment.Name + DynPackFileExtension;
                    if (!fileManager.Exists(segmentFileName, fileManager.GetMasterTrace()))
                    {
                        segment.Dirty.Set();
                    }
                }

                // Split segments too large
                for (int i = 0; i < segments.Count; i++)
                {
                    SegmentRecord segment = segments[i];

                    if (!segment.Dirty.Value)
                    {
                        // do not gratuitously split too-large segments that already exist and aren't dirty
                        continue;
                    }

                    // determine prefix that fits in one segment
                    int start = segment.start.Value;
                    int end = (i + 1 < segments.Count) ? segments[i + 1].start.Value : mergedFiles.Count;
                    int count = end - start;
                    long totalSize = 0;
                    int j = 0;
                    while (j < count)
                    {
                        totalSize += mergedFiles[j + start].EmbeddedStreamLength + mergedFiles[j + start].HeaderOverhead;
                        if (totalSize > segmentSizeTarget)
                        {
                            if (j > 0)
                            {
                                break;
                            }
                        }
                        j++;
                    }

                    if (j < count)
                    {
                        // this segment was too large - split it

                        // special case: try to split the segment evenly (only exactly two segments can contain data)
                        {
                            int left = 0;
                            int right = count;
                            long leftSize = 0;
                            long rightSize = 0;
                            while ((left < right) && (leftSize <= segmentSizeTarget) && (rightSize <= segmentSizeTarget))
                            {
                                long leftOne = mergedFiles[left + start].EmbeddedStreamLength + mergedFiles[left + start].HeaderOverhead;
                                long rightOne = mergedFiles[right - 1 + start].EmbeddedStreamLength + mergedFiles[right - 1 + start].HeaderOverhead;
                                if ((leftSize + leftOne <= rightSize) || (rightSize + rightOne > segmentSizeTarget))
                                {
                                    leftSize += leftOne;
                                    left++;
                                }
                                else
                                {
                                    rightSize += rightOne;
                                    right--;
                                }
                            }
                            if ((left == right) && (leftSize <= segmentSizeTarget) && (rightSize <= segmentSizeTarget))
                            {
                                j = left;
                            }
                        }

                        // assign the new segment for the overflow items
                        segment.Dirty.Set();
                        SegmentRecord newSegment = new SegmentRecord();
                        newSegment.start = j + start;
                        if (traceDynpack != null)
                        {
                            traceDynpack.WriteLine("Split: {0} after {1}", segment.DiagnosticSerialNumber, mergedFiles[newSegment.start.Value].PartialPath);
                        }
                        segments.Insert(i + 1, newSegment);
                        for (int k = j; k < count; k++)
                        {
                            mergedFiles[k + start].Segment = newSegment;
                        }
                    }
                }

                // Join (fold) small segments
                for (int i = 0; i < segments.Count - 1; i++)
                {
                    if (!segments[i].Dirty.Value && !segments[i + 1].Dirty.Value)
                    {
                        // do not gratuitously merge too-small segments that already exist and aren't dirty
                        continue;
                    }

                    int start = segments[i].start.Value;
                    int end = (i + 2 < segments.Count) ? segments[i + 2].start.Value : mergedFiles.Count;
                    int count = end - start;
                    long totalSize = 0;
                    for (int j = 0; j < count; j++)
                    {
                        totalSize += mergedFiles[j + start].EmbeddedStreamLength + mergedFiles[j + start].HeaderOverhead;
                    }
                    if (totalSize <= segmentSizeTarget)
                    {
                        if (traceDynpack != null)
                        {
                            traceDynpack.WriteLine("Join: {0}, {1}", segments[i].DiagnosticSerialNumber, segments[i + 1].DiagnosticSerialNumber);
                        }

                        segments[i].Dirty.Set();

                        if ((segments[i].Name == null) && (segments[i + 1].Name != null))
                        {
                            segments[i].Name = segments[i + 1].Name;
                        }
                        for (int j = 0; j < count; j++)
                        {
                            mergedFiles[j + start].Segment = segments[i];
                        }
                        segments.RemoveAt(i + 1);
                        i--;
                    }
                }

                // program logic test - verify segment structure validity
                for (int i = 0; i < segments.Count - 1; i++)
                {
                    if (segments[i].start.Value >= segments[i + 1].start.Value)
                    {
                        Console.WriteLine("DEFECT! Segment overlap!");
                        Debugger.Break();
                        throw new ApplicationException("DEFECT! Segment overlap!");
                    }
                }

                // Rename segments
                {
                    if (segments.Count > 0)
                    {
                        if (segments[0].Name != "a")
                        {
                            segments[0].Name = "a";
                            if (traceDynpack != null)
                            {
                                traceDynpack.WriteLine("Rename: {0} --> {1}", segments[0].DiagnosticSerialNumber, segments[0].Name);
                            }
                        }
                    }
                    int lastName = 0;
                    int i;
                    for (i = 1; i < segments.Count; i++)
                    {
                        if (segments[i].Name != null)
                        {
                            if (DynPackSegmentNameCompare(segments[lastName].Name, segments[i].Name) >= 0)
                            {
                                // later segment with same or earlier (less than) name has an
                                // invalid name and must be renamed - remove name here to trigger that
                                segments[i].Name = null;
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Rename: {0} --> {1}", segments[i].DiagnosticSerialNumber, "<>");
                                }
                            }
                            else
                            {
                                lastName = i;
                            }
                        }
                    }
                    i = 1;
                    while (i < segments.Count)
                    {
                        if (segments[i].Name == null)
                        {
                            int nextName = i + 1;
                            while ((nextName < segments.Count) && (segments[nextName].Name == null))
                            {
                                nextName++;
                            }
                            string[] newNames = DynPackMakeSegmentNamesBetween(segments[i - 1].Name, nextName < segments.Count ? segments[nextName].Name : "z", nextName - i);
                            for (int j = 0; j < nextName - i; j++)
                            {
                                segments[i + j].Name = newNames[j];
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Rename: {0} --> {1}", segments[i + j].DiagnosticSerialNumber, segments[i + j].Name);
                                }
                            }
                        }
                        i++;
                    }
                    for (i = 1; i < segments.Count; i++)
                    {
                        if (segments[i].Dirty.Value)
                        {
                            string newName = segments[i].Name;
                            newName = newName.Substring(0, newName.Length - 1);
                            if ((newName.Length >= 1) && (newName[newName.Length - 1] != 'a') && (DynPackSegmentNameCompare(segments[i - 1].Name, newName) < 0))
                            {
                                segments[i].Name = newName;
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Rename: {0} --> {1}", segments[i].DiagnosticSerialNumber, segments[i].Name);
                                }
                            }
                        }
                    }
                }
                if (traceDynpack != null)
                {
                    traceDynpack.WriteLine();
                    traceDynpack.WriteLine("Segments (2):");
                    foreach (SegmentRecord segment in segments)
                    {
                        traceDynpack.WriteLine("    {0} {1}", segment.DiagnosticSerialNumber, segment.Name != null ? segment.Name : "<>");
                    }
                    traceDynpack.WriteLine();
                    traceDynpack.Flush();
                }

                // program logic test - verify segment naming validity
                {
                    bool fault1 = false, fault2 = false;
                    Dictionary<string, bool> usedSegmentNames = new Dictionary<string, bool>();
                    string currentSegmentName = String.Empty;
                    SegmentRecord currentSegment = null;
                    for (int i = 0; i < mergedFiles.Count - 1; i++)
                    {
                        if (!String.Equals(currentSegmentName, mergedFiles[i].Segment.Name))
                        {
                            if (DynPackSegmentNameCompare(currentSegmentName, mergedFiles[i].Segment.Name) > 0)
                            {
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Program defect: segment name sequence violation:  {0} > {2}  [{1},{3}]  ({4})", currentSegmentName, currentSegment.DiagnosticSerialNumber, mergedFiles[i].Segment.Name, mergedFiles[i].Segment.DiagnosticSerialNumber, mergedFiles[i].DiagnosticSerialNumber);
                                    traceDynpack.Flush();
                                }
                                fault1 = true;
                            }

                            if (usedSegmentNames.ContainsKey(mergedFiles[i].Segment.Name))
                            {
                                if (traceDynpack != null)
                                {
                                    traceDynpack.WriteLine("Program defect: name used more than once for separated regions:  {0} [{1}]  ({2})", mergedFiles[i].Segment.Name, mergedFiles[i].Segment.DiagnosticSerialNumber, mergedFiles[i].DiagnosticSerialNumber);
                                    traceDynpack.Flush();
                                }
                                fault2 = true;
                            }

                            currentSegment = mergedFiles[i].Segment;
                            currentSegmentName = mergedFiles[i].Segment.Name;
                            usedSegmentNames[currentSegmentName] = false;
                        }
                    }
                    if (fault1 || fault2)
                    {
                        string message = String.Empty;
                        if (fault1)
                        {
                            message = message + "DEFECT! Segment name sequence violation! ";
                        }
                        if (fault2)
                        {
                            message = message + "DEFECT! Segment name used more than once for separated regions!";
                        }
                        Debugger.Break();
                        throw new ApplicationException(message);
                    }
                }

                // TODO: rename segments (and rename files) if names have become too long for file system

                // Second scan (after renaming) - ensure missing segments are dirty
                foreach (SegmentRecord segment in segments)
                {
                    string segmentFileName = targetArchiveFileNameTemplate + "." + segment.Name + DynPackFileExtension;
                    if (!fileManager.Exists(segmentFileName, fileManager.GetMasterTrace()))
                    {
                        segment.Dirty.Set();
                    }
                }

                // debug logging - callouts
                if (traceDynpack != null)
                {
                    traceDynpack.WriteLine();

                    traceDynpack.WriteLine("Callout - over-large (unsplit) files");
                    for (int i = 0; i < mergedFiles.Count; i++)
                    {
                        if ((mergedFiles[i].Range == null) && (mergedFiles[i].EmbeddedStreamLength > segmentSizeTarget))
                        {
                            traceDynpack.WriteLine("{7} [{5}] {0}{4}{6} {1} {2} {3}", mergedFiles[i].EmbeddedStreamLength, mergedFiles[i].CreationTimeUtc, mergedFiles[i].LastWriteTimeUtc, mergedFiles[i].PartialPath, mergedFiles[i].Range != null ? String.Format("[{0}]", mergedFiles[i].Range) : String.Empty, i, mergedFiles[i].Segment.Dirty.Value ? " dirty=true" : String.Empty, mergedFiles[i].DiagnosticSerialNumber);
                        }
                    }
                    traceDynpack.WriteLine();

                    traceDynpack.WriteLine("Callout - all files with Range record");
                    for (int i = 0; i < mergedFiles.Count; i++)
                    {
                        if (mergedFiles[i].Range != null)
                        {
                            traceDynpack.WriteLine("{7} [{5}] {0}{4}{6} {1} {2} {3}", mergedFiles[i].EmbeddedStreamLength, mergedFiles[i].CreationTimeUtc, mergedFiles[i].LastWriteTimeUtc, mergedFiles[i].PartialPath, mergedFiles[i].Range != null ? String.Format("[{0}]", mergedFiles[i].Range) : String.Empty, i, mergedFiles[i].Segment.Dirty.Value ? " dirty=true" : String.Empty, mergedFiles[i].DiagnosticSerialNumber);
                        }
                    }
                    traceDynpack.WriteLine();

                    traceDynpack.Flush();
                }


                // From this point forward, all concurrency-unsafe updates to data structures should
                // be finished. Some safe updates (such as setting dirty flags or changing serial
                // numbers) are permitted after this point


                using (ConcurrentMessageLog messagesLog = new ConcurrentMessageLog(Interactive(), true/*enableSequencing*/))
                {
                    int threadCount = GetConcurrency(fileManager, context);
                    using (ConcurrentTasks concurrent = new ConcurrentTasks(threadCount, 0, messagesLog, traceDynpack != null ? traceDynpack : fileManager.GetMasterTrace()))
                    {
                        int fatal;
                        bool abort = false;


                        // begin concurrent region


                        // remove abandoned temp files
                        fatal = 0;
                        {
                            string targetFileNamePrefix = targetArchiveFileNameTemplate + ".";
                            foreach (string segmentFileNameEnum in fileManager.GetFileNames(targetFileNamePrefix, fileManager.GetMasterTrace()))
                            {
                                concurrent.WaitQueueEmpty();
                                if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                {
                                    if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                                    {
                                        abort = true;
                                        break;
                                    }
                                    fatal = 0;
                                }

                                // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                // variable) in order to capture each value in the anonymous method.
                                // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                string segmentFileName = segmentFileNameEnum;

                                Debug.Assert(segmentFileName.StartsWith(targetFileNamePrefix, StringComparison.OrdinalIgnoreCase));

                                if (segmentFileName.EndsWith(DynPackTempFileExtension))
                                {
                                    long sequenceNumber = messagesLog.GetSequenceNumber();
                                    concurrent.Do(
                                        String.Format("delete-tempfile:{0}", segmentFileName),
                                        delegate(ConcurrentTasks.ITaskContext taskContext)
                                        {
                                            using (TextWriter threadTraceDynPack = TaskWriter.Create(traceDynpack))
                                            {
                                                using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                                {
                                                    try
                                                    {
                                                        using (TextWriter threadTraceFileManager = TaskWriter.Create(fileManager.GetMasterTrace()))
                                                        {
                                                            messages.WriteLine("Deleting (old temporary file): {0}", segmentFileName);
                                                            fileManager.Delete(segmentFileName, threadTraceFileManager);
                                                        }
                                                    }
                                                    catch (Exception exception)
                                                    {
                                                        if (threadTraceDynPack != null)
                                                        {
                                                            threadTraceDynPack.WriteLine("Exception deleting {0}: {1}", segmentFileName, exception);
                                                        }
                                                        messages.WriteLine("Error deleting {0}: {1}", segmentFileName, exception.Message);

                                                        Interlocked.Exchange(ref fatal, 1);
                                                        throw;
                                                    }
                                                }
                                            }
                                        });
                                }

                                messagesLog.Flush();
                            }
                        }

                        // state of "fatal" continues into this region

                        // verify integrity of non-dirty segments - note this validates metadata
                        // (i.e. the structure of the segment pack file) but DOES NOT verify content
                        // of each file.
                        List<string> badSegments = new List<string>(); // multi-threaded: lock this!
                        if (verifyNonDirtyMetadata)
                        {
                            for (int iEnum = 0; iEnum < segments.Count; iEnum++)
                            {
                                concurrent.WaitQueueEmpty();
                                if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                {
                                    if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                                    {
                                        abort = true;
                                        break;
                                    }
                                    fatal = 0;
                                }

                                // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                // variable) in order to capture each value in the anonymous method.
                                // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                int i = iEnum;
                                SegmentRecord segment = segments[iEnum];

                                if (!segment.Dirty.Value)
                                {
                                    string segmentFileName = targetArchiveFileNameTemplate + "." + segment.Name + DynPackFileExtension;

                                    long sequenceNumber = messagesLog.GetSequenceNumber();
                                    concurrent.Do(
                                        String.Format("validate-nondirty:{0}", segmentFileName),
                                        delegate(ConcurrentTasks.ITaskContext taskContext)
                                        {
                                            using (TextWriter threadTraceDynPack = TaskWriter.Create(traceDynpack))
                                            {
                                                using (TextWriter threadTraceFileManager = TaskWriter.Create(fileManager.GetMasterTrace()))
                                                {
                                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                                    {
                                                        bool invalid = false;

                                                        if (threadTraceDynPack != null)
                                                        {
                                                            threadTraceDynPack.WriteLine("Validating non-dirty segment: {0} {1}", segment.DiagnosticSerialNumber, segment.Name);
                                                            threadTraceDynPack.Flush();
                                                        }
                                                        messages.WriteLine("Validating non-dirty segment: {0}", segment.Name);

                                                        using (ILocalFileCopy fileRef = fileManager.Read(segmentFileName, null/*progressTracker*/, threadTraceFileManager))
                                                        {
                                                            Context unpackContext = new Context(context);
                                                            if (unpackContext.compressionOption == CompressionOption.Compress)
                                                            {
                                                                unpackContext.compressionOption = CompressionOption.Decompress;
                                                            }
                                                            if (unpackContext.cryptoOption == EncryptionOption.Encrypt)
                                                            {
                                                                unpackContext.cryptoOption = EncryptionOption.Decrypt;
                                                                unpackContext.decrypt = unpackContext.encrypt;
                                                                unpackContext.encrypt = null;
                                                            }
                                                            ulong segmentSerialNumber = 0;
                                                            byte[] segmentRandomArchiveSignature = new byte[0];
                                                            UnpackedFileRecord[] archiveFiles = null;
                                                            try
                                                            {
                                                                using (Stream segmentStream = fileRef.Read())
                                                                {
                                                                    ApplicationException[] deferredExceptions;
                                                                    archiveFiles = UnpackInternal(segmentStream, source, unpackContext, UnpackMode.Parse, out segmentSerialNumber, out segmentRandomArchiveSignature, threadTraceDynPack, faultDynamicPack.Select("VerifySegment", segmentFileName), out deferredExceptions);
                                                                    Debug.Assert(deferredExceptions == null); // load manifest should never generate deferred exceptions
                                                                }
                                                            }
                                                            catch (Exception exception)
                                                            {
                                                                invalid = true;

                                                                if (traceDynpack != null)
                                                                {
                                                                    traceDynpack.WriteLine("Segment corrupt, could not be read: {0}", exception);
                                                                }
                                                                messages.WriteLine("SEGMENT INTEGRITY PROBLEM {0} (segment corrupt, could not be read): {1}", segment.Name, exception);
                                                            }

                                                            if (!ArrayEqual(segmentRandomArchiveSignature, randomArchiveSignature))
                                                            {
                                                                invalid = true;

                                                                if (traceDynpack != null)
                                                                {
                                                                    traceDynpack.WriteLine("Segment random signature mismatch: expected={0}, actual={1}", Logging.ScrubSecuritySensitiveValue(randomArchiveSignature), Logging.ScrubSecuritySensitiveValue(segmentRandomArchiveSignature));
                                                                }
                                                                messages.WriteLine("SEGMENT INTEGRITY PROBLEM {0} (serial number mismatch): {1}", segment.Name, segmentFileName);
                                                            }

                                                            if (segmentSerialNumber != segment.SerialNumber)
                                                            {
                                                                invalid = true;

                                                                if (traceDynpack != null)
                                                                {
                                                                    traceDynpack.WriteLine("Segment serial number mismatch: manfest-ref={0}, actual={1}", segment.SerialNumber, segmentSerialNumber);
                                                                }
                                                                messages.WriteLine("SEGMENT INTEGRITY PROBLEM {0} (serial number mismatch): {1}", segment.Name, segmentFileName);
                                                            }

                                                            if (archiveFiles != null)
                                                            {
                                                                int segmentStart = segment.start.Value;
                                                                int segmentLength = (i < segments.Count - 1 ? segments[i + 1].start.Value : mergedFiles.Count) - segmentStart;
                                                                if (segmentLength != archiveFiles.Length)
                                                                {
                                                                    invalid = true;

                                                                    if (traceDynpack != null)
                                                                    {
                                                                        traceDynpack.WriteLine("Length mismatch: {0}, {1}", segmentLength, archiveFiles.Length);
                                                                    }
                                                                    messages.WriteLine("SEGMENT INTEGRITY PROBLEM {0} (length mismatch): {1}", segment.Name, segmentFileName);
                                                                }

                                                                bool stop = false;
                                                                for (int j = 0; (j < segmentLength) && !stop; j++)
                                                                {
                                                                    if (!String.Equals(archiveFiles[j].ArchivePath, mergedFiles[j + segmentStart].PartialPath.ToString()))
                                                                    {
                                                                        invalid = true;
                                                                        stop = true;

                                                                        if (traceDynpack != null)
                                                                        {
                                                                            traceDynpack.WriteLine("File added or removed: {0} : {1}", archiveFiles[j].ArchivePath, mergedFiles[j + segmentStart].PartialPath);
                                                                        }
                                                                        messages.WriteLine("SEGMENT INTEGRITY PROBLEM {0} (file added or removed): {1} : {2}", segment.Name, archiveFiles[j].ArchivePath, mergedFiles[j + segmentStart].PartialPath);
                                                                    }
                                                                    else if ((archiveFiles[j].EmbeddedStreamLength != mergedFiles[j + segmentStart].EmbeddedStreamLength) ||
                                                                        (archiveFiles[j].CreationTimeUtc != mergedFiles[j + segmentStart].CreationTimeUtc) ||
                                                                        (archiveFiles[j].LastWriteTimeUtc != mergedFiles[j + segmentStart].LastWriteTimeUtc))
                                                                    {
                                                                        invalid = true;

                                                                        if (traceDynpack != null)
                                                                        {
                                                                            traceDynpack.WriteLine("File different: {0}", archiveFiles[j].ArchivePath);
                                                                        }
                                                                        messages.WriteLine("SEGMENT INTEGRITY PROBLEM {0} (file different): {1}", segment.Name, archiveFiles[j].ArchivePath);
                                                                        break;
                                                                    }
                                                                }
                                                                if (invalid)
                                                                {
                                                                    segment.Dirty.Set();
                                                                    // dirty segment will be removed in subsequent pass

                                                                    try
                                                                    {
                                                                        string tempFile = Path.GetTempFileName();
                                                                        fileRef.CopyLocal(tempFile, true/*overwrite*/);
                                                                        string message = String.Format("Copied of corrupt segment \"{0}\" to \"{1}\"", segmentFileName, tempFile);
                                                                        if (traceDynpack != null)
                                                                        {
                                                                            traceDynpack.WriteLine(message);
                                                                        }
                                                                        messages.WriteLine(ConsoleColor.Yellow, message);
                                                                    }
                                                                    catch (IOException exception)
                                                                    {
                                                                        if (threadTraceDynPack != null)
                                                                        {
                                                                            threadTraceDynPack.WriteLine("Exception verifying {0}: {1}", segmentFileName, exception);
                                                                        }
                                                                        messages.WriteLine("Exception verifying {0}: {1}", segmentFileName, exception);
                                                                        uint hr = (uint)Marshal.GetHRForException(exception);
                                                                        if (hr != 0x80070070/*out of disk space*/)
                                                                        {
                                                                            Interlocked.Exchange(ref fatal, 1);
                                                                            throw;
                                                                        }
                                                                        // running out of disk space saving the invalid segment was regarded as non-fatal
                                                                    }
                                                                }
                                                            }

                                                            if (invalid)
                                                            {
                                                                lock (badSegments)
                                                                {
                                                                    badSegments.Add(segmentFileName);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        });
                                }

                                messagesLog.Flush();
                            }
                        }

                        // turns out that updating segment serial numbers (below) could break
                        // non-dirty segment validation, as the serial number changes out from
                        // under it. therefore, introduce a barrier here.
                        concurrent.Drain(delegate() { messagesLog.Flush(); }, WaitInterval);
                        messagesLog.Flush();
                        if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                        {
                            if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                            {
                                throw new ApplicationException("Unable to continue after last error");
                            }
                        }

                        // Assign new serial numbers for dirty segments
                        segmentSerialNumbering++; // do not reuse manifest serial number
                        foreach (SegmentRecord segment in segments)
                        {
                            if (segment.Dirty.Value)
                            {
                                segment.SerialNumber = segmentSerialNumbering++;
                            }
                        }

                        // Backup (or remove if !safe) dirty segments
                        fatal = 0;
                        {
                            List<string> namesToBackupOrRemove = new List<string>(segments.Count + 1);
                            namesToBackupOrRemove.Add(DynPackManifestName);
                            foreach (SegmentRecord segment in segments)
                            {
                                if (segment.Dirty.Value)
                                {
                                    namesToBackupOrRemove.Add(segment.Name);
                                }
                            }
                            foreach (string nameEnum in namesToBackupOrRemove)
                            {
                                concurrent.WaitQueueEmpty();
                                if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                {
                                    if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                                    {
                                        abort = true;
                                        break;
                                    }
                                    fatal = 0;
                                }

                                // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                // variable) in order to capture each value in the anonymous method.
                                // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                string name = nameEnum;

                                long sequenceNumber = messagesLog.GetSequenceNumber();
                                concurrent.Do(
                                    String.Format("rename-old-segment:{0}", name),
                                    delegate(ConcurrentTasks.ITaskContext taskContext)
                                    {
                                        string segmentFileName = String.Concat(targetArchiveFileNameTemplate, ".", name, DynPackFileExtension);
                                        string segmentBackupFileName = String.Concat(targetArchiveFileNameTemplate, ".-", name, DynPackFileExtension);

                                        using (TextWriter threadTraceDynPack = TaskWriter.Create(traceDynpack))
                                        {
                                            using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                            {
                                                try
                                                {
                                                    using (TextWriter threadTraceFileManager = TaskWriter.Create(fileManager.GetMasterTrace()))
                                                    {
                                                        if (fileManager.Exists(segmentFileName, threadTraceFileManager))
                                                        {
                                                            bool manifest = name.Equals(DynPackManifestName);

                                                            // Always back up manifest. Back up segments if "safe"
                                                            // But only back up if no backup exists. Otherwise, retain the older backup files
                                                            // so that the backup is a consistent picture. They will be cleared when a
                                                            // run finally completes. (Which means delete the "newer" to keep the backup.)
                                                            if ((!manifest && !safe) || fileManager.Exists(segmentBackupFileName, threadTraceFileManager))
                                                            {
                                                                messages.WriteLine("Deleting (segment dirty): {0}", segmentFileName);
                                                                fileManager.Delete(segmentFileName, threadTraceFileManager);
                                                            }
                                                            else
                                                            {
                                                                messages.WriteLine("Renaming (segment dirty): {0} to {1}", segmentFileName, segmentBackupFileName);
                                                                fileManager.Rename(segmentFileName, segmentBackupFileName, threadTraceFileManager);
                                                            }
                                                        }
                                                    }
                                                }
                                                catch (Exception exception)
                                                {
                                                    if (threadTraceDynPack != null)
                                                    {
                                                        threadTraceDynPack.WriteLine("Exception renaming or deleting old segment {0}{1}: {2}", segmentFileName, segmentBackupFileName != null ? " to " + segmentBackupFileName : String.Empty, exception);
                                                    }
                                                    messages.WriteLine("Error renaming/deleting {0}: {1}", segmentFileName, exception.Message);

                                                    // Failure is fatal because it interferes with the integrity of backup
                                                    // files. If process were allowed to continue and files overwritten, the
                                                    // archive could be inconsistent (e.g. if old segments are not removed or
                                                    // renamed but new manifest is written, then program fails before writing
                                                    // new versions of the segments - old segment will remain while manifest
                                                    // will claim it is the new one, resulting in serial number inconsistency)
                                                    Interlocked.Exchange(ref fatal, 1);
                                                    throw;
                                                }
                                            }
                                        }
                                    });

                                messagesLog.Flush();
                            }
                        }

                        // Drain all rename/delete of old segment files so that uploads can be
                        // initiated subsequently without worry of colliding with a file that hasn't
                        // been moved out of the way yet.
                        concurrent.Drain(delegate() { messagesLog.Flush(); }, WaitInterval);
                        messagesLog.Flush();
                        if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                        {
                            if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                            {
                                throw new ApplicationException("Unable to continue after last error");
                            }
                        }


                        // From this point forward, ALL UPDATES (threadsafe or not) should be completed.
                        // Structures should be regarded as immutable/read-only


                        // redundancy check - ensure all serial numbers are valid
                        {
                            Dictionary<ulong, bool> used = new Dictionary<ulong, bool>(segments.Count);
                            for (int i = 0; i < segments.Count; i++)
                            {
                                ulong segmentSerialNumber = segments[i].SerialNumber;
                                if (segmentSerialNumber == 0)
                                {
                                    throw new InvalidOperationException("Segment serial number not initialized");
                                }
                                if (segmentSerialNumber > segmentSerialNumbering)
                                {
                                    throw new InvalidOperationException("Segment serial number beyond limit");
                                }
                                if (used.ContainsKey(segmentSerialNumber))
                                {
                                    throw new InvalidOperationException("Segment serial number used multiple times");
                                }
                                used.Add(segmentSerialNumber, false);
                            }
                        }

                        // Save manifest, diagnostic file, and html file
                        // these tasks are done synchronously since they represent a small fraction of
                        // run time for a large job.
                        {
                            if (diagnosticPath != null)
                            {
                                string newDiagnosticFile = Path.Combine(diagnosticPath, manifestFileName + DynPackManifestLogFileExtension);
                                string oldDiagnosticFile = Path.Combine(diagnosticPath, manifestFileName + DynPackManifestLogFileExtensionOld);

                                // "rotate" diagnostic files to facilitate windiff for seeing what changed
                                if (File.Exists(oldDiagnosticFile))
                                {
                                    File.Delete(oldDiagnosticFile);
                                }
                                if (File.Exists(newDiagnosticFile))
                                {
                                    File.Move(newDiagnosticFile, oldDiagnosticFile);
                                }

                                // the sole purpose of this is to compute a segment metadata digest value (using CRC32) to be written to the diagnostic log file
                                Dictionary<SegmentRecord, uint> segmentDiagnosticCRC32 = new Dictionary<SegmentRecord, uint>();
                                for (int i = 0; i < segments.Count; i++)
                                {
                                    byte[] b;
                                    using (CheckedWriteStream checkedStream = new CheckedWriteStream(Stream.Null, new CRC32()))
                                    {
                                        int start = segments[i].start.Value;
                                        int endP1 = i < segments.Count - 1 ? segments[i + 1].start.Value : mergedFiles.Count;
                                        for (int j = start; j < endP1; j++)
                                        {
                                            FileRecord record = mergedFiles[j];
                                            BinaryWriteUtils.WriteVariableLengthQuantity(checkedStream, record.EmbeddedStreamLength);
                                            if (record.CreationTimeUtc != default(DateTime))
                                            {
                                                BinaryWriteUtils.WriteStringUtf8(checkedStream, PackedFileHeaderRecord.FormatDateTime(record.CreationTimeUtc));
                                            }
                                            if (record.LastWriteTimeUtc != default(DateTime))
                                            {
                                                BinaryWriteUtils.WriteStringUtf8(checkedStream, PackedFileHeaderRecord.FormatDateTime(record.LastWriteTimeUtc));
                                            }
                                            BinaryWriteUtils.WriteStringUtf8(checkedStream, record.PartialPath.ToString());
                                        }

                                        checkedStream.Close();
                                        b = checkedStream.CheckValue;
                                    }

                                    uint checkValue = (uint)b[0] + ((uint)b[1] << 8) + ((uint)b[2] << 16) + ((uint)b[3] << 24);
                                    segmentDiagnosticCRC32.Add(segments[i], checkValue);
                                }

                                Dictionary<SegmentRecord, long> segmentSizes = new Dictionary<SegmentRecord, long>();
                                foreach (FileRecord record in mergedFiles)
                                {
                                    if (!segmentSizes.ContainsKey(record.Segment))
                                    {
                                        segmentSizes.Add(record.Segment, 0);
                                    }
                                    segmentSizes[record.Segment] = segmentSizes[record.Segment] + record.EmbeddedStreamLength + record.HeaderOverhead;
                                }

                                using (TextWriter writer = new StreamWriter(newDiagnosticFile))
                                {
                                    if (verifyNonDirtyMetadata)
                                    {
                                        writer.WriteLine("[Non-dirty segment verification enabled]");
                                        if (badSegments.Count != 0)
                                        {
                                            writer.WriteLine("{0} BAD SEGMENTS DETECTED DURING VERIFICATION:", badSegments.Count);
                                            foreach (string badSegment in badSegments)
                                            {
                                                writer.WriteLine("  {1}", badSegment);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        writer.WriteLine("[Non-dirty segment verification skipped]");
                                    }
                                    writer.WriteLine();

                                    SegmentRecord currentSegment = null;
                                    foreach (FileRecord record in mergedFiles)
                                    {
                                        if (currentSegment != record.Segment)
                                        {
                                            currentSegment = record.Segment;
                                            writer.WriteLine("SEGMENT {0} {1} {2:x8}" + Environment.NewLine + "{3} {4}", currentSegment.Name, segmentSizes[currentSegment], segmentDiagnosticCRC32[currentSegment], currentSegment.SerialNumber, currentSegment.Dirty.Value ? "dirty" : "not-dirty");
                                        }
                                    }
                                    writer.WriteLine();

                                    currentSegment = null;
                                    foreach (FileRecord record in mergedFiles)
                                    {
                                        if (currentSegment != record.Segment)
                                        {
                                            currentSegment = record.Segment;
                                            writer.WriteLine("SEGMENT {0} {1} {2:x8}", currentSegment.Name, segmentSizes[currentSegment], segmentDiagnosticCRC32[currentSegment]);
                                        }
                                        writer.WriteLine("  FILE {0,12}{4} {1} {2} {3}", record.EmbeddedStreamLength, record.CreationTimeUtc.ToString(DynPackDiagnosticDateTimeFormat), record.LastWriteTimeUtc.ToString(DynPackDiagnosticDateTimeFormat), record.PartialPath, record.Range != null ? String.Format("[{0}]", record.Range) : String.Empty);
                                    }
                                }
                                File.SetLastWriteTime(newDiagnosticFile, context.now);
                                File.SetCreationTime(newDiagnosticFile, context.now);

                                if (windiff && File.Exists(newDiagnosticFile) && File.Exists(oldDiagnosticFile))
                                {
                                    Windiff(oldDiagnosticFile, newDiagnosticFile, false/*waitForExit*/);
                                }
                            }


                            // Write actual archive manifest
                            if (traceDynpack != null)
                            {
                                traceDynpack.WriteLine("Writing: {0}", manifestFileName);
                            }
                            Console.WriteLine("Writing: {0}", manifestFileName);
                            string manifestTempFileName = String.Concat(targetArchiveFileNameTemplate, ".", DynPackManifestName, DynPackTempFileExtension);
                            using (ILocalFileCopy fileRef = fileManager.WriteTemp(manifestTempFileName, fileManager.GetMasterTrace()))
                            {
                                using (Stream fileStream = fileRef.Write())
                                {
                                    CryptoKeygroup keys = null;
                                    EncryptedFileContainerHeader fch = null;
                                    if (context.cryptoOption == EncryptionOption.Encrypt)
                                    {
                                        CryptoMasterKeyCacheEntry entry = context.encrypt.GetDefaultMasterKeyEntry();
                                        fch = new EncryptedFileContainerHeader(context.encrypt);
                                        fch.passwordSalt = entry.PasswordSalt;
                                        context.encrypt.algorithm.DeriveNewSessionKeys(entry.MasterKey, out fch.fileSalt, out keys);
                                    }

                                    DoWithStreamStack(
                                        fileStream,
                                        new StreamWrapMethod[]
                                        {
                                            delegate(Stream stream)
                                            {
                                                // see note and references about
                                                // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                                if (context.cryptoOption == EncryptionOption.Encrypt)
                                                {
                                                    return new TaggedWriteStream(stream, context.encrypt.algorithm.CreateMACGenerator(keys.SigningKey));
                                                }
                                                return null;
                                            },
                                            delegate(Stream stream)
                                            {
                                                if (context.cryptoOption == EncryptionOption.Encrypt)
                                                {
                                                    // why write here? need to write salt within HMAC container
                                                    fch.Write(stream);
                                                }
                                                return null;
                                            },
                                            delegate(Stream stream)
                                            {
                                                if (context.cryptoOption == EncryptionOption.Encrypt)
                                                {
                                                    return context.encrypt.algorithm.CreateEncryptStream(stream, keys.CipherKey, keys.InitialCounter);
                                                }
                                                return null;
                                            },
                                            delegate(Stream stream)
                                            {
                                                if (context.compressionOption == CompressionOption.Compress)
                                                {
                                                    return new BlockedCompressStream(stream);
                                                }
                                                return null;
                                            },
                                            delegate(Stream stream)
                                            {
                                                // total file CRC32 check value
                                                return new TaggedWriteStream(stream, new CRC32());
                                            }
                                        },
                                        delegate(Stream stream)
                                        {
                                            BinaryWriteUtils.WriteBytes(stream, new byte[1] { PackArchiveFixedHeaderNumber });

                                            BinaryWriteUtils.WriteVariableLengthByteArray(stream, randomArchiveSignature);

                                            BinaryWriteUtils.WriteVariableLengthQuantity(stream, segmentSerialNumbering++);

                                            BinaryWriteUtils.WriteVariableLengthQuantity(stream, PackArchiveStructureTypeManifest);

                                            string currentSegmentName = null;
                                            ulong currentSegmentSerialNumber = 0;
                                            foreach (FileRecord record in mergedFiles)
                                            {
                                                if (!String.Equals(currentSegmentName, record.Segment.Name))
                                                {
                                                    currentSegmentName = record.Segment.Name;
                                                    currentSegmentSerialNumber = record.Segment.SerialNumber;

                                                    PackedFileHeaderRecord segmentHeader = new PackedFileHeaderRecord(null, default(DateTime), default(DateTime), default(PackedFileHeaderRecord.HeaderAttributes), 0, record.Segment.Name, record.Segment.SerialNumber);
                                                    segmentHeader.Write(stream);
                                                }

                                                record.WriteHeader(stream);
                                            }

                                            PackedFileHeaderRecord.WriteNullHeader(stream);
                                        });
                                }

                                fileManager.Commit(fileRef, manifestTempFileName, manifestFileName, true/*overwrite*/, null/*progressTracker*/, fileManager.GetMasterTrace());
                            }
                        }


                        List<ProgressTracker> progressTrackers = new List<ProgressTracker>(); // Use lock() on this!
                        int maxStatusLines = 0;
                        bool progressVisible = false;
                        DateTime lastProgressUpdate = default(DateTime);
                        ConcurrentTasks.WaitIntervalMethod eraseProgress = delegate()
                        {
                            if (Interactive())
                            {
                                lock (progressTrackers)
                                {
                                    if (progressVisible)
                                    {
                                        for (int i = 0; i < maxStatusLines; i++)
                                        {
                                            Console.WriteLine(new String(' ', Math.Max(0, Console.BufferWidth - 1)));
                                        }
                                        Console.CursorTop -= maxStatusLines;

                                        progressVisible = false;
                                        lastProgressUpdate = default(DateTime);
                                    }
                                }
                            }
                        };
                        ConcurrentMessageLog.PrepareConsoleMethod prepareConsole = delegate()
                        {
                            eraseProgress();
                        };
                        ConcurrentTasks.WaitIntervalMethod showProgress = delegate()
                        {
                            if (traceDynpack != null)
                            {
                                traceDynpack.Flush();
                            }

                            messagesLog.Flush(prepareConsole);

                            if (Interactive())
                            {
                                if (lastProgressUpdate.AddMilliseconds(WaitInterval - 100) <= DateTime.Now)
                                {
                                    lock (progressTrackers)
                                    {
                                        List<string> lines = new List<string>();

                                        if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                        {
                                            lines.Add("  [fatal error pending]");
                                        }

                                        ProgressTracker[] progressTrackers2 = progressTrackers.ToArray();
                                        Array.Sort(progressTrackers2, delegate(ProgressTracker l, ProgressTracker r) { return l.Tag.CompareTo(r.Tag); });
                                        for (int i = 0; i < progressTrackers.Count; i++)
                                        {
                                            ProgressTracker progressTracker = progressTrackers2[i];
                                            string progress;
                                            if (progressTracker.Total >= 0)
                                            {
                                                progress = String.Format("{0}% of {1}", progressTracker.Current * 100 / progressTracker.Total, FileSizeString(progressTracker.Total));
                                            }
                                            else
                                            {
                                                progress = "creating";
                                            }
                                            lines.Add(String.Format("  [{0}: {1}]", progressTracker.Tag, progress));
                                        }

                                        while (lines.Count < maxStatusLines)
                                        {
                                            lines.Add(String.Empty);
                                        }
                                        maxStatusLines = lines.Count;

                                        foreach (string line in lines)
                                        {
                                            Console.WriteLine(line + new String(' ', Math.Max(0, Console.BufferWidth - 1 - line.Length)));
                                        }
                                        Console.CursorTop -= lines.Count;
                                        progressVisible = true;
                                    }

                                    lastProgressUpdate = DateTime.Now;
                                }
                            }
                        };


                        // Archive modified segments (concurrently)
                        long sharedSequenceNumber = messagesLog.GetSequenceNumber();
                        using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sharedSequenceNumber))
                        {
                            // ensure this shared sequence number is used at least once.
                        }
                        fatal = 0;
                        for (int iEnum = 0; iEnum < segments.Count; iEnum++)
                        {
                            concurrent.WaitQueueEmpty(showProgress, WaitInterval);
                            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                            {
                                if (abort || !FatalPromptContinue(concurrent, messagesLog, showProgress, WaitInterval, prepareConsole))
                                {
                                    abort = true;
                                    break;
                                }
                                fatal = 0;
                            }

                            // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                            // variable) in order to capture each value in the anonymous method.
                            // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                            int i = iEnum;
                            SegmentRecord segment = segments[i];

                            if (segment.Dirty.Value)
                            {
                                string segmentFileName = targetArchiveFileNameTemplate + "." + segment.Name + DynPackFileExtension;
                                string segmentTempFileName = targetArchiveFileNameTemplate + "." + segment.Name + DynPackTempFileExtension;

                                long sequenceNumber = sharedSequenceNumber; // messagesLog.GetSequenceNumber();

                                concurrent.Do(
                                    String.Format("write-segment:{0}", segmentFileName),
                                    delegate(ConcurrentTasks.ITaskContext taskContext)
                                    {
                                        using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                        {
                                            messages.WriteLine("Writing: {0}", segmentFileName);
                                        }

                                        ProgressTracker progressTracker = null;

                                        try
                                        {
                                            using (TextWriter threadTraceDynPack = TaskWriter.Create(traceDynpack))
                                            {
                                                using (TextWriter threadTraceFileManager = TaskWriter.Create(fileManager.GetMasterTrace()))
                                                {
                                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                                    {
                                                        progressTracker = new ProgressTracker(segmentFileName);
                                                        lock (progressTrackers)
                                                        {
                                                            progressTrackers.Add(progressTracker);
                                                        }

                                                        try
                                                        {
                                                            bool succeeded = false;
                                                            using (ILocalFileCopy fileRef = fileManager.WriteTemp(segmentTempFileName, threadTraceFileManager))
                                                            {
                                                                try
                                                                {
                                                                    if (threadTraceDynPack != null)
                                                                    {
                                                                        threadTraceDynPack.WriteLine("Writing: {0}", segmentFileName);
                                                                    }
                                                                    using (Stream fileStream = fileRef.Write())
                                                                    {
                                                                        // reserve estimated file size now, to reduce file system fragmentation
                                                                        try
                                                                        {
                                                                            long estimatedSegmentSize = segmentSizeTarget;
                                                                            int start = segment.start.Value;
                                                                            int end = (i + 1 < segments.Count) ? segments[i + 1].start.Value : mergedFiles.Count;
                                                                            int count = end - start;
                                                                            if (count == 1)
                                                                            {
                                                                                if (estimatedSegmentSize < mergedFiles[start].EmbeddedStreamLength)
                                                                                {
                                                                                    estimatedSegmentSize = mergedFiles[start].EmbeddedStreamLength;
                                                                                }
                                                                            }
                                                                            fileStream.SetLength(estimatedSegmentSize);
                                                                        }
                                                                        catch (IOException)
                                                                        {
                                                                        }

                                                                        CryptoKeygroup keys = null;
                                                                        EncryptedFileContainerHeader fch = null;
                                                                        if (context.cryptoOption == EncryptionOption.Encrypt)
                                                                        {
                                                                            CryptoMasterKeyCacheEntry entry = context.encrypt.GetDefaultMasterKeyEntry();
                                                                            fch = new EncryptedFileContainerHeader(context.encrypt);
                                                                            fch.passwordSalt = entry.PasswordSalt;
                                                                            context.encrypt.algorithm.DeriveNewSessionKeys(entry.MasterKey, out fch.fileSalt, out keys);
                                                                        }

                                                                        DoWithStreamStack(
                                                                            fileStream,
                                                                            new StreamWrapMethod[]
                                                                            {
                                                                                delegate(Stream stream)
                                                                                {
                                                                                    // see note and references about
                                                                                    // "Colin Percival, 2009, advocates encryption (CTR mode) followed by appending an HMAC of encrypted text"
                                                                                    if (context.cryptoOption == EncryptionOption.Encrypt)
                                                                                    {
                                                                                        return new TaggedWriteStream(stream, context.encrypt.algorithm.CreateMACGenerator(keys.SigningKey));
                                                                                    }
                                                                                    return null;
                                                                                },
                                                                                delegate(Stream stream)
                                                                                {
                                                                                    if (context.cryptoOption == EncryptionOption.Encrypt)
                                                                                    {
                                                                                        // why write here? need to write salt within HMAC container
                                                                                        fch.Write(stream);
                                                                                    }
                                                                                    return null;
                                                                                },
                                                                                delegate(Stream stream)
                                                                                {
                                                                                    if (context.cryptoOption == EncryptionOption.Encrypt)
                                                                                    {
                                                                                        return context.encrypt.algorithm.CreateEncryptStream(stream, keys.CipherKey, keys.InitialCounter);
                                                                                    }
                                                                                    return null;
                                                                                },
                                                                                delegate(Stream stream)
                                                                                {
                                                                                    if (context.compressionOption == CompressionOption.Compress)
                                                                                    {
                                                                                        return new BlockedCompressStream(stream);
                                                                                    }
                                                                                    return null;
                                                                                },
                                                                                delegate(Stream stream)
                                                                                {
                                                                                    // total file CRC32 check value
                                                                                    return new TaggedWriteStream(stream, new CRC32());
                                                                                }
                                                                            },
                                                                            delegate(Stream stream)
                                                                            {
                                                                                BinaryWriteUtils.WriteBytes(stream, new byte[1] { PackArchiveFixedHeaderNumber });

                                                                                BinaryWriteUtils.WriteVariableLengthByteArray(stream, randomArchiveSignature);

                                                                                BinaryWriteUtils.WriteVariableLengthQuantity(stream, segment.SerialNumber);

                                                                                BinaryWriteUtils.WriteVariableLengthQuantity(stream, PackArchiveStructureTypeFiles);

                                                                                int start = segment.start.Value;
                                                                                int end = (i + 1 < segments.Count) ? segments[i + 1].start.Value : mergedFiles.Count;
                                                                                int count = end - start;
                                                                                for (int j = 0; j < count; j++)
                                                                                {
                                                                                    const string NoOpPrefix = ".\\";
                                                                                    string fullPath = mergedFiles[j + start].PartialPath.ToString();
                                                                                    if (fullPath.StartsWith(NoOpPrefix))
                                                                                    {
                                                                                        // remove .\ from path because Path.Combine() doesn't do it,
                                                                                        // and a path that is exactly the maximum length will become
                                                                                        // too long as a result.
                                                                                        fullPath = fullPath.Substring(NoOpPrefix.Length);
                                                                                    }
                                                                                    fullPath = Path.Combine(source, fullPath);
                                                                                    PackOne(fullPath, stream, Path.GetDirectoryName(mergedFiles[j + start].PartialPath.ToString()), mergedFiles[j + start].Range, threadCount > 0/*enableRetry*/, context);
                                                                                }

                                                                                PackedFileHeaderRecord.WriteNullHeader(stream);
                                                                            });

                                                                        // remove any reserved space that turned out to be unneeded
                                                                        if (fileStream.Position < fileStream.Length)
                                                                        {
                                                                            fileStream.SetLength(fileStream.Position);
                                                                        }

                                                                        succeeded = true;
                                                                    }
                                                                }
                                                                finally
                                                                {
                                                                    if (!succeeded)
                                                                    {
                                                                        fileManager.Abandon(fileRef, segmentTempFileName, threadTraceFileManager);
                                                                    }
                                                                    else
                                                                    {
                                                                        fileManager.Commit(fileRef, segmentTempFileName, segmentFileName, false/*overwrite*/, progressTracker, threadTraceFileManager);
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        catch (Exception exception)
                                                        {
                                                            if (threadTraceDynPack != null)
                                                            {
                                                                threadTraceDynPack.WriteLine("Exception archiving {0}: {1}", segmentFileName, exception);
                                                            }
                                                            messages.WriteLine("Error archiving {0}: {1}", segmentFileName, exception.Message);

                                                            Interlocked.Exchange(ref fatal, 1);
                                                            throw;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        finally
                                        {
                                            if (progressTracker != null)
                                            {
                                                lock (progressTrackers)
                                                {
                                                    progressTrackers.Remove(progressTracker);
                                                }
                                            }
                                        }
                                    },
                                    showProgress,
                                    WaitInterval);
                            }

                            messagesLog.Flush(prepareConsole);
                            showProgress();
                        }

                        // Finish creating (or uploading) segments
                        concurrent.Drain(showProgress, WaitInterval);
                        messagesLog.Flush(prepareConsole);
                        eraseProgress();
                        if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                        {
                            if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                            {
                                throw new ApplicationException("Unable to continue after last error");
                            }
                        }


                        // upon successful completion - delete unreferenced items (backups and abandoned segments)
                        fatal = 0;
                        {
                            string targetFileNamePrefix = targetArchiveFileNameTemplate + ".";
                            foreach (string segmentFileNameEnum in fileManager.GetFileNames(targetFileNamePrefix, fileManager.GetMasterTrace()))
                            {
                                concurrent.WaitQueueEmpty(showProgress, WaitInterval);
                                if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                {
                                    if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                                    {
                                        abort = true;
                                        break;
                                    }
                                    fatal = 0;
                                }

                                // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                // variable) in order to capture each value in the anonymous method.
                                // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                string segmentFileName = segmentFileNameEnum;

                                Debug.Assert(segmentFileName.StartsWith(targetFileNamePrefix, StringComparison.OrdinalIgnoreCase));

                                string suffix = segmentFileName.Substring(targetFileNamePrefix.Length);
                                if (suffix.EndsWith(DynPackFileExtension))
                                {
                                    suffix = suffix.Substring(0, suffix.Length - DynPackFileExtension.Length);
                                    if ((suffix != DynPackManifestName)
                                        && (null == segments.Find(delegate(SegmentRecord a) { return a.Name == suffix; })))
                                    {
                                        long sequenceNumber = messagesLog.GetSequenceNumber();
                                        concurrent.Do(
                                            String.Format("cleanup:{0}", segmentFileName),
                                            delegate(ConcurrentTasks.ITaskContext taskContext)
                                            {
                                                using (TextWriter threadTraceDynPack = TaskWriter.Create(traceDynpack))
                                                {
                                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                                    {
                                                        messages.WriteLine("Deleting ({0} file): {1}", suffix.StartsWith("-") ? "backup" : "unreferenced", segmentFileName);
                                                        try
                                                        {
                                                            using (TextWriter threadTraceFileManager = TaskWriter.Create(fileManager.GetMasterTrace()))
                                                            {
                                                                fileManager.Delete(segmentFileName, threadTraceFileManager);
                                                            }
                                                        }
                                                        catch (Exception exception)
                                                        {
                                                            if (threadTraceDynPack != null)
                                                            {
                                                                threadTraceDynPack.WriteLine("Exception deleting {0}: {1}", segmentFileName, exception);
                                                            }
                                                            messages.WriteLine("Exception deleting {0}: {1}", segmentFileName, exception);

                                                            Interlocked.Exchange(ref fatal, 1);
                                                            throw;
                                                        }
                                                    }
                                                }
                                            });
                                    }
                                }

                                messagesLog.Flush();
                            }
                        }

                        // final flush of tasks and messages
                        concurrent.Drain(delegate() { messagesLog.Flush(); }, WaitInterval);
                        messagesLog.Flush();
                        if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                        {
                            if (abort || !FatalPromptContinue(concurrent, messagesLog, null, -1, null))
                            {
                                throw new ApplicationException("Unable to continue after last error");
                            }
                            fatal = 0;
                        }


                        // end concurrent region
                    }
                }
            }

            if (traceDynpack != null)
            {
                traceDynpack.Dispose();
            }

            Console.WriteLine();
        }

        private static int GetConcurrency(IArchiveFileManager fileManager, Context context)
        {
            int threadCount;
            if (context.explicitConcurrency.HasValue)
            {
                threadCount = context.explicitConcurrency.Value;
            }
            else
            {
                threadCount = Constants.ConcurrencyForDiskBound;
                if (!(fileManager is LocalArchiveFileManager))
                {
                    threadCount = Math.Max(threadCount, Constants.ConcurrencyForNetworkBound);
                }
                if ((context.cryptoOption != EncryptionOption.None)
                    || (context.compressionOption != CompressionOption.None))
                {
                    threadCount = Math.Max(threadCount, Constants.ConcurrencyForComputeBound);
                }
            }
            WebMethodsBase.EnsureConcurrency(threadCount);
            return threadCount;
        }

        private static IArchiveFileManager GetArchiveFileManager(string archivePathTemplate, out string archiveFileNameTemplate, out bool remote, Context context)
        {
            archiveFileNameTemplate = null;

            Uri uri;
            if (Uri.TryCreate(archivePathTemplate, UriKind.Absolute, out uri))
            {
                if (uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
                    || uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        int lastSlash = uri.PathAndQuery.LastIndexOf('/');
                        archiveFileNameTemplate = uri.PathAndQuery.Substring(lastSlash + 1);
                        remote = true;
                        return new RemoteArchiveFileManager(uri.Scheme + "://" + uri.Host, uri.PathAndQuery.Substring(0, lastSlash), context.refreshTokenProtected, context);
                    }
                    catch (NotSupportedException)
                    {
                        throw new UsageException(String.Format("Specified remote storage service is not supported: \"{0}\"", uri.Scheme + "://" + uri.Host));
                    }
                }
                // else fall through to local filesystem manager
            }
            // else fall through to local filesystem manager

            archiveFileNameTemplate = Path.GetFileName(archivePathTemplate);
            remote = false;
            return new LocalArchiveFileManager(context, Path.GetDirectoryName(Path.IsPathRooted(archivePathTemplate) ? archivePathTemplate : Path.Combine(Environment.CurrentDirectory, archivePathTemplate)));
        }

        private class LocalArchiveFileManager : IArchiveFileManager
        {
            // all members should be threadsafe, read-only, or protected with lock() in class code
            private Context context;
            private string root;
            private Dictionary<string, DateTime> stickyCreationTimestamps = new Dictionary<string, DateTime>();
            private Dictionary<string, LocalFileCopy> uncommittedLocalTempFiles = new Dictionary<string, LocalFileCopy>(1);

            private LocalArchiveFileManager()
            {
                throw new NotSupportedException();
            }

            public LocalArchiveFileManager(Context context, string root)
            {
                this.context = context;
                this.root = root;
            }

            public void Dispose()
            {
                root = null;

                stickyCreationTimestamps = null;

                if (uncommittedLocalTempFiles != null)
                {
                    foreach (KeyValuePair<string, LocalFileCopy> item in uncommittedLocalTempFiles)
                    {
                        item.Value.Release();
                    }
                    uncommittedLocalTempFiles.Clear();
                    uncommittedLocalTempFiles = null;
                }
            }

            private void CheckSimpleName(string name)
            {
                if (!String.Equals(Path.GetFileName(name), name))
                {
                    throw new ArgumentException();
                }
            }

            private void RememberTimestamps(string name)
            {
                lock (stickyCreationTimestamps)
                {
                    if (!stickyCreationTimestamps.ContainsKey(name))
                    {
                        string path = Path.Combine(root, name);
                        DateTime creationTime = File.GetCreationTime(path);
                        stickyCreationTimestamps.Add(name, creationTime);
                    }
                }
            }

            private void EnsureTimestamps(string name)
            {
                string path = Path.Combine(root, name);

                File.SetLastWriteTime(path, context.now);
                DateTime created;
                lock (stickyCreationTimestamps)
                {
                    if (!stickyCreationTimestamps.TryGetValue(name, out created))
                    {
                        created = context.now;
                    }
                }
                File.SetCreationTime(path, created);
            }

            public ILocalFileCopy Read(string name, ProgressTracker progressTracker, TextWriter trace)
            {
                CheckSimpleName(name);
                return new LocalFileCopy(Path.Combine(root, name), false/*writable*/, false/*delete*/);
            }

            public ILocalFileCopy WriteTemp(string nameTemp, TextWriter trace)
            {
                CheckSimpleName(nameTemp);
                string pathTemp = Path.Combine(root, nameTemp);

                if (File.Exists(pathTemp))
                {
                    File.Delete(pathTemp);
                }

                using (LocalFileCopy localCopy = new LocalFileCopy(pathTemp, true/*writable*/, false/*delete*/))
                {
                    // refcount == 1, owned by using()

                    lock (uncommittedLocalTempFiles)
                    {
                        // Could throw if nameTemp is already used
                        uncommittedLocalTempFiles.Add(nameTemp, localCopy);
                        localCopy.AddRef(); // refcount++ for uncommittedLocalTempFiles's reference
                    }

                    return localCopy.AddRef(); // refcount++ for callee's using() reference
                }
            }

            public ILocalFileCopy GetTempExisting(string localPath, string nameTemp, TextWriter trace)
            {
                CheckSimpleName(nameTemp);
                string pathTemp = Path.Combine(root, nameTemp);

                using (Stream tempStream = new FileStream(pathTemp, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    using (Stream localStream = new FileStream(localPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        tempStream.SetLength(localStream.Length);

                        byte[] buffer = new byte[Constants.BufferSize];
                        int read;
                        while ((read = localStream.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            tempStream.Write(buffer, 0, read);
                        }
                    }
                }

                using (LocalFileCopy localCopy = new LocalFileCopy(pathTemp, false/*writable*/, false/*delete*/))
                {
                    // refcount == 1, owned by using()

                    lock (uncommittedLocalTempFiles)
                    {
                        // Could throw if nameTemp is already used
                        uncommittedLocalTempFiles.Add(nameTemp, localCopy);
                        localCopy.AddRef(); // refcount++ for uncommittedLocalTempFiles's reference
                    }

                    return localCopy.AddRef(); // refcount++ for callee's using() reference
                }
            }

            public void Commit(ILocalFileCopy localFile, string nameTemp, string name, bool overwrite, ProgressTracker progressTracker, TextWriter trace)
            {
                if (!overwrite && Exists(name, trace))
                {
                    throw new InvalidOperationException();
                }

                CheckSimpleName(nameTemp);
                CheckSimpleName(name);
                string pathTemp = Path.Combine(root, nameTemp);
                string path = Path.Combine(root, name);

                if (!File.Exists(pathTemp))
                {
                    throw new InvalidOperationException();
                }

                if (pathTemp != ((LocalFileCopy)localFile).LocalFilePath)
                {
                    throw new InvalidOperationException();
                }

                LocalFileCopy uncommitted;
                lock (uncommittedLocalTempFiles)
                {
                    if (!uncommittedLocalTempFiles.TryGetValue(nameTemp, out uncommitted)
                        || (uncommitted != localFile))
                    {
                        throw new InvalidOperationException();
                    }

                    uncommittedLocalTempFiles.Remove(nameTemp); // transfer ownership to using()
                }
                using (uncommitted) // refcount-- at end of scope
                {

                    if (!name.Equals(nameTemp))
                    {
                        if (Exists(name, trace))
                        {
                            Delete(name, trace); // use our version - records creation timestamp
                        }

                        uncommitted.Vacate(); // give up ownership - file will survive program termination
                        File.Move(pathTemp, path); // move file to final permanent location
                    }

                    EnsureTimestamps(name);
                }
            }

            public void Abandon(ILocalFileCopy localFile, string nameTemp, TextWriter trace)
            {
                CheckSimpleName(nameTemp);
                string pathTemp = Path.Combine(root, nameTemp);

                if (pathTemp != ((LocalFileCopy)localFile).LocalFilePath)
                {
                    throw new InvalidOperationException();
                }

                LocalFileCopy uncommitted;
                lock (uncommittedLocalTempFiles)
                {
                    if (!uncommittedLocalTempFiles.TryGetValue(nameTemp, out uncommitted)
                        || (uncommitted != localFile))
                    {
                        throw new InvalidOperationException();
                    }
                    uncommittedLocalTempFiles.Remove(nameTemp);
                }
                uncommitted.Release();

                File.Delete(pathTemp);
            }

            public void Delete(string name, TextWriter trace)
            {
                CheckSimpleName(name);
                string path = Path.Combine(root, name);

                if (!File.Exists(path))
                {
                    throw new FileNotFoundException(name);
                }

                lock (stickyCreationTimestamps)
                {
                    if (!stickyCreationTimestamps.ContainsKey(name))
                    {
                        DateTime creationTime = File.GetCreationTime(path);
                        stickyCreationTimestamps.Add(name, creationTime);
                    }
                }

                File.Delete(path);
            }

            public void DeleteById(string id, TextWriter trace)
            {
                throw new NotSupportedException();
            }

            public bool Exists(string name, TextWriter trace)
            {
                CheckSimpleName(name);
                string path = Path.Combine(root, name);
                return File.Exists(path) || Directory.Exists(path);
            }

            public void Rename(string oldName, string newName, TextWriter trace)
            {
                CheckSimpleName(oldName);
                CheckSimpleName(newName);
                RememberTimestamps(oldName);
                File.Move(Path.Combine(root, oldName), Path.Combine(root, newName));
                EnsureTimestamps(newName);
            }

            public void RenameById(string id, string newName, TextWriter trace)
            {
                throw new NotSupportedException();
            }

            public string[] GetFileNames(string prefix, TextWriter trace)
            {
                if (prefix == null)
                {
                    prefix = String.Empty;
                }
                if (FileNamePatternMatch.ContainsWildcards(prefix))
                {
                    throw new ArgumentException();
                }

                string[] files = Directory.GetFileSystemEntries(root, prefix + "*");
                for (int i = 0; i < files.Length; i++)
                {
                    files[i] = Path.GetFileName(files[i]);
                }
                return files;
            }

            public void GetFileInfo(string name, out string id, out bool directory, out DateTime created, out DateTime modified, out long size, TextWriter trace)
            {
                CheckSimpleName(name);
                string path = Path.Combine(root, name);

                if (!File.Exists(path) && !Directory.Exists(path))
                {
                    throw new FileNotFoundException(name);
                }

                id = null;
                directory = Directory.Exists(path);
                created = File.GetCreationTime(path);
                modified = File.GetLastWriteTime(path);
                size = File.Exists(path) ? GetFileLength(path) : -1;
            }

            public void GetFileInfo(string name, out bool directory, TextWriter trace)
            {
                string id;
                DateTime created, modified;
                long size;
                GetFileInfo(name, out id, out directory, out created, out modified, out size, trace);
            }

            public void GetQuota(out long quotaTotal, out long quotaUsed, TextWriter trace)
            {
                quotaTotal = Int64.MaxValue;
                quotaUsed = 0;
            }

            public TextWriter GetMasterTrace() // TextWriter is threadsafe; remains owned - do not Dispose()
            {
                return null;
            }
        }

        private struct DynUnpackJournalEntry
        {
            public readonly string segmentName;
            public readonly ulong segmentSerialNumber;

            public DynUnpackJournalEntry(string segmentName, ulong segmentSerialNumber)
            {
                this.segmentName = segmentName;
                this.segmentSerialNumber = segmentSerialNumber;
            }

            public DynUnpackJournalEntry(string line)
            {
                string[] parts = line.Split(new char[] { '(', ',', ')' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length != 2)
                {
                    throw new InvalidDataException();
                }
                this.segmentName = parts[0];
                this.segmentSerialNumber = UInt64.Parse(parts[1]);
            }

            public void WriteLine(TextWriter writer)
            {
                writer.WriteLine("({0}, {1})", segmentName, segmentSerialNumber);
            }
        }

        internal static void ValidateOrUnpackDynamicInternal(string archivePathTemplate, string targetDirectory, Context context, UnpackMode mode, string journalPath)
        {
            FaultInstanceNode faultValidateOrUnpackDynamicInternal = context.faultInjectionRoot.Select("ValidateOrUnpackDynamicInternal");

            int fatal = 0;
            OneWaySwitch invalid = new OneWaySwitch();
            ConcurrentTasks.CompletionObject[] completionTable = null;

            const string ExpectedManifestExtension = "." + DynPackManifestName + DynPackFileExtension;
            string manifestPath = archivePathTemplate + ExpectedManifestExtension;

            Dictionary<string, DynUnpackJournalEntry> journal = new Dictionary<string, DynUnpackJournalEntry>();
            ulong journalManifestSerialNumber = 0;
            byte[] journalRandomArchiveSignatureDigest = null;
            if ((mode & UnpackMode.Resume) == UnpackMode.Resume)
            {
                if (File.Exists(journalPath))
                {
                    using (TextReader reader = new StreamReader(journalPath, Encoding.UTF8))
                    {
                        string line;

                        line = reader.ReadLine();
                        if (line != null)
                        {
                            journalRandomArchiveSignatureDigest = HexDecode(line);
                        }

                        line = reader.ReadLine();
                        if (line != null)
                        {
                            journalManifestSerialNumber = UInt64.Parse(line);
                        }

                        while ((line = reader.ReadLine()) != null)
                        {
                            try
                            {
                                DynUnpackJournalEntry journalEntry = new DynUnpackJournalEntry(line);
                                journal.Add(journalEntry.segmentName, journalEntry);
                            }
                            catch (Exception)
                            {
                                // ignore improperly formatted entries - file may have been truncated
                                Console.WriteLine("Journal: ignoring improperly formatted entry");
                            }
                        }
                    }
                }
            }
            else
            {
                if (File.Exists(journalPath))
                {
                    throw new UsageException("Journal already exists, but -resume not specified");
                }
            }

            TextWriter traceDynunpack = context.traceEnabled ? Logging.CreateLogFile(DynUnpackTraceFilePrefix) : null;

            string archiveFileNameTemplate;
            string manifestFileName = Path.GetFileName(manifestPath);
            bool remote;
            using (IArchiveFileManager fileManager = GetArchiveFileManager(archivePathTemplate, out archiveFileNameTemplate, out remote, context))
            {
                string targetFileNamePrefix = archiveFileNameTemplate + ".";


                Dictionary<ulong, bool> usedMapping = new Dictionary<ulong, bool>(); // use lock() on this!


                if (!fileManager.Exists(manifestFileName, fileManager.GetMasterTrace()))
                {
                    Console.WriteLine("Manifest file \"{0}\" could not be found", manifestFileName);
                    throw new UsageException();
                }


                // read manifest
                ulong manifestSerialNumber;
                byte[] randomArchiveSignature;
                UnpackedFileRecord[] manifestFileList;
                Console.WriteLine("Reading {0}", manifestFileName);
                using (ILocalFileCopy fileRef = fileManager.Read(manifestFileName, null/*progressTracker*/, fileManager.GetMasterTrace()))
                {
                    using (Stream manifestStream = fileRef.Read())
                    {
                        ApplicationException[] deferredExceptions;
                        manifestFileList = UnpackInternal(manifestStream, targetDirectory, context, UnpackMode.Parse, out manifestSerialNumber, out randomArchiveSignature, traceDynunpack, faultValidateOrUnpackDynamicInternal.Select("Segment", manifestFileName), out deferredExceptions);
                        Debug.Assert(deferredExceptions == null); // load manifest should never generate deferred exceptions
                    }
                }

                byte[] randomArchiveSignatureDigest;
                {
                    SHA256 sha256 = SHA256.Create();
                    randomArchiveSignatureDigest = sha256.ComputeHash(randomArchiveSignature);
                }

                if (journalRandomArchiveSignatureDigest != null)
                {
                    if (!ArrayEqual(journalRandomArchiveSignatureDigest, randomArchiveSignatureDigest))
                    {
                        throw new UsageException("Journal appears to be for a different archive.");
                    }

                    if (journalManifestSerialNumber != manifestSerialNumber)
                    {
                        ConsoleWriteLineColor(ConsoleColor.Yellow, "Journal was generated with older version of manifest. Updated segments will be re-unpacked. Files that were extracted from previous version and do not exist in new version may be left behind on disk. Continue? [y/n]");
                        while (true)
                        {
                            char key = WaitReadKey(false/*intercept*/);
                            Console.WriteLine();
                            if (key == 'y')
                            {
                                break;
                            }
                            else if (key == 'n')
                            {
                                throw new ApplicationException("The user cancelled the operation");
                            }
                        }
                    }
                }

                journalRandomArchiveSignatureDigest = null;
                journalManifestSerialNumber = 0;


                // process manifest contents
                Dictionary<string, ulong> serialNumberMapping = new Dictionary<string, ulong>();
                List<string> segmentNameList = new List<string>();
                foreach (UnpackedFileRecord file in manifestFileList)
                {
                    string segmentName = file.SegmentName;
                    ulong segmentSerialNumber = file.SegmentSerialNumber;
                    if ((segmentSerialNumber == 0) || (segmentSerialNumber >= manifestSerialNumber))
                    {
                        ConsoleWriteLineColor(ConsoleColor.Yellow, "Manifest segment {0}: serial number {1} is invalid", segmentName, segmentSerialNumber);
                        invalid.Set();
                        if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                        {
                            goto Abort; // if unpacking, abort, otherwise continue to see what else is wrong
                        }
                    }
                    ulong expectedSerialNumber;
                    if (serialNumberMapping.TryGetValue(segmentName.ToLowerInvariant(), out expectedSerialNumber))
                    {
                        if (expectedSerialNumber != segmentSerialNumber)
                        {
                            ConsoleWriteLineColor(ConsoleColor.Yellow, "Manifest segment {0}: wrong serial number (is {1}, should be {2})", segmentName, segmentSerialNumber, expectedSerialNumber);
                            invalid.Set();
                            if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                            {
                                goto Abort; // if unpacking, abort, otherwise continue to see what else is wrong
                            }
                        }
                    }
                    else
                    {
                        serialNumberMapping.Add(segmentName, segmentSerialNumber);
                        usedMapping.Add(segmentSerialNumber, false);
                        segmentNameList.Add(segmentName);

                        DynUnpackJournalEntry journalEntry;
                        if (journal.TryGetValue(segmentName, out journalEntry))
                        {
                            if (journalEntry.segmentSerialNumber != segmentSerialNumber)
                            {
                                Console.WriteLine("Journal: segment {0} changed since last run", segmentName);
                                journal.Remove(segmentName);
                            }
                        }
                    }
                }

                Dictionary<string, string> dependencyGraph = new Dictionary<string, string>();
                Dictionary<string, int> completionIndexTable = new Dictionary<string, int>();
                {
                    int completionCounter = 0;
                    if (traceDynunpack != null)
                    {
                        traceDynunpack.WriteLine("Dependency graph (for ranged segment serialization):");
                    }
                    for (int i = 1; i < manifestFileList.Length; i++)
                    {
                        if ((manifestFileList[i].Range != null)
                            && String.Equals(manifestFileList[i].FullPath, manifestFileList[i - 1].FullPath)
                            && (manifestFileList[i].SegmentSerialNumber != manifestFileList[i - 1].SegmentSerialNumber))
                        {
                            dependencyGraph.Add(manifestFileList[i].SegmentName, manifestFileList[i - 1].SegmentName);
                            completionIndexTable.Add(manifestFileList[i - 1].SegmentName, completionCounter);
                            if (traceDynunpack != null)
                            {
                                traceDynunpack.WriteLine("{0} --> {1} (completion-index={2})", manifestFileList[i].SegmentName, manifestFileList[i - 1].SegmentName, completionCounter);
                            }
                            completionCounter++;
                        }
                    }
                    if (traceDynunpack != null)
                    {
                        traceDynunpack.WriteLine();
                    }
                    completionTable = new ConcurrentTasks.CompletionObject[completionCounter];
                }

                manifestFileList = null;

                if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                {
                    Directory.CreateDirectory(targetDirectory);
                }


                // enumerate invalid files
                foreach (string segmentFileName in fileManager.GetFileNames(targetFileNamePrefix, fileManager.GetMasterTrace()))
                {
                    string name = segmentFileName.Substring(targetFileNamePrefix.Length, segmentFileName.Length - targetFileNamePrefix.Length - DynPackFileExtension.Length);

                    bool manifest = String.Equals(segmentFileName, manifestFileName, StringComparison.OrdinalIgnoreCase);
                    bool eligible = !manifest
                        && segmentFileName.EndsWith(DynPackFileExtension, StringComparison.OrdinalIgnoreCase);

                    if (!eligible && !manifest)
                    {
                        if (traceDynunpack != null)
                        {
                            traceDynunpack.WriteLine("skipping {0} - invalid extension", segmentFileName);
                        }
                    }

                    bool member = serialNumberMapping.ContainsKey(name);
                    if (eligible && !member && !manifest)
                    {
                        if (traceDynunpack != null)
                        {
                            traceDynunpack.WriteLine("Validation error: {0} not a member of this archive", segmentFileName);
                        }
                        ConsoleWriteLineColor(ConsoleColor.Yellow, "Error: {0} is not a member of this archive", segmentFileName);

                        // it is considered a validation error (because someone could "unpack *") but continue
                        // to look for other errors or proceed with unpack (this method won't unpack extraneous
                        // files such as this one).
                        invalid.Set();
                    }
                }


                using (TextWriter journalWriter = journalPath != null ? TextWriter.Synchronized(new StreamWriter(journalPath, false/*append*/, Encoding.UTF8)) : null)
                {
                    if (journalWriter != null)
                    {
                        journalWriter.WriteLine(HexEncode(randomArchiveSignatureDigest));
                        journalWriter.WriteLine(manifestSerialNumber);
                        foreach (KeyValuePair<string, DynUnpackJournalEntry> journalEntry in journal)
                        {
                            journalEntry.Value.WriteLine(journalWriter);
                        }
                        journalWriter.Flush(); // ensure data is pushed out of process in case of failure in manifest loading code (next)
                    }


                    // set up concurrency status reporting
                    using (ConcurrentMessageLog messagesLog = new ConcurrentMessageLog(Interactive(), true/*enableSequencing*/))
                    {
                        int threadCount = GetConcurrency(fileManager, context);
                        using (ConcurrentTasks concurrent = new ConcurrentTasks(threadCount, 0, messagesLog, fileManager.GetMasterTrace()))
                        {
                            const int WaitInterval = 2000; // milliseconds
                            List<ProgressTracker> progressTrackers = new List<ProgressTracker>(); // Use lock() on this!
                            int maxStatusLines = 0;
                            bool progressVisible = false;
                            DateTime lastProgressUpdate = default(DateTime);
                            ConcurrentTasks.WaitIntervalMethod eraseProgress = delegate()
                            {
                                if (Interactive())
                                {
                                    lock (progressTrackers)
                                    {
                                        if (progressVisible)
                                        {
                                            for (int i = 0; i < maxStatusLines; i++)
                                            {
                                                Console.WriteLine(new String(' ', Math.Max(0, Console.BufferWidth - 1)));
                                            }
                                            Console.CursorTop -= maxStatusLines;

                                            progressVisible = false;
                                            lastProgressUpdate = default(DateTime);
                                        }
                                    }
                                }
                            };
                            ConcurrentMessageLog.PrepareConsoleMethod prepareConsole = delegate()
                            {
                                eraseProgress();
                            };
                            ConcurrentTasks.WaitIntervalMethod showProgress = delegate()
                            {
                                messagesLog.Flush(prepareConsole);

                                if (Interactive())
                                {
                                    if (lastProgressUpdate.AddMilliseconds(WaitInterval - 100) <= DateTime.Now)
                                    {
                                        lock (progressTrackers)
                                        {
                                            List<string> lines = new List<string>();

                                            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                            {
                                                lines.Add("  [fatal error pending]");
                                            }

                                            ProgressTracker[] progressTrackers2 = progressTrackers.ToArray();
                                            Array.Sort(progressTrackers2, delegate(ProgressTracker l, ProgressTracker r) { return l.Tag.CompareTo(r.Tag); });
                                            for (int i = 0; i < progressTrackers.Count; i++)
                                            {
                                                ProgressTracker progressTracker = progressTrackers2[i];
                                                string progress;
                                                if ((progressTracker.Current == 0) || (progressTracker.Total >= 0))
                                                {
                                                    progress = String.Format("{0}%{1}", progressTracker.Current * 100 / Math.Max(progressTracker.Total, 1), progressTracker.Total > 0 ? String.Format(" of {0}", FileSizeString(Math.Max(progressTracker.Total, 0))) : String.Empty);
                                                }
                                                else
                                                {
                                                    progress = "processing";
                                                }
                                                lines.Add(String.Format("  [{0}: {1}]", progressTracker.Tag, progress));
                                            }

                                            while (lines.Count < maxStatusLines)
                                            {
                                                lines.Add(String.Empty);
                                            }
                                            maxStatusLines = lines.Count;

                                            foreach (string line in lines)
                                            {
                                                Console.WriteLine(line + new String(' ', Math.Max(0, Console.BufferWidth - 1 - line.Length)));
                                            }
                                            Console.CursorTop -= lines.Count;
                                            progressVisible = true;
                                        }

                                        lastProgressUpdate = DateTime.Now;
                                    }
                                }
                            };


                            // process segments (concurrently)
                            long sharedSequenceNumber = messagesLog.GetSequenceNumber();
                            using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sharedSequenceNumber))
                            {
                                // ensure this shared sequence number is used at least once.
                            }
                            foreach (String segmentNameEnum in segmentNameList)
                            {
                                concurrent.WaitQueueEmpty(showProgress, WaitInterval);
                                if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                {
                                    break;
                                }


                                // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                // variable) in order to capture each value in the anonymous method.
                                // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                string name = segmentNameEnum;

                                string segmentFileName = String.Concat(targetFileNamePrefix, name, DynPackFileExtension);

                                bool exists = fileManager.Exists(segmentFileName, fileManager.GetMasterTrace());
                                bool processedPreviousRun;
                                lock (journal)
                                {
                                    processedPreviousRun = journal.ContainsKey(name);
                                }
                                if (processedPreviousRun || !exists)
                                {
                                    if (processedPreviousRun)
                                    {
                                        if (traceDynunpack != null)
                                        {
                                            traceDynunpack.WriteLine("Journal: skipping {0} - processed during previous run", segmentFileName);
                                        }
                                        using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                        {
                                            messages.WriteLine("Journal: skipping {0} - processed during previous run", segmentFileName);
                                        }
                                    }
                                    if (!exists)
                                    {
                                        if (traceDynunpack != null)
                                        {
                                            traceDynunpack.WriteLine("Skipping {0}: file does not exist", segmentFileName);
                                        }
                                        using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                        {
                                            messages.WriteLine(ConsoleColor.Yellow, "Skipping {0}: file does not exist", segmentFileName);
                                        }
                                    }

                                    int completionIndex;
                                    if (completionIndexTable.TryGetValue(name, out completionIndex))
                                    {
                                        Debug.Assert(completionTable[completionIndex] == null);
                                        completionTable[completionIndex] = new ConcurrentTasks.NullCompletionObject();
                                        completionTable[completionIndex].SetSucceeded();
                                        if (traceDynunpack != null)
                                        {
                                            traceDynunpack.WriteLine("  dependency exists: creating NullCompletionObject for task {0} index {1}; setting succeeded", name, completionIndex);
                                        }
                                    }

                                    continue;
                                }

                                if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                {
                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                    {
                                        messages.WriteLine("Unpacking {0}", segmentFileName);
                                    }
                                }

                                long sequenceNumber = sharedSequenceNumber;

                                // if task has dependency, ask for completion object
                                bool needCompletionObject = false;
                                int completionIndex2 = 0;
                                ConcurrentTasks.CompletionObject[] completionObjectReceiver = new ConcurrentTasks.CompletionObject[1];
                                if (needCompletionObject = completionIndexTable.TryGetValue(name, out completionIndex2))
                                {
                                    completionObjectReceiver = completionTable;
                                    Debug.Assert(completionTable[completionIndex2] == null);
                                    if (traceDynunpack != null)
                                    {
                                        traceDynunpack.WriteLine("  [dependency exists: preparing to receive CompletionObject for task {0} index {1}", name, completionIndex2);
                                    }
                                }

                                concurrent.Do(
                                    String.Format("unpack:{0}", segmentFileName),
                                    needCompletionObject,
                                    out completionObjectReceiver[completionIndex2],
                                    delegate(ConcurrentTasks.ITaskContext taskContext)
                                    {
                                        using (TextWriter threadTraceDynunpack = TaskWriter.Create(traceDynunpack))
                                        {
                                            if (threadTraceDynunpack != null)
                                            {
                                                threadTraceDynunpack.WriteLine("unpack:{0}", segmentFileName);
                                            }

                                            using (TextWriter threadTraceFileManager = TaskWriter.Create(fileManager.GetMasterTrace()))
                                            {
                                                if (threadTraceFileManager != null)
                                                {
                                                    threadTraceFileManager.WriteLine("unpack:{0}", segmentFileName);
                                                }

                                                ProgressTracker progressTracker = null;

                                                try
                                                {
                                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(sequenceNumber))
                                                    {
                                                        progressTracker = new ProgressTracker(segmentFileName);
                                                        lock (progressTrackers)
                                                        {
                                                            progressTrackers.Add(progressTracker);
                                                        }

                                                        ulong segmentSerialNumber = 0;
                                                        try
                                                        {
                                                            using (ILocalFileCopy fileRef = fileManager.Read(segmentFileName, progressTracker, threadTraceFileManager))
                                                            {
                                                                using (Stream segmentStream = fileRef.Read())
                                                                {
                                                                    progressTracker.Reset();


                                                                    // wait on dependency - before unpacking data

                                                                    string dependentOnName;
                                                                    if (dependencyGraph.TryGetValue(name, out dependentOnName))
                                                                    {
                                                                        if (threadTraceDynunpack != null)
                                                                        {
                                                                            threadTraceDynunpack.WriteLine("dependency: waiting for completion of {0}", dependentOnName);
                                                                        }

                                                                        int completionIndex;
                                                                        if (!completionIndexTable.TryGetValue(dependentOnName, out completionIndex))
                                                                        {
                                                                            if (threadTraceDynunpack != null)
                                                                            {
                                                                                threadTraceDynunpack.WriteLine("  completion object missing for required dependency {0}", dependentOnName);
                                                                            }
                                                                            Interlocked.Exchange(ref fatal, 1);
                                                                            throw new InvalidOperationException();
                                                                        }

                                                                        ConcurrentTasks.CompletionObject completionObject = completionTable[completionIndex];
                                                                        if (completionObject == null)
                                                                        {
                                                                            if (threadTraceDynunpack != null)
                                                                            {
                                                                                threadTraceDynunpack.WriteLine("  completion object null for index={0}", completionIndex);
                                                                            }
                                                                            Interlocked.Exchange(ref fatal, 1);
                                                                            throw new InvalidOperationException();
                                                                        }

                                                                        completionObject.Wait();

                                                                        if (threadTraceDynunpack != null)
                                                                        {
                                                                            threadTraceDynunpack.WriteLine("  wait completed, proceeding");
                                                                        }

                                                                        if (!completionObject.Succeeded)
                                                                        {
                                                                            if (threadTraceDynunpack != null)
                                                                            {
                                                                                threadTraceDynunpack.WriteLine("  dependency task failed, aborting");
                                                                            }
                                                                            Interlocked.Exchange(ref fatal, 1);
                                                                            throw new InvalidOperationException();
                                                                        }
                                                                    }


                                                                    // membership and MAC validation

                                                                    byte[] segmentRandomArchiveSignature;

                                                                    ApplicationException[] deferredExceptions;
                                                                    UnpackedFileRecord[] segmentFileList;

                                                                    UnpackMode firstPassMode;
                                                                    if (((mode & UnpackMode.Unpack) != UnpackMode.Unpack) || !context.doNotPreValidateMAC)
                                                                    {
                                                                        firstPassMode = (mode & ~UnpackMode.Unpack) | UnpackMode.SignatureOnly;
                                                                    }
                                                                    else
                                                                    {
                                                                        firstPassMode = mode;
                                                                    }
                                                                    segmentFileList = UnpackInternal(segmentStream, targetDirectory, context, firstPassMode, out segmentSerialNumber, out segmentRandomArchiveSignature, threadTraceDynunpack, faultValidateOrUnpackDynamicInternal.Select("Segment", segmentFileName), out deferredExceptions);
                                                                    if (deferredExceptions != null)
                                                                    {
                                                                        throw new DeferredMultiException(deferredExceptions);
                                                                    }

                                                                    if (!ArrayEqual(segmentRandomArchiveSignature, randomArchiveSignature))
                                                                    {
                                                                        messages.WriteLine(ConsoleColor.Yellow, "Segment {0}: random signature number is invalid - segment does not belong to this archive. Segment may have been inadvertently included, or segments have been deliberately tampered with. Examine unpacked contents carefully!", name);
                                                                        invalid.Set();
                                                                        if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                                                        {
                                                                            Interlocked.Exchange(ref fatal, 1);
                                                                            return; // if unpacking, abort, otherwise continue to see what else is wrong
                                                                        }
                                                                    }

                                                                    if ((segmentSerialNumber == 0) || (segmentSerialNumber >= manifestSerialNumber))
                                                                    {
                                                                        messages.WriteLine(ConsoleColor.Yellow, "Segment {0}: serial number {1} is invalid", name, segmentSerialNumber);
                                                                        invalid.Set();
                                                                        if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                                                        {
                                                                            Interlocked.Exchange(ref fatal, 1);
                                                                            return; // if unpacking, abort, otherwise continue to see what else is wrong
                                                                        }
                                                                    }

                                                                    ulong expectedSerialNumber;
                                                                    if (serialNumberMapping.TryGetValue(name.ToLowerInvariant(), out expectedSerialNumber))
                                                                    {
                                                                        if (expectedSerialNumber != segmentSerialNumber)
                                                                        {
                                                                            messages.WriteLine(ConsoleColor.Yellow, "Segment {0}: wrong serial number (is {1}, should be {2})", name, segmentSerialNumber, expectedSerialNumber);
                                                                            invalid.Set();
                                                                            if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                                                            {
                                                                                Interlocked.Exchange(ref fatal, 1);
                                                                                return; // if unpacking, abort, otherwise continue to see what else is wrong
                                                                            }
                                                                        }
                                                                        else
                                                                        {
                                                                            lock (usedMapping)
                                                                            {
                                                                                usedMapping[segmentSerialNumber] = true;
                                                                            }
                                                                        }
                                                                    }
                                                                    else
                                                                    {
                                                                        messages.WriteLine(ConsoleColor.Yellow, "Segment {0}: segment is extraneous (not referenced from manifest)", name);
                                                                        invalid.Set();
                                                                        if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                                                        {
                                                                            Interlocked.Exchange(ref fatal, 1);
                                                                            return; // if unpacking, abort, otherwise continue to see what else is wrong
                                                                        }
                                                                    }


                                                                    // content validation or unpacking pass, if not done earlier

                                                                    if (((mode & UnpackMode.Unpack) == UnpackMode.Unpack) && ((firstPassMode & UnpackMode.Unpack) != UnpackMode.Unpack))
                                                                    {
                                                                        segmentStream.Position = 0; // rewind
                                                                        segmentFileList = UnpackInternal(segmentStream, targetDirectory, context, mode, out segmentSerialNumber, out segmentRandomArchiveSignature, threadTraceDynunpack, faultValidateOrUnpackDynamicInternal.Select("Segment", segmentFileName), out deferredExceptions);
                                                                        if (deferredExceptions != null)
                                                                        {
                                                                            throw new DeferredMultiException(deferredExceptions);
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        catch (DeferredMultiException exception)
                                                        {
                                                            messages.WriteLine(ConsoleColor.Yellow, "Segment {0}: {1}", name, exception);
                                                            invalid.Set();
                                                            // continue processing remaining files
                                                        }
                                                        catch (Exception exception)
                                                        {
                                                            if (!(exception is TaggedReadStream.TagInvalidException)
                                                               && !(exception is InvalidDataException))
                                                            {
                                                                messages.WriteLine("Exception processing {0}: {1}", segmentFileName, exception);
                                                                Interlocked.Exchange(ref fatal, 1);
                                                                throw;
                                                            }

                                                            messages.WriteLine(ConsoleColor.Yellow, "Segment {0}: {1}", name, exception.Message);
                                                            invalid.Set();
                                                            if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                                            {
                                                                Interlocked.Exchange(ref fatal, 1);
                                                                return; // if unpacking, abort, otherwise continue to see what else is wrong
                                                            }
                                                            // do nothing further with cryptographically inauthentic segments
                                                            return;
                                                        }

                                                        DynUnpackJournalEntry journalEntry = new DynUnpackJournalEntry(name, segmentSerialNumber);
                                                        lock (journal)
                                                        {
                                                            journal.Add(journalEntry.segmentName, journalEntry);
                                                        }
                                                        if (journalWriter != null)
                                                        {
                                                            journalEntry.WriteLine(journalWriter);
                                                            journalWriter.Flush();
                                                        }

                                                        taskContext.SetSucceeded();
                                                    }
                                                }
                                                finally
                                                {
                                                    if (progressTracker != null)
                                                    {
                                                        lock (progressTrackers)
                                                        {
                                                            progressTrackers.Remove(progressTracker);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    showProgress,
                                    WaitInterval);

                                messagesLog.Flush(prepareConsole);
                                showProgress();
                            }

                            // Finish parsing or unpacking segments
                            concurrent.Drain(showProgress, WaitInterval);
                            messagesLog.Flush(prepareConsole);
                            eraseProgress();
                            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                            {
                                if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                {
                                    if (traceDynunpack != null)
                                    {
                                        traceDynunpack.WriteLine("aborting");
                                    }
                                    goto Abort;
                                }
                            }


                            // final pass to list missing segments
                            foreach (KeyValuePair<string, ulong> declaredSegments in serialNumberMapping)
                            {
                                if (!usedMapping[declaredSegments.Value])
                                {
                                    ConsoleWriteLineColor(ConsoleColor.Yellow, "Segment {0}: missing segment (referenced in manifest, serial number {1})", declaredSegments.Key, declaredSegments.Value);
                                    invalid.Set();
                                    if ((mode & UnpackMode.Unpack) == UnpackMode.Unpack)
                                    {
                                        goto Abort; // if unpacking, abort, otherwise continue to see what else is wrong
                                    }
                                }
                            }
                        }
                    }
                }
            }

        Abort:

            if (traceDynunpack != null)
            {
                traceDynunpack.Close();
            }

            if (completionTable != null)
            {
                foreach (ConcurrentTasks.CompletionObject completionObject in completionTable)
                {
                    if (completionObject != null)
                    {
                        completionObject.Dispose();
                    }
                }
            }

            if (invalid.Value)
            {
                throw new ExitCodeException((int)ExitCodes.ConditionNotSatisfied);
            }
            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
            {
                throw new ApplicationException();
            }
        }

        internal static void DynamicUnpack(string manifestPrefix, string targetDirectory, Context context, string[] args)
        {
            UnpackMode mode = UnpackMode.Unpack;

            // options
            bool resume = false;
            string journalPath = null;

            while (args.Length > 0)
            {
                switch (args[0])
                {
                    default:
                        throw new UsageException();
                    case "-resume":
                        GetAdHocArgument(ref args, "-resume", false/*defaultValue*/, true/*explicitValue*/, out resume);
                        if (resume)
                        {
                            mode |= UnpackMode.Resume;
                        }
                        break;
                    case "-journal":
                        GetAdHocArgument(ref args, "-journal", null/*defaultValue*/, delegate(string s) { return s; }, out journalPath);
                        break;
                }
            }

#if false // In remote case, causes download of all data twice. Per-segment prevalidation still occurs.
            if ((context.cryptoOption != EncryptionOption.None) && !context.doNotPreValidateMAC)
            {
                ValidateOrUnpackDynamicInternal(manifestPrefix, ".", context, UnpackMode.ParseOnly,args);
                // throws ExitCodeException()
            }
#endif

            ValidateOrUnpackDynamicInternal(manifestPrefix, targetDirectory, context, mode, journalPath);
            // throws ExitCodeException()
        }

        internal static void ValidateDynamicPack(string manifestPrefix, Context context)
        {
            ValidateOrUnpackDynamicInternal(manifestPrefix, ".", context, UnpackMode.Parse, null/*journalPath*/);
            // throws ExitCodeException()
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Remote web service access tools
        //
        ////////////////////////////////////////////////////////////////////////////

        public static void RemoteCommand(string[] args, Context context)
        {
            IArchiveFileManager fileManager;
            string path;

            if (args.Length < 1)
            {
                throw new UsageException();
            }

            string serviceUrl = args[0];
            Uri serviceUri;
            if (Uri.TryCreate(serviceUrl, UriKind.Absolute, out serviceUri)
                && (serviceUri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
                || serviceUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)))
            {
                if (!serviceUrl.EndsWith("/"))
                {
                    throw new UsageException();
                }

                try
                {
                    int lastSlash = serviceUri.PathAndQuery.LastIndexOf('/');
                    string name = serviceUri.PathAndQuery.Substring(lastSlash + 1);
                    Debug.Assert(String.IsNullOrEmpty(name));
                    path = serviceUri.PathAndQuery.Substring(0, lastSlash);
                    fileManager = new RemoteArchiveFileManager(serviceUri.Scheme + "://" + serviceUri.Host, path, context.refreshTokenProtected, context);
                }
                catch (NotSupportedException)
                {
                    throw new UsageException(String.Format("Specified remote storage service is not supported: \"{0}\"", serviceUri.Scheme + "://" + serviceUri.Host));
                }
            }
            else
            {
                if (!Directory.Exists(serviceUrl))
                {
                    throw new UsageException();
                }

                if (!serviceUrl.EndsWith(@"\"))
                {
                    serviceUrl = serviceUrl + @"\";
                }

                string name = Path.GetFileName(serviceUrl);
                Debug.Assert(String.IsNullOrEmpty(name));
                path = serviceUrl.Substring(0, serviceUrl.Length - name.Length);
                string fullPath = Path.GetDirectoryName(Path.IsPathRooted(serviceUrl) ? serviceUrl : Path.Combine(Environment.CurrentDirectory, serviceUrl));
                serviceUri = new Uri(fullPath);
                fileManager = new LocalArchiveFileManager(context, fullPath);
            }

            ArrayRemoveAt(ref args, 0, 1);

            using (fileManager)
            {
                using (ConcurrentMessageLog messagesLog = new ConcurrentMessageLog(Interactive(), true/*enableSequencing*/))
                {
                    using (ConcurrentTasks concurrent = new ConcurrentTasks(context.explicitConcurrency.HasValue ? context.explicitConcurrency.Value : Constants.ConcurrencyForNetworkBound, 0, messagesLog, fileManager.GetMasterTrace()))
                    {
                        int fatal = 0;

                        while ((args.Length > 0) && (Interlocked.CompareExchange(ref fatal, 1, 1) == 0))
                        {
                            int used;

                            switch (args[0])
                            {
                                default:
                                    throw new ArgumentException();

                                case "quota":
                                    {
                                        long quotaTotal, quotaUsed;
                                        fileManager.GetQuota(out quotaTotal, out quotaUsed, fileManager.GetMasterTrace());
                                        long quotaAvailable = quotaTotal - quotaUsed;
                                        Console.WriteLine("Quota: total={0}, used={1}, available={2}", FileSizeString(quotaTotal), FileSizeString(quotaUsed), FileSizeString(quotaAvailable));
                                    }
                                    used = 1;
                                    break;

                                case "list":
                                    {
                                        Console.WriteLine("list {0}{1}/*", String.Concat(serviceUri.Scheme, "://", serviceUri.Host), path);
                                        string[] names = fileManager.GetFileNames(null, fileManager.GetMasterTrace());
                                        Array.Sort(names, delegate(string l, string r) { return String.Compare(l, r, StringComparison.OrdinalIgnoreCase); });
                                        foreach (string file in names)
                                        {
                                            string id;
                                            bool directory;
                                            DateTime created, modified;
                                            long size;

                                            fileManager.GetFileInfo(file, out id, out directory, out created, out modified, out size, fileManager.GetMasterTrace());

                                            Console.WriteLine("{0:yyyy-MM-dd HH:mm}  {1:yyyy-MM-dd HH:mm} {2} {3,44} {4}", created, modified, directory ? String.Format("{0,-15}", "<DIR>") : String.Format("{0,15}", size), id, file);
                                        }
                                    }
                                    used = 1;
                                    break;

                                case "rename":
                                    if (args.Length < 3)
                                    {
                                        throw new ArgumentException();
                                    }
                                    {
                                        string name = args[1];
                                        string newName = args[2];
                                        Console.WriteLine("rename {0} to {1}", name, newName);
                                        fileManager.Rename(name, newName, fileManager.GetMasterTrace());
                                    }
                                    used = 3;
                                    break;

                                case "rename-id":
                                    if (args.Length < 3)
                                    {
                                        throw new ArgumentException();
                                    }
                                    {
                                        string id = args[1];
                                        string newName = args[2];
                                        Console.WriteLine("rename id {0} to {1}", id, newName);
                                        fileManager.RenameById(id, newName, fileManager.GetMasterTrace());
                                    }
                                    used = 3;
                                    break;

                                case "delete":
                                case "del":
                                    if (args.Length < 2)
                                    {
                                        throw new ArgumentException();
                                    }
                                    if (!FileNamePatternMatch.ContainsWildcards(args[1]))
                                    {
                                        string name = args[1];
                                        if (fileManager.Exists(name, fileManager.GetMasterTrace()))
                                        {
                                            Console.WriteLine("delete {0}", name);
                                            fileManager.Delete(name, fileManager.GetMasterTrace());
                                        }
                                    }
                                    else
                                    {
                                        string pattern = args[1];
                                        FileNamePatternMatch matcher = new FileNamePatternMatch(pattern);
                                        List<string> names = new List<string>();
                                        foreach (string name in fileManager.GetFileNames(null, fileManager.GetMasterTrace()))
                                        {
                                            if (matcher.IsMatch(name))
                                            {
                                                if (fileManager.Exists(name, fileManager.GetMasterTrace()))
                                                {
                                                    bool directory;
                                                    fileManager.GetFileInfo(name, out directory, fileManager.GetMasterTrace());
                                                    if (!directory)
                                                    {
                                                        names.Add(name);
                                                    }
                                                }
                                            }
                                        }
                                        foreach (string nameEnum in names)
                                        {
                                            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                            {
                                                break;
                                            }

                                            // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                            // variable) in order to capture each value in the anonymous method.
                                            // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                            string name = nameEnum;

                                            concurrent.Do(
                                                String.Empty,
                                                delegate(ConcurrentTasks.ITaskContext taskContext)
                                                {
                                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                                    {
                                                        try
                                                        {
                                                            messages.WriteLine("delete {0}", name);
                                                            fileManager.Delete(name, fileManager.GetMasterTrace());
                                                        }
                                                        catch (Exception exception)
                                                        {
                                                            Interlocked.Exchange(ref fatal, 1);
                                                            messages.WriteLine("Exception: {0}", exception);
                                                        }
                                                    }
                                                });

                                            messagesLog.Flush();
                                        }
                                    }
                                    used = 2;
                                    break;

                                case "delete-id":
                                case "del-id":
                                    if (args.Length < 2)
                                    {
                                        throw new ArgumentException();
                                    }
                                    {
                                        string id = args[1];
                                        Console.WriteLine("delete id {0}", id);
                                        fileManager.DeleteById(id, fileManager.GetMasterTrace());
                                    }
                                    used = 2;
                                    break;

                                case "rename-stem":
                                    if (args.Length < 2)
                                    {
                                        throw new ArgumentException();
                                    }
                                    {
                                        string oldStem = args[1];
                                        string newStem = args[2];
                                        Console.WriteLine("rename {0}* to {1}*", oldStem, newStem);
                                        string[] oldNames = fileManager.GetFileNames(oldStem/*prefix*/, fileManager.GetMasterTrace());
                                        string[] newNames = new string[oldNames.Length];
                                        for (int i = 0; i < newNames.Length; i++)
                                        {
                                            Debug.Assert(oldNames[i].StartsWith(oldStem/*prefix*/));
                                            string suffix = oldNames[i].Substring(oldStem/*prefix*/.Length);
                                            newNames[i] = newStem + suffix;
                                            if (fileManager.Exists(newNames[i], fileManager.GetMasterTrace()))
                                            {
                                                throw new IOException(String.Format("File exists: remote:{0}", newNames[i]));
                                            }
                                        }
                                        for (int iEnum = 0; iEnum < newNames.Length; iEnum++)
                                        {
                                            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                            {
                                                break;
                                            }

                                            // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                            // variable) in order to capture each value in the anonymous method.
                                            // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                            int i = iEnum;

                                            concurrent.Do(
                                                "rename",
                                                delegate(ConcurrentTasks.ITaskContext taskContext)
                                                {
                                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                                    {
                                                        try
                                                        {
                                                            fileManager.Rename(oldNames[i], newNames[i], fileManager.GetMasterTrace());
                                                        }
                                                        catch (Exception exception)
                                                        {
                                                            Interlocked.Exchange(ref fatal, 1);
                                                            messages.WriteLine("Exception: {0}", exception);
                                                        }
                                                    }
                                                });

                                            messagesLog.Flush();
                                        }
                                    }
                                    used = 3;
                                    break;

                                case "upload":
                                    if (!FileNamePatternMatch.ContainsWildcards(args[1]))
                                    {
                                        // single file, explicit names
                                        if (args.Length < 3)
                                        {
                                            throw new ArgumentException();
                                        }
                                        string localFileToUpload = args[1];
                                        string targetName = args[2];
                                        Console.WriteLine("upload {0} to {1}", localFileToUpload, targetName);
                                        Random rnd = new Random();
                                        string nameTemp = null;
                                        ILocalFileCopy fileRef = null;
                                        while (fileRef == null)
                                        {
                                            nameTemp = rnd.Next().ToString();
                                            try
                                            {
                                                fileRef = fileManager.GetTempExisting(localFileToUpload, nameTemp, fileManager.GetMasterTrace());
                                            }
                                            catch (Exception)
                                            {
                                            }
                                        }
                                        using (fileRef)
                                        {
                                            fileManager.Commit(fileRef, nameTemp, targetName, true/*overwrite*/, null/*progressTracker*/, fileManager.GetMasterTrace());
                                        }
                                        used = 3;
                                    }
                                    else
                                    {
                                        // multiple files
                                        if (args.Length < 2)
                                        {
                                            throw new ArgumentException();
                                        }
                                        string pattern = args[1];
                                        string directory = Path.GetDirectoryName(pattern);
                                        if (String.IsNullOrEmpty(directory))
                                        {
                                            directory = ".";
                                        }
                                        if (!Directory.Exists(directory))
                                        {
                                            throw new UsageException();
                                        }
                                        FileNamePatternMatch matcher = new FileNamePatternMatch(pattern);
                                        List<string> names = new List<string>();
                                        foreach (string sourcePath in Directory.GetFiles(directory))
                                        {
                                            string sourceName = Path.GetFileName(sourcePath);
                                            if (matcher.IsMatch(sourceName))
                                            {
                                                names.Add(sourceName);
                                            }
                                            if (fileManager.Exists(sourceName, fileManager.GetMasterTrace()))
                                            {
                                                throw new IOException(String.Format("File exists: remote:{0}", sourceName));
                                            }
                                        }
                                        foreach (string nameEnum in names)
                                        {
                                            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                            {
                                                break;
                                            }

                                            // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                            // variable) in order to capture each value in the anonymous method.
                                            // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                            string name = nameEnum;

                                            concurrent.Do(
                                                "upload",
                                                delegate(ConcurrentTasks.ITaskContext taskContext)
                                                {
                                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                                    {
                                                        try
                                                        {
                                                            messages.WriteLine("upload {0}", name);
                                                            Random rnd = new Random();
                                                            string nameTemp = null;
                                                            ILocalFileCopy fileRef = null;
                                                            while (fileRef == null)
                                                            {
                                                                nameTemp = rnd.Next().ToString();
                                                                try
                                                                {
                                                                    fileRef = fileManager.GetTempExisting(Path.Combine(directory, name), nameTemp, fileManager.GetMasterTrace());
                                                                }
                                                                catch (Exception)
                                                                {
                                                                }
                                                            }
                                                            using (fileRef)
                                                            {
                                                                fileManager.Commit(fileRef, nameTemp, name, true/*overwrite*/, null/*progressTracker*/, fileManager.GetMasterTrace());
                                                            }
                                                        }
                                                        catch (Exception exception)
                                                        {
                                                            Interlocked.Exchange(ref fatal, 1);
                                                            messages.WriteLine("Exception: {0}", exception);
                                                        }
                                                    }
                                                });

                                            messagesLog.Flush();
                                        }
                                        used = 2;
                                    }
                                    break;

                                case "download":
                                    if (args.Length < 3)
                                    {
                                        throw new ArgumentException();
                                    }
                                    if (!FileNamePatternMatch.ContainsWildcards(args[1]))
                                    {
                                        // single file, explicit names
                                        string sourceName = args[1];
                                        string localFileToSaveInto = args[2];
                                        if (File.Exists(localFileToSaveInto))
                                        {
                                            throw new IOException(String.Format("File exists: {0}", localFileToSaveInto));
                                        }
                                        Console.WriteLine("download {0} to {1}", sourceName, localFileToSaveInto);
                                        using (ILocalFileCopy fileRef = fileManager.Read(sourceName, null/*progressTracker*/, fileManager.GetMasterTrace()))
                                        {
                                            fileRef.CopyLocal(localFileToSaveInto, true/*overwrite*/);
                                        }
                                        File.SetCreationTime(localFileToSaveInto, context.now);
                                        File.SetLastWriteTime(localFileToSaveInto, context.now);
                                    }
                                    else
                                    {
                                        // multiple files
                                        if (args.Length < 3)
                                        {
                                            throw new ArgumentException();
                                        }
                                        string pattern = args[1];
                                        string directory = args[2];
                                        if (!Directory.Exists(directory))
                                        {
                                            throw new UsageException();
                                        }
                                        FileNamePatternMatch matcher = new FileNamePatternMatch(pattern);
                                        List<string> names = new List<string>();
                                        foreach (string sourceName in fileManager.GetFileNames(null, fileManager.GetMasterTrace()))
                                        {
                                            if (matcher.IsMatch(sourceName))
                                            {
                                                names.Add(sourceName);
                                            }
                                            string localPath = Path.Combine(directory, sourceName);
                                            if (File.Exists(localPath) || Directory.Exists(localPath))
                                            {
                                                throw new IOException(String.Format("File or directory exists: {0}", localPath));
                                            }
                                        }
                                        foreach (string nameEnum in names)
                                        {
                                            if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                                            {
                                                break;
                                            }

                                            // due to C# 2.0 bug - must declare as local variable (NOT foreach enumeration
                                            // variable) in order to capture each value in the anonymous method.
                                            // See: http://www.c-sharpcorner.com/UploadFile/vendettamit/foreach-behavior-with-anonymous-methods-and-captured-value/
                                            string name = nameEnum;

                                            concurrent.Do(
                                                "download",
                                                delegate(ConcurrentTasks.ITaskContext taskContext)
                                                {
                                                    using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog())
                                                    {
                                                        try
                                                        {
                                                            messages.WriteLine("download {0}", name);
                                                            string localFileToSaveInto = Path.Combine(directory, name);
                                                            using (ILocalFileCopy fileRef = fileManager.Read(name, null/*progressTracker*/, fileManager.GetMasterTrace()))
                                                            {
                                                                fileRef.CopyLocal(localFileToSaveInto, true/*overwrite*/);
                                                            }
                                                            File.SetCreationTime(localFileToSaveInto, context.now);
                                                            File.SetLastWriteTime(localFileToSaveInto, context.now);
                                                        }
                                                        catch (Exception exception)
                                                        {
                                                            Interlocked.Exchange(ref fatal, 1);
                                                            messages.WriteLine("Exception: {0}", exception);
                                                        }
                                                    }
                                                });

                                            messagesLog.Flush();
                                        }
                                    }
                                    used = 3;
                                    break;

                                // specialized command for undoing a failed/incomplete partial dynpack update
                                case "dynpack-rollback":
                                    if (args.Length < 3)
                                    {
                                        throw new ArgumentException();
                                    }
                                    used = 2;
                                    {
                                        string targetArchiveFileNameTemplate = args[1];

                                        string manifestFileName = String.Concat(targetArchiveFileNameTemplate, ".", DynPackManifestName, DynPackFileExtension);
                                        string manifestFileNameOld = String.Concat(targetArchiveFileNameTemplate, ".", DynPackManifestNameOld, DynPackFileExtension);
                                        if (!fileManager.Exists(manifestFileNameOld, fileManager.GetMasterTrace()))
                                        {
                                            Console.WriteLine("Old manifest does not exist ({0}), rollback not possible.", manifestFileNameOld);
                                            break;
                                        }
                                        if (fileManager.Exists(manifestFileName, fileManager.GetMasterTrace()))
                                        {
                                            Console.Write("A newer manifest also exists ({0}). Are you sure you want to roll back? [y/n] ", manifestFileName);
                                            bool accepted;
                                            while (true)
                                            {
                                                char key = WaitReadKey(false/*intercept*/);
                                                if (key == 'n')
                                                {
                                                    accepted = false;
                                                    break;
                                                }
                                                else if (key == 'y')
                                                {
                                                    accepted = true;
                                                    break;
                                                }
                                            }
                                            Console.WriteLine();
                                            if (!accepted)
                                            {
                                                break;
                                            }
                                        }

                                        string targetArchiveFileNameTemplateDot = targetArchiveFileNameTemplate + ".";
                                        foreach (string file in fileManager.GetFileNames(targetArchiveFileNameTemplateDot, fileManager.GetMasterTrace()))
                                        {
                                            Debug.Assert(file.StartsWith(targetArchiveFileNameTemplateDot, StringComparison.OrdinalIgnoreCase));
                                            string suffix = file.Substring(targetArchiveFileNameTemplateDot.Length);
                                            if (suffix.StartsWith("-"))
                                            {
                                                string targetSuffix = suffix.Substring(1);

                                                string targetFile = targetArchiveFileNameTemplateDot + targetSuffix;
                                                if (fileManager.Exists(targetFile, fileManager.GetMasterTrace()))
                                                {
                                                    Console.WriteLine("deleting {0}", targetFile);
                                                    fileManager.Delete(targetFile, fileManager.GetMasterTrace());
                                                }
                                                Console.WriteLine("renaming {0} to {1}", file, targetFile);
                                                fileManager.Rename(file, targetFile, fileManager.GetMasterTrace());
                                            }
                                        }
                                    }
                                    break;
                            }

                            concurrent.Drain();
                            messagesLog.Flush();

                            ArrayRemoveAt(ref args, 0, used);
                        }

                        if (Interlocked.CompareExchange(ref fatal, 1, 1) != 0)
                        {
                            throw new ExitCodeException((int)ExitCodes.ProgramFailure);
                        }
                    }
                }
            }
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Dir
        //
        ////////////////////////////////////////////////////////////////////////////

        private static void DirRecursive(string path, string[] parts, int index)
        {
            if ((index == 0) && (parts[index].EndsWith(":")))
            {
                DirRecursive(String.Concat(parts[0], "\\"), parts, index + 1);
            }
            else if (index == parts.Length - 1)
            {
                path = Path.Combine(path, parts[index]);
                if (Directory.Exists(path) || File.Exists(path))
                {
                    StringBuilder output = new StringBuilder();
                    using (StringWriter writer = new StringWriter(output))
                    {
                        using (Process process = new Process())
                        {
                            process.StartInfo.FileName = "cmd.exe";
                            process.StartInfo.Arguments = String.Format("/C dir \"{0}\"", path);
                            process.StartInfo.CreateNoWindow = true;
                            process.StartInfo.RedirectStandardOutput = true;
                            process.StartInfo.RedirectStandardError = true;
                            process.StartInfo.UseShellExecute = false;
                            process.StartInfo.WorkingDirectory = Path.GetTempPath();
                            process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) { writer.WriteLine(e.Data); } };
                            process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) { writer.WriteLine(e.Data); } };
                            process.Start();
                            process.BeginOutputReadLine();
                            process.WaitForExit();
                        }
                    }
                    Console.Write(output.ToString());
                }
            }
            else if (0 <= parts[index].IndexOf('*'))
            {
                string[] subdirs = Directory.GetDirectories(path, parts[index]);
                foreach (string subdir in subdirs)
                {
                    DirRecursive(Path.Combine(path, subdir), parts, index + 1);
                }
            }
            else
            {
                path = Path.Combine(path, parts[index]);
                DirRecursive(path, parts, index + 1);
            }
        }

        internal static void Dir(string path)
        {
            string[] parts = path.Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            DirRecursive(String.Empty, parts, 0);
        }


        ////////////////////////////////////////////////////////////////////////////
        //
        // Main
        //
        ////////////////////////////////////////////////////////////////////////////

        public class UsageException : ApplicationException
        {
            private string message;

            public UsageException()
                : base()
            {
            }

            public UsageException(string message)
                : base(message)
            {
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

        private static string ListCryptoSystems()
        {
            StringBuilder sb = new StringBuilder();
            bool first = true;
            foreach (ICryptoSystem cryptoSystem in CryptoSystems)
            {
                if (!first)
                {
                    sb.Append(", ");
                }
                first = false;
                sb.Append(cryptoSystem.Name);
            };
            return sb.ToString();
        }

        internal static void UsageThrow()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  backup [<options>] copy <source-path> [<destination-path>]");
            Console.WriteLine("  backup [<options>] compare <source-path> <destination-path>");
            Console.WriteLine("  backup [<options>] backup <source-path> <archive-folder-path> [<backup-options>] [<exclusion-options>]");
            Console.WriteLine("  backup [<options>] verify <source-path> <archive-folder-path>");
            Console.WriteLine("  backup [<options>] purge <archive-folder-path> <start-checkpoint> <end-checkpoint>");
            Console.WriteLine("  backup [<options>] prune <archive-folder-path>");
            Console.WriteLine("  backup [<options>] restore <archive-folder-path> <checkpoint-path> <destination-path>");
            Console.WriteLine("  backup [<options>] pack <source-path> <destination-file> [<exclusion-options>]");
            Console.WriteLine("  backup [<options>] unpack <source-file> <destination-path>");
            Console.WriteLine("  backup [<options>] split <source-file> <destination-file-prefix> <segment-size-in-bytes>");
            Console.WriteLine("  backup [<options>] unsplit <source-file-prefix> <destination-file>");
            Console.WriteLine("  backup [<options>] dynpack <source-path> <destination-file-prefix> <segment-size-in-bytes> [<dynpack-options>] [<exclusion-options>]");
            Console.WriteLine("  backup [<options>] dynunpack <source-file-prefix> <destination-path>");
            Console.WriteLine("  backup [<options>] sync <local-path> <remote-path> [<sync-options>] [<sync-exclusion-options>]");
            Console.WriteLine("");
            Console.WriteLine("Options (<options>):");
            Console.WriteLine("  -decompress | -compress");
            Console.WriteLine("  -decrypt <algo> <source-key> | -encrypt <algo> <destination-key> | -recrypt <algo1> <algo2> <source-key> <destination-key>");
            Console.WriteLine("     <algo> one of {{{0}}}", ListCryptoSystems());
            Console.WriteLine("  -dirsonly");
            Console.WriteLine("  -ignoreaccessdenied");
            Console.WriteLine("  -zerolen");
            Console.WriteLine("  -beep");
            Console.WriteLine("  -priority {lowest | belownormal | normal | abovenormal | highest }");
            Console.WriteLine("  -waitdebugger");
            Console.WriteLine("  -break");
            Console.WriteLine("  -date <datetime>");
            Console.WriteLine("  -logpath <log-file-path>");
            Console.WriteLine("");
            Console.WriteLine("Cryptography configurations:");
            int maxWidth = 0;
            foreach (ICryptoSystem cryptoSystem in CryptoSystems)
            {
                maxWidth = Math.Max(maxWidth, cryptoSystem.Name.Length);
            }
            foreach (ICryptoSystem cryptoSystem in CryptoSystems)
            {
                Console.WriteLine("  {0,-" + maxWidth.ToString() + "} {1}", cryptoSystem.Name, cryptoSystem.Description);
            }
            Console.WriteLine("");
            Console.WriteLine("Backup options (<backup-options>):");
            Console.WriteLine("  -nofinish");
            Console.WriteLine("");
            Console.WriteLine("Exclusion options (<exclusion-options>):");
            Console.WriteLine("  -skip .<file-extension>");
            Console.WriteLine("  -exclude <path>");
            Console.WriteLine("");
            Console.WriteLine("Sync exclusion options (<sync-exclusion-options>):");
            Console.WriteLine("  -exclude <relative-path>");
            Console.WriteLine("");
            Console.WriteLine("Options -decompress, -decrypt, -recrypt, or -dirsonly can't be used with 'backup' or 'verify'");
            Console.WriteLine("Option -dirsonly can't be used with 'compare' or 'restore'");
            Console.WriteLine("No options can be used with 'purge'");
            Console.WriteLine("");

            throw new UsageException(String.Empty);
        }

        private static string EnsureRootedLocalPath(string path)
        {
            return Path.IsPathRooted(path) ? path : Path.Combine(Environment.CurrentDirectory, path);
        }

        private static string EnsureRootedRemotablePath(string path)
        {
            try
            {
                Uri uri = new Uri(path);
                if (uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
                    || uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                {
                    return path;
                }
            }
            catch (UriFormatException)
            {
            }
            return Path.IsPathRooted(path) ? path : Path.Combine(Environment.CurrentDirectory, path);
        }

        private static void Main(string[] args)
        {
            int exitCode = (int)ExitCodes.Success;
            Context context = new Context();
            context.faultInjectionTemplateRoot = new FaultTemplateNode();



            // implementation validations
            {
                CRC32.Test();
                Dictionary<string, bool> uniquePersistedID = new Dictionary<string, bool>();
                foreach (ICryptoSystem cryptoSystem in CryptoSystems)
                {
                    cryptoSystem.Test();
                    uniquePersistedID.Add(cryptoSystem.UniquePersistentCiphersuiteIdentifier, false);
                }
            }


            try
            {
                bool debug = false;
                bool waitDebugger = false;

                context.now = DateTime.Now;

                if (args.Length == 0)
                {
                    UsageThrow();
                }

                int i = 0;
                while (i < args.Length)
                {
                    if (args[i] == "-break")
                    {
                        debug = true;
                    }
                    else if (args[i] == "-waitdebugger")
                    {
                        waitDebugger = true;
                    }
                    else if (args[i] == "-trace")
                    {
                        context.traceEnabled = true;
                    }
                    else if (args[i] == "-dirsonly")
                    {
                        context.dirsOnly = true;
                    }
                    else if (args[i] == "-ignoreaccessdenied")
                    {
                        context.continueOnAccessDenied = true;
                    }
                    else if (args[i] == "-date")
                    {
                        i++;
                        if (!(i < args.Length))
                        {
                            throw new UsageException();
                        }
                        context.now = DateTime.Parse(args[i]);
                    }
                    else if (args[i] == "-logpath")
                    {
                        i++;
                        if (!(i < args.Length))
                        {
                            throw new UsageException();
                        }
                        context.logPath = EnsureRootedLocalPath(args[i]);
                    }
                    else if (args[i] == "-compress")
                    {
                        if (context.compressionOption != CompressionOption.None)
                        {
                            throw new UsageException();
                        }
                        context.compressionOption = CompressionOption.Compress;
                    }
                    else if (args[i] == "-decompress")
                    {
                        if (context.compressionOption != CompressionOption.None)
                        {
                            throw new UsageException();
                        }
                        context.compressionOption = CompressionOption.Decompress;
                    }
                    else if (args[i] == "-recompress")
                    {
                        if (context.compressionOption != CompressionOption.None)
                        {
                            throw new UsageException();
                        }
                        context.compressionOption = CompressionOption.Recompress;
                    }
                    else if (args[i] == "-encrypt")
                    {
                        if (context.cryptoOption != EncryptionOption.None)
                        {
                            throw new UsageException();
                        }
                        i++;

                        context.cryptoOption = EncryptionOption.Encrypt;
                        context.encrypt = new CryptoContext();

                        GetPasswordArgument(args, ref i, "Password:", out context.encrypt.algorithm, out context.encrypt.password);
                    }
                    else if (args[i] == "-decrypt")
                    {
                        if (context.cryptoOption != EncryptionOption.None)
                        {
                            throw new UsageException();
                        }
                        i++;

                        context.cryptoOption = EncryptionOption.Decrypt;
                        context.decrypt = new CryptoContext();

                        GetPasswordArgument(args, ref i, "Password:", out context.decrypt.algorithm, out context.decrypt.password);
                    }
                    else if (args[i] == "-recrypt")
                    {
                        if (context.cryptoOption != EncryptionOption.None)
                        {
                            throw new UsageException();
                        }
                        i++;

                        context.cryptoOption = EncryptionOption.Recrypt;
                        context.encrypt = new CryptoContext();
                        context.decrypt = new CryptoContext();

                        GetPasswordArgument(args, ref i, "Password 1:", out context.decrypt.algorithm, out context.decrypt.password);
                        i++;

                        GetPasswordArgument(args, ref i, "Password 2:", out context.encrypt.algorithm, out context.encrypt.password);
                    }
                    else if (args[i] == "-zerolen")
                    {
                        context.zeroLengthSpecial = true;
                    }
                    else if (args[i] == "-beep")
                    {
                        context.beepEnabled = true;
                    }
                    else if (args[i] == "-nomacprevalidate")
                    {
                        context.doNotPreValidateMAC = true;
                    }
                    else if (args[i] == "-forcenewkeys")
                    {
                        if (context.encrypt == null)
                        {
                            throw new UsageException();
                        }
                        context.encrypt.forceNewKeys = true;
                    }
                    else if (args[i] == "-priority")
                    {
                        i++;
                        if (i < args.Length)
                        {
                            switch (args[i].ToLowerInvariant())
                            {
                                default:
                                    throw new UsageException();
                                case "-":
                                case "belownormal":
                                    Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
                                    break;
                                case "--":
                                case "lowest":
                                    Thread.CurrentThread.Priority = ThreadPriority.Lowest;
                                    break;
                                case "+":
                                case "abovenormal":
                                    Thread.CurrentThread.Priority = ThreadPriority.AboveNormal;
                                    break;
                                case "++":
                                case "highest":
                                    Thread.CurrentThread.Priority = ThreadPriority.Highest;
                                    break;
                                case "0":
                                case "n":
                                case "normal":
                                    Thread.CurrentThread.Priority = ThreadPriority.Normal;
                                    break;
                            }
                        }
                        else
                        {
                            throw new UsageException();
                        }
                    }
                    else if (args[i] == "-refreshtoken")
                    {
                        i++;
                        if (i < args.Length)
                        {
                            context.refreshTokenProtected = args[i];
                        }
                        else
                        {
                            throw new UsageException();
                        }
                    }
                    else if (args[i] == "-concurrency")
                    {
                        i++;
                        if (i < args.Length)
                        {
                            if (args[i].Equals("default"))
                            {
                                context.explicitConcurrency = null;
                            }
                            else
                            {
                                context.explicitConcurrency = Int32.Parse(args[i]);
                                if (context.explicitConcurrency.Value == 1)
                                {
                                    context.explicitConcurrency = 0; // see ConcurrentTasks constructor for why
                                }
                                if ((context.explicitConcurrency.Value < 0) || (context.explicitConcurrency.Value > 64))
                                {
                                    throw new UsageException();
                                }
                            }
                        }
                        else
                        {
                            throw new UsageException();
                        }
                    }
                    else if (args[i] == "-overridesecurityblock")
                    {
                        context.overrideRemoteSecurityBlock = true;
                    }
                    else if (args[i] == "-injectfault")
                    {
                        i++;
                        if (!(i < args.Length))
                        {
                            throw new UsageException();
                        }
                        string method = args[i];
                        i++;
                        if (!(i < args.Length))
                        {
                            throw new UsageException();
                        }
                        ParseFaultInjectionPath(context.faultInjectionTemplateRoot, method, args[i]);
                    }
                    else if (args[i] == "-throttle")
                    {
                        i++;
                        if (!(i < args.Length))
                        {
                            throw new UsageException();
                        }
                        int approximateBytesPerSecond = Int32.Parse(args[i]);
                        WebMethodsBase.SetThrottle(approximateBytesPerSecond);
                    }
                    else if (args[i] == "-maxretries")
                    {
                        i++;
                        if (!(i < args.Length))
                        {
                            throw new UsageException();
                        }
                        int maxRetries = Int32.Parse(args[i]);
                        RetryHelper.SetMaxRetries(maxRetries);
                    }
                    else
                    {
                        break;
                    }
                    i++;
                }

                context.faultInjectionRoot = new FaultInstanceNode(context.faultInjectionTemplateRoot).Select(null);

                if (waitDebugger)
                {
                    Console.Write("Attach debugger... ");
                    while (!Debugger.IsAttached)
                    {
                        Thread.Sleep(250);
                    }
                    Console.WriteLine("found");
                }
                if (debug)
                {
                    Debugger.Break();
                }

                switch (args[i++])
                {
                    default:
                        throw new UsageException();

                    case "copy":
                        if (i + 1 > args.Length)
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            string[] argsExtra = new string[args.Length - (i + 2)];
                            Array.Copy(args, i + 2, argsExtra, 0, argsExtra.Length);
                            Copy(
                                EnsureRootedLocalPath(args[i]),
                                i + 1 < args.Length
                                    ? EnsureRootedLocalPath(args[i + 1])
                                    : Environment.CurrentDirectory,
                                context,
                                argsExtra);
                        }
                        break;

                    case "compare":
                        if ((i + 2 > args.Length) || context.dirsOnly)
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Compare(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context);
                        }
                        break;

                    case "backup":
                        if ((i + 2 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Compress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Encrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            string[] argsExtra = new string[args.Length - (i + 2)];
                            Array.Copy(args, i + 2, argsExtra, 0, argsExtra.Length);
                            if (context.cryptoOption != EncryptionOption.None)
                            {
                                ConsoleWriteLineColor(ConsoleColor.Yellow, "WARNING: Use of encryption in \"backup\" archiving mode is not recommended. Filenames and directory structure can provide substantial information to an adversary, even if the file contents can't be read.");
                            }
                            Backup(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context,
                                argsExtra);
                        }
                        break;

                    case "verify":
                        if ((i + 2 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Compress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Encrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Verify(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context);
                        }
                        break;

                    case "purge":
                        if ((i + 3 > args.Length) ||
                            context.dirsOnly ||
                            (context.compressionOption != CompressionOption.None) ||
                            (context.cryptoOption != EncryptionOption.None) ||
                            Path.IsPathRooted(args[i + 1]) ||
                            (args[i + 1] != Path.GetFileName(args[i + 1])) ||
                            Path.IsPathRooted(args[i + 2]) ||
                            (args[i + 2] != Path.GetFileName(args[i + 2])))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Purge(
                                EnsureRootedLocalPath(args[i]),
                                args[i + 1],
                                args[i + 2],
                                context);
                        }
                        break;

                    case "prune":
                        if ((i + 1 > args.Length) ||
                            context.dirsOnly ||
                            (context.compressionOption != CompressionOption.None) ||
                            (context.cryptoOption != EncryptionOption.None))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Prune(
                                EnsureRootedLocalPath(args[i]),
                                context);
                        }
                        break;

                    case "restore":
                        if ((i + 3 > args.Length) ||
                            context.dirsOnly ||
                            Path.IsPathRooted(args[i + 1]))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Restore(
                                EnsureRootedLocalPath(args[i]),
                                args[i + 1],
                                EnsureRootedLocalPath(args[i + 2]),
                                context);
                        }
                        break;

                    case "pack":
                        if ((i + 2 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Compress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Encrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            string[] argsExtra = new string[args.Length - (i + 2)];
                            Array.Copy(args, i + 2, argsExtra, 0, argsExtra.Length);
                            Pack(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context,
                                argsExtra);
                        }
                        break;

                    case "unpack":
                        if ((i + 2 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Decompress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Decrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Unpack(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context);
                        }
                        break;

                    case "dumppack":
                        if ((i + 1 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Decompress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Decrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Dumppack(
                                EnsureRootedRemotablePath(args[i]),
                                context);
                        }
                        break;

                    case "validate":
                        if ((i + 1 > args.Length) ||
                            context.dirsOnly ||
                            (context.compressionOption != CompressionOption.None) ||
                            (context.cryptoOption != EncryptionOption.Decrypt))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            ValidateEncryption(
                                EnsureRootedLocalPath(args[i]),
                                context);
                        }
                        break;

                    case "valdynpack":
                        if ((i + 1 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Decompress)) ||
                            (context.cryptoOption != EncryptionOption.Decrypt))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            ValidateDynamicPack(
                                EnsureRootedRemotablePath(args[i]),
                                context);
                        }
                        break;

                    case "split":
                        {
                            int size;
                            if ((i + 3 > args.Length) ||
                                context.dirsOnly ||
                                (context.compressionOption != CompressionOption.None) ||
                                (context.cryptoOption != EncryptionOption.None) ||
                                !Int32.TryParse(args[i + 2], out size))
                            {
                                throw new UsageException();
                            }
                            else
                            {
                                Split(
                                    EnsureRootedLocalPath(args[i]),
                                    EnsureRootedLocalPath(args[i + 1]),
                                    size,
                                    context);
                            }
                        }
                        break;

                    case "unsplit":
                        if ((i + 2 > args.Length) ||
                            context.dirsOnly ||
                            (context.compressionOption != CompressionOption.None) ||
                            (context.cryptoOption != EncryptionOption.None))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Unsplit(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context);
                        }
                        break;

                    case "sync":
                        if ((i + 2 > args.Length) || context.dirsOnly)
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            string[] argsExtra = new string[args.Length - (i + 2)];
                            Array.Copy(args, i + 2, argsExtra, 0, argsExtra.Length);
                            Sync(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context,
                                argsExtra);
                        }
                        break;

                    case "dynpack":
                        if ((i + 3 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Compress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Encrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            string[] argsExtra = new string[args.Length - (i + 3)];
                            Array.Copy(args, i + 3, argsExtra, 0, argsExtra.Length);
                            DynamicPack(
                                EnsureRootedLocalPath(args[i]),
                                EnsureRootedRemotablePath(args[i + 1]),
                                Int64.Parse(args[i + 2]),
                                context,
                                argsExtra);
                        }
                        break;

                    case "dynunpack":
                        if ((i + 2 > args.Length) ||
                            context.dirsOnly ||
                            ((context.compressionOption != CompressionOption.None) &&
                            (context.compressionOption != CompressionOption.Decompress)) ||
                            ((context.cryptoOption != EncryptionOption.None) &&
                            (context.cryptoOption != EncryptionOption.Decrypt)))
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            string[] argsExtra = new string[args.Length - (i + 2)];
                            Array.Copy(args, i + 2, argsExtra, 0, argsExtra.Length);
                            DynamicUnpack(
                                EnsureRootedRemotablePath(args[i]),
                                EnsureRootedLocalPath(args[i + 1]),
                                context,
                                argsExtra);
                        }
                        break;

                    case "dir":
                        if (i + 1 > args.Length)
                        {
                            throw new UsageException();
                        }
                        else
                        {
                            Dir(EnsureRootedLocalPath(args[i]));
                        }
                        break;

                    case "remote":
                        {
                            string[] argsExtra = new string[args.Length - i];
                            Array.Copy(args, i, argsExtra, 0, argsExtra.Length);
                            RemoteCommand(
                                argsExtra,
                                context);
                        }
                        break;
                }
            }
            catch (UsageException exception)
            {
                if (exception.Message == null)
                {
                    Console.WriteLine("Invalid program arguments");
                }
                else if (!String.IsNullOrEmpty(exception.Message))
                {
                    Console.WriteLine(exception.Message);
                }
                exitCode = (int)ExitCodes.Usage;
            }
            catch (ExitCodeException exception)
            {
                if (!String.IsNullOrEmpty(exception.Message))
                {
                    ConsoleWriteLineColor(ConsoleColor.Red, exception.Message);
                }
                exitCode = exception.ExitCode;
            }
            catch (Exception exception)
            {
                if (context.beepEnabled)
                {
                    Console.Beep(440, 500);
                }
                ConsoleWriteLineColor(ConsoleColor.Red, "");
                ConsoleWriteLineColor(ConsoleColor.Red, "Error:");
                ConsoleWriteLineColor(ConsoleColor.Red, exception.Message);
                foreach (KeyValuePair<object, object> items in exception.Data)
                {
                    ConsoleWriteLineColor(ConsoleColor.Red, "{0}: {1}", items.Key != null ? items.Key.ToString() : "(null)", items.Value != null ? items.Value.ToString() : "(null)");
                }
                ConsoleWriteLineColor(ConsoleColor.Red, exception.StackTrace);

                exitCode = (int)ExitCodes.ProgramFailure;
            }

            Environment.ExitCode = exitCode;
        }
    }
}
