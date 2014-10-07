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
using System.Security.Cryptography;
using System.Threading;
using System.Text;
using System.Text.RegularExpressions;

namespace Backup
{
    ////////////////////////////////////////////////////////////////////////////
    //
    // Logging utilities
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
                hashText = String.Format("length={0} sha1={1}", value.Length, HexUtility.HexEncode(sha1.ComputeHash(value)));
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


        public static int StreamLoggingLengthLimit = Int32.MaxValue;

        public static string ToString(Stream stream)
        {
            return ToString(stream, false/*omitContent*/);
        }

        public static string ToString(Stream stream, bool omitContent)
        {
            StringBuilder sb = new StringBuilder();
            if (stream == null)
            {
                sb.Append("null");
            }
            else
            {
                sb.AppendFormat("{0}(", typeof(Stream).Name);
                sb.AppendFormat("len={0}, pos={1}", stream.Length, stream.Position);
                if (!omitContent && (stream is MemoryStream))
                {
                    sb.Append(", content=");
                    sb.Append(Encoding.ASCII.GetString(((MemoryStream)stream).ToArray(), 0, Math.Min((int)stream.Length, StreamLoggingLengthLimit)).Replace("\r", " ").Replace("\n", " "));
                }
                sb.Append(")");
            }
            return sb.ToString();
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


    ////////////////////////////////////////////////////////////////////////////
    //
    // Fault injection framework
    //
    ////////////////////////////////////////////////////////////////////////////

    public interface IFaultPredicate
    {
        IFaultPredicate Clone();
        bool Test();
        bool Test(long l);
        bool Test(string s);
    }

    public interface IFaultInstance
    {
        IFaultInstance Select(string tag);
        IFaultInstance Select(string tag, long l);
        IFaultInstance Select(string tag, string s);
        IFaultPredicate SelectPredicate(string tag);
    }

    // Inject faults as points are passed during execution, in accord with the specified
    // FaultTemplateNode passed to the constructor.
    public class FaultInstanceNode : IFaultInstance
    {
        public class NullFaultPredicate : IFaultPredicate
        {
            public static readonly NullFaultPredicate Null = new NullFaultPredicate();

            public IFaultPredicate Clone()
            {
                return Null;
            }

            public bool Test()
            {
                return true;
            }

            public bool Test(long l)
            {
                return true;
            }

            public bool Test(string s)
            {
                return true;
            }

            public override string ToString()
            {
                return String.Empty;
            }
        }

        public class CountFaultPredicate : IFaultPredicate
        {
            private long count;
            private readonly long trigger;

            public CountFaultPredicate(long trigger)
            {
                this.trigger = trigger;
            }

            public CountFaultPredicate(CountFaultPredicate original)
            {
                this.count = original.count;
                this.trigger = original.trigger;
            }

            public IFaultPredicate Clone()
            {
                return new CountFaultPredicate(this);
            }

            public bool Test()
            {
                long current = Interlocked.Increment(ref count);
                return current == trigger;
            }

            public bool Test(long l)
            {
                return Test();
            }

            public bool Test(string s)
            {
                return Test();
            }

            public override string ToString()
            {
                return String.Format("[count:{0}]", trigger);
            }
        }

        public class LimitFaultPredicate : IFaultPredicate
        {
            private readonly long limit;

            public LimitFaultPredicate(long limit)
            {
                this.limit = limit;
            }

            public LimitFaultPredicate(LimitFaultPredicate original)
            {
                this.limit = original.limit;
            }

            public IFaultPredicate Clone()
            {
                return new LimitFaultPredicate(this);
            }

            public bool Test()
            {
                return false;
            }

            public bool Test(long l)
            {
                return l >= limit;
            }

            public bool Test(string s)
            {
                return false;
            }

            public override string ToString()
            {
                return String.Format("[limit:{0}]", limit);
            }
        }

        public class SumLimitFaultPredicate : IFaultPredicate
        {
            private long sum;
            private readonly long limit;

            public SumLimitFaultPredicate(long limit)
            {
                this.limit = limit;
            }

            public SumLimitFaultPredicate(SumLimitFaultPredicate original)
            {
                this.sum = original.sum;
                this.limit = original.limit;
            }

            public IFaultPredicate Clone()
            {
                return new SumLimitFaultPredicate(this);
            }

            public bool Test()
            {
                return false;
            }

            public bool Test(long l)
            {
                long current = Interlocked.Add(ref sum, l);
                return current >= limit;
            }

            public bool Test(string s)
            {
                return false;
            }

            public override string ToString()
            {
                return String.Format("[sumlimit:{0}]", limit);
            }
        }

        public class StringEqualFaultPredicate : IFaultPredicate
        {
            private readonly string equals;

            public StringEqualFaultPredicate(string match)
            {
                this.equals = match;
            }

            public StringEqualFaultPredicate(StringEqualFaultPredicate original)
            {
                this.equals = original.equals;
            }

            public IFaultPredicate Clone()
            {
                return new StringEqualFaultPredicate(this);
            }

            public bool Test()
            {
                return false;
            }

            public bool Test(long l)
            {
                return Test(l.ToString());
            }

            public bool Test(string s)
            {
                return String.Equals(s, equals);
            }

            public override string ToString()
            {
                return String.Format("[stringequal:{0}]", equals);
            }
        }

        public class StringMatchFaultPredicate : IFaultPredicate
        {
            private readonly string pattern;
            private readonly Regex match;

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

            public IFaultPredicate Clone()
            {
                return new StringMatchFaultPredicate(this);
            }

            public bool Test()
            {
                return false;
            }

            public bool Test(long l)
            {
                return Test(l.ToString());
            }

            public bool Test(string s)
            {
                return match.IsMatch(s);
            }

            public override string ToString()
            {
                return String.Format("[regex:{0}]", pattern);
            }
        }


        private readonly KeyValuePair<IFaultPredicate, FaultTemplateNode>[] predicates;

        public static readonly FaultInstanceNode Null = new FaultInstanceNode((KeyValuePair<IFaultPredicate, FaultTemplateNode>[])null);

        public FaultInstanceNode(FaultTemplateNode templateNode)
        {
            this.predicates = new KeyValuePair<IFaultPredicate, FaultTemplateNode>[1];
            this.predicates[0] = new KeyValuePair<IFaultPredicate, FaultTemplateNode>(NullFaultPredicate.Null, templateNode);
        }

        private FaultInstanceNode(KeyValuePair<IFaultPredicate, FaultTemplateNode>[] predicates)
        {
            this.predicates = predicates;
        }


        // Use Select() to descend one path step and match predicates either by count or explicit value test

        public IFaultInstance Select(string tag)
        {
            if (predicates == null)
            {
                return Null;
            }
            return Select(tag, delegate(IFaultPredicate predicate) { return predicate.Test(); });
        }

        public IFaultInstance Select(string tag, long l)
        {
            if (predicates == null)
            {
                return Null;
            }
            return Select(tag, delegate(IFaultPredicate predicate) { return predicate.Test(l); });
        }

        public IFaultInstance Select(string tag, string s)
        {
            if (predicates == null)
            {
                return Null;
            }
            return Select(tag, delegate(IFaultPredicate predicate) { return predicate.Test(s); });
        }


        // Use SelectPredicate() to descend a path without evaluating predicates. Evaluation is
        // performed by explicit invocation of Test() on the returned FaultPredicate object.
        // Use this approach for performance-sensitive code in order to hoist path string match
        // portion of operation out of loops.

        public IFaultPredicate SelectPredicate(string tag)
        {
            if (predicates == null)
            {
                return FaultInstancePredicate.Null;
            }

            KeyValuePair<IFaultPredicate, FaultTemplateNode>[] matchingPredicates = null;
            for (int i = 0; i < predicates.Length; i++)
            {
                if (String.Equals(tag, predicates[i].Value.Tag))
                {
                    if (matchingPredicates == null)
                    {
                        matchingPredicates = new KeyValuePair<IFaultPredicate, FaultTemplateNode>[1];
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

        private delegate bool TestMethod(IFaultPredicate predicate);
        private FaultInstanceNode Select(string tag, TestMethod testMethod)
        {
            // caller optimizes case where predicates == null

            KeyValuePair<IFaultPredicate, FaultTemplateNode>[] childPredicates = null;
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

                            case FaultTemplateNode.FaultMethod.None:
                                break;

                            case FaultTemplateNode.FaultMethod.Throw:
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

                            case FaultTemplateNode.FaultMethod.Kill:
                                Environment.ExitCode = (int)Core.ExitCodes.ProgramFailure;
                                Process.GetCurrentProcess().Kill(); // no finalizers!
                                break;
                        }
                    }
                    else
                    {
                        KeyValuePair<FaultTemplateNode, IFaultPredicate>[] children = predicates[i].Value.Children;
                        for (int j = 0; j < children.Length; j++)
                        {
                            if (childPredicates == null)
                            {
                                childPredicates = new KeyValuePair<IFaultPredicate, FaultTemplateNode>[1];
                            }
                            else
                            {
                                Array.Resize(ref childPredicates, childPredicates.Length + 1);
                            }
                            childPredicates[childPredicates.Length - 1] = new KeyValuePair<IFaultPredicate, FaultTemplateNode>(children[j].Value.Clone(), children[j].Key);
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
                        KeyValuePair<FaultTemplateNode, IFaultPredicate> item = Array.Find(parent.Children, delegate(KeyValuePair<FaultTemplateNode, IFaultPredicate> candidate) { return candidate.Key == walk; });
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
            throw new FaultTemplateNode.FaultInjectionException(message.ToString());
        }


        // Fast predicate evaluator for performance-sensitive code
        private class FaultInstancePredicate : IFaultPredicate
        {
            private readonly KeyValuePair<IFaultPredicate, FaultTemplateNode>[] predicates;
            private readonly FaultInstanceNode owner;

            public static readonly FaultInstancePredicate Null = new FaultInstancePredicate(null, null);

            public FaultInstancePredicate(KeyValuePair<IFaultPredicate, FaultTemplateNode>[] predicates, FaultInstanceNode owner)
            {
                this.predicates = predicates;
                this.owner = owner;
            }

            public IFaultPredicate Clone()
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

                                case FaultTemplateNode.FaultMethod.None:
                                    break;

                                case FaultTemplateNode.FaultMethod.Throw:
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

                                case FaultTemplateNode.FaultMethod.Kill:
                                    Environment.ExitCode = (int)Core.ExitCodes.ProgramFailure;
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

            public bool Test()
            {
                if (predicates == null)
                {
                    return TestReturnValue;
                }
                return Test(delegate(IFaultPredicate predicate) { return predicate.Test(); });
            }

            public bool Test(long l)
            {
                if (predicates == null)
                {
                    return TestReturnValue;
                }
                return Test(delegate(IFaultPredicate predicate) { return predicate.Test(l); });
            }

            public bool Test(string s)
            {
                if (predicates == null)
                {
                    return TestReturnValue;
                }
                return Test(delegate(IFaultPredicate predicate) { return predicate.Test(s); });
            }
        }
    }

    // Generate trace listing of all fault injection points passed during a particular
    // program run. No actual fault injection is done.
    public class FaultTraceNode : IFaultInstance
    {
        private readonly TextWriter trace;
        private readonly string prefix;
        private long count;

        private const string FaultTraceFilePrefix = "faulttrace";

        public FaultTraceNode()
        {
            trace = Logging.CreateLogFile(FaultTraceFilePrefix);
        }

        protected FaultTraceNode(TextWriter trace, string prefix)
        {
            this.trace = trace;
            this.prefix = prefix;
        }

        // Many synonyms will not be listed. For example, the second invocation of /foo
        // with a limit specifier (say, of value 100) might be listed as:
        //   /foo[limit:100]
        // but could also be triggered using the count specifier:
        //   /foo[count:2]
        // which would not be explicitly listed. (Otherwise the fan-out of possible synonymous
        // paths would result in exponential growth of log file.)

        public IFaultInstance Select(string tag)
        {
            count++;
            string newPrefix = prefix + String.Format("/{0}[count:{1}]", tag, count);
            trace.WriteLine(newPrefix);
            trace.Flush();
            return new FaultTraceNode(trace, newPrefix);
        }

        public IFaultInstance Select(string tag, long l)
        {
            count++;
            string newPrefix = prefix + String.Format("/{0}[limit:{1}]", tag, l);
            trace.WriteLine(newPrefix);
            trace.Flush();
            return new FaultTraceNode(trace, newPrefix);
        }

        public IFaultInstance Select(string tag, string s)
        {
            count++;
            string newPrefix = prefix + String.Format("/{0}[stringequal:{1}]", tag, s);
            trace.WriteLine(newPrefix);
            trace.Flush();
            return new FaultTraceNode(trace, newPrefix);
        }

        public IFaultPredicate SelectPredicate(string tag)
        {
            string newPrefix = prefix + String.Format("/{0}", tag);
            return new FaultTracePredicate(trace, newPrefix);
        }

        private class FaultTracePredicate : IFaultPredicate
        {
            private readonly TextWriter trace;
            private readonly string prefix;
            private long count;

            public FaultTracePredicate(TextWriter trace, string prefix)
            {
                this.trace = trace;
                this.prefix = prefix;
            }

            public IFaultPredicate Clone()
            {
                throw new InvalidOperationException();
            }

            public bool Test()
            {
                count++;
                string newPrefix = prefix + String.Format("[count:{0}]", count);
                trace.WriteLine(newPrefix);
                trace.Flush();
                return false;
            }

            public bool Test(long l)
            {
                count++;
                string newPrefix = prefix + String.Format("[limit:{0}]", l);
                trace.WriteLine(newPrefix);
                trace.Flush();
                return false;
            }

            public bool Test(string s)
            {
                count++;
                string newPrefix = prefix + String.Format("[stringequal:{0}]", s);
                trace.WriteLine(newPrefix);
                trace.Flush();
                return false;
            }
        }
    }

    // Specification of fault injection points with trigger criteria. The constrained
    // points may not actually be reached during a given program run.
    public class FaultTemplateNode
    {
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


        private string tag;
        private FaultTemplateNode parent;
        private FaultMethod method;
        private KeyValuePair<FaultTemplateNode, IFaultPredicate>[] children = new KeyValuePair<FaultTemplateNode, IFaultPredicate>[0];

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
        public KeyValuePair<FaultTemplateNode, IFaultPredicate>[] Children { get { return children; } }
        public bool Terminal { get { return children.Length == 0; } }
        public FaultMethod Method { get { return method; } }

        public void Add(FaultTemplateNode child, IFaultPredicate childPredicate)
        {
            Array.Resize(ref children, children.Length + 1);
            children[children.Length - 1] = new KeyValuePair<FaultTemplateNode, IFaultPredicate>(child, childPredicate);
        }


        // Parse fault injection path and add to template.

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
                IFaultPredicate predicate = FaultInstanceNode.NullFaultPredicate.Null;
                if (colon > 0)
                {
                    switch (predicateString.Substring(0, colon))
                    {
                        default:
                            throw new ArgumentException();
                        case "count":
                            predicate = new FaultInstanceNode.CountFaultPredicate(Int64.Parse(predicateString.Substring(colon + 1)));
                            break;
                        case "limit":
                            predicate = new FaultInstanceNode.LimitFaultPredicate(Int64.Parse(predicateString.Substring(colon + 1)));
                            break;
                        case "sumlimit":
                            predicate = new FaultInstanceNode.SumLimitFaultPredicate(Int64.Parse(predicateString.Substring(colon + 1)));
                            break;
                        case "stringequal":
                            predicate = new FaultInstanceNode.StringEqualFaultPredicate(predicateString.Substring(colon + 1));
                            break;
                        case "regex":
                            predicate = new FaultInstanceNode.StringMatchFaultPredicate(predicateString.Substring(colon + 1));
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
    }
}
