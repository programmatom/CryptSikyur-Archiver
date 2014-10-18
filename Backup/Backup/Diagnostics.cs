/*
 *  Copyright � 2014 Thomas R. Lawrence
 *    except: "SkeinFish 0.5.0/*.cs", which are Copyright � 2010 Alberto Fajardo
 *    except: "SerpentEngine.cs", which is Copyright � 1997, 1998 Systemics Ltd on behalf of the Cryptix Development Team (but see license discussion at top of that file)
 *    except: "Keccak/*.cs", which are Copyright � 2000 - 2011 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
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

        public class BinaryOperatorPredicate : IFaultPredicate
        {
            // binary operator has short circuit semantics

            private readonly IFaultPredicate left;
            private readonly IFaultPredicate right;
            private readonly Operation operation;

            public enum Operation
            {
                And,
                Or,
            }
            private static readonly string[] Operations = new string[] { "and", "or" };

            public BinaryOperatorPredicate(Operation operation, IFaultPredicate left, IFaultPredicate right)
            {
                this.operation = operation;
                this.left = left;
                this.right = right;
            }

            public BinaryOperatorPredicate(BinaryOperatorPredicate original)
            {
                this.operation = original.operation;
                this.left = original.left;
                this.right = original.right;
            }

            public IFaultPredicate Clone()
            {
                return new BinaryOperatorPredicate(this);
            }

            public bool Test()
            {
                switch (operation)
                {
                    default:
                        throw new InvalidOperationException();
                    case Operation.And:
                        return left.Test() && right.Test(); // short-circuiting operator
                    case Operation.Or:
                        return left.Test() || right.Test(); // short-circuiting operator
                }
            }

            public bool Test(long l)
            {
                switch (operation)
                {
                    default:
                        throw new InvalidOperationException();
                    case Operation.And:
                        return left.Test(l) && right.Test(l); // short-circuiting operator
                    case Operation.Or:
                        return left.Test(l) || right.Test(l); // short-circuiting operator
                }
            }

            public bool Test(string s)
            {
                switch (operation)
                {
                    default:
                        throw new InvalidOperationException();
                    case Operation.And:
                        return left.Test(s) && right.Test(s); // short-circuiting operator
                    case Operation.Or:
                        return left.Test(s) || right.Test(s); // short-circuiting operator
                }
            }

            public override string ToString()
            {
                string leftString = left.ToString();
                if ((leftString.Length >= 2) && (leftString[0] == '[') && (leftString[leftString.Length - 1] == ']'))
                {
                    leftString = leftString.Substring(1, leftString.Length - 2);
                }
                string rightString = right.ToString();
                if ((rightString.Length >= 2) && (rightString[0] == '[') && (rightString[rightString.Length - 1] == ']'))
                {
                    rightString = rightString.Substring(1, rightString.Length - 2);
                }
                return String.Format("[{1} {0} {2}]", Operations[(int)operation], leftString, rightString);
            }
        }


        public class NullFaultInstanceNode : IFaultInstance
        {
            public IFaultInstance Select(string tag)
            {
                return this;
            }

            public IFaultInstance Select(string tag, long l)
            {
                return this;
            }

            public IFaultInstance Select(string tag, string s)
            {
                return this;
            }

            public IFaultPredicate SelectPredicate(string tag)
            {
                return FaultInstancePredicate.Null;
            }
        }

        public static readonly IFaultInstance Null = new NullFaultInstanceNode();


        private readonly KeyValuePair<IFaultPredicate, FaultTemplateNode>[] predicates;

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
                            case FaultTemplateNode.FaultMethod.Custom:
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
                                if (!String.IsNullOrEmpty(predicates[i].Value.ProofPath))
                                {
                                    File.WriteAllText(predicates[i].Value.ProofPath, ComputePath(predicates[i].Value));
                                }
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
                string path = ComputePath(node);

                if (!String.IsNullOrEmpty(node.ProofPath))
                {
                    File.WriteAllText(node.ProofPath, path);
                }

                if (node.Method == FaultTemplateNode.FaultMethod.Custom)
                {
                    throw new FaultTemplateNode.FaultInjectionPayloadException(path, node.Payload);
                }

                if (message.Length != 0)
                {
                    message.Append(", ");
                }
                message.Append(path);
            }
            throw new FaultTemplateNode.FaultInjectionException(message.ToString());
        }

        private static string ComputePath(FaultTemplateNode node)
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
            return path;
        }


        // Fast predicate evaluator for performance-sensitive code
        private class FaultInstancePredicate : IFaultPredicate
        {
            private class NullFaultInstancePredicate : IFaultPredicate
            {
                public IFaultPredicate Clone()
                {
                    return this;
                }

                public bool Test()
                {
                    return false;
                }

                public bool Test(long l)
                {
                    return false;
                }

                public bool Test(string s)
                {
                    return false;
                }
            }

            public static readonly IFaultPredicate Null = new NullFaultInstancePredicate();


            private readonly KeyValuePair<IFaultPredicate, FaultTemplateNode>[] predicates;
            private readonly FaultInstanceNode owner;

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
                                case FaultTemplateNode.FaultMethod.Custom:
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
                                    if (!String.IsNullOrEmpty(predicates[i].Value.ProofPath))
                                    {
                                        File.WriteAllText(predicates[i].Value.ProofPath, ComputePath(predicates[i].Value));
                                    }
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
        private readonly IFaultInstance underlying;
        private readonly TextWriter trace;
        private readonly string prefix;
        private long count;

        // NOTE: Faults of type "kill" are not logged to the fault trace file because the process
        // is terminated before code returns through this class. All injected faults of a thrown
        // exception type are logged.
        private const string FaultTraceFilePrefix = "faulttrace";
        private const string FaultTraceLogMessage = "fault injected on preceding path";

        public FaultTraceNode(IFaultInstance underlying)
        {
            this.underlying = underlying;
            trace = Logging.CreateLogFile(FaultTraceFilePrefix);
        }

        protected FaultTraceNode(TextWriter trace, string prefix, IFaultInstance underlying)
        {
            this.underlying = underlying;
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

            try
            {
                IFaultInstance underlyingResult = underlying.Select(tag);
                return new FaultTraceNode(trace, newPrefix, underlyingResult);
            }
            catch (FaultTemplateNode.FaultInjectionException)
            {
                trace.WriteLine(FaultTraceLogMessage);
                trace.Flush();
                throw;
            }
        }

        public IFaultInstance Select(string tag, long l)
        {
            count++;
            string newPrefix = prefix + String.Format("/{0}[count:{1},limit:{2}]", tag, count, l);
            trace.WriteLine(newPrefix);
            trace.Flush();

            try
            {
                IFaultInstance underlyingResult = underlying.Select(tag, l);
                return new FaultTraceNode(trace, newPrefix, underlyingResult);
            }
            catch (FaultTemplateNode.FaultInjectionException)
            {
                trace.WriteLine(FaultTraceLogMessage);
                trace.Flush();
                throw;
            }
        }

        public IFaultInstance Select(string tag, string s)
        {
            count++;
            string newPrefix = prefix + String.Format("/{0}[count:{1},stringequal:{2}]", tag, count, PrepareString(s));
            trace.WriteLine(newPrefix);
            trace.Flush();

            try
            {
                IFaultInstance underlyingResult = underlying.Select(tag, s);
                return new FaultTraceNode(trace, newPrefix, underlyingResult);
            }
            catch (FaultTemplateNode.FaultInjectionException)
            {
                trace.WriteLine(FaultTraceLogMessage);
                trace.Flush();
                throw;
            }
        }

        public IFaultPredicate SelectPredicate(string tag)
        {
            string newPrefix = prefix + String.Format("/{0}", tag);

            IFaultPredicate underlyingResult = underlying.SelectPredicate(tag);
            return new FaultTracePredicate(trace, newPrefix, underlyingResult);
        }

        private class FaultTracePredicate : IFaultPredicate
        {
            private readonly IFaultPredicate underlying;
            private readonly TextWriter trace;
            private readonly string prefix;
            private long count;

            public FaultTracePredicate(TextWriter trace, string prefix, IFaultPredicate underlying)
            {
                this.underlying = underlying;
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

                try
                {
                    return underlying.Test();
                }
                catch (FaultTemplateNode.FaultInjectionException)
                {
                    trace.WriteLine(FaultTraceLogMessage);
                    trace.Flush();
                    throw;
                }
            }

            public bool Test(long l)
            {
                count++;
                string newPrefix = prefix + String.Format("[count:{0},limit:{1}]", count, l);
                trace.WriteLine(newPrefix);
                trace.Flush();

                try
                {
                    return underlying.Test(l);
                }
                catch (FaultTemplateNode.FaultInjectionException)
                {
                    trace.WriteLine(FaultTraceLogMessage);
                    trace.Flush();
                    throw;
                }
            }

            public bool Test(string s)
            {
                count++;
                string newPrefix = prefix + String.Format("[count:{0},stringequal:{1}]", count, PrepareString(s));
                trace.WriteLine(newPrefix);
                trace.Flush();

                try
                {
                    return underlying.Test(s);
                }
                catch (FaultTemplateNode.FaultInjectionException)
                {
                    trace.WriteLine(FaultTraceLogMessage);
                    trace.Flush();
                    throw;
                }
            }
        }

        private static string PrepareString(string s)
        {
            return String.Concat("\"", (s != null ? s.Replace("\"", "\\\"") : null), "\"");
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

        public class FaultInjectionPayloadException : FaultInjectionException
        {
            private string payload;

            public FaultInjectionPayloadException(string message, string payload)
                : base(message)
            {
                this.payload = payload;
            }

            public string Payload { get { return payload; } }
        }

        public enum FaultMethod
        {
            None = 0,

            Throw,
            Kill,
            Custom,
        }

        private string tag;
        private FaultTemplateNode parent;
        private FaultMethod method;
        private string payload;
        private string proofPath;
        private KeyValuePair<FaultTemplateNode, IFaultPredicate>[] children = new KeyValuePair<FaultTemplateNode, IFaultPredicate>[0];

        public FaultTemplateNode()
        {
        }

        public FaultTemplateNode(string tag, FaultTemplateNode parent, FaultMethod method, string payload, string proofPath)
        {
            this.tag = tag;
            this.parent = parent;
            this.method = method;
            this.payload = payload;
            this.proofPath = proofPath;
        }

        public string Tag { get { return tag; } }
        public FaultTemplateNode Parent { get { return parent; } }
        public KeyValuePair<FaultTemplateNode, IFaultPredicate>[] Children { get { return children; } }
        public bool Terminal { get { return children.Length == 0; } }
        public FaultMethod Method { get { return method; } }
        public string Payload { get { return payload; } }
        public string ProofPath { get { return proofPath; } }

        public void Add(FaultTemplateNode child, IFaultPredicate childPredicate)
        {
            Array.Resize(ref children, children.Length + 1);
            children[children.Length - 1] = new KeyValuePair<FaultTemplateNode, IFaultPredicate>(child, childPredicate);
        }


        // Parse fault injection path and add to template.

        public static void ParseFaultInjectionPath(FaultTemplateNode root, string method, string proofPath, string arg)
        {
            if (String.IsNullOrEmpty(arg) || (arg[0] != '/'))
            {
                throw new ArgumentException();
            }
            FaultMethod faultMethod;
            string faultPayload = null;
            int faultMethodColon = method.IndexOf(':');
            switch (faultMethodColon < 0 ? method : method.Substring(0, faultMethodColon))
            {
                default:
                    throw new ArgumentException();
                case "throw":
                    faultMethod = FaultMethod.Throw;
                    break;
                case "kill":
                    faultMethod = FaultMethod.Kill;
                    break;
                case "custom":
                    faultMethod = FaultMethod.Custom;
                    faultPayload = method.Substring(faultMethodColon + 1, method.Length - (faultMethodColon + 1));
                    break;
            }

            int i = 0;
            string t;
            while ((t = NextToken(arg, ref i)) != null)
            {
                if (!t.Equals("/"))
                {
                    throw new ArgumentException();
                }

                string tag = NextToken(arg, ref i);
                if (!Char.IsLetterOrDigit(tag[0]))
                {
                    throw new ArgumentException();
                }

                bool hasPredicate = false;
                {
                    int oldi = i;
                    t = NextToken(arg, ref i);
                    if ((t != null) && !(hasPredicate = String.Equals(t, "[")) && !String.Equals(t, "/"))
                    {
                        throw new ArgumentException();
                    }
                    i = oldi;
                }

                IFaultPredicate predicate = null;
                while (hasPredicate)
                {
                    IFaultPredicate previousPredicate = predicate;

                    t = NextToken(arg, ref i);
                    if (!String.Equals(t, "[") && !String.Equals(t, "and"))
                    {
                        throw new ArgumentException();
                    }

                    string op = NextToken(arg, ref i);

                    if (!String.Equals(NextToken(arg, ref i), ":"))
                    {
                        throw new ArgumentException();
                    }

                    string operand = NextToken(arg, ref i);

                    switch (op)
                    {
                        default:
                            throw new ArgumentException();
                        case "count":
                            predicate = new FaultInstanceNode.CountFaultPredicate(Int64.Parse(operand));
                            break;
                        case "limit":
                            predicate = new FaultInstanceNode.LimitFaultPredicate(Int64.Parse(operand));
                            break;
                        case "sumlimit":
                            predicate = new FaultInstanceNode.SumLimitFaultPredicate(Int64.Parse(operand));
                            break;
                        case "stringequal":
                            predicate = new FaultInstanceNode.StringEqualFaultPredicate(operand);
                            break;
                        case "regex":
                            predicate = new FaultInstanceNode.StringMatchFaultPredicate(operand);
                            break;
                    }

                    int oldi = i;
                    t = NextToken(arg, ref i);
                    if (t.Equals("]"))
                    {
                        hasPredicate = false;
                    }
                    else if (t.Equals("and"))
                    {
                        i = oldi;
                    }
                    else
                    {
                        throw new ArgumentException();
                    }

                    // TODO: if desired to support more than conjunction, then a proper precedence-based
                    // parser will have to be developed to assemble the expressions.
                    if (previousPredicate != null)
                    {
                        predicate = new FaultInstanceNode.BinaryOperatorPredicate(FaultInstanceNode.BinaryOperatorPredicate.Operation.And, previousPredicate, predicate);
                    }
                }
                if (predicate == null)
                {
                    predicate = FaultInstanceNode.NullFaultPredicate.Null;
                }

                bool last;
                {
                    int oldi = i;
                    last = NextToken(arg, ref i) == null;
                    i = oldi;
                }

                FaultTemplateNode node = new FaultTemplateNode(tag, root, last ? faultMethod : FaultMethod.None, last ? faultPayload : null, proofPath);
                root.Add(node, predicate);

                root = node;
            }
        }

        private static string NextToken(string s, ref int i)
        {
            while ((i < s.Length) && Char.IsWhiteSpace(s[i]))
            {
                i++;
            }
            if (!(i < s.Length))
            {
                return null;
            }

            const string Delimiters = "[]:/{}()";
            if (Delimiters.IndexOf(s[i]) >= 0)
            {
                return new String(s[i++], 1);
            }
            else if ((s[i] == '"') || (s[i] == '\''))
            {
                char stop = s[i];

                StringBuilder sb = new StringBuilder();
                i++;
                if (!(i < s.Length))
                {
                    throw new InvalidDataException();
                }
                while (s[i] != stop)
                {
                    if (s[i] == '\\')
                    {
                        i++;
                        if (!(i < s.Length))
                        {
                            throw new InvalidDataException();
                        }
                        switch (s[i])
                        {
                            default:
                                throw new InvalidDataException();
                            case '"':
                            case '\'':
                            case '\\':
                                sb.Append(s[i]);
                                break;
                        }
                    }
                    else
                    {
                        sb.Append(s[i]);
                    }
                    i++;
                    if (!(i < s.Length))
                    {
                        throw new InvalidDataException();
                    }
                }
                i++;
                return sb.ToString();
            }
            else
            {
                StringBuilder sb = new StringBuilder();
                const string ExtendedDelimiters = Delimiters + "\"'";
                do
                {
                    sb.Append(s[i]);
                    i++;
                } while ((i < s.Length) && !Char.IsWhiteSpace(s[i]) && (ExtendedDelimiters.IndexOf(s[i]) < 0));
                return sb.ToString();
            }
        }
    }
}
