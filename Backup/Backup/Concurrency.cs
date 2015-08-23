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
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace Concurrent
{
    ////////////////////////////////////////////////////////////////////////////
    //
    // Concurrent task service
    //
    ////////////////////////////////////////////////////////////////////////////

    public class SequenceNumberDispenser
    {
        private long lastSequenceNumber;

        // threadsafe
        public long Next()
        {
            return Interlocked.Increment(ref lastSequenceNumber); // ++sequenceNumbering
        }
    }

    public class ConcurrentMessageLog : IDisposable
    {
        private long lastSequenceNumber;
        private SequenceNumberDispenser sequenceNumbering;
        private List<Record> records = new List<Record>(); // should be "multi"-SortedList, but .NET 2.0's lacks essential features
        private readonly int threadId = Thread.CurrentThread.ManagedThreadId;
        private readonly bool interactive;
        private int lastWidth;

        private class Record
        {
            internal readonly long sequenceNumber;
            internal readonly List<Line> lines;

            internal Record(long sequenceNumber, List<Line> lines)
            {
                this.sequenceNumber = sequenceNumber;
                this.lines = lines;
            }
        }

        public ConcurrentMessageLog(bool interactive, bool enableSequencing)
        {
            this.interactive = interactive;
            this.lastWidth = interactive ? Console.BufferWidth : 0;
            if (enableSequencing)
            {
                sequenceNumbering = new SequenceNumberDispenser();
            }
        }

        private ConcurrentMessageLog()
        {
            throw new NotSupportedException();
        }

        private class Line
        {
            internal string line;
            internal ConsoleColor? color;
            internal bool newline;

            private Line(string line, ConsoleColor? color, bool newline)
            {
                this.line = line;
                this.color = color;
                this.newline = newline;
            }

            internal Line(string line)
                : this(line, null, true)
            {
            }

            internal Line(string line, ConsoleColor color)
                : this(line, color, true)
            {
            }

            internal Line(string line, bool newline)
                : this(line, null, newline)
            {
            }

            internal Line(string line, ConsoleColor color, bool newline)
                : this(line, (ConsoleColor?)color, newline)
            {
            }
        }

        public class ThreadMessageLog : TextWriter /* IDisposable */
        {
            private readonly long sequenceNumber;
            private List<Line> lines = new List<Line>();
            private ConcurrentMessageLog owner;
            private readonly int threadId = Thread.CurrentThread.ManagedThreadId;

            public ThreadMessageLog(ConcurrentMessageLog owner, long sequenceNumber)
            {
                this.sequenceNumber = sequenceNumber;
                this.owner = owner;
            }

            public override void Write(char value)
            {
                Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
                lines.Add(new Line(new String(value, 1), false));
            }

            public override void Write(string line)
            {
                Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
                lines.Add(new Line(line, false));
            }

            public override void WriteLine()
            {
                Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
                lines.Add(new Line(String.Empty));
            }

            public override void WriteLine(string line)
            {
                Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
                lines.Add(new Line(line));
            }

            public override void WriteLine(string format, object arg0)
            {
                Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
                lines.Add(new Line(String.Format(format, arg0)));
            }

            public override void WriteLine(string format, object arg0, object arg1)
            {
                Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
                lines.Add(new Line(String.Format(format, arg0, arg1)));
            }

            public override void WriteLine(string format, object arg0, object arg1, object arg2)
            {
                Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
                lines.Add(new Line(String.Format(format, arg0, arg1, arg2)));
            }

            public override void WriteLine(string format, params object[] arg)
            {
                Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
                lines.Add(new Line(String.Format(format, arg)));
            }

            public void WriteLine(ConsoleColor color, string line)
            {
                Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
                lines.Add(new Line(line, color));
            }

            public void WriteLine(ConsoleColor color, string format, params object[] arg)
            {
                Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
                lines.Add(new Line(String.Format(format, arg), color));
            }

            protected override void Dispose(bool disposing)
            {
                if (owner != null)
                {
                    owner.Incorporate(lines, sequenceNumber);
                    lines = null;
                    owner = null;
                }
                base.Dispose(disposing);
            }

            public override Encoding Encoding
            {
                get
                {
                    return Encoding.Unicode;
                }
            }
        }

        public ThreadMessageLog GetNewMessageLog(long sequenceNumber)
        {
            return new ThreadMessageLog(this, sequenceNumber);
        }

        // For proper sequencing it is recommended to not use this method, but rather 
        // use GetNewMessageLog(long sequenceNumber) [above] in conjunction with an
        // explicitly obtained sequence number from GetSequenceNumber() called at a point
        // in the code that ensures those sequence numbers are being obtained in a
        // meaningful order - because sequence numbers can be obtained well before
        // GetNewMessageLog is called, and on a different thread, whereas GetNewMessageLog
        // must be called on the thread that will use it, which may occur out of sequence.
        // This auto-generating method is for convenience in the case where sequencing
        // is not enabled.
        public ThreadMessageLog GetNewMessageLog()
        {
            return new ThreadMessageLog(this, GetSequenceNumber());
        }

        // WARNING: once a sequence number is obtained, it MUST be used or all log
        // entries after it will be delayed until termination of the entire object.
        // If an operation is conditional and does not occur, the sequence number
        // should be "disposed" of by obtaining and immediately discarding an empty
        // ThreadMessageLog via GetNewMessageLog(long sequenceNumber).
        public long GetSequenceNumber()
        {
            return sequenceNumbering != null ? sequenceNumbering.Next() : 0;
        }

        private class CompareRecords : IComparer<Record>
        {
            public int Compare(Record l, Record r)
            {
                return l.sequenceNumber.CompareTo(r.sequenceNumber);
            }
        }

        private void Incorporate(List<Line> lines, long sequenceNumber)
        {
            if ((sequenceNumbering == null) && (sequenceNumber != 0))
            {
                throw new InvalidOperationException();
            }

            CompareRecords comparer = new CompareRecords();
            Record record = new Record(sequenceNumber, lines);
            lock (this)
            {
                int index;
                if (sequenceNumbering != null)
                {
                    // "records" is essentially a priority queue. It is anticipated that the
                    // list will be short. If the chain of out-of-order messages gets very
                    // large the vector manipulations may become inefficient and should be
                    // replaced with a tree-based implementation.

                    index = records.BinarySearch(record, comparer);
                    if (index >= 0)
                    {
                        // https://msdn.microsoft.com/en-us/library/w4e7fxsh%28v=vs.110%29.aspx
                        // "If the List<T> contains more than one element with the same value, the method returns
                        // only one of the occurrences, and it might return any one of the occurrences, not necessarily
                        // the first one."

                        // scan to end of run of multiple records of same value in order to
                        // preserve actual order of insertion in non-sequenced use case
                        while ((index < records.Count) && (comparer.Compare(record, records[index]) == 0))
                        {
                            index++;
                        }
                    }
                    else
                    {
                        index = ~index;
                    }
                }
                else
                {
                    // for non-sequenced case, always append
                    index = records.Count;
                }

                records.Insert(index, record);

                // assert ordering invariant
                for (int i = 1; i < records.Count; i++)
                {
                    Debug.Assert(records[i - 1].sequenceNumber <= records[i].sequenceNumber);
                }
            }
        }

        public bool Pending
        {
            get
            {
                Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
                lock (this)
                {
                    return records.Count > 0;
                }
            }
        }

        public delegate void PrepareConsoleMethod();
        public bool Flush(bool permitOutOfSequence, PrepareConsoleMethod prepareConsole)
        {
            Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);

            List<Line> batch = new List<Line>();
            bool flushedAll;

            lock (this)
            {
                if (interactive)
                {
                    lastWidth = Console.BufferWidth;
                }

                // "records" is essentially a priority queue. It is anticipated that the
                // list will be short. If the chain of out-of-order messages gets very
                // large the vector manipulations may become inefficient and should be
                // replaced with a tree-based implementation.
                int i;
                for (i = 0; (i < records.Count) && (permitOutOfSequence || (records[i].sequenceNumber <= lastSequenceNumber + 1)); i++)
                {
                    Record record = records[i];

                    if (!(record.sequenceNumber <= lastSequenceNumber + 1))
                    {
                        batch.Add(new Line("[out of sequence:]", ConsoleColor.Cyan));
                    }
                    foreach (Line line in record.lines)
                    {
                        batch.Add(line);
                    }

                    lastSequenceNumber = Math.Max(lastSequenceNumber, record.sequenceNumber);
                }
                records.RemoveRange(0, i);

                flushedAll = records.Count == 0;
            }

            if ((batch.Count != 0) && (prepareConsole != null))
            {
                prepareConsole(); // allow any status to be cleared
            }

            foreach (Line line in batch)
            {
                ConsoleColor old = Console.ForegroundColor;
                if (line.color.HasValue)
                {
                    Console.ForegroundColor = line.color.Value;
                }
                if (line.newline)
                {
                    Console.WriteLine(line.line);
                }
                else
                {
                    Console.Write(line.line);
                }
                if (line.color.HasValue)
                {
                    Console.ForegroundColor = old;
                }
            }

            return flushedAll;
        }

        public void Flush(PrepareConsoleMethod prepareConsole)
        {
            Flush(false/*permitOutOfSequence*/, prepareConsole);
        }

        public void Flush()
        {
            Flush(null/*prepareConsole*/);
        }

        public void Dispose()
        {
            Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
            bool flushedAll = Flush(true/*permitOutOfSequence*/, null/*prepareConsole*/);
            Debug.Assert(flushedAll);
        }

        public int BufferWidth
        {
            get
            {
                return lastWidth;
            }
        }

        public bool Interactive
        {
            get
            {
                return interactive;
            }
        }

        public void WriteLine()
        {
            using (ThreadMessageLog messages = GetNewMessageLog(GetSequenceNumber()))
            {
                messages.WriteLine();
            }
        }

        public void WriteLine(string line)
        {
            using (ThreadMessageLog messages = GetNewMessageLog(GetSequenceNumber()))
            {
                messages.WriteLine(line);
            }
        }

        public void WriteLine(string format, params object[] arg)
        {
            using (ThreadMessageLog messages = GetNewMessageLog(GetSequenceNumber()))
            {
                messages.WriteLine(format, arg);
            }
        }

        public void WriteLine(ConsoleColor color, string format, params object[] arg)
        {
            using (ThreadMessageLog messages = GetNewMessageLog(GetSequenceNumber()))
            {
                messages.WriteLine(color, format, arg);
            }
        }
    }

    // TODO: should build on top of System.Threading.ThreadPool?
    public class ConcurrentTasks : IDisposable
    {
        private readonly int threadCount;
        private readonly int maxQueuedTasksCount;

        private readonly int primaryThreadId;
        private readonly ConcurrentMessageLog messagesLog; // null ok
        private readonly TextWriter trace; // null ok
        private bool writeStatsToMessagesLog;

        private readonly Queue<EventWaitHandle> availableCompletionHandles = new Queue<EventWaitHandle>();

        private readonly SequenceNumberDispenser taskSequenceNumbering = new SequenceNumberDispenser();

        private Semaphore waitForTask;
        private EventWaitHandle waitQueueNotFull;
        private Queue<TaskMethodInternal> tasks;
        private EventWaitHandle waitQueueEmpty;
        private int running;
        private EventWaitHandle waitAllIdle;
        private int waiting;
        private EventWaitHandle waitTermination;
        private long faultingTasks;
        private ThreadState[] threads;

        private const int LogDelayInterval = 2 * 60; // this should be tunable for different applications

        internal class ThreadState
        {
            public readonly ConcurrentTasks owner;
            public readonly Thread thread;

            public long currentTaskSequenceNumber;
            public string currentTaskTraceTag;

            internal ThreadState(ConcurrentTasks owner, Thread thread)
            {
                this.owner = owner;
                this.thread = thread;
            }
        }

        private ConcurrencyHistogram queueLengthHistogram;
        private ConcurrencyBlocked mainThreadBlocked;

        private delegate void TaskMethodInternal(ThreadState threadState);

        public delegate void TaskMethod(ITaskContext taskContext);
        public delegate void WaitIntervalMethod();
        public delegate void WriteLineMethod(string line);

        public bool WriteStatsToMessagesLog { set { writeStatsToMessagesLog = value; } }

        // Note about threadCount: 0 and 1 are slightly different. threadCount==0 runs everything
        // on the main thread, eliminating any cross-thread synchronization (i.e. the Do() method
        // invokes the task delegate directly in the ordinary way and does not return until the
        // delegate has finished). threadCount==1 creates a single task thread, so tasks will be
        // executed in order, non-overlapped, but the main thread is permitted to continue it's own
        // work simultaneously.
        // messagesLog and trace are both optional (can be null).
        public ConcurrentTasks(int threadCount, int? maxQueuedTasksCount, ConcurrentMessageLog messagesLog, TextWriter trace)
        {
            if (threadCount < 0)
            {
                throw new ArgumentException();
            }

            this.primaryThreadId = Thread.CurrentThread.ManagedThreadId;

            this.messagesLog = messagesLog;
            this.trace = trace;

            this.threadCount = threadCount;
            this.maxQueuedTasksCount = (maxQueuedTasksCount.HasValue ? maxQueuedTasksCount.Value : threadCount) + 1;

            if (threadCount > 0)
            {
                this.tasks = new Queue<TaskMethodInternal>(this.maxQueuedTasksCount);

                this.waitForTask = new Semaphore(0, threadCount + this.maxQueuedTasksCount);
                this.waitQueueNotFull = new EventWaitHandle(true/*intially signalled*/, EventResetMode.ManualReset);
                this.waitTermination = new EventWaitHandle(false/*intially signalled*/, EventResetMode.ManualReset);
                this.waitQueueEmpty = new EventWaitHandle(true/*intially signalled*/, EventResetMode.ManualReset);
                this.waitAllIdle = new EventWaitHandle(false/*intially signalled*/, EventResetMode.ManualReset);
                this.threads = new ThreadState[threadCount];

                for (int i = 0; i < threadCount; i++)
                {
                    this.threads[i] = new ThreadState(this, new Thread(StaticThreadMain));
                    this.threads[i].thread.Start(threads[i]);
                }

                this.queueLengthHistogram = new ConcurrencyHistogram(this.maxQueuedTasksCount + 1/*0..maxQueuedTasksCount - range inclusive*/);
                this.mainThreadBlocked = new ConcurrencyBlocked("Main thread");

                this.waitAllIdle.WaitOne(); // wait for spin-up to complete (otherwise a too-soon Dispose() will hang)
            }
        }

        private ConcurrentTasks()
        {
            throw new NotSupportedException();
        }

        public void Drain(WaitIntervalMethod waitIntervalMethod, int waitInterval)
        {
            Debug.Assert(Thread.CurrentThread.ManagedThreadId == primaryThreadId);
            // draining paused queue is ok.

            if ((waitInterval == -1) != (waitIntervalMethod == null))
            {
                throw new ArgumentException(); // both or neither
            }

            if (threadCount > 0)
            {
                mainThreadBlocked.EnterWaitRegion();

                if (waitInterval < 0)
                {
                    waitInterval = LogDelayInterval * 1000;
                }

                // must drain queue first, otherwise waitAllIdle is invalid because it may jitter
                DateTime start = DateTime.UtcNow;
                while (!waitQueueEmpty.WaitOne(waitInterval))
                {
                    if (waitIntervalMethod != null)
                    {
                        waitIntervalMethod();
                    }

                    if ((trace != null) && ((DateTime.UtcNow - start).TotalSeconds >= LogDelayInterval))
                    {
                        trace.WriteLine("ConcurrentTasks.Drain() {0} seconds for waitQueueEmpty - still waiting", LogDelayInterval);
                        trace.Flush();
                        start = DateTime.UtcNow;
                    }
                }

                while (!waitAllIdle.WaitOne(waitInterval))
                {
                    if (waitIntervalMethod != null)
                    {
                        waitIntervalMethod();
                    }

                    if ((trace != null) && ((DateTime.UtcNow - start).TotalSeconds >= LogDelayInterval))
                    {
                        trace.WriteLine("ConcurrentTasks.Drain() {0} seconds for waitAllIdle - still waiting", LogDelayInterval);
                        trace.Flush();
                        start = DateTime.UtcNow;
                    }
                }

                mainThreadBlocked.ExitWaitRegion();
            }
        }

        public void Drain()
        {
            Drain(null, -1);
        }

        public void Dispose()
        {
            Debug.Assert(Thread.CurrentThread.ManagedThreadId == primaryThreadId);

            Drain();

            if (threadCount > 0)
            {
                Debug.Assert(tasks.Count == 0);
                Debug.Assert(running == threadCount);

                mainThreadBlocked.EnterWaitRegion();

                // with queue empty (ensured by Drain() above), release all threads and they will terminate
                waitForTask.Release(threadCount);
                // wait for last thead to exit
                waitTermination.WaitOne();

                mainThreadBlocked.ExitWaitRegion();

                // release resources
                waitForTask.Close();
                waitTermination.Close();
                waitQueueEmpty.Close();
                waitQueueNotFull.Close();
                waitAllIdle.Close();
                foreach (EventWaitHandle completionHandle in availableCompletionHandles)
                {
                    completionHandle.Close();
                }
                availableCompletionHandles.Clear();

                // write concurrency statistics
                mainThreadBlocked.Stop();
                mainThreadBlocked.Report(WriteLineMessage);
                queueLengthHistogram.Report(WriteLineMessage);
            }

            // write fault statistics in all modes
            if (faultingTasks > 0)
            {
                WriteLineMessage(String.Format("{0} asynchronous tasks threw exceptions", faultingTasks));
            }
        }

        private void WriteLineMessage(string line)
        {
            if (trace != null)
            {
                trace.WriteLine(line);
                trace.Flush();
            }
            if (writeStatsToMessagesLog && (messagesLog != null))
            {
                long logSequenceNumber = messagesLog.GetSequenceNumber();
                using (ConcurrentMessageLog.ThreadMessageLog messages = messagesLog.GetNewMessageLog(logSequenceNumber))
                {
                    messages.WriteLine(line);
                }
            }
        }

        public abstract class CompletionObject : IDisposable
        {
            private bool succeeded;

            public abstract void Wait();
            public bool Succeeded { get { return succeeded; } }
            public abstract void Dispose();

            internal void SetSucceeded()
            {
                succeeded = true;
            }
        }

        public class NullCompletionObject : CompletionObject
        {
            public override void Wait()
            {
            }

            public override void Dispose()
            {
                GC.SuppressFinalize(this);
            }

            ~NullCompletionObject()
            {
                Debug.Assert(false);
                throw new InvalidOperationException("NullCompletionObject finalizer invoked - did you forget to Dispose() it?");
            }
        }

        public class ConcurrentCompletionObject : CompletionObject
        {
            private ConcurrentTasks owner;
            private EventWaitHandle waitCompleted;
            private bool waited;

            internal ConcurrentCompletionObject(ConcurrentTasks owner, EventWaitHandle waitCompleted)
            {
                this.owner = owner;
                this.waitCompleted = waitCompleted;
            }

            public override void Wait()
            {
                waitCompleted.WaitOne();
                waited = true;
            }

            public override void Dispose()
            {
                if (waited)
                {
                    // can only hand back if async task no longer will signal it eventually
                    // (otherwise some other subsequent client might get spurriously signalled)
                    owner.HandBackCompletionHandle(ref waitCompleted);
                }
                else
                {
                    // otherwise, discard object. signalling code will eat the received exception.
                    waitCompleted.Close();
                }
                waitCompleted = null;
                GC.SuppressFinalize(this);
            }

            ~ConcurrentCompletionObject()
            {
                Debug.Assert(false);
                throw new InvalidOperationException("ConcurrentCompletionObject finalizer invoked - did you forget to Dispose() it?");
            }
        }

        private EventWaitHandle GetCompletionHandle()
        {
            EventWaitHandle completionHandle = null;
            lock (availableCompletionHandles)
            {
                if (availableCompletionHandles.Count > 0)
                {
                    completionHandle = availableCompletionHandles.Dequeue();
                    completionHandle.Reset(); // ensure initially unsignalled
                }
            }
            if (completionHandle == null)
            {
                completionHandle = new EventWaitHandle(false/*intially signalled*/, EventResetMode.ManualReset);
            }
            return completionHandle;
        }

        private void HandBackCompletionHandle(ref EventWaitHandle completionHandle)
        {
            lock (availableCompletionHandles)
            {
                Debug.Assert(Array.IndexOf(availableCompletionHandles.ToArray(), completionHandle) < 0);
                availableCompletionHandles.Enqueue(completionHandle);
                completionHandle = null;
            }
        }

        public interface ITaskContext
        {
            long TaskSequenceNumber { get; }
            void SetSucceeded();
        }

        public class CallbackProxy : ITaskContext
        {
            private long taskSequenceNumber;
            private ThreadState threadState;
            private CompletionObject completionObject;

            internal CallbackProxy(ConcurrentTasks owner, ThreadState threadState, long taskSequenceNumber, CompletionObject completionObject)
            {
                this.threadState = threadState;
                this.taskSequenceNumber = taskSequenceNumber;
                this.completionObject = completionObject;
            }

            public CallbackProxy(CompletionObject completionObject)
            {
                this.completionObject = completionObject;
            }

            private CallbackProxy()
            {
                throw new NotSupportedException();
            }

            public long TaskSequenceNumber
            {
                get
                {
                    return taskSequenceNumber;
                }
            }

            public void SetSucceeded()
            {
                if (completionObject != null)
                {
                    completionObject.SetSucceeded();
                }
            }
        }

        public void Do(string traceTag, bool desireCompletionObject, out CompletionObject completionObject, TaskMethod method, WaitIntervalMethod waitIntervalMethod, int waitInterval)
        {
            Debug.Assert(Thread.CurrentThread.ManagedThreadId == primaryThreadId);

            if ((waitInterval == -1) != (waitIntervalMethod == null))
            {
                throw new ArgumentException(); // both or neither
            }

            completionObject = null;
            if (threadCount > 0)
            {
                // create *and assign* completion object before task has any chance of executing
                EventWaitHandle waitCompleted = null;
                CompletionObject completionObjectLocal = null;
                if (desireCompletionObject)
                {
                    waitCompleted = GetCompletionHandle();
                    completionObjectLocal = completionObject = new ConcurrentCompletionObject(this, waitCompleted);
                }

                long taskSequenceNumber = taskSequenceNumbering.Next();

                lock (this)
                {
                    // Note that task is added to queue, and then we wait for dispatch. This is done for performance,
                    // so that the task is immediately available for the next available thread. It does mean that
                    // (depending on how the program is structured) if a fatal error occurs that will abort the main
                    // processing loop, the task enqueued will still be dispatched after the error is flagged.

                    tasks.Enqueue(
                        delegate(ThreadState threadState)
                        {
                            if (trace != null)
                            {
                                trace.WriteLine("{0:HH:mm:ss+ffff} task {1} initiated", DateTime.Now, traceTag);
                                trace.Flush();
                            }

                            threadState.currentTaskTraceTag = traceTag;
                            Interlocked.Exchange(ref threadState.currentTaskSequenceNumber, taskSequenceNumber);

                            CallbackProxy callbackProxy = new CallbackProxy(this, threadState, taskSequenceNumber, completionObjectLocal);

                            try
                            {
                                method(callbackProxy);
                            }
                            catch (Exception exception)
                            {
                                Interlocked.Increment(ref faultingTasks);

                                if (trace != null)
                                {
                                    trace.WriteLine("{0:HH:mm:ss+ffff} task {1} terminated with exception {2}", DateTime.Now, traceTag, exception);
                                    trace.Flush();
                                }
                            }
                            finally
                            {
                                Interlocked.Exchange(ref threadState.currentTaskSequenceNumber, 0);
                                threadState.currentTaskTraceTag = null;

                                if (waitCompleted != null)
                                {
                                    try
                                    {
                                        waitCompleted.Set(); // it's all over but the shoutin'
                                    }
                                    catch (ObjectDisposedException)
                                    {
                                    }
                                }

                                if (trace != null)
                                {
                                    trace.WriteLine("{0:HH:mm:ss+ffff} task {1} completed", DateTime.Now, traceTag);
                                    trace.Flush();
                                }
                            }
                        });

                    waitQueueEmpty.Reset();
                    if (tasks.Count == maxQueuedTasksCount)
                    {
                        waitQueueNotFull.Reset();
                    }

                    queueLengthHistogram.Update(tasks.Count);
                }

                waitForTask.Release();

                if (waitInterval < 0)
                {
                    waitInterval = LogDelayInterval * 1000;
                }

                mainThreadBlocked.EnterWaitRegion();
                DateTime start = DateTime.UtcNow;
                while (!waitQueueNotFull.WaitOne(waitInterval))
                {
                    if (waitIntervalMethod != null)
                    {
                        waitIntervalMethod();
                    }

                    if ((trace != null) && ((DateTime.UtcNow - start).TotalSeconds >= LogDelayInterval))
                    {
                        trace.WriteLine("ConcurrentTasks.Do() {0} seconds for waitQueueNotFull - still waiting", LogDelayInterval);
                        trace.Flush();
                        start = DateTime.UtcNow;
                    }
                }
                mainThreadBlocked.ExitWaitRegion();
            }
            else
            {
                // create *and assign* completion object before task has any chance of executing
                completionObject = desireCompletionObject ? new NullCompletionObject() : null;

                // low overhead non-concurrent option
                try
                {
                    method(new CallbackProxy(completionObject));
                }
                catch (Exception)
                {
                    faultingTasks++;
                }
            }
        }

        public void Do(string traceTag, TaskMethod method, WaitIntervalMethod waitIntervalMethod, int waitInterval)
        {
            CompletionObject completionObject;
            Do(traceTag, false/*desireCompletionObject*/, out completionObject, method, waitIntervalMethod, waitInterval);
            Debug.Assert(completionObject == null);
        }

        public void Do(string traceTag, TaskMethod method)
        {
            CompletionObject completionObject;
            Do(traceTag, false/*desireCompletionObject*/, out completionObject, method, null, -1/*infinite timeout*/);
            Debug.Assert(completionObject == null);
        }

        // These two methods are hacky: because Do() enqueues a task and then waits for dispatch, if a fatal
        // error occurs in the main processing loop (that calls Do()), it will still dispatch one more task.
        // These methods enqueue an empty task to ensure that the task queue is drained AND that there is a
        // thread imminently available (as soon as the empty task completes).
        // This implementation is inefficient and is not recommended unless tasks are long-running.

        public void WaitQueueNotFull(WaitIntervalMethod waitIntervalMethod, int waitInterval)
        {
            Do("(WaitQueueNotFull)", delegate(ITaskContext taskContext) { }, waitIntervalMethod, waitInterval);
        }

        public void WaitQueueNotFull()
        {
            WaitQueueNotFull(null/*waitIntervalMethod*/, -1/*inifinite wait*/);
        }


        // Task threads

        private static void StaticThreadMain(object o)
        {
            ThreadState threadState = (ThreadState)o;
            threadState.owner.ThreadMain(threadState);
        }

        private void ThreadMain(ThreadState threadState)
        {
            Interlocked.Increment(ref running);
            try
            {
                while (true)
                {
                    threadState.thread.Priority = ThreadPriority.Normal;

                    if (Interlocked.Increment(ref waiting) == threadCount)
                    {
                        waitAllIdle.Set();
                    }
                    waitForTask.WaitOne();
                    Interlocked.Decrement(ref waiting);
                    waitAllIdle.Reset();

                    TaskMethodInternal method;
                    lock (this)
                    {
                        if (tasks.Count == 0)
                        {
                            break; // terminate
                        }

                        method = tasks.Dequeue();
                        waitQueueNotFull.Set();

                        if (tasks.Count == 0)
                        {
                            waitQueueEmpty.Set();
                        }

                        queueLengthHistogram.Update(tasks.Count);
                    }

                    try
                    {
                        method(threadState);
                    }
                    catch (Exception)
                    {
                    }
                }
            }
            finally
            {
                if (Interlocked.Decrement(ref running) == 0)
                {
                    waitTermination.Set(); // will the last one out the door, please...
                }
            }
        }


        // Performance measurement

        private class ConcurrencyHistogram
        {
            private long lastTick;
            private int lastBin;
            private long[] ticksHistogram;

            public ConcurrencyHistogram(int bins)
            {
                ticksHistogram = new long[bins];
                lastTick = DateTime.UtcNow.Ticks;
            }

            public void Update(int currentBin)
            {
                lock (this)
                {
                    long currentTick = DateTime.UtcNow.Ticks;
                    Interlocked.Add(ref ticksHistogram[lastBin], currentTick - lastTick);

                    lastTick = currentTick;
                    lastBin = currentBin;
                }
            }

            public void Report(WriteLineMethod writeLine)
            {
                lock (this)
                {
                    long totalTicks = 0;
                    for (int i = 0; i < ticksHistogram.Length; i++)
                    {
                        totalTicks += ticksHistogram[i];
                    }
                    if (totalTicks > 0)
                    {
                        writeLine("Concurrency histogram:");
                        for (int i = 0; i < ticksHistogram.Length; i++)
                        {
                            writeLine(String.Format("[{0}]: {1}%", i, 100 * ticksHistogram[i] / totalTicks));
                        }
                    }
                }
            }
        }

        private class ConcurrencyBlocked
        {
            private string who;
            private long startTick;
            private long endTick;
            private long blockedTicks;

            private long waitStartTick;

            public ConcurrencyBlocked(string who)
            {
                this.who = who;
                this.startTick = DateTime.UtcNow.Ticks;
            }

            public void Stop()
            {
                endTick = DateTime.UtcNow.Ticks;
            }

            public void EnterWaitRegion()
            {
                waitStartTick = DateTime.UtcNow.Ticks;
            }

            public void ExitWaitRegion()
            {
                Interlocked.Add(ref blockedTicks, DateTime.UtcNow.Ticks - waitStartTick);
            }

            public void Report(WriteLineMethod writeLine)
            {
                long totalTicks = endTick - startTick;
                long unblockedTicks = totalTicks - blockedTicks;

                if (totalTicks > 0)
                {
                    writeLine(String.Format("{0} was blocked {1}% of time", who, 100 * blockedTicks / totalTicks));
                }
            }
        }
    }
}
