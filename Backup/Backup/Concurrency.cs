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
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace Backup
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

            internal Line(string line)
            {
                this.line = line;
            }

            internal Line(string line, ConsoleColor color)
            {
                this.line = line;
                this.color = color;
            }
        }

        public class ThreadMessageLog : IDisposable
        {
            private long sequenceNumber;
            private List<Line> lines = new List<Line>();
            private ConcurrentMessageLog owner;
            private int threadId = Thread.CurrentThread.ManagedThreadId;

            public ThreadMessageLog(ConcurrentMessageLog owner, long sequenceNumber)
            {
                this.sequenceNumber = sequenceNumber;
                this.owner = owner;
            }

            public void WriteLine()
            {
                Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
                lines.Add(new Line(String.Empty));
            }

            public void WriteLine(string line)
            {
                Debug.Assert(threadId == Thread.CurrentThread.ManagedThreadId);
                lines.Add(new Line(line));
            }

            public void WriteLine(string format, params object[] arg)
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

            public void Dispose()
            {
                owner.Incorporate(lines, sequenceNumber);
                lines = null;
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
        private ThreadMessageLog GetNewMessageLog()
        {
            if (sequenceNumbering != null) // actually forbid this case for now
            {
                throw new InvalidOperationException();
            }
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

            lock (this)
            {
                Record record = new Record(sequenceNumber, lines);

                int index;
                if (sequenceNumbering != null)
                {
                    // "records" is essentially a priority queue. It is anticipated that the
                    // list will be short. If the chain of out-of-order messages gets very
                    // large the vector manipulations may become inefficient and should be
                    // replaced with a tree-based implementation.

                    CompareRecords comparer = new CompareRecords();
                    index = records.BinarySearch(record, comparer);
                    if (index >= 0)
                    {
                        // scan to end of run of multiple records of same value in order to
                        // preserve actual order of insertion in non-sequenced use case
                        while ((index + 1 < records.Count) && (comparer.Compare(record, records[index + 1]) == 0))
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
                    lastWidth = Console.BufferWidth; // Int32 interlocked not needed
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

                    lastSequenceNumber = record.sequenceNumber;
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
                Console.WriteLine(line.line);
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
            Flush(true/*permitOutOfSequence*/, null/*prepareConsole*/);
        }

        public int BufferWidth
        {
            get
            {
                return lastWidth; // Int32 interlocked not needed
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

        private readonly List<EventWaitHandle> availableCompletionHandles = new List<EventWaitHandle>();

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
        // messagesLog and trace are both optional (can be null);
        public ConcurrentTasks(int threadCount, ConcurrentMessageLog messagesLog, TextWriter trace)
        {
            this.primaryThreadId = Thread.CurrentThread.ManagedThreadId;
            this.messagesLog = messagesLog;
            this.trace = trace;

            if (threadCount < 0)
            {
                throw new ArgumentException();
            }
            this.threadCount = threadCount;
            this.maxQueuedTasksCount = threadCount + 1;
            if (threadCount > 0)
            {
                tasks = new Queue<TaskMethodInternal>(maxQueuedTasksCount);

                waitForTask = new Semaphore(0, maxQueuedTasksCount);
                waitQueueNotFull = new EventWaitHandle(false/*intially signalled*/, EventResetMode.AutoReset);
                waitTermination = new EventWaitHandle(false/*intially signalled*/, EventResetMode.ManualReset);
                waitQueueEmpty = new EventWaitHandle(true/*intially signalled*/, EventResetMode.ManualReset);
                waitAllIdle = new EventWaitHandle(false/*intially signalled*/, EventResetMode.ManualReset);
                threads = new ThreadState[threadCount];

                queueLengthHistogram = new ConcurrencyHistogram(maxQueuedTasksCount + 1/*needed for waiting on full queue*/);
                mainThreadBlocked = new ConcurrencyBlocked("Main thread");

                for (int i = 0; i < threadCount; i++)
                {
                    threads[i] = new ThreadState(this, new Thread(StaticThreadMain));
                    threads[i].thread.Start(threads[i]);
                }

                waitAllIdle.WaitOne(); // wait for spin-up to complete (otherwise a too-soon Dispose() will hang)
            }
        }

        public ConcurrentTasks(ConcurrentMessageLog messagesLog, TextWriter trace)
            : this(0, messagesLog, trace)
        {
        }

        private ConcurrentTasks()
        {
            throw new NotSupportedException();
        }

        public int MaxTasksInProgress { get { return threadCount/*potentially running*/ + maxQueuedTasksCount /*potentially waiting*/; } }

        public void Drain(WaitIntervalMethod waitIntervalMethod, int waitInterval)
        {
            Debug.Assert(Thread.CurrentThread.ManagedThreadId == primaryThreadId);

            if ((waitInterval == -1) != (waitIntervalMethod == null))
            {
                throw new ArgumentException(); // both or neither
            }

            if (threadCount > 0)
            {
                mainThreadBlocked.EnterWaitRegion();

                // must drain queue first, otherwise waitAllIdle is invalid because it may jitter
                while (!waitQueueEmpty.WaitOne(waitInterval))
                {
                    waitIntervalMethod();
                }

                while (!waitAllIdle.WaitOne(waitInterval))
                {
                    waitIntervalMethod();
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

            if (threadCount > 0)
            {
                mainThreadBlocked.EnterWaitRegion();

                // wait for all real tasks to dispatch
                waitQueueEmpty.WaitOne();
                Debug.Assert(tasks.Count == 0);
                Debug.Assert(running == threadCount);

                // with queue empty, release all threads and they will terminate
                waitForTask.Release(threadCount);
                // wait for last thead to exit
                waitTermination.WaitOne();

                mainThreadBlocked.ExitWaitRegion();
                mainThreadBlocked.Stop();

                waitForTask.Close();
                waitQueueNotFull.Close();
                foreach (EventWaitHandle completionHandle in availableCompletionHandles)
                {
                    completionHandle.Close();
                }
                availableCompletionHandles.Clear();

                // write concurrency statistics
                queueLengthHistogram.Report(WriteLineMessage);
                mainThreadBlocked.Report(WriteLineMessage);
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
            public abstract void Wait();
            public abstract void Dispose();
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
                    owner.HandBackCompletionHandle(waitCompleted);
                }
                else
                {
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
            EventWaitHandle completionHandle;
            if (availableCompletionHandles.Count > 0)
            {
                completionHandle = availableCompletionHandles[availableCompletionHandles.Count - 1];
                availableCompletionHandles.RemoveAt(availableCompletionHandles.Count - 1);
                completionHandle.Reset(); // ensure initially unsignalled
            }
            else
            {
                completionHandle = new EventWaitHandle(false/*intially signalled*/, EventResetMode.ManualReset);
            }
            return completionHandle;
        }

        private void HandBackCompletionHandle(EventWaitHandle completionHandle)
        {
            Debug.Assert(availableCompletionHandles.IndexOf(completionHandle) < 0);
            availableCompletionHandles.Add(completionHandle);
        }

        public enum Status
        {
            Unspecified,

            Completed,

            ComputeBound,
            IOBound,
        }

        public interface ITaskContext
        {
        }

        public class CallbackProxy : ITaskContext
        {
            private ThreadState threadState;

            internal CallbackProxy(ConcurrentTasks owner, ThreadState threadState)
            {
                this.threadState = threadState;
            }

            public CallbackProxy()
            {
            }
        }

        public CompletionObject Do(string traceTag, TaskMethod method, WaitIntervalMethod waitIntervalMethod, int waitInterval, bool desireCompletionObject)
        {
            Debug.Assert(Thread.CurrentThread.ManagedThreadId == primaryThreadId);

            if ((waitInterval == -1) != (waitIntervalMethod == null))
            {
                throw new ArgumentException(); // both or neither
            }

            CompletionObject completionObject = null;

            if (threadCount > 0)
            {
                EventWaitHandle waitCompleted = null;
                if (desireCompletionObject)
                {
                    waitCompleted = GetCompletionHandle();
                    completionObject = new ConcurrentCompletionObject(this, waitCompleted);
                }

                long taskSequenceNumber = taskSequenceNumbering.Next();

                bool queueFull;
                lock (tasks)
                {
                    tasks.Enqueue(
                        delegate(ThreadState threadState)
                        {
                            if (trace != null)
                            {
                                trace.WriteLine("{0:HH:mm:ss+ffff} task {1} initiated", DateTime.Now, traceTag);
                            }

                            threadState.currentTaskTraceTag = traceTag;
                            Interlocked.Exchange(ref threadState.currentTaskSequenceNumber, taskSequenceNumber);

                            CallbackProxy callbackProxy = new CallbackProxy(this, threadState);

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
                                }
                            }
                        });
                    queueLengthHistogram.Update(tasks.Count);
                    queueFull = tasks.Count == maxQueuedTasksCount;
                    waitQueueEmpty.Reset();
                }
                waitForTask.Release();
                if (queueFull)
                {
                    mainThreadBlocked.EnterWaitRegion();
                    while (!waitQueueNotFull.WaitOne(waitInterval))
                    {
                        waitIntervalMethod();
                    }
                    mainThreadBlocked.ExitWaitRegion();
                }
            }
            else
            {
                // low overhead non-concurrent option
                try
                {
                    method(new CallbackProxy());
                }
                catch (Exception)
                {
                    faultingTasks++;
                }
                completionObject = desireCompletionObject ? new NullCompletionObject() : null;
            }

            return completionObject;
        }

        public CompletionObject Do(string traceTag, TaskMethod method, bool desireCompletionObject)
        {
            return Do(traceTag, method, null, -1/*infinite timeout*/, desireCompletionObject);
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
                    lock (tasks)
                    {
                        if (tasks.Count == 0)
                        {
                            break; // terminate
                        }
                        if (tasks.Count == maxQueuedTasksCount)
                        {
                            waitQueueNotFull.Set();
                        }
                        method = tasks.Dequeue();
                        queueLengthHistogram.Update(tasks.Count);
                        if (tasks.Count == 0)
                        {
                            waitQueueEmpty.Set();
                        }
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
                lastTick = DateTime.Now.Ticks;
            }

            public void Update(int currentBin)
            {
                lock (this)
                {
                    long currentTick = DateTime.Now.Ticks;
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
                this.startTick = DateTime.Now.Ticks;
            }

            public void Stop()
            {
                endTick = DateTime.Now.Ticks;
            }

            public void EnterWaitRegion()
            {
                waitStartTick = DateTime.Now.Ticks;
            }

            public void ExitWaitRegion()
            {
                Interlocked.Add(ref blockedTicks, DateTime.Now.Ticks - waitStartTick);
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
