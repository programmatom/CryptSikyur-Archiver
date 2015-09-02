/*
 *  Copyright © 2014 Thomas R. Lawrence
 * 
 *  This file is part of FileUtilityTester
 *
 *  FileUtilityTester is free software: you can redistribute it and/or modify
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
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml;
using System.Xml.XPath;
using Microsoft.Win32.SafeHandles;

using Concurrent;
using HexUtil;
using ProtectedData;

namespace FileUtilityTester
{
    class Program
    {
        private const string WorkspaceRootCollection = "test-workspace";

        private const string CodeCoverageReports = "test-coverage";
        // OpenCoverage reports can be processed after run with a script like this:
        //   cd %TEMP%\test-coverage
        //   "C:\Program Files (x86)\ReportGenerator_2.1.8.0\bin\ReportGenerator.exe" -reports:result*.xml -targetdir:.
        //   start index.html

        private static readonly RandomNumberGenerator random = RNGCryptoServiceProvider.Create(); // threadsafe

        private static void Throw(Exception exception)
        {
            if (Debugger.IsAttached)
            {
                Debugger.Break();
            }
            throw exception;
        }

        private class TaskHistory
        {
            public const int DurationHistory = 5;
            public const int FailuresHistory = 5;

            private Dictionary<string, Record> records = new Dictionary<string, Record>();

            public struct Record
            {
                public string identifier;
                public long[] durations;
                public uint failures;
                public bool visited;

                public Record(string identifier, long[] durations, uint failures, bool visited)
                {
                    this.identifier = identifier;
                    this.durations = durations;
                    this.failures = failures;
                    this.visited = visited;
                }
            }

            public TaskHistory()
            {
            }

            public TaskHistory(string path)
            {
                XmlDocument xml = new XmlDocument();
                xml.Load(path);
                foreach (XPathNavigator task in xml.CreateNavigator().Select("/history/tasks/task"))
                {
                    string identifier = task.SelectSingleNode("id").Value;
                    List<long> durations = new List<long>();
                    foreach (XPathNavigator duration in task.Select("durations/duration"))
                    {
                        durations.Add(duration.ValueAsLong);
                    }
                    uint failures = (uint)task.SelectSingleNode("failures").ValueAsInt;

                    records.Add(identifier, new Record(identifier, durations.ToArray(), failures, false/*visited*/));
                }
            }

            public void Save(string path)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                try
                {
                    File.Copy(Path.ChangeExtension(path, ".bak1"), Path.ChangeExtension(path, ".bak2"), true/*overwrite*/);
                }
                catch
                {
                }
                try
                {
                    File.Copy(path, Path.ChangeExtension(path, ".bak1"), true/*overwrite*/);
                }
                catch
                {
                }

                XmlWriterSettings settings = new XmlWriterSettings();
                settings.Indent = true;
                settings.IndentChars = new String((char)32, 4);
                using (XmlWriter writer = XmlWriter.Create(path, settings))
                {
                    writer.WriteStartElement("history");

                    writer.WriteStartElement("tasks");

                    foreach (KeyValuePair<string, Record> item in records)
                    {
                        if (item.Value.visited)
                        {
                            writer.WriteStartElement("task");

                            writer.WriteStartElement("id");
                            writer.WriteString(item.Value.identifier);
                            writer.WriteEndElement(); // id

                            writer.WriteStartElement("durations");
                            foreach (long duration in item.Value.durations)
                            {
                                writer.WriteStartElement("duration");
                                writer.WriteValue(duration);
                                writer.WriteEndElement(); // duration
                            }
                            writer.WriteEndElement(); // durations

                            writer.WriteStartElement("failures");
                            writer.WriteValue((int)item.Value.failures);
                            writer.WriteEndElement(); // failures

                            writer.WriteEndElement(); // task
                        }
                    }

                    writer.WriteEndElement(); // tasks

                    writer.WriteEndElement(); // history
                }
            }

            public int Count
            {
                get
                {
                    lock (this)
                    {
                        return records.Count;
                    }
                }
            }

            private static string FormatIdentifier(string scriptName, int moduleNumber, string moduleName)
            {
                return String.Format("{0}:{1}:{2}", scriptName, moduleNumber, moduleName);
            }

            public void UpdateHistory(string scriptName, int moduleNumber, string moduleName, long? duration, bool failed)
            {
                UpdateHistory(FormatIdentifier(scriptName, moduleNumber, moduleName), duration, failed);
            }

            private void UpdateHistory(string identifier, long? duration, bool failed)
            {
                lock (this)
                {
                    long[] durations;
                    uint failures;
                    Record record;
                    if (records.TryGetValue(identifier, out record))
                    {
                        durations = record.durations;
                        failures = record.failures;
                    }
                    else
                    {
                        durations = new long[0];
                        failures = (1 << FailuresHistory) - 1; // treat new tests as often failed so they are run earlier
                    }

                    if (duration.HasValue)
                    {
                        Array.Resize(ref durations, durations.Length + 1);
                        durations[durations.Length - 1] = duration.Value;
                        if (durations.Length > DurationHistory)
                        {
                            Array.Copy(durations, durations.Length - DurationHistory, durations, 0, DurationHistory);
                            Array.Resize(ref durations, DurationHistory);
                        }
                    }

                    failures = (((failures << 1) | (uint)(failed ? 1 : 0)) & (uint)((1 << FailuresHistory) - 1));

                    records[identifier] = new Record(identifier, durations, failures, true/*visited*/);
                }
            }

            public bool QueryHistory(string scriptName, int moduleNumber, string moduleName, out Record record)
            {
                return QueryHistory(FormatIdentifier(scriptName, moduleNumber, moduleName), out record);
            }

            private bool QueryHistory(string identifier, out Record record)
            {
                lock (this)
                {
                    return records.TryGetValue(identifier, out record);
                }
            }

            public void VisitHistory(string scriptName, int moduleNumber, string moduleName)
            {
                VisitHistory(FormatIdentifier(scriptName, moduleNumber, moduleName));
            }

            private void VisitHistory(string identifier)
            {
                lock (this)
                {
                    Record record;
                    if (records.TryGetValue(identifier, out record))
                    {
                        record.visited = true;
                        records[identifier] = record;
                    }
                }
            }
        }

        private class TaskQueue
        {
            private bool[] resourcesInUse = new bool[0];
            private readonly Dictionary<string, int> resourcesNameToIndex = new Dictionary<string, int>();

            private readonly List<Task> queue = new List<Task>();
            private bool adding = true;
            private bool fatal;

            public class Task
            {
                public readonly string scriptName;
                public readonly int moduleNumber;
                public readonly string moduleName;

                public readonly TaskMethod method;
                public readonly int[] resources;
                public readonly string[] resourcesNames;
                public readonly int sequence;
                public long? messageSequenceNumber;

                public long averageDuration;
                public int recentFailures;

                private static int sequenceGenerator;

                public class TaskContext
                {
                    private readonly TextWriter consoleWriter;
                    private bool fatal;
                    public Status status;

                    public TextWriter ConsoleWriter { get { return consoleWriter; } }
                    public bool Fatal { get { return fatal; } }

                    public TaskContext(TextWriter consoleWriter, Status status)
                    {
                        this.consoleWriter = consoleWriter;
                        this.status = status;
                    }

                    public void SetFatal()
                    {
                        fatal = true;
                    }
                }

                public delegate void TaskMethod(TaskContext taskContext);

                public Task(string scriptName, int moduleNumber, string moduleName, TaskMethod method, string[] resourcesNames)
                {
                    this.scriptName = scriptName;
                    this.moduleNumber = moduleNumber;
                    this.moduleName = moduleName;

                    this.method = method;
                    this.sequence = Interlocked.Increment(ref sequenceGenerator);

                    this.resourcesNames = (string[])resourcesNames.Clone();
                    Array.Sort(resourcesNames);
                    for (int i = 1; i < resourcesNames.Length; i++)
                    {
                        if (String.Equals(resourcesNames[i - 1], resourcesNames[i]))
                        {
                            Throw(new ArgumentException());
                        }
                    }
                    this.resources = new int[resourcesNames.Length];
                }

                public class CompareTasks : IComparer<Task>
                {
                    public int Compare(Task l, Task r)
                    {
                        int c = 0;

                        if (c == 0)
                        {
                            c = -l.recentFailures.CompareTo(r.recentFailures);
                        }

                        if (c == 0)
                        {
                            c = -l.resources.Length.CompareTo(r.resources.Length);
                        }
                        for (int i = 0; (c == 0) && (i < l.resources.Length); i++)
                        {
                            c = l.resources[i].CompareTo(r.resources[i]);
                        }

                        if (c == 0)
                        {
                            c = -l.averageDuration.CompareTo(r.averageDuration);
                        }

                        if (c == 0)
                        {
                            c = l.sequence.CompareTo(r.sequence);
                        }

                        return c;
                    }
                }

                public class CompareTasksScriptOrdering : IComparer<Task>
                {
                    public int Compare(Task l, Task r)
                    {
                        return l.sequence.CompareTo(r.sequence);
                    }
                }
            }

            public void Add(IEnumerable<Task> tasks)
            {
                if (!adding)
                {
                    Throw(new InvalidOperationException());
                }

                queue.AddRange(tasks);

                foreach (Task task in tasks)
                {
                    for (int i = 0; i < task.resources.Length; i++)
                    {
                        int resource;
                        if (!resourcesNameToIndex.TryGetValue(task.resourcesNames[i], out resource))
                        {
                            resource = resourcesInUse.Length;
                            Array.Resize(ref resourcesInUse, resourcesInUse.Length + 1);

                            resourcesNameToIndex.Add(task.resourcesNames[i], resource);
                        }
                        task.resources[i] = resource;
                    }
                }
            }

            public void Prepare(bool forceScriptOrder, Concurrent.ConcurrentMessageLog messagesLog, TaskHistory taskHistory)
            {
                if (!adding)
                {
                    Throw(new InvalidOperationException());
                }

                if (taskHistory != null)
                {
                    foreach (Task task in queue)
                    {
                        TaskHistory.Record record;
                        if (taskHistory.QueryHistory(task.scriptName, task.moduleNumber, task.moduleName, out record))
                        {
                            task.averageDuration = 0;
                            foreach (long duration in record.durations)
                            {
                                task.averageDuration += duration;
                            }
                            task.averageDuration /= Math.Max(record.durations.Length, 1);

                            task.recentFailures = 0;
                            uint f = record.failures;
                            for (int i = 0; i < TaskHistory.FailuresHistory; i++)
                            {
                                if ((f & 1) != 0)
                                {
                                    task.recentFailures++;
                                }
                                f = f >> 1;
                            }
                        }
                    }
                }

                queue.Sort(new Task.CompareTasksScriptOrdering());

                // force output in script order
                if (messagesLog != null)
                {
                    foreach (Task task in queue)
                    {
                        task.messageSequenceNumber = messagesLog.GetSequenceNumber();
                    }
                }

                if (!forceScriptOrder)
                {
                    queue.Sort(new Task.CompareTasks());
                }
                // else force execution in script order - to the degree possible

                adding = false;
            }

            // must call FinalizeTask() on all objects returned from this method
            private Task GetNextTask() // threadsafe
            {
                if (adding)
                {
                    Throw(new InvalidOperationException());
                }

                Task task = null;

                lock (this)
                {
                    for (int i = 0; i < queue.Count; i++)
                    {
                        Task candidate = queue[i];

                        bool resourcesAvailable = true;
                        for (int j = 0; j < candidate.resources.Length; j++)
                        {
                            resourcesAvailable = resourcesAvailable && !resourcesInUse[candidate.resources[j]];
                        }
                        if (resourcesAvailable)
                        {
                            task = candidate;
                            queue.RemoveAt(i);

                            for (int j = 0; j < candidate.resources.Length; j++)
                            {
                                Debug.Assert(!resourcesInUse[task.resources[j]]);
                                resourcesInUse[candidate.resources[j]] = true;
                            }

                            break;
                        }
                    }
                }

                return task;
            }

            private void FinalizeTask(Task task) // threadsafe
            {
                if (adding)
                {
                    Throw(new InvalidOperationException());
                }

                lock (this)
                {
                    for (int j = 0; j < task.resources.Length; j++)
                    {
                        Debug.Assert(resourcesInUse[task.resources[j]]);
                        resourcesInUse[task.resources[j]] = false;
                    }
                }
            }

            public int Count // threadsafe
            {
                get
                {
                    lock (this)
                    {
                        return queue.Count;
                    }
                }
            }

            public bool Empty // threadsafe
            {
                get
                {
                    if (adding)
                    {
                        Throw(new InvalidOperationException());
                    }

                    lock (this)
                    {
                        return queue.Count == 0;
                    }
                }
            }

            public bool Fatal // threadsafe
            {
                get
                {
                    lock (this)
                    {
                        return fatal;
                    }
                }
            }

            public void SetFatal() // threadsafe
            {
                lock (this)
                {
                    fatal = true;
                }
            }

            public class Status
            {
                private string scriptName;
                private string moduleName;
                private int moduleNumber;
                private DateTime startTime;

                public void SetStatus(string scriptName, string moduleName, int moduleNumber, DateTime startTime)
                {
                    lock (this)
                    {
                        this.scriptName = scriptName;
                        this.moduleName = moduleName;
                        this.moduleNumber = moduleNumber;
                        this.startTime = startTime;
                    }
                }

                public void GetStatus(out string scriptName, out string moduleName, out int moduleNumber, out DateTime startTime)
                {
                    lock (this)
                    {
                        scriptName = this.scriptName;
                        moduleName = this.moduleName;
                        moduleNumber = this.moduleNumber;
                        startTime = this.startTime;
                    }
                }
            }

            public void ThreadMain(ConcurrentMessageLog messageLog, Status status)
            {
                while (!Empty && !Fatal)
                {
                    Task task = null;
                    try
                    {
                        task = GetNextTask();
                        if (task != null)
                        {
                            using (ConcurrentMessageLog.ThreadMessageLog messages = task.messageSequenceNumber.HasValue ? messageLog.GetNewMessageLog(task.messageSequenceNumber.Value) : messageLog.GetNewMessageLog())
                            {
                                Task.TaskContext taskContext = new Task.TaskContext(messages, status);
                                task.method(taskContext);
                                if (taskContext.Fatal)
                                {
                                    SetFatal();
                                }
                            }
                        }
                        else
                        {
                            Thread.Sleep(1000);
                        }
                    }
                    finally
                    {
                        if (task != null)
                        {
                            FinalizeTask(task);
                        }
                    }
                }
            }
        }

        private static class FileCompressionHelper
        {
            [Flags]
            private enum EFileAttributes : uint
            {
                Readonly = 0x00000001,
                Hidden = 0x00000002,
                System = 0x00000004,
                Directory = 0x00000010,
                Archive = 0x00000020,
                Device = 0x00000040,
                Normal = 0x00000080,
                Temporary = 0x00000100,
                SparseFile = 0x00000200,
                ReparsePoint = 0x00000400,
                Compressed = 0x00000800,
                Offline = 0x00001000,
                NotContentIndexed = 0x00002000,
                Encrypted = 0x00004000,
                Write_Through = 0x80000000,
                Overlapped = 0x40000000,
                NoBuffering = 0x20000000,
                RandomAccess = 0x10000000,
                SequentialScan = 0x08000000,
                DeleteOnClose = 0x04000000,
                BackupSemantics = 0x02000000,
                PosixSemantics = 0x01000000,
                OpenReparsePoint = 0x00200000,
                OpenNoRecall = 0x00100000,
                FirstPipeInstance = 0x00080000
            }
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern IntPtr CreateFile(
                 [MarshalAs(UnmanagedType.LPTStr)] string filename,
                 [MarshalAs(UnmanagedType.U4)] FileAccess access,
                 [MarshalAs(UnmanagedType.U4)] FileShare share,
                 IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
                 [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
                 [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
                 IntPtr templateFile);

            [DllImport("Kernel32.dll", SetLastError = true)]
            public static extern bool DeviceIoControl(
                SafeFileHandle hDevice,
                [MarshalAs(UnmanagedType.U4)] int IoControlCode,
                byte[] InBuffer,
                [MarshalAs(UnmanagedType.U4)] int nInBufferSize,
                byte[] OutBuffer,
                [MarshalAs(UnmanagedType.U4)] int nOutBufferSize,
                [MarshalAs(UnmanagedType.U4)] out int pBytesReturned,
                IntPtr Overlapped);
            private const int FSCTL_SET_COMPRESSION = 0x0009C040;
            private const short COMPRESSION_FORMAT_DEFAULT = 1;
            private const short COMPRESSION_FORMAT_NONE = 0;

            public static bool IsCompressed(string path)
            {
                if (File.Exists(path))
                {
                    return (File.GetAttributes(path) & FileAttributes.Compressed) != 0;
                }
                else if (Directory.Exists(path))
                {
                    return (File.GetAttributes(path) & FileAttributes.Compressed) != 0;
                }
                else
                {
                    throw new FileNotFoundException("File not found", path);
                }
            }

            public static void SetCompressed(string path, bool compress)
            {
                bool directory;
                if (File.Exists(path))
                {
                    directory = false;
                }
                else if (Directory.Exists(path))
                {
                    directory = true;
                }
                else
                {
                    throw new FileNotFoundException("File or directory not found", path);
                }

                using (SafeFileHandle file = new SafeFileHandle(CreateFile(path, FileAccess.ReadWrite, FileShare.ReadWrite, IntPtr.Zero, FileMode.Open, directory ? (FileAttributes)EFileAttributes.BackupSemantics : (FileAttributes)0, IntPtr.Zero), true/*ownsHandle*/))
                {
                    if (file.IsInvalid)
                    {
                        Marshal.ThrowExceptionForHR(Marshal.GetLastWin32Error());
                    }
                    int lpBytesReturned = 0;
                    byte[] lpInBuffer = new byte[2];
                    lpInBuffer[0] = (byte)(compress ? COMPRESSION_FORMAT_DEFAULT : COMPRESSION_FORMAT_NONE);
                    if (!DeviceIoControl(file, FSCTL_SET_COMPRESSION, lpInBuffer, sizeof(short), null, 0, out lpBytesReturned, IntPtr.Zero))
                    {
                        Marshal.ThrowExceptionForHR(Marshal.GetLastWin32Error());
                    }
                }
            }
        }

        private static object EvalExpression(string expression, Dictionary<string, object> variables)
        {
            expression = expression.Trim();
            if (expression[0] == '"')
            {
                return expression.Substring(1, expression.IndexOf('"', 1) - 1);
            }
            else if (Char.IsLetter(expression[0]))
            {
                return variables[expression];
            }
            else
            {
                return Int64.Parse(expression);
            }
        }

        private class SharedContext
        {
            private List<Substitution> substitutions = new List<Substitution>();

            private class Substitution
            {
                public readonly UniqueLocation Location;
                public readonly string Name;
                public string Value;

                public Substitution(UniqueLocation location, string name)
                {
                    this.Location = location;
                    this.Name = name;
                }

                public override string ToString()
                {
                    return String.Format("{{{0} ({1}) --> {2}}}", Name, Location, Value != null ? String.Concat("\"", Value, "\"") : "not set");
                }
            }

            private class UniqueLocation
            {
                public readonly string Script;
                public readonly int LineNumber;
                public readonly string VariableName;

                public UniqueLocation(string script, int lineNumber, string variableName)
                {
                    this.Script = script;
                    this.LineNumber = lineNumber;
                    this.VariableName = variableName;
                }

                public override bool Equals(object obj)
                {
                    UniqueLocation other = obj as UniqueLocation;
                    if (other == null)
                    {
                        return false;
                    }

                    return String.Equals(this.Script, other.Script)
                        && (this.LineNumber == other.LineNumber)
                        && String.Equals(this.VariableName, other.VariableName);
                }

#if false
                public override int GetHashCode()
                {
                    return unchecked(Script.GetHashCode() ^ LineNumber.GetHashCode() ^ VariableName.GetHashCode());
                }
#endif

                public override string ToString()
                {
                    return string.Format("[{0}:{1}:{2}]", Script, LineNumber, VariableName);
                }
            }

            public SharedContext()
            {
            }

            public void EnsureOutputValueSubstitution(string script, int lineNumber, string variableName)
            {
                lock (this)
                {
                    UniqueLocation location = new UniqueLocation(script, lineNumber, variableName);
                    int i = substitutions.FindIndex(delegate(Substitution substitution) { return location.Equals(substitution.Location); });
                    if (i >= 0)
                    {
                        return;
                    }

                    int extra = 0;
                    while (true)
                    {
                        string name = String.Format(extra == 0 ? "{0}:{1}" : "{0}-{2}:{1}", Path.GetFileNameWithoutExtension(script), variableName, extra);
                        if (substitutions.FindIndex(delegate(Substitution substitution) { return String.Equals(name, substitution.Name); }) < 0)
                        {
                            substitutions.Add(new Substitution(location, name));
                            return;
                        }
                        extra++;
                    }
                }
            }

            public void SetOutputValueSubstitution(string script, int lineNumber, string variableName, string value)
            {
                lock (this)
                {
                    UniqueLocation location = new UniqueLocation(script, lineNumber, variableName);
                    int i = substitutions.FindIndex(delegate(Substitution substitution) { return location.Equals(substitution.Location); });
                    if (i < 0)
                    {
                        Throw(new ApplicationException());
                    }
                    substitutions[i].Value = value;
                }
            }

#if false
            public string QueryOutputValueSubstitution(string script, int lineNumber, string variableName)
            {
                lock (this)
                {
                    UniqueLocation location = new UniqueLocation(script, lineNumber, variableName);
                    int i = substitutions.FindIndex(delegate(Substitution substitution) { return location.Equals(substitution.Location); });
                    if (i < 0)
                    {
                        Throw(new ApplicationException());
                    }
                    return substitutions[i].Value;
                }
            }
#endif

            public string ReplaceOutputValueSubstitutions(string arguments)
            {
                foreach (Substitution substitution in substitutions)
                {
                    if (substitution.Value != null)
                    {
                        arguments = arguments.Replace(substitution.Value, String.Concat("%", substitution.Name, "%"));
                    }
                }
                return arguments;
            }
        }

        private class Context
        {
            readonly public int scriptNumber;
            readonly public TestResultMatrix resultMatrix;

            public readonly int moduleNumber;
            public readonly string moduleName;

            public int testNumber = 0;
            public string testName = null;
            public bool testFailed = false;

            public readonly DateTime resetNow = new DateTime(2010, 1, 1);
            public DateTime now;

            public const string InitialDefaultDateFormat = "s"; // sortable datetime format: yyyy-MM-ddTHH:mm:ss
            public string defaultDateFormat = InitialDefaultDateFormat;
            public int? commandTimeoutSeconds = null;
            public bool failPause;

            public Dictionary<string, KeyValuePair<string, string>> commands = new Dictionary<string, KeyValuePair<string, string>>();
            public Dictionary<string, bool> opencover = new Dictionary<string, bool>();
            public Dictionary<string, object> variables = new Dictionary<string, object>();
            public HashDispenser hashes = new HashDispenser();
            public Dictionary<string, Stream> openFiles = new Dictionary<string, Stream>();
            public Dictionary<string, bool> resources = new Dictionary<string, bool>();

            public readonly WorkspaceDispenser workspaceDispenser;
            public Workspace workspace;

            private Context()
            {
                now = resetNow;
                variables["DATE"] = now.ToString(Context.InitialDefaultDateFormat);
            }

            public Context(WorkspaceDispenser workspaceDispenser)
                : this()
            {
                this.workspaceDispenser = workspaceDispenser;
            }

            public Context(int scriptNumber, TestResultMatrix resultMatrix, WorkspaceDispenser workspaceDispenser)
                : this(workspaceDispenser)
            {
                this.scriptNumber = scriptNumber;
                this.resultMatrix = resultMatrix;
            }

            public Context(Context original, int moduleNumber, string moduleName)
                : this(original.scriptNumber, original.resultMatrix, original.workspaceDispenser)
            {
                this.moduleNumber = moduleNumber;
                this.moduleName = moduleName;

                //this.testNumber = 0; -- redundant
                //this.testName = null; -- redundant
                //this.testFailed = false; -- redundant

                this.resetNow = original.resetNow;
                this.now = this.resetNow;
                this.variables["DATE"] = this.now.ToString(Context.InitialDefaultDateFormat);

                this.defaultDateFormat = original.defaultDateFormat;
                this.commandTimeoutSeconds = original.commandTimeoutSeconds;
                this.failPause = original.failPause;

                this.commands = new Dictionary<string, KeyValuePair<string, string>>(original.commands);
                this.opencover = new Dictionary<string, bool>(original.opencover);
                this.variables = new Dictionary<string, object>(original.variables);
                //this.hashes = new HashDispenser(); -- redundant
                //this.openFiles = new Dictionary<string, Stream>(); -- redundant
                this.resources = new Dictionary<string, bool>(original.resources);
            }
        }

        [Flags]
        private enum Mode
        {
            Unrestricted = 0x01,

            PrepareTasks = 0x02,

            Module = 0x04,
            Callback = 0x08,

            GlobalModes = Unrestricted | PrepareTasks,
            SequentialModes = Unrestricted | PrepareTasks | Module,
        }

        private static List<TaskQueue.Task> Eval(LineReader scriptReader, int initialLineNumber, string scriptName, Context contextBase, Mode mode, TextWriter consoleWriter, TaskHistory taskHistory, SharedContext sharedContext)
        {
            List<TaskQueue.Task> tasks = null;

            // Stateful commands before the first module have a direct effect on script-global state.
            // For each module declaration, contextBase is cloned and subsequent changes therefore private to that module.
            Context context = contextBase;

            int lastExitCode = 0;
            string lastOutput = null;

            string skipToModule = null;

            int moduleNumber = 0;
            string moduleName = null;

            DateTime? startTime = null;

            int lineNumber = initialLineNumber;
            try
            {
                if (mode == Mode.PrepareTasks)
                {
                    tasks = new List<TaskQueue.Task>();
                    context.testFailed = true;
                }

                bool firstTime = mode == Mode.Module; // part of a HACK to do "reset" as the first command of a module
                if (firstTime)
                {
                    lineNumber--;
                }

                string line;
                while ((line = firstTime ? "\0module"/*HACK*/ : scriptReader.ReadLine()) != null)
                {
                    firstTime = false; // part of a HACK to do "reset" as the first command of a module

                    bool currentFailed = false;

                    lineNumber++;

                    if (line.StartsWith("#"))
                    {
                        continue;
                    }

                    line = line.TrimEnd();
                    if (String.IsNullOrEmpty(line))
                    {
                        continue;
                    }

                    string command;
                    int space = line.IndexOf(' ');
                    if (space >= 0)
                    {
                        command = line.Substring(0, space);
                    }
                    else
                    {
                        command = line;
                    }
                    if (space < 0)
                    {
                        space = line.Length;
                    }

                    string[] args = ParseArguments(line.Substring(space));
                    switch (command)
                    {
                        default:
                            Throw(new ApplicationException(String.Format("Invalid command \"{0}\" on line {1}", command, lineNumber)));
                            break;

                        case "command":
                            if ((mode & Mode.SequentialModes) == 0)
                            {
                                Throw(new ApplicationException());
                            }
                            if (args.Length < 2)
                            {
                                Throw(new ApplicationException());
                            }
                            context.commands[args[0]] = new KeyValuePair<string, string>(FindCommand(args[1]), Combine(args, 2, args.Length - 2, " ", true/*quoteWhitespace*/));
                            break;

                        case "opencover":
                            if ((mode & Mode.GlobalModes) == 0)
                            {
                                Throw(new ApplicationException());
                            }
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            if (!context.commands.ContainsKey(args[0]))
                            {
                                Throw(new ApplicationException());
                            }
                            context.opencover[args[0]] = true;
                            break;

                        case "fail-pause":
                            if ((mode & Mode.SequentialModes) == 0)
                            {
                                Throw(new ApplicationException());
                            }
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            switch (args[0])
                            {
                                default:
                                    Throw(new ApplicationException());
                                    break;
                                case "on":
                                    context.failPause = true;
                                    break;
                                case "off":
                                    context.failPause = false;
                                    break;
                            }
                            break;

                        case "date-format":
                            if ((mode & Mode.SequentialModes) == 0)
                            {
                                Throw(new ApplicationException());
                            }
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            context.defaultDateFormat = args[0];
                            DateTime.Now.ToString(context.defaultDateFormat); // validate
                            break;

                        case "skip-to":
                            if (mode != Mode.Unrestricted)
                            {
                                Throw(new ApplicationException());
                            }
                            if (args.Length == 0)
                            {
                                Throw(new ApplicationException());
                            }
                            if (args[0].Equals("module", StringComparison.OrdinalIgnoreCase))
                            {
                                skipToModule = Combine(args, 1, args.Length - 1, " ", false/*quoteWhitespace*/);
                                context.testFailed = true;
                            }
                            else
                            {
                                Throw(new ApplicationException());
                            }
                            break;

                        case "declare-exclusive-resource":
                            if ((mode & Mode.GlobalModes) == 0)
                            {
                                Throw(new ApplicationException());
                            }
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            if (moduleNumber > 0)
                            {
                                Throw(new ApplicationException());
                            }
                            context.resources.Add(args[0], false);
                            break;

                        case "use-exclusive-resource":
                            if ((mode & Mode.SequentialModes) == 0)
                            {
                                Throw(new ApplicationException());
                            }
                            if (args.Length < 1)
                            {
                                Throw(new ApplicationException());
                            }
                            Dictionary<string, bool> used = new Dictionary<string, bool>();
                            foreach (string resource in args)
                            {
                                if (!context.resources.ContainsKey(resource))
                                {
                                    Throw(new ApplicationException());
                                }
                                if (used.ContainsKey(resource))
                                {
                                    Throw(new ApplicationException());
                                }
                                used.Add(resource, false);
                            }
                            break;

                        case "reset":
                            if ((mode & Mode.SequentialModes) == 0)
                            {
                                Throw(new ApplicationException());
                            }
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length != 0)
                            {
                                Throw(new ApplicationException());
                            }
                        Reset:
                            VerifyDeferredClear(
                                true/*forceClose*/,
                                context.variables,
                                ref currentFailed,
                                context.resultMatrix,
                                context.scriptNumber,
                                context.moduleNumber,
                                context.testNumber,
                                lineNumber,
                                consoleWriter);
                            foreach (Stream stream in context.openFiles.Values)
                            {
                                stream.Dispose();
                            }
                            context.openFiles.Clear();

                            if (context.workspace != null)
                            {
                                context.workspace.Dispose(); // delete temp files
                                context.workspace = null;
                            }

                            bool testFailed = context.testFailed; // propagate from previous, not base
                            // One might think this could be omitted for mode==Mode.Module since each module
                            // will have a separate prepared context, but it still needs to be done to preserve
                            // an unpolluted context in order to support the "reset" command.
                            context = new Context(contextBase, moduleNumber, moduleName);
                            context.testFailed = testFailed;

                            // One might think this could be omitted for mode==Mode.PrepareTasks, but paths are
                            // still computed even when execution is suppressed, so the unused workspace needs to
                            // exist.
                            context.workspace = context.workspaceDispenser.CreateWorkspace();
                            break;

                        case "\0module":
                            if (mode != Mode.Module)
                            {
                                Throw(new ApplicationException());
                            }
                            moduleNumber = context.moduleNumber;
                            moduleName = context.moduleName;
                            goto Module2;

                        case "module":
                            if ((mode & Mode.GlobalModes) == 0)
                            {
                                Throw(new ApplicationException());
                            }
                            VerifyDeferredClear(
                                true/*forceClose*/,
                                context.variables,
                                ref currentFailed,
                                context.resultMatrix,
                                context.scriptNumber,
                                context.moduleNumber,
                                context.testNumber,
                                lineNumber,
                                consoleWriter);
                            moduleNumber++;
                            moduleName = Combine(args, 0, args.Length, " ", false/*quoteWhitespace*/);
                        Module2:

                            taskHistory.VisitHistory(scriptName, moduleNumber, moduleName);
                            if (startTime.HasValue)
                            {
                                long? duration = null;
                                if (context.opencover.Count == 0)
                                {
                                    duration = (DateTime.UtcNow - startTime.Value).Ticks;
                                }
                                taskHistory.UpdateHistory(scriptName, moduleNumber, moduleName, duration, context.testFailed);

                                startTime = null;
                            }

                            if (skipToModule != null)
                            {
                                if (!String.Equals(skipToModule, moduleName))
                                {
                                    context.testFailed = true;
                                }
                                else
                                {
                                    skipToModule = null;
                                    context.testFailed = false;
                                }
                            }
                            if (mode != Mode.PrepareTasks)
                            {
                                consoleWriter.WriteLine();
                                consoleWriter.WriteLine();
                                consoleWriter.WriteLine("[Script \"{0}\"]", scriptName);
                                consoleWriter.WriteLine("MODULE {0} ({1})", moduleName, moduleNumber);
                            }

                            if (mode == Mode.PrepareTasks)
                            {
                                List<string> resources = new List<string>();
                                LineReader peekReader = new LineReader(scriptReader);
                                int limit = 0;
                                while ((line = peekReader.ReadLine()) != null)
                                {
                                    limit++;

                                    if (line.StartsWith("#"))
                                    {
                                        continue;
                                    }

                                    line = line.TrimEnd();
                                    if (String.IsNullOrEmpty(line))
                                    {
                                        continue;
                                    }

                                    string command2;
                                    int space2 = line.IndexOf(' ');
                                    if (space2 >= 0)
                                    {
                                        command2 = line.Substring(0, space2);
                                    }
                                    else
                                    {
                                        command2 = line;
                                    }
                                    if (space2 < 0)
                                    {
                                        space2 = line.Length;
                                    }

                                    switch (command2)
                                    {
                                        default:
                                            break;
                                        case "module":
                                            limit--;
                                            goto EndPeek;
                                        case "use-exclusive-resource":
                                            string[] args2 = ParseArguments(line.Substring(space2));
                                            foreach (string arg in args2)
                                            {
                                                resources.Add(arg);
                                            }
                                            break;
                                    }
                                }
                            EndPeek:
                                LineReader localScriptReader = new LineReader(scriptReader, limit);
                                Context localContext = new Context(contextBase, moduleNumber, moduleName);
                                int localLineNumber = lineNumber;
                                tasks.Add(
                                    new TaskQueue.Task(
                                        scriptName,
                                        moduleNumber,
                                        moduleName,
                                        delegate(TaskQueue.Task.TaskContext taskContext)
                                        {
                                            try
                                            {
                                                taskContext.status.SetStatus(scriptName, localContext.moduleName, localContext.moduleNumber, DateTime.UtcNow);
                                                Eval(
                                                    localScriptReader,
                                                    localLineNumber,
                                                    scriptName,
                                                    localContext,
                                                    Mode.Module,
                                                    taskContext.ConsoleWriter,
                                                    taskHistory,
                                                    sharedContext);
                                            }
                                            catch (Exception exception)
                                            {
                                                taskContext.ConsoleWriter.WriteLine("EXCEPTION: {0}", exception);
                                                taskContext.SetFatal();
                                            }
                                            finally
                                            {
                                                taskContext.status.SetStatus(null, null, 0, DateTime.MinValue);
                                            }
                                        },
                                        resources.ToArray()));
                            }

                            if (mode != Mode.PrepareTasks)
                            {
                                startTime = DateTime.UtcNow;
                            }

                            goto Reset;

                        case "test":
                            if ((mode & Mode.SequentialModes) == 0)
                            {
                                Throw(new ApplicationException());
                            }
                            if (context.testFailed)
                            {
                                if (mode != Mode.PrepareTasks)
                                {
                                    context.resultMatrix.Skipped();
                                }
                                break;
                            }
                            VerifyDeferredClear(
                                true/*forceClose*/,
                                context.variables,
                                ref currentFailed,
                                context.resultMatrix,
                                context.scriptNumber,
                                context.moduleNumber,
                                context.testNumber,
                                lineNumber,
                                consoleWriter);
                            context.testNumber++;
                            context.testName = Combine(args, 0, args.Length, " ", false/*quoteWhitespace*/);
                            context.resultMatrix.InitTest(context.scriptNumber, scriptName, context.moduleNumber, context.moduleName, context.testNumber, context.testName);
                            consoleWriter.WriteLine();
                            consoleWriter.WriteLine("TEST {0} ({1})", context.testName, context.testNumber);
                            break;

                        case "set":
                            {
                                string statement = Combine(args, 0, args.Length, " ", false/*quoteWhitespace*/);
                                int equals = statement.IndexOf('=');
                                string var = statement.Substring(0, equals).Trim();
                                string expression = statement.Substring(equals + 1);
                                context.variables[var] = EvalExpression(expression, context.variables);
                            }
                            break;

                        case "timeout":
                            if ((mode & Mode.SequentialModes) == 0)
                            {
                                Throw(new ApplicationException());
                            }
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            if (args[0].Equals("none"))
                            {
                                context.commandTimeoutSeconds = null;
                            }
                            else
                            {
                                context.commandTimeoutSeconds = Int32.Parse(args[0]);
                            }
                            break;

                        case "mkdir":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string path = CheckPath(args[0], lineNumber);
                                path = Path.Combine(context.workspace.Root, path);
                                Directory.CreateDirectory(path);
                                Directory.SetCreationTime(path, context.now);
                                Directory.SetLastWriteTime(path, context.now);
                            }
                            break;

                        case "rmdir":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            DeleteDirectory(Path.Combine(context.workspace.Root, CheckPath(args[0], lineNumber)));
                            break;

                        case "show-output":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length != 0)
                            {
                                Throw(new ApplicationException());
                            }
                            consoleWriter.Write(lastOutput);
                            break;

                        case "save-output":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            File.WriteAllText(Path.Combine(context.workspace.Root, CheckPath(args[0], lineNumber)), lastOutput);
                            break;

                        case "lastoutput-verify":
                            StreamVerify(
                                command,
                                scriptReader,
                                args,
                                0,
                                "endoutput",
                                ref lineNumber,
                                context.defaultDateFormat,
                                delegate(string dateFormat) { return lastOutput; },
                                context.testFailed,
                                ref currentFailed,
                                context.resultMatrix,
                                context.scriptNumber,
                                context.moduleNumber,
                                context.testNumber,
                                consoleWriter,
                                context.workspace);
                            break;

                        case "call":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length < 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string exe = args[0];
                                string commandArgs = String.Concat(context.commands[exe].Value, " ", Combine(args, 1, args.Length - 1, " ", true/*quoteWhitespace*/));
                                foreach (KeyValuePair<string, object> variable in context.variables)
                                {
                                    commandArgs = commandArgs.Replace(String.Concat("%", variable.Key, "%"), variable.Value.ToString());
                                }
                                consoleWriter.WriteLine("{0} {1}", context.commands[exe].Key, sharedContext.ReplaceOutputValueSubstitutions(commandArgs));
                                if (!Exec(
                                    context.commands[exe].Key,
                                    context.opencover.ContainsKey(exe),
                                    commandArgs,
                                    null,
                                    context.commandTimeoutSeconds,
                                    context.workspace,
                                    scriptName,
                                    lineNumber,
                                    out lastExitCode,
                                    out lastOutput))
                                {
                                    currentFailed = true;
                                    context.resultMatrix.Failed(context.scriptNumber, context.moduleNumber, context.testNumber, lineNumber);

                                    consoleWriter.WriteLine("FAILURE: command exceeded timeout, script line {0}", lineNumber);
                                }
                                VerifyDeferredClear(
                                    false/*forceClose*/,
                                    context.variables,
                                    ref currentFailed,
                                    context.resultMatrix,
                                    context.scriptNumber,
                                    context.moduleNumber,
                                    context.testNumber,
                                    lineNumber,
                                    consoleWriter);
                            }
                            break;

                        case "call-with-input":
                            if (args.Length < 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string linePrefix = ".";
                                if (args[0].Equals("-lineprefix"))
                                {
                                    linePrefix = args[1];
                                    string[] args2 = new string[args.Length - 2];
                                    Array.Copy(args, 2, args2, 0, args2.Length);
                                    args = args2;
                                }

                                string exe = args[0];
                                string commandArgs = String.Concat(context.commands[exe].Value, " ", Combine(args, 1, args.Length - 1, " ", true/*quoteWhitespace*/));
                                foreach (KeyValuePair<string, object> variable in context.variables)
                                {
                                    commandArgs = commandArgs.Replace(String.Concat("%", variable.Key, "%"), variable.Value.ToString());
                                }

                                string input = ReadInlineContent(scriptReader, linePrefix, "endinput", ref lineNumber, null);

                                if (context.testFailed)
                                {
                                    break;
                                }

                                consoleWriter.WriteLine("{0} {1}", context.commands[exe].Key, sharedContext.ReplaceOutputValueSubstitutions(commandArgs));
                                if (!Exec(
                                    context.commands[exe].Key,
                                    context.opencover.ContainsKey(exe),
                                    commandArgs,
                                    input,
                                    context.commandTimeoutSeconds,
                                    context.workspace,
                                    scriptName,
                                    lineNumber,
                                    out lastExitCode,
                                    out lastOutput))
                                {
                                    currentFailed = true;
                                    context.resultMatrix.Failed(context.scriptNumber, context.moduleNumber, context.testNumber, lineNumber);

                                    consoleWriter.WriteLine("FAILURE: command exceeded timeout, script line {0}", lineNumber);
                                }
                                VerifyDeferredClear(
                                    false/*forceClose*/,
                                    context.variables,
                                    ref currentFailed,
                                    context.resultMatrix,
                                    context.scriptNumber,
                                    context.moduleNumber,
                                    context.testNumber,
                                    lineNumber,
                                    consoleWriter);
                            }
                            break;

                        case "date":
                        case "time":
                            if (args.Length < 1)
                            {
                                Throw(new ApplicationException());
                            }
                            if (args[0] == "+")
                            {
                                if (args.Length != 2)
                                {
                                    Throw(new ApplicationException());
                                }
                                context.now = context.now.Add(TimeSpan.Parse(args[1]));
                                context.variables["DATE"] = context.now.ToString(Context.InitialDefaultDateFormat);
                            }
                            else if (args[0] == "-")
                            {
                                if (args.Length != 2)
                                {
                                    Throw(new ApplicationException());
                                }
                                context.now = context.now.Subtract(TimeSpan.Parse(args[1]));
                                context.variables["DATE"] = context.now.ToString(Context.InitialDefaultDateFormat);
                            }
                            else
                            {
                                if (args.Length != 1)
                                {
                                    Throw(new ApplicationException());
                                }
                                context.now = DateTime.Parse(args[0]);
                                context.variables["DATE"] = context.now.ToString(Context.InitialDefaultDateFormat);
                            }
                            break;

                        case "delete":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string file = CheckPath(args[0], lineNumber);
                                file = Path.Combine(context.workspace.Root, file);
                                File.Delete(file);
                            }
                            break;

                        case "edit":
                        case "create":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length < 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                bool create = command == "create";
                                long? size = null;
                                string valueUtf8Literal = null;
                                string binaryResourcePath = null;
                                for (int i = 1; i < args.Length; i++)
                                {
                                    if (args[i] == "-size")
                                    {
                                        i++;
                                        size = Int64.Parse(args[i]);
                                    }
                                    else if (args[i] == "-value")
                                    {
                                        i++;
                                        valueUtf8Literal = args[i];
                                    }
                                    else if (args[i] == "-resource")
                                    {
                                        i++;
                                        binaryResourcePath = CheckPath(args[i], lineNumber);
                                    }
                                    else
                                    {
                                        Throw(new ApplicationException());
                                    }
                                }
                                string file = CheckPath(args[0], lineNumber);
                                file = Path.Combine(context.workspace.Root, file);
                                if (create == File.Exists(file))
                                {
                                    Throw(new ApplicationException(String.Format("file already exists, line {0}", lineNumber)));
                                }
                                using (Stream stream = new FileStream(file, FileMode.Create))
                                {
                                    if (valueUtf8Literal != null)
                                    {
                                        byte[] data = Encoding.UTF8.GetBytes(valueUtf8Literal);
                                        stream.Write(data, 0, data.Length);
                                        if (size.HasValue)
                                        {
                                            stream.SetLength(size.Value);
                                        }
                                    }
                                    else if (binaryResourcePath != null)
                                    {
                                        using (FileStream resource = new FileStream(Path.Combine(Path.GetDirectoryName(scriptName), binaryResourcePath), FileMode.Open, FileAccess.Read, FileShare.Read))
                                        {
                                            byte[] buffer = new byte[4096];
                                            int read;
                                            while ((read = resource.Read(buffer, 0, buffer.Length)) != 0)
                                            {
                                                stream.Write(buffer, 0, read);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        using (TextWriter writer = new StreamWriter(stream, Encoding.ASCII))
                                        {
                                            byte[] rnd = new byte[2];
                                            random.GetBytes(rnd);
                                            long length = size.HasValue ? size.Value : Math.Max(0x0fff, 0x3fff & (rnd[0] + ((int)rnd[1] << 8)));
                                            long count = 0;
                                            StringBuilder one = new StringBuilder();
                                            while (count < length)
                                            {
                                                one.Length = 0;
                                                rnd = new byte[1];
                                                random.GetBytes(rnd);
                                                rnd = new byte[(rnd[0] & 0x7) + 1];
                                                random.GetBytes(rnd);
                                                foreach (byte i in rnd)
                                                {
                                                    rnd = new byte[(i & 0xf) + 1];
                                                    random.GetBytes(rnd);
                                                    foreach (byte j in rnd)
                                                    {
                                                        char c = (char)(j % 26 + 'a');
                                                        one.Append(c);
                                                    }
                                                    one.Append(' ');
                                                }
                                                one.AppendLine();
                                                if (count + one.Length > length)
                                                {
                                                    one.Length = (int)(length - count);
                                                }
                                                writer.Write(one);
                                                count += one.Length;
                                            }
                                        }
                                    }
                                }
                                if (create)
                                {
                                    File.SetCreationTime(file, context.now);
                                }
                                File.SetLastWriteTime(file, context.now);
                            }
                            break;

                        case "write":
                            if (args.Length < 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string file = CheckPath(args[0], lineNumber);
                                file = Path.Combine(context.workspace.Root, file);
                                string linePrefix = ".";
                                bool binary = false;
                                for (int i = 1; i < args.Length; i++)
                                {
                                    if (args[i].Equals("-lineprefix"))
                                    {
                                        i++;
                                        linePrefix = args[i];
                                    }
                                    else if (args[i].Equals("-binary"))
                                    {
                                        binary = true;
                                    }
                                    else
                                    {
                                        Throw(new ApplicationException());
                                    }
                                }

                                bool create = !File.Exists(file);
                                string content = ReadInlineContent(scriptReader, linePrefix, "endwrite", ref lineNumber, null);
                                if (context.testFailed)
                                {
                                    break;
                                }
                                if (!binary)
                                {
                                    using (TextWriter writer = new StreamWriter(file))
                                    {
                                        writer.Write(content);
                                    }
                                }
                                else
                                {
                                    using (TextReader reader = new StringReader(content))
                                    {
                                        File.WriteAllBytes(file, BinaryDecode(linePrefix, reader));
                                    }
                                }
                                if (create)
                                {
                                    File.SetCreationTime(file, context.now);
                                }
                                File.SetLastWriteTime(file, context.now);
                            }
                            break;

                        case "invert-range":
                            if (args.Length != 3)
                            {
                                Throw(new ApplicationException());
                            }
                            if (context.testFailed)
                            {
                                break;
                            }
                            {
                                string file = CheckPath(args[0], lineNumber);
                                file = Path.Combine(context.workspace.Root, file);

                                int offset = Int32.Parse(args[1]); // offset >= 0: from start, offset <= 0: from end
                                int range = Int32.Parse(args[2]);

                                using (Stream stream = File.Open(file, FileMode.Open))
                                {
                                    stream.Seek(offset >= 0 ? offset : stream.Length + offset, SeekOrigin.Begin);
                                    byte[] b = new byte[range];
                                    int r = stream.Read(b, 0, range);
                                    if (r != range)
                                    {
                                        Throw(new IOException());
                                    }
                                    for (int i = 0; i < b.Length; i++)
                                    {
                                        b[i] = (byte)~b[i];
                                    }
                                    stream.Seek(offset >= 0 ? offset : stream.Length + offset, SeekOrigin.Begin);
                                    stream.Write(b, 0, range);
                                }
                                File.SetLastWriteTime(file, context.now);
                            }
                            break;

                        case "file-verify":
                            if (args.Length < 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string file = CheckPath(args[0], lineNumber);
                                file = Path.Combine(context.workspace.Root, file);
                                StreamVerify(
                                    command,
                                    scriptReader,
                                    args,
                                    1,
                                    "endfile",
                                    ref lineNumber,
                                    context.defaultDateFormat,
                                    delegate(string dateFormat) { return File.ReadAllText(file); },
                                    context.testFailed,
                                    ref currentFailed,
                                    context.resultMatrix,
                                    context.scriptNumber,
                                    context.moduleNumber,
                                    context.testNumber,
                                    consoleWriter,
                                    context.workspace);
                            }
                            break;

                        case "open":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length != 2)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string file = CheckPath(args[0], lineNumber);
                                file = Path.Combine(context.workspace.Root, file);
                                switch (args[1])
                                {
                                    default:
                                        Throw(new ApplicationException());
                                        break;
                                    case "wx":
                                        context.openFiles[file] = File.Open(file, FileMode.Open, FileAccess.Write, FileShare.None);
                                        break;
                                    case "rx":
                                        context.openFiles[file] = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.None);
                                        break;
                                    case "rr":
                                        context.openFiles[file] = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.Read);
                                        break;
                                    case "ra":
                                        context.openFiles[file] = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                        break;
                                }
                            }
                            break;

                        case "close-all":
                            if (context.testFailed)
                            {
                                break;
                            }
                            foreach (Stream stream in context.openFiles.Values)
                            {
                                stream.Dispose();
                            }
                            context.openFiles.Clear();
                            break;

                        case "copy":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length != 2)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string source = CheckPath(args[0], lineNumber);
                                source = Path.Combine(context.workspace.Root, source);
                                string target = CheckPath(args[1], lineNumber);
                                target = Path.Combine(context.workspace.Root, target);
                                if (File.Exists(source))
                                {
                                    File.Copy(source, target);
                                    File.SetAttributes(target, File.GetAttributes(target) & ~FileAttributes.ReadOnly);
                                    File.SetCreationTime(target, File.GetCreationTime(source));
                                    File.SetLastWriteTime(target, File.GetLastWriteTime(source));
                                    File.SetAttributes(target, File.GetAttributes(source));
                                }
                                else if (Directory.Exists(source))
                                {
                                    CopyTree(source, target);
                                }
                                else
                                {
                                    Throw(new ApplicationException());
                                }
                            }
                            break;

                        case "move":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length != 2)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string source = CheckPath(args[0], lineNumber);
                                source = Path.Combine(context.workspace.Root, source);
                                string target = CheckPath(args[1], lineNumber);
                                target = Path.Combine(context.workspace.Root, target);
                                if (Directory.Exists(source))
                                {
                                    if (!String.Equals(source, target, StringComparison.OrdinalIgnoreCase))
                                    {
                                        Directory.Move(source, target);
                                    }
                                    else
                                    {
                                        string container = Path.GetDirectoryName(source);
                                        uint i = 0;
                                        byte[] start = new byte[sizeof(uint)];
                                        random.GetBytes(start);
                                        foreach (byte b in start)
                                        {
                                            i = (i << 8) | b;
                                        }
                                        string temp;
                                        while (File.Exists(temp = Path.Combine(container, i.ToString())) || Directory.Exists(temp))
                                        {
                                            i++;
                                        }
                                        Directory.Move(source, temp);
                                        Directory.Move(temp, target);
                                    }
                                }
                                else
                                {
                                    File.Move(source, target);
                                }
                            }
                            break;

                        case "attrib":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length < 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string path = CheckPath(args[0], lineNumber);
                                path = Path.Combine(context.workspace.Root, path);
                                for (int i = 1; i < args.Length; i++)
                                {
                                    if (args[i].Length != 2)
                                    {
                                        Throw(new ApplicationException());
                                    }
                                    FileAttributes mask = 0;
                                    switch (Char.ToLower(args[i][1]))
                                    {
                                        default:
                                            Throw(new ApplicationException());
                                            break;
                                        case 'a':
                                            mask = FileAttributes.Archive;
                                            break;
                                        case 'r':
                                            mask = FileAttributes.ReadOnly;
                                            break;
                                        case 'h':
                                            mask = FileAttributes.Hidden;
                                            break;
                                        case 's':
                                            mask = FileAttributes.System;
                                            break;
                                        case 'c':
                                            mask = FileAttributes.Compressed;
                                            break;
                                    }
                                    if (((mask & FileAttributes.Compressed) != 0) && ((mask & ~FileAttributes.Compressed) != 0))
                                    {
                                        Throw(new ApplicationException("compressed attribute must be set/cleared by itself"));
                                    }
                                    if ((mask & FileAttributes.Compressed) == 0)
                                    {
                                        switch (args[i][0])
                                        {
                                            default:
                                                Throw(new ApplicationException());
                                                break;
                                            case '-':
                                                File.SetAttributes(path, File.GetAttributes(path) & ~mask);
                                                break;
                                            case '+':
                                                File.SetAttributes(path, File.GetAttributes(path) | mask);
                                                break;
                                        }
                                    }
                                    else
                                    {
                                        switch (args[i][0])
                                        {
                                            default:
                                                Throw(new ApplicationException());
                                                break;
                                            case '-':
                                                FileCompressionHelper.SetCompressed(path, false);
                                                break;
                                            case '+':
                                                FileCompressionHelper.SetCompressed(path, true);
                                                break;
                                        }
                                    }
                                }
                            }
                            break;

                        case "touch":
                            if (args.Length < 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string path = CheckPath(args[0], lineNumber);
                                path = Path.Combine(context.workspace.Root, path);
                                if (context.testFailed)
                                {
                                    break;
                                }
                                if (args.Length == 1)
                                {
                                    File.SetLastWriteTime(path, context.now);
                                }
                                else if ((args.Length == 2) && args[1].Equals("-created"))
                                {
                                    File.SetCreationTime(path, context.now);
                                }
                                else if ((args.Length == 2) && args[1].Equals("-modified"))
                                {
                                    File.SetLastWriteTime(path, context.now);
                                }
                                else
                                {
                                    DateTime? created = null;
                                    DateTime? lastWritten = null;
                                    for (int i = 1; i < args.Length; i++)
                                    {
                                        if (args[i].Equals("-created"))
                                        {
                                            i++;
                                            created = DateTime.Parse(args[i]);
                                        }
                                        else if (args[i].Equals("-modified"))
                                        {
                                            i++;
                                            lastWritten = DateTime.Parse(args[i]);
                                        }
                                        else
                                        {
                                            Throw(new ApplicationException());
                                        }
                                    }
                                    if (created.HasValue)
                                    {
                                        File.SetCreationTime(path, created.Value);
                                    }
                                    if (lastWritten.HasValue)
                                    {
                                        File.SetLastWriteTime(path, lastWritten.Value);
                                    }
                                }
                            }
                            break;

                        case "list":
                        case "qlist":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length < 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string path = CheckPath(args[0], lineNumber);
                                path = Path.Combine(context.workspace.Root, path);
                                string dateFormat = context.defaultDateFormat;
                                string linePrefix = ".";
                                bool showSizes = false;
                                bool showCompressed = false;
                                for (int i = 1; i < args.Length; i++)
                                {
                                    if (args[i].Equals("-lineprefix"))
                                    {
                                        i++;
                                        linePrefix = args[i];
                                    }
                                    else if (args[i].Equals("-dateformat"))
                                    {
                                        i++;
                                        dateFormat = args[i];
                                    }
                                    else if (args[i].Equals("-sizes"))
                                    {
                                        showSizes = true;
                                    }
                                    else if (args[i].Equals("-compressed"))
                                    {
                                        showCompressed = true;
                                    }
                                    else
                                    {
                                        Throw(new ApplicationException());
                                    }
                                }

                                string output = List(path, context.hashes, dateFormat, showSizes, showCompressed);
                                if (command != "qlist")
                                {
                                    WriteWithLinePrefix(consoleWriter, output, linePrefix);
                                    consoleWriter.WriteLine("endlist");
                                }
                            }
                            break;

                        case "list-verify":
                            if (args.Length < 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string path = CheckPath(args[0], lineNumber);
                                path = Path.Combine(context.workspace.Root, path);
                                bool showSizes = false;
                                if ((args.Length > 1) && args[1].Equals("-sizes"))
                                {
                                    showSizes = true;
                                    Array.Copy(args, 2, args, 1, args.Length - 2);
                                    Array.Resize(ref args, args.Length - 1);
                                }
                                bool showCompressed = false;
                                if ((args.Length > 1) && args[1].Equals("-compressed"))
                                {
                                    showCompressed = true;
                                    Array.Copy(args, 2, args, 1, args.Length - 2);
                                    Array.Resize(ref args, args.Length - 1);
                                }
                                StreamVerify(
                                    command,
                                    scriptReader,
                                    args,
                                    1,
                                    "endlist",
                                    ref lineNumber,
                                    context.defaultDateFormat,
                                    delegate(string dateFormat) { return List(path, context.hashes, dateFormat, showSizes, showCompressed); },
                                    context.testFailed,
                                    ref currentFailed,
                                    context.resultMatrix,
                                    context.scriptNumber,
                                    context.moduleNumber,
                                    context.testNumber,
                                    consoleWriter,
                                    context.workspace);
                            }
                            break;

                        case "dirs-equal-verify":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length < 2)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string left = CheckPath(args[0], lineNumber);
                                left = Path.Combine(context.workspace.Root, left);
                                string right = CheckPath(args[1], lineNumber);
                                right = Path.Combine(context.workspace.Root, right);
                                string dateFormat = context.defaultDateFormat;
                                string linePrefix = ".";
                                bool showSizes = false;
                                bool showCompressed = false;
                                for (int i = 2; i < args.Length; i++)
                                {
                                    if (args[i].StartsWith("-lineprefix"))
                                    {
                                        i++;
                                        linePrefix = args[i];
                                    }
                                    else if (args[i].Equals("-dateformat"))
                                    {
                                        i++;
                                        dateFormat = args[i];
                                    }
                                    else if (args[i].Equals("-sizes"))
                                    {
                                        showSizes = true;
                                    }
                                    else if (args[i].Equals("-compressed"))
                                    {
                                        showCompressed = true;
                                    }
                                    else
                                    {
                                        Throw(new ApplicationException());
                                    }
                                }
                                string leftList = List(left, context.hashes, dateFormat, showSizes, showCompressed);
                                string rightList = List(right, context.hashes, dateFormat, showSizes, showCompressed);
                                if (!String.Equals(leftList, rightList))
                                {
                                    currentFailed = true;
                                    context.resultMatrix.Failed(context.scriptNumber, context.moduleNumber, context.testNumber, lineNumber);

                                    consoleWriter.WriteLine("FAILURE in 'dirs-equal-verify', script line {0}", lineNumber);
                                    consoleWriter.WriteLine("LEFT");
                                    WriteWithLinePrefix(consoleWriter, leftList, linePrefix);
                                    consoleWriter.WriteLine("RIGHT");
                                    WriteWithLinePrefix(consoleWriter, rightList, linePrefix);

                                    string leftTemp = Path.GetTempFileName();
                                    string rightTemp = Path.GetTempFileName();
                                    File.WriteAllText(leftTemp, leftList);
                                    File.WriteAllText(rightTemp, rightList);
                                    Process.Start("windiff.exe", String.Format(" \"{0}\" \"{1}\"", leftTemp, rightTemp));
                                }
                            }
                            break;

                        case "exitcode-verify":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if ((args.Length < 1) || (args.Length > 2))
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                bool not = args[0] == "not";
                                int expected = Int32.Parse(args[args.Length - 1]);
                                if (not != (lastExitCode != expected))
                                {
                                    currentFailed = true;
                                    context.resultMatrix.Failed(context.scriptNumber, context.moduleNumber, context.testNumber, lineNumber);

                                    consoleWriter.WriteLine("FAILURE in 'exitcode-verify', script line {0}", lineNumber);
                                    consoleWriter.WriteLine("EXITCODE expected={0}{1} actual={2}", not ? "not " : String.Empty, expected, lastExitCode);
                                    consoleWriter.WriteLine("program output was:{0}", String.IsNullOrEmpty(lastOutput) ? " [none]" : String.Empty);
                                    consoleWriter.WriteLine(lastOutput);
                                }
                            }
                            break;

                        case "verify-not-exist":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string path = CheckPath(args[0], lineNumber);
                                path = Path.Combine(context.workspace.Root, path);
                                if (File.Exists(path) || Directory.Exists(path))
                                {
                                    currentFailed = true;
                                    context.resultMatrix.Failed(context.scriptNumber, context.moduleNumber, context.testNumber, lineNumber);

                                    consoleWriter.WriteLine("FAILURE in 'verify-not-exist', script line {0}", lineNumber);
                                    consoleWriter.WriteLine(lastOutput);
                                }
                            }
                            break;

                        case "load-resource":
                            if (context.testFailed && !(mode == Mode.PrepareTasks)) // permit during parallel task preparation
                            {
                                break;
                            }
                            if (args.Length != 2)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string variable = args[0];
                                string resourcePath = CheckPath(args[1], lineNumber);
                                context.variables[variable] = File.ReadAllText(Path.Combine(Path.GetDirectoryName(scriptName), resourcePath));
                            }
                            break;

                        case "encrypt-memory":
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string variable = args[0];
                                if ((mode & Mode.GlobalModes) != 0)
                                {
                                    sharedContext.EnsureOutputValueSubstitution(scriptName, lineNumber, variable);
                                }

                                if (context.testFailed && !(mode == Mode.PrepareTasks)) // permit during parallel task preparation
                                {
                                    break;
                                }

                                string value = ProtectedDataStorageHelpers.EncryptMemory(context.variables[variable].ToString());
                                context.variables[variable] = value;
                                sharedContext.SetOutputValueSubstitution(scriptName, lineNumber, variable, value);
                            }
                            break;

                        case "decrypt-memory":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string variable = args[0];
                                context.variables[variable] = ProtectedDataStorageHelpers.DecryptMemory(context.variables[variable].ToString());
                            }
                            break;

                        case "encrypt-user-persistent":
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string variable = args[0];
                                if ((mode & Mode.GlobalModes) != 0)
                                {
                                    sharedContext.EnsureOutputValueSubstitution(scriptName, lineNumber, variable);
                                }

                                if (context.testFailed && !(mode == Mode.PrepareTasks)) // permit during parallel task preparation
                                {
                                    break;
                                }

                                string value = ProtectedDataStorageHelpers.EncryptUserPersistent(context.variables[variable].ToString());
                                context.variables[variable] = value;
                                sharedContext.SetOutputValueSubstitution(scriptName, lineNumber, variable, value);
                            }
                            break;

                        case "decrypt-user-persistent":
                            if (context.testFailed)
                            {
                                break;
                            }
                            if (args.Length != 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string variable = args[0];
                                context.variables[variable] = ProtectedDataStorageHelpers.DecryptUserPersistent(context.variables[variable].ToString());
                            }
                            break;

                        case "defer":
                            if ((mode & Mode.SequentialModes) == 0)
                            {
                                Throw(new ApplicationException());
                            }
                            if (args.Length < 1)
                            {
                                Throw(new ApplicationException());
                            }
                            {
                                string variableName = args[0];
                                int startLineNumber = lineNumber;
                                if ((mode & Mode.GlobalModes) != 0)
                                {
                                    sharedContext.EnsureOutputValueSubstitution(scriptName, startLineNumber, variableName);
                                }

                                string linePrefix = ".";
                                for (int i = 1; i < args.Length; i++)
                                {
                                    switch (args[i])
                                    {
                                        default:
                                            Throw(new ApplicationException());
                                            break;
                                        case "-lineprefix":
                                            linePrefix = args[1];
                                            break;
                                    }
                                }

                                string taskCode = ReadInlineContent(scriptReader, linePrefix, "enddefer", ref lineNumber, null);
                                if (context.testFailed)
                                {
                                    break;
                                }

                                DeferredTask deferredTask = new DeferredTask(taskCode, scriptName, lineNumber, context, consoleWriter, sharedContext);
                                context.variables.Add(variableName, deferredTask);
                                sharedContext.SetOutputValueSubstitution(scriptName, startLineNumber, variableName, deferredTask.ToString());
                                deferredTask.Start();
                            }
                            break;
                    }

                    context.testFailed = context.testFailed || currentFailed;
                    if ((mode == Mode.Unrestricted) && currentFailed && context.failPause)
                    {
                        consoleWriter.Write("<ENTER> to continue ('r' to attempt to ignore error)...");
                        string s = Console.ReadLine();
                        if (s == "r")
                        {
                            context.testFailed = false;
                        }
                    }
                }

                if (mode != Mode.Callback)
                {
                    VerifyDeferredClear(
                        false/*forceClose*/,
                        context.variables,
                        ref context.testFailed,
                        context.resultMatrix,
                        context.scriptNumber,
                        context.moduleNumber,
                        context.testNumber,
                        lineNumber,
                        consoleWriter);
                }
            }
            catch (Exception exception)
            {
                if (context.moduleNumber != 0)
                {
                    context.resultMatrix.Failed(context.scriptNumber, context.moduleNumber, context.testNumber, lineNumber);
                }

                if (exception is ApplicationException)
                {
                    throw;
                }
                throw new Exception(String.Format("line {0} of script", lineNumber), exception);
            }
            finally
            {
                if (startTime.HasValue)
                {
                    long? duration = null;
                    if (context.opencover.Count == 0)
                    {
                        duration = (DateTime.UtcNow - startTime.Value).Ticks;
                    }
                    taskHistory.UpdateHistory(scriptName, context.moduleNumber, context.moduleName, duration, context.testFailed);

                    startTime = null;
                }

                if (mode != Mode.PrepareTasks)
                {
                    consoleWriter.Flush();
                }

                if (mode != Mode.Callback)
                {
                    if (context.workspace != null)
                    {
                        context.workspace.Dispose();
                        context.workspace = null;
                    }
                }
            }

            return tasks;
        }

        private static void VerifyDeferredClear(bool forceClose, Dictionary<string, object> variables, ref bool currentFailed, TestResultMatrix resultMatrix, int scriptNumber, int moduleNumber, int testNumber, int lineNumber, TextWriter consoleWriter)
        {
            List<KeyValuePair<string, object>> toRemove = new List<KeyValuePair<string, object>>();
            foreach (KeyValuePair<string, object> variable in variables)
            {
                DeferredTask deferredTask = variable.Value as DeferredTask;
                if (deferredTask != null)
                {
                    if (deferredTask.Active)
                    {
                        currentFailed = true;
                        resultMatrix.Failed(scriptNumber, moduleNumber, testNumber, lineNumber);

                        consoleWriter.WriteLine("FAILURE in 'verify-deferred-clear', script line {0}", lineNumber);
                        consoleWriter.WriteLine("Deferred task \"{0}\" still active", variable.Key);
                        toRemove.Add(variable);
                    }
                    else
                    {
                        if (forceClose)
                        {
                            toRemove.Add(variable);
                        }
                    }
                }
            }
            foreach (KeyValuePair<string, object> variable in toRemove)
            {
                variables.Remove(variable.Key);
                ((IDisposable)variable.Value).Dispose();
            }
        }

        private class DeferredTask : IDisposable
        {
            private readonly string triggerEventName;
            private readonly string resumeEventName;
            private EventWaitHandle triggerEvent;
            private EventWaitHandle resumeEvent;
            private const string EventNamePrefix = "FileUtilityTester.exe-";

            private bool active;
            private readonly Thread thread;

            private readonly string scriptName;
            private readonly int originatingLineNumber;
            private readonly Context context;
            private readonly SharedContext sharedContext;
            private readonly TextWriter consoleWriter;
            private readonly string taskCode;

            public string TriggerEventName { get { return EventNamePrefix + triggerEventName; } }
            public string ResumeEventName { get { return EventNamePrefix + resumeEventName; } }

            public bool Active { get { return active; } }

            public DeferredTask(string taskCode, string scriptName, int originatingLineNumber, Context context, TextWriter consoleWriter, SharedContext sharedContext)
                : this(Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("D"), taskCode, scriptName, originatingLineNumber, context, consoleWriter, sharedContext)
            {
            }

            public DeferredTask(string triggerEventName, string resumeEventName, string taskCode, string scriptName, int originatingLineNumber, Context context, TextWriter consoleWriter, SharedContext sharedContext)
            {
                this.scriptName = scriptName;
                this.originatingLineNumber = originatingLineNumber;
                this.taskCode = taskCode;
                this.context = context;
                this.sharedContext = sharedContext;
                this.consoleWriter = consoleWriter;

                this.triggerEventName = triggerEventName;
                this.resumeEventName = resumeEventName;
                this.triggerEvent = new EventWaitHandle(false, EventResetMode.AutoReset, TriggerEventName);
                this.resumeEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ResumeEventName);

                this.thread = new Thread(StaticThreadMain);
            }

            public void Start()
            {
                active = true;
                thread.Start(this);
            }

            private static void StaticThreadMain(object o)
            {
                DeferredTask This = (DeferredTask)o;
                This.ThreadMain();
            }

            private void ThreadMain()
            {
                // wait for subprogram to trigger task
                if (!triggerEvent.WaitOne())
                {
                    return;
                }

                // do task
                try
                {
                    Eval(
                        new LineReader(taskCode.Split(new string[] { Environment.NewLine }, StringSplitOptions.None)),
                        originatingLineNumber,
                        String.Format("{0}-defer{1}", scriptName, originatingLineNumber),
                        context,
                        Mode.Callback,
                        consoleWriter,
                        null/*taskHistory*/,
                        sharedContext);
                }
                catch (Exception)
                {
                }

                // signal subprogram to resume
                active = false;
                resumeEvent.Set();
            }

            public void Dispose()
            {
                active = false;
                thread.Abort(); // thread will have already exited in normal cases - aborts waiting thread only in error cases
                if (resumeEvent != null)
                {
                    resumeEvent.Close();
                    resumeEvent = null;
                }
                if (triggerEvent != null)
                {
                    triggerEvent.Close();
                    triggerEvent = null;
                }
            }

            public override string ToString()
            {
                return String.Concat(TriggerEventName, ",", ResumeEventName);
            }
        }

        private static string FindCommand(string specifiedPath)
        {
            string[] specifiedPathParts = specifiedPath.Split(Path.DirectorySeparatorChar);
            string path = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
            foreach (string specifiedPathPart in specifiedPathParts)
            {
                if (specifiedPathPart == ".")
                {
                    continue;
                }
                else if (specifiedPathPart == "..")
                {
                    path = Path.GetDirectoryName(path);
                }
                else
                {
                    path = Path.Combine(path, specifiedPathPart);
                }
            }
            return path;
        }

        private static void CopyTree(string source, string target)
        {
            if (!Path.IsPathRooted(source) || !Path.IsPathRooted(target))
            {
                Throw(new ApplicationException());
            }

            Directory.CreateDirectory(target);
            foreach (string file in Directory.GetFileSystemEntries(source))
            {
                string name = Path.GetFileName(file);
                string sourcePath = Path.Combine(source, name);
                string targetPath = Path.Combine(target, name);
                if (File.Exists(sourcePath))
                {
                    File.Copy(sourcePath, targetPath);
                    FileAttributes attr = File.GetAttributes(targetPath);
                    File.SetAttributes(targetPath, attr & ~FileAttributes.ReadOnly);
                    File.SetCreationTime(targetPath, File.GetCreationTime(sourcePath));
                    File.SetLastWriteTime(targetPath, File.GetLastWriteTime(sourcePath));
                    File.SetAttributes(targetPath, attr);
                }
                else
                {
                    CopyTree(sourcePath, targetPath);
                }
            }
        }

        private delegate string GetContent(string dateFormat);
        private static void StreamVerify(string command, LineReader scriptReader, string[] args, int argsStart, string endKeyword, ref int lineNumber, string defaultDateFormat, GetContent getActual, bool testFailed, ref bool currentFailed, TestResultMatrix resultMatrix, int scriptNumber, int moduleNumber, int testNumber, TextWriter consoleWriter, Workspace workspace)
        {
            int startLineNumber = lineNumber;
            string dateFormat = defaultDateFormat;
            string linePrefix = ".";
            bool ignoreExtraLines = false;
            bool workspacePathHack = false;
            for (int i = argsStart; i < args.Length; i++)
            {
                if (args[i].StartsWith("-lineprefix"))
                {
                    i++;
                    linePrefix = args[i];
                }
                else if (args[i].Equals("-dateformat"))
                {
                    i++;
                    dateFormat = args[i];
                }
                else if (args[i].Equals("-ignoreextralines"))
                {
                    ignoreExtraLines = true;
                }
                else if (args[i].Equals("-workspacepathhack"))
                {
                    workspacePathHack = true;
                }
                else
                {
                    Throw(new ApplicationException());
                }
            }

            List<int> wildcardLines = new List<int>();
            string standard = ReadInlineContent(scriptReader, linePrefix, endKeyword, ref lineNumber, wildcardLines);
            if (testFailed)
            {
                return;
            }
            string actual = getActual(dateFormat);
            if (workspacePathHack)
            {
                actual = actual.Replace(workspace.Root, "%WORKSPACE%");
                actual = actual.Replace(workspace.Root.ToLowerInvariant(), "%WORKSPACE%"); // try a common case variation
            }
            if (!CompareContent(standard, actual, wildcardLines.ToArray(), ignoreExtraLines))
            {
                currentFailed = true;
                resultMatrix.Failed(scriptNumber, moduleNumber, testNumber, startLineNumber);

                consoleWriter.WriteLine("FAILURE in '{0}', script line {1}", command, startLineNumber);
                //
                consoleWriter.WriteLine("EXPECTED");
                WriteWithLinePrefix(consoleWriter, standard, linePrefix);
                string standardPrefixedTempFile = Path.GetTempFileName();
                using (TextWriter writer = new StreamWriter(standardPrefixedTempFile, false/*append*/, Encoding.UTF8))
                {
                    WriteWithLinePrefix(writer, standard, linePrefix);
                }
                //
                consoleWriter.WriteLine("ACTUAL");
                WriteWithLinePrefix(consoleWriter, actual, linePrefix);
                string actualPrefixedTempFile = Path.GetTempFileName();
                using (TextWriter writer = new StreamWriter(actualPrefixedTempFile, false/*append*/, Encoding.UTF8))
                {
                    WriteWithLinePrefix(writer, actual, linePrefix);
                }

                consoleWriter.WriteLine("Prefixed standard available at \"{0}\", actual at \"{1}\"", standardPrefixedTempFile, actualPrefixedTempFile);

                string standardTemp = Path.GetTempFileName();
                string actualTemp = Path.GetTempFileName();
                File.WriteAllText(standardTemp, standard);
                File.WriteAllText(actualTemp, actual);
                Process.Start("windiff.exe", String.Format(" \"{0}\" \"{1}\"", standardTemp, actualTemp));
            }
        }

        private static string[] ParseArguments(string line)
        {
            List<string> arguments = new List<string>();

            int i = 0;
            while (i < line.Length)
            {
                if (Char.IsWhiteSpace(line[i]))
                {
                    i++;
                    continue;
                }

                if (line[i] == '"')
                {
                    char stop = line[i];
                    i++;
                    StringBuilder sb = new StringBuilder();
                    while (line[i] != stop)
                    {
                        if ((line[i] == '\\') && (line[i + 1] == '"'))
                        {
                            sb.Append(line[i++]);
                        }
                        sb.Append(line[i++]);
                    }
                    i++;
                    arguments.Add(sb.ToString());
                }
                else
                {
                    StringBuilder sb = new StringBuilder();
                    while ((i < line.Length) && !Char.IsWhiteSpace(line[i]))
                    {
                        if ((line[i] == '\\') && (line[i + 1] == '"'))
                        {
                            sb.Append(line[i++]);
                        }
                        sb.Append(line[i++]);
                    }
                    arguments.Add(sb.ToString());
                }
            }

            return arguments.ToArray();
        }

        private static string Combine(string[] parts, int start, int count, string separator, bool quoteWhitespace)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = start; i < start + count; i++)
            {
                if (i > start)
                {
                    sb.Append(separator);
                }
                bool quote = quoteWhitespace && (String.IsNullOrEmpty(parts[i]) || Array.Exists(parts[i].ToCharArray(), delegate(char c) { return Char.IsWhiteSpace(c); }));
                if (quote)
                {
                    sb.Append('"');
                }
                sb.Append(parts[i]);
                if (quote)
                {
                    sb.Append('"');
                }
            }
            return sb.ToString();
        }

        private static string ReadInlineContent(LineReader scriptReader, string linePrefix, string ender, ref int lineNumber, List<int> wildcardLines)
        {
            string line;
            StringBuilder sb = new StringBuilder();
            int localLineNumber = 0;
            while ((line = scriptReader.ReadLine()) != null)
            {
                localLineNumber++;
                lineNumber++;

                if (line.StartsWith(linePrefix))
                {
                    sb.AppendLine(line.Substring(linePrefix.Length));
                }
                else if (line == ender)
                {
                    break;
                }
                else if (line.StartsWith("#"))
                {
                    localLineNumber--;
                    continue;
                }
                else if ((wildcardLines != null) && line.StartsWith("*"))
                {
                    wildcardLines.Add(localLineNumber);
                    sb.AppendLine(line.Substring(1));
                    continue;
                }
                else
                {
                    Throw(new ApplicationException());
                }
            }
            return sb.ToString();
        }

        private static bool CompareContent(string standard, string actual, int[] wildcardLines, bool skipExtraLines)
        {
            using (TextReader standardReader = new StringReader(standard))
            {
                using (TextReader actualReader = new StringReader(actual))
                {
                    int lineNumber = 0;
                    string lineActual, lineStandard;
                    while (true)
                    {
                        lineNumber++;
                        lineStandard = standardReader.ReadLine();
                        lineActual = actualReader.ReadLine();
                        if ((lineStandard == null) && (lineActual == null))
                        {
                            break;
                        }
                        if ((lineStandard == null) != (lineActual == null))
                        {
                            if (skipExtraLines && (lineStandard == null) && (lineActual != null))
                            {
                                return true;
                            }
                            return false;
                        }
                        if (Array.IndexOf(wildcardLines, lineNumber) >= 0)
                        {
                            if (!String.IsNullOrEmpty(lineStandard))
                            {
                                // http://msdn.microsoft.com/en-us/library/az24scfc%28v=vs.110%29.aspx
                                if (!Regex.IsMatch(lineActual, lineStandard))
                                {
                                    return false;
                                }
                            }
                            continue;
                        }
                        if (!String.Equals(lineStandard, lineActual))
                        {
                            return false;
                        }
                    }
                }
            }
            return true;
        }

        private static void WriteWithLinePrefix(TextWriter writer, string text, string linePrefix)
        {
            using (TextReader reader = new StringReader(text))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    writer.WriteLine(linePrefix + line);
                }
            }
        }

        private class HashDispenser
        {
            private Dictionary<string, int> hashes = new Dictionary<string, int>();

            internal HashDispenser()
            {
                hashes[ComputeHash(new byte[0])] = 0;
            }

            internal int GetNumber(string path)
            {
                string hashString = ComputeHash(File.ReadAllBytes(path));
                if (!hashes.ContainsKey(hashString))
                {
                    hashes[hashString] = hashes.Count;
                }
                return hashes[hashString];
            }

            private static string ComputeHash(byte[] data)
            {
                SHA256 sha256 = SHA256.Create();
                byte[] hashBytes = sha256.ComputeHash(data);
                char[] hashChars = new char[hashBytes.Length];
                for (int i = 0; i < hashChars.Length; i++)
                {
                    hashChars[i] = (char)hashBytes[i];
                }
                return new String(hashChars);
            }
        }

        private static string List(string root, HashDispenser hashes, string dateFormat, bool showSizes, bool showCompressed)
        {
            StringBuilder sb = new StringBuilder();
            using (TextWriter writer = new StringWriter(sb))
            {
                ListRecursive(root, writer, hashes, dateFormat, showSizes, showCompressed, root.Length + 1);
            }
            return sb.ToString();
        }

        private static void ListRecursive(string root, TextWriter writer, HashDispenser hashes, string dateFormat, bool showSizes, bool showCompressed, int substring)
        {
            if (!Path.IsPathRooted(root))
            {
                Throw(new ApplicationException());
            }

            foreach (string entry in Directory.GetFileSystemEntries(root))
            {
                string entryPrintable = entry.Substring(substring);
                bool isDirectory = Directory.Exists(entry);
                int hashNum = 0;
                if (!isDirectory)
                {
                    hashNum = hashes.GetNumber(entry);
                }
                string created = !isDirectory ? File.GetCreationTime(entry).ToString(dateFormat) : String.Empty;
                string lastModified = !isDirectory ? File.GetLastWriteTime(entry).ToString(dateFormat) : String.Empty;
                FileAttributes entryAttrs = File.GetAttributes(entry);
                string attrs = new String(
                    new char[]
                    {
                        ((entryAttrs & FileAttributes.ReadOnly) != 0) ? 'R' : '-',
                        ((entryAttrs & FileAttributes.Archive) != 0) ? 'A' : '-',
                        ((entryAttrs & FileAttributes.Hidden) != 0) ? 'H' : '-',
                        ((entryAttrs & FileAttributes.System) != 0) ? 'S' : '-',
                        !isDirectory && (GetFileLength(entry) == 0) ? 'Z' : '-',
                        ((entryAttrs & FileAttributes.Directory) != 0) ? 'D' : '-',
                    });
                if (showCompressed)
                {
                    attrs = String.Concat(attrs, new String(FileCompressionHelper.IsCompressed(entry) ? 'C' : '-', 1));
                }
                writer.WriteLine(" {0,19} {1,19} {2,5}{5} {3}{4}",
                    created,
                    lastModified,
                    attrs,
                    entryPrintable,
                    isDirectory ? new String(Path.DirectorySeparatorChar, 1) : String.Format(" [{0}]", hashNum),
                    showSizes ? String.Format("{0,12}", !isDirectory ? GetFileLength(entry).ToString() : String.Empty) : String.Empty);
                if (isDirectory)
                {
                    ListRecursive(entry, writer, hashes, dateFormat, showSizes, showCompressed, substring);
                }
            }
        }

        private static Object openCoverLock; // created in Main() to avoid issues with deferred static construction
        private static string coverageReportsPath;
        private static int coverageResultsCounter;
        private static string openCoverExe;
        private static TextWriter openCoverFileMapLog;

        private static bool Exec(string program, bool opencover, string arguments, string input, int? commandTimeoutSeconds, Workspace workspace, string scriptName, int lineNumber, out int exitCode, out string output)
        {
            if (opencover)
            {
                lock (openCoverLock)
                {
                    if (openCoverExe == null)
                    {
                        string[] paths = new string[]
                        {
                            Path.Combine(Environment.GetEnvironmentVariable("ProgramFiles"), "OpenCover"),
                            Path.Combine(Environment.GetEnvironmentVariable("ProgramFiles(x86)"), "OpenCover"),
                            Path.Combine(Environment.GetEnvironmentVariable("USERPROFILE"), @"Local Settings\Application Data\Apps\OpenCover"),
                        };
                        foreach (string openCoverHome in paths)
                        {
                            string openCoverExeCandidate = Path.Combine(openCoverHome, "OpenCover.Console.exe");
                            if (Directory.Exists(openCoverHome) && File.Exists(program))
                            {
                                openCoverExe = openCoverExeCandidate;
                                goto FoundOpenCover;
                            }
                        }
                        Throw(new ApplicationException("Could not find OpenCover in the usual places - make sure it is installed"));
                    FoundOpenCover:
                        ;
                    }

                    int coverageResultsIndex = Interlocked.Increment(ref coverageResultsCounter);

                    arguments = arguments.Replace("\"", "\\\"");
                    string resultsFile = String.Format("result{0:0000000000}.xml", coverageResultsIndex);
                    arguments = String.Format("-register \"-target:{0}\" \"-targetargs:{1}\" \"-output:{2}\" -returntargetcode -log:Off", program, arguments, Path.Combine(coverageReportsPath, resultsFile));

                    if (openCoverFileMapLog == null)
                    {
                        openCoverFileMapLog = TextWriter.Synchronized(new StreamWriter(Path.Combine(coverageReportsPath, "opencovermap.log")));
                        openCoverFileMapLog.WriteLine("Map from OpenCover results file name to script file and line number of invoking command:");
                        openCoverFileMapLog.WriteLine();
                    }
                    openCoverFileMapLog.WriteLine("\"{0}\" --> \"{1}\", line {2}", resultsFile, scriptName, lineNumber);
                    openCoverFileMapLog.Flush();

                    program = openCoverExe;
                }
            }

            bool killed = false;
            exitCode = 0;
            output = null;

            StringBuilder output2 = new StringBuilder();
            using (TextWriter outputWriter = TextWriter.Synchronized(new StringWriter(output2)))
            {
                using (Process cmd = new Process())
                {
                    cmd.StartInfo.Arguments = arguments;
                    cmd.StartInfo.CreateNoWindow = true;
                    cmd.StartInfo.FileName = program;
                    cmd.StartInfo.UseShellExecute = false;
                    cmd.StartInfo.WorkingDirectory = workspace.Root;
                    if (input != null)
                    {
                        cmd.StartInfo.RedirectStandardInput = true;
                    }
                    cmd.StartInfo.RedirectStandardOutput = true;
                    cmd.StartInfo.RedirectStandardError = true;
                    cmd.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) { outputWriter.WriteLine(e.Data); } };
                    cmd.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) { outputWriter.WriteLine(e.Data); } };

                    cmd.Start();
                    cmd.BeginOutputReadLine();
                    cmd.BeginErrorReadLine();
                    if (input != null)
                    {
                        using (TextWriter inputWriter = cmd.StandardInput)
                        {
                            inputWriter.Write(input);
                        }
                    }
                    cmd.WaitForExit(commandTimeoutSeconds.HasValue ? (int)Math.Min((long)commandTimeoutSeconds.Value * 1000, Int32.MaxValue - 1) : Int32.MaxValue);
                    if (!cmd.HasExited)
                    {
                        cmd.Kill();
                        cmd.WaitForExit();
                        killed = true;
                    }
                    cmd.CancelOutputRead();
                    cmd.CancelErrorRead();
                    exitCode = cmd.ExitCode;
                }
            }
            output = output2.ToString();
            if (opencover)
            {
                if (output.StartsWith("Executing: "))
                {
                    int firstLineEnd = output.IndexOf(Environment.NewLine) + Environment.NewLine.Length;
                    output = output.Substring(firstLineEnd);
                }
            }
            return !killed;
        }

        private static string CheckPath(string path, int lineNumber)
        {
            if (String.IsNullOrEmpty(path) || Path.IsPathRooted(path))
            {
                Throw(new ApplicationException(String.Format("Invalid path \"{0}\" on line {1}", path, lineNumber)));
            }

            Stack<string> parts = new Stack<string>();
            foreach (string part in path.Split(new char[] { Path.DirectorySeparatorChar }))
            {
                if (part == ".")
                {
                    continue;
                }
                else if (part == "..")
                {
                    if (parts.Count == 0)
                    {
                        Throw(new ApplicationException(String.Format("Invalid path \"{0}\" on line {1}", path, lineNumber)));
                    }
                    parts.Pop();
                }
                else
                {
                    if (part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                    {
                        Throw(new ApplicationException(String.Format("Invalid path \"{0}\" on line {1}", path, lineNumber)));
                    }
                    parts.Push(part);
                }
            }

            StringBuilder sb = new StringBuilder(path.Length);
            if (parts.Count == 0)
            {
                sb.Append(".");
            }
            else
            {
                string[] parts2 = parts.ToArray();
                Array.Reverse(parts2);
                foreach (string part in parts2)
                {
                    if (sb.Length > 0)
                    {
                        sb.Append(Path.DirectorySeparatorChar);
                    }
                    sb.Append(part);
                }
            }

            return sb.ToString();
        }

        private static long GetFileLength(string path)
        {
            if (!Path.IsPathRooted(path))
            {
                Throw(new ApplicationException());
            }

            using (Stream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                return stream.Length;
            }
        }

        private static void DeleteDirectory(string path)
        {
            if (!Path.IsPathRooted(path))
            {
                Throw(new ApplicationException());
            }

            foreach (string subdirectory in Directory.GetDirectories(path))
            {
                DeleteDirectory(subdirectory);
            }

            foreach (string file in Directory.GetFiles(path))
            {
                File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.ReadOnly);
                File.Delete(file);
            }

            Directory.Delete(path);
        }

        private class TestResultMatrix
        {
            private ScriptInfo[] scripts = new ScriptInfo[0];
            private int skippedTests;

            private class ScriptInfo
            {
                internal readonly string scriptName;
                internal ModuleInfo[] modules = new ModuleInfo[0];

                internal ScriptInfo(string scriptName)
                {
                    this.scriptName = scriptName;
                }
            }

            private class ModuleInfo
            {
                internal readonly string moduleName;
                internal TestInfo[] tests = new TestInfo[0];

                internal ModuleInfo(string moduleName)
                {
                    this.moduleName = moduleName;
                }
            }

            private class TestInfo
            {
                internal readonly string testName;
                internal bool passed = true;
                internal int lineNumber = -1;

                internal TestInfo(string testName)
                {
                    this.testName = testName;
                }
            }

            public void InitTest(int scriptNumber, string scriptName, int moduleNumber, string moduleName, int testNumber, string testName)
            {
                lock (this)
                {
                    if (scripts.Length < scriptNumber)
                    {
                        Array.Resize(ref scripts, scriptNumber);
                    }
                    if (scripts[scriptNumber - 1] == null)
                    {
                        scripts[scriptNumber - 1] = new ScriptInfo(scriptName);
                    }
                    ScriptInfo script = scripts[scriptNumber - 1];

                    if (script.modules.Length < moduleNumber)
                    {
                        Array.Resize(ref script.modules, moduleNumber);
                    }
                    if (script.modules[moduleNumber - 1] == null)
                    {
                        script.modules[moduleNumber - 1] = new ModuleInfo(moduleName);
                    }
                    ModuleInfo module = script.modules[moduleNumber - 1];

                    if (module.tests.Length < testNumber)
                    {
                        Array.Resize(ref module.tests, testNumber);
                    }
                    if (module.tests[testNumber - 1] == null)
                    {
                        module.tests[testNumber - 1] = new TestInfo(testName);
                    }
                    TestInfo testInfo = module.tests[testNumber - 1];
                }
            }

            public void Failed(int scriptNumber, int moduleNumber, int testNumber, int lineNumber)
            {
                lock (this)
                {
                    TestInfo testInfo = scripts[scriptNumber - 1].modules[moduleNumber - 1].tests[testNumber - 1];
                    testInfo.passed = false;
                    testInfo.lineNumber = lineNumber;
                }
            }

            public void Skipped()
            {
                lock (this)
                {
                    skippedTests++;
                }
            }

            public void EnumerateResults(bool write, out int failCount, out int passCount, out int skipCount)
            {
                lock (this)
                {
                    failCount = 0;
                    passCount = 0;
                    skipCount = skippedTests;
                    for (int scriptNumber = 1; scriptNumber <= scripts.Length; scriptNumber++)
                    {
                        ScriptInfo script = scripts[scriptNumber - 1];
                        if (script != null)
                        {
                            if (write)
                            {
                                Console.WriteLine("SCRIPT \"{0}\" ({1})", script.scriptName, scriptNumber);
                            }
                            for (int moduleNumber = 1; moduleNumber <= script.modules.Length; moduleNumber++)
                            {
                                ModuleInfo modules = script.modules[moduleNumber - 1];
                                if (modules != null)
                                {
                                    if (write)
                                    {
                                        Console.WriteLine("  MODULE {0} ({1})", modules.moduleName, moduleNumber);
                                    }
                                    for (int testNumber = 1; testNumber <= modules.tests.Length; testNumber++)
                                    {
                                        TestInfo test = modules.tests[testNumber - 1];
                                        if (write)
                                        {
                                            ConsoleColor oldColor = Console.ForegroundColor;
                                            if (!test.passed)
                                            {
                                                Console.ForegroundColor = ConsoleColor.Yellow;
                                            }
                                            Console.WriteLine("    {0,6} : TEST {1} ({2}){3}", test.passed ? "passed" : "FAILED", test.testName, testNumber, test.passed ? String.Empty : String.Format(" at line {0}", test.lineNumber));
                                            Console.ForegroundColor = oldColor;
                                        }

                                        if (!test.passed)
                                        {
                                            failCount++;
                                        }
                                        else
                                        {
                                            passCount++;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        private const string Hex = "0123456789abcdef";

        private static byte[] BinaryDecode(string linePrefix, TextReader reader)
        {
            bool deflated = false;

            List<byte> result = new List<byte>();

            string line;
            while ((line = reader.ReadLine()) != null)
            {
                if (line.StartsWith(linePrefix))
                {
                    line = line.Substring(linePrefix.Length);
                }
                if ((result.Count == 0) && line.Equals("deflate", StringComparison.OrdinalIgnoreCase))
                {
                    deflated = true;
                    continue;
                }
                for (int i = 0; i < line.Length; )
                {
                    if (Char.IsWhiteSpace(line[i]))
                    {
                        i++;
                        continue;
                    }
                    if (!(i + 1 < line.Length))
                    {
                        Throw(new ApplicationException());
                    }
                    byte b = (byte)((Hex.IndexOf(Char.ToLowerInvariant(line[i])) << 4)
                        | Hex.IndexOf(Char.ToLowerInvariant(line[i + 1])));
                    i += 2;
                    result.Add(b);
                }
            }

            if (deflated)
            {
                using (MemoryStream stream = new MemoryStream(result.ToArray()))
                {
                    result.Clear();
                    using (Stream decompressor = new DeflateStream(stream, CompressionMode.Decompress, true/*leaveOpen*/))
                    {
                        byte[] buffer = new byte[4096];
                        int read;
                        while ((read = decompressor.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            for (int i = 0; i < read; i++)
                            {
                                result.Add(buffer[i]);
                            }
                        }
                    }
                }
            }

            return result.ToArray();
        }

        private static string BinaryEncode(string linePrefix, byte[] data, bool? compress)
        {
            bool deflated = false;
            if (!(compress.HasValue && !compress.Value))
            {
                byte[] compressed;
                using (MemoryStream stream = new MemoryStream(data.Length))
                {
                    using (Stream compressor = new DeflateStream(stream, CompressionMode.Compress, true/*leaveOpen*/))
                    {
                        compressor.Write(data, 0, data.Length);
                    }
                    compressed = stream.ToArray();
                }

                if ((compress.HasValue && compress.Value) || (compressed.Length < data.Length))
                {
                    deflated = true;
                    data = compressed;
                }
            }

            StringBuilder sb = new StringBuilder(data.Length * 3);

            if (deflated)
            {
                sb.AppendLine(".deflate");
            }

            const int BytesPerLine = 64;
            const int BytesPerGroup = 16;
            for (int i = 0; i < data.Length; i++)
            {
                if (i % BytesPerLine == 0)
                {
                    if (i > 0)
                    {
                        sb.AppendLine();
                    }
                    sb.Append('.');
                }
                else
                {
                    if (i % BytesPerGroup == 0)
                    {
                        sb.Append(' ');
                    }
                }
                sb.Append(Hex[data[i] >> 4]);
                sb.Append(Hex[data[i] & 0x0f]);
            }
            sb.AppendLine();

            return sb.ToString();
        }

        public class Workspace : IDisposable
        {
            public readonly string Root;

            public Workspace(string root)
            {
                if (!Path.IsPathRooted(root))
                {
                    Throw(new ApplicationException());
                }

                Root = root;
            }

            public void Dispose()
            {
                try
                {
                    DeleteDirectory(Root);
                }
                catch (Exception)
                {
                    // This failure usually occurs because two reasons:
                    // 1. Some process is still running (usually a hung test exe or windiff)
                    // 2. Some object *in this process* has a filesystem reference to one of the
                    //    files and was leaked (i.e. Dispose() wasn't called on it)
                }
            }
        }

        public class WorkspaceDispenser
        {
            private readonly string collection;
            private int serial;

            public WorkspaceDispenser()
            {
                collection = Path.Combine(Path.GetTempPath(), WorkspaceRootCollection);

                try
                {
                    Directory.CreateDirectory(collection);
                    DeleteDirectory(collection);
                }
                catch (Exception exception)
                {
                    // This failure usually occurs because two reasons:
                    // 1. Some process is still running (usually a hung test exe or windiff)
                    // 2. Some object *in this process* has a filesystem reference to one of the
                    //    files and was leaked (i.e. Dispose() wasn't called on it)
                    throw new ApplicationException("Unable to empty workspace directory", exception);
                }

                Directory.CreateDirectory(collection);
            }

            public Workspace CreateWorkspace()
            {
                lock (this)
                {
                    while (true)
                    {
                        string root = Path.Combine(collection, (serial++).ToString());
                        if (!Directory.Exists(root))
                        {
                            Directory.CreateDirectory(root);
                            return new Workspace(root);
                        }
                    }
                }
            }
        }

        private class LineReader
        {
            private string[] lines;
            private int next;
            private int limit;

            public LineReader()
            {
                lines = new string[0];
                limit = Int32.MaxValue;
            }

            public LineReader(string path)
            {
                lines = File.ReadAllLines(path);
                limit = Int32.MaxValue;
            }

            public LineReader(string[] lines)
            {
                this.lines = lines;
                limit = Int32.MaxValue;
            }

            public LineReader(LineReader original, int limit)
            {
                this.lines = original.lines;
                this.next = original.next;
                this.limit = limit;
            }

            public LineReader(LineReader original)
                : this(original, original.limit)
            {
            }

            public string ReadLine()
            {
                if (limit == 0)
                {
                    return null;
                }

                if (next < lines.Length)
                {
                    limit--;
                    return lines[next++];
                }
                return null;
            }
        }

        private class MulticastWriter : TextWriter
        {
            private TextWriter[] writers;

            public MulticastWriter(TextWriter[] writers)
            {
                this.writers = writers;
            }

            public MulticastWriter(TextWriter one, TextWriter two)
                : this(new TextWriter[] { one, two })
            {
            }

            protected override void Dispose(bool disposing)
            {
                foreach (TextWriter writer in writers)
                {
                    writer.Close();
                }
                writers = null;
            }

            public override void Flush()
            {
                foreach (TextWriter writer in writers)
                {
                    writer.Flush();
                }
            }

            public override Encoding Encoding
            {
                get
                {
                    return Encoding.UTF8;
                }
            }

            public override void Write(char value)
            {
                foreach (TextWriter writer in writers)
                {
                    writer.Write(value);
                }
            }

            public override void Write(string value)
            {
                foreach (TextWriter writer in writers)
                {
                    writer.Write(value);
                }
            }

            public override void WriteLine(String value)
            {
                foreach (TextWriter writer in writers)
                {
                    writer.WriteLine(value);
                }
            }
        }

        private static class ProtectedDataStorageHelpers
        {
            public static string EncryptMemory(string plaintext)
            {
                byte[] data = Encoding.UTF8.GetBytes(plaintext);
                byte[] encryptedData = ProtectedDataStorage.EncryptEphemeral(data, 0, data.Length, ProtectedDataStorage.EphemeralScope.SameLogon);
                return HexUtility.HexEncode(encryptedData);
            }

            public static string DecryptMemory(string ciphertext)
            {
                byte[] encryptedData = HexUtility.HexDecode(ciphertext);
                using (ProtectedArray<byte> data = ProtectedDataStorage.DecryptEphemeral(encryptedData, 0, encryptedData.Length, ProtectedDataStorage.EphemeralScope.SameLogon))
                {
                    data.Reveal();
                    return Encoding.UTF8.GetString(data.ExposeArray());
                }
            }

            private const int PersistentEncryptionSecondaryEntropyLength = 32;

            public static string EncryptUserPersistent(string plaintext)
            {
                byte[] data = Encoding.UTF8.GetBytes(plaintext);
                byte[] entropy = new byte[PersistentEncryptionSecondaryEntropyLength];
                RNGCryptoServiceProvider.Create().GetBytes(entropy);
                byte[] encryptedData = ProtectedDataStorage.EncryptPersistent(data, 0, data.Length, entropy);
                Array.Resize(ref encryptedData, encryptedData.Length + PersistentEncryptionSecondaryEntropyLength);
                Array.Copy(encryptedData, 0, encryptedData, PersistentEncryptionSecondaryEntropyLength, encryptedData.Length - PersistentEncryptionSecondaryEntropyLength);
                Array.Copy(entropy, 0, encryptedData, 0, PersistentEncryptionSecondaryEntropyLength);
                return HexUtility.HexEncode(encryptedData);
            }

            public static string DecryptUserPersistent(string ciphertext)
            {
                byte[] encryptedData = HexUtility.HexDecode(ciphertext);
                byte[] entropy = new byte[PersistentEncryptionSecondaryEntropyLength];
                Array.Copy(encryptedData, 0, entropy, 0, PersistentEncryptionSecondaryEntropyLength);
                Array.Copy(encryptedData, PersistentEncryptionSecondaryEntropyLength, encryptedData, 0, encryptedData.Length - PersistentEncryptionSecondaryEntropyLength);
                Array.Resize(ref encryptedData, encryptedData.Length - PersistentEncryptionSecondaryEntropyLength);
                using (ProtectedArray<byte> data = ProtectedDataStorage.DecryptPersistent(encryptedData, 0, encryptedData.Length, entropy))
                {
                    data.Reveal();
                    return Encoding.UTF8.GetString(data.ExposeArray());
                }
            }
        }

        static void Main(string[] args)
        {
            // special hacks
            if ((args.Length >= 2) && (args[0] == "-binaryencode"))
            {
                Console.WriteLine(BinaryEncode(".", File.ReadAllBytes(args[1]), args.Length > 2 ? (args[2] == "-compress" ? (bool?)true : args[2] == "-nocompress" ? (bool?)false : (bool?)null) : (bool?)null));
                return;
            }
            else if ((args.Length >= 2) && (args[0] == "-binarydecode"))
            {
                File.WriteAllBytes(args[1], BinaryDecode(".", Console.In));
                return;
            }
            else if ((args.Length >= 2) && (args[0] == "-decryptmemory"))
            {
                Console.WriteLine(ProtectedDataStorageHelpers.DecryptMemory(args[1]));
                return;
            }
            else if ((args.Length >= 2) && (args[0] == "-decryptuserpersistent"))
            {
                Console.WriteLine(ProtectedDataStorageHelpers.DecryptUserPersistent(args[1]));
                return;
            }
            else if ((args.Length >= 2) && (args[0] == "-encryptmemory"))
            {
                Console.WriteLine(ProtectedDataStorageHelpers.EncryptMemory(args[1]));
                return;
            }
            else if ((args.Length >= 2) && (args[0] == "-encryptuserpersistent"))
            {
                Console.WriteLine(ProtectedDataStorageHelpers.EncryptUserPersistent(args[1]));
                return;
            }


            // program switches

            if ((args.Length >= 1) && (args[0] == "-argsfromfile"))
            {
                string[] insertArgs;
                using (TextReader reader = new StreamReader(args[1]))
                {
                    string line = reader.ReadLine();
                    if (!line.StartsWith("#"))
                    {
                        throw new ApplicationException();
                    }
                    insertArgs = ParseArguments(Environment.ExpandEnvironmentVariables(line.Substring(1)));
                }

                List<string> args2 = new List<string>();
                args2.AddRange(insertArgs);
                args2.AddRange(new List<string>(args).GetRange(1, args.Length - 1));
                args = args2.ToArray();
            }

            int concurrency = 0;
            if ((args.Length >= 2) && (args[0] == "-concurrency"))
            {
                if (String.Equals(args[1], "*") || String.Equals(args[1], "default"))
                {
                    concurrency = Int32.Parse(Environment.GetEnvironmentVariable("NUMBER_OF_PROCESSORS"));
                }
                else
                {
                    concurrency = Int32.Parse(args[1]);
                }
                Array.Copy(args, 2, args, 0, args.Length - 2);
                Array.Resize(ref args, args.Length - 2);
            }
            if (concurrency > 0)
            {
                Console.WriteLine("Running concurrently with {0} task threads", concurrency);
            }

            TextWriter consoleExclusiveOut = Console.Out;
            string consoleLogPath = null;
            if ((args.Length >= 2) && (args[0] == "-log"))
            {
                consoleLogPath = Path.GetFullPath(args[1]);
                Array.Copy(args, 2, args, 0, args.Length - 2);
                Array.Resize(ref args, args.Length - 2);
            }
            if (consoleLogPath != null)
            {
                TextWriter logWriter = new StreamWriter(consoleLogPath, false/*append*/, Encoding.UTF8);
                TextWriter consoleWriter = Console.Out;
                Console.SetOut(new MulticastWriter(logWriter, consoleWriter));
            }

            bool orderedOutput = false;
            if ((args.Length >= 1) && (args[0] == "-orderedoutput"))
            {
                orderedOutput = true;
                Array.Copy(args, 1, args, 0, args.Length - 1);
                Array.Resize(ref args, args.Length - 1);
            }

            string taskHistoryPath = null;
            if ((args.Length >= 2) && (args[0] == "-history"))
            {
                taskHistoryPath = Path.GetFullPath(args[1]);
                Array.Copy(args, 2, args, 0, args.Length - 2);
                Array.Resize(ref args, args.Length - 2);
            }


            // main

            Environment.ExitCode = 2;

            openCoverLock = new Object();

            WorkspaceDispenser workspaceDispenser = new WorkspaceDispenser();

            coverageReportsPath = Path.Combine(Path.GetTempPath(), CodeCoverageReports);
            try
            {
                Directory.Delete(coverageReportsPath, true/*recursive*/);
            }
            catch
            {
            }
            Directory.CreateDirectory(coverageReportsPath);
            if (Directory.GetFileSystemEntries(coverageReportsPath).Length > 0)
            {
                Throw(new ApplicationException(String.Format("Unable to empty/create {0}", coverageReportsPath)));
            }
            try
            {
                FileCompressionHelper.SetCompressed(coverageReportsPath, true);
            }
            catch
            {
            }

            List<string> scripts = new List<string>();
            foreach (string manifest in args)
            {
                string manifestPath = Path.GetFullPath(manifest);
                Console.WriteLine("Manifest: \"{0}\"", manifestPath);
                if (File.Exists(manifestPath))
                {
                    using (TextReader reader = new StreamReader(manifestPath))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            if (line.StartsWith("#"))
                            {
                                continue;
                            }
                            line = line.Trim();
                            if (String.IsNullOrEmpty(line))
                            {
                                continue;
                            }

                            string scriptPath = line;
                            if (!Path.IsPathRooted(scriptPath))
                            {
                                string scriptPath2 = Path.Combine(Path.GetDirectoryName(manifestPath), scriptPath);
                                if (!File.Exists(scriptPath2))
                                {
                                    scriptPath2 = Path.GetFullPath(scriptPath);
                                }
                                scriptPath = scriptPath2;
                            }
                            scripts.Add(scriptPath);
                        }
                    }
                }
                else if (Directory.Exists(manifestPath))
                {
                    foreach (string scriptPath in Directory.GetFiles(manifestPath))
                    {
                        scripts.Add(scriptPath);
                    }
                }
                else
                {
                    Throw(new ApplicationException(String.Format("{0} does not exist", manifestPath)));
                }
            }
            Console.WriteLine();

            Environment.CurrentDirectory = Path.GetTempPath(); // try to fail uses of relative paths

            TaskHistory taskHistory = new TaskHistory();
            if (taskHistoryPath != null)
            {
                try
                {
                    taskHistory = new TaskHistory(taskHistoryPath);
                }
                catch (FileNotFoundException)
                {
                }
                catch (DirectoryNotFoundException)
                {
                }
                consoleExclusiveOut.WriteLine("Loaded {0} history records from previous runs", taskHistory.Count);
            }

            TestResultMatrix resultMatrix = new TestResultMatrix();

            DateTime programStartTime = DateTime.UtcNow;
            Console.WriteLine(programStartTime.ToLocalTime());
            Console.WriteLine();
            Console.WriteLine();
            SharedContext sharedContext = new SharedContext();
            if (concurrency == 0)
            {
                for (int i = 0; i < scripts.Count; i++)
                {
                    string scriptPath = scripts[i];

                    if (consoleLogPath == null)
                    {
                        // only write header if not logging - for output comparability between concurrent and non-concurrent modes
                        Console.WriteLine();
                        Console.WriteLine();
                        Console.WriteLine(new String('-', Console.BufferWidth - 1));
                        Console.WriteLine("SCRIPT \"{0}\" ({1})", scriptPath, i + 1);
                    }

                    Console.Title = String.Format("{0} - {1}", Path.GetFileName(Process.GetCurrentProcess().MainModule.FileName), Path.GetFileName(scriptPath));
                    Eval(
                        new LineReader(scriptPath),
                        0,
                        scriptPath,
                        new Context(i + 1, resultMatrix, workspaceDispenser),
                        Mode.Unrestricted,
                        Console.Out,
                        taskHistory,
                        sharedContext);
                }
            }
            else
            {
                TaskQueue taskQueue = new TaskQueue();

                using (ConcurrentMessageLog messagesLog = concurrency > 0 ? new ConcurrentMessageLog(true/*interactive*/, orderedOutput/*enableSequencing*/) : null)
                {
                    using (ConcurrentTasks concurrent = concurrency > 0 ? new ConcurrentTasks(concurrency, 0, messagesLog, null/*trace*/) : null)
                    {
                        for (int i = 0; i < scripts.Count; i++)
                        {
                            List<TaskQueue.Task> tasks = Eval(
                                new LineReader(scripts[i]),
                                0,
                                scripts[i],
                                new Context(i + 1, resultMatrix, workspaceDispenser),
                                Mode.PrepareTasks,
                                null/*consoleWriter*/,
                                taskHistory,
                                sharedContext);
                            taskQueue.Add(tasks);
                        }

                        taskQueue.Prepare(concurrency == 1, orderedOutput ? messagesLog : null, taskHistory);

                        int total = taskQueue.Count;

                        int maxStatusLines = 0;
                        bool progressVisible = false;
                        DateTime lastProgressUpdate = default(DateTime);
                        const int WaitInterval = 1000;
                        TaskQueue.Status[] statuses = new TaskQueue.Status[concurrency];
                        ConcurrentTasks.WaitIntervalMethod eraseProgress = delegate()
                        {
                            if (progressVisible)
                            {
                                for (int i = 0; i < maxStatusLines; i++)
                                {
                                    consoleExclusiveOut.WriteLine(new String(' ', Math.Max(0, Console.BufferWidth - 1)));
                                }
                                Console.CursorTop -= maxStatusLines;

                                progressVisible = false;
                                lastProgressUpdate = default(DateTime);
                            }
                        };
                        ConcurrentMessageLog.PrepareConsoleMethod prepareConsole = delegate()
                        {
                            eraseProgress();
                        };
                        ConcurrentTasks.WaitIntervalMethod showProgress = delegate()
                        {
                            messagesLog.Flush(prepareConsole);

                            while (Console.KeyAvailable)
                            {
                                ConsoleKeyInfo key = Console.ReadKey(true/*intercept*/);
                                if (key.KeyChar == 'q')
                                {
                                    taskQueue.SetFatal();
                                }
                            }

                            if (lastProgressUpdate.AddMilliseconds(WaitInterval - 100) <= DateTime.UtcNow)
                            {
                                lock (statuses)
                                {
                                    List<KeyValuePair<string, ConsoleColor?>> lines = new List<KeyValuePair<string, ConsoleColor?>>();

                                    lines.Add(new KeyValuePair<string, ConsoleColor?>(String.Empty, null));
                                    lines.Add(new KeyValuePair<string, ConsoleColor?>(String.Empty, null));

                                    if (taskQueue.Fatal)
                                    {
                                        lines.Add(new KeyValuePair<string, ConsoleColor?>("  [fatal error pending]", ConsoleColor.Yellow));
                                    }

                                    for (int i = 0; i < statuses.Length; i++)
                                    {
                                        string scriptName, moduleName;
                                        int moduleNumber;
                                        DateTime startTime;
                                        statuses[i].GetStatus(out scriptName, out moduleName, out moduleNumber, out startTime);

                                        string progress = !String.IsNullOrEmpty(scriptName) ? String.Format("  {2,3} sec  {0}: module {1} ({3})", Path.GetFileName(scriptName), moduleName, (int)(DateTime.UtcNow - startTime).TotalSeconds, moduleNumber) : String.Empty;
                                        lines.Add(new KeyValuePair<string, ConsoleColor?>(progress, null));
                                    }

                                    int failCount2, passCount2, skipCount2;
                                    resultMatrix.EnumerateResults(false/*write*/, out failCount2, out passCount2, out skipCount2);
                                    lines.Add(new KeyValuePair<string, ConsoleColor?>(String.Format("  {0}/{1} modules remaining;  tests: failed={2} skipped={3} passed={4}", taskQueue.Count, total, failCount2, skipCount2, passCount2), null));

                                    while (lines.Count < maxStatusLines)
                                    {
                                        lines.Add(new KeyValuePair<string, ConsoleColor?>(String.Empty, null));
                                    }
                                    maxStatusLines = lines.Count;

                                    foreach (KeyValuePair<string, ConsoleColor?> line in lines)
                                    {
                                        ConsoleColor? oldConsoleColor = null;
                                        if (line.Value.HasValue)
                                        {
                                            oldConsoleColor = Console.ForegroundColor;
                                            Console.ForegroundColor = line.Value.Value;
                                        }
                                        consoleExclusiveOut.WriteLine(line.Key + new String(' ', Math.Max(0, Console.BufferWidth - 1 - line.Key.Length)));
                                        if (oldConsoleColor.HasValue)
                                        {
                                            Console.ForegroundColor = oldConsoleColor.Value;
                                        }
                                    }
                                    Console.CursorTop -= lines.Count;
                                    progressVisible = true;
                                }

                                lastProgressUpdate = DateTime.UtcNow;

                                string title = String.Format("{0} - {1}/{2}", Path.GetFileName(Process.GetCurrentProcess().MainModule.FileName), total - taskQueue.Count, total);
                                if (!String.Equals(title, Console.Title))
                                {
                                    Console.Title = title;
                                }
                            }
                        };

                        for (int i = 0; i < concurrency; i++)
                        {
                            if (i > 0)
                            {
                                Thread.Sleep(50);
                            }
                            TaskQueue.Status status = statuses[i] = new TaskQueue.Status();
                            concurrent.Do(
                                null,
                                delegate(ConcurrentTasks.ITaskContext context)
                                {
                                    taskQueue.ThreadMain(messagesLog, status);
                                });
                        }
                        concurrent.Drain(showProgress, WaitInterval);
                        messagesLog.Flush(prepareConsole);
                    }
                }

                if (taskQueue.Fatal)
                {
                    Console.WriteLine();
                    Console.WriteLine();
                    ConsoleColor oldColor = Console.ForegroundColor;
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("FATAL EXCEPTION OCCURRED RUNNING TESTS");
                    Console.ForegroundColor = oldColor;
                    Console.WriteLine();
                    Console.WriteLine();
                }
            }

            Console.Title = String.Format("{0} - {1}", Path.GetFileName(Process.GetCurrentProcess().MainModule.FileName), "Finished");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("finished - total run time {0:g}", DateTime.UtcNow - programStartTime);
            Console.WriteLine();
            Console.WriteLine();
            int failCount, passCount, skipCount;
            resultMatrix.EnumerateResults(true/*write*/, out failCount, out passCount, out skipCount);
            Console.WriteLine();
            Console.WriteLine("failed={0} skipped={1} passed={2}", failCount, skipCount, passCount);
            Console.WriteLine();
            Console.Out.Flush();

            if (taskHistoryPath != null)
            {
                taskHistory.Save(taskHistoryPath);
            }
            if (openCoverFileMapLog != null)
            {
                openCoverFileMapLog.Close();
            }

            if (Debugger.IsAttached)
            {
                Console.ReadLine();
            }

            Environment.ExitCode = failCount > 0 ? 1 : 0;
        }
    }
}
