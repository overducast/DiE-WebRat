using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace DiE_WebRat
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        static extern bool SetWindowText(IntPtr hWnd, string text);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("psapi.dll", SetLastError = true)]
        static extern bool EmptyWorkingSet(IntPtr hProcess);

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public long Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        struct MEMORY_BASIC_INFORMATION { public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct MEMORYSTATUSEX { public uint dwLength; public uint dwMemoryLoad; public ulong ullTotalPhys; public ulong ullAvailPhys; public ulong ullTotalPageFile; public ulong ullAvailPageFile; public ulong ullTotalVirtual; public ulong ullAvailVirtual; public ulong ullAvailExtendedVirtual; }

        private static Mutex singleInstanceMutex;
        private const string Chars = "01V8YutSgDmzEX8pK3gimydac1Sn2eWa9g3z";
        private static readonly Random Rnd = new Random();

        static byte[][] rawPatterns = new byte[][]
        {
            new byte[] { 0x6D, 0x61, 0x69, 0x6E, 0x2E, 0x64, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x44, 0x61, 0x74, 0x61, 0x45, 0x64, 0x67, 0x65, 0x00 }, // main.decryptDataEdge
            new byte[] { 0x6D, 0x61, 0x69, 0x6E, 0x2E, 0x64, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x44, 0x61, 0x74, 0x61, 0x42, 0x72, 0x61, 0x76, 0x65, 0x00 },// main.decryptDataBrave
            new byte[] { 0x6D, 0x61, 0x69, 0x6E, 0x2E, 0x73, 0x74, 0x61, 0x72, 0x74, 0x4B, 0x65, 0x79, 0x6C, 0x6F, 0x67, 0x67, 0x65, 0x72, 0x00 },// main.startKeylogger
            new byte[] { 0x6D, 0x61, 0x69, 0x6E, 0x2E, 0x73, 0x74, 0x6F, 0x70, 0x4B, 0x65, 0x79, 0x6C, 0x6F, 0x67, 0x67, 0x65, 0x72, 0x00 },// main.stopKeylogger
            new byte[] { 0x6D, 0x61, 0x69, 0x6E, 0x2E, 0x72, 0x75, 0x6E, 0x4B, 0x65, 0x79, 0x6C, 0x6F, 0x67, 0x67, 0x65, 0x72, 0x00 },// main.runKeylogger
            new byte[] { 0x6D, 0x61, 0x69, 0x6E, 0x2E, 0x53, 0x74, 0x65, 0x61, 0x6C, 0x00 }// main.Steal
            /* 
            you can add more rules for detect what i collect, 
            Login Data
6C 6F 67 69 6E 20 44 61 74 61

Cookies
43 6F 6F 6B 69 65 73

Local State
4C 6F 63 61 6C 20 53 74 61 74 65

History
48 69 73 74 6F 72 79

Web Data
57 65 62 20 44 61 74 61

config.vdf
63 6F 6E 66 69 67 2E 76 64 66

AccountId-
41 63 63 6F 75 6E 74 49 64 2D

WRONG JSON
57 52 4F 4E 47 20 4A 53 4F 4E

GOT RESULT
47 4F 54 20 52 45 53 55 4C 54

call stuck
63 61 6C 6C 20 73 74 75 63 6B

ENCKEY ERR
45 4E 43 4B 45 59 20 45 52 52

NO PREAPPB
4E 4F 20 50 52 45 41 50 50 42

myhostname
6D 79 68 6F 73 74 6E 61 6D 65*/
        };

        static int[][] bmhShiftTables;

        static void Main(string[] args)
        {
            singleInstanceMutex = new Mutex(true, "Local\\DiEWebRat_SingleInstance", out bool isFirst); // neuro mutex 
            if (!isFirst) return;

            if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return;

            IntPtr hw = GetConsoleWindow();
            Task.Run(() =>
            {
                while (true)
                {
                    int titleLen = Rnd.Next(6, 12); // title 
                    char[] tBuffer = new char[titleLen];
                    for (int i = 0; i < titleLen; i++) tBuffer[i] = Chars[Rnd.Next(Chars.Length)];
                    SetWindowText(hw, new string(tBuffer));
                    Thread.Sleep(1);
                }
            });

            bmhShiftTables = new int[rawPatterns.Length][];
            for (int p = 0; p < rawPatterns.Length; p++)
            {
                int[] table = new int[256];
                int pLen = rawPatterns[p].Length;
                for (int i = 0; i < 256; i++) table[i] = pLen;
                for (int i = 0; i < pLen - 1; i++) table[rawPatterns[p][i]] = pLen - 1 - i;
                bmhShiftTables[p] = table;
            }

            if (OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out IntPtr tkn))
            {
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Attributes = 0x00000002 };
                if (LookupPrivilegeValue(null, "SeDebugPrivilege", out tp.Luid))
                {
                    AdjustTokenPrivileges(tkn, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                }
                CloseHandle(tkn);
            }
            Console.WriteLine("SeDebugPrivilege");
            Console.WriteLine("[ % ] github -> https://github.com/overducast/DiE-WebRat");// github
            Console.WriteLine("[ @ ] Author Telegram -> @codevirtualizer");// telegram

            ScanSystemContext();

            Task.Run(() =>
            {
                foreach (var p in Process.GetProcesses())
                {
                    try
                    {
                        if (p.Id <= 4) continue;
                        IntPtr h = OpenProcess(0x1100, false, p.Id);
                        if (h != IntPtr.Zero) { EmptyWorkingSet(h); CloseHandle(h); }
                    }
                    catch { }
                }
            });

            var w = new ManagementEventWatcher(new WqlEventQuery("__InstanceCreationEvent", new TimeSpan(0, 0, 1), "TargetInstance ISA 'Win32_Process'"));
            w.EventArrived += (s, e) => { ScanSystemContext(); };
            w.Start();

            new AutoResetEvent(false).WaitOne();
        }

        static void ScanSystemContext()
        {
            try
            {
                foreach (var p in Process.GetProcesses())
                {
                    try { CheckProcessMemory(p); } catch { }
                }
            }
            catch { }
        }

        static void CheckProcessMemory(Process p)
        {
            if (p.Id == Process.GetCurrentProcess().Id || p.Id == 0 || p.Id == 4) return;

            try { if (p.WorkingSet64 < 1500000) return; } catch { } // 1,5mb 

            IntPtr hProc = OpenProcess(0x0010 | 0x1000, false, p.Id);
            if (hProc == IntPtr.Zero) return;

            uint cap = 2048;
            StringBuilder sb = new StringBuilder((int)cap);
            string exePath = QueryFullProcessImageName(hProc, 0, sb, ref cap) ? sb.ToString() : null;

            bool[] matched = new bool[rawPatterns.Length];
            int totalMatched = 0;
            IntPtr addr = IntPtr.Zero;

            IntPtr imgBase = IntPtr.Zero;
            IntPtr sigAddr = IntPtr.Zero;
            long rSize = 0;

            byte[] memBuffer = new byte[1048576];

            while (VirtualQueryEx(hProc, addr, out MEMORY_BASIC_INFORMATION mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))))
            {
                if (mbi.State == 0x1000 && mbi.Type == 0x1000000 && (mbi.Protect == 0x04 || mbi.Protect == 0x02 || mbi.Protect == 0x40))
                {
                    long size = mbi.RegionSize.ToInt64();
                    long currentOffset = 0;

                    while (currentOffset < size)
                    {
                        int chunk = (int)Math.Min(memBuffer.Length, size - currentOffset);
                        IntPtr readAddr = new IntPtr(mbi.BaseAddress.ToInt64() + currentOffset);

                        if (ReadProcessMemory(hProc, readAddr, memBuffer, chunk, out IntPtr read))
                        {
                            int bytes = read.ToInt32();
                            for (int i = 0; i < rawPatterns.Length; i++)
                            {
                                if (!matched[i])
                                {
                                    bool found = false;
                                    int pLen = rawPatterns[i].Length;
                                    if (bytes >= pLen)
                                    {
                                        int idx = 0;
                                        while (idx <= bytes - pLen)
                                        {
                                            int j = pLen - 1;
                                            while (j >= 0 && memBuffer[idx + j] == rawPatterns[i][j]) j--;
                                            if (j < 0) { found = true; break; }
                                            idx += bmhShiftTables[i][memBuffer[idx + pLen - 1]];
                                        }
                                    }

                                    if (found)
                                    {
                                        matched[i] = true;
                                        totalMatched++;
                                    }
                                }
                            }

                            if (totalMatched == rawPatterns.Length)
                            {
                                imgBase = mbi.AllocationBase;
                                sigAddr = readAddr;
                                rSize = size;
                                break;
                            }
                        }
                        currentOffset += chunk;
                    }
                    if (totalMatched == rawPatterns.Length) break;
                }
                addr = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
            }
            CloseHandle(hProc);

            if (totalMatched == rawPatterns.Length)
            {
                string pName = p.ProcessName;
                int pid = p.Id;

                p.Kill();
                p.WaitForExit(3000);

                Console.WriteLine($"Sorry NyashTeam you get fucked:(");// i like this:)
                Console.WriteLine($"[ $ ] PID: {pid}");
                Console.WriteLine($"[ $ ] NAME: {pName}");
                Console.WriteLine($"[ $ ] BASE: 0x{imgBase.ToInt64():X}");
                Console.WriteLine($"[ $ ] OFFSET: 0x{sigAddr.ToInt64():X}");
                Console.WriteLine($"[ $ ] SIZE: {rSize} bytes");

                string nameForRegistry = pName;

                if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
                {
                    try { nameForRegistry = Path.GetFileNameWithoutExtension(exePath); } catch { }
                    try
                    {
                        File.Delete(exePath);
                        Console.WriteLine($"Removed exe {exePath}");
                    }
                    catch { }
                }

                try
                {
                    string runPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
                    using (RegistryKey rk = Registry.CurrentUser.OpenSubKey(runPath, true))
                    {
                        if (rk != null && rk.GetValue(nameForRegistry) != null)
                        {
                            rk.DeleteValue(nameForRegistry);
                            Console.WriteLine($"Cleared HKCU\\{runPath}\\{nameForRegistry}");
                        }
                    }
                }
                catch { } 

                try
                {
                    using (Process pr = Process.Start(new ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        Arguments = $"/Delete /TN \"{nameForRegistry}\" /F",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    }))
                    {
                        pr.WaitForExit();
                        if (pr.ExitCode == 0)
                        {
                            Console.WriteLine($"Deleted task \"{nameForRegistry}\"");
                        }
                    }
                }
                catch { }
            }
        }
    }
}
