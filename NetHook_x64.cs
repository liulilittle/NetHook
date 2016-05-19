namespace NetHook
{
    using System;
    using System.Runtime.InteropServices;

    public partial class NetHook_x64 : NetHook // 48 B8 00 00 00 00 00 00 00 00 FF E0
    {
        private int mOldMemoryProtect;
        private IntPtr mOldMethodAddress;
        private IntPtr mNewMethodAddress;
        private byte[] mOldMethodAsmCode;
        private byte[] mNewMethodAsmCode;

        private abstract partial class NativeMethods
        {
            public const int PAGE_EXECUTE_READWRITE = 64;
            public static readonly IntPtr NULL = IntPtr.Zero;

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr LoadLibrary(string lpLibFileName);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, int flNewProtect, out int lpflOldProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool FreeLibrary([In] IntPtr hLibModule);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, IntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentProcess();
        }
    }

    public partial class NetHook_x64 : NetHook
    {
        public override void Install(IntPtr oldMethodAddress, IntPtr newMethodAddress)
        {
            if (oldMethodAddress == NativeMethods.NULL || newMethodAddress == NativeMethods.NULL)
                throw new Exception("The address is invalid.");
            if (!this.VirtualProtect(oldMethodAddress, NativeMethods.PAGE_EXECUTE_READWRITE))
                throw new Exception("Unable to modify memory protection.");
            this.mOldMethodAddress = oldMethodAddress;
            this.mNewMethodAddress = newMethodAddress;
            this.mOldMethodAsmCode = this.GetHeadCode(this.mOldMethodAddress);
            this.mNewMethodAsmCode = this.ConvetToBinary((long)this.mNewMethodAddress);
            this.mNewMethodAsmCode = this.CombineOfArray(new byte[] { 0x48, 0xB8 }, this.mNewMethodAsmCode);
            this.mNewMethodAsmCode = this.CombineOfArray(this.mNewMethodAsmCode, new byte[] { 0xFF, 0xE0 });
            if (!this.WriteToMemory(this.mNewMethodAsmCode, this.mOldMethodAddress, 12))
                throw new Exception("Cannot be written to memory.");
        }

        public override void Suspend()
        {
            if (this.mOldMethodAddress == NativeMethods.NULL)
                throw new Exception("Unable to suspend.");
            this.WriteToMemory(this.mOldMethodAsmCode, this.mOldMethodAddress, 12);
        }

        public override void Resume()
        {
            if (this.mOldMethodAddress == NativeMethods.NULL)
                throw new Exception("Unable to resume.");
            this.WriteToMemory(this.mNewMethodAsmCode, this.mOldMethodAddress, 12);
        }

        public override void Uninstall()
        {
            if (this.mOldMethodAddress == NativeMethods.NULL)
                throw new Exception("Unable to uninstall.");
            if (!this.WriteToMemory(this.mOldMethodAsmCode, this.mOldMethodAddress, 12))
                throw new Exception("Cannot be written to memory.");
            if (!this.VirtualProtect(this.mOldMethodAddress, this.mOldMemoryProtect))
                throw new Exception("Unable to modify memory protection.");
            this.mOldMemoryProtect = 0;
            this.mOldMethodAsmCode = null;
            this.mNewMethodAsmCode = null;
            this.mOldMethodAddress = NativeMethods.NULL;
            this.mNewMethodAddress = NativeMethods.NULL;
        }
    }

    public partial class NetHook_x64 : NetHook
    {
        private byte[] GetHeadCode(IntPtr ptr)
        {
            byte[] buffer = new byte[12];
            Marshal.Copy(ptr, buffer, 0, 12);
            return buffer;
        }
        private byte[] ConvetToBinary(long num)
        {
            byte[] buffer = new byte[8];
            IntPtr ptr = Marshal.AllocHGlobal(8);
            Marshal.WriteInt64(ptr, num);
            Marshal.Copy(ptr, buffer, 0, 8);
            Marshal.FreeHGlobal(ptr);
            return buffer;
        }
        private byte[] CombineOfArray(byte[] x, byte[] y)
        {
            int i = 0, len = x.Length;
            byte[] buffer = new byte[len + y.Length];
            while (i < len)
            {
                buffer[i] = x[i];
                i++;
            }
            while (i < buffer.Length)
            {
                buffer[i] = y[i - len];
                i++;
            }
            return buffer;
        }
        private bool WriteToMemory(byte[] buffer, IntPtr address, uint size)
        {
            IntPtr hRemoteProcess = NativeMethods.GetCurrentProcess();
            return NativeMethods.WriteProcessMemory(hRemoteProcess, address, buffer, size, NativeMethods.NULL);
        }
    }

    public partial class NetHook_x64 : NetHook
    {
        public override IntPtr GetProcAddress(Delegate d)
        {
            return Marshal.GetFunctionPointerForDelegate(d);
        }
        public override IntPtr GetProcAddress(string strLibraryName, string strMethodName)
        {
            IntPtr hRemoteModule;
            if ((hRemoteModule = NativeMethods.GetModuleHandle(strLibraryName)) == NativeMethods.NULL)
                hRemoteModule = NativeMethods.LoadLibrary(strLibraryName);
            return NativeMethods.GetProcAddress(hRemoteModule, strMethodName);
        }
    }

    public partial class NetHook_x64 : NetHook
    {
        private bool VirtualProtect(IntPtr ptr, int flNewProtect)
        {
            return NativeMethods.VirtualProtect(ptr, 12, flNewProtect, out this.mOldMemoryProtect);
        }
    }
}
