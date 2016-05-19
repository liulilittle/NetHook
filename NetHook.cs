namespace NetHook
{
    using System;
    using System.Runtime.InteropServices;

    public abstract class NetHook
    {
        public abstract void Install(IntPtr oldMethodAddress, IntPtr newMethodAddress);
        public abstract void Suspend();
        public abstract void Resume();
        public abstract void Uninstall();
        public abstract IntPtr GetProcAddress(Delegate d);
        public abstract IntPtr GetProcAddress(string strLibraryName, string strMethodName);

        public static NetHook CreateInstance() // ::IsWow64Process
        {
            if (IntPtr.Size != sizeof(int)) // Environment.Is64BitProcess
            {
                return new NetHook_x64();
            }
            return new NetHook_x86();
        }

        public static NetHook CreateInstance(IntPtr oldMethodAddress, IntPtr newMethodAddress)
        {
            NetHook hook = NetHook.CreateInstance();
            try
            {
                return hook;
            }
            finally
            {
                hook.Install(oldMethodAddress, newMethodAddress);
            }
        }

        public static NetHook CreateInstance(IntPtr oldMethodAddress, Delegate newMethodDelegate)
        {
            return NetHook.CreateInstance(oldMethodAddress, Marshal.GetFunctionPointerForDelegate(newMethodDelegate));
        }
    }
}
