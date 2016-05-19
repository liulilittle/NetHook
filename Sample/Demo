using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

class Demo
{
    static NetHook.NetHook hook = NetHook.NetHook.CreateInstance();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
    public static extern int MessageBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto)]
    public delegate int LPMESSAGEBOX(IntPtr hWnd, string lpText, string lpCaption, uint uType);

    public static int MsgBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType)
    {
        try
        {
            hook.Suspend();
            Console.Title = lpCaption;
            Console.WriteLine(lpText);
            return MessageBoxW(hWnd, lpText, lpCaption, uType);
        }
        finally
        {
            hook.Resume();
        }
    }

    static void Main(string[] args)
    {
        LPMESSAGEBOX fnMsgBoxW = MsgBoxW;
        hook.Install(hook.GetProcAddress("user32.dll", "MessageBoxW"), hook.GetProcAddress(fnMsgBoxW));
        MessageBox.Show("text", "caption");
    }
}
