using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public static class Demo // for MessageBoxW function hook.
{
    static NetHook.NetHook hook = NetHook.NetHook.CreateInstance(); // for nethook assign a object instance.

    [DllImport("user32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
    public static extern int MessageBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto)]
    public delegate int LPMESSAGEBOX(IntPtr hWnd, string lpText, string lpCaption, uint uType);

    public static int MsgBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType)
    {
        try
        {
            hook.Suspend(); // suspend hook, easy call MessageBoxW.
            Console.Title = lpCaption; // get input param, and set to the title.
            Console.WriteLine(lpText);
            return MessageBoxW(hWnd, lpText, lpCaption, uType); // call MessageBoxW and returns its value.
        }
        finally
        {
            hook.Resume(); // when you do not need time, resume hook.
        }
    }

    static void Main(string[] args)
    {
        LPMESSAGEBOX fnMsgBoxW = MsgBoxW; // bind managed method delegate.
        // for MessageBoxW install a inline hook, and managed code bindings.
        hook.Install(hook.GetProcAddress("user32.dll", "MessageBoxW"), hook.GetProcAddress(fnMsgBoxW));
        // call a managed the MessageBox.Show methods.
        MessageBox.Show("text", "caption");
    }
}
