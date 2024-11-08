using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("filecrypt.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Encrypt(string filePath, string password);

    [DllImport("filecrypt.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Decrypt(string filePath, string password);

    static void Main()
    {
        string filePath = "testfile";
        string password = "hello";

        int encryptResult = Encrypt(filePath, password);
        if (encryptResult == 0)
        {
            Console.WriteLine("File encrypted successfully.");
        }
        else
        {
            Console.WriteLine("Encryption failed.");
        }

        int decryptResult = Decrypt("testfile.enc", password);
        if (decryptResult == 0)
        {
            Console.WriteLine("File decrypted successfully.");
        }
        else
        {
            Console.WriteLine("Decryption failed.");
        }
    }
}
