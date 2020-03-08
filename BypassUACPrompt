using System;
using System.Diagnostics;
using System.Collections;
using System.IO;



    public class Task
    {
        public static string Execute(string ExecutablePath, string Arguments)
        {
                if (!File.Exists(ExecutablePath)) {return "Executable Path does not exist";}
                Process proc = new Process();  
                ProcessStartInfo info = new ProcessStartInfo(ExecutablePath, Arguments);
                info.WindowStyle = ProcessWindowStyle.Hidden;
                info.UseShellExecute = true;
                info.Verb = "runas";
                proc.StartInfo = info;
                try 
                {
                  proc.Start();
                  return "User Accepted"; 
                } catch {return "User Declined";}
                   
            
        }
    }

