using System.Runtime.InteropServices;
using System.Diagnostics;



public class Task 
{        
    	[DllImport("user32")]
		public static extern void LockWorkStation();
        
        public static string Execute ()
        {
                LockWorkStation();
                return "Workstation has locked";
        }
}

