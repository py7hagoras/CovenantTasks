# CovenantTasks
Source for tasks I have used with Covenant. They can be more elegant than this, so feel free to modify as you choose.

### ppid.cs
This is a modified code from https://github.com/leoloobeek/csharp/blob/master/ExecutionTesting.cs that implements PPID spoofing.
Make sure to graphically "Add" the parameters within the Execute method. Names have to match.

### donutInject.cs
This is a modified code from https://github.com/TheWover/donut/blob/master/DonutTest/Program.cs that implements process injection through CreateRemoteThread API. You can add parameters to it and modify the Execute method accordingly. I did this for explorer injection with a speicific base64 encoded shellcode generated using donut and base64 encoded: [Convert]::ToBase64String([IO.File]::ReadAllBytes("filelocation")) | clip

### wnfInject.cs
Some EDRs catch injection techniques that use the CreateRemoteThread API. This is a task for process injection through Windows Notification Facility (WNF). Modified FuzzySecurity's C# implementation of WNF process injection technique. https://github.com/FuzzySecurity/Sharp-Suite/tree/master/WindfarmDynamite. Make sure to replace <Place Shellcode here> with your own shellcode e.g 0xe8, 0xe5, 0xe3.... 
It injects into explorer and might not work all the time (works 8 out of 10), execute and be patient. 
 **Note** if you exit the grunt, the target's explorer process will restart (bottom icons dissappear and re-appear, folders close, but every other thing is fine.)
  
### ByPassUACPrompt.cs
Sometimes, the best way to bypass UAC is to ask the user...lol. 
***ExecutablePath*** and ***Arguments*** are compulsory.
**Sample execution:**  

```BypassUACPrompt /executablepath:"C:\\Program Files\\Microsoft Office\\Office15\\WINWORD.EXE" /arguments:"C:\\Users\\pytha\\AppData\\Roaming\\Microsoft\\Templates\\WheelOfFortune.docm"```

### GetPIDByName.cs
Gets the Process ID using the process name
***GetPIDByName explorer***

### PhishUser.cs
Phishes a user by prompting for Credentials. It will keep prompting till user enters valid credentials.
***PhishUser "Outlook Security"*** You can also modify the ***pszMessageText*** as you deem fit.

### LockSystem.cs
This is a simple task to lock the user's system. Might come in handy, especially when you want user to re-enter credentials.

### UrbanBishop.yaml
Adaptation of FuzzySecurity's UrbanBishop code for injection into specified process. Takes binary payload and process ID as input.

### PatchETW.yaml
This disables ETW logging for current process. Makes AV/EDR blind to inline assembly execution amongst other activities within the process.

### BypassUACSilentCleanUp-OpSafe.yaml
This implements Juian Ureno's C# code for SilentCleanUp bypass. I added PPID Spoofing to make it opsafe (spoofing the explorer id is recommended), without it, Defender detects and kills the initiating process, probably because it detects the it's the same process that sets the Environment variable that also calls the "schtasks". So ppid spoofing is my way of bypassing this detection, so it would seems its explorer that calls schtasks.

### PopUp.yaml
Used this to demonstrate to someone I had popped their system ;).

### Argue.yaml
Similar to cobalt's strike argue command for argument spoofing. This is a simple Covenant adaptation of FuzzySecurity's SwampThing code. Found it useful for bypassing commandline parsing for certain EDRs.  
```argue C:\Windows\System32\notepad.exe "real.txt" "fake.txt"```  
```argue C:\Windows\System32\reg.exe "save HKLM\SAM C:\Users\Admin\Desktop\SAM" "whatever"```  
```argue C:\Windows\System32\reg.exe "save HKLM\SYSTEM C:\Users\Admin\Desktop\SYSTEM" "whatever"```  
```argue C:\Windows\System32\reg.exe "save HKLM\SECURITY C:\Users\Admin\Desktop\SECURITY" "whatever"```

 **Please contribute if you have any**
