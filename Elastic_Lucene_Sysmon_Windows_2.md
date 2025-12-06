# Elastic Stack Detection Rules for Sysmon & Windows Events
## Converted from Sigma Rules to Elasticsearch/Lucene Syntax

---

### 🔥 Windows Firewall Rule Modification
**Sigma ID:** `win_firewall_as_change_rule`  
**Tactic:** Defense Evasion  
**Technique:** T1562.004 (Impair Defenses: Disable or Modify System Firewall)  
```
EventID:(2005 OR 2073)
AND NOT (
    winlog.event_data.ApplicationPath:*\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe OR
    winlog.event_data.ApplicationPath:*\\AppData\\Local\\Keybase\\keybase.exe OR
    winlog.event_data.ApplicationPath:*\\AppData\\Local\\Programs\\Messenger\\Messenger.exe OR
    (
        winlog.event_data.ApplicationPath:*:\\Users\\* AND
        winlog.event_data.ApplicationPath:*\\AppData\\Local\\Programs\\Opera\\* AND
        winlog.event_data.ApplicationPath:*\\opera.exe
    ) OR
    (
        winlog.event_data.ApplicationPath:*:\\Users\\* AND
        winlog.event_data.ApplicationPath:*\\AppData\\Local\\BraveSoftware\\Brave-Browser\\Application\\brave.exe
    )
)
```

### 👻 Suspicious WMI Script Consumer Execution
**Sigma ID:** `win_security_scrcons_remote_wmi_scripteventconsumer`  
**Tactic:** Execution  
**Technique:** T1047 (Windows Management Instrumentation)  
```
EventID:4624
AND winlog.event_data.LogonType:3
AND winlog.event_data.ProcessName:*scrcons.exe
AND NOT winlog.event_data.TargetLogonId:"0x3e7"
```

### 🔐 Browser Credential File Access
**Sigma ID:** `win_security_file_access_browser_credential`  
**Tactic:** Credential Access  
**Technique:** T1555 (Credentials from Password Stores)  
```
(
    EventID:4663
    AND winlog.event_data.ObjectType:"File"
    AND winlog.event_data.AccessMask:"0x1"
    AND (
        winlog.event_data.ObjectName:*\\User Data\\Default\\Login Data* OR
        winlog.event_data.ObjectName:*\\User Data\\Local State* OR
        winlog.event_data.ObjectName:*\\User Data\\Default\\Network\\Cookies* OR
        winlog.event_data.FileName:*\\cookies.sqlite OR
        winlog.event_data.FileName:*\\places.sqlite OR
        winlog.event_data.FileName:*release\\key3.db OR
        winlog.event_data.FileName:*release\\key4.db OR
        winlog.event_data.FileName:*release\\logins.json
    )
)
AND NOT winlog.event_data.ProcessName:System
AND NOT (
    winlog.event_data.ProcessName:C:\\Program Files (x86)\\* OR
    winlog.event_data.ProcessName:C:\\Program Files\\* OR
    winlog.event_data.ProcessName:C:\\Windows\\system32\\* OR
    winlog.event_data.ProcessName:C:\\Windows\\SysWOW64\\*
)
AND NOT (
    winlog.event_data.ProcessName:C:\\ProgramData\\Microsoft\\Windows Defender\\*
    AND (
        winlog.event_data.ProcessName:*\\MpCopyAccelerator.exe OR
        winlog.event_data.ProcessName:*\\MsMpEng.exe
    )
)
```

### ⏰ Scheduled Task Deletion
**Sigma ID:** `win_security_scheduled_task_deletion`  
**Tactic:** Persistence, Defense Evasion  
**Technique:** T1053.005 (Scheduled Task)  
```
EventID:4699
AND NOT winlog.event_data.TaskName:\\Microsoft\\Windows\\RemovalTools\\MRT_ERROR_HB
AND NOT winlog.event_data.TaskName:*\\Mozilla\\Firefox Default Browser Agent*
```

### 🧵 CreateRemoteThread with LoadLibrary
**Sigma ID:** `create_remote_thread_win_loadlibrary`  
**Tactic:** Defense Evasion, Privilege Escalation  
**Technique:** T1055 (Process Injection)  
```
winlog.event_data.StartModule:*\\kernel32.dll
AND winlog.event_data.StartFunction:LoadLibraryA
```

### ⚡ PowerShell CreateRemoteThread
**Sigma ID:** `create_remote_thread_win_powershell_generic`  
**Tactic:** Defense Evasion  
**Technique:** T1055 (Process Injection)  
```
winlog.event_data.SourceImage:(*\\powershell.exe OR *\\pwsh.exe)
AND NOT winlog.event_data.SourceParentImage:*:\\Windows\\System32\\CompatTelRunner.exe
```

### 🎯 Suspicious CreateRemoteThread Targeting Shells
**Sigma ID:** `create_remote_thread_win_susp_target_shell_application`  
**Tactic:** Defense Evasion  
**Technique:** T1055 (Process Injection)  
```
winlog.event_data.TargetImage:(*\\cmd.exe OR *\\powershell.exe OR *\\pwsh.exe)
AND NOT (
    winlog.event_data.SourceImage:(
        C:\\Windows\\System32\\* OR
        C:\\Windows\\SysWOW64\\* OR
        C:\\Program Files (x86)\\* OR
        C:\\Program Files\\*
    )
)
AND NOT winlog.event_data.SourceImage:*\\MsMpEng.exe
```

### 🌐 Chromium Browser Sensitive File Access
**Sigma ID:** `file_access_win_browsers_chromium_sensitive_files`  
**Tactic:** Collection  
**Technique:** T1213 (Data from Information Repositories)  
```
winlog.event_data.FileName:(
    *\\User Data\\Default\\Cookies* OR
    *\\User Data\\Default\\History* OR
    *\\User Data\\Default\\Network\\Cookies* OR
    *\\User Data\\Default\\Web Data*
)
AND NOT winlog.event_data.Image:System
AND NOT (
    winlog.event_data.Image:(
        C:\\Program Files (x86)\\* OR
        C:\\Program Files\\* OR
        C:\\Windows\\system32\\* OR
        C:\\Windows\\SysWOW64\\*
    )
)
AND NOT (
    winlog.event_data.Image:C:\\ProgramData\\Microsoft\\Windows Defender\\*
    AND (
        winlog.event_data.Image:*\\MpCopyAccelerator.exe OR
        winlog.event_data.Image:*\\MsMpEng.exe
    )
)
```

### 🔓 Browser Credential Access
**Sigma ID:** `file_access_win_browsers_credential`  
**Tactic:** Credential Access  
**Technique:** T1555 (Credentials from Password Stores)  
```
(
    winlog.event_data.FileName:*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat OR
    winlog.event_data.FileName:(*\\cookies.sqlite OR *\\places.sqlite) OR
    winlog.event_data.FileName:*release\\key3.db OR
    winlog.event_data.FileName:*release\\key4.db OR
    winlog.event_data.FileName:*release\\logins.json OR
    winlog.event_data.FileName:*\\User Data\\Default\\Login Data* OR
    winlog.event_data.FileName:*\\User Data\\Local State*
)
AND NOT winlog.event_data.Image:System
AND NOT (
    winlog.event_data.Image:(
        C:\\Program Files (x86)\\* OR
        C:\\Program Files\\* OR
        C:\\Windows\\system32\\* OR
        C:\\Windows\\SysWOW64\\*
    )
)
AND NOT (
    winlog.event_data.Image:C:\\ProgramData\\Microsoft\\Windows Defender\\*
    AND (
        winlog.event_data.Image:*\\MpCopyAccelerator.exe OR
        winlog.event_data.Image:*\\MsMpEng.exe
    )
)
AND NOT winlog.event_data.Image:(*\\thor.exe OR *\\thor64.exe)
```

### 📧 Outlook Mail Credential Access
**Sigma ID:** `file_access_win_office_outlook_mail_credential`  
**Tactic:** Collection  
**Technique:** T1114 (Email Collection)  
```
(
    winlog.event_data.FileName:*\\AppData\\Local\\Comms\\Unistore\\data* OR
    winlog.event_data.FileName:*\\AppData\\Local\\Comms\\UnistoreDB\\store.vol
)
AND NOT winlog.event_data.Image:System
AND NOT (
    winlog.event_data.Image:(
        C:\\Program Files (x86)\\* OR
        C:\\Program Files\\* OR
        C:\\Windows\\system32\\* OR
        C:\\Windows\\SysWOW64\\*
    )
)
AND NOT (
    winlog.event_data.Image:C:\\ProgramData\\Microsoft\\Windows Defender\\*
    AND (
        winlog.event_data.Image:*\\MpCopyAccelerator.exe OR
        winlog.event_data.Image:*\\MsMpEng.exe
    )
)
AND NOT winlog.event_data.Image:(*\\thor64.exe OR *\\thor.exe)
```

### 🏛️ Suspicious GPO Access
**Sigma ID:** `file_access_win_susp_gpo_access_uncommon_process`  
**Tactic:** Defense Evasion  
**Technique:** T1484 (Domain Policy Modification)  
```
winlog.event_data.FileName:\\\\*
AND winlog.event_data.FileName:*\\sysvol\\*
AND winlog.event_data.FileName:*\\Policies\\*
AND NOT (
    winlog.event_data.Image:(
        *:\\Program Files (x86)\\* OR
        *:\\Program Files\\* OR
        *:\\Windows\\explorer.exe OR
        *:\\Windows\\system32\\* OR
        *:\\Windows\\SysWOW64\\*
    )
)
```

### 🔧 Registry Hive Access
**Sigma ID:** `file_access_win_susp_reg_and_hive`  
**Tactic:** Persistence, Defense Evasion  
**Technique:** T1112 (Modify Registry)  
```
winlog.event_data.FileName:(*.hive OR *.reg)
AND NOT (
    winlog.event_data.Image:(
        C:\\Program Files (x86)\\* OR
        C:\\Program Files\\* OR
        C:\\Windows\\System32\\* OR
        C:\\Windows\\SysWOW64\\*
    )
)
```

### ⚙️ Unattend.xml Access
**Sigma ID:** `file_access_win_susp_unattend_xml`  
**Tactic:** Persistence  
**Technique:** T1078 (Valid Accounts)  
```
winlog.event_data.FileName:*\\Panther\\unattend.xml
```

### 🗑️ Zone Identifier Deletion
**Sigma ID:** `file_delete_win_zone_identifier_ads`  
**Tactic:** Defense Evasion  
**Technique:** T1070 (Indicator Removal)  
```
winlog.event_data.TargetFilename:*:Zone.Identifier
```

### 💾 Memory Dump Creation
**Sigma ID:** `file_event_win_dump_file_creation`  
**Tactic:** Credential Access  
**Technique:** T1003 (OS Credential Dumping)  
```
winlog.event_data.TargetFilename:(*.dmp OR *.dump OR *.hdmp)
```

### 🔐 PFX Certificate Creation
**Sigma ID:** `file_event_win_pfx_file_creation`  
**Tactic:** Defense Evasion  
**Technique:** T1553 (Subvert Trust Controls)  
```
winlog.event_data.TargetFilename:*.pfx
AND NOT (
    (
        winlog.event_data.Image:(
            C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe OR
            C:\\Program Files (x86)\\Microsoft OneDrive\\OneDrive.exe
        )
        AND winlog.event_data.TargetFilename:*\\OneDrive\\CodeSigning.pfx
    ) OR
    winlog.event_data.TargetFilename:(
        C:\\Program Files (x86)\\Microsoft Visual Studio\\* OR
        C:\\Program Files\\Microsoft Visual Studio\\*
    ) OR
    winlog.event_data.TargetFilename:C:\\Program Files\\CMake\\*
)
```

### 🐍 Python Path Configuration Files
**Sigma ID:** `file_event_win_python_path_configuration_files`  
**Tactic:** Persistence  
**Technique:** T1546 (Event Triggered Execution)  
```
winlog.event_data.TargetFilename:/.*\\(venv|python(.+)?)\\lib\\site-packages\\.*/
AND winlog.event_data.TargetFilename:*.pth
AND NOT (
    winlog.event_data.Image:*\\python.exe
    AND winlog.event_data.TargetFilename:(*\\pywin32.pth OR *\\distutils-precedence.pth)
)
```

### 📋 Scheduled Task Creation
**Sigma ID:** `file_event_win_scheduled_task_creation`  
**Tactic:** Persistence  
**Technique:** T1053.005 (Scheduled Task)  
```
winlog.event_data.TargetFilename:(
    *:\\Windows\\System32\\Tasks\\* OR
    *:\\Windows\\SysWOW64\\Tasks\\* OR
    *:\\Windows\\Tasks\\*
)
```

### 🚨 Suspicious Binary Dropper
**Sigma ID:** `file_event_win_susp_binary_dropper`  
**Tactic:** Defense Evasion  
**Technique:** T1204 (User Execution)  
```
winlog.event_data.Image:*.exe
AND winlog.event_data.TargetFilename:*.exe
AND NOT (
    winlog.event_data.Image:(
        *:\\Windows\\System32\\msiexec.exe OR
        *:\\Windows\\system32\\cleanmgr.exe OR
        *:\\Windows\\explorer.exe OR
        *:\\WINDOWS\\system32\\dxgiadaptercache.exe OR
        *:\\WINDOWS\\system32\\Dism.exe OR
        *:\\Windows\\System32\\wuauclt.exe
    ) OR
    (
        winlog.event_data.Image:*:\\WINDOWS\\system32\\svchost.exe
        AND winlog.event_data.TargetFilename:*:\\Windows\\SoftwareDistribution\\Download\\*
    ) OR
    (
        winlog.event_data.Image:*:\\Windows\\system32\\svchost.exe
        AND winlog.event_data.TargetFilename:*:\\WUDownloadCache\\*
        AND winlog.event_data.TargetFilename:*WindowsUpdateBox.exe
    ) OR
    (
        winlog.event_data.Image:*:\\WINDOWS\\SoftwareDistribution\\Download\\*
        AND winlog.event_data.Image:*\\WindowsUpdateBox.Exe
        AND winlog.event_data.TargetFilename:*:\\$WINDOWS.~BT\\Sources\\*
    ) OR
    (
        winlog.event_data.Image:*:\\Windows\\WinSxS\\*
        AND winlog.event_data.Image:*\\TiWorker.exe
    ) OR
    (
        winlog.event_data.Image:(*:\\Program Files\\* OR *:\\Program Files (x86)\\*)
        AND winlog.event_data.TargetFilename:(*:\\Program Files\\* OR *:\\Program Files (x86)\\*)
    ) OR
    winlog.event_data.Image:(
        *:\\ProgramData\\Microsoft\\Windows Defender\\* OR
        *:\\Program Files\\Windows Defender\\*
    ) OR
    winlog.event_data.TargetFilename:*\\AppData\\Local\\Microsoft\\WindowsApps\\* OR
    (
        winlog.event_data.Image:*\\AppData\\Local\\Microsoft\\Teams\\Update.exe
        AND winlog.event_data.TargetFilename:(
            *\\AppData\\Local\\Microsoft\\Teams\\stage\\Teams.exe OR
            *\\AppData\\Local\\Microsoft\\Teams\\stage\\Squirrel.exe OR
            *\\AppData\\Local\\Microsoft\\SquirrelTemp\\tempb\\*
        )
    ) OR
    (
        winlog.event_data.Image:(
            *:\\Windows\\Microsoft.NET\\Framework\\* OR
            *:\\Windows\\Microsoft.NET\\Framework64\\* OR
            *:\\Windows\\Microsoft.NET\\FrameworkArm\\* OR
            *:\\Windows\\Microsoft.NET\\FrameworkArm64\\*
        )
        AND winlog.event_data.Image:*\\mscorsvw.exe
        AND winlog.event_data.TargetFilename:*:\\Windows\\assembly\\NativeImages_*
    ) OR
    (
        winlog.event_data.Image:*\\AppData\\Local\\*
        AND winlog.event_data.Image:*\\Microsoft VS Code\\Code.exe
        AND winlog.event_data.TargetFilename:*\\.vscode\\extensions\\*
    ) OR
    (
        winlog.event_data.Image:*\\AppData\\Local\\GitHubDesktop\\Update.exe
        AND winlog.event_data.TargetFilename:*\\AppData\\Local\\SquirrelTemp\\*
    ) OR
    (
        winlog.event_data.Image:*:\\WINDOWS\\TEMP\\*
        AND winlog.event_data.TargetFilename:*:\\WINDOWS\\TEMP\\*
    ) OR
    (
        winlog.event_data.Image:*\\Python27\\python.exe
        AND winlog.event_data.TargetFilename:(
            *\\Python27\\Lib\\site-packages\\* OR
            *\\Python27\\Scripts\\* OR
            *\\AppData\\Local\\Temp\\*
        )
    ) OR
    (
        winlog.event_data.Image:*\\AppData\\Local\\SquirrelTemp\\Update.exe
        AND winlog.event_data.TargetFilename:*\\AppData\\Local\\*
    ) OR
    (
        winlog.event_data.Image:*\\AppData\\Local\\Temp\\*
        AND winlog.event_data.TargetFilename:*\\AppData\\Local\\Temp\\*
    ) OR
    (
        winlog.event_data.Image:*\\ChromeSetup.exe
        AND winlog.event_data.TargetFilename:*\\Google\\*
    ) OR
    (
        winlog.event_data.Image:*:\\Windows\\Microsoft.NET\\Framework*
        AND winlog.event_data.Image:*\\mscorsvw.exe
        AND winlog.event_data.TargetFilename:*:\\Windows\\assembly\\*
    )
)
```

### 🌐 VS Code Tunnel Indicators
**Sigma ID:** `file_event_win_vscode_tunnel_indicators`  
**Tactic:** Command and Control  
**Technique:** T1095 (Non-Application Layer Protocol)  
```
winlog.event_data.TargetFilename:*\\code_tunnel.json
```

### 🛡️ WDAC Policy Creation
**Sigma ID:** `file_event_win_wdac_policy_creation_in_codeintegrity_folder`  
**Tactic:** Defense Evasion  
**Technique:** T1553 (Subvert Trust Controls)  
```
winlog.event_data.TargetFilename:*:\\Windows\\System32\\CodeIntegrity\\*
AND winlog.event_data.TargetFilename:(*.cip OR *.p7b)
AND winlog.event_data.IntegrityLevel:High
```

### 🌐 WebDAV Temporary File Creation
**Sigma ID:** `file_event_win_webdav_tmpfile_creation`  
**Tactic:** Defense Evasion  
**Technique:** T1218 (Signed Binary Proxy Execution)  
```
winlog.event_data.TargetFilename:*\\AppData\\Local\\Temp\\TfsStore\\Tfs_DAV\\*
AND winlog.event_data.TargetFilename:(
    *.7z OR *.bat OR *.dat OR *.ico OR *.js OR *.lnk OR
    *.ps1 OR *.rar OR *.vbe OR *.vbs OR *.zip
)
```

### 🔄 Non-DLL to DLL Rename
**Sigma ID:** `file_rename_win_non_dll_to_dll_ext`  
**Tactic:** Defense Evasion  
**Technique:** T1036 (Masquerading)  
```
winlog.event_data.TargetFilename:*.dll
AND NOT (
    winlog.event_data.SourceFilename:*.dll OR
    winlog.event_data.SourceFilename:*.tmp OR
    winlog.event_data.SourceFilename:"" OR
    NOT _exists_:winlog.event_data.SourceFilename OR
    (
        winlog.event_data.Image:*:\\Windows\\WinSxS\\*
        AND winlog.event_data.Image:*\\TiWorker.exe
    ) OR
    (
        winlog.event_data.Image:*:\\Windows\\System32\\wuauclt.exe
        AND winlog.event_data.TargetFilename:*:\\$WINDOWS.~BT\\Sources\\*
    ) OR
    winlog.event_data.Image:(*:\\Program Files (x86)\\* OR *:\\Program Files\\*) OR
    winlog.event_data.SourceFilename:*\\SquirrelTemp\\temp*
)
```

### 🛡️ AMSI DLL Load by Uncommon Process
**Sigma ID:** `image_load_dll_amsi_uncommon_process`  
**Tactic:** Defense Evasion  
**Technique:** T1562.001 (Impair Defenses: Disable or Modify Tools)  
```
winlog.event_data.ImageLoaded:*\\amsi.dll
AND NOT (
    winlog.event_data.Image:(*:\\Windows\\explorer.exe OR *:\\Windows\\Sysmon64.exe) OR
    winlog.event_data.Image:(
        *:\\Program Files (x86)\\* OR
        *:\\Program Files\\* OR
        *:\\Windows\\System32\\* OR
        *:\\Windows\\SysWOW64\\* OR
        *:\\Windows\\WinSxS\\*
    ) OR
    (
        winlog.event_data.Image:*:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*
        AND winlog.event_data.Image:*\\MsMpEng.exe
    ) OR
    (
        winlog.event_data.Image:(
            *:\\Windows\\Microsoft.NET\\Framework\\* OR
            *:\\Windows\\Microsoft.NET\\Framework64\\* OR
            *:\\Windows\\Microsoft.NET\\FrameworkArm\\* OR
            *:\\Windows\\Microsoft.NET\\FrameworkArm64\\*
        )
        AND winlog.event_data.Image:*\\ngentask.exe
    ) OR
    NOT _exists_:winlog.event_data.Image OR
    winlog.event_data.Image:""
)
```

### 🔄 BitsProxy DLL Load
**Sigma ID:** `image_load_dll_bitsproxy_load_by_uncommon_process`  
**Tactic:** Defense Evasion  
**Technique:** T1197 (BITS Jobs)  
```
winlog.event_data.ImageLoaded:*\\BitsProxy.dll
AND NOT (
    winlog.event_data.Image:(
        C:\\Windows\\System32\\aitstatic.exe OR
        C:\\Windows\\System32\\bitsadmin.exe OR
        C:\\Windows\\System32\\desktopimgdownldr.exe OR
        C:\\Windows\\System32\\DeviceEnroller.exe OR
        C:\\Windows\\System32\\MDMAppInstaller.exe OR
        C:\\Windows\\System32\\ofdeploy.exe OR
        C:\\Windows\\System32\\RecoveryDrive.exe OR
        C:\\Windows\\System32\\Speech_OneCore\\common\\SpeechModelDownload.exe OR
        C:\\Windows\\SysWOW64\\bitsadmin.exe OR
        C:\\Windows\\SysWOW64\\OneDriveSetup.exe OR
        C:\\Windows\\SysWOW64\\Speech_OneCore\\Common\\SpeechModelDownload.exe
    ) OR
    winlog.event_data.Image:C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe
)
```

### 🔍 DbgHelp/DbgCore Suspicious Load
**Sigma ID:** `image_load_dll_dbghelp_dbgcore_susp_load`  
**Tactic:** Discovery  
**Technique:** T1059 (Command and Scripting Interpreter)  
```
winlog.event_data.ImageLoaded:(*\\dbghelp.dll OR *\\dbgcore.dll)
AND winlog.event_data.Image:(
    *\\bash.exe OR *\\cmd.exe OR *\\cscript.exe OR *\\dnx.exe OR
    *\\excel.exe OR *\\monitoringhost.exe OR *\\msbuild.exe OR
    *\\mshta.exe OR *\\outlook.exe OR *\\powerpnt.exe OR *\\regsvcs.exe OR
    *\\rundll32.exe OR *\\sc.exe OR *\\scriptrunner.exe OR *\\winword.exe OR
    *\\wmic.exe OR *\\wscript.exe
)
AND NOT (
    (
        winlog.event_data.CommandLine:C:\\WINDOWS\\WinSxS\\*
        AND winlog.event_data.CommandLine:*\\TiWorker.exe -Embedding
    ) OR
    (
        winlog.event_data.Image:*\\svchost.exe
        AND winlog.event_data.CommandLine:(*-k LocalServiceNetworkRestricted OR *-k WerSvcGroup)
    ) OR
    (
        winlog.event_data.Image:*\\rundll32.exe
        AND winlog.event_data.CommandLine:(
            */d srrstr.dll,ExecuteScheduledSPPCreation OR
            *aepdu.dll,AePduRunUpdate OR
            *shell32.dll,OpenAs_RunDL OR
            *Windows.Storage.ApplicationData.dll,CleanupTemporaryState
        )
    )
)
```

### 🎨 System.Drawing DLL Load
**Sigma ID:** `image_load_dll_system_drawing_load`  
**Tactic:** Discovery  
**Technique:** T1016 (System Network Configuration Discovery)  
```
winlog.event_data.ImageLoaded:*\\System.Drawing.ni.dll
```

### ⚙️ TaskScheduler DLL Load from Suspicious Locations
**Sigma ID:** `image_load_dll_taskschd_by_process_in_potentially_suspicious_location`  
**Tactic:** Persistence  
**Technique:** T1053.005 (Scheduled Task)  
```
(
    winlog.event_data.ImageLoaded:*\\taskschd.dll OR
    winlog.event_data.OriginalFileName:taskschd.dll
)
AND winlog.event_data.Image:(
    *:\\Temp\\* OR
    *:\\Users\\Public\\* OR
    *:\\Windows\\Temp\\* OR
    *\\AppData\\Local\\Temp\\* OR
    *\\Desktop\\* OR
    *\\Downloads\\*
)
```

### 📊 Excel XLL Add-in Load
**Sigma ID:** `image_load_office_excel_xll_load`  
**Tactic:** Persistence  
**Technique:** T1137 (Office Application Startup)  
```
winlog.event_data.Image:*\\excel.exe
AND winlog.event_data.ImageLoaded:*.xll
```

### 📝 Word WLL Add-in Load
**Sigma ID:** `image_load_office_word_wll_load`  
**Tactic:** Persistence  
**Technique:** T1137 (Office Application Startup)  
```
winlog.event_data.Image:*\\winword.exe
AND winlog.event_data.ImageLoaded:*.wll
```

### ⚡ WMI Module Load by Uncommon Process
**Sigma ID:** `image_load_wmi_module_load_by_uncommon_process`  
**Tactic:** Execution  
**Technique:** T1047 (Windows Management Instrumentation)  
```
winlog.event_data.ImageLoaded:(
    *\\fastprox.dll OR *\\wbemcomn.dll OR *\\wbemprox.dll OR
    *\\wbemsvc.dll OR *\\WmiApRpl.dll OR *\\wmiclnt.dll OR
    *\\WMINet_Utils.dll OR *\\wmiprov.dll OR *\\wmiutils.dll
)
AND NOT (
    winlog.event_data.Image:(
        *:\\Program Files (x86)\\* OR
        *:\\Program Files\\* OR
        *:\\Windows\\explorer.exe OR
        *:\\Windows\\Microsoft.NET\\Framework\\* OR
        *:\\Windows\\Microsoft.NET\\FrameworkArm\\* OR
        *:\\Windows\\Microsoft.NET\\FrameworkArm64\\* OR
        *:\\Windows\\Microsoft.NET\\Framework64\\* OR
        *:\\Windows\\System32\\* OR
        *:\\Windows\\SysWOW64\\*
    ) OR
    winlog.event_data.Image:(*\\WindowsAzureGuestAgent.exe OR *\\WaAppAgent.exe) OR
    winlog.event_data.Image:(*\\thor.exe OR *\\thor64.exe) OR
    winlog.event_data.Image:*\\MsMpEng.exe OR
    winlog.event_data.Image:(*\\Microsoft\\Teams\\current\\Teams.exe OR *\\Microsoft\\Teams\\Update.exe) OR
    winlog.event_data.Image:(*:\\Windows\\Sysmon.exe OR *:\\Windows\\Sysmon64.exe)
)
```

### 🌐 DFsvc Network Connections to Non-Local IPs
**Sigma ID:** `net_connection_win_dfsvc_non_local_ip`  
**Tactic:** Command and Control  
**Technique:** T1071 (Application Layer Protocol)  
```
winlog.event_data.Image:*\\dfsvc.exe
AND winlog.event_data.Initiated:true
AND NOT (
    (
        winlog.event_data.DestinationIp:127.0.0.0/8 OR
        winlog.event_data.DestinationIp:10.0.0.0/8 OR
        winlog.event_data.DestinationIp:169.254.0.0/16 OR
        winlog.event_data.DestinationIp:172.16.0.0/12 OR
        winlog.event_data.DestinationIp:192.168.0.0/16 OR
        winlog.event_data.DestinationIp::1/128 OR
        winlog.event_data.DestinationIp:fe80::/10 OR
        winlog.event_data.DestinationIp:fc00::/7
    )
)
```

### 🌐 DFsvc Uncommon Port Connections
**Sigma ID:** `net_connection_win_dfsvc_uncommon_ports`  
**Tactic:** Command and Control  
**Technique:** T1071 (Application Layer Protocol)  
```
winlog.event_data.Image:*:\\Windows\\Microsoft.NET\\*
AND winlog.event_data.Image:*\\dfsvc.exe
AND winlog.event_data.Initiated:true
AND NOT winlog.event_data.DestinationPort:(80 OR 443)
AND NOT (
    winlog.event_data.DestinationIsIpv6:true
    AND winlog.event_data.DestinationPort:53
)
```

### 🌐 DLLHost Network Connections
**Sigma ID:** `net_connection_win_dllhost_non_local_ip`  
**Tactic:** Command and Control  
**Technique:** T1071 (Application Layer Protocol)  
```
winlog.event_data.Image:*\\dllhost.exe
AND winlog.event_data.Initiated:true
AND NOT (
    winlog.event_data.DestinationIp:(
        ::1/128 OR 10.0.0.0/8 OR 127.0.0.0/8 OR
        172.16.0.0/12 OR 192.168.0.0/16 OR
        169.254.0.0/16 OR fc00::/7 OR fe80::/10 OR
        20.184.0.0/13 OR 20.192.0.0/10 OR 23.72.0.0/13 OR
        51.10.0.0/15 OR 51.103.0.0/16 OR 51.104.0.0/15 OR
        52.224.0.0/11 OR 150.171.0.0/19 OR 204.79.197.0/24
    )
)
```

### 🌐 HH.exe HTTP Connections
**Sigma ID:** `net_connection_win_hh_http_connection`  
**Tactic:** Command and Control  
**Technique:** T1218 (Signed Binary Proxy Execution)  
```
winlog.event_data.Image:*\\hh.exe
AND winlog.event_data.Initiated:true
AND winlog.event_data.DestinationPort:(80 OR 443)
```

### 📦 MSIExec HTTP Connections
**Sigma ID:** `net_connection_win_msiexec_http`  
**Tactic:** Command and Control  
**Technique:** T1218 (Signed Binary Proxy Execution)  
```
winlog.event_data.Initiated:true
AND winlog.event_data.Image:*\\msiexec.exe
AND winlog.event_data.DestinationPort:(80 OR 443)
```

### ⚡ PowerShell Network Connections
**Sigma ID:** `net_connection_win_powershell_network_connection`  
**Tactic:** Command and Control  
**Technique:** T1059.001 (PowerShell)  
```
winlog.event_data.Image:(*\\powershell.exe OR *\\pwsh.exe)
AND winlog.event_data.Initiated:true
AND NOT (
    winlog.event_data.DestinationIp:(
        127.0.0.0/8 OR 10.0.0.0/8 OR 169.254.0.0/16 OR
        172.16.0.0/12 OR 192.168.0.0/16 OR ::1/128 OR
        fe80::/10 OR fc00::/7
    )
    AND winlog.event_data.User:(*AUTHORI* OR *AUTORI*)
)
AND NOT winlog.event_data.DestinationIp:(20.184.0.0/13 OR 51.103.210.0/23)
```

### ☁️ Suspicious Azure Front Door Connections
**Sigma ID:** `net_connection_win_susp_azurefd_connection`  
**Tactic:** Command and Control  
**Technique:** T1071 (Application Layer Protocol)  
```
winlog.event_data.DestinationHostname:*azurefd.net
AND NOT (
    winlog.event_data.Image:(
        *\\brave.exe OR *\\chrome.exe OR *\\chromium.exe OR
        *\\firefox.exe OR *\\msedge.exe OR *\\msedgewebview2.exe OR
        *\\opera.exe OR *\\vivaldi.exe
    ) OR
    winlog.event_data.Image:*\\searchapp.exe OR
    winlog.event_data.DestinationHostname:(
        *afdxtest.z01.azurefd.net OR
        *fp-afd.azurefd.net OR
        *fp-afdx-bpdee4gtg6frejfd.z01.azurefd.net OR
        *roxy.azurefd.net OR
        *powershellinfraartifacts-gkhedzdeaghdezhr.z01.azurefd.net OR
        *storage-explorer-publishing-feapcgfgbzc2cjek.b01.azurefd.net OR
        *graph.azurefd.net
    )
)
```

### 📂 Network Connections from Public Folder
**Sigma ID:** `net_connection_win_susp_initaited_public_folder`  
**Tactic:** Execution  
**Technique:** T1036 (Masquerading)  
```
winlog.event_data.Initiated:true
AND winlog.event_data.Image:*:\\Users\\Public\\*
AND NOT winlog.event_data.Image:*:\\Users\\Public\\IBM\\ClientSolutions\\Start_Programs\\*
```

### 🔌 PsExec Named Pipe
**Sigma ID:** `pipe_created_sysinternals_psexec_default_pipe`  
**Tactic:** Lateral Movement  
**Technique:** T1021.002 (Remote Services: SMB/Windows Admin Shares)  
```
winlog.event_data.PipeName:\\PSEXESVC
```

### ⚡ Alternate PowerShell Hosts
**Sigma ID:** `posh_pc_alternate_powershell_hosts`  
**Tactic:** Defense Evasion  
**Technique:** T1059.001 (PowerShell)  
```
winlog.event_data.Data:*HostApplication=*
AND NOT (
    winlog.event_data.Data:(
        *HostApplication=?:/Windows/System32/WindowsPowerShell/v1.0/powershell* OR
        *HostApplication=?:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell* OR
        *HostApplication=?:\Windows\System32\sdiagnhost.exe* OR
        *HostApplication=?:\Windows\System32\WindowsPowerShell\v1.0\powershell* OR
        *HostApplication=?:\Windows\SysWOW64\sdiagnhost.exe* OR
        *HostApplication=?:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell* OR
        *HostApplication=powershell*
    ) OR
    winlog.event_data.Data:*Citrix\\ConfigSync\\ConfigSync.ps1* OR
    winlog.event_data.Data:*HostApplication=C:\Hexnode\Hexnode Agent\Current\HexnodeAgent.exe*
)
```

### 🔄 PowerShell BXOR Operator
**Sigma ID:** `posh_pc_bxor_operator_usage`  
**Tactic:** Defense Evasion  
**Technique:** T1059.001 (PowerShell)  
```
winlog.event_data.Data:*HostName=ConsoleHost*
AND winlog.event_data.Data:* -bxor *
```

### 🛡️ PowerShell Firewall Rule Recon
**Sigma ID:** `posh_pm_susp_netfirewallrule_recon`  
**Tactic:** Discovery  
**Technique:** T1016 (System Network Configuration Discovery)  
```
winlog.event_data.Payload:(*Get-NetFirewallRule* OR *Show-NetFirewallRule*)
OR winlog.event_data.ContextInfo:(*Get-NetFirewallRule* OR *Show-NetFirewallRule*)
```

### 📦 PowerShell Compress-Archive
**Sigma ID:** `posh_ps_compress_archive_usage`  
**Tactic:** Collection  
**Technique:** T1560 (Archive Collected Data)  
```
winlog.event_data.ScriptBlockText:*Compress-Archive*
```

### 📧 PowerShell Mailbox Access
**Sigma ID:** `posh_ps_mailbox_access`  
**Tactic:** Collection  
**Technique:** T1114 (Email Collection)  
```
winlog.event_data.ScriptBlockText:*\\Comms\\Unistore\\data*
```

### 🛡️ PowerShell New Firewall Rule
**Sigma ID:** `posh_ps_new_netfirewallrule_allow`  
**Tactic:** Defense Evasion  
**Technique:** T1562.004 (Impair Defenses: Disable or Modify System Firewall)  
```
winlog.event_data.ScriptBlockText:*New-NetFirewallRule*-Action*Allow*
```

### 🗂️ PowerShell New SMB Mapping QUIC
**Sigma ID:** `posh_ps_new_smbmapping_quic`  
**Tactic:** Lateral Movement  
**Technique:** T1021.002 (Remote Services: SMB/Windows Admin Shares)  
```
winlog.event_data.ScriptBlockText:*New-SmbMapping*
AND winlog.event_data.ScriptBlockText:*-TransportType QUIC*
```

### 🔍 PowerShell Registry Reconnaissance
**Sigma ID:** `posh_ps_registry_reconnaissance`  
**Tactic:** Discovery  
**Technique:** T1012 (Query Registry)  
```
winlog.event_data.ScriptBlockText:/.*(Get-Item|gci|Get-ChildItem).{1,64}-Path.{1,64}\\(currentcontrolset\\services|CurrentVersion\\Policies\\Explorer\\Run|CurrentVersion\\Run|CurrentVersion\\ShellServiceObjectDelayLoad|CurrentVersion\\Windows\winlogon)\\.*/
```

### 🗑️ PowerShell Remove Item Path
**Sigma ID:** `posh_ps_remove_item_path`  
**Tactic:** Defense Evasion  
**Technique:** T1070 (Indicator Removal)  
```
winlog.event_data.ScriptBlockText:(
    *Remove-Item -Path * OR *del -Path * OR *erase -Path * OR
    *rd -Path * OR *ri -Path * OR *rm -Path * OR *rmdir -Path *
)
```

### 📤 PowerShell Send-MailMessage with Attachments
**Sigma ID:** `posh_ps_send_mailmessage`  
**Tactic:** Exfiltration  
**Technique:** T1048 (Exfiltration Over Alternative Protocol)  
```
winlog.event_data.ScriptBlockText:*Send-MailMessage*-Attachments*
```

### 🎭 PowerShell Token Obfuscation
**Sigma ID:** `posh_ps_token_obfuscation`  
**Tactic:** Defense Evasion  
**Technique:** T1027 (Obfuscated Files or Information)  
```
(
    winlog.event_data.ScriptBlockText:/.*\w+`(\w+|-|.)`[\w+|\s].*/ OR
    winlog.event_data.ScriptBlockText:/.*"(\{\d\}){2,}"\s*-f.*/ OR
    winlog.event_data.ScriptBlockText:/.*\$\{`?e`?n`?v`?:`?p`?a`?t`?h`?\}.*/
)
AND NOT (
    winlog.event_data.ScriptBlockText:*\$\{env:path\}* OR
    winlog.event_data.ScriptBlockText:(
        *it will return true or false instead* OR
        *The function also prevents `Get-ItemProperty` from failing*
    ) OR
    (
        winlog.event_data.Path:C:\\Program Files\\Microsoft\\Exchange Server\\*
        AND winlog.event_data.Path:*\\bin\\servicecontrol.ps1
        AND winlog.event_data.ScriptBlockText:*`r`n*
    )
)
```

### ⚙️ PowerShell WinAPI Functions Access
**Sigma ID:** `posh_ps_win_api_functions_access`  
**Tactic:** Defense Evasion  
**Technique:** T1059.001 (PowerShell)  
```
winlog.event_data.ScriptBlockText:(
    *Advapi32.dll* OR *kernel32.dll* OR *KernelBase.dll* OR
    *ntdll.dll* OR *secur32.dll* OR *user32.dll*
)
```

### ⚙️ PowerShell WinAPI Library Access
**Sigma ID:** `posh_ps_win_api_library_access`  
**Tactic:** Defense Evasion  
**Technique:** T1059.001 (PowerShell)  
```
winlog.event_data.ScriptBlockText:(
    *AddSecurityPackage* OR *AdjustTokenPrivileges* OR *CloseHandle* OR
    *CreateProcessWithToken* OR *CreateRemoteThread* OR *CreateThread* OR
    *CreateUserThread* OR *DangerousGetHandle* OR *DuplicateTokenEx* OR
    *EnumerateSecurityPackages* OR *FreeLibrary* OR *GetDelegateForFunctionPointer* OR
    *GetLogonSessionData* OR *GetModuleHandle* OR *GetProcAddress* OR
    *GetProcessHandle* OR *GetTokenInformation* OR *ImpersonateLoggedOnUser* OR
    *LoadLibrary* OR *memcpy* OR *MiniDumpWriteDump* OR *OpenDesktop* OR
    *OpenProcess* OR *OpenProcessToken* OR *OpenThreadToken* OR *OpenWindowStation* OR
    *QueueUserApc* OR *ReadProcessMemory* OR *RevertToSelf* OR *RtlCreateUserThread* OR
    *SetThreadToken* OR *VirtualAlloc* OR *VirtualFree* OR *VirtualProtect* OR
    *WaitForSingleObject* OR *WriteInt32* OR *WriteProcessMemory* OR *ZeroFreeGlobalAllocUnicode*
)
```

### 🔓 LSASS Access by PowerShell
**Sigma ID:** `proc_access_win_lsass_powershell_access`  
**Tactic:** Credential Access  
**Technique:** T1003 (OS Credential Dumping)  
```
winlog.event_data.SourceImage:(*\\powershell.exe OR *\\pwsh.exe)
AND winlog.event_data.TargetImage:*\\lsass.exe
```

### 🔓 Suspicious LSASS Access
**Sigma ID:** `proc_access_win_lsass_susp_source_process`  
**Tactic:** Credential Access  
**Technique:** T1003 (OS Credential Dumping)  
```
winlog.event_data.TargetImage:*\\lsass.exe
AND winlog.event_data.GrantedAccess:(
    *10 OR *30 OR *50 OR *70 OR *90 OR *B0 OR *D0 OR *F0 OR
    *18 OR *38 OR *58 OR *78 OR *98 OR *B8 OR *D8 OR *F8 OR
    *1A OR *3A OR *5A OR *7A OR *9A OR *BA OR *DA OR *FA OR
    0x14C2 OR FF
)
AND winlog.event_data.SourceImage:(
    *\\Temp\\* OR *\\Users\\Public\\* OR *\\PerfLogs\\* OR
    *\\AppData\\* OR *\\Temporary*
)
AND NOT (
    (
        winlog.event_data.SourceImage:(*:\\Users\\* AND *\\AppData\\Local\\*)
        AND winlog.event_data.SourceImage:(
            *\\Microsoft VS Code\\Code.exe OR
            *\\software_reporter_tool.exe OR
            *\\DropboxUpdate.exe OR
            *\\MBAMInstallerService.exe OR
            *\\WebexMTA.exe OR
            *\\Meetings\\WebexMTAV2.exe OR
            *\\WebEx\\WebexHost.exe OR
            *\\JetBrains\\Toolbox\\bin\\jetbrains-toolbox.exe
        )
        AND winlog.event_data.GrantedAccess:0x410
    ) OR
    (
        winlog.event_data.SourceImage:*:\\Windows\\Temp\\*
        AND winlog.event_data.SourceImage:*.tmp\\DropboxUpdate.exe
        AND winlog.event_data.GrantedAccess:(0x410 OR 0x1410)
    ) OR
    (
        winlog.event_data.SourceImage:(*:\\Users\\* AND *\\AppData\\Local\\Temp\\*)
        AND winlog.event_data.SourceImage:*.tmp\\DropboxUpdate.exe
        AND winlog.event_data.GrantedAccess:0x1410
    ) OR
    (
        winlog.event_data.SourceImage:(
            *:\\Program Files (x86)\\Dropbox\\* OR
            *:\\Program Files\\Dropbox\\*
        )
        AND winlog.event_data.SourceImage:*\\DropboxUpdate.exe
        AND winlog.event_data.GrantedAccess:0x1410
    ) OR
    (
        winlog.event_data.SourceImage:(
            *:\\Windows\\Temp\\asgard2-agent\\* OR
            *:\\Windows\\Temp\\asgard2-agent-sc\\*
        )
        AND winlog.event_data.SourceImage:(
            *\\thor64.exe OR *\\thor.exe OR
            *\\aurora-agent-64.exe OR *\\aurora-agent.exe
        )
        AND winlog.event_data.GrantedAccess:(0x1fffff OR 0x1010 OR 0x101010)
    ) OR
    (
        winlog.event_data.SourceImage:(
            *:\\Users\\* AND
            *\\AppData\\Local\\Temp\\* AND
            *\\vs_bootstrapper_*
        )
        AND winlog.event_data.GrantedAccess:0x1410
    ) OR
    (
        winlog.event_data.SourceImage:*:\\Program Files (x86)\\Google\\Temp\\*
        AND winlog.event_data.SourceImage:*.tmp\\GoogleUpdate.exe
        AND winlog.event_data.GrantedAccess:(0x410 OR 0x1410)
    ) OR
    (
        winlog.event_data.SourceImage:*:\\Users\\*
        AND winlog.event_data.SourceImage:*\\AppData\\Local\\Keybase\\keybase.exe
        AND winlog.event_data.GrantedAccess:0x1fffff
    ) OR
    (
        winlog.event_data.SourceImage:*\\AppData\\Local\\Temp\\is-*
        AND winlog.event_data.SourceImage:*.tmp\\avira_system_speedup.tmp
        AND winlog.event_data.GrantedAccess:0x1410
    ) OR
    (
        winlog.event_data.SourceImage:*\\AppData\\Roaming\\ViberPC\\*
        AND winlog.event_data.SourceImage:*\\updater.exe
        AND winlog.event_data.TargetImage:*\\winlogon.exe
        AND winlog.event_data.GrantedAccess:0x1fffff
    ) OR
    (
        winlog.event_data.SourceImage:(
            *:\\Program Files\\Common Files\\Adobe\\ARM\\* OR
            *:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\*
        )
        AND winlog.event_data.SourceImage:*\\AdobeARMHelper.exe
        AND winlog.event_data.GrantedAccess:0x1410
    )
)
```

### 🔓 Uncommon LSASS Access Flags
**Sigma ID:** `proc_access_win_lsass_uncommon_access_flag`  
**Tactic:** Credential Access  
**Technique:** T1003 (OS Credential Dumping)  
```
winlog.event_data.TargetImage:*\\lsass.exe
AND winlog.event_data.GrantedAccess:*10
AND NOT (
    winlog.event_data.SourceImage:(
        C:\\Program Files\\Common Files\\McAfee\\MMSSHost\\MMSSHOST.exe OR
        C:\\Program Files\\Malwarebytes\\Anti-Malware\\MBAMService.exe OR
        C:\\Program Files\\Windows Defender\\MsMpEng.exe OR
        C:\\PROGRAMDATA\\MALWAREBYTES\\MBAMSERVICE\\ctlrupdate\\mbupdatr.exe OR
        C:\\Windows\\System32\\lsass.exe OR
        C:\\Windows\\System32\\msiexec.exe OR
        C:\\WINDOWS\\System32\\perfmon.exe OR
        C:\\WINDOWS\\system32\\taskhostw.exe OR
        C:\\WINDOWS\\system32\\taskmgr.exe OR
        C:\\WINDOWS\\system32\\wbem\\wmiprvse.exe OR
        C:\\Windows\\SysWOW64\\msiexec.exe OR
        C:\\Windows\\sysWOW64\\wbem\\wmiprvse.exe
    ) OR
    (
        winlog.event_data.SourceImage:C:\\ProgramData\\Microsoft\\Windows Defender\\*
        AND winlog.event_data.SourceImage:*\\MsMpEng.exe
    ) OR
    (
        winlog.event_data.SourceImage:C:\\Program Files\\WindowsApps\\*
        AND winlog.event_data.SourceImage:*\\GamingServices.exe
    ) OR
    winlog.event_data.SourceImage:(*\\PROCEXP64.EXE OR *\\PROCEXP.EXE) OR
    (
        winlog.event_data.SourceImage:C:\\ProgramData\\VMware\\VMware Tools\\*
        AND winlog.event_data.SourceImage:*\\vmtoolsd.exe
    ) OR
    (
        winlog.event_data.SourceImage:(
            C:\\Program Files\\* OR
            C:\\Program Files (x86)\\*
        )
        AND winlog.event_data.SourceImage:*Antivirus*
    ) OR
    winlog.event_data.SourceImage:(
        *\\thor64.exe OR *\\thor.exe OR
        *\\aurora-agent-64.exe OR *\\aurora-agent.exe
    ) OR
    (
        winlog.event_data.SourceImage:*\\AppData\\Local\\Temp\\*
        AND winlog.event_data.SourceImage:*\\vs_bootstrapper_*
        AND winlog.event_data.GrantedAccess:0x1410
    ) OR
    winlog.event_data.SourceImage:(
        C:\\Program Files\\* OR
        C:\\Program Files (x86)\\* OR
        C:\\WINDOWS\\system32\\*
    ) OR
    winlog.event_data.SourceCommandLine:C:\\WINDOWS\\system32\\wermgr.exe -upload OR
    (
        winlog.event_data.SourceImage:(C:\\Users\\* AND *\\AppData\\Local\\*)
        AND winlog.event_data.SourceImage:(
            *\\Microsoft VS Code\\Code.exe OR
            *\\software_reporter_tool.exe OR
            *\\DropboxUpdate.exe OR
            *\\MBAMInstallerService.exe OR
            *\\WebEx\\WebexHost.exe OR
            *\\Programs\\Microsoft VS Code\\Code.exe OR
            *\\JetBrains\\Toolbox\\bin\\jetbrains-toolbox.exe
        )
    ) OR
    (
        winlog.event_data.SourceImage:*\\xampp-control.exe
        AND winlog.event_data.GrantedAccess:0x410
    ) OR
    (
        winlog.event_data.SourceImage:*\\SteamLibrary\\steamapps\\*
        AND winlog.event_data.GrantedAccess:(0x410 OR 0x10)
    )
)
```

### 💉 Potential Shellcode Injection
**Sigma ID:** `proc_access_win_susp_potential_shellcode_injection`  
**Tactic:** Defense Evasion  
**Technique:** T1055 (Process Injection)  
```
winlog.event_data.GrantedAccess:(0x147a OR 0x1f3fff)
AND winlog.event_data.CallTrace:*UNKNOWN*
AND NOT (
    (
        winlog.event_data.SourceImage:C:\\Windows\\System32\\Wbem\\Wmiprvse.exe
        AND winlog.event_data.TargetImage:C:\\Windows\\system32\\lsass.exe
    ) OR
    (
        winlog.event_data.SourceImage:(
            C:\\Program Files\\Dell\\* OR
            C:\\Program Files (x86)\\Dell\\*
        )
        AND winlog.event_data.TargetImage:(
            C:\\Program Files\\Dell\\* OR
            C:\\Program Files (x86)\\Dell\\*
        )
    ) OR
    (
        winlog.event_data.SourceImage:C:\\Program Files (x86)\\Dell\\UpdateService\\ServiceShell.exe
        AND winlog.event_data.TargetImage:C:\\Windows\\Explorer.EXE
    ) OR
    (
        winlog.event_data.SourceImage:C:\\Program Files\\Microsoft Visual Studio\\*
        AND winlog.event_data.TargetImage:C:\\Program Files\\Microsoft Visual Studio\\*
    )
)
```

### 📦 7-Zip Password Extraction
**Sigma ID:** `proc_creation_win_7zip_password_extraction`  
**Tactic:** Credential Access  
**Technique:** T1555 (Credentials from Password Stores)  
```
(
    winlog.event_data.Description:*7-Zip* OR
    winlog.event_data.Image:(*\\7z.exe OR *\\7zr.exe OR *\\7za.exe) OR
    winlog.event_data.OriginalFileName:(7z.exe OR 7za.exe)
)
AND winlog.event_data.CommandLine:* -p*
AND winlog.event_data.CommandLine:* x *
AND winlog.event_data.CommandLine:* -o*
```

### 📁 Attrib System Attribute Modification
**Sigma ID:** `proc_creation_win_attrib_system`  
**Tactic:** Defense Evasion  
**Technique:** T1564 (Hide Artifacts)  
```
(
    winlog.event_data.Image:*\\attrib.exe OR
    winlog.event_data.OriginalFileName:ATTRIB.EXE
)
AND winlog.event_data.CommandLine:* +s *
```

---

## 🚀 Deployment Notes

### **Elasticsearch Index Pattern:**
```
winlogbeat-* OR logs-windows.* OR sysmon-*
```

### **Field Mapping Requirements:**
- Ensure `winlog.event_data.*` fields are properly mapped
- `DestinationIp` should support CIDR notation queries
- Regular expression queries require `keyword` field type
- EventID should be mapped as integer
