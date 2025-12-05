# https://github.com/elastic/detection-rules/tree/main/rules/windows

## collection_email_outlook_mailbox_via_com.toml
```
query = '''
sequence with maxspan=1m
[process where host.os.type == "windows" and event.action == "start" and
  (
    process.name : (
      "rundll32.exe", "mshta.exe", "powershell.exe", "pwsh.exe",
      "cmd.exe", "regsvr32.exe", "cscript.exe", "wscript.exe"
    ) or
    (
      (process.code_signature.trusted == false or process.code_signature.exists == false) and
      (process.Ext.relative_file_creation_time <= 500 or process.Ext.relative_file_name_modify_time <= 500)
    )
  )
] by process.entity_id
[process where host.os.type == "windows" and event.action == "start" and process.name : "OUTLOOK.EXE" and
  process.Ext.effective_parent.name != null] by process.Ext.effective_parent.entity_id
'''
```

## collection_email_powershell_exchange_mailbox
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and
  process.command_line : ("*MailboxExportRequest*", "*-Mailbox*-ContentFilter*")
'''
```

## collection_mailbox_export_winlog
```
query = '''
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : "New-MailboxExportRequest"
'''
```

## collection_posh_audio_capture
```
query = '''
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "Get-MicrophoneAudio" or
    "WindowsAudioDevice-Powershell-Cmdlet" or
    (waveInGetNumDevs and mciSendStringA)
  )
  and not powershell.file.script_block_text : (
    "sentinelbreakpoints" and "Set-PSBreakpoint" and "PowerSploitIndicators"
  )
  and not user.id : "S-1-5-18"
'''
```

## collection_posh_clipboard_capture
```
query = '''
event.category:process and host.os.type:windows and
  (powershell.file.script_block_text : (
    "Windows.Clipboard" or
    "Windows.Forms.Clipboard" or
    "Windows.Forms.TextBox"
   ) and
   powershell.file.script_block_text : (
    "]::GetText" or
    ".Paste()"
  )) or powershell.file.script_block_text : "Get-Clipboard" and
  not powershell.file.script_block_text : (
    "sentinelbreakpoints" and "Set-PSBreakpoint" and "PowerSploitIndicators"
  ) and
  not user.id : "S-1-5-18" and
  not (
    file.path : *WindowsPowerShell\\Modules\\*.ps1 and
    file.name : ("Convert-ExcelRangeToImage.ps1" or "Read-Clipboard.ps1")
  )
'''
```

## collection_posh_keylogger
```
query = '''
event.category:process and host.os.type:windows and
  (
   powershell.file.script_block_text : (GetAsyncKeyState or NtUserGetAsyncKeyState or GetKeyboardState or "Get-Keystrokes") or
   powershell.file.script_block_text : (
        (SetWindowsHookA or SetWindowsHookW or SetWindowsHookEx or SetWindowsHookExA or NtUserSetWindowsHookEx) and
        (GetForegroundWindow or GetWindowTextA or GetWindowTextW or "WM_KEYBOARD_LL" or "WH_MOUSE_LL")
   )
   ) and not user.id : "S-1-5-18"
  and not powershell.file.script_block_text : (
    "sentinelbreakpoints" and "Set-PSBreakpoint"
  )
'''
```

## collection_posh_mailbox
```
query = '''
event.category:process and host.os.type:windows and
  (
    (
      powershell.file.script_block_text : (
        "Microsoft.Office.Interop.Outlook" or
        "Interop.Outlook.olDefaultFolders" or
        "olFolderInBox" or
        "Outlook.Application"
      ) and powershell.file.script_block_text : ("MAPI" or "GetDefaultFolder" or "GetNamespace" or "Session" or "GetSharedDefaultFolder")
    ) or
    (
      powershell.file.script_block_text : (
        "Microsoft.Exchange.WebServices.Data.Folder" or
        "Microsoft.Exchange.WebServices.Data.FileAttachment" or
        "Microsoft.Exchange.WebServices.Data.ExchangeService"
      ) and
      powershell.file.script_block_text : ("FindItems" or "Bind" or "WellKnownFolderName" or "FolderId" or "ItemView" or "PropertySet" or "SearchFilter" or "Attachments")
    )
  )
'''
```

## collection_posh_screen_grabber
```
query = '''
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    CopyFromScreen and
    ("System.Drawing.Bitmap" or "Drawing.Bitmap")
  ) and not user.id : "S-1-5-18"
'''
```

## collection_posh_webcam_video_capture
```
query = '''
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "NewFrameEventHandler" or
    "VideoCaptureDevice" or
    "DirectX.Capture.Filters" or
    "VideoCompressors" or
    "Start-WebcamRecorder" or
    (
      ("capCreateCaptureWindowA" or
       "capCreateCaptureWindow" or
       "capGetDriverDescription") and
      ("avicap32.dll" or "avicap32")
    )
  )
'''
```

## collection_winrar_encryption
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
(
  (
    (
      process.name : ("rar.exe", "WinRAR.exe") or ?process.code_signature.subject_name == "win.rar GmbH" or
      ?process.pe.original_file_name == "WinRAR.exe"
    ) and
    process.args == "a" and process.args : ("-hp*", "-p*", "/hp*", "/p*")
  ) or
  (
    (process.name : ("7z.exe", "7za.exe") or ?process.pe.original_file_name in ("7z.exe", "7za.exe")) and
    process.args == "a" and process.args : "-p*"
  )
) and
  not process.parent.executable : (
        "C:\\Program Files\\*.exe",
        "C:\\Program Files (x86)\\*.exe",
        "?:\\ManageEngine\\*\\jre\\bin\\java.exe",
        "?:\\Nox\\bin\\Nox.exe",
        "\\Device\\HarddiskVolume?\\Program Files\\*.exe",
        "\\Device\\HarddiskVolume?\\Program Files (x86)\\*.exe",
        "\\Device\\HarddiskVolume?\\ManageEngine\\*\\jre\\bin\\java.exe",
        "\\Device\\HarddiskVolume?\\Nox\\bin\\Nox.exe"
      )
'''
```

## command_and_control_certreq_postdata
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "CertReq.exe" or ?process.pe.original_file_name == "CertReq.exe") and process.args : "-Post"
'''
```

## command_and_control_common_llm_endpoint
```
query = '''
network where host.os.type == "windows" and dns.question.name != null and
(
  process.name : ("MSBuild.exe", "mshta.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "rundll32.exe",
  "bitsadmin.exe", "InstallUtil.exe", "RegAsm.exe", "vbc.exe", "RegSvcs.exe", "python.exe", "regsvr32.exe", "dllhost.exe",
  "node.exe", "javaw.exe", "java.exe", "*.pif", "*.com") or

  ?process.code_signature.subject_name : ("AutoIt Consulting Ltd", "OpenJS Foundation", "Python Software Foundation") or

  (
    process.executable : ("?:\\Users\\*.exe", "?:\\ProgramData\\*.exe") and
    (?process.code_signature.trusted == false or ?process.code_signature.exists == false)
  )
 ) and
    dns.question.name : (
    // Major LLM APIs
    "api.openai.com",
    "*.openai.azure.com",
    "api.anthropic.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "api.ai21.com",
    "api.groq.com",
    "api.perplexity.ai",
    "api.x.ai",
    "api.deepseek.com",
    "api.gemini.google.com",
    "generativelanguage.googleapis.com",
    "api.azure.com",
    "api.bedrock.aws",
    "bedrock-runtime.amazonaws.com",

    // Hugging Face & other ML infra
    "api-inference.huggingface.co",
    "inference-endpoint.huggingface.cloud",
    "*.hf.space",
    "*.replicate.com",
    "api.replicate.com",
    "api.runpod.ai",
    "*.runpod.io",
    "api.modal.com",
    "*.forefront.ai",

    // Consumer-facing AI chat portals
    "chat.openai.com",
    "chatgpt.com",
    "copilot.microsoft.com",
    "bard.google.com",
    "gemini.google.com",
    "claude.ai",
    "perplexity.ai",
    "poe.com",
    "chat.forefront.ai",
    "chat.deepseek.com"
  ) and

  not process.executable : (
          "?:\\Program Files\\*.exe",
          "?:\\Program Files (x86)\\*.exe",
          "?:\\Windows\\System32\\svchost.exe",
          "?:\\Windows\\SystemApps\\Microsoft.LockApp_*\\LockApp.exe",
          "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
          "?:\\Users\\*\\AppData\\Local\\BraveSoftware\\*\\Application\\brave.exe",
          "?:\\Users\\*\\AppData\\Local\\Vivaldi\\Application\\vivaldi.exe",
          "?:\\Users\\*\\AppData\\Local\\Programs\\Opera*\\opera.exe",
          "?:\\Users\\*\\AppData\\Local\\Programs\\Fiddler\\Fiddler.exe"
        ) and
    not (?process.code_signature.trusted == true and
         ?process.code_signature.subject_name : ("Anthropic, PBC", "Google LLC", "Mozilla Corporation", "Brave Software, Inc.", "Island Technology Inc.", "Opera Norway AS"))
'''
```

## command_and_control_common_webservices
```
query = '''
network where host.os.type == "windows" and
    dns.question.name != null and process.name != null and
    not (?user.id in ("S-1-5-18", "S-1-5-19", "S-1-5-20") or user.domain == "NT AUTHORITY") and
    /* Add new WebSvc domains here */
    dns.question.name :
       (
        "raw.githubusercontent.*",
        "pastebin.*",
        "paste4btc.com",
        "paste.ee",
        "ghostbin.com",
        "drive.google.com",
        "?.docs.live.net",
        "api.dropboxapi.*",
        "content.dropboxapi.*",
        "dl.dropboxusercontent.*",
        "api.onedrive.com",
        "*.onedrive.org",
        "onedrive.live.com",
        "filebin.net",
        "*.ngrok.io",
        "ngrok.com",
        "*.portmap.*",
        "*serveo.net",
        "*localtunnel.me",
        "*pagekite.me",
        "*localxpose.io",
        "*notabug.org",
        "rawcdn.githack.*",
        "paste.nrecom.net",
        "zerobin.net",
        "controlc.com",
        "requestbin.net",
        "slack.com",
        "api.slack.com",
        "slack-redir.net",
        "slack-files.com",
        "cdn.discordapp.com",
        "discordapp.com",
        "discord.com",
        "apis.azureedge.net",
        "cdn.sql.gg",
        "?.top4top.io",
        "top4top.io",
        "www.uplooder.net",
        "*.cdnmegafiles.com",
        "transfer.sh",
        "gofile.io",
        "updates.peer2profit.com",
        "api.telegram.org",
        "t.me",
        "meacz.gq",
        "rwrd.org",
        "*.publicvm.com",
        "*.blogspot.com",
        "api.mylnikov.org",
        "file.io",
        "stackoverflow.com",
        "*files.1drv.com",
        "api.anonfile.com",
        "*hosting-profi.de",
        "ipbase.com",
        "ipfs.io",
        "*up.freeo*.space",
        "api.mylnikov.org",
        "script.google.com",
        "script.googleusercontent.com",
        "api.notion.com",
        "graph.microsoft.com",
        "*.sharepoint.com",
        "mbasic.facebook.com",
        "login.live.com",
        "api.gofile.io",
        "api.anonfiles.com",
        "api.notion.com",
        "api.trello.com",
        "gist.githubusercontent.com",
        "files.pythonhosted.org",
        "g.live.com",
        "*.zulipchat.com",
        "webhook.site",
        "run.mocky.io",
        "mockbin.org", 
        "www.googleapis.com", 
        "googleapis.com",
        "global.rel.tunnels.api.visualstudio.com",
        "*.devtunnels.ms", 
        "api.github.com") and
        
    /* Insert noisy false positives here */
    not (
      (
        process.executable : (
          "?:\\Program Files\\*.exe",
          "?:\\Program Files (x86)\\*.exe",
          "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
          "?:\\Users\\*\\AppData\\Local\\BraveSoftware\\*\\Application\\brave.exe",
          "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
          "?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
          "?:\\Users\\*\\AppData\\Local\\Programs\\Opera*\\opera.exe",
          "?:\\Users\\*\\AppData\\Local\\Programs\\Fiddler\\Fiddler.exe",
          "?:\\Users\\*\\AppData\\Local\\PowerToys\\PowerToys.exe",
          "?:\\Users\\*\\AppData\\Local\\Vivaldi\\Application\\vivaldi.exe",
          "?:\\Users\\*\\AppData\\Local\\Zen Browser\\zen.exe",
          "?:\\Users\\*\\Wavesor Software\\WaveBrowser\\wavebrowser.exe",
          "?:\\Windows\\System32\\MicrosoftEdgeCP.exe",
          "?:\\Windows\\system32\\mobsync.exe",
          "?:\\Windows\\SysWOW64\\mobsync.exe", 
          "?:\\Windows\\system32\\svchost.exe",
          "?:\\Windows\\System32\\smartscreen.exe",
          "?:\\Windows\\System32\\wsl.exe", 
          "?:\\Windows\\System32\\WWAHost.exe"
        )
      ) or
    
      /* Discord App */
      (process.name : "Discord.exe" and (process.code_signature.subject_name : "Discord Inc." and
       process.code_signature.trusted == true) and dns.question.name : ("discord.com", "cdn.discordapp.com", "discordapp.com")
      ) or 

      /* MS Sharepoint / OneDrive */
      (process.name : ("Microsoft.SharePoint.exe", "OneDrive.Sync.Service.exe") and dns.question.name : "onedrive.live.com" and
       (process.code_signature.subject_name : "Microsoft Corporation" and process.code_signature.trusted == true)
      ) or 

      /* Obsidian - Plugins are stored on raw.githubusercontent.com */
      (process.name : "Obsidian.exe" and (process.code_signature.subject_name : "Dynalist Inc" and
       process.code_signature.trusted == true) and dns.question.name : "raw.githubusercontent.com"
      ) or 

      /* WebExperienceHostApp */
      (process.name : "WebExperienceHostApp.exe" and (process.code_signature.subject_name : "Microsoft Windows" and
       process.code_signature.trusted == true) and dns.question.name : ("onedrive.live.com", "skyapi.onedrive.live.com")
      ) or

      /* IntelliJ IDEA connecting to raw.githubusercontent.com */
      (process.code_signature.subject_name : "JetBrains s.r.o." and
       process.code_signature.trusted == true and dns.question.name : ("api.github.com", "raw.githubusercontent.com")
      ) or 

      (process.code_signature.subject_name : "Microsoft *" and process.code_signature.trusted == true and
       dns.question.name : ("*.sharepoint.com", "graph.microsoft.com", "g.live.com", "login.live.com")
      ) or

      (process.code_signature.subject_name : ("Python Software Foundation", "Anaconda, Inc.") and
       process.code_signature.trusted == true and dns.question.name : "files.pythonhosted.org"
      ) or

      /* Zoom */
      (process.name : "Zoom.exe" and (process.code_signature.subject_name : "Zoom Video Communications, Inc." and
       process.code_signature.trusted == true) and dns.question.name : ("www.googleapis.com", "graph.microsoft.com")
      ) or

      /* VSCode */
      (process.name : "Code.exe" and (process.code_signature.subject_name : "Microsoft Corporation" and
       process.code_signature.trusted == true) and dns.question.name : ("api.github.com", "raw.githubusercontent.com")
      ) or

      /* Terraform */
      (process.name : "terraform-provider*.exe" and (process.code_signature.subject_name : "HashiCorp, Inc." and
       process.code_signature.trusted == true) and dns.question.name : "graph.microsoft.com"
      ) or

      (
        process.code_signature.trusted == true and
        process.code_signature.subject_name : (
                              "Johannes Schindelin",
                              "Redis Inc.",
                              "Slack Technologies, LLC",
                              "Cisco Systems, Inc.",
                              "Dropbox, Inc",
                              "Amazon.com Services LLC", 
                              "Island Technology Inc.", 
                              "GitHub, Inc.", 
                              "Red Hat, Inc",
                              "Mozilla Corporation"
        )
      )
    )
'''
```

## command_and_control_dns_susp_tld
```
query = '''
network where host.os.type == "windows" and dns.question.name != null and
 (
  process.name : ("MSBuild.exe", "mshta.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "rundll32.exe",
                  "bitsadmin.exe", "InstallUtil.exe", "python.exe", "regsvr32.exe", "dllhost.exe", "node.exe",
                  "java.exe", "javaw.exe", "*.pif", "*.com", "*.scr") or
  (?process.code_signature.trusted == false or ?process.code_signature.exists == false) or
  ?process.code_signature.subject_name : ("AutoIt Consulting Ltd", "OpenJS Foundation", "Python Software Foundation") or
  ?process.executable : ("?:\\Users\\*.exe", "?:\\ProgramData\\*.exe")
 ) and
dns.question.name regex """.*\.(top|buzz|xyz|rest|ml|cf|gq|ga|onion|monster|cyou|quest|cc|bar|cfd|click|cam|surf|tk|shop|club|icu|pw|ws|online|fun|life|boats|store|hair|skin|motorcycles|christmas|lol|makeup|mom|bond|beauty|biz|live|work|zip|country|accountant|date|party|science|loan|win|men|faith|review|racing|download|host)"""
'''
```

## command_and_control_dns_tunneling_nslookup
```
query = '''
sequence by host.id with maxspan=5m
[process where host.os.type == "windows" and event.type == "start" and
  process.name : "nslookup.exe" and process.args:("-querytype=*", "-qt=*", "-q=*", "-type=*")] with runs = 10
'''
```

## command_and_control_encrypted_channel_freesslcert
```
query = '''
network where host.os.type == "windows" and network.protocol == "dns" and
  /* Add new free SSL certificate provider domains here */
  dns.question.name : ("*letsencrypt.org", "*.sslforfree.com", "*.zerossl.com", "*.freessl.org") and

  /* Native Windows process paths that are unlikely to have network connections to domains secured using free SSL certificates */
  process.executable : ("C:\\Windows\\System32\\*.exe",
                        "C:\\Windows\\System\\*.exe",
	                  "C:\\Windows\\SysWOW64\\*.exe",
		          "C:\\Windows\\Microsoft.NET\\Framework*\\*.exe",
		          "C:\\Windows\\explorer.exe",
		          "C:\\Windows\\notepad.exe") and

  /* Insert noisy false positives here */
  not process.name : ("svchost.exe", "MicrosoftEdge*.exe", "msedge.exe")
'''
```

## command_and_control_headless_browser
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("chrome.exe", "msedge.exe", "brave.exe", "browser.exe", "dragon.exe", "vivaldi.exe") and
  process.args : "--headless*" and
  process.args : ("--disable-gpu", "--dump-dom", "*http*", "data:text/html;base64,*") and
  process.parent.name :
     ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "conhost.exe", "msiexec.exe",
      "explorer.exe", "rundll32.exe", "winword.exe", "excel.exe", "onenote.exe", "hh.exe", "powerpnt.exe", "forfiles.exe",
      "pcalua.exe", "wmiprvse.exe") and
  not process.executable : (
        "?:\\inetpub\\wwwroot\\*\\ext\\modules\\html2pdf\\bin\\chrome\\*\\chrome-win64\\chrome.exe",
        "\\Device\\HarddiskVolume*\\inetpub\\wwwroot\\*\\ext\\modules\\html2pdf\\bin\\chrome\\*\\chrome-win64\\chrome.exe"
  )
'''
```

## command_and_control_iexplore_via_com
```
query = '''
sequence by host.id, user.name with maxspan = 5s
  [library where host.os.type == "windows" and dll.name : "IEProxy.dll" and process.name : ("rundll32.exe", "regsvr32.exe")]
  [process where host.os.type == "windows" and event.type == "start" and process.parent.name : "iexplore.exe" and process.parent.args : "-Embedding"]
  /* IE started via COM in normal conditions makes few connections, mainly to Microsoft and OCSP related domains, add FPs here */
  [network where host.os.type == "windows" and network.protocol == "dns" and process.name : "iexplore.exe" and
   not dns.question.name :
   (
    "*.microsoft.com",
    "*.digicert.com",
    "*.msocsp.com",
    "*.windowsupdate.com",
    "*.bing.com",
    "*.identrust.com",
    "*.sharepoint.com",
    "*.office365.com",
    "*.office.com"
    )
  ] /* with runs=5 */
'''
```

## command_and_control_ingress_transfer_bits
```
query = '''
file where host.os.type == "windows" and event.action == "rename" and
  process.name : "svchost.exe" and file.Ext.original.name : "BIT*.tmp" and 
  (file.extension : ("exe", "zip", "rar", "bat", "dll", "ps1", "vbs", "wsh", "js", "vbe", "pif", "scr", "cmd", "cpl") or
   file.Ext.header_bytes : "4d5a*") and 
 
  /* noisy paths, for hunting purposes you can use the same query without the following exclusions */
  not file.path : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*", "?:\\Windows\\*", "?:\\ProgramData\\*\\*") and 
 
  /* lot of third party SW use BITS to download executables with a long file name */
  not length(file.name) > 30 and
  not file.path : (
        "?:\\Users\\*\\AppData\\Local\\Temp*\\wct*.tmp",
        "?:\\Users\\*\\AppData\\Local\\Adobe\\ARM\\*\\RdrServicesUpdater*.exe",
        "?:\\Users\\*\\AppData\\Local\\Adobe\\ARM\\*\\AcroServicesUpdater*.exe",
        "?:\\Users\\*\\AppData\\Local\\Docker Desktop Installer\\update-*.exe"
  )
'''
```

## command_and_control_new_terms_commonly_abused_rat_execution
```
query = '''
host.os.type: "windows" and

   event.category: "process" and event.type : "start" and

    (
        process.code_signature.subject_name : (
            "Action1 Corporation" or
            "AeroAdmin LLC" or
            "Ammyy LLC" or
            "Atera Networks Ltd" or
            "AWERAY PTE. LTD." or
            "BeamYourScreen GmbH" or
            "Bomgar Corporation" or
            "DUC FABULOUS CO.,LTD" or
            "DOMOTZ INC." or
            "DWSNET OÜ" or
            "FleetDeck Inc" or
            "GlavSoft LLC" or
            "GlavSoft LLC." or
            "Hefei Pingbo Network Technology Co. Ltd" or
            "IDrive, Inc." or
            "IMPERO SOLUTIONS LIMITED" or
            "Instant Housecall" or
            "ISL Online Ltd." or
            "LogMeIn, Inc." or
            "Monitoring Client" or
            "MMSOFT Design Ltd." or
            "Nanosystems S.r.l." or
            "NetSupport Ltd" or 
	    "NetSupport Ltd." or 
	    "NETSUPPORT LTD." or 
            "NinjaRMM, LLC" or
            "Parallels International GmbH" or
            "philandro Software GmbH" or
            "Pro Softnet Corporation" or
            "RealVNC" or
            "RealVNC Limited" or
            "BreakingSecurity.net" or
            "Remote Utilities LLC" or
            "Rocket Software, Inc." or
            "SAFIB" or
            "Servably, Inc." or
            "ShowMyPC INC" or
            "Splashtop Inc." or
            "Superops Inc." or
            "TeamViewer" or
            "TeamViewer GmbH" or
            "TeamViewer Germany GmbH" or
            "Techinline Limited" or
            "uvnc bvba" or
            "Yakhnovets Denis Aleksandrovich IP" or
            "Zhou Huabing"
        ) or

        process.name.caseless : (
            AA_v*.exe or
            "AeroAdmin.exe" or
            "AnyDesk.exe" or
            "apc_Admin.exe" or
            "apc_host.exe" or
            "AteraAgent.exe" or
            aweray_remote*.exe or
            "AweSun.exe" or
            "B4-Service.exe" or
            "BASupSrvc.exe" or
            "bomgar-scc.exe" or
            "domotzagent.exe" or
            "domotz-windows-x64-10.exe" or
            "dwagsvc.exe" or
            "DWRCC.exe" or
            "ImperoClientSVC.exe" or
            "ImperoServerSVC.exe" or
            "ISLLight.exe" or
            "ISLLightClient.exe" or
            fleetdeck_commander*.exe or
            "getscreen.exe" or
            "LMIIgnition.exe" or
            "LogMeIn.exe" or
            "ManageEngine_Remote_Access_Plus.exe" or
            "Mikogo-Service.exe" or
            "NinjaRMMAgent.exe" or
            "NinjaRMMAgenPatcher.exe" or
            "ninjarmm-cli.exe" or
            "r_server.exe" or
            "radmin.exe" or
            "radmin3.exe" or
            "RCClient.exe" or
            "RCService.exe" or
            "RemoteDesktopManager.exe" or
            "RemotePC.exe" or
            "RemotePCDesktop.exe" or
            "RemotePCService.exe" or
            "rfusclient.exe" or
            "ROMServer.exe" or
            "ROMViewer.exe" or
            "RPCSuite.exe" or
            "rserver3.exe" or
            "rustdesk.exe" or
            "rutserv.exe" or
            "rutview.exe" or
            "saazapsc.exe" or
            ScreenConnect*.exe or
            "smpcview.exe" or
            "spclink.exe" or
            "Splashtop-streamer.exe" or
            "SRService.exe" or
            "strwinclt.exe" or
            "Supremo.exe" or
            "SupremoService.exe" or
            "teamviewer.exe" or
            "TiClientCore.exe" or
            "TSClient.exe" or
            "tvn.exe" or
            "tvnserver.exe" or
            "tvnviewer.exe" or
            UltraVNC*.exe or
            UltraViewer*.exe or
            "vncserver.exe" or
            "vncviewer.exe" or
            "winvnc.exe" or
            "winwvc.exe" or
            "Zaservice.exe" or
            "ZohoURS.exe"
        ) or
        process.name : (
            AA_v*.exe or
            "AeroAdmin.exe" or
            "AnyDesk.exe" or
            "apc_Admin.exe" or
            "apc_host.exe" or
            "AteraAgent.exe" or
            aweray_remote*.exe or
            "AweSun.exe" or
            "B4-Service.exe" or
            "BASupSrvc.exe" or
            "bomgar-scc.exe" or
            "domotzagent.exe" or
            "domotz-windows-x64-10.exe" or
            "dwagsvc.exe" or
            "DWRCC.exe" or
            "ImperoClientSVC.exe" or
            "ImperoServerSVC.exe" or
            "ISLLight.exe" or
            "ISLLightClient.exe" or
            fleetdeck_commander*.exe or
            "getscreen.exe" or
            "LMIIgnition.exe" or
            "LogMeIn.exe" or
            "ManageEngine_Remote_Access_Plus.exe" or
            "Mikogo-Service.exe" or
            "NinjaRMMAgent.exe" or
            "NinjaRMMAgenPatcher.exe" or
            "ninjarmm-cli.exe" or
            "r_server.exe" or
            "radmin.exe" or
            "radmin3.exe" or
            "RCClient.exe" or
            "RCService.exe" or
            "RemoteDesktopManager.exe" or
            "RemotePC.exe" or
            "RemotePCDesktop.exe" or
            "RemotePCService.exe" or
            "rfusclient.exe" or
            "ROMServer.exe" or
            "ROMViewer.exe" or
            "RPCSuite.exe" or
            "rserver3.exe" or
            "rustdesk.exe" or
            "rutserv.exe" or
            "rutview.exe" or
            "saazapsc.exe" or
            ScreenConnect*.exe or
            "smpcview.exe" or
            "spclink.exe" or
            "Splashtop-streamer.exe" or
            "SRService.exe" or
            "strwinclt.exe" or
            "Supremo.exe" or
            "SupremoService.exe" or
            "teamviewer.exe" or
            "TiClientCore.exe" or
            "TSClient.exe" or
            "tvn.exe" or
            "tvnserver.exe" or
            "tvnviewer.exe" or
            UltraVNC*.exe or
            UltraViewer*.exe or
            "vncserver.exe" or
            "vncviewer.exe" or
            "winvnc.exe" or
            "winwvc.exe" or
            "Zaservice.exe" or
            "ZohoURS.exe"
        )
	) and

	not (process.pe.original_file_name : ("G2M.exe" or "Updater.exe" or "powershell.exe") and process.code_signature.subject_name : "LogMeIn, Inc.")
'''
```

## command_and_control_outlook_home_page
```
query = '''
registry where host.os.type == "windows" and event.action != "deletion" and registry.value : "URL" and
    registry.path : (
        "*\\SOFTWARE\\Microsoft\\Office\\*\\Outlook\\Webview\\*",
        "*\\SOFTWARE\\Microsoft\\Office\\*\\Outlook\\Today\\*"
    ) and registry.data.strings : ("*://*", "*:\\*")
'''
```

## command_and_control_port_forwarding_added_registry
```
query = '''
registry where host.os.type == "windows" and event.type == "change" and 
  registry.path : "*\\SYSTEM\\*ControlSet*\\Services\\PortProxy\\v4tov4\\*" and registry.data.strings != null
'''
```

## command_and_control_rdp_tunnel_plink
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  /* RDP port and usual SSH tunneling related switches in command line */
  process.args : "*:3389" and
  process.args : ("-L", "-P", "-R", "-pw", "-ssh")
'''
```

## command_and_control_remcos_rat_iocs
```
query = '''
any where host.os.type == "windows" and
(
 (event.category == "file" and event.type == "deletion" and file.path like "C:\\Users\\*\\AppData\\Local\\Temp\\TH????.tmp") or

 (event.category == "file" and file.path : "?:\\Users\\*\\AppData\\Roaming\\remcos\\logs.dat") or

 (event.category == "registry" and
  registry.value : ("Remcos", "Rmc-??????", "licence") and
  registry.path : (
      "*\\Windows\\CurrentVersion\\Run\\Remcos",
      "*\\Windows\\CurrentVersion\\Run\\Rmc-??????",
      "*\\SOFTWARE\\Remcos-*\\licence",
      "*\\Software\\Rmc-??????\\licence"
  )
 )
)
'''
```

## command_and_control_remote_file_copy_desktopimgdownldr
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "desktopimgdownldr.exe" or ?process.pe.original_file_name == "desktopimgdownldr.exe") and
  process.args : "/lockscreenurl:http*"
'''
```

## command_and_control_remote_file_copy_mpcmdrun
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "MpCmdRun.exe" or ?process.pe.original_file_name == "MpCmdRun.exe") and
   process.args : "-DownloadFile" and process.args : "-url" and process.args : "-path"
'''
```

## command_and_control_remote_file_copy_powershell
```
query = '''
sequence by process.entity_id with maxspan=30s
[network where host.os.type == "windows" and 
  process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and
  network.protocol == "dns" and
  not dns.question.name : (
        "*.microsoft.com", "*.azureedge.net", "*.powershellgallery.com", "*.windowsupdate.com",
        "metadata.google.internal", "dist.nuget.org", "artifacts.elastic.co", "*.digicert.com",
        "*.chocolatey.org", "outlook.office365.com", "cdn.oneget.org", "ci.dot.net",
        "packages.icinga.com", "login.microsoftonline.com", "*.gov", "*.azure.com", "*.python.org",
        "dl.google.com", "sensor.cloud.tenable.com", "*.azurefd.net", "*.office.net", "*.anac*",
        "aka.ms", "dot.net", "*.visualstudio.com", "*.local") and
  not user.id == "S-1-5-18" and
  /* Filter out NetBIOS/LLMNR-style names (e.g. host, localhost, etc.) */
  dns.question.name regex """.*\.[a-zA-Z]{2,5}"""]
[file where host.os.type == "windows" and event.type == "creation" and
  process.name : "powershell.exe" and 
  (file.extension : ("exe", "dll", "ps1", "bat") or file.Ext.header_bytes : "4d5a*") and
  not file.name : "__PSScriptPolicy*.ps1" and
  not file.path : (
        "?:\\Users\\*\\AppData\\Local\\Temp\\????????.dll",
        "?:\\Users\\*\\AppData\\Local\\Temp\\*\\????????.dll",
        "?:\\Windows\\TEMP\\ansible-tmp-*\\AnsiballZ*.ps1"
  ) and
  not user.id == "S-1-5-18"]
'''
```

## command_and_control_remote_file_copy_scripts
```
query = '''
sequence by host.id, process.entity_id
  [network where host.os.type == "windows" and process.name : ("wscript.exe", "cscript.exe") and network.protocol != "dns" and
   network.direction : ("outgoing", "egress") and network.type == "ipv4" and destination.ip != "127.0.0.1"
  ]
  [file where host.os.type == "windows" and event.type == "creation" and file.extension : ("exe", "dll")]
'''
```

## command_and_control_rmm_netsupport_susp_path
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "client32.exe" or ?process.pe.original_file_name == "client32.exe" or process.parent.name : "client32.exe") and
 (
  process.executable :
               ("?:\\Users\\*.exe",
                "?:\\ProgramData\\*.exe",
                "\\Device\\HarddiskVolume?\\Users\\*.exe",
                "\\Device\\HarddiskVolume?\\ProgramData\\*.exe") or
  ?process.parent.executable : ("?:\\Users\\*\\client32.exe", "?:\\ProgramData\\*\\client32.exe")
  )
'''
```

## command_and_control_screenconnect_childproc
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name :
                ("ScreenConnect.ClientService.exe",
                 "ScreenConnect.WindowsClient.exe",
                 "ScreenConnect.WindowsBackstageShell.exe",
                 "ScreenConnect.WindowsFileManager.exe") and
  (
   (process.name : "powershell.exe" and
    process.args : ("-enc", "-ec", "-e", "*downloadstring*", "*Reflection.Assembly*", "*http*")) or
   (process.name : "cmd.exe" and process.args : "/c") or
   (process.name : "net.exe" and process.args : "/add") or
   (process.name : "schtasks.exe" and process.args : ("/create", "-create")) or
   (process.name : "sc.exe" and process.args : "create") or
   (process.name : "rundll32.exe" and not process.args : "url.dll,FileProtocolHandler") or
   (process.name : "msiexec.exe" and process.args : ("/i", "-i") and
    process.args : ("/q", "/quiet", "/qn", "-q", "-quiet", "-qn", "-Q+")) or
   process.name : ("mshta.exe", "certutil.exe", "bistadmin.exe", "certreq.exe", "wscript.exe", "cscript.exe", "curl.exe",
                   "ssh.exe", "scp.exe", "wevtutil.exe", "wget.exe", "wmic.exe")
   )
'''
```

## command_and_control_sunburst_c2_activity_detected
```
query = '''
network where host.os.type == "windows" and event.type == "protocol" and network.protocol == "http" and
  process.name : ("ConfigurationWizard.exe",
                  "NetFlowService.exe",
                  "NetflowDatabaseMaintenance.exe",
                  "SolarWinds.Administration.exe",
                  "SolarWinds.BusinessLayerHost.exe",
                  "SolarWinds.BusinessLayerHostx64.exe",
                  "SolarWinds.Collector.Service.exe",
                  "SolarwindsDiagnostics.exe") and
  (
    (
      (http.request.body.content : "*/swip/Upload.ashx*" and http.request.body.content : ("POST*", "PUT*")) or
      (http.request.body.content : ("*/swip/SystemDescription*", "*/swip/Events*") and http.request.body.content : ("GET*", "HEAD*"))
    ) and
    not http.request.body.content : "*solarwinds.com*"
  )
'''
```

## command_and_control_teamviewer_remote_file_copy
```
query = '''
file where host.os.type == "windows" and event.type == "creation" and process.name : "TeamViewer.exe" and
  file.extension : ("exe", "dll", "scr", "com", "bat", "ps1", "vbs", "vbe", "js", "wsh", "hta") and
  not 
  (
    file.path : (
      "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\*.js",
      "?:\\Users\\*\\AppData\\Local\\Temp\\TeamViewer\\update.exe",
      "?:\\Users\\*\\AppData\\Local\\Temp\\?\\TeamViewer\\update.exe",
      "?:\\Users\\*\\AppData\\Local\\TeamViewer\\CustomConfigs\\???????\\TeamViewer_Resource_??.dll",
      "?:\\Users\\*\\AppData\\Local\\TeamViewer\\CustomConfigs\\???????\\TeamViewer*.exe"
    ) and process.code_signature.trusted == true
  )
'''
```

## command_and_control_tool_transfer_via_curl
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.executable : (
    "?:\\Windows\\System32\\curl.exe",
    "?:\\Windows\\SysWOW64\\curl.exe"
  ) and
  process.command_line : "*http*" and
  process.parent.name : (
    "cmd.exe", "powershell.exe",
    "rundll32.exe", "explorer.exe",
    "conhost.exe", "forfiles.exe",
    "wscript.exe", "cscript.exe",
    "mshta.exe", "hh.exe", "mmc.exe"
  ) and 
  not (
    ?user.id == "S-1-5-18" and
    /* Don't apply the user.id exclusion to Sysmon for compatibility */
    not event.dataset : ("windows.sysmon_operational", "windows.sysmon")
  ) and
  /* Exclude System Integrity Processes for Sysmon */
  not ?winlog.event_data.IntegrityLevel == "System"
'''
```

## command_and_control_tunnel_vscode
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.args : "tunnel" and (process.args : "--accept-server-license-terms" or process.name : "code*.exe") and
  not (process.name == "code-tunnel.exe" and process.args == "status" and process.parent.name == "Code.exe")
'''
```

## credential_access_adidns_wildcard
```
query = '''
any where host.os.type == "windows" and event.code == "5137" and
    startsWith(winlog.event_data.ObjectDN, "DC=*,")
'''
```

## credential_access_adidns_wpad_record
```
query = '''
any where host.os.type == "windows" and event.code == "5137" and winlog.event_data.ObjectDN : "DC=wpad,*"
'''
```

## credential_access_browsers_unusual_parent
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("chrome.exe", "msedge.exe") and
  process.parent.executable != null and process.command_line != null and
  (
  process.command_line :
           ("\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\"",
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"",
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --headless --disable-logging --log-level=3 --v=0",
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --headless --log-level=3",
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --headless",
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --remote-debugging-port=922? --profile-directory=\"Default\"*",
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --headless --restore-last-session --remote-debugging-port=45452*") or

  (process.args : "--remote-debugging-port=922?" and process.args : "--window-position=-*,-*")
   ) and
  not process.parent.executable :
                         ("C:\\Windows\\explorer.exe",
                          "C:\\Program Files (x86)\\*.exe",
                          "C:\\Program Files\\*.exe",
                          "C:\\Windows\\System32\\rdpinit.exe",
                          "C:\\Windows\\System32\\sihost.exe",
                          "C:\\Windows\\System32\\RuntimeBroker.exe",
                          "C:\\Windows\\System32\\SECOCL64.exe")
'''
```

## credential_access_bruteforce_admin_account
```
query = '''
sequence by winlog.computer_name, source.ip with maxspan=10s
  [authentication where host.os.type == "windows" and
    event.action == "logon-failed" and winlog.logon.type : "Network" and
    source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1" and user.name : "*admin*" and

    /* noisy failure status codes often associated to authentication misconfiguration */
    not winlog.event_data.Status : ("0xC000015B", "0XC000005E", "0XC0000133", "0XC0000192")] with runs=5
'''
```

## credential_access_bruteforce_multiple_logon_failure_followed_by_success
```
query = '''
sequence by winlog.computer_name, source.ip with maxspan=5s
  [authentication where host.os.type == "windows" and event.action == "logon-failed" and
    /* event 4625 need to be logged */
    winlog.logon.type : "Network" and user.id != null and 
    source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1" and 
    not winlog.event_data.TargetUserSid : "S-1-0-0" and not user.id : "S-1-0-0" and 
    not user.name : ("ANONYMOUS LOGON", "-", "*$") and not user.domain == "NT AUTHORITY" and

    /* noisy failure status codes often associated to authentication misconfiguration */
    not winlog.event_data.Status : ("0xC000015B", "0XC000005E", "0XC0000133", "0XC0000192")] with runs=5
  [authentication where host.os.type == "windows" and event.action == "logged-in" and
    /* event 4624 need to be logged */
    winlog.logon.type : "Network" and
    source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1" and
    not user.name : ("ANONYMOUS LOGON", "-", "*$") and not user.domain == "NT AUTHORITY"]
'''
```

## credential_access_bruteforce_multiple_logon_failure_same_srcip
```
query = '''
sequence by winlog.computer_name, source.ip with maxspan=10s
  [authentication where host.os.type == "windows" and event.action == "logon-failed" and
    /* event 4625 need to be logged */
    winlog.logon.type : "Network" and
    source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1" and
    not user.name : ("ANONYMOUS LOGON", "-", "*$") and not user.domain == "NT AUTHORITY" and

    /*
    noisy failure status codes often associated to authentication misconfiguration :
     0xC000015B - The user has not been granted the requested logon type (also called the logon right) at this machine.
     0XC000005E	- There are currently no logon servers available to service the logon request.
     0XC0000133	- Clocks between DC and other computer too far out of sync.
     0XC0000192	An attempt was made to logon, but the Netlogon service was not started.
    */
    not winlog.event_data.Status : ("0xC000015B", "0XC000005E", "0XC0000133", "0XC0000192")] with runs=10
'''
```

## credential_access_cmdline_dump_tool
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
(
  (
    (?process.pe.original_file_name : "procdump" or process.name : "procdump.exe") and process.args : "-ma"
  ) or
  (
    process.name : "ProcessDump.exe" and not process.parent.executable regex~ """C:\\Program Files( \(x86\))?\\Cisco Systems\\.*"""
  ) or
  (
    (?process.pe.original_file_name : "WriteMiniDump.exe" or process.name : "WriteMiniDump.exe") and
      not process.parent.executable regex~ """C:\\Program Files( \(x86\))?\\Steam\\.*"""
  ) or
  (
    (?process.pe.original_file_name : "RUNDLL32.EXE" or process.name : "RUNDLL32.exe") and
      (process.args : "*MiniDump*" or process.command_line : "*comsvcs*#*24*")
  ) or
  (
    (?process.pe.original_file_name : "RdrLeakDiag.exe" or process.name : "RdrLeakDiag.exe") and
      process.args : "/fullmemdmp"
  ) or
  (
    (?process.pe.original_file_name : "SqlDumper.exe" or process.name : "SqlDumper.exe") and
      process.args : "0x01100*") or
  (
    (?process.pe.original_file_name : "TTTracer.exe" or process.name : "TTTracer.exe") and
      process.args : "-dumpFull" and process.args : "-attach") or
  (
    (?process.pe.original_file_name : "ntdsutil.exe" or process.name : "ntdsutil.exe") and
      process.args : "cr*fu*") or
  (
    (?process.pe.original_file_name : "diskshadow.exe" or process.name : "diskshadow.exe") and process.args : "/s")
)
'''
```

## credential_access_copy_ntds_sam_volshadowcp_cmdline
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (
    ((?process.pe.original_file_name in ("Cmd.Exe", "PowerShell.EXE", "XCOPY.EXE") or process.name : ("Cmd.Exe", "PowerShell.EXE", "XCOPY.EXE")) and
       process.args : ("copy", "xcopy", "Copy-Item", "move", "cp", "mv")
    ) or
    ((?process.pe.original_file_name : "esentutl.exe" or process.name : "esentutl.exe") and process.args : ("*/y*", "*/vss*", "*/d*"))
  ) and
  process.command_line : ("*\\ntds.dit*", "*\\config\\SAM*", "*\\*\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\*", "*/system32/config/SAM*", "*\\User Data\\*")
'''
```

## credential_access_credential_dumping_msbuild
```
query = '''
sequence by process.entity_id
 [process where host.os.type == "windows" and event.type == "start" and (process.name : "MSBuild.exe" or process.pe.original_file_name == "MSBuild.exe")]
 [any where host.os.type == "windows" and (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
  (?dll.name : ("vaultcli.dll", "SAMLib.DLL") or file.name : ("vaultcli.dll", "SAMLib.DLL"))]
'''
```

## credential_access_dcsync_newterm_subjectuser
```
query = '''
event.code:"4662" and host.os.type:"windows" and 
  winlog.event_data.Properties:(
    *DS-Replication-Get-Changes* or *DS-Replication-Get-Changes-All* or
    *DS-Replication-Get-Changes-In-Filtered-Set* or *1131f6ad-9c07-11d1-f79f-00c04fc2dcd2* or
    *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2* or *89e95b76-444d-4c62-991a-0facbeda640c*) and
  not winlog.event_data.SubjectUserName:(*$ or MSOL_*)
'''
```

## credential_access_dcsync_replication_rights
```
query = '''
host.os.type:"windows" and event.code:"4662" and
  winlog.event_data.Properties:(
    *DS-Replication-Get-Changes* or *DS-Replication-Get-Changes-All* or
    *DS-Replication-Get-Changes-In-Filtered-Set* or *1131f6ad-9c07-11d1-f79f-00c04fc2dcd2* or
    *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2* or *89e95b76-444d-4c62-991a-0facbeda640c*
  ) and winlog.event_data.AccessMask : "0x100" and
  not winlog.event_data.SubjectUserName:(*$ or MSOL_*)
'''
```

## credential_access_dcsync_user_backdoor
```
query = '''
event.code:"5136" and host.os.type:"windows" and
  winlog.event_data.AttributeLDAPDisplayName:"nTSecurityDescriptor" and
  winlog.event_data.AttributeValue : (
    (
      *1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-* and
      *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-* and
      *89e95b76-444d-4c62-991a-0facbeda640c;;S-1-5-21-*
    )
  )
'''
```

## credential_access_disable_kerberos_preauth
```
query = '''
any where host.os.type == "windows" and event.code == "4738" and
  winlog.event_data.NewUACList == "USER_DONT_REQUIRE_PREAUTH"
'''
```

## credential_access_dnsnode_creation
```
query = '''
any where host.os.type == "windows" and event.code == "5137" and winlog.event_data.ObjectClass == "dnsNode" and
    not winlog.event_data.SubjectUserName : "*$"
'''
```

## credential_access_dollar_account_relay
```
query = '''
authentication where host.os.type == "windows" and event.code in ("4624", "4625") and
    endswith~(user.name, "$") and winlog.logon.type : "network" and

    /* Filter for a machine account that matches the hostname */
    startswith~(host.name, substring(user.name, 0, -1)) and

    /* Verify if the Source IP belongs to the host */
    not endswith(string(source.ip), string(host.ip)) and
    source.ip != null and source.ip != "::1" and source.ip != "127.0.0.1"
'''
```

## credential_access_dollar_account_relay_kerberos
```
query = '''
sequence by winlog.computer_name, source.ip with maxspan=5s

/* Filter for an event that indicates coercion against known abused named pipes using an account that is not the host */
[file where host.os.type == "windows" and event.code : "5145" and 
    not startswith~(winlog.computer_name, substring(user.name, 0, -1)) and
    file.name : (
        "Spoolss", "netdfs", "lsarpc", "lsass", "netlogon", "samr", "efsrpc", "FssagentRpc",
        "eventlog", "winreg", "srvsvc", "dnsserver", "dhcpserver", "WinsPipe"
    )]

/* Detects a logon attempt using the Kerberos protocol resulting from the coercion coming from the same IP address */
[authentication where host.os.type == "windows" and event.code in ("4624", "4625") and
    endswith~(user.name, "$") and winlog.logon.type : "network" and
    winlog.event_data.AuthenticationPackageName : "Kerberos" and

    /* Filter for a machine account that matches the hostname */
    startswith~(winlog.computer_name, substring(user.name, 0, -1)) and

    /* Verify if the Source IP belongs to the host */
    not endswith(string(source.ip), string(host.ip)) and
    source.ip != null and source.ip != "::1" and source.ip != "127.0.0.1"]
'''
```

## credential_access_dollar_account_relay_ntlm
```
query = '''
sequence by winlog.computer_name, source.ip with maxspan=5s

/* Filter for an event that indicates coercion against known abused named pipes using an account that is not the host */
[file where host.os.type == "windows" and event.code : "5145" and 
    not startswith~(winlog.computer_name, substring(user.name, 0, -1)) and
    file.name : (
        "Spoolss", "netdfs", "lsarpc", "lsass", "netlogon", "samr", "efsrpc", "FssagentRpc",
        "eventlog", "winreg", "srvsvc", "dnsserver", "dhcpserver", "WinsPipe"
    )]

/* Detects a logon attempt using the NTLM protocol resulting from the coercion coming from the same IP address */
[authentication where host.os.type == "windows" and event.code in ("4624", "4625") and
    endswith~(user.name, "$") and winlog.logon.type : "network" and
    winlog.event_data.AuthenticationPackageName : "NTLM" and

    /* Filter for a machine account that matches the hostname */
    startswith~(winlog.computer_name, substring(user.name, 0, -1)) and

    /* Verify if the Source IP belongs to the host */
    not endswith(string(source.ip), string(host.ip)) and
    source.ip != null and source.ip != "::1" and source.ip != "127.0.0.1"]
'''
```

## credential_access_domain_backup_dpapi_private_keys
```
query = '''
file where host.os.type == "windows" and event.type != "deletion" and file.name : ("ntds_capi_*.pfx", "ntds_capi_*.pvk")
'''
```

## credential_access_dump_registry_hives
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 (?process.pe.original_file_name == "reg.exe" or process.name : "reg.exe") and
 process.args : ("save", "export") and
 process.args : ("hklm\\sam", "hklm\\security")
'''
```

## credential_access_generic_localdumps
```
query = '''
registry where host.os.type == "windows" and
    registry.path : (
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\DumpType",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\DumpType"
    ) and
    registry.data.strings : ("2", "0x00000002") and
    not (process.executable : "?:\\Windows\\system32\\svchost.exe" and user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20"))
'''
```

## credential_access_iis_connectionstrings_dumping
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "aspnet_regiis.exe" or ?process.pe.original_file_name == "aspnet_regiis.exe") and
  process.args : "connectionStrings" and process.args : "-pdf"
'''
```

## credential_access_imageload_azureadconnectauthsvc
```
query = '''
any where host.os.type == "windows" and process.name : "AzureADConnectAuthenticationAgentService.exe" and
(
 (event.category == "library" and event.action == "load") or
 (event.category == "process" and event.action : "Image loaded*")
) and

not (?dll.code_signature.trusted == true or file.code_signature.status == "Valid") and not

  (
   /* Elastic defend DLL path */
   ?dll.path :
         ("?:\\Windows\\assembly\\NativeImages*",
          "?:\\Windows\\Microsoft.NET\\*",
          "?:\\Windows\\WinSxS\\*",
          "?:\\Windows\\System32\\DriverStore\\FileRepository\\*") or

   /* Sysmon DLL path is mapped to file.path */
   file.path :
         ("?:\\Windows\\assembly\\NativeImages*",
          "?:\\Windows\\Microsoft.NET\\*",
          "?:\\Windows\\WinSxS\\*",
          "?:\\Windows\\System32\\DriverStore\\FileRepository\\*")
  )
'''
```

## credential_access_kerberoasting_unusual_process
```
query = '''
network where host.os.type == "windows" and event.type == "start" and network.direction == "egress" and
  destination.port == 88 and source.port >= 49152 and process.pid != 4 and destination.address : "*" and
  not 
  (
    process.executable : (
        "\\device\\harddiskvolume?\\program files (x86)\\nmap\\nmap.exe",
        "\\device\\harddiskvolume?\\program files (x86)\\nmap oem\\nmap.exe",
        "\\device\\harddiskvolume?\\windows\\system32\\lsass.exe",
        "?:\\Program Files\\Amazon Corretto\\jdk1*\\bin\\java.exe",
        "?:\\Program Files\\BlackBerry\\UEM\\Proxy Server\\bin\\prunsrv.exe",
        "?:\\Program Files\\BlackBerry\\UEM\\Core\\tomcat-core\\bin\\tomcat9.exe",
        "?:\\Program Files\\DBeaver\\dbeaver.exe",
        "?:\\Program Files\\Docker\\Docker\\resources\\com.docker.backend.exe",
        "?:\\Program Files\\Docker\\Docker\\resources\\com.docker.vpnkit.exe",
        "?:\\Program Files\\Docker\\Docker\\resources\\vpnkit.exe",
        "?:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "?:\\Program Files\\Internet Explorer\\iexplore.exe",
        "?:\\Program Files\\JetBrains\\PyCharm Community Edition*\\bin\\pycharm64.exe",
        "?:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "?:\\Program Files\\Oracle\\VirtualBox\\VirtualBoxVM.exe",
        "?:\\Program Files\\Puppet Labs\\Puppet\\puppet\\bin\\ruby.exe",
        "?:\\Program Files\\rapid7\\nexpose\\nse\\.DLLCACHE\\nseserv.exe",
        "?:\\Program Files\\Silverfort\\Silverfort AD Adapter\\SilverfortServer.exe",
        "?:\\Program Files\\Tenable\\Nessus\\nessusd.exe",
        "?:\\Program Files\\VMware\\VMware View\\Server\\bin\\ws_TomcatService.exe",
        "?:\\Program Files (x86)\\Advanced Port Scanner\\advanced_port_scanner.exe",
        "?:\\Program Files (x86)\\DesktopCentral_Agent\\bin\\dcpatchscan.exe",
        "?:\\Program Files (x86)\\GFI\\LanGuard 12 Agent\\lnsscomm.exe",
        "?:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        "?:\\Program Files (x86)\\Internet Explorer\\iexplore.exe",
        "?:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "?:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
        "?:\\Program Files (x86)\\Microsoft Silverlight\\sllauncher.exe",
        "?:\\Program Files (x86)\\Nmap\\nmap.exe",
        "?:\\Program Files (x86)\\Nmap OEM\\nmap.exe",
        "?:\\Program Files (x86)\\nwps\\NetScanTools Pro\\NSTPRO.exe",
        "?:\\Program Files (x86)\\SAP BusinessObjects\\tomcat\\bin\\tomcat9.exe",
        "?:\\Program Files (x86)\\SuperScan\\scanner.exe",
        "?:\\Program Files (x86)\\Zscaler\\ZSATunnel\\ZSATunnel.exe",
        "?:\\Windows\\System32\\lsass.exe",
        "?:\\Windows\\System32\\MicrosoftEdgeCP.exe",
        "?:\\Windows\\System32\\svchost.exe",
        "?:\\Windows\\SysWOW64\\vmnat.exe",
        "?:\\Windows\\SystemApps\\Microsoft.MicrosoftEdge_*\\MicrosoftEdge.exe",
        "System"
    ) and process.code_signature.trusted == true
  ) and
 destination.address != "127.0.0.1" and destination.address != "::1"
'''
```

## credential_access_kerberos_coerce
```
query = '''
host.os.type:"windows" and
(
  (event.code:4662 and winlog.event_data.AdditionalInfo: *UWhRC*BAAAA*MicrosoftDNS*) or 
  (event.code:5137 and winlog.event_data.ObjectDN: *UWhRC*BAAAA*MicrosoftDNS*)
)
'''
```

## credential_access_kerberos_coerce_dns
```
query = '''
network where host.os.type == "windows" and dns.question.name : "*UWhRC*BAAAA*"
'''
```

## credential_access_kirbi_file
```
query = '''
file where host.os.type == "windows" and event.type == "creation" and file.extension : "kirbi"
'''
```

## credential_access_ldap_attributes
```
query = '''
any where host.os.type == "windows" and event.code == "4662" and

  not winlog.event_data.SubjectUserSid : "S-1-5-18" and

  winlog.event_data.Properties : (
   /* unixUserPassword */
  "*612cb747-c0e8-4f92-9221-fdd5f15b550d*",

  /* ms-PKI-AccountCredentials */
  "*b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7*",

  /*  ms-PKI-DPAPIMasterKeys */
  "*b3f93023-9239-4f7c-b99c-6745d87adbc2*",

  /* msPKI-CredentialRoamingTokens */
  "*b7ff5a38-0818-42b0-8110-d3d154c97f24*"
  ) and

  /*
   Excluding noisy AccessMasks
   0x0 undefined and 0x100 Control Access
   https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
   */
  not winlog.event_data.AccessMask in ("0x0", "0x100")
'''
```
 
## credential_access_lsass_handle_via_malseclogon
```
query = '''
process where host.os.type == "windows" and event.code == "10" and
  winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe" and

   /* seclogon service accessing lsass */
  winlog.event_data.CallTrace : "*seclogon.dll*" and process.name : "svchost.exe" and

   /* PROCESS_CREATE_PROCESS & PROCESS_DUP_HANDLE & PROCESS_QUERY_INFORMATION */
  winlog.event_data.GrantedAccess == "0x14c0"
'''
```

## credential_access_lsass_loaded_susp_dll
```
query = '''
any where event.category in ("library", "driver") and host.os.type == "windows" and
  process.executable : "?:\\Windows\\System32\\lsass.exe" and
  not (dll.code_signature.subject_name :
               ("Microsoft Windows",
                "Microsoft Corporation",
                "Microsoft Windows Publisher",
                "Microsoft Windows Software Compatibility Publisher",
                "Microsoft Windows Hardware Compatibility Publisher",
                "McAfee, Inc.",
                "SecMaker AB",
                "HID Global Corporation",
                "HID Global",
                "Apple Inc.",
                "Citrix Systems, Inc.",
                "Dell Inc",
                "Hewlett-Packard Company",
                "Symantec Corporation",
                "National Instruments Corporation",
                "DigitalPersona, Inc.",
                "Novell, Inc.",
                "gemalto",
                "EasyAntiCheat Oy",
                "Entrust Datacard Corporation",
                "AuriStor, Inc.",
                "LogMeIn, Inc.",
                "VMware, Inc.",
                "Istituto Poligrafico e Zecca dello Stato S.p.A.",
                "Nubeva Technologies Ltd",
                "Micro Focus (US), Inc.",
                "Yubico AB",
                "GEMALTO SA",
                "Secure Endpoints, Inc.",
                "Sophos Ltd",
                "Morphisec Information Security 2014 Ltd",
                "Entrust, Inc.",
                "Nubeva Technologies Ltd",
                "Micro Focus (US), Inc.",
                "F5 Networks Inc",
                "Bit4id",
                "Thales DIS CPL USA, Inc.",
                "Micro Focus International plc",
                "HYPR Corp",
                "Intel(R) Software Development Products",
                "PGP Corporation",
                "Parallels International GmbH",
                "FrontRange Solutions Deutschland GmbH",
                "SecureLink, Inc.",
                "Tidexa OU",
                "Amazon Web Services, Inc.",
                "SentryBay Limited",
                "Audinate Pty Ltd",
                "CyberArk Software Ltd.",
                "McAfeeSysPrep",
                "NVIDIA Corporation PE Sign v2016",
                "Trend Micro, Inc.",
                "Fortinet Technologies (Canada) Inc.",
                "Carbon Black, Inc.") and
       dll.code_signature.status : ("trusted", "errorExpired", "errorCode_endpoint*", "errorChaining")) and

     not dll.hash.sha256 :
                ("811a03a5d7c03802676d2613d741be690b3461022ea925eb6b2651a5be740a4c",
                 "1181542d9cfd63fb00c76242567446513e6773ea37db6211545629ba2ecf26a1",
                 "ed6e735aa6233ed262f50f67585949712f1622751035db256811b4088c214ce3",
                 "26be2e4383728eebe191c0ab19706188f0e9592add2e0bf86b37442083ae5e12",
                 "9367e78b84ef30cf38ab27776605f2645e52e3f6e93369c674972b668a444faa",
                 "d46cc934765c5ecd53867070f540e8d6f7701e834831c51c2b0552aba871921b",
                 "0f77a3826d7a5cd0533990be0269d951a88a5c277bc47cff94553330b715ec61",
                 "4aca034d3d85a9e9127b5d7a10882c2ef4c3e0daa3329ae2ac1d0797398695fb",
                 "86031e69914d9d33c34c2f4ac4ae523cef855254d411f88ac26684265c981d95")
'''
```

## credential_access_lsass_memdump_file_created
```
query = '''
file where host.os.type == "windows" and event.action != "deletion" and
  file.name : ("lsass*.dmp", "dumpert.dmp", "Andrew.dmp", "SQLDmpr*.mdmp", "Coredump.dmp") and

  not (
        process.executable : (
          "?:\\Program Files\\Microsoft SQL Server\\*\\Shared\\SqlDumper.exe",
          "?:\\Program Files\\Microsoft SQL Server Reporting Services\\SSRS\\ReportServer\\bin\\SqlDumper.exe",
          "?:\\Windows\\System32\\dllhost.exe"
        ) and
        file.path : (
          "?:\\*\\Reporting Services\\Logfiles\\SQLDmpr*.mdmp",
          "?:\\Program Files\\Microsoft SQL Server Reporting Services\\SSRS\\Logfiles\\SQLDmpr*.mdmp",
          "?:\\Program Files\\Microsoft SQL Server\\*\\Shared\\ErrorDumps\\SQLDmpr*.mdmp",
          "?:\\Program Files\\Microsoft SQL Server\\*\\MSSQL\\LOG\\SQLDmpr*.mdmp"
        )
      ) and

  not (
        process.executable : (
          "?:\\Windows\\system32\\WerFault.exe",
          "?:\\Windows\\System32\\WerFaultSecure.exe"
          ) and
        file.path : (
          "?:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\CrashDumps\\lsass.exe.*.dmp",
          "?:\\Windows\\System32\\%LOCALAPPDATA%\\CrashDumps\\lsass.exe.*.dmp"
        )
  )
'''
```

## credential_access_lsass_memdump_handle_access
```
query = '''
host.os.type:"windows" and event.code:"4656" and
  (
    winlog.event_data.AccessMask : ("0x1fffff" or "0x1010" or "0x120089" or "0x1F3FFF") or
    winlog.event_data.AccessMaskDescription : ("READ_CONTROL" or "Read from process memory")
  ) and
  winlog.event_data.ObjectName : *\\Windows\\System32\\lsass.exe and
  not winlog.event_data.ProcessName : (
      "C:\Windows\System32\wbem\WmiPrvSE.exe" or
      "C:\Windows\SysWOW64\wbem\WmiPrvSE.exe" or
      "C:\Windows\System32\dllhost.exe" or
      "C:\Windows\System32\svchost.exe" or
      "C:\Windows\System32\msiexec.exe" or
      "C:\Windows\explorer.exe"
  )
'''
```

## credential_access_lsass_openprocess_api
```
query = '''
api where host.os.type == "windows" and 
  process.Ext.api.name in ("OpenProcess", "OpenThread") and Target.process.name : "lsass.exe" and 
  not 
  (
    process.executable : (
        "?:\\ProgramData\\GetSupportService*\\Updates\\Update_*.exe",
        "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
        "?:\\Program Files (x86)\\Asiainfo Security\\OfficeScan Client\\NTRTScan.exe",
        "?:\\Program Files (x86)\\Blackpoint\\SnapAgent\\SnapAgent.exe",
        "?:\\Program Files (x86)\\CheckPoint\\Endpoint Security\\EFR\\EFRService.exe",
        "?:\\Program Files (x86)\\CyberCNSAgent\\osqueryi.exe",
        "?:\\Program Files (x86)\\cisco\\cisco anyconnect secure mobility client\\vpnagent.exe",
        "?:\\Program Files (x86)\\cisco\\cisco anyconnect secure mobility client\\aciseagent.exe",
        "?:\\Program Files (x86)\\cisco\\cisco anyconnect secure mobility client\\vpndownloader.exe",
        "?:\\Program Files (x86)\\eScan\\reload.exe",
        "?:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe",
        "?:\\Program Files (x86)\\Kaspersky Lab\\*\\avp.exe",
        "?:\\Program Files (x86)\\microsoft intune management extension\\microsoft.management.services.intunewindowsagent.exe",
        "?:\\Program Files (x86)\\N-able Technologies\\Reactive\\bin\\NableReactiveManagement.exe",
        "?:\\Program Files (x86)\\N-able Technologies\\Windows Agent\\bin\\agent.exe",
        "?:\\Program Files (x86)\\Tanium\\Tanium Client\\TaniumClient.exe",
        "?:\\Program Files (x86)\\Trend Micro\\*\\CCSF\\TmCCSF.exe",
        "?:\\Program Files (x86)\\Trend Micro\\Security Agent\\TMASutility.exe",
        "?:\\Program Files*\\Windows Defender\\MsMpEng.exe",
        "?:\\Program Files\\Bitdefender\\Endpoint Security\\EPSecurityService.exe",
        "?:\\Program Files\\Cisco\\AMP\\*\\sfc.exe",
        "?:\\Program Files\\Common Files\\McAfee\\AVSolution\\mcshield.exe",
        "?:\\Program Files\\EA\\AC\\EAAntiCheat.GameService.exe",
        "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\agentbeat.exe",
        "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\metricbeat.exe",
        "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\osqueryd.exe",
        "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\packetbeat.exe",
        "?:\\Program Files\\ESET\\ESET Security\\ekrn.exe",
        "?:\\Program Files\\Fortinet\\FortiClient\\FortiProxy.exe",
        "?:\\Program Files\\Fortinet\\FortiClient\\FortiSSLVPNdaemon.exe",
        "?:\\Program Files\\Goverlan Inc\\GoverlanAgent\\GovAgentx64.exe",
        "?:\\Program Files\\Huntress\\HuntressAgent.exe",
        "?:\\Program Files\\LogicMonitor\\Agent\\bin\\sbshutdown.exe",
        "?:\\Program Files\\Malwarebytes\\Anti-Malware\\MBAMService.exe",
        "?:\\Program Files\\Microsoft Monitoring Agent\\Agent\\Health Service State\\*\\pmfexe.exe", 
        "?:\\Program Files\\Microsoft Security Client\\MsMpEng.exe",
        "?:\\Program Files\\Qualys\\QualysAgent\\QualysAgent.exe",
        "?:\\Program Files\\smart-x\\controlupagent\\version*\\cuagent.exe",
        "?:\\Program Files\\TDAgent\\ossec-agent\\ossec-agent.exe",
        "?:\\Program Files\\Topaz OFD\\Warsaw\\core.exe",
        "?:\\Program Files\\Trend Micro\\Deep Security Agent\\netagent\\tm_netagent.exe",
        "?:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
        "?:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe",
        "?:\\Program Files\\Wise\\Wise Memory Optimizer\\WiseMemoryOptimzer.exe",
        "?:\\Windows\\AdminArsenal\\PDQDeployRunner\\*\\exec\\Sysmon64.exe",
        "?:\\Windows\\Sysmon.exe",
        "?:\\Windows\\Sysmon64.exe",
        "?:\\Windows\\System32\\csrss.exe",
        "?:\\Windows\\System32\\MRT.exe",
        "?:\\Windows\\System32\\msiexec.exe",
        "?:\\Windows\\System32\\taskhostw.exe",
        "?:\\Windows\\System32\\RtkAudUService64.exe",
        "?:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
        "?:\\Windows\\SysWOW64\\wbem\\WmiPrvSE.exe",
        "?:\\Windows\\tenable_mw_scan_142a90001fb65e0beb1751cc8c63edd0.exe"
    ) and not ?process.code_signature.trusted == false
  )
'''
```

## credential_access_machine_account_smb_relay
```
query = '''
file where host.os.type == "windows" and event.code == "5145" and endswith(user.name, "$") and

 /* compare computername with user.name and make sure they match */
 startswith~(winlog.computer_name, substring(user.name, 0, -1)) and

 /* exclude local access */
 not endswith(string(source.ip), string(host.ip)) and
 source.ip != "::" and source.ip != null and source.ip != "::1" and source.ip != "127.0.0.1"
'''
```

## credential_access_mimikatz_memssp_default_logs
```
query = '''
file where host.os.type == "windows" and file.name : "mimilsa.log" and process.name : "lsass.exe"
'''
```

## credential_access_mimikatz_powershell_module
```
query = '''
event.category:process and host.os.type:windows and
powershell.file.script_block_text:(
  (DumpCreds and
  DumpCerts) or
  "sekurlsa::logonpasswords" or
  ("crypto::certificates" and
  "CERT_SYSTEM_STORE_LOCAL_MACHINE")
)
'''
```

## credential_access_mod_wdigest_security_provider
```
query = '''
registry where host.os.type == "windows" and event.type in ("creation", "change") and
    registry.value : "UseLogonCredential" and
    registry.path : "*\\SYSTEM\\*ControlSet*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential" and
    registry.data.strings : ("1", "0x00000001") and
    not (process.executable : "?:\\Windows\\System32\\svchost.exe" and user.id : "S-1-5-18")
'''
```

## credential_access_moving_registry_hive_via_smb
```
query = '''
file where host.os.type == "windows" and event.type == "creation" and
 /* regf file header */
 file.Ext.header_bytes : "72656766*" and file.size >= 30000 and
 process.pid == 4 and user.id : ("S-1-5-21*", "S-1-12-1-*") and
 not file.path : (
    "?:\\*\\UPM_Profile\\NTUSER.DAT",
    "?:\\*\\UPM_Profile\\NTUSER.DAT.LASTGOODLOAD",
    "?:\\*\\UPM_Profile\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat*",
    "?:\\Windows\\Netwrix\\Temp\\????????.???.offreg",
    "?:\\*\\AppData\\Local\\Packages\\Microsoft.*\\Settings\\settings.dat*"
 )
'''
```

## credential_access_persistence_network_logon_provider_modification
```
query = '''
registry where host.os.type == "windows" and event.type == "change" and
  registry.data.strings : "?*" and registry.value : "ProviderPath" and
  registry.path : (
    "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\NetworkProvider\\ProviderPath",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\*\\NetworkProvider\\ProviderPath"
  ) and
  /* Excluding default NetworkProviders RDPNP, LanmanWorkstation and webclient. */
  not (
    user.id : "S-1-5-18" and
    registry.data.strings : (
        "%SystemRoot%\\System32\\ntlanman.dll",
        "%SystemRoot%\\System32\\drprov.dll",
        "%SystemRoot%\\System32\\davclnt.dll",
        "%SystemRoot%\\System32\\vmhgfs.dll",
        "?:\\Program Files (x86)\\Citrix\\ICA Client\\x64\\pnsson.dll",
        "?:\\Program Files\\Dell\\SARemediation\\agent\\DellMgmtNP.dll",
        "?:\\Program Files (x86)\\CheckPoint\\Endpoint Connect\\\\epcgina.dll"
    )
  )
'''
```

## credential_access_posh_invoke_ninjacopy
```
query = '''
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "StealthReadFile" or
    "StealthReadFileAddr" or
    "StealthCloseFileDelegate" or
    "StealthOpenFile" or
    "StealthCloseFile" or
    "StealthReadFile" or
    "Invoke-NinjaCopy"
   )
  and not user.id : "S-1-5-18"
  and not powershell.file.script_block_text : (
    "sentinelbreakpoints" and "Set-PSBreakpoint" and "PowerSploitIndicators"
  )
'''
```

## credential_access_posh_kerb_ticket_dump
```
query = '''
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "LsaCallAuthenticationPackage" and
    (
      "KerbRetrieveEncodedTicketMessage" or
      "KerbQueryTicketCacheMessage" or
      "KerbQueryTicketCacheExMessage" or
      "KerbQueryTicketCacheEx2Message" or
      "KerbRetrieveTicketMessage" or
      "KerbDecryptDataMessage"
    )
  )
'''
```

## credential_access_posh_minidump
```
query = '''
event.category:process and host.os.type:windows and powershell.file.script_block_text:(MiniDumpWriteDump or MiniDumpWithFullMemory or pmuDetirWpmuDiniM) and not user.id : "S-1-5-18"
'''
```

## credential_access_posh_relay_tools
```
query = '''
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    ("NTLMSSPNegotiate" and ("NegotiateSMB" or "NegotiateSMB2")) or
    "4E544C4D53535000" or
    "0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50" or
    "0x4e,0x54,0x20,0x4c,0x4d" or
    "0x53,0x4d,0x42,0x20,0x32" or
    "0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38"
  ) and
  not file.directory : "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads"
'''
```

## credential_access_posh_request_ticket
```
query = '''
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    KerberosRequestorSecurityToken
  ) and not user.id : ("S-1-5-18" or "S-1-5-20") and
  not powershell.file.script_block_text : (
    ("sentinelbreakpoints" and ("Set-PSBreakpoint" or "Set-HookFunctionTabs")) or
    ("function global" and "\\windows\\sentinel\\4")
  )
'''
```

## credential_access_posh_veeam_sq
```
query = '''
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    (
      "[dbo].[Credentials]" and
      ("Veeam" or "VeeamBackup")
    ) or
    "ProtectedStorage]::GetLocalString"
  )
'''
```

## credential_access_potential_lsa_memdump_via_mirrordump
```
query = '''
process where host.os.type == "windows" and event.code == "10" and

 /* LSASS requesting DuplicateHandle access right to another process */
 process.name : "lsass.exe" and winlog.event_data.GrantedAccess == "0x40" and

 /* call is coming from an unknown executable region */
 winlog.event_data.CallTrace : "*UNKNOWN*"
'''
```

## credential_access_rare_webdav_destination
```
query = '''
from logs-*
| where
    @timestamp > now() - 8 hours and
    event.category == "process" and
    event.type == "start" and
    process.name == "rundll32.exe" and
    process.command_line like "*DavSetCookie*"
| keep host.id, process.command_line, user.name
| grok
    process.command_line """(?<Esql.server_webdav_cookie>DavSetCookie .* http)"""
| eval
    Esql.server_webdav_cookie_replace = replace(Esql.server_webdav_cookie, "(DavSetCookie | http)", "")
| where
    Esql.server_webdav_cookie_replace is not null and
    Esql.server_webdav_cookie_replace rlike """(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,3}(@SSL.*)*|(\d{1,3}\.){3}\d{1,3})""" and
    not Esql.server_webdav_cookie_replace in ("www.google.com@SSL", "www.elastic.co@SSL") and
    not Esql.server_webdav_cookie_replace rlike """(10\.(\d{1,3}\.){2}\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.(\d{1,3}\.)\d{1,3}|192\.168\.(\d{1,3}\.)\d{1,3})"""
| stats
    Esql.event_count = count(*),
    Esql.host_id_count_distinct = count_distinct(host.id),
    Esql.host_id_values = values(host.id),
    Esql.user_name_values = values(user.name)
  by Esql.server_webdav_cookie_replace
| where
    Esql.host_id_count_distinct == 1 and
    Esql.event_count <= 3
'''
```

## credential_access_regback_sam_security_hives
```
query = '''
file where host.os.type == "windows" and 
 event.action == "open" and event.outcome == "success" and process.executable != null and 
 file.path :
      ("?:\\Windows\\System32\\config\\RegBack\\SAM",
       "?:\\Windows\\System32\\config\\RegBack\\SECURITY",
       "?:\\Windows\\System32\\config\\RegBack\\SYSTEM") and 
 not (
    user.id == "S-1-5-18" and process.executable : (
        "?:\\Windows\\system32\\taskhostw.exe", "?:\\Windows\\system32\\taskhost.exe"
    ))
'''
```

## credential_access_relay_ntlm_auth_via_http_spoolss
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : "rundll32.exe" and

  /* Rundll32 WbeDav Client  */
  process.args : ("?:\\Windows\\System32\\davclnt.dll,DavSetCookie", "?:\\Windows\\SysWOW64\\davclnt.dll,DavSetCookie") and

  /* Access to named pipe via http */
  process.args : ("http*/print/pipe/*", "http*/pipe/spoolss", "http*/pipe/srvsvc")
'''
```

## credential_access_remote_sam_secretsdump
```
query = '''
file where host.os.type == "windows" and
  event.action == "creation" and process.name : "svchost.exe" and
  file.Ext.header_bytes : "72656766*" and user.id : ("S-1-5-21-*", "S-1-12-1-*") and file.size >= 30000 and
  file.path : ("?:\\Windows\\system32\\*.tmp", "?:\\WINDOWS\\Temp\\*.tmp")
'''
```

## credential_access_saved_creds_vault_winlog
```
query = '''
sequence by winlog.computer_name, winlog.process.pid with maxspan=1s

 /* 2 consecutive vault reads from same pid for web creds */

 [any where host.os.type == "windows" and event.code == "5382" and
  (winlog.event_data.SchemaFriendlyName : "Windows Web Password Credential" and winlog.event_data.Resource : "http*") and
  not winlog.event_data.SubjectLogonId : "0x3e7" and
  not winlog.event_data.Resource : "http://localhost/"]

 [any where host.os.type == "windows" and event.code == "5382" and
  (winlog.event_data.SchemaFriendlyName : "Windows Web Password Credential" and winlog.event_data.Resource : "http*") and
  not winlog.event_data.SubjectLogonId : "0x3e7" and
  not winlog.event_data.Resource : "http://localhost/"]
'''
```

## credential_access_saved_creds_vaultcmd
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (?process.pe.original_file_name:"vaultcmd.exe" or process.name:"vaultcmd.exe") and
  process.args:"/list*"
'''
```

## credential_access_seenabledelegationprivilege_assigned_to_user
```
query = '''
event.code:4704 and host.os.type:"windows" and winlog.event_data.PrivilegeList:"SeEnableDelegationPrivilege"
'''
```

## credential_access_shadow_credentials
```
query = '''
event.code:"5136" and host.os.type:"windows" and winlog.event_data.AttributeLDAPDisplayName:"msDS-KeyCredentialLink" and
  winlog.event_data.AttributeValue :B\:828* and
  not winlog.event_data.SubjectUserName: MSOL_*
'''
```

## credential_access_spn_attribute_modified
```
query = '''
event.code:5136 and host.os.type:"windows" and winlog.event_data.OperationType:"%%14674" and
  winlog.event_data.ObjectClass:"user" and
  winlog.event_data.AttributeLDAPDisplayName:"servicePrincipalName"
'''
```

## credential_access_suspicious_comsvcs_imageload
```
query = '''
sequence by process.entity_id with maxspan=1m
 [process where host.os.type == "windows" and event.category == "process" and
    process.name : "rundll32.exe"]
 [process where host.os.type == "windows" and event.category == "process" and event.dataset : "windows.sysmon_operational" and event.code == "7" and
   (file.pe.original_file_name : "COMSVCS.DLL" or file.pe.imphash : "EADBCCBB324829ACB5F2BBE87E5549A8") and
    /* renamed COMSVCS */
    not file.name : "COMSVCS.DLL"]
'''
```

## credential_access_suspicious_lsass_access_generic
```
query = '''
process where host.os.type == "windows" and event.code == "10" and
  winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe" and
  not winlog.event_data.GrantedAccess :
                ("0x1000", "0x1400", "0x101400", "0x101000", "0x101001", "0x100000", "0x100040", "0x3200", "0x40", "0x3200") and
  not process.name : ("procexp64.exe", "procmon.exe", "procexp.exe", "Microsoft.Identity.AadConnect.Health.AadSync.Host.ex") and
  not process.executable : (
        "?:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*",
        "?:\\ProgramData\\WebEx\\webex\\*",
        "?:\\Program Files (x86)\\*",
        "?:\\Program Files\\*",
        "?:\\Windows\\CCM\\CcmExec.exe",
        "?:\\Windows\\LTSvc\\LTSVC.exe",
        "?:\\Windows\\Sysmon.exe",
        "?:\\Windows\\Sysmon64.exe",
        "C:\\Windows\\CynetMS.exe",
        "?:\\Windows\\system32\\csrss.exe",
        "?:\\Windows\\System32\\lsm.exe",
        "?:\\Windows\\system32\\MRT.exe",
        "?:\\Windows\\System32\\msiexec.exe",
        "?:\\Windows\\system32\\wbem\\wmiprvse.exe",
        "?:\\Windows\\system32\\wininit.exe",
        "?:\\Windows\\SystemTemp\\GUM*.tmp\\GoogleUpdate.exe",
        "?:\\Windows\\sysWOW64\\wbem\\wmiprvse.exe",
        "C:\\oracle\\64\\02\\instantclient_19_13\\sqlplus.exe",
        "C:\\oracle\\64\\02\\instantclient_19_13\\sqlldr.exe",
        "d:\\oracle\\product\\19\\dbhome1\\bin\\ORACLE.EXE",
        "C:\\wamp\\bin\\apache\\apache*\\bin\\httpd.exe",
        "C:\\Windows\\system32\\netstat.exe",
        "C:\\PROGRA~1\\INFORM~1\\apps\\jdk\\*\\jre\\bin\\java.exe",
        "C:\\PROGRA~2\\CyberCNSAgentV2\\osqueryi.exe",
        "C:\\Utilityw2k19\\packetbeat\\packetbeat.exe",
        "C:\\ProgramData\\Cisco\\Cisco AnyConnect Secure Mobility Client\\Temp\\CloudUpdate\\vpndownloader.exe",
        "C:\\ProgramData\\Cisco\\Cisco Secure Client\\Temp\\CloudUpdate\\vpndownloader.exe"
  ) and
  not winlog.event_data.CallTrace : ("*mpengine.dll*", "*appresolver.dll*", "*sysmain.dll*")
'''
```

## credential_access_suspicious_lsass_access_memdump
```
query = '''
process where host.os.type == "windows" and event.code == "10" and
  winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe" and

   /* DLLs exporting MiniDumpWriteDump API to create an lsass mdmp*/
  winlog.event_data.CallTrace : ("*dbghelp*", "*dbgcore*") and

   /* case of lsass crashing */
  not process.executable : (
        "?:\\Windows\\System32\\WerFault.exe",
        "?:\\Windows\\SysWOW64\\WerFault.exe",
        "?:\\Windows\\System32\\WerFaultSecure.exe"
      )
'''
```

## credential_access_suspicious_lsass_access_via_snapshot
```
query = '''
event.category:process and host.os.type:windows and event.code:10 and
 winlog.event_data.TargetImage:("C:\\Windows\\system32\\lsass.exe" or
                                 "c:\\Windows\\system32\\lsass.exe" or
                                 "c:\\Windows\\System32\\lsass.exe")
'''
```

## credential_access_suspicious_winreg_access_via_sebackup_priv
```
query = '''
sequence by winlog.computer_name, winlog.event_data.SubjectLogonId with maxspan=1m
 [iam where host.os.type == "windows" and event.action == "logged-in-special" and
  winlog.event_data.PrivilegeList : "SeBackupPrivilege" and

  /* excluding accounts with existing privileged access */
  not winlog.event_data.PrivilegeList : "SeDebugPrivilege"]
 [any where host.os.type == "windows" and event.code == "5145" and winlog.event_data.RelativeTargetName : "winreg"]
'''
```

## credential_access_symbolic_link_to_shadow_copy_created
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 (
    (?process.pe.original_file_name in ("Cmd.Exe","PowerShell.EXE")) or
    (process.name : ("cmd.exe", "powershell.exe"))
 ) and

 /* Create Symbolic Link to Shadow Copies */
 process.args : ("*mklink*", "*SymbolicLink*") and process.command_line : ("*HarddiskVolumeShadowCopy*")
'''
```

## credential_access_veeam_backup_dll_imageload
```
query = '''
library where host.os.type == "windows" and event.action == "load" and
  (dll.name : "Veeam.Backup.Common.dll" or dll.pe.original_file_name : "Veeam.Backup.Common.dll") and
  (
    process.code_signature.trusted == false or
    process.code_signature.exists == false or
    process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
  )
'''
```

## credential_access_veeam_commands
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (
    (process.name : "sqlcmd.exe" or ?process.pe.original_file_name : "sqlcmd.exe") or
    process.args : ("Invoke-Sqlcmd", "Invoke-SqlExecute", "Invoke-DbaQuery", "Invoke-SqlQuery")
  ) and
  process.args : "*[VeeamBackup].[dbo].[Credentials]*"
'''
```

## credential_access_via_snapshot_lsass_clone_creation
```
query = '''
process where host.os.type == "windows" and event.code:"4688" and
  process.executable : "?:\\Windows\\System32\\lsass.exe" and
  process.parent.executable : "?:\\Windows\\System32\\lsass.exe"
'''
```

## credential_access_wbadmin_ntds
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
    (process.name : "wbadmin.exe" or ?process.pe.original_file_name : "wbadmin.exe") and
     process.args : "recovery" and process.command_line : "*ntds.dit*"
'''
```

## credential_access_web_config_file_access
```
query = '''
event.category:file and host.os.type:windows and event.action:open and
  file.name:"web.config" and file.path : *VirtualDirectories*
'''
```

## credential_access_wireless_creds_dumping
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "netsh.exe" or ?process.pe.original_file_name == "netsh.exe") and
  process.args : "wlan" and process.args : "key*clear"
'''
```

## defense_evasion_adding_the_hidden_file_attribute_with_via_attribexe
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "attrib.exe" or ?process.pe.original_file_name == "ATTRIB.EXE") and process.args : "+h" and
  not (process.parent.name: "cmd.exe" and process.command_line: "attrib  +R +H +S +A *.cui") and

  not (
    process.parent.name: "draw.io.exe" and
    (
      process.command_line : ("*drawio.bkp*", "*drawio.dtmp*")
    )
  )
'''
```

## defense_evasion_amsi_bypass_dllhijack
```
query = '''
file where host.os.type == "windows" and event.type != "deletion" and file.path != null and
  file.name : ("amsi.dll", "amsi") and 
  event.action != "A process changed a file creation time" and 
  not file.path : (
    "?:\\$SysReset\\CloudImage\\Package_for_RollupFix*\\amsi.dll",
    "?:\\Windows\\system32\\amsi.dll",
    "?:\\Windows\\Syswow64\\amsi.dll",
    "?:\\$WINDOWS.~BT\\*\\amsi.dll",
    "?:\\Windows\\CbsTemp\\*\\amsi.dll",
    "?:\\Windows\\SoftwareDistribution\\Download\\*",
    "?:\\Windows\\WinSxS\\*\\amsi.dll", 
    "?:\\Windows\\servicing\\*\\amsi.dll",
    "\\\\?\\Volume{*}\\Windows\\WinSxS\\*\\amsi.dll", 
    "\\\\?\\Volume{*}\\Windows\\system32\\amsi.dll", 
    "\\\\?\\Volume{*}\\Windows\\syswow64\\amsi.dll",

    /* Crowdstrike specific exclusion as it uses NT Object paths */
    "\\Device\\HarddiskVolume*\\Windows\\system32\\amsi.dll", 
    "\\Device\\HarddiskVolume*\\Windows\\syswow64\\amsi.dll", 
    "\\Device\\HarddiskVolume*\\Windows\\WinSxS\\*\\amsi.dll",
    "\\Device\\HarddiskVolume*\\$SysReset\\CloudImage\\Package_for_RollupFix*\\amsi.dll",
    "\\Device\\HarddiskVolume*\\$WINDOWS.~BT\\*\\amsi.dll", 
    "\\Device\\HarddiskVolume*\\Windows\\SoftwareDistribution\\Download\\*\\amsi.dll", 
    "\\Device\\HarddiskVolume*\\Windows\\CbsTemp\\*\\amsi.dll", 
    "\\Device\\HarddiskVolume*\\Windows\\servicing\\*\\amsi.dll"
  ) 
'''
```

## defense_evasion_amsi_bypass_powershell
```
query = '''
event.category:"process" and host.os.type:windows and
  (
    powershell.file.script_block_text : (
      "System.Management.Automation.AmsiUtils" or
			amsiInitFailed or 
			"Invoke-AmsiBypass" or 
			"Bypass.AMSI" or 
			"amsi.dll" or 
			AntimalwareProvider  or 
			amsiSession or 
			amsiContext or
			AmsiInitialize or 
			unloadobfuscated or 
			unloadsilent or 
			AmsiX64 or 
			AmsiX32 or 
			FindAmsiFun or
		    "AllocHGlobal((9076" or
		    "[cHAr](65)+[cHaR]([byTe]0x6d)+[ChaR]([ByTe]0x73)+[CHaR]([BYte]0x69"
    ) or
    powershell.file.script_block_text:("[Ref].Assembly.GetType(('System.Management.Automation" and ".SetValue(") or
    powershell.file.script_block_text:("::AllocHGlobal((" and ".SetValue(" and "-replace" and ".NoRMALiZe(")
  ) and
  not powershell.file.script_block_text : (
    "sentinelbreakpoints" and "Set-PSBreakpoint"
  )
'''
```

## defense_evasion_amsienable_key_mod
```
query = '''
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : "AmsiEnable" and registry.data.strings: ("0", "0x00000000")

  /*
    Full registry key path omitted due to data source variations:
    HKEY_USERS\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable"
  */
'''
```

## defense_evasion_audit_policy_disabled_winlog
```
query = '''
event.code : "4719" and host.os.type : "windows" and
  winlog.event_data.AuditPolicyChangesDescription : "Success removed" and
  winlog.event_data.SubCategory : (
     "Logon" or
     "Audit Policy Change" or
     "Process Creation" or
     "Audit Other System Events" or
     "Audit Security Group Management" or
     "Audit User Account Management"
  )
'''
```

## defense_evasion_clearing_windows_console_history
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (
    process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or
    ?process.pe.original_file_name in ("PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE")
  ) and
  (
    process.args : "*Clear-History*" or
    (process.args : ("*Remove-Item*", "rm") and process.args : ("*ConsoleHost_history.txt*", "*(Get-PSReadlineOption).HistorySavePath*")) or
    (process.args : "*Set-PSReadlineOption*" and process.args : "*SaveNothing*")
  )
'''
```

## defense_evasion_clearing_windows_event_logs
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
(
  (
    (process.name : "wevtutil.exe" or ?process.pe.original_file_name == "wevtutil.exe") and
    process.args : ("/e:false", "cl", "clear-log")
  ) or
  (
    (
      process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or
      ?process.pe.original_file_name in ("PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE")
    ) and
    process.args : "Clear-EventLog"
  )
)
'''
```

## defense_evasion_clearing_windows_security_logs
```
query = '''
host.os.type:windows and event.action:("audit-log-cleared" or "Log clear") and
  not winlog.provider_name:"AD FS Auditing"
'''
```

## defense_evasion_code_signing_policy_modification_builtin_tools
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (process.name: "bcdedit.exe" or ?process.pe.original_file_name == "bcdedit.exe") and process.args: ("-set", "/set") and 
  process.args: ("TESTSIGNING", "nointegritychecks", "loadoptions", "DISABLE_INTEGRITY_CHECKS")
'''
```

## defense_evasion_code_signing_policy_modification_registry
```
query = '''
registry where host.os.type == "windows" and event.type == "change" and
  registry.value: "BehaviorOnFailedVerify" and registry.data.strings : ("0", "0x00000000", "1", "0x00000001") and 
  not process.executable : 
                      ("?:\\Windows\\System32\\svchost.exe", 
                       "?:\\Windows\\CCM\\CcmExec.exe",
                       "\\Device\\HarddiskVolume*\\Windows\\system32\\svchost.exe", 
                       "\\Device\\HarddiskVolume*\\Windows\\CCM\\CcmExec.exe")
  /*
    Full registry key path omitted due to data source variations:
    "HKEY_USERS\\*\\Software\\Policies\\Microsoft\\Windows NT\\Driver Signing\\BehaviorOnFailedVerify"
  */
'''
```

## defense_evasion_communication_apps_suspicious_child_process
```
query = '''
process where host.os.type == "windows" and event.type == "start" and 
 not process.executable : 
             ("?:\\Program Files\\*.exe", 
              "?:\\Program Files (x86)\\*.exe", 
              "?:\\Windows\\System32\\WerFault.exe", 
              "?:\\Windows\\SysWOW64\\WerFault.exe") and 
  (
    /* Slack */
    (process.parent.name : "slack.exe" and not
      (
        (
          process.executable : (
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Island\\Island\\Application\\Island.exe",
            "?:\\Users\\*\\AppData\\Roaming\\Zoom\\bin*\\Zoom.exe",
            "?:\\Windows\\System32\\rundll32.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
            "?:\\Windows\\System32\\notepad.exe",
            "?:\\Users\\*\\AppData\\Local\\Programs\\Opera\\opera.exe"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "Slack Technologies, Inc.",
            "Slack Technologies, LLC"
          ) and process.code_signature.trusted == true
        ) or
        (
          (process.name : "powershell.exe" and process.command_line : "powershell.exe -c Invoke-WebRequest -Uri https://slackb.com/*") or
          (process.name : "cmd.exe" and process.command_line : "C:\\WINDOWS\\system32\\cmd.exe /d /s /c \"%windir%\\System32\\rundll32.exe User32.dll,SetFocus 0\"")
        )
      )
    ) or

    /* WebEx */
    (process.parent.name : ("CiscoCollabHost.exe", "WebexHost.exe") and not
      (
        (
          process.executable : (
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
            "?:\\Users\\*\\AppData\\Local\\Programs\\Opera\\opera.exe"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "Cisco Systems, Inc.",
            "Cisco WebEx LLC",
            "Cisco Systems Inc."
          ) and process.code_signature.trusted == true
        )
      )
    ) or

    /* Teams */
    (process.parent.name : "Teams.exe" and not
      (
        (
          process.executable : (
            "?:\\Windows\\BrowserCore\\BrowserCore.exe",
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe", 
            "?:\\Users\\*\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "Microsoft Corporation",
            "Microsoft 3rd Party Application Component"
          ) and process.code_signature.trusted == true
        ) or
        (
          (process.name : "taskkill.exe" and process.args : "Teams.exe")
        )
      )
    ) or

    /* Discord */
    (process.parent.name : "Discord.exe" and not
      (
        (
          process.executable : (
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Windows\\System32\\reg.exe",
            "?:\\Windows\\SysWOW64\\reg.exe"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "Discord Inc."
          ) and process.code_signature.trusted == true
        ) or
        (
          process.name : "cmd.exe" and
          (
            process.command_line : (
              "C:\\WINDOWS\\system32\\cmd.exe /d /s /c \"chcp\"",
              "C:\\WINDOWS\\system32\\cmd.exe /q /d /s /c \"C:\\Program^ Files\\NVIDIA^ Corporation\\NVSMI\\nvidia-smi.exe\""
            ) or
            process.args : (
              "C:\\WINDOWS/System32/nvidia-smi.exe",
              "C:\\WINDOWS\\System32\\nvidia-smi.exe",
              "C:\\Windows\\System32\\DriverStore\\FileRepository/*/nvidia-smi.exe*"
            )
          )
        )
      )
    ) or

    /* WhatsApp */
    (process.parent.name : "Whatsapp.exe" and not
      (
        (
          process.executable : (
            "?:\\Windows\\System32\\reg.exe",
            "?:\\Windows\\SysWOW64\\reg.exe"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "WhatsApp LLC",
            "WhatsApp, Inc",
            "24803D75-212C-471A-BC57-9EF86AB91435"
          ) and process.code_signature.trusted == true
        ) or
        (
          (process.name : "cmd.exe" and process.command_line : "C:\\Windows\\system32\\cmd.exe /d /s /c \"C:\\Windows\\system32\\wbem\\wmic.exe*")
        )
      )
    ) or

    /* Zoom */
    (process.parent.name : "Zoom.exe" and not
      (
        (
          process.executable : (
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Island\\Island\\Application\\Island.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "Zoom Video Communications, Inc."
          ) and process.code_signature.trusted == true
        )
      )
    ) or

    /* Thunderbird */
    (process.parent.name : "thunderbird.exe" and not
      (
        (
          process.executable : (
            "?:\\Windows\\splwow64.exe", 
            "?:\\Windows\\System32\\spool\\drivers\\x64\\3\\*.EXE"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "Mozilla Corporation"
          ) and process.code_signature.trusted == true
        )
      )
    )
  )
'''
```

## defense_evasion_create_mod_root_certificate
```
query = '''
registry where host.os.type == "windows" and event.type == "change" and registry.value : "Blob" and
  registry.path :
    (
      "HKLM\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "HKLM\\Software\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "HKLM\\Software\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "HKLM\\Software\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "\\REGISTRY\\MACHINE\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "\\REGISTRY\\MACHINE\\Software\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "MACHINE\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "MACHINE\\Software\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "MACHINE\\Software\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "MACHINE\\Software\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob"
    ) and
  not process.executable : (
          "?:\\Program Files (x86)\\*.exe",
          "?:\\Program Files\\*.exe",
          "?:\\ProgramData\\bomgar-*\\*\\sra-pin.exe",
          "?:\\ProgramData\\bomgar-*\\*\\bomgar-scc.exe",
          "?:\\ProgramData\\CTES\\Ctes.exe",
          "?:\\ProgramData\\CTES\\Components\\SNG\\AbtSngSvc.exe",
          "?:\\ProgramData\\CTES\\Components\\SVC\\CtesHostSvc.exe",
          "?:\\ProgramData\\Lenovo\\Vantage\\Addins\\LenovoHardwareScanAddin\\*\\LdeApi.Server.exe",
          "?:\\ProgramData\\Logishrd\\LogiOptionsPlus\\Plugins\\64\\certmgr.exe",
          "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\*.exe",
          "?:\\ProgramData\\Quest\\KACE\\modules\\clientidentifier\\clientidentifier.exe",
          "?:\\ProgramData\\Sophos\\AutoUpdate\\Cache\\sophos_autoupdate1.dir\\*.exe",
          "?:\\ProgramData\\tychoncloud\\bin\\OVAL\\tvs.exe",
          "?:\\Windows\\CCM\\CcmEval.exe",
          "?:\\Windows\\CCM\\CcmExec.exe",
          "?:\\Windows\\ccmsetup\\autoupgrade\\ccmsetup*.exe",
          "?:\\Windows\\ccmsetup\\cache\\ccmsetup.exe",
          "?:\\Windows\\ccmsetup\\ccmsetup.exe",
          "?:\\Windows\\Cluster\\clussvc.exe",
          "?:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe",
          "?:\\Windows\\Lenovo\\ImController\\PluginHost86\\Lenovo.Modern.ImController.PluginHost.Device.exe",
          "?:\\Windows\\Lenovo\\ImController\\Service\\Lenovo.Modern.ImController.exe",
          "?:\\Windows\\Sysmon.exe",
          "?:\\Windows\\Sysmon64.exe",
          "?:\\Windows\\UUS\\amd64\\MoUsoCoreWorker.exe",
          "?:\\Windows\\UUS\\amd64\\WaaSMedicAgent.exe",
          "?:\\Windows\\UUS\\Packages\\Preview\\amd64\\MoUsoCoreWorker.exe",
          "?:\\Windows\\WinSxS\\*.exe"
  ) and
  not
  (
    process.executable : (
      "?:\\Windows\\System32\\*.exe",
      "?:\\Windows\\SysWOW64\\*.exe"
    ) and
    not process.name : (
        "rundll32.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "expand.exe",
        "regsvr32.exe", "cscript.exe", "wscript.exe", "wmiprvse.exe", "certutil.exe", "xcopy.exe"
    )
  )
'''
```

## defense_evasion_cve_2020_0601
```
query = '''
event.provider:"Microsoft-Windows-Audit-CVE" and message:"[CVE-2020-0601]" and host.os.type:windows
'''
```

## defense_evasion_defender_disabled_via_registry
```
query = '''
registry where host.os.type == "windows" and event.type == "change" and
  (
    (
      registry.path: (
        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware"
      ) and
      registry.data.strings: ("1", "0x00000001")
   ) or
   (
      registry.path: (
        "HKLM\\System\\*ControlSet*\\Services\\WinDefend\\Start",
        "\\REGISTRY\\MACHINE\\System\\*ControlSet*\\Services\\WinDefend\\Start"
      ) and
      registry.data.strings in ("3", "4", "0x00000003", "0x00000004")
   )
  ) and

  not
    (
      process.executable : (
          "?:\\WINDOWS\\system32\\services.exe",
          "?:\\Windows\\System32\\svchost.exe",
          "?:\\Program Files (x86)\\Trend Micro\\Security Agent\\NTRmv.exe"
      ) and user.id : "S-1-5-18"
    )
'''
```

## defense_evasion_defender_exclusion_via_powershell
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or ?process.pe.original_file_name in ("PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE")) and
  process.args : ("*Add-MpPreference*", "*Set-MpPreference*") and
  process.args : ("*-Exclusion*")
'''
```

## defense_evasion_delete_volume_usn_journal_with_fsutil
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "fsutil.exe" or ?process.pe.original_file_name == "fsutil.exe") and
  process.args : "deletejournal" and process.args : "usn"
'''
```

## defense_evasion_disable_nla
```
query = '''
registry where host.os.type == "windows" and event.action != "deletion" and registry.value : "UserAuthentication" and
  registry.path : (
    "HKLM\\SYSTEM\\ControlSet*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication",
    "MACHINE\\SYSTEM\\*ControlSet*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication"
  ) and registry.data.strings :  ("0", "0x00000000")
'''
```

## defense_evasion_disable_posh_scriptblocklogging
```
query = '''
registry where host.os.type == "windows" and event.type == "change" and
    registry.value : "EnableScriptBlockLogging" and
    registry.data.strings : ("0", "0x00000000") and
    not process.executable : (
          "?:\\Windows\\System32\\svchost.exe",
          "?:\\Windows\\System32\\DeviceEnroller.exe",
          "?:\\Windows\\system32\\omadmclient.exe",
          "?:\\Program Files (x86)\\N-able Technologies\\AutomationManagerAgent\\AutomationManager.AgentService.exe",
          
          /* Crowdstrike specific exclusion as it uses NT Object paths */
          "\\Device\\HarddiskVolume*\\Windows\\System32\\svchost.exe",
          "\\Device\\HarddiskVolume*\\Windows\\System32\\DeviceEnroller.exe",
          "\\Device\\HarddiskVolume*\\Windows\\system32\\omadmclient.exe",
          "\\Device\\HarddiskVolume*\\Program Files (x86)\\N-able Technologies\\AutomationManagerAgent\\AutomationManager.AgentService.exe"
    )
'''
```

## defense_evasion_disable_windows_firewall_rules_with_netsh
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : "netsh.exe" and
  (
    (process.args : "disable" and process.args : "firewall" and process.args : "set") or
    (process.args : "advfirewall" and process.args : "off" and process.args : "state")
  )
'''
```

## defense_evasion_disabling_windows_defender_powershell
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (
    process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or
    ?process.pe.original_file_name in ("PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE")
  ) and
  process.args : "Set-MpPreference" and process.args : ("-Disable*", "Disabled", "NeverSend", "-Exclusion*")
'''
```

## defense_evasion_disabling_windows_logs
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
(
  (
    (process.name:"logman.exe" or ?process.pe.original_file_name == "Logman.exe") and
    process.args : "EventLog-*" and process.args : ("stop", "delete")
  ) or
  (
    (
      process.name : ("pwsh.exe", "powershell.exe", "powershell_ise.exe") or
      ?process.pe.original_file_name in ("PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE")
    ) and
	  process.args : "Set-Service" and process.args: "EventLog" and process.args : "Disabled"
  )  or
  (
    (process.name:"auditpol.exe" or ?process.pe.original_file_name == "AUDITPOL.EXE") and process.args : "/success:disable"
  )
)
'''
```

## defense_evasion_dns_over_https_enabled
```
query = '''
registry where host.os.type == "windows" and event.type == "change" and
  (registry.path : "*\\SOFTWARE\\Policies\\Microsoft\\Edge\\BuiltInDnsClientEnabled" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "*\\SOFTWARE\\Google\\Chrome\\DnsOverHttpsMode" and
  registry.data.strings : "secure") or
  (registry.path : "*\\SOFTWARE\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS" and
  registry.data.strings : ("1", "0x00000001"))
'''
```

## defense_evasion_dotnet_compiler_parent_process
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("csc.exe", "vbc.exe") and
  process.parent.name : ("wscript.exe", "mshta.exe", "cscript.exe", "wmic.exe", "svchost.exe", "rundll32.exe", "cmstp.exe", "regsvr32.exe")
'''
```

## defense_evasion_enable_inbound_rdp_with_netsh
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "netsh.exe" or ?process.pe.original_file_name == "netsh.exe") and
 process.args : ("localport=3389", "RemoteDesktop", "group=\"remote desktop\"") and
 process.args : ("action=allow", "enable=Yes", "enable")
'''
```

## defense_evasion_enable_network_discovery_with_netsh
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
process.name : "netsh.exe" and
process.args : ("firewall", "advfirewall") and process.args : "group=Network Discovery" and process.args : "enable=Yes"
'''
```

## defense_evasion_execution_control_panel_suspicious_args
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : "control.exe" and
  process.command_line : (
    "*.jpg*", "*.png*",
    "*.gif*", "*.bmp*",
    "*.jpeg*", "*.TIFF*",
    "*.inf*", "*.cpl:*/*",
    "*../../..*",
    "*/AppData/Local/*",
    "*:\\Users\\Public\\*",
    "*\\AppData\\Local\\*"
)
'''
```

## defense_evasion_execution_lolbas_wuauclt
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (?process.pe.original_file_name == "wuauclt.exe" or process.name : "wuauclt.exe") and
   /* necessary windows update client args to load a dll */
   process.args : "/RunHandlerComServer" and process.args : "/UpdateDeploymentProvider" and
   /* common paths writeable by a standard user where the target DLL can be placed */
   process.args : ("C:\\Users\\*.dll", "C:\\ProgramData\\*.dll", "C:\\Windows\\Temp\\*.dll", "C:\\Windows\\Tasks\\*.dll")
'''
```

## defense_evasion_execution_msbuild_started_by_office_app
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : "MSBuild.exe" and
  process.parent.name : ("eqnedt32.exe",
                         "excel.exe",
                         "fltldr.exe",
                         "msaccess.exe",
                         "mspub.exe",
                         "outlook.exe",
                         "powerpnt.exe",
                         "winword.exe" )
'''
```

## defense_evasion_execution_msbuild_started_by_script
```
query = '''
host.os.type:windows and event.category:process and event.type:start and (
  process.name.caseless:"msbuild.exe" or process.pe.original_file_name:"MSBuild.exe") and
  process.parent.name:("cmd.exe" or "powershell.exe" or "pwsh.exe" or "powershell_ise.exe" or "cscript.exe" or
    "wscript.exe" or "mshta.exe")
'''
```

## defense_evasion_execution_msbuild_started_by_system_process
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : "MSBuild.exe" and
  process.parent.name : ("explorer.exe", "wmiprvse.exe")
'''
```

## defense_evasion_execution_msbuild_started_renamed
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.pe.original_file_name == "MSBuild.exe" and
  not process.name : "MSBuild.exe"
'''
```

## defense_evasion_execution_msbuild_started_unusal_process
```
query = '''
host.os.type:windows and event.category:process and event.type:start and process.parent.name:("MSBuild.exe" or "msbuild.exe") and
process.name:("csc.exe" or "iexplore.exe" or "powershell.exe")
'''
```

## defense_evasion_execution_suspicious_explorer_winword
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (
    process.name : ("WinWord.exe", "EXPLORER.EXE", "w3wp.exe", "DISM.EXE") or
    ?process.pe.original_file_name : ("WinWord.exe", "EXPLORER.EXE", "w3wp.exe", "DISM.EXE")
  ) and
  not process.executable : (
          "\\\\?\\Volume{????????-????-????-????-????????????}\\Windows\\System32\\inetsrv\\w3wp.exe",
          "?:\\PROGRA~?\\MICROS~?\\Office??\\winword.exe",
          "?:\\Program Files\\Microsoft Office\\*\\winword.exe",
          "?:\\Program Files\\Microsoft Office ??\\*\\winword.exe",
          "?:\\Program Files\\WindowsApps\\Microsoft.Office.Desktop.*\\Office??\\winword.exe",
          "?:\\Program Files (x86)\\Microsoft Office\\*\\winword.exe",
          "?:\\Program Files (x86)\\Windows Kits\\*Assessment and Deployment Kit\\Deployment Tools\\amd64\\DISM\\dism.exe",
          "?:\\Windows\\explorer.exe",
          "?:\\Windows\\System32\\Dism.exe",
          "?:\\Windows\\System32\\inetsrv\\w3wp.exe",
          "?:\\Windows\\SysWOW64\\Dism.exe",
          "?:\\Windows\\SysWOW64\\explorer.exe",
          "?:\\Windows\\SysWOW64\\inetsrv\\w3wp.exe"
  ) and
  /* Crowdstrike specific exclusion as it uses NT Object paths */
  not
  (
    data_stream.dataset == "crowdstrike.fdr" and
    process.executable : (
        "\\Device\\HarddiskVolume*\\Program Files\\Microsoft Office\\*\\winword.exe",
        "\\Device\\HarddiskVolume*\\Program Files\\Microsoft Office ??\\*\\winword.exe",
        "\\Device\\HarddiskVolume*\\Program Files\\WindowsApps\\Microsoft.Office.Desktop.*\\Office??\\winword.exe",
        "\\Device\\HarddiskVolume*\\Program Files (x86)\\Microsoft Office\\*\\winword.exe",
        "\\Device\\HarddiskVolume*\\Program Files (x86)\\Windows Kits\\10\\Assessment and Deployment Kit\\Deployment Tools\\amd64\\DISM\\dism.exe",
        "\\Device\\HarddiskVolume*\\Windows\\explorer.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\Dism.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\inetsrv\\w3wp.exe",
        "\\Device\\HarddiskVolume*\\Windows\\SysWOW64\\Dism.exe",
        "\\Device\\HarddiskVolume*\\Windows\\SysWOW64\\explorer.exe",
        "\\Device\\HarddiskVolume*\\Windows\\SysWOW64\\inetsrv\\w3wp.exe"
    )
  )
'''
```

## defense_evasion_execution_windefend_unusual_path
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
(
  (process.pe.original_file_name == "MsMpEng.exe" and not process.name : "MsMpEng.exe") or
  (
    process.name : "MsMpEng.exe" and
    not process.executable : (
            "?:\\ProgramData\\Microsoft\\Windows Defender\\*.exe",
            "?:\\Program Files\\Windows Defender\\*.exe",
            "?:\\Program Files (x86)\\Windows Defender\\*.exe",
            "?:\\Program Files\\Microsoft Security Client\\*.exe",
            "?:\\Program Files (x86)\\Microsoft Security Client\\*.exe",

            /* Crowdstrike specific exclusion as it uses NT Object paths */
            "\\Device\\HarddiskVolume*\\ProgramData\\Microsoft\\Windows Defender\\*.exe",
            "\\Device\\HarddiskVolume*\\Program Files\\Windows Defender\\*.exe",
            "\\Device\\HarddiskVolume*\\Program Files (x86)\\Windows Defender\\*.exe",
            "\\Device\\HarddiskVolume*\\Program Files\\Microsoft Security Client\\*.exe",
            "\\Device\\HarddiskVolume*\\Program Files (x86)\\Microsoft Security Client\\*.exe"
    )
  )
)
'''
```

## defense_evasion_file_creation_mult_extension
```
query = '''
file where host.os.type == "windows" and event.type == "creation" and file.extension : "exe" and
  file.name regex~ """.*\.(vbs|vbe|bat|js|cmd|wsh|ps1|pdf|docx?|xlsx?|pptx?|txt|rtf|gif|jpg|png|bmp|hta|txt|img|iso)\.exe""" and
  not (
      process.executable : (
          "?:\\Windows\\System32\\msiexec.exe",
          "\\Device\\HarddiskVolume*\\Windows\\System32\\msiexec.exe",
          "*\\Users\\*\\QGIS_SCCM\\Files\\QGIS-OSGeo4W-*-Setup-x86_64.exe"
      ) and
      file.path : ("?:\\Program Files\\QGIS *\\apps\\grass\\*.exe", "\\Device\\HarddiskVolume*\\Program Files\\QGIS *\\apps\\grass\\*.exe")
  ) and 
  not process.executable : 
                             ("C:\\Program Files\\dotnet\\dotnet.exe", 
                              "C:\\Program Files\\Microsoft Visual Studio\\*.exe",
                              "\\Device\\HarddiskVolume*\\Program Files\\dotnet\\dotnet.exe", 
                              "\\Device\\HarddiskVolume*\\Program Files\\Microsoft Visual Studio\\*.exe")
'''
```

## defense_evasion_from_unusual_directory
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  /* add suspicious execution paths here */
  process.executable : (
    "?:\\PerfLogs\\*.exe", "?:\\Users\\Public\\*.exe", "?:\\Windows\\Tasks\\*.exe",
    "?:\\Intel\\*.exe", "?:\\AMD\\Temp\\*.exe", "?:\\Windows\\AppReadiness\\*.exe",
    "?:\\Windows\\ServiceState\\*.exe", "?:\\Windows\\security\\*.exe", "?:\\Windows\\IdentityCRL\\*.exe",
    "?:\\Windows\\Branding\\*.exe", "?:\\Windows\\csc\\*.exe", "?:\\Windows\\DigitalLocker\\*.exe",
    "?:\\Windows\\en-US\\*.exe", "?:\\Windows\\wlansvc\\*.exe", "?:\\Windows\\Prefetch\\*.exe",
    "?:\\Windows\\Fonts\\*.exe", "?:\\Windows\\diagnostics\\*.exe", "?:\\Windows\\TAPI\\*.exe",
    "?:\\Windows\\INF\\*.exe", "?:\\Windows\\System32\\Speech\\*.exe", "?:\\windows\\tracing\\*.exe",
    "?:\\windows\\IME\\*.exe", "?:\\Windows\\Performance\\*.exe", "?:\\windows\\intel\\*.exe",
    "?:\\windows\\ms\\*.exe", "?:\\Windows\\dot3svc\\*.exe", "?:\\Windows\\panther\\*.exe",
    "?:\\Windows\\RemotePackages\\*.exe", "?:\\Windows\\OCR\\*.exe", "?:\\Windows\\appcompat\\*.exe",
    "?:\\Windows\\apppatch\\*.exe", "?:\\Windows\\addins\\*.exe", "?:\\Windows\\Setup\\*.exe",
    "?:\\Windows\\Help\\*.exe", "?:\\Windows\\SKB\\*.exe", "?:\\Windows\\Vss\\*.exe",
    "?:\\Windows\\Web\\*.exe", "?:\\Windows\\servicing\\*.exe", "?:\\Windows\\CbsTemp\\*.exe",
    "?:\\Windows\\Logs\\*.exe", "?:\\Windows\\WaaS\\*.exe", "?:\\Windows\\ShellExperiences\\*.exe",
    "?:\\Windows\\ShellComponents\\*.exe", "?:\\Windows\\PLA\\*.exe", "?:\\Windows\\Migration\\*.exe",
    "?:\\Windows\\debug\\*.exe", "?:\\Windows\\Cursors\\*.exe", "?:\\Windows\\Containers\\*.exe",
    "?:\\Windows\\Boot\\*.exe", "?:\\Windows\\bcastdvr\\*.exe", "?:\\Windows\\assembly\\*.exe",
    "?:\\Windows\\TextInput\\*.exe", "?:\\Windows\\security\\*.exe", "?:\\Windows\\schemas\\*.exe",
    "?:\\Windows\\SchCache\\*.exe", "?:\\Windows\\Resources\\*.exe", "?:\\Windows\\rescache\\*.exe",
    "?:\\Windows\\Provisioning\\*.exe", "?:\\Windows\\PrintDialog\\*.exe", "?:\\Windows\\PolicyDefinitions\\*.exe",
    "?:\\Windows\\media\\*.exe", "?:\\Windows\\Globalization\\*.exe", "?:\\Windows\\L2Schemas\\*.exe",
    "?:\\Windows\\LiveKernelReports\\*.exe", "?:\\Windows\\ModemLogs\\*.exe",
    "?:\\Windows\\ImmersiveControlPanel\\*.exe"
  ) and
  
  not process.name : (
    "SpeechUXWiz.exe", "SystemSettings.exe", "TrustedInstaller.exe",
    "PrintDialog.exe", "MpSigStub.exe", "LMS.exe", "mpam-*.exe"
  ) and
  not process.executable :
            ("?:\\Intel\\Wireless\\WUSetupLauncher.exe",
             "?:\\Intel\\Wireless\\Setup.exe",
             "?:\\Intel\\Move Mouse.exe",
             "?:\\windows\\Panther\\DiagTrackRunner.exe",
             "?:\\Windows\\servicing\\GC64\\tzupd.exe",
             "?:\\Users\\Public\\res\\RemoteLite.exe",
             "?:\\Users\\Public\\IBM\\ClientSolutions\\*.exe",
             "?:\\Users\\Public\\Documents\\syspin.exe",
             "?:\\Users\\Public\\res\\FileWatcher.exe")
'''
```

## defense_evasion_hide_encoded_executable_registry
```
query = '''
registry where host.os.type == "windows" and
/* update here with encoding combinations */
 registry.data.strings : "TVqQAAMAAAAEAAAA*"
'''
```

## defense_evasion_indirect_exec_forfiles
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "forfiles.exe" or ?process.pe.original_file_name == "forfiles.exe") and process.args : ("/c", "-c")
'''
```

## defense_evasion_injection_msbuild
```
query = '''
process where host.os.type == "windows" and
  event.provider == "Microsoft-Windows-Sysmon" and
  /* CreateRemoteThread */
  event.code == "8" and process.name: "MSBuild.exe"
'''
```

## defense_evasion_installutil_beacon
```
query = '''
/* the benefit of doing this as an eql sequence vs kql is this will limit to alerting only on the first network connection */

sequence by process.entity_id
  [process where host.os.type == "windows" and event.type == "start" and process.name : "installutil.exe"]
  [network where host.os.type == "windows" and process.name : "installutil.exe" and network.direction : ("outgoing", "egress")]
'''
```

## defense_evasion_masquerading_as_elastic_endpoint_process
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("esensor.exe", "elastic-endpoint.exe") and
  process.parent.executable != null and
  process.args != null and
  /* add FPs here */
  not process.parent.executable : (
        "?:\\Program Files\\Elastic\\*",
        "?:\\Windows\\System32\\services.exe",
        "?:\\Windows\\System32\\WerFault*.exe",
        "?:\\Windows\\System32\\wermgr.exe",
        "?:\\Windows\\explorer.exe"
  ) and
  not (
    process.parent.executable : (
        "?:\\Windows\\System32\\cmd.exe",
        "?:\\Windows\\System32\\SecurityHealthHost.exe",
        "?:\\Windows\\System32\\SecurityHealth\\*\\SecurityHealthHost.exe",
        "?:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    ) and
    process.args : (
        "test", "version",
        "top", "run",
        "*help", "status",
        "upgrade", "/launch",
        "/enable", "/av"
    )
  )
'''
```

## defense_evasion_masquerading_business_apps_installer
```
query = '''
process where host.os.type == "windows" and
  event.type == "start" and process.executable : "?:\\Users\\*\\Downloads\\*" and
  not process.code_signature.status : ("errorCode_endpoint*", "errorUntrustedRoot", "errorChaining") and
  (
    /* Slack */
    (process.name : "*slack*.exe" and not
      (process.code_signature.subject_name in (
        "Slack Technologies, Inc.",
        "Slack Technologies, LLC"
       ) and process.code_signature.trusted == true)
    ) or

    /* WebEx */
    (process.name : "*webex*.exe" and not
      (process.code_signature.subject_name in ("Cisco WebEx LLC", "Cisco Systems, Inc.") and process.code_signature.trusted == true)
    ) or

    /* Teams */
    (process.name : "teams*.exe" and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Discord */
    (process.name : "*discord*.exe" and not
      (process.code_signature.subject_name == "Discord Inc." and process.code_signature.trusted == true)
    ) or

    /* WhatsApp */
    (process.name : "*whatsapp*.exe" and not
      (process.code_signature.subject_name in (
        "WhatsApp LLC",
        "WhatsApp, Inc",
        "24803D75-212C-471A-BC57-9EF86AB91435"
       ) and process.code_signature.trusted == true)
    ) or

    /* Zoom */
    (process.name : ("*zoom*installer*.exe", "*zoom*setup*.exe", "zoom.exe")  and not
      (process.code_signature.subject_name == "Zoom Video Communications, Inc." and process.code_signature.trusted == true)
    ) or

    /* Outlook */
    (process.name : "*outlook*.exe" and not
      (
        (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true) or
        (
          process.name: "MSOutlookHelp-PST-Viewer.exe" and process.code_signature.subject_name == "Aryson Technologies Pvt. Ltd" and
          process.code_signature.trusted == true
        )
      )
    ) or

    /* Thunderbird */
    (process.name : "*thunderbird*.exe" and not
      (process.code_signature.subject_name == "Mozilla Corporation" and process.code_signature.trusted == true)
    ) or

    /* Grammarly */
    (process.name : "*grammarly*.exe" and not
      (process.code_signature.subject_name == "Grammarly, Inc." and process.code_signature.trusted == true)
    ) or

    /* Dropbox */
    (process.name : "*dropbox*.exe" and not
      (process.code_signature.subject_name == "Dropbox, Inc" and process.code_signature.trusted == true)
    ) or

    /* Tableau */
    (process.name : "*tableau*.exe" and not
      (process.code_signature.subject_name == "Tableau Software LLC" and process.code_signature.trusted == true)
    ) or

    /* Google Drive */
    (process.name : "*googledrive*.exe" and not
      (process.code_signature.subject_name == "Google LLC" and process.code_signature.trusted == true)
    ) or

    /* MSOffice */
    (process.name : "*office*setup*.exe" and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Okta */
    (process.name : "*okta*.exe" and not
      (process.code_signature.subject_name == "Okta, Inc." and process.code_signature.trusted == true)
    ) or

    /* OneDrive */
    (process.name : "*onedrive*.exe" and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Chrome */
    (process.name : "*chrome*.exe" and not
      (process.code_signature.subject_name in ("Google LLC", "Google Inc") and process.code_signature.trusted == true)
    ) or

    /* Firefox */
    (process.name : "*firefox*.exe" and not
      (process.code_signature.subject_name == "Mozilla Corporation" and process.code_signature.trusted == true)
    ) or

    /* Edge */
    (process.name : ("*microsoftedge*.exe", "*msedge*.exe") and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Brave */
    (process.name : "*brave*.exe" and not
      (process.code_signature.subject_name == "Brave Software, Inc." and process.code_signature.trusted == true)
    ) or

    /* GoogleCloud Related Tools */
    (process.name : "*GoogleCloud*.exe" and not
      (process.code_signature.subject_name == "Google LLC" and process.code_signature.trusted == true)
    ) or

    /* Github Related Tools */
    (process.name : "*github*.exe" and not
      (process.code_signature.subject_name == "GitHub, Inc." and process.code_signature.trusted == true)
    ) or

    /* Notion */
    (process.name : "*notion*.exe" and not
      (process.code_signature.subject_name == "Notion Labs, Inc." and process.code_signature.trusted == true)
    )
  )
'''
```

## defense_evasion_masquerading_communication_apps
```
query = '''
process where host.os.type == "windows" and
  event.type == "start" and
  (
    /* Slack */
    (process.name : "slack.exe" and not
      (process.code_signature.subject_name : (
        "Slack Technologies, Inc.",
        "Slack Technologies, LLC"
       ) and process.code_signature.trusted == true)
    ) or

    /* WebEx */
    (process.name : "WebexHost.exe" and not
      (process.code_signature.subject_name : ("Cisco WebEx LLC", "Cisco Systems, Inc.") and process.code_signature.trusted == true)
    ) or

    /* Teams */
    (process.name : "Teams.exe" and not
      (process.code_signature.subject_name : "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Discord */
    (process.name : "Discord.exe" and not
      (process.code_signature.subject_name : "Discord Inc." and process.code_signature.trusted == true)
    ) or

    /* RocketChat */
    (process.name : "Rocket.Chat.exe" and not
      (process.code_signature.subject_name : "Rocket.Chat Technologies Corp." and process.code_signature.trusted == true)
    ) or

    /* Mattermost */
    (process.name : "Mattermost.exe" and not
      (process.code_signature.subject_name : "Mattermost, Inc." and process.code_signature.trusted == true)
    ) or

    /* WhatsApp */
    (process.name : "WhatsApp.exe" and not
      (process.code_signature.subject_name : (
        "WhatsApp LLC",
        "WhatsApp, Inc",
        "24803D75-212C-471A-BC57-9EF86AB91435"
       ) and process.code_signature.trusted == true)
    ) or

    /* Zoom */
    (process.name : "Zoom.exe" and not
      (process.code_signature.subject_name : "Zoom Video Communications, Inc." and process.code_signature.trusted == true)
    ) or

    /* Outlook */
    (process.name : "outlook.exe" and not
      (process.code_signature.subject_name : "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Thunderbird */
    (process.name : "thunderbird.exe" and not
      (process.code_signature.subject_name : "Mozilla Corporation" and process.code_signature.trusted == true)
    )
  )
'''
```

## defense_evasion_masquerading_trusted_directory
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.executable : (
    "C:\\*Program*Files*\\*.exe",
    "\\Device\\HarddiskVolume*\\*Program*Files*\\*.exe"
  ) and
  not process.executable : (
        "?:\\Program Files\\*.exe",
        "?:\\Program Files (x86)\\*.exe",
        "?:\\Users\\*.exe",
        "?:\\ProgramData\\*.exe",
        "?:\\Windows\\Downloaded Program Files\\*.exe",
        "?:\\Windows\\Temp\\.opera\\????????????\\CProgram?FilesOpera*\\*.exe",
        "?:\\Windows\\Temp\\.opera\\????????????\\CProgram?Files?(x86)Opera*\\*.exe"
  ) and
  not (
    /* Crowdstrike specific exclusion as it uses NT Object paths */
    event.dataset == "crowdstrike.fdr" and
      process.executable : (
        "\\Device\\HarddiskVolume*\\Program Files\\*.exe",
        "\\Device\\HarddiskVolume*\\Program Files (x86)\\*.exe",
        "\\Device\\HarddiskVolume*\\Users\\*.exe",
        "\\Device\\HarddiskVolume*\\ProgramData\\*.exe",
        "\\Device\\HarddiskVolume*\\Windows\\Downloaded Program Files\\*.exe",
        "\\Device\\HarddiskVolume*\\Windows\\Temp\\.opera\\????????????\\CProgram?FilesOpera*\\*.exe",
        "\\Device\\HarddiskVolume*\\Windows\\Temp\\.opera\\????????????\\CProgram?Files?(x86)Opera*\\*.exe"
      )
  )
'''
```

## defense_evasion_misc_lolbin_connecting_to_the_internet
```
query = '''
sequence by process.entity_id
  [process where host.os.type == "windows" and (process.name : "expand.exe" or process.name : "extrac32.exe" or
                 process.name : "ieexec.exe" or process.name : "makecab.exe") and
                 event.type == "start"]
  [network where host.os.type == "windows" and (process.name : "expand.exe" or process.name : "extrac32.exe" or
                 process.name : "ieexec.exe" or process.name : "makecab.exe") and
    not cidrmatch(destination.ip,
      "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32",
      "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24",
      "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
      "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10", "FF00::/8")]
'''
```

## defense_evasion_modify_ownership_os_files
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (
   (process.name : "icacls.exe" and process.args : "/reset") or
   (process.name : "takeown.exe" and process.args : "/f") or
   (process.name : "icacls.exe" and process.args : "/grant" and process.args : "Everyone:F")
   ) and
   process.command_line : "*.exe *C:\\Windows\\*"
'''
```

## defense_evasion_msbuild_making_network_connections
```
query = '''
sequence by process.entity_id with maxspan=30s

  /* Look for MSBuild.exe process execution */
  /* The events for this first sequence may be noisy, consider adding exceptions */
  [process where host.os.type == "windows" and event.type == "start" and
    (
      process.pe.original_file_name: "MSBuild.exe" or
      process.name: "MSBuild.exe"
    ) and
    not user.id == "S-1-5-18"]

  /* Followed by a network connection to an external address */
  /* Exclude domains that are known to be benign */
  [network where host.os.type == "windows" and
    event.action: ("connection_attempted", "lookup_requested") and
    (
      process.pe.original_file_name: "MSBuild.exe" or
      process.name: "MSBuild.exe"
    ) and
    not user.id == "S-1-5-18" and
    not cidrmatch(destination.ip, "127.0.0.1", "::1") and
    not dns.question.name : (
      "localhost",
      "dc.services.visualstudio.com",
      "vortex.data.microsoft.com",
      "api.nuget.org")]
'''
```

## defense_evasion_mshta_beacon
```
query = '''
sequence by process.entity_id with maxspan=10m
  [process where host.os.type == "windows" and event.type == "start" and process.name : "mshta.exe" and
     not process.parent.name : "Microsoft.ConfigurationManagement.exe" and
     not (process.parent.executable : "C:\\Amazon\\Amazon Assistant\\amazonAssistantService.exe" or
          process.parent.executable : "C:\\TeamViewer\\TeamViewer.exe") and
     not process.args : "ADSelfService_Enroll.hta"]
  [network where host.os.type == "windows" and process.name : "mshta.exe"]
'''
```

## defense_evasion_mshta_susp_child
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "mshta.exe" and
 (
  process.name : ("cmd.exe", "powershell.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "msiexec.exe", "schtasks.exe", "reg.exe", "wscript.exe", "rundll32.exe") or
  process.executable : ("C:\\Users\\*\\*.exe", "\\Device\\HarddiskVolume*\\Users\\*\\*.exe")
  )
'''
```

## defense_evasion_msiexec_child_proc_netcon
```
query = '''
sequence by process.entity_id with maxspan=1m
 [process where host.os.type == "windows" and event.type : "start" and
  process.parent.name : "msiexec.exe" and process.parent.args : "/v" and
  not process.executable :
        ("?:\\Windows\\System32\\msiexec.exe",
         "?:\\Windows\\sysWOW64\\msiexec.exe",
         "?:\\Windows\\system32\\srtasks.exe",
         "?:\\Windows\\syswow64\\srtasks.exe",
         "?:\\Windows\\sys*\\taskkill.exe",
         "?:\\Program Files\\*.exe",
         "?:\\Program Files (x86)\\*.exe",
         "?:\\Windows\\Installer\\MSI*.tmp",
         "?:\\Windows\\Microsoft.NET\\Framework*\\RegSvcs.exe",
         "C:\\Windows\\System32\\regsvr32.exe",
         "C:\\Windows\\Sys?????\\certutil.exe",
         "C:\\Windows\\System32\\WerFault.exe",
         "C:\\Windows\\System32\\wevtutil.exe",
         "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe") and
 not (process.name : ("rundll32.exe", "regsvr32.exe", "powershell.exe", "regasm.exe", "wscript.exe") and process.args : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*")) and
 not (?process.code_signature.subject_name : ("Bruno Software Inc", "Proton AG", "Axis Communications AB", "Citrix Systems, Inc.", "NSUS Limited", "Action1 Corporation", "Solarwinds Worldwide, LLC") and
      ?process.code_signature.trusted == true) and
 not (?process.pe.original_file_name in ("dxsetup.exe", "MofCompiler.exe", "ShellApp.exe") and
      ?process.code_signature.subject_name : "Microsoft Corporation" and ?process.code_signature.trusted == true) and
 not ?process.hash.sha256 in ("cfaef8c711db04d6c4a4381c66ac21b9e234e57febedb77fedc9316898b214bc",
                              "2f26f37cce780ca76f0dbac0de233f4c8d84c31b3f37380b9d5faacc3ee2d03e",
                              "7d9c691bfbf3beb78919dfd940fa6d325c3437425d5b0371df39aef6accf858d")
 ]
[network where host.os.type == "windows" and process.name != null and
 not dns.question.name : ("core.bdec.microsoft.com", "go.microsoft.com", "ocsp.digicert.com", "localhost", "www.google-analytics.com",
                          "ocsp.verisign.com", "*.symcb.com")]
'''
```

## defense_evasion_ntlm_downgrade
```
query = '''
registry where host.os.type == "windows" and event.action != "deletion" and
 registry.value == "LmCompatibilityLevel" and registry.data.strings in ("2", "1", "0", "0x00000002", "0x00000001", "0x00000000")
'''
```

## defense_evasion_parent_process_pid_spoofing
```
query = '''
/* This rule is compatible with Elastic Endpoint only */

sequence by host.id, user.id with maxspan=3m

 [process where host.os.type == "windows" and event.type == "start" and
  process.Ext.token.integrity_level_name != "system" and
  (
    process.pe.original_file_name : ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "eqnedt32.exe",
                                     "fltldr.exe", "mspub.exe", "msaccess.exe", "powershell.exe", "pwsh.exe",
                                     "cscript.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe", "msbuild.exe",
                                     "mshta.exe", "wmic.exe", "cmstp.exe", "msxsl.exe") or

    (process.executable : ("?:\\Users\\*.exe",
                           "?:\\ProgramData\\*.exe",
                           "?:\\Windows\\Temp\\*.exe",
                           "?:\\Windows\\Tasks\\*") and
      (process.code_signature.exists == false or process.code_signature.status : "errorBadDigest")) or

    process.executable : "?:\\Windows\\Microsoft.NET\\*.exe"
  ) and

  not process.executable :
             ("?:\\Windows\\System32\\WerFaultSecure.exe",
              "?:\\WINDOWS\\SysWOW64\\WerFaultSecure.exe",
              "?:\\Windows\\System32\\WerFault.exe",
              "?:\\Windows\\SysWOW64\\WerFault.exe")
  ] by process.pid
 [process where host.os.type == "windows" and event.type == "start" and
  process.parent.Ext.real.pid > 0 and

  /* process.parent.Ext.real.pid is only populated if the parent process pid doesn't match */
  not (process.name : "msedge.exe" and process.parent.name : "sihost.exe") and

   not process.executable :
             ("?:\\Windows\\System32\\WerFaultSecure.exe",
              "?:\\WINDOWS\\SysWOW64\\WerFaultSecure.exe",
              "?:\\Windows\\System32\\WerFault.exe",
              "?:\\Windows\\SysWOW64\\WerFault.exe")
 ] by process.parent.Ext.real.pid
'''
```

## defense_evasion_posh_assembly_load
```
query = '''
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "[System.Reflection.Assembly]::Load" or
    "[Reflection.Assembly]::Load" or
    "Assembly.Load("
  ) and
  not powershell.file.script_block_text : (
        ("CommonWorkflowParameters" or "RelatedLinksHelpInfo") and
        "HelpDisplayStrings"
  ) and
  not (powershell.file.script_block_text :
        ("Get-SolutionFiles" or "Get-VisualStudio" or "Select-MSBuildPath") and
        file.name : "PathFunctions.ps1"
  ) and
  not powershell.file.script_block_text : (
        "Microsoft.PowerShell.Workflow.ServiceCore" and "ExtractPluginProperties([string]$pluginDir"
  ) and 
  
  not powershell.file.script_block_text : ("reflection.assembly]::Load('System." or "LoadWithPartialName('Microsoft." or "::Load(\"Microsoft." or "Microsoft.Build.Utilities.Core.dll") and 
  
  not user.id : "S-1-5-18"
'''
```

## defense_evasion_posh_encryption
```
query = '''
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    (
      "Cryptography.AESManaged" or
      "Cryptography.RijndaelManaged" or
      "Cryptography.SHA1Managed" or
      "Cryptography.SHA256Managed" or
      "Cryptography.SHA384Managed" or
      "Cryptography.SHA512Managed" or
      "Cryptography.SymmetricAlgorithm" or
      "PasswordDeriveBytes" or
      "Rfc2898DeriveBytes"
    ) and
    (
      CipherMode and PaddingMode
    ) and
    (
      ".CreateEncryptor" or
      ".CreateDecryptor"
    )
  ) and
  not user.id : "S-1-5-18" and
  not (
    file.name : "Bootstrap.Octopus.FunctionAppenderContext.ps1" and
    powershell.file.script_block_text : ("function Decrypt-Variables" or "github.com/OctopusDeploy")
  )
'''
```

## defense_evasion_posh_obfuscation_backtick_var
```
query = '''
from logs-windows.powershell_operational* metadata _id, _version, _index
| where event.code == "4104"

// Filter out smaller scripts that are unlikely to implement obfuscation using the patterns we are looking for
| eval Esql.script_block_length = length(powershell.file.script_block_text)
| where Esql.script_block_length > 500

// replace the patterns we are looking for with the 🔥 emoji to enable counting them
// The emoji is used because it's unlikely to appear in scripts and has a consistent character length of 1
| eval Esql.script_block_tmp = replace(powershell.file.script_block_text, """\$\{(\w++`){2,}\w++\}""", "🔥")

// count how many patterns were detected by calculating the number of 🔥 characters inserted
| eval Esql.script_block_pattern_count = length(Esql.script_block_tmp) - length(replace(Esql.script_block_tmp, "🔥", ""))

// keep the fields relevant to the query, although this is not needed as the alert is populated using _id
| keep
    Esql.script_block_pattern_count,
    Esql.script_block_length,
    Esql.script_block_tmp,
    powershell.file.*,
    file.path,
    file.name,
    powershell.sequence,
    powershell.total,
    _id,
    _index,
    host.name,
    agent.id,
    user.id

// Filter for scripts that match the pattern at least once
| where Esql.script_block_pattern_count >= 1
'''
```

## defense_evasion_posh_obfuscation_iex_env_vars_reconstruction
```
query = '''
from logs-windows.powershell_operational* metadata _id, _version, _index
| where event.code == "4104"

// Filter out smaller scripts that are unlikely to implement obfuscation using the patterns we are looking for
| eval Esql.script_block_length = length(powershell.file.script_block_text)
| where Esql.script_block_length > 500

// replace the patterns we are looking for with the 🔥 emoji to enable counting them
// The emoji is used because it's unlikely to appear in scripts and has a consistent character length of 1
| eval Esql.script_block_tmp = replace(
    powershell.file.script_block_text,
    """(?i)(\$(?:\w+|\w+\:\w+)\[\d++\]\+\$(?:\w+|\w+\:\w+)\[\d++\]\+['"]x['"]|\$(?:\w+\:\w+)\[\d++,\d++,\d++\]|\.name\[\d++,\d++,\d++\])""",
    "🔥"
)

// count how many patterns were detected by calculating the number of 🔥 characters inserted
| eval Esql.script_block_pattern_count = length(Esql.script_block_tmp) - length(replace(Esql.script_block_tmp, "🔥", ""))

// keep the fields relevant to the query, although this is not needed as the alert is populated using _id
| keep
    Esql.script_block_pattern_count,
    Esql.script_block_length,
    Esql.script_block_tmp,
    powershell.file.*,
    file.path,
    powershell.sequence,
    powershell.total,
    _id,
    _index,
    host.name,
    agent.id,
    user.id

// Filter for scripts that match the pattern at least once
| where Esql.script_block_pattern_count >= 1
'''
```

## defense_evasion_posh_obfuscation_reverse_keyword
```
query = '''
from logs-windows.powershell_operational* metadata _id, _version, _index
| where event.code == "4104"

// Filter for scripts that contains these keywords using MATCH, boosts the query performance,
// match will ignore the | and look for the individual words
| where powershell.file.script_block_text : "rahc|metsys|stekcos|tcejboimw|ecalper|ecnerferpe|noitcennoc|nioj|eman|vne|gnirts|tcejbo-wen|_23niw|noisserpxe|ekovni|daolnwod"

// replace the patterns we are looking for with the 🔥 emoji to enable counting them
// The emoji is used because it's unlikely to appear in scripts and has a consistent character length of 1
| eval Esql.script_block_tmp = replace(
    powershell.file.script_block_text,
    """(?i)(rahc|metsys|stekcos|tcejboimw|ecalper|ecnerferpe|noitcennoc|nioj|eman\.|:vne$|gnirts|tcejbo-wen|_23niw|noisserpxe|ekovni|daolnwod)""",
    "🔥"
)

// count how many patterns were detected by calculating the number of 🔥 characters inserted
| eval Esql.script_block_pattern_count = length(Esql.script_block_tmp) - length(replace(Esql.script_block_tmp, "🔥", ""))

// keep the fields relevant to the query, although this is not needed as the alert is populated using _id
| keep
    Esql.script_block_pattern_count,
    Esql.script_block_tmp,
    powershell.file.*,
    file.path,
    powershell.sequence,
    powershell.total,
    _id,
    _index,
    agent.id

// Filter for scripts that match the pattern at least twice
| where Esql.script_block_pattern_count >= 2
'''
```

## defense_evasion_posh_process_injection
```
query = '''
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
   (VirtualAlloc or VirtualAllocEx or VirtualProtect or LdrLoadDll or LoadLibrary or LoadLibraryA or
      LoadLibraryEx or GetProcAddress or OpenProcess or OpenProcessToken or AdjustTokenPrivileges) and
   (WriteProcessMemory or CreateRemoteThread or NtCreateThreadEx or CreateThread or QueueUserAPC or
      SuspendThread or ResumeThread or GetDelegateForFunctionPointer)
  ) and not 
  file.directory: (
    "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\SenseCM" or
    "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads"
  )
'''
```

## defense_evasion_process_termination_followed_by_deletion
```
query = '''
sequence by host.id with maxspan=5s
   [process where host.os.type == "windows" and event.type == "end" and
    process.code_signature.trusted != true and
    not process.executable like
             ("C:\\Windows\\SoftwareDistribution\\*.exe",
              "C:\\Windows\\WinSxS\\*.exe",
              "?:\\Windows\\Postillion\\Office\\*.exe") and
    not (
      process.name : "infinst.exe" and process.parent.name: "dxsetup.exe" and
      process.parent.code_signature.subject_name == "NVIDIA Corporation" and
      process.parent.code_signature.status == "trusted"
    )
   ] by process.executable
   [file where host.os.type == "windows" and event.type == "deletion" and file.extension in~ ("exe", "scr", "com") and
    not process.executable like
             ("?:\\Program Files\\*.exe",
              "?:\\Program Files (x86)\\*.exe",
              "?:\\Windows\\System32\\svchost.exe",
              "?:\\Windows\\System32\\drvinst.exe",
              "?:\\Windows\\Postillion\\Office\\*.exe") and
    not file.path like (
          "?:\\Program Files\\*.exe",
          "?:\\Program Files (x86)\\*.exe",
          "?:\\Windows\\Temp\\*\\DismHost.exe",
          "?:\\$WINDOWS.~BT\\Work\\*\\DismHost.exe",
          "?:\\$WinREAgent\\Scratch\\*\\DismHost.exe",
          "?:\\Windows\\tenable_mw_scan_*.exe",
          "?:\\Users\\*\\AppData\\Local\\Temp\\LogiUI\\Pak\\uninstall.exe",
          "?:\\ProgramData\\chocolatey\\*.exe"
    ) and
    not (process.name : "OktaVerifySetup-*.exe" and process.code_signature.subject_name == "Okta, Inc.") and
    not (
      process.executable : "?:\\Windows\\SysWOW64\\config\\systemprofile\\Citrix\\UpdaterBinaries\\CitrixReceiver\\*" and
      process.code_signature.subject_name == "Citrix Systems, Inc." and
      file.path : "?:\\Windows\\SysWOW64\\config\\systemprofile\\Citrix\\UpdaterBinaries\\CitrixReceiver\\*\\bootstrapperhelper.exe"
    )
   ] by file.path
'''
```

## defense_evasion_root_dir_ads_creation
```
query = '''
any where host.os.type == "windows" and event.category in ("file", "process") and
  (
    (event.type == "creation" and file.path regex~ """[A-Z]:\\:.+""") or
    (event.type == "start" and process.executable regex~ """[A-Z]:\\:.+""")
  )
'''
```

## defense_evasion_rundll32_no_argument
```
query = '''
sequence with maxspan=1h
  [process where host.os.type == "windows" and event.type == "start" and
     (process.name : "rundll32.exe" or process.pe.original_file_name == "RUNDLL32.EXE") and
      (process.args_count == 1 and
        /* Excludes bug where a missing closing quote sets args_count to 1 despite extra args */
        not process.command_line regex~ """\".*\.exe[^\"].*""")
  ] by process.entity_id
  [process where host.os.type == "windows" and event.type == "start" and process.parent.name : "rundll32.exe"
  ] by process.parent.entity_id
'''
```

## defense_evasion_sccm_scnotification_dll
```
query = '''
library where host.os.type == "windows" and process.name : "SCNotification.exe" and
  (dll.Ext.relative_file_creation_time < 86400 or dll.Ext.relative_file_name_modify_time <= 500) and dll.code_signature.status != "trusted"
'''
```

## defense_evasion_script_via_html_app
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 process.name : ("rundll32.exe", "mshta.exe") and
  (
     (process.command_line :
        (
        "*script*eval(*",
         "*script*GetObject*",
         "*.regread(*",
         "*WScript.Shell*",
         "*.run(*",
         "*).Exec()*",
         "*mshta*http*",
         "*mshtml*RunHTMLApplication*",
         "*mshtml*,#135*",
         "*StrReverse*",
         "*.RegWrite*",
         /* Issue #379 */
         "*window.close(*",
         "* Chr(*"
         )
     and not ?process.parent.executable :
                  ("?:\\Program Files (x86)\\Citrix\\System32\\wfshell.exe",
                   "?:\\Program Files (x86)\\Microsoft Office\\Office*\\MSACCESS.EXE",
                   "?:\\Program Files\\Quokka.Works GTInstaller\\GTInstaller.exe")
     ) or

    (process.name : "mshta.exe" and
     not process.command_line : ("*.hta*", "*.htm*", "-Embedding") and ?process.args_count >=2) or

     /* Execution of HTA file downloaded from the internet */
     (process.name : "mshta.exe" and process.command_line : "*\\Users\\*\\Downloads\\*.hta*") or

     /* Execution of HTA file from archive */
     (process.name : "mshta.exe" and
      process.args : ("?:\\Users\\*\\Temp\\7z*", "?:\\Users\\*\\Temp\\Rar$*", "?:\\Users\\*\\Temp\\Temp?_*", "?:\\Users\\*\\Temp\\BNZ.*"))
   )
'''
```

## defense_evasion_sdelete_like_filename_rename
```
query = '''
file where host.os.type == "windows" and event.type == "change" and file.name : "*AAA.AAA"
'''
```

## defense_evasion_suspicious_certutil_commands
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "certutil.exe" or ?process.pe.original_file_name == "CertUtil.exe") and
  process.args : ("?decode", "?encode", "?urlcache", "?verifyctl", "?encodehex", "?decodehex", "?exportPFX")
'''
```

## defense_evasion_suspicious_process_access_direct_syscall
```
query = '''
process where host.os.type == "windows" and event.code == "10" and
 length(winlog.event_data.CallTrace) > 0 and

 /* Sysmon CallTrace starting with unknown memory module instead of ntdll which host Windows NT Syscalls */
 not winlog.event_data.CallTrace :
            ("?:\\WINDOWS\\SYSTEM32\\ntdll.dll*",
             "?:\\WINDOWS\\SysWOW64\\ntdll.dll*",
             "?:\\Windows\\System32\\wow64cpu.dll*",
             "?:\\WINDOWS\\System32\\wow64win.dll*",
             "?:\\Windows\\System32\\win32u.dll*") and

 not winlog.event_data.TargetImage :
            ("?:\\Program Files (x86)\\Malwarebytes Anti-Exploit\\mbae-svc.exe",
             "?:\\Program Files\\Cisco\\AMP\\*\\sfc.exe",
             "?:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\*\\msedgewebview2.exe",
             "?:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\*\\AcroCEF.exe") and

 not (process.executable : ("?:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
                            "?:\\Program Files (x86)\\World of Warcraft\\_classic_\\WowClassic.exe") and
      not winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe")
'''
```

## defense_evasion_suspicious_scrobj_load
```
query = '''
any where host.os.type == "windows" and
 (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
 (?dll.name : "scrobj.dll" or ?file.name : "scrobj.dll") and
 process.executable : ("?:\\Windows\\System32\\*.exe", "?:\\Windows\\SysWOW64\\*.exe") and
 not process.executable : (
       "?:\\Windows\\System32\\cscript.exe",
       "?:\\Windows\\SysWOW64\\cscript.exe",
       "?:\\Windows\\system32\\msiexec.exe",
       "?:\\Windows\\SysWOW64\\msiexec.exe",
       "?:\\Windows\\System32\\smartscreen.exe",
       "?:\\Windows\\system32\\taskhostw.exe",
       "?:\\windows\\system32\\inetsrv\\w3wp.exe",
       "?:\\windows\\SysWOW64\\inetsrv\\w3wp.exe",
       "?:\\Windows\\system32\\wscript.exe",
       "?:\\Windows\\SysWOW64\\wscript.exe",
       "?:\\Windows\\System32\\mshta.exe",
       "?:\\Windows\\system32\\mobsync.exe",
       "?:\\Windows\\SysWOW64\\mobsync.exe",
       "?:\\Windows\\System32\\cmd.exe",
       "?:\\Windows\\SysWOW64\\cmd.exe",
       "?:\\Windows\\System32\\OpenWith.exe",
       "?:\\Windows\\System32\\wbem\\WMIADAP.exe",
       "?:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
'''
```

## defense_evasion_suspicious_wmi_script
```
query = '''
sequence by process.entity_id with maxspan = 2m
[process where host.os.type == "windows" and event.type == "start" and
   (process.name : "WMIC.exe" or process.pe.original_file_name : "wmic.exe") and
   process.args : ("format*:*", "/format*:*", "*-format*:*") and
   not process.command_line : ("* /format:table *", "* /format:table")]
[any where host.os.type == "windows" and (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
 (?dll.name : ("jscript.dll", "vbscript.dll") or file.name : ("jscript.dll", "vbscript.dll"))]
'''
```

## defense_evasion_system_critical_proc_abnormal_file_activity
```
query = '''
file where host.os.type == "windows" and event.type != "deletion" and
  file.extension : ("exe", "dll") and
  process.name : ("smss.exe",
                  "autochk.exe",
                  "csrss.exe",
                  "wininit.exe",
                  "services.exe",
                  "lsass.exe",
                  "winlogon.exe",
                  "userinit.exe",
                  "LogonUI.exe")
'''
```

## defense_evasion_timestomp_sysmon
```
query = '''
file where host.os.type == "windows" and
  event.provider == "Microsoft-Windows-Sysmon" and
  /* File creation time change */
  event.code == "2" and
  not process.executable :
           ("?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Windows\\system32\\cleanmgr.exe",
            "?:\\Windows\\system32\\msiexec.exe",
            "?:\\Windows\\syswow64\\msiexec.exe",
            "?:\\Windows\\system32\\svchost.exe",
            "?:\\WINDOWS\\system32\\backgroundTaskHost.exe",
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
            "?:\\Users\\*\\AppData\\Local\\slack\\app-*\\slack.exe",
            "?:\\Users\\*\\AppData\\Local\\GitHubDesktop\\app-*\\GitHubDesktop.exe",
            "?:\\Users\\*\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
            "?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe") and
  not file.extension : ("temp", "tmp", "~tmp", "xml", "newcfg") and not user.name : ("SYSTEM", "Local Service", "Network Service") and
  not file.name : ("LOG", "temp-index", "license.rtf", "iconcache_*.db")
'''
```

## defense_evasion_unsigned_dll_loaded_from_suspdir
```
query = '''
library where host.os.type == "windows" and

 process.code_signature.trusted == true and

 (dll.Ext.relative_file_creation_time <= 500 or dll.Ext.relative_file_name_modify_time <= 500) and

  not dll.code_signature.status : ("trusted", "errorExpired", "errorCode_endpoint*", "errorChaining") and

      /* Suspicious Paths */
      dll.path : ("?:\\PerfLogs\\*.dll",
                  "?:\\Users\\*\\Pictures\\*.dll",
                  "?:\\Users\\*\\Music\\*.dll",
                  "?:\\Users\\Public\\*.dll",
                  "?:\\Users\\*\\Documents\\*.dll",
                  "?:\\Windows\\Tasks\\*.dll",
                  "?:\\Windows\\System32\\Tasks\\*.dll",
                  "?:\\Intel\\*.dll",
                  "?:\\AMD\\Temp\\*.dll",
                  "?:\\Windows\\AppReadiness\\*.dll",
                  "?:\\Windows\\ServiceState\\*.dll",
                  "?:\\Windows\\security\\*.dll",
		  "?:\\Windows\\System\\*.dll",
                  "?:\\Windows\\IdentityCRL\\*.dll",
                  "?:\\Windows\\Branding\\*.dll",
                  "?:\\Windows\\csc\\*.dll",
                  "?:\\Windows\\DigitalLocker\\*.dll",
                  "?:\\Windows\\en-US\\*.dll",
                  "?:\\Windows\\wlansvc\\*.dll",
                  "?:\\Windows\\Prefetch\\*.dll",
                  "?:\\Windows\\Fonts\\*.dll",
                  "?:\\Windows\\diagnostics\\*.dll",
                  "?:\\Windows\\TAPI\\*.dll",
                  "?:\\Windows\\INF\\*.dll",
                  "?:\\windows\\tracing\\*.dll",
                  "?:\\windows\\IME\\*.dll",
                  "?:\\Windows\\Performance\\*.dll",
                  "?:\\windows\\intel\\*.dll",
                  "?:\\windows\\ms\\*.dll",
                  "?:\\Windows\\dot3svc\\*.dll",
                  "?:\\Windows\\ServiceProfiles\\*.dll",
                  "?:\\Windows\\panther\\*.dll",
                  "?:\\Windows\\RemotePackages\\*.dll",
                  "?:\\Windows\\OCR\\*.dll",
                  "?:\\Windows\\appcompat\\*.dll",
                  "?:\\Windows\\apppatch\\*.dll",
                  "?:\\Windows\\addins\\*.dll",
                  "?:\\Windows\\Setup\\*.dll",
                  "?:\\Windows\\Help\\*.dll",
                  "?:\\Windows\\SKB\\*.dll",
                  "?:\\Windows\\Vss\\*.dll",
                  "?:\\Windows\\Web\\*.dll",
                  "?:\\Windows\\servicing\\*.dll",
                  "?:\\Windows\\CbsTemp\\*.dll",
                  "?:\\Windows\\Logs\\*.dll",
                  "?:\\Windows\\WaaS\\*.dll",
                  "?:\\Windows\\twain_32\\*.dll",
                  "?:\\Windows\\ShellExperiences\\*.dll",
                  "?:\\Windows\\ShellComponents\\*.dll",
                  "?:\\Windows\\PLA\\*.dll",
                  "?:\\Windows\\Migration\\*.dll",
                  "?:\\Windows\\debug\\*.dll",
                  "?:\\Windows\\Cursors\\*.dll",
                  "?:\\Windows\\Containers\\*.dll",
                  "?:\\Windows\\Boot\\*.dll",
                  "?:\\Windows\\bcastdvr\\*.dll",
                  "?:\\Windows\\TextInput\\*.dll",
                  "?:\\Windows\\schemas\\*.dll",
                  "?:\\Windows\\SchCache\\*.dll",
                  "?:\\Windows\\Resources\\*.dll",
                  "?:\\Windows\\rescache\\*.dll",
                  "?:\\Windows\\Provisioning\\*.dll",
                  "?:\\Windows\\PrintDialog\\*.dll",
                  "?:\\Windows\\PolicyDefinitions\\*.dll",
                  "?:\\Windows\\media\\*.dll",
                  "?:\\Windows\\Globalization\\*.dll",
                  "?:\\Windows\\L2Schemas\\*.dll",
                  "?:\\Windows\\LiveKernelReports\\*.dll",
                  "?:\\Windows\\ModemLogs\\*.dll",
                  "?:\\Windows\\ImmersiveControlPanel\\*.dll",
                  "?:\\$Recycle.Bin\\*.dll") and

	 /* DLL loaded from the process.executable current directory */
	 endswith~(substring(dll.path, 0, length(dll.path) - (length(dll.name) + 1)), substring(process.executable, 0, length(process.executable) - (length(process.name) + 1)))
'''
```

## defense_evasion_untrusted_driver_loaded
```
query = '''
driver where host.os.type == "windows" and process.pid == 4 and
  (dll.code_signature.trusted == false or dll.code_signature.exists == false) and
  not dll.code_signature.status : ("errorExpired", "errorRevoked", "errorCode_endpoint:*")
'''
```

## defense_evasion_unusual_ads_file_creation
```
query = '''
file where host.os.type == "windows" and event.type == "creation" and

  file.path : "C:\\*:*" and file.extension in~ (
    "pdf", "dll", "exe", "dat", "com", "bat", "cmd", "sys", "vbs", "ps1", "hta", "txt", "vbe", "js",
    "wsh", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "rtf", "gif", "jpg", "png", "bmp", "img", "iso"
  ) and

  not file.path : 
          ("C:\\*:zone.identifier*",
           "C:\\users\\*\\appdata\\roaming\\microsoft\\teams\\old_weblogs_*:$DATA",
           "C:\\Windows\\CSC\\*:CscBitmapStream") and

  not process.executable : (
          "?:\\Program Files (x86)\\Dropbox\\Client\\Dropbox.exe",
          "?:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
          "?:\\Program Files (x86)\\Microsoft Office\\root\\*\\EXCEL.EXE",
          "?:\\Program Files (x86)\\Microsoft Office\\root\\*\\OUTLOOK.EXE",
          "?:\\Program Files (x86)\\Microsoft Office\\root\\*\\POWERPNT.EXE",
          "?:\\Program Files (x86)\\Microsoft Office\\root\\*\\WINWORD.EXE",
          "?:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
          "?:\\Program Files\\ExpressConnect\\ExpressConnectNetworkService.exe",
          "?:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
          "?:\\Program Files\\Microsoft Office\\root\\*\\EXCEL.EXE",
          "?:\\Program Files\\Microsoft Office\\root\\*\\OUTLOOK.EXE",
          "?:\\Program Files\\Microsoft Office\\root\\*\\POWERPNT.EXE",
          "?:\\Program Files\\Microsoft Office\\root\\*\\WINWORD.EXE",
          "?:\\Program Files\\Mozilla Firefox\\firefox.exe",
          "?:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe",
          "?:\\Program Files\\Rivet Networks\\SmartByte\\SmartByteNetworkService.exe",
          "?:\\Windows\\explorer.exe",
          "?:\\Windows\\System32\\DataExchangeHost.exe",
          "?:\\Windows\\System32\\drivers\\Intel\\ICPS\\IntelConnectivityNetworkService.exe",
          "?:\\Windows\\System32\\drivers\\RivetNetworks\\Killer\\KillerNetworkService.exe",
          "?:\\Windows\\System32\\inetsrv\\w3wp.exe",
          "?:\\Windows\\System32\\PickerHost.exe",
          "?:\\Windows\\System32\\RuntimeBroker.exe",
          "?:\\Windows\\System32\\SearchProtocolHost.exe",
          "?:\\Windows\\System32\\sihost.exe",
          "?:\\windows\\System32\\svchost.exe",
          "?:\\Windows\\System32\\WFS.exe"
  ) and
  
  not (
    ?process.code_signature.trusted == true and
    file.name : "*:sec.endpointdlp:$DATA"
  )

'''
```

## defense_evasion_unusual_system_vp_child_program
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.parent.pid == 4 and process.executable : "?*" and
  not process.executable : ("Registry", "MemCompression", "?:\\Windows\\System32\\smss.exe", "HotPatch")
'''
```

## defense_evasion_via_filter_manager
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : "fltMC.exe" and process.args : "unload" and
  not process.parent.executable : 
                   ("?:\\Program Files (x86)\\ManageEngine\\UEMS_Agent\\bin\\DCFAService64.exe", 
                    "?:\\Windows\\SysWOW64\\msiexec.exe", 
                    "?:\\Program Files\\Bitdefender\\Endpoint Security\\installer\\installer.exe", 
                    "?:\\Program Files\\Bitdefender\\Endpoint Security\\EPSecurityService.exe", 
                    "?:\\Program Files\\Bitdefender\\Bitdefender Security\\productcfg.exe", 
                    "?:\\Program Files\\Bitdefender\\Bitdefender Security\\bdservicehost.exe", 
                    "?:\\Program Files\\Bitdefender\\EndpointSetupInformation\\{*}\\Installer.exe")
'''
```

## defense_evasion_wdac_policy_by_unusual_process
```
query = '''
file where host.os.type == "windows" and event.action != "deletion" and
  file.extension : ("p7b", "cip") and
  file.path : (
    "?:\\Windows\\System32\\CodeIntegrity\\*.p7b",
    "?:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip",
    "\\Device\\HarddiskVolume*\\Windows\\System32\\CodeIntegrity\\*.p7b",
    "\\Device\\HarddiskVolume*\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip"
  ) and
  not process.executable : (
    "C:\\Windows\\System32\\poqexec.exe",
    "\\Device\\HarddiskVolume*\\Windows\\System32\\poqexec.exe"
  )
'''
```

## defense_evasion_wsl_child_process
```
query = '''
process where host.os.type == "windows" and event.type : "start" and
  process.parent.name : ("wsl.exe", "wslhost.exe") and
  not process.executable : (
        "?:\\Program Files (x86)\\*",
        "?:\\Program Files\\*",
        "?:\\Program Files*\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_*\\wsl*.exe",
        "?:\\Windows\\System32\\conhost.exe",
        "?:\\Windows\\System32\\lxss\\wslhost.exe",
        "?:\\Windows\\System32\\WerFault.exe",
        "?:\\Windows\\Sys?????\\wslconfig.exe"
  ) and
  not (
    /* Crowdstrike specific exclusion as it uses NT Object paths */
    event.dataset == "crowdstrike.fdr" and
      process.executable : (
        "\\Device\\HarddiskVolume*\\Program Files (x86)\\*",
        "\\Device\\HarddiskVolume*\\Program Files\\*",
        "\\Device\\HarddiskVolume*\\Program Files*\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_*\\wsl*.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\conhost.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\lxss\\wslhost.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\WerFault.exe",
        "\\Device\\HarddiskVolume*\\Windows\\Sys?????\\wslconfig.exe"
      )
  )
'''
```

## defense_evasion_wsl_filesystem
```
query = '''
sequence by process.entity_id with maxspan=5m
[process where host.os.type == "windows" and event.type == "start" and
 process.name : "dllhost.exe" and
  /* Plan9FileSystem CLSID - WSL Host File System Worker */
 process.command_line : "*{DFB65C4C-B34F-435D-AFE9-A86218684AA8}*"]
[file where host.os.type == "windows" and process.name : "dllhost.exe" and
  not file.path : (
        "?:\\Users\\*\\Downloads\\*",
        "?:\\Windows\\Prefetch\\DLLHOST.exe-????????.pf")]
'''
```

## discovery_active_directory_webservice
```
query = '''
sequence by process.entity_id with maxspan=3m
 [library where host.os.type == "windows" and
  dll.name : ("System.DirectoryServices*.dll", "System.IdentityModel*.dll") and
  not user.id in ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
  not process.executable :
                ("?:\\windows\\system32\\dsac.exe",
                 "?:\\program files\\powershell\\?\\pwsh.exe",
                 "?:\\windows\\system32\\windowspowershell\\*.exe",
                 "?:\\windows\\syswow64\\windowspowershell\\*.exe",
                 "?:\\program files\\microsoft monitoring agent\\*.exe",
                 "?:\\windows\\adws\\microsoft.activedirectory.webservices.exe")]
 [network where host.os.type == "windows" and destination.port == 9389 and source.port >= 49152 and
  network.direction == "egress" and network.transport == "tcp" and not cidrmatch(destination.ip, "127.0.0.0/8", "::1/128")]
'''
``` 
## discovery_adfind_command_activity
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "AdFind*.exe" or ?process.pe.original_file_name == "AdFind.exe") and
  process.args : ("objectcategory=computer", "(objectcategory=computer)",
                  "objectcategory=person", "(objectcategory=person)",
                  "objectcategory=subnet", "(objectcategory=subnet)",
                  "objectcategory=group", "(objectcategory=group)",
                  "objectcategory=organizationalunit", "(objectcategory=organizationalunit)",
                  "objectcategory=attributeschema", "(objectcategory=attributeschema)",
                  "domainlist", "dcmodes", "adinfo", "dclist", "computers_pwnotreqd", "trustdmp")
'''
```

## discovery_admin_recon
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
(
  (
    (
      (process.name : "net.exe" or ?process.pe.original_file_name == "net.exe") or
      ((process.name : "net1.exe" or ?process.pe.original_file_name == "net1.exe") and not process.parent.name : "net.exe")
    ) and
    process.args : ("group", "user", "localgroup") and
    process.args : ("*admin*", "Domain Admins", "Remote Desktop Users", "Enterprise Admins", "Organization Management")
    and not process.args : ("/add", "/delete")
  ) or
  (
    (process.name : "wmic.exe" or ?process.pe.original_file_name == "wmic.exe") and
    process.args : ("group", "useraccount")
  )
) and not user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20")
'''
```

## discovery_command_system_account
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (?process.Ext.token.integrity_level_name : "System" or
  ?winlog.event_data.IntegrityLevel : "System") and
  (
    process.name : "whoami.exe" or
    (
      process.name : "net1.exe" and not process.parent.name : "net.exe" and not process.args : ("start", "stop", "/active:*")
    )
  ) and 
process.parent.executable != null and 
not (process.name : "net1.exe" and process.working_directory : "C:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\Downloads\\") and 
not process.parent.executable : 
                ("C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe", 
                 "C:\\Program Files\\Dell\\SupportAssistAgent\\SRE\\SRE.exe", 
                 "C:\\Program Files\\Obkio Agent\\main.dist\\ObkioAgentSoftware.exe", 
                 "C:\\Windows\\Temp\\WinGet\\defaultState\\PostgreSQL.PostgreSQL*\\postgresql-*-windows-x64.exe", 
                 "C:\\Program Files\\Obkio Agent\\main.dist\\ObkioAgentSoftware.exe", 
                 "C:\\Program Files (x86)\\SolarWinds\\Agent\\Plugins\\JobEngine\\SWJobEngineWorker2.exe") and 
not (process.parent.executable : "C:\\Windows\\Sys?????\\WindowsPowerShell\\v1.0\\powershell.exe" and 
     process.parent.args : ("C:\\Program Files (x86)\\Microsoft Intune Management Extension\\*.ps1", 
                            "Agent\\Modules\\AdHealthConfiguration\\AdHealthConfiguration.psd1'")) and 
not (process.parent.name : "cmd.exe" and process.working_directory : "C:\\Program Files\\Infraon Corp\\SecuraAgent\\")
'''
```

## discovery_group_policy_object_discovery
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
(process.name: "gpresult.exe" or ?process.pe.original_file_name == "gprslt.exe") and process.args: ("/z", "/v", "/r", "/x")
'''
```

## discovery_signal_unusual_discovery_signal_proc_cmdline
```
query = '''
host.os.type:windows and event.kind:signal and kibana.alert.rule.rule_id:(
  "d68e95ad-1c82-4074-a12a-125fe10ac8ba" or "7b8bfc26-81d2-435e-965c-d722ee397ef1" or
  "0635c542-1b96-4335-9b47-126582d2c19a" or "6ea55c81-e2ba-42f2-a134-bccf857ba922" or
  "e0881d20-54ac-457f-8733-fe0bc5d44c55" or "06568a02-af29-4f20-929c-f3af281e41aa" or
  "c4e9ed3e-55a2-4309-a012-bc3c78dad10a" or "51176ed2-2d90-49f2-9f3d-17196428b169"
)
'''
```

## discovery_whoami_command_activity
```
query = '''
process where host.os.type == "windows" and event.type == "start" and process.name : "whoami.exe" and
(
  (
    /* scoped for whoami execution under system privileges */
    (
      (
        user.domain : ("NT *", "* NT", "IIS APPPOOL") and
        user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-82-*") and
        not ?winlog.event_data.SubjectUserName : "*$" and

        /* Sysmon will always populate user.id as S-1-5-18, leading to FPs */
        not event.dataset : ("windows.sysmon_operational", "windows.sysmon")
      ) or
      (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System")
    ) and
    not (
      process.parent.name : "cmd.exe" and
      process.parent.args : (
          "chcp 437>nul 2>&1 & C:\\WINDOWS\\System32\\whoami.exe  /groups",
          "chcp 437>nul 2>&1 & %systemroot%\\system32\\whoami /user",
          "C:\\WINDOWS\\System32\\whoami.exe /groups",
          "*WINDOWS\\system32\\config\\systemprofile*"
      )
    ) and
    not (process.parent.executable : "C:\\Windows\\system32\\inetsrv\\appcmd.exe" and process.parent.args : "LIST") and
    not process.parent.executable : (
        "C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe",
        "C:\\Program Files\\Cohesity\\cohesity_windows_agent_service.exe"
    )
  ) or
  process.parent.name : ("wsmprovhost.exe", "w3wp.exe", "wmiprvse.exe", "rundll32.exe", "regsvr32.exe")
)
'''
```

## execution_apt_solarwinds_backdoor_child_cmd_powershell
```
query = '''
process where host.os.type == "windows" and event.type == "start" and process.name: ("cmd.exe", "powershell.exe") and
process.parent.name: (
     "ConfigurationWizard*.exe",
     "NetflowDatabaseMaintenance*.exe",
     "NetFlowService*.exe",
     "SolarWinds.Administration*.exe",
     "SolarWinds.Collector.Service*.exe",
     "SolarwindsDiagnostics*.exe"
     )
'''
```

## execution_apt_solarwinds_backdoor_unusual_child_processes
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name: ("SolarWinds.BusinessLayerHost.exe", "SolarWinds.BusinessLayerHostx64.exe") and
 not (
    process.name : (
        "APMServiceControl*.exe",
        "ExportToPDFCmd*.Exe",
        "SolarWinds.Credentials.Orion.WebApi*.exe",
        "SolarWinds.Orion.Topology.Calculator*.exe",
        "Database-Maint.exe",
        "SolarWinds.Orion.ApiPoller.Service.exe",
        "WerFault.exe",
        "WerMgr.exe",
        "SolarWinds.BusinessLayerHost.exe",
        "SolarWinds.BusinessLayerHostx64.exe",
        "SolarWinds.Topology.Calculator.exe",
        "SolarWinds.Topology.Calculatorx64.exe",
        "SolarWinds.APM.RealTimeProcessPoller.exe") and
    process.code_signature.trusted == true
 ) and
 not process.executable : ("?:\\Windows\\SysWOW64\\ARP.EXE", "?:\\Windows\\SysWOW64\\lodctr.exe", "?:\\Windows\\SysWOW64\\unlodctr.exe")
'''
```

## execution_command_shell_started_by_svchost
```
query = '''
host.os.type:windows and event.category:process and event.type:start and process.parent.name:"svchost.exe" and
process.name:("cmd.exe" or "Cmd.exe" or "CMD.EXE") and

  not process.command_line : "\"cmd.exe\" /C sc control hptpsmarthealthservice 211"
'''
```

## execution_command_shell_started_by_unusual_process
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : "cmd.exe" and
  process.parent.name : ("lsass.exe",
                         "csrss.exe",
                         "epad.exe",
                         "regsvr32.exe",
                         "dllhost.exe",
                         "LogonUI.exe",
                         "wermgr.exe",
                         "spoolsv.exe",
                         "jucheck.exe",
                         "jusched.exe",
                         "ctfmon.exe",
                         "taskhostw.exe",
                         "GoogleUpdate.exe",
                         "sppsvc.exe",
                         "sihost.exe",
                         "slui.exe",
                         "SIHClient.exe",
                         "SearchIndexer.exe",
                         "SearchProtocolHost.exe",
                         "FlashPlayerUpdateService.exe",
                         "WerFault.exe",
                         "WUDFHost.exe",
                         "unsecapp.exe",
                         "wlanext.exe" ) and
  not (process.parent.name : "dllhost.exe" and process.parent.args : "/Processid:{CA8C87C1-929D-45BA-94DB-EF8E6CB346AD}")
'''
```

## execution_command_shell_via_rundll32
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 process.name : ("cmd.exe", "powershell.exe") and
  process.parent.name : "rundll32.exe" and process.parent.command_line != null and
  /* common FPs can be added here */
  not process.parent.args : ("C:\\Windows\\System32\\SHELL32.dll,RunAsNewUser_RunDLL",
                             "C:\\WINDOWS\\*.tmp,zzzzInvokeManagedCustomActionOutOfProc")
'''
```

## execution_from_unusual_path_cmdline
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("wscript.exe",
                  "cscript.exe",
                  "rundll32.exe",
                  "regsvr32.exe",
                  "cmstp.exe",
                  "RegAsm.exe",
                  "installutil.exe",
                  "mshta.exe",
                  "RegSvcs.exe",
                  "powershell.exe",
                  "pwsh.exe",
                  "cmd.exe") and

  /* add suspicious execution paths here */
  process.args : ("C:\\PerfLogs\\*",
                  "C:\\Users\\Public\\*",
                  "C:\\Windows\\Tasks\\*",
                  "C:\\Intel\\*",
                  "C:\\AMD\\Temp\\*",
                  "C:\\Windows\\AppReadiness\\*",
                  "C:\\Windows\\ServiceState\\*",
                  "C:\\Windows\\security\\*",
                  "C:\\Windows\\IdentityCRL\\*",
                  "C:\\Windows\\Branding\\*",
                  "C:\\Windows\\csc\\*",
                  "C:\\Windows\\DigitalLocker\\*",
                  "C:\\Windows\\en-US\\*",
                  "C:\\Windows\\wlansvc\\*",
                  "C:\\Windows\\Prefetch\\*",
                  "C:\\Windows\\Fonts\\*",
                  "C:\\Windows\\diagnostics\\*",
                  "C:\\Windows\\TAPI\\*",
                  "C:\\Windows\\INF\\*",
                  "C:\\Windows\\System32\\Speech\\*",
                  "C:\\windows\\tracing\\*",
                  "c:\\windows\\IME\\*",
                  "c:\\Windows\\Performance\\*",
                  "c:\\windows\\intel\\*",
                  "c:\\windows\\ms\\*",
                  "C:\\Windows\\dot3svc\\*",
                  "C:\\Windows\\panther\\*",
                  "C:\\Windows\\RemotePackages\\*",
                  "C:\\Windows\\OCR\\*",
                  "C:\\Windows\\appcompat\\*",
                  "C:\\Windows\\apppatch\\*",
                  "C:\\Windows\\addins\\*",
                  "C:\\Windows\\Setup\\*",
                  "C:\\Windows\\Help\\*",
                  "C:\\Windows\\SKB\\*",
                  "C:\\Windows\\Vss\\*",
                  "C:\\Windows\\servicing\\*",
                  "C:\\Windows\\CbsTemp\\*",
                  "C:\\Windows\\Logs\\*",
                  "C:\\Windows\\WaaS\\*",
                  "C:\\Windows\\twain_32\\*",
                  "C:\\Windows\\ShellExperiences\\*",
                  "C:\\Windows\\ShellComponents\\*",
                  "C:\\Windows\\PLA\\*",
                  "C:\\Windows\\Migration\\*",
                  "C:\\Windows\\debug\\*",
                  "C:\\Windows\\Cursors\\*",
                  "C:\\Windows\\Containers\\*",
                  "C:\\Windows\\Boot\\*",
                  "C:\\Windows\\bcastdvr\\*",
                  "C:\\Windows\\TextInput\\*",
                  "C:\\Windows\\security\\*",
                  "C:\\Windows\\schemas\\*",
                  "C:\\Windows\\SchCache\\*",
                  "C:\\Windows\\Resources\\*",
                  "C:\\Windows\\rescache\\*",
                  "C:\\Windows\\Provisioning\\*",
                  "C:\\Windows\\PrintDialog\\*",
                  "C:\\Windows\\PolicyDefinitions\\*",
                  "C:\\Windows\\media\\*",
                  "C:\\Windows\\Globalization\\*",
                  "C:\\Windows\\L2Schemas\\*",
                  "C:\\Windows\\LiveKernelReports\\*",
                  "C:\\Windows\\ModemLogs\\*",
                  "C:\\Windows\\ImmersiveControlPanel\\*",
                  "C:\\$Recycle.Bin\\*") and

  /* noisy FP patterns */

  not process.parent.executable : ("C:\\WINDOWS\\System32\\DriverStore\\FileRepository\\*\\igfxCUIService*.exe",
                                   "C:\\Windows\\System32\\spacedeskService.exe",
                                   "C:\\Program Files\\Dell\\SupportAssistAgent\\SRE\\SRE.exe") and
  not (process.name : "rundll32.exe" and
       process.args : ("uxtheme.dll,#64",
                       "PRINTUI.DLL,PrintUIEntry",
                       "?:\\Windows\\System32\\FirewallControlPanel.dll,ShowNotificationDialog",
                       "?:\\WINDOWS\\system32\\Speech\\SpeechUX\\sapi.cpl",
                       "?:\\Windows\\system32\\shell32.dll,OpenAs_RunDLL")) and

  not (process.name : "cscript.exe" and process.args : "?:\\WINDOWS\\system32\\calluxxprovider.vbs") and

  not (process.name : "cmd.exe" and process.args : "?:\\WINDOWS\\system32\\powercfg.exe" and process.args : "?:\\WINDOWS\\inf\\PowerPlan.log") and

  not (process.name : "regsvr32.exe" and process.args : "?:\\Windows\\Help\\OEM\\scripts\\checkmui.dll") and

  not (process.name : "cmd.exe" and
       process.parent.executable : ("?:\\Windows\\System32\\oobe\\windeploy.exe",
                                    "?:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe",
                                    "?:\\Windows\\System32\\igfxCUIService.exe",
                                    "?:\\Windows\\Temp\\IE*.tmp\\IE*-support\\ienrcore.exe"))
'''
```

## execution_initial_access_via_msc_file
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.parent.executable : "?:\\Windows\\System32\\mmc.exe" and endswith~(process.parent.args, ".msc") and
  not (
    process.parent.args : (
      "?:\\Windows\\System32\\*.msc",
      "?:\\Windows\\SysWOW64\\*.msc",
      "?:\\Program files\\*.msc",
      "?:\\Program Files (x86)\\*.msc"
    ) or
    (
      process.executable : "?:\\Windows\\System32\\mmc.exe" and
      process.command_line : "\"C:\\WINDOWS\\system32\\mmc.exe\" \"C:\\Windows\\System32\\gpme.msc\" /s /gpobject:\"LDAP://*"
    ) or
    (
      process.executable : (
        "?:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "?:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "?:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "?:\\Program Files\\internet explorer\\iexplore.exe"
      ) and
      process.args : "http*://go.microsoft.com/fwlink/*"
    ) or
    process.executable : (
      "?:\\Windows\\System32\\vmconnect.exe",
      "?:\\Windows\\System32\\WerFault.exe",
      "?:\\Windows\\System32\\wermgr.exe"
    )
  )
'''
```

## execution_posh_malicious_script_agg
```
query = '''
from .alerts-security.* metadata _id

// Filter for PowerShell related alerts
| where kibana.alert.rule.name like "*PowerShell*"

// as alerts don't have non-ECS fields, parse the script block ID using grok
| grok message "ScriptBlock ID: (?<Esql.script_block_id>.+)"
| where Esql.script_block_id is not null

// keep relevant fields for further processing
| keep kibana.alert.rule.name, Esql.script_block_id, _id

// count distinct alerts and filter for matches above the threshold
| stats
    Esql.kibana_alert_rule_name_count_distinct = count_distinct(kibana.alert.rule.name),
    Esql.kibana_alert_rule_name_values = values(kibana.alert.rule.name),
    Esql._id_values = values(_id)
  by Esql.script_block_id

// Apply detection threshold
| where Esql.kibana_alert_rule_name_count_distinct >= 5
'''
```

## execution_powershell_susp_args_via_winscript
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.command_line != null and
  (
    process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe", "cmd.exe") or
    ?process.pe.original_file_name : ("powershell.exe", "pwsh.dll", "powershell_ise.exe", "Cmd.Exe")
  ) and
  process.parent.name : ("wscript.exe", "mshta.exe")
'''
```

## execution_psexec_lateral_movement_command
```
query = '''
sequence by process.entity_id
  [process where host.os.type == "windows" and process.name : "PsExec.exe" and event.type == "start" and

   /* This flag suppresses the display of the license dialog and may
      indicate that psexec executed for the first time in the machine */
   process.args : "-accepteula" and

   not process.executable : ("?:\\ProgramData\\Docusnap\\Discovery\\discovery\\plugins\\17\\Bin\\psexec.exe",
                             "?:\\Docusnap 11\\Bin\\psexec.exe",
                             "?:\\Program Files\\Docusnap X\\Bin\\psexec.exe",
                             "?:\\Program Files\\Docusnap X\\Tools\\dsDNS.exe") and
   not process.parent.executable : "?:\\Program Files (x86)\\Cynet\\Cynet Scanner\\CynetScanner.exe"]
  [network where host.os.type == "windows" and process.name : "PsExec.exe"]
'''
```

## execution_revshell_cmd_via_netcat
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
process.name : ("cmd.exe", "powershell.exe") and process.parent.args : "-e" and
 (
  (process.parent.args_count == 5 and process.parent.command_line regex~ """.*[0-9]{1,3}(\.[0-9]{1,3}){3}.*""") or
  (process.parent.args : "-*l*" and process.parent.args : "-*p*" and process.parent.args : ("cmd.exe", "powershell.exe"))
  )
'''
```

## execution_scripts_archive_file
```
query = '''
process where host.os.type == "windows" and event.type == "start" and process.name : "wscript.exe" and
 process.parent.name : ("explorer.exe", "winrar.exe", "7zFM.exe") and
 process.args :
        ("?:\\Users\\*\\AppData\\Local\\Temp\\7z*\\*",
         "?:\\Users\\*\\AppData\\Local\\Temp\\*.zip.*\\*",
         "?:\\Users\\*\\AppData\\Local\\Temp\\Rar$*\\*",
         "?:\\Users\\*\\AppData\\Local\\Temp\\Temp?_*\\*",
         "?:\\Users\\*\\AppData\\Local\\Temp\\BNZ.*")
'''
```
## execution_suspicious_cmd_wmi
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "WmiPrvSE.exe" and process.name : "cmd.exe" and process.args : "/c" and process.args:"/Q" and 
 process.args : "2>&1" and process.args: "1>"  and 
 process.args : ("C:\\windows\\temp\\*.txt", "\\Windows\\Temp\\*", "-encodehex", "\\\\127.0.0.1\\C$\\Windows\\Temp\\*", "\\\\127.0.0.1\\ADMIN$\\__*.*")
'''
```

## execution_suspicious_powershell_imgload
```
query = '''
host.os.type:windows and event.category:library and
  dll.name:("System.Management.Automation.dll" or "System.Management.Automation.ni.dll") and
  not (
    process.code_signature.subject_name:(
      "Microsoft Corporation" or
      "Microsoft Dynamic Code Publisher" or
      "Microsoft Windows"
    ) and process.code_signature.trusted:true and not process.name.caseless:"regsvr32.exe"
  ) and
  not (
    process.executable:(C\:\\Program*Files*\(x86\)\\*.exe or C\:\\Program*Files\\*.exe) and
    process.code_signature.trusted:true
  ) and
  not (
    process.executable: C\:\\Windows\\Lenovo\\*.exe and process.code_signature.subject_name:"Lenovo" and
    process.code_signature.trusted:true
  ) and
  not (
    process.executable: C\:\\Windows\\AdminArsenal\\PDQInventory-Scanner\\service-*\\exec\\PDQInventoryScanner.exe and
    process.code_signature.subject_name:"PDQ.com Corporation" and
    process.code_signature.trusted:true
  ) and
  not (
    process.name: (_is*.exe or "DellInstaller_x64.exe") and
    process.code_signature.subject_name:("Dell Technologies Inc." or "Dell Inc" or "Dell Inc.") and
    process.code_signature.trusted:true
  ) and
  not (
    process.executable: C\:\\ProgramData\\chocolatey\\* and
    process.code_signature.subject_name:("Chocolatey Software, Inc." or "Chocolatey Software, Inc") and
    process.code_signature.trusted:true
  ) and
  not (
    process.name: "Docker Desktop Installer.exe" and
    process.code_signature.subject_name:"Docker Inc" and
    process.code_signature.trusted:true
  ) and
  not process.executable : (
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" or
    "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"
  )
'''
```

## execution_windows_cmd_shell_susp_args
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : "cmd.exe" and
  (
    process.command_line : (
        "*).Run(*", "*GetObject*", "* curl*regsvr32*", "*echo*wscript*", "*echo*ZONE.identifier*",
        "*ActiveXObject*", "*dir /s /b *echo*", "*unescape(*",  "*findstr*TVNDRgAAAA*", "*findstr*passw*", "*start*\\\\*\\DavWWWRoot\\*",
        "* explorer*%CD%*", "*%cd%\\*.js*", "*attrib*%CD%*", "*/?cMD<*", "*/AutoIt3ExecuteScript*..*", "*&cls&cls&cls&cls&cls&*",
        "*&#*;&#*;&#*;&#*;*", "* &&s^eT*", "*& ChrW(*", "*&explorer /root*", "*start __ & __\\*", "*findstr /V /L *forfiles*",
        "*=wscri& set *", "*http*!COmpUternaME!*", "*start *.pdf * start /min cmd.exe /c *\\\\*", "*pip install*System.Net.WebClient*",
        "*Invoke-WebReques*Start-Process*", "*-command (Invoke-webrequest*", "*copy /b *\\\\* ping *-n*", "*echo*.ToCharArray*"
    ) or

    (process.args : "echo" and process.parent.name : ("wscript.exe", "mshta.exe")) or
    
    process.args : ("1>?:\\*.vbs", "1>?:\\*.js") or

    (process.args : "explorer.exe" and process.args : "type" and process.args : ">" and process.args : "start") or

    (
      process.parent.name : "explorer.exe" and
      process.command_line : (
        "*&&S^eT *",
        "*&& set *&& set *&& set *&& set *&& set *&& call*",
        "**\\u00??\\u00??\\u00??\\u00??\\u00??\\u00??\\u00??\\u00??*"
      )
    ) or

    (process.parent.name : "explorer.exe" and process.args : "copy" and process.args : "&&" and process.args : "\\\\*@*\\*")
  ) and

  /* false positives */
  not (process.args : "%TEMP%\\Spiceworks\\*" and process.parent.name : "wmiprvse.exe") and
  not ?process.parent.executable : (
        "?:\\Perl64\\bin\\perl.exe",
        "?:\\Program Files\\nodejs\\node.exe",
        "?:\\Program Files\\HP\\RS\\pgsql\\bin\\pg_dumpall.exe",
        "?:\\Program Files (x86)\\PRTG Network Monitor\\64 bit\\PRTG Server.exe",
        "?:\\Program Files (x86)\\Spiceworks\\bin\\spiceworks-finder.exe",
        "?:\\Program Files (x86)\\Zuercher Suite\\production\\leds\\leds.exe",
        "?:\\Program Files\\Tripwire\\Agent\\Plugins\\twexec\\twexec.exe",
        "D:\\Agents\\?\\_work\\_tasks\\*\\SonarScanner.MSBuild.exe",
        "?:\\Program Files\\Microsoft VS Code\\Code.exe",
        "?:\\programmiweb\\NetBeans-*\\netbeans\\bin\\netbeans64.exe",
        "?:\\Program Files (x86)\\Public Safety Suite Professional\\production\\leds\\leds.exe",
        "?:\\Program Files (x86)\\Tier2Tickets\\button_gui.exe",
        "?:\\Program Files\\NetBeans-*\\netbeans\\bin\\netbeans*.exe",
        "?:\\Program Files (x86)\\Public Safety Suite Professional\\production\\leds\\leds.exe",
        "?:\\Program Files (x86)\\Tier2Tickets\\button_gui.exe",
        "?:\\Program Files (x86)\\Helpdesk Button\\button_gui.exe",
        "?:\\VTSPortable\\VTS\\jre\\bin\\javaw.exe",
        "?:\\Program Files\\Bot Framework Composer\\Bot Framework Composer.exe",
        "?:\\Program Files\\KMSYS Worldwide\\eQuate\\*\\SessionMgr.exe",
        "?:\\Program Files (x86)\\Craneware\\Pricing Analyzer\\Craneware.Pricing.Shell.exe",
        "?:\\Program Files (x86)\\jumpcloud-agent-app\\jumpcloud-agent-app.exe",
        "?:\\Program Files\\PostgreSQL\\*\\bin\\pg_dumpall.exe",
        "?:\\Program Files (x86)\\Vim\\vim*\\vimrun.exe") and
  not (
        /* Crowdstrike doesn't populate process.parent.executable */
        event.dataset == "crowdstrike.fdr" and
        process.parent.name : (
          "perl.exe", "node.exe", "pg_dumpall.exe", "PRTG Server.exe", "spiceworks-finder.exe", "leds.exe", "twexec.exe",
          "SonarScanner.MSBuild.exe", "Code.exe", "netbeans64.exe", "javaw.exe", "Bot Framework Composer.exe", "SessionMgr.exe",
          "Craneware.Pricing.Shell.exe", "jumpcloud-agent-app.exe", "vimrun.exe"
        )
      ) and
  not (process.args :  "?:\\Program Files\\Citrix\\Secure Access Client\\nsauto.exe" and process.parent.name : "userinit.exe") and
  not process.args : (
        "?:\\Program Files (x86)\\PCMatic\\PCPitstopScheduleService.exe",
        "?:\\Program Files (x86)\\AllesTechnologyAgent\\*",
        "https://auth.axis.com/oauth2/oauth-authorize*"
  ) and
  not process.command_line : (
    "\"cmd\" /c %NETBEANS_MAVEN_COMMAND_LINE%",
    "?:\\Windows\\system32\\cmd.exe /q /d /s /c \"npm.cmd ^\"install^\" ^\"--no-bin-links^\" ^\"--production^\"\""
  ) and
  not (process.name : "cmd.exe" and process.args : "%TEMP%\\Spiceworks\\*" and process.args : "http*/dataloader/persist_netstat_data") and
  not (process.args == "echo" and process.args == "GEQ" and process.args == "1073741824")
'''
```

## execution_windows_powershell_susp_args
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 process.name : "powershell.exe" and

  not (
    ?user.id == "S-1-5-18" and
    /* Don't apply the user.id exclusion to Sysmon for compatibility */
    not event.dataset : ("windows.sysmon_operational", "windows.sysmon")
  ) and

  (
    process.command_line : (
          "*^*^*^*^*^*^*^*^*^*",
          "*`*`*`*`*",
          "*+*+*+*+*+*+*",
          "*[char[]](*)*-join*",
          "*Base64String*",
          "*[*Convert]*",
          "*.Compression.*",
          "*-join($*",
          "*.replace*",
          "*MemoryStream*",
          "*WriteAllBytes*",
          "* -enc *",
          "* -ec *",
          "* /e *",
          "* /enc *",
          "* /ec *",
          "*WebClient*",
          "*DownloadFile*",
          "*DownloadString*",
          "* iex*",
          "* iwr*",
          "* aQB3AHIAIABpA*",
          "*Reflection.Assembly*",
          "*Assembly.GetType*",
          "*$env:temp\\*start*",
          "*powercat*",
          "*nslookup -q=txt*",
          "*$host.UI.PromptForCredential*",
          "*Net.Sockets.TCPClient*",
          "*curl *;Start*",
          "powershell.exe \"<#*",
          "*ssh -p *",
          "*http*|iex*",
          "*@SSL\\DavWWWRoot\\*.ps1*",
          "*.lnk*.Seek(0x*",
          "*[string]::join(*",
          "*[Array]::Reverse($*",
          "* hidden $(gc *",
          "*=wscri& set*",
          "*http'+'s://*",
          "*.content|i''Ex*",
          "*//:sptth*",
          "*//:ptth*",
          "*h''t''t''p*",
          "*'tp'':''/'*",
          "*$env:T\"E\"MP*",
          "*;cmd /c $?",
          "*s''t''a''r*",
          "*$*=Get-Content*AppData*.SubString(*$*",
          "*=cat *AppData*.substring(*);*$*",
          "*-join'';*|powershell*",
          "*.Content;sleep *|powershell*",
          "*h\''t\''tp:\''*",
          "*-e aQB3AHIAIABp*",
          "*iwr *https*).Content*",
          "*$env:computername*http*",
          "*;InVoKe-ExpRESsIoN $COntent.CONTENt;*",
          "*WebClient*example.com*",
          "*=iwr $*;iex $*",
          "*ServerXmlHttp*IEX*",
          "*XmlDocument*IEX*"
    ) or

    (process.args : "-c" and process.args : "&{'*") or

    (process.args : "-Outfile" and process.args : "Start*") or

    (process.args : "-bxor" and process.args : "0x*") or

    process.args : "$*$*;set-alias" or

    process.args == "-e" or

    // ATHPowerShellCommandLineParameter
    process.args : ("-EncodedCommandParamVariation", "-UseEncodedArguments", "-CommandParamVariation") or

    (
      process.parent.name : ("explorer.exe", "cmd.exe") and
      process.command_line : ("*-encodedCommand*", "*Invoke-webrequest*", "*WebClient*", "*Reflection.Assembly*"))
    )
'''
```

## execution_windows_script_from_internet
```
query = '''
sequence by host.id, user.id with maxspan=3m
[file where host.os.type == "windows" and event.action == "creation" and user.id != "S-1-5-18" and
  process.name : ("chrome.exe", "msedge.exe", "brave.exe", "browser.exe", "dragon.exe", "vivaldi.exe", "explorer.exe", "winrar.exe", "7zFM.exe", "7zG.exe", "Bandizip.exe") and
  file.extension in~ ("js", "jse", "vbs", "vbe", "wsh", "hta", "cmd", "bat") and
  (file.origin_url != null or file.origin_referrer_url != null)]
[process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : ("chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "browser.exe", "dragon.exe", "vivaldi.exe", "explorer.exe", "winrar.exe", "7zFM.exe", "7zG.exe", "Bandizip.exe") and 
 process.args_count >= 2 and
 (
  process.name in~ ("wscript.exe", "mshta.exe") or
  (process.name : "cmd.exe" and process.command_line : ("*.cmd*", "*.bat*"))
  )]
'''
```

## impact_backup_file_deletion
```
query = '''
file where host.os.type == "windows" and event.type == "deletion" and
  (
    /* Veeam Related Backup Files */
    (
      file.extension : ("VBK", "VIB", "VBM") and
      not (
        process.executable : ("?:\\Windows\\*", "?:\\Program Files\\*", "?:\\Program Files (x86)\\*") and
        (process.code_signature.trusted == true and process.code_signature.subject_name : ("Veeam Software Group GmbH", "Veeam Software AG"))
      )
    ) or
    /* Veritas Backup Exec Related Backup File */
    (
      file.extension : "BKF" and
        not process.executable : (
          "?:\\Program Files\\Veritas\\Backup Exec\\*",
          "?:\\Program Files (x86)\\Veritas\\Backup Exec\\*"
        )
    )
  ) and
  not (
    process.name : ("MSExchangeMailboxAssistants.exe", "Microsoft.PowerBI.EnterpriseGateway.exe") and
      (process.code_signature.subject_name : "Microsoft Corporation" and process.code_signature.trusted == true)
  ) and
  not file.path : (
    "?:\\ProgramData\\Trend Micro\\*",
    "?:\\Program Files (x86)\\Trend Micro\\*",
    "?:\\$RECYCLE.BIN\\*"
  )
'''
```

## impact_mod_critical_os_files
```
query = '''
file where host.os.type == "windows" and event.type in ("change", "deletion") and
  file.name : ("winload.exe", "winlod.efi", "ntoskrnl.exe", "bootmgr") and
  file.path : ("?:\\Windows\\*", "\\Device\\HarddiskVolume*\\Windows\\*") and
  not process.executable : (
    "?:\\Windows\\System32\\poqexec.exe",
    "?:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack_*\\tiworker.exe"
  ) and
  not file.path : (
    "?:\\Windows\\WinSxS\\Temp\\InFlight\\*",
    "?:\\Windows\\SoftwareDistribution\\Download*",
    "?:\\Windows\\WinSxS\\amd64_microsoft-windows*",
    "?:\\Windows\\SystemTemp\\*",
    "?:\\Windows\\Temp\\????????.???\\*",
    "?:\\Windows\\Temp\\*\\amd64_microsoft-windows-*"
  )
'''
```

## impact_ransomware_file_rename_smb
```
query = '''
sequence by host.id with maxspan=1s
 [network where host.os.type == "windows" and
  event.action == "connection_accepted" and destination.port == 445 and source.port >= 49152 and process.pid == 4 and
  source.ip != "127.0.0.1" and source.ip != "::1" and
  network.type == "ipv4" and not endswith(source.address, destination.address)]
 [file where host.os.type == "windows" and
  event.action == "rename" and process.pid == 4 and user.id : ("S-1-5-21*", "S-1-12-*") and
  file.extension != null and file.Ext.entropy >= 6 and file.path : "C:\\Users\\*" and
  file.Ext.original.name : ("*.jpg", "*.bmp", "*.png", "*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx", "*.ppt", "*.pptx", "*.lnk") and
  not file.extension : ("jpg", "bmp", "png", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "*.lnk")] with runs=3
'''
```

## impact_ransomware_note_file_over_smb
```
query = '''
sequence by host.id with maxspan=1s
 [network where host.os.type == "windows" and
  event.action == "connection_accepted" and destination.port == 445 and source.port >= 49152 and process.pid == 4 and
  source.ip != "127.0.0.1" and source.ip != "::1" and
  network.type == "ipv4" and not endswith(source.address, destination.address)]
 [file where host.os.type == "windows" and event.action == "creation" and
  process.pid == 4 and user.id : ("S-1-5-21*", "S-1-12-*") and file.extension : ("hta", "txt", "readme", "htm*") and
  file.path : "C:\\Users\\*" and
   /* ransom file name keywords */
    file.name : ("*read*me*", "*lock*", "*@*", "*RECOVER*", "*decrypt*", "*restore*file*", "*FILES_BACK*", "*how*to*")] with runs=3
'''
```

## initial_access_execution_remote_via_msiexec
```
query = '''
sequence with maxspan=1m
 [process where host.os.type == "windows" and event.action == "start" and
    process.name : "msiexec.exe" and process.args : "/V"] by process.entity_id
 [network where host.os.type == "windows" and process.name : "msiexec.exe" and
    event.action == "connection_attempted"] by process.entity_id
 [process where host.os.type == "windows" and event.action == "start" and
  process.parent.name : "msiexec.exe" and user.id : ("S-1-5-21-*", "S-1-5-12-1-*") and
  not process.executable : ("?:\\Windows\\SysWOW64\\msiexec.exe",
                            "?:\\Windows\\System32\\msiexec.exe",
                            "?:\\Windows\\System32\\srtasks.exe",
                            "?:\\Windows\\SysWOW64\\srtasks.exe",
                            "?:\\Windows\\System32\\taskkill.exe",
                            "?:\\Windows\\Installer\\MSI*.tmp",
                            "?:\\Program Files\\*.exe",
                            "?:\\Program Files (x86)\\*.exe",
                            "?:\\Windows\\System32\\ie4uinit.exe",
                            "?:\\Windows\\SysWOW64\\ie4uinit.exe",
                            "?:\\Windows\\System32\\sc.exe",
                            "?:\\Windows\\system32\\Wbem\\mofcomp.exe",
                            "?:\\Windows\\twain_32\\fjscan32\\SOP\\crtdmprc.exe",
                            "?:\\Windows\\SysWOW64\\taskkill.exe",
                            "?:\\Windows\\SysWOW64\\schtasks.exe",
                            "?:\\Windows\\system32\\schtasks.exe",
                            "?:\\Windows\\System32\\sdbinst.exe") and
  not (process.code_signature.subject_name == "Citrix Systems, Inc." and process.code_signature.trusted == true) and
  not (process.name : ("regsvr32.exe", "powershell.exe", "rundll32.exe", "wscript.exe") and
       process.Ext.token.integrity_level_name == "high" and
       process.args : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*")) and
  not (process.executable : ("?:\\Program Files\\*.exe", "?:\\Program Files (x86)\\*.exe") and process.code_signature.trusted == true) and
  not (process.name : "rundll32.exe" and process.args : "printui.dll,PrintUIEntry")
  ] by process.parent.entity_id
'''
```

## initial_access_script_executing_powershell
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : ("cscript.exe", "wscript.exe") and process.name : "powershell.exe" and
  not (
    process.parent.name : "wscript.exe" and
    process.parent.args : "?:\\ProgramData\\intune-drive-mapping-generator\\IntuneDriveMapping-VBSHelper.vbs" and
    process.parent.args : "?:\\ProgramData\\intune-drive-mapping-generator\\DriveMapping.ps1"
  )
'''
```

## initial_access_scripts_process_started_via_wmi
```
query = '''
sequence by host.id with maxspan = 5s
    [any where host.os.type == "windows" and
     (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
     (?dll.name : "wmiutils.dll" or file.name : "wmiutils.dll") and process.name : ("wscript.exe", "cscript.exe")]
    [process where host.os.type == "windows" and event.type == "start" and
     process.parent.name : "wmiprvse.exe" and
     user.domain != "NT AUTHORITY" and
     (process.pe.original_file_name :
        (
          "cscript.exe",
          "wscript.exe",
          "PowerShell.EXE",
          "Cmd.Exe",
          "MSHTA.EXE",
          "RUNDLL32.EXE",
          "REGSVR32.EXE",
          "MSBuild.exe",
          "InstallUtil.exe",
          "RegAsm.exe",
          "RegSvcs.exe",
          "msxsl.exe",
          "CONTROL.EXE",
          "EXPLORER.EXE",
          "Microsoft.Workflow.Compiler.exe",
          "msiexec.exe"
        ) or
      process.executable : ("C:\\Users\\*.exe", "C:\\ProgramData\\*.exe")
     )
    ]
'''
```

## initial_access_suspicious_ms_exchange_process
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : ("UMService.exe", "UMWorkerProcess.exe") and
    not process.executable : (
          "?:\\Windows\\System32\\werfault.exe",
          "?:\\Windows\\System32\\wermgr.exe",
          "?:\\Program Files\\Microsoft\\Exchange Server\\V??\\Bin\\UMWorkerProcess.exe",
          "?:\\Program Files\\Microsoft\\Exchange Server\\Bin\\UMWorkerProcess.exe",
          "D:\\Exchange 2016\\Bin\\UMWorkerProcess.exe",
          "E:\\ExchangeServer\\Bin\\UMWorkerProcess.exe",
          "D:\\Exchange\\Bin\\UMWorkerProcess.exe",
          "D:\\Exchange Server\\Bin\\UMWorkerProcess.exe",
          "E:\\Exchange Server\\V15\\Bin\\UMWorkerProcess.exe",

          /* Crowdstrike specific exclusion as it uses NT Object paths */
          "\\Device\\HarddiskVolume*\\Windows\\System32\\werfault.exe",
          "\\Device\\HarddiskVolume*\\Windows\\System32\\wermgr.exe",
          "\\Device\\HarddiskVolume*\\Program Files\\Microsoft\\Exchange Server\\V??\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume*\\Program Files\\Microsoft\\Exchange Server\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume*\\Exchange 2016\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume*\\ExchangeServer\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume*\\Exchange\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume*\\Exchange Server\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume*\\Exchange Server\\V15\\Bin\\UMWorkerProcess.exe"
    )
'''
```

## initial_access_suspicious_ms_exchange_files
```
query = '''
file where host.os.type == "windows" and event.type == "creation" and
  process.name : ("UMWorkerProcess.exe", "umservice.exe") and
  file.extension : ("php", "jsp", "js", "aspx", "asmx", "asax", "cfm", "shtml") and
  (
    file.path : "?:\\inetpub\\wwwroot\\aspnet_client\\*" or

    (file.path : "?:\\*\\Microsoft\\Exchange Server*\\FrontEnd\\HttpProxy\\owa\\auth\\*" and
       not (file.path : "?:\\*\\Microsoft\\Exchange Server*\\FrontEnd\\HttpProxy\\owa\\auth\\version\\*" or
            file.name : ("errorFE.aspx", "expiredpassword.aspx", "frowny.aspx", "GetIdToken.htm", "logoff.aspx",
                        "logon.aspx", "OutlookCN.aspx", "RedirSuiteServiceProxy.aspx", "signout.aspx"))) or

    (file.path : "?:\\*\\Microsoft\\Exchange Server*\\FrontEnd\\HttpProxy\\ecp\\auth\\*" and
       not file.name : "TimeoutLogoff.aspx")
  )
'''
```

## initial_access_suspicious_windows_server_update_svc
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "rundll32.exe", "curl.exe") and
  (
   (process.parent.name : "w3wp.exe" and process.parent.args : "WsusPool") or
   process.parent.name : "WsusService.exe"
   )
'''
```

## initial_access_xsl_script_execution_via_com
```
query = '''
sequence with maxspan=1m
 [library where host.os.type == "windows" and dll.name : "msxml3.dll" and
  process.name : ("winword.exe", "excel.exe", "powerpnt.exe", "mspub.exe")] by process.entity_id
 [process where host.os.type == "windows" and event.action == "start" and
  process.parent.name : ("winword.exe", "excel.exe", "powerpnt.exe", "mspub.exe") and
  not process.executable :
        ("?:\\Windows\\System32\\WerFault.exe",
         "?:\\Windows\\SysWoW64\\WerFault.exe",
         "?:\\windows\\splwow64.exe",
         "?:\\Windows\\System32\\conhost.exe",
         "?:\\Program Files\\*.exe",
         "?:\\Program Files (x86)\\*exe")] by process.parent.entity_id
'''
```

## lateral_movement_cmd_service
```
query = '''
sequence by process.entity_id with maxspan = 1m
  [process where host.os.type == "windows" and event.type == "start" and
     (process.name : "sc.exe" or process.pe.original_file_name : "sc.exe") and
      process.args : "\\\\*" and process.args : ("binPath=*", "binpath=*") and
      process.args : ("create", "config", "failure", "start")]
  [network where host.os.type == "windows" and process.name : "sc.exe" and destination.ip != "127.0.0.1"]
'''
```

## lateral_movement_credential_access_kerberos_correlation
```
query = '''
sequence by source.port, source.ip with maxspan=3s
 [network where host.os.type == "windows" and destination.port == 88 and
  process.executable != null and
  not process.executable : 
              ("?:\\Windows\\system32\\lsass.exe", 
               "\\device\\harddiskvolume*\\windows\\system32\\lsass.exe") and
  not (process.executable : ("C:\\Windows\\System32\\svchost.exe", 
                             "C:\\Program Files\\VMware\\VMware View\\Server\\bin\\ws_TomcatService.exe", 
                             "F:\\IGEL\\RemoteManager\\*\\bin\\tomcat10.exe") and user.id in ("S-1-5-20", "S-1-5-18")) and   
  source.ip != "127.0.0.1" and destination.ip != "::1" and destination.ip != "127.0.0.1"]
 [authentication where host.os.type == "windows" and event.code in ("4768", "4769")]
'''
```

## lateral_movement_powershell_remoting_target
```
query = '''
sequence by host.id with maxspan = 30s
   [network where host.os.type == "windows" and network.direction : ("incoming", "ingress") and destination.port in (5985, 5986) and
    source.ip != "127.0.0.1" and source.ip != "::1"]
   [process where host.os.type == "windows" and
    event.type == "start" and process.parent.name : "wsmprovhost.exe" and not process.executable : "?:\\Windows\\System32\\conhost.exe"]
'''
```

## lateral_movement_remote_service_installed_winlog
```
query = '''
sequence by winlog.logon.id, winlog.computer_name with maxspan=1m
[authentication where host.os.type == "windows" and event.action == "logged-in" and winlog.logon.type : "Network" and
 event.outcome == "success" and source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1"]
[iam where host.os.type == "windows" and event.action == "service-installed" and
 not winlog.event_data.SubjectLogonId : "0x3e7" and
 not winlog.event_data.ServiceFileName :
               ("?:\\Windows\\ADCR_Agent\\adcrsvc.exe",
                "?:\\Windows\\System32\\VSSVC.exe",
                "?:\\Windows\\servicing\\TrustedInstaller.exe",
                "?:\\Windows\\System32\\svchost.exe",
                "?:\\Program Files (x86)\\*.exe",
                "?:\\Program Files\\*.exe",
                "?:\\Windows\\PSEXESVC.EXE",
                "?:\\Windows\\System32\\sppsvc.exe",
                "?:\\Windows\\System32\\wbem\\WmiApSrv.exe",
                "?:\\WINDOWS\\RemoteAuditService.exe",
                "?:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe",
                "?:\\Windows\\VeeamLogShipper\\VeeamLogShipper.exe",
                "?:\\Windows\\CAInvokerService.exe",
                "?:\\Windows\\System32\\upfc.exe",
                "?:\\Windows\\AdminArsenal\\PDQ*.exe",
                "?:\\Windows\\System32\\vds.exe",
                "?:\\Windows\\Veeam\\Backup\\VeeamDeploymentSvc.exe",
                "?:\\Windows\\ProPatches\\Scheduler\\STSchedEx.exe",
                "?:\\Windows\\System32\\certsrv.exe",
                "?:\\Windows\\eset-remote-install-service.exe",
                "?:\\Pella Corporation\\Pella Order Management\\GPAutoSvc.exe",
                "?:\\Pella Corporation\\OSCToGPAutoService\\OSCToGPAutoSvc.exe",
                "?:\\Pella Corporation\\Pella Order Management\\GPAutoSvc.exe",
                "?:\\Windows\\SysWOW64\\NwxExeSvc\\NwxExeSvc.exe",
                "?:\\Windows\\System32\\taskhostex.exe")]
'''
```

## lateral_movement_remote_services
```
query = '''
sequence with maxspan=1s
   [network where host.os.type == "windows" and process.name : "services.exe" and
      network.direction : ("incoming", "ingress") and network.transport == "tcp" and
      source.port >= 49152 and destination.port >= 49152 and source.ip != "127.0.0.1" and source.ip != "::1"
   ] by host.id, process.entity_id
   [process where host.os.type == "windows" and 
       event.type == "start" and process.parent.name : "services.exe" and
       not (process.executable : "?:\\Windows\\System32\\msiexec.exe" and process.args : "/V") and
       not process.executable : (
                "?:\\Pella Corporation\\OSCToGPAutoService\\OSCToGPAutoSvc.exe",
                "?:\\Pella Corporation\\Pella Order Management\\GPAutoSvc.exe",
                "?:\\Pella Corporation\\Pella Order Management\\GPAutoSvc.exe",
                "?:\\Program Files (x86)\\*.exe",
                "?:\\Program Files\\*.exe",
                "?:\\Windows\\ADCR_Agent\\adcrsvc.exe",
                "?:\\Windows\\AdminArsenal\\PDQ*.exe",
                "?:\\Windows\\CAInvokerService.exe",
                "?:\\Windows\\ccmsetup\\ccmsetup.exe",
                "?:\\Windows\\eset-remote-install-service.exe",
                "?:\\Windows\\ProPatches\\Scheduler\\STSchedEx.exe",
                "?:\\Windows\\PSEXESVC.EXE",
                "?:\\Windows\\RemoteAuditService.exe",
                "?:\\Windows\\servicing\\TrustedInstaller.exe",
                "?:\\Windows\\System32\\certsrv.exe",
                "?:\\Windows\\System32\\sppsvc.exe",
                "?:\\Windows\\System32\\srmhost.exe",
                "?:\\Windows\\System32\\svchost.exe",
                "?:\\Windows\\System32\\taskhostex.exe",
                "?:\\Windows\\System32\\upfc.exe",
                "?:\\Windows\\System32\\vds.exe",
                "?:\\Windows\\System32\\VSSVC.exe",
                "?:\\Windows\\System32\\wbem\\WmiApSrv.exe",
                "?:\\Windows\\SysWOW64\\NwxExeSvc\\NwxExeSvc.exe",
                "?:\\Windows\\Veeam\\Backup\\VeeamDeploymentSvc.exe",
                "?:\\Windows\\VeeamLogShipper\\VeeamLogShipper.exe",
                "?:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe"
       )] by host.id, process.parent.entity_id
'''
```

## lateral_movement_remote_task_creation_winlog
```
query = '''
iam where host.os.type == "windows" and event.action == "scheduled-task-created" and
 winlog.event_data.RpcCallClientLocality : "0" and winlog.event_data.ClientProcessId : "0"
'''
```

## persistence_ad_adminsdholder
```
query = '''
event.code:5136 and host.os.type:"windows" and winlog.event_data.ObjectDN:CN=AdminSDHolder,CN=System*
'''
```

## persistence_browser_extension_install
```
query = '''
file where host.os.type == "windows" and event.type : "creation" and
(
  /* Firefox-Based Browsers */
  (
    file.name : "*.xpi" and
    file.path : "?:\\Users\\*\\AppData\\Roaming\\*\\Profiles\\*\\Extensions\\*.xpi" and
    not
    (
      process.name : "firefox.exe" and
      file.name : (
        "langpack-*@firefox.mozilla.org.xpi",
        "*@dictionaries.addons.mozilla.org.xpi",
        "newtab@mozilla.org.xpi",
        "uBlock0@raymondhill.net.xpi",
        /* AdBlockPlus */
        "{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}.xpi",
        /* Bitwarden */
        "{446900e4-71c2-419f-a6a7-df9c091e268b}.xpi",
        "addon@darkreader.org.xpi",
        /* 1Password */
        "{d634138d-c276-4fc8-924b-40a0ea21d284}.xpi",
        "support@lastpass.com.xpi",
        /* Grammarly */
        "87677a2c52b84ad3a151a4a72f5bd3c4@jetpack.xpi",
        "sentinelone_visibility@sentinelone.com.xpi",
        "keepassxc-browser@keepassxc.org.xpi"
      )
    )
  ) or
  /* Chromium-Based Browsers */
  (
    file.name : "*.crx" and
    file.path : "?:\\Users\\*\\AppData\\Local\\*\\*\\User Data\\Webstore Downloads\\*"
  )
)
'''
```

## persistence_dontexpirepasswd_account
```
query = '''
any where host.os.type == "windows" and
(
  (
    event.code == "4738" and winlog.event_data.NewUACList == "USER_DONT_EXPIRE_PASSWORD" and not user.id == "S-1-5-18"
  ) or
  (
    event.code == "5136" and winlog.event_data.AttributeLDAPDisplayName == "userAccountControl" and
    winlog.event_data.AttributeValue in ("66048", "66080") and winlog.event_data.OperationType == "%%14674" and
    not (
      winlog.event_data.SubjectUserName : "*svc*" or
      winlog.event_data.ObjectDN : "*Service*"
    )
  )
)
'''
```

## persistence_evasion_hidden_local_account_creation
```
query = '''
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
    "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\*$\\",
    "\\REGISTRY\\MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\*$\\",
    "MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\*$\\"
)
'''
```

## persistence_evasion_registry_ifeo_injection
```
query = '''
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : ("Debugger", "MonitorProcess") and length(registry.data.strings) > 0 and
  registry.path : (
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*.exe\\Debugger",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\Debugger",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*.exe\\Debugger",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\Debugger",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess",
    "MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*.exe\\Debugger",
    "MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\Debugger",
    "MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess",
    "MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess"
  ) and
    /* add FPs here */
  not registry.data.strings regex~ ("""C:\\Program Files( \(x86\))?\\ThinKiosk\\thinkiosk\.exe""", """.*\\PSAppDeployToolkit\\.*""")
'''
```

## persistence_evasion_registry_startup_shell_folder_modified
```
query = '''
registry where host.os.type == "windows" and event.type == "change" and
 registry.value : ("Common Startup", "Startup") and
 registry.path : (
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "HKCU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKCU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup"
     ) and
  registry.data.strings != null and
  /* Normal Startup Folder Paths */
  not registry.data.strings : (
           "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "%%USERPROFILE%%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "\\\\*"
           )
'''
```

## persistence_powershell_exch_mailbox_activesync_add_device
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and process.args : "Set-CASMailbox*ActiveSyncAllowedDeviceIDs*"
'''
```

## persistence_powershell_profiles
```
query = '''
file where host.os.type == "windows" and event.type != "deletion" and
  file.name : ("profile.ps1", "Microsoft.Powershell_profile.ps1") and
  file.path : ("?:\\Users\\*\\Documents\\WindowsPowerShell\\*.ps1", 
                    "?:\\Users\\*\\Documents\\PowerShell\\*.ps1", 
                    "?:\\Windows\\System32\\WindowsPowerShell\\*.ps1", 
                    "\\Device\\HarddiskVolume*\\Users\\*\\Documents\\WindowsPowerShell\\*.ps1", 
                    "\\Device\\HarddiskVolume*\\Users\\*\\Documents\\PowerShell\\*.ps1", 
                    "\\Device\\HarddiskVolume*\\Windows\\System32\\WindowsPowerShell\\*.ps1")
'''
```

## persistence_remote_password_rese
```
query = '''
sequence by winlog.computer_name with maxspan=1m
  [authentication where host.os.type == "windows" and event.action == "logged-in" and
    /* event 4624 need to be logged */
    winlog.logon.type : "Network" and event.outcome == "success" and source.ip != null and
    source.ip != "127.0.0.1" and source.ip != "::1" and
    not winlog.event_data.TargetUserName : ("svc*", "PIM_*", "_*_", "*-*-*", "*$")] by winlog.event_data.TargetLogonId
   /* event 4724 need to be logged */
  [iam where host.os.type == "windows" and event.action == "reset-password" and
   (
    /*
       This rule is very noisy if not scoped to privileged accounts, duplicate the
       rule and add your own naming convention and accounts of interest here.
     */
    winlog.event_data.TargetUserName: ("*Admin*", "*super*", "*SVC*", "*DC0*", "*service*", "*DMZ*", "*ADM*") or
    winlog.event_data.TargetSid : ("S-1-5-21-*-500", "S-1-12-1-*-500")
    )
  ] by winlog.event_data.SubjectLogonId
'''
```

## persistence_scheduled_task_creation_winlog
```
query = '''
iam where host.os.type == "windows" and event.action == "scheduled-task-created" and

 /* excluding tasks created by the computer account */
 not user.name : "*$" and

 /* TaskContent is not parsed, exclude by full taskname noisy ones */
 not winlog.event_data.TaskName : (
              "\\CreateExplorerShellUnelevatedTask",
              "\\Hewlett-Packard\\HPDeviceCheck",
              "\\Hewlett-Packard\\HP Support Assistant\\WarrantyChecker",
              "\\Hewlett-Packard\\HP Support Assistant\\WarrantyChecker_backup",
              "\\Hewlett-Packard\\HP Web Products Detection",
              "\\Microsoft\\VisualStudio\\Updates\\BackgroundDownload",
              "\\OneDrive Standalone Update Task-S-1-5-21*",
              "\\OneDrive Standalone Update Task-S-1-12-1-*"
 )
'''
```

## persistence_service_dll_unsigned
```
query = '''
library where host.os.type == "windows" and

 process.executable :
     ("?:\\Windows\\System32\\svchost.exe", "?:\\Windows\\Syswow64\\svchost.exe") and

 dll.code_signature.trusted != true and

 not dll.code_signature.status : ("trusted", "errorExpired", "errorCode_endpoint*") and

 dll.hash.sha256 != null and

 (
       /* DLL created within 5 minutes of the library load event - compatible with Elastic Endpoint 8.4+ */
       dll.Ext.relative_file_creation_time <= 300 or

       /* unusual paths */
       dll.path :("?:\\ProgramData\\*",
                  "?:\\Users\\*",
                  "?:\\PerfLogs\\*",
                  "?:\\Windows\\Tasks\\*",
                  "?:\\Intel\\*",
                  "?:\\AMD\\Temp\\*",
                  "?:\\Windows\\AppReadiness\\*",
                  "?:\\Windows\\ServiceState\\*",
                  "?:\\Windows\\security\\*",
                  "?:\\Windows\\IdentityCRL\\*",
                  "?:\\Windows\\Branding\\*",
                  "?:\\Windows\\csc\\*",
                  "?:\\Windows\\DigitalLocker\\*",
                  "?:\\Windows\\en-US\\*",
                  "?:\\Windows\\wlansvc\\*",
                  "?:\\Windows\\Prefetch\\*",
                  "?:\\Windows\\Fonts\\*",
                  "?:\\Windows\\diagnostics\\*",
                  "?:\\Windows\\TAPI\\*",
                  "?:\\Windows\\INF\\*",
                  "?:\\Windows\\System32\\Speech\\*",
                  "?:\\windows\\tracing\\*",
                  "?:\\windows\\IME\\*",
                  "?:\\Windows\\Performance\\*",
                  "?:\\windows\\intel\\*",
                  "?:\\windows\\ms\\*",
                  "?:\\Windows\\dot3svc\\*",
                  "?:\\Windows\\panther\\*",
                  "?:\\Windows\\RemotePackages\\*",
                  "?:\\Windows\\OCR\\*",
                  "?:\\Windows\\appcompat\\*",
                  "?:\\Windows\\apppatch\\*",
                  "?:\\Windows\\addins\\*",
                  "?:\\Windows\\Setup\\*",
                  "?:\\Windows\\Help\\*",
                  "?:\\Windows\\SKB\\*",
                  "?:\\Windows\\Vss\\*",
                  "?:\\Windows\\servicing\\*",
                  "?:\\Windows\\CbsTemp\\*",
                  "?:\\Windows\\Logs\\*",
                  "?:\\Windows\\WaaS\\*",
                  "?:\\Windows\\twain_32\\*",
                  "?:\\Windows\\ShellExperiences\\*",
                  "?:\\Windows\\ShellComponents\\*",
                  "?:\\Windows\\PLA\\*",
                  "?:\\Windows\\Migration\\*",
                  "?:\\Windows\\debug\\*",
                  "?:\\Windows\\Cursors\\*",
                  "?:\\Windows\\Containers\\*",
                  "?:\\Windows\\Boot\\*",
                  "?:\\Windows\\bcastdvr\\*",
                  "?:\\Windows\\TextInput\\*",
                  "?:\\Windows\\security\\*",
                  "?:\\Windows\\schemas\\*",
                  "?:\\Windows\\SchCache\\*",
                  "?:\\Windows\\Resources\\*",
                  "?:\\Windows\\rescache\\*",
                  "?:\\Windows\\Provisioning\\*",
                  "?:\\Windows\\PrintDialog\\*",
                  "?:\\Windows\\PolicyDefinitions\\*",
                  "?:\\Windows\\media\\*",
                  "?:\\Windows\\Globalization\\*",
                  "?:\\Windows\\L2Schemas\\*",
                  "?:\\Windows\\LiveKernelReports\\*",
                  "?:\\Windows\\ModemLogs\\*",
                  "?:\\Windows\\ImmersiveControlPanel\\*",
                  "?:\\$Recycle.Bin\\*")
  ) and

  not dll.hash.sha256 :
            ("3ed33e71641645367442e65dca6dab0d326b22b48ef9a4c2a2488e67383aa9a6",
             "b4db053f6032964df1b254ac44cb995ffaeb4f3ade09597670aba4f172cf65e4",
             "214c75f678bc596bbe667a3b520aaaf09a0e50c364a28ac738a02f867a085eba",
             "23aa95b637a1bf6188b386c21c4e87967ede80242327c55447a5bb70d9439244",
             "5050b025909e81ae5481db37beb807a80c52fc6dd30c8aa47c9f7841e2a31be7")
'''
```

## persistence_service_windows_service_winlog
```
query = '''
any where host.os.type == "windows" and
  (event.code : "4697" and
   (winlog.event_data.ServiceFileName : 
           ("*COMSPEC*", "*\\127.0.0.1*", "*Admin$*", "*powershell*", "*rundll32*", "*cmd.exe*", "*PSEXESVC*", 
            "*echo*", "*RemComSvc*", "*.bat*", "*.cmd*", "*certutil*", "*vssadmin*", "*certmgr*", "*bitsadmin*", 
            "*\\Users\\*", "*\\Windows\\Temp\\*", "*\\Windows\\Tasks\\*", "*\\PerfLogs\\*", "*\\Windows\\Debug\\*",
            "*regsvr32*", "*msbuild*") or
   winlog.event_data.ServiceFileName regex~ """%systemroot%\\[a-z0-9]+\.exe""")) or

  (event.code : "7045" and
   winlog.event_data.ImagePath : (
       "*COMSPEC*", "*\\127.0.0.1*", "*Admin$*", "*powershell*", "*rundll32*", "*cmd.exe*", "*PSEXESVC*",
       "*echo*", "*RemComSvc*", "*.bat*", "*.cmd*", "*certutil*", "*vssadmin*", "*certmgr*", "*bitsadmin*",
       "*\\Users\\*", "*\\Windows\\Temp\\*", "*\\Windows\\Tasks\\*", "*\\PerfLogs\\*", "*\\Windows\\Debug\\*",
       "*regsvr32*", "*msbuild*"))
'''
```

## persistence_temp_scheduled_task
```
query = '''
sequence by winlog.computer_name, winlog.event_data.TaskName with maxspan=5m
   [iam where host.os.type == "windows" and event.action == "scheduled-task-created" and not user.name : "*$"]
   [iam where host.os.type == "windows" and event.action == "scheduled-task-deleted" and not user.name : "*$"]
'''
```

## persistence_user_account_creation
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
  (process.name : ("net.exe", "net1.exe") and not process.parent.name : "net.exe") and
  (process.args : "user" and process.args : ("/ad", "/add"))
'''
```

## privilege_escalation_create_process_as_different_user
```
query = '''
sequence by winlog.computer_name with maxspan=1m

[authentication where host.os.type == "windows" and event.action:"logged-in" and
 event.outcome == "success" and user.id : ("S-1-5-21-*", "S-1-12-1-*") and

 /* seclogon service */
 process.name == "svchost.exe" and
 winlog.event_data.LogonProcessName : "seclogo*" and source.ip == "::1" ] by winlog.event_data.TargetLogonId

[process where host.os.type == "windows" and event.type == "start"] by winlog.event_data.TargetLogonId
'''
```

## privilege_escalation_dmsa_creation_by_unusual_user
```
query = '''
event.code:5137 and host.os.type:"windows" and winlog.event_data.ObjectClass:"msDS-DelegatedManagedServiceAccount"
'''
```

## privilege_escalation_driver_newterm_imphash
```
query = '''
event.category:"driver" and host.os.type:windows and event.action:"load"
'''
```

## privilege_escalation_expired_driver_loaded
```
query = '''
driver where host.os.type == "windows" and process.pid == 4 and
  dll.code_signature.status : ("errorExpired", "errorRevoked")
'''
```

## privilege_escalation_installertakeover
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
    process.Ext.token.integrity_level_name : "System" and
    (
      (process.name : "elevation_service.exe" and
       not process.pe.original_file_name == "elevation_service.exe") or
      
      (process.name : "elevation_service.exe" and
       not process.code_signature.trusted == true) or

      (process.parent.name : "elevation_service.exe" and
       process.name : ("rundll32.exe", "cmd.exe", "powershell.exe"))
    ) and
    not
    (
      process.name : "elevation_service.exe" and process.code_signature.trusted == true and
      process.pe.original_file_name == null
    )
'''
```

## privilege_escalation_named_pipe_impersonation
```
query = '''
process where host.os.type == "windows" and event.type == "start" and
 (process.name : ("Cmd.Exe", "PowerShell.EXE") or ?process.pe.original_file_name in ("Cmd.Exe", "PowerShell.EXE")) and
 process.args : "echo" and process.args : ">" and process.args : "\\\\.\\pipe\\*"
'''
```

## privilege_escalation_newcreds_logon_rare_process.toml

Идентифицирует новый тип учетных данных для входа в систему, выполненный необычным способом. Это может указывать на наличие
возможности подделки токена доступа, которой часто злоупотребляют для обхода ограничений контроля доступа.

event.category:"authentication" and host.os.type:"windows" and winlog.logon.type:"NewCredentials" and
    winlog.event_data.LogonProcessName:Advapi* and
    not winlog.event_data.SubjectUserName:*$ and
    not process.executable: (C\:\\Program*Files*\(x86\)\\*.exe or C\:\\Program*Files\\*.exe)

## privilege_escalation_persistence_phantom_dll.toml

Идентифицирует загрузку библиотеки DLL, не подписанной корпорацией Майкрософт, которая отсутствует при установке Windows по умолчанию (фантомная библиотека DLL) или
может быть загружена из другого места с помощью встроенного процесса Windows. Это может быть использовано для сохранения или повышения
привилегий с помощью уязвимостей привилегированной записи файлов.

any where host.os.type == "windows" and
(event.category : ("driver", "library") or (event.category == "process" and event.action : "Image loaded*")) and
(
  /* compatible with Elastic Endpoint Library Events */
  (
    ?dll.name : (
        "wlbsctrl.dll", "wbemcomn.dll", "WptsExtensions.dll", "Tsmsisrv.dll", "TSVIPSrv.dll", "Msfte.dll",
        "wow64log.dll", "WindowsCoreDeviceInfo.dll", "Ualapi.dll", "wlanhlp.dll", "phoneinfo.dll", "EdgeGdi.dll",
        "cdpsgshims.dll", "windowsperformancerecordercontrol.dll", "diagtrack_win.dll", "TPPCOIPW32.dll", 
        "tpgenlic.dll", "thinmon.dll", "fxsst.dll", "msTracer.dll"
    )
    and (
      ?dll.code_signature.trusted != true or
      ?dll.code_signature.exists != true or
      (
        ?dll.code_signature.trusted == true and
          not ?dll.code_signature.subject_name : ("Microsoft Windows", "Microsoft Corporation", "Microsoft Windows Publisher")
      )
  ) or
   /* oci.dll is too noisy due to unsigned Oracle related DLL loaded from random dirs */
  (
   (?dll.path : "?:\\Windows\\*\\oci.dll" and process.executable : "?:\\Windows\\*.exe" and 
    (?dll.code_signature.trusted != true or ?dll.code_signature.exists != true)) or 
    
   (file.path : "?:\\Windows\\*\\oci.dll" and not file.code_signature.status == "Valid" and process.executable : "?:\\Windows\\*.exe")
   ) or 

  /* compatible with Sysmon EventID 7 - Image Load */
  (file.name : ("wlbsctrl.dll", "wbemcomn.dll", "WptsExtensions.dll", "Tsmsisrv.dll", "TSVIPSrv.dll", "Msfte.dll",
               "wow64log.dll", "WindowsCoreDeviceInfo.dll", "Ualapi.dll", "wlanhlp.dll", "phoneinfo.dll", "EdgeGdi.dll",
               "cdpsgshims.dll", "windowsperformancerecordercontrol.dll", "diagtrack_win.dll", "TPPCOIPW32.dll", 
               "tpgenlic.dll", "thinmon.dll", "fxsst.dll", "msTracer.dll") and 
   not file.hash.sha256 : 
            ("6e837794fc282446906c36d681958f2f6212043fc117c716936920be166a700f", 
             "b14e4954e8cca060ffeb57f2458b6a3a39c7d2f27e94391cbcea5387652f21a4", 
             "c258d90acd006fa109dc6b748008edbb196d6168bc75ace0de0de54a4db46662") and 
   not file.code_signature.status == "Valid")
  ) and
  not
  (
    ?dll.path : (
      "?:\\Windows\\System32\\wbemcomn.dll",
      "?:\\Windows\\SysWOW64\\wbemcomn.dll",
      "?:\\Windows\\System32\\windowsperformancerecordercontrol.dll",
      "?:\\Windows\\System32\\wlanhlp.dll", 
      "\\Device\\HarddiskVolume?\\Windows\\SysWOW64\\wbemcomn.dll", 
      "\\Device\\HarddiskVolume?\\Windows\\System32\\wbemcomn.dll", 
      "\\Device\\HarddiskVolume?\\Windows\\SysWOW64\\wlanhlp.dll", 
      "\\Device\\HarddiskVolume?\\Windows\\System32\\wlanhlp.dll", 
      "\\Device\\HarddiskVolume?\\Windows\\SysWOW64\\windowsperformancerecordercontrol.dll", 
      "\\Device\\HarddiskVolume?\\Windows\\System32\\windowsperformancerecordercontrol.dll", 
      "C:\\ProgramData\\docker\\windowsfilter\\*\\Files\\Windows\\System32\\windowsperformancerecordercontrol.dll", 
      "C:\\ProgramData\\docker\\windowsfilter\\*\\Files\\Windows\\System32\\windowsperformancerecordercontrol.dll", 
      "\\Device\\vmsmb\\VSMB-{*}\\os\\windows\\system32\\*.dll"
    ) or
    file.path : (
      "?:\\Windows\\System32\\wbemcomn.dll",
      "?:\\Windows\\SysWOW64\\wbemcomn.dll",
      "?:\\Windows\\System32\\windowsperformancerecordercontrol.dll",
      "?:\\Windows\\System32\\wlanhlp.dll", 
      "C:\\ProgramData\\docker\\windowsfilter\\*\\Files\\Windows\\System32\\windowsperformancerecordercontrol.dll", 
      "C:\\ProgramData\\docker\\windowsfilter\\*\\Files\\Windows\\System32\\wbemcomn.dll", 
      "\\Device\\vmsmb\\VSMB-{*}\\os\\windows\\system32\\*.dll"
    )
  )
)

## privilege_escalation_port_monitor_print_pocessor_abuse.toml

Определяет изменения в реестре port monitor и print processor. Злоумышленники могут использовать port monitor и print
processors для запуска вредоносных библиотек DLL во время загрузки системы, которые будут выполняться как SYSTEM для повышения привилегий и/или
сохранения, если разрешения позволяют указать полный путь к этой библиотеке DLL.

registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
      "HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Monitors\\*",
      "HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Environments\\Windows*\\Print Processors\\*",
      "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Print\\Monitors\\*",
      "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Print\\Environments\\Windows*\\Print Processors\\*"
  ) and registry.data.strings : "*.dll" and
  /* exclude SYSTEM SID - look for changes by non-SYSTEM user */
  not user.id : "S-1-5-18"

## privilege_escalation_posh_token_impersonation.toml

Обнаруживает скрипты, содержащие функции PowerShell, структуры или Windows API, связанные с
выдачей/кражей токена. Злоумышленники могут скопировать, а затем выдать себя за токен другого пользователя, чтобы повысить привилегии и обойти
контроль доступа.

event.category:process and host.os.type:windows and
  powershell.file.script_block_text:(
    "Invoke-TokenManipulation" or
    "ImpersonateNamedPipeClient" or
    "NtImpersonateThread" or
    (
      "STARTUPINFOEX" and
      "UpdateProcThreadAttribute"
    ) or
    (
      "AdjustTokenPrivileges" and
      "SeDebugPrivilege"
    ) or
    (
      ("DuplicateToken" or
      "DuplicateTokenEx") and
      ("SetThreadToken" or
      "ImpersonateLoggedOnUser" or
      "CreateProcessWithTokenW" or
      "CreatePRocessAsUserW" or
      "CreateProcessAsUserA")
    ) 
  ) and
  not (
    user.id:("S-1-5-18" or "S-1-5-19" or "S-1-5-20") and
    file.directory: "C:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\Downloads"
  ) and
  not powershell.file.script_block_text : (
    "sentinelbreakpoints" and "Set-PSBreakpoint" and "PowerSploitIndicators"
  ) and
  not (
    powershell.file.script_block_text : "New-HPPrivateToastNotificationLogo" and
    file.path : "C:\Program Files\HPConnect\hp-cmsl-wl\modules\HP.Notifications\HP.Notifications.psm1"
  )

## privilege_escalation_printspooler_registry_copyfiles.toml

Обнаруживает попытки использования уязвимости, связанной с повышением привилегий (CVE-2020-1030), связанной со службой диспетчера очереди печати.
Использование этой уязвимости заключается в объединении нескольких примитивов для загрузки произвольной библиотеки DLL в процесс диспетчера очереди печати, запущенный от
имени системы.

sequence by host.id with maxspan=30s
[registry where host.os.type == "windows" and
   registry.value : "SpoolDirectory" and
   registry.path : "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\SpoolDirectory" and
   registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4"]
[registry where host.os.type == "windows" and
   registry.value : "Module" and
   registry.path : "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\CopyFiles\\Payload\\Module" and
   registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4\\*"]

## privilege_escalation_printspooler_service_suspicious_file.toml

Обнаруживает попытки использования уязвимостей с повышением привилегий, связанных со службой диспетчера очереди печати. Для получения дополнительной
информации обратитесь к следующим CVE - CVE-2020-1048, CVE-2020-1337 и CVE-2020-1300 и убедитесь, что поврежденная
система исправлена.

event.category : "file" and host.os.type : "windows" and event.type : "creation" and
  process.name : "spoolsv.exe" and file.extension : "dll"

## privilege_escalation_printspooler_suspicious_file_deletion.toml

Обнаруживает удаление файлов драйвера принтера необычным способом. Это может указывать на попытку очистки после успешного
повышения привилегий с помощью уязвимостей, связанных со службой диспетчера очереди печати.

file where host.os.type == "windows" and event.type == "deletion" and
  file.extension : "dll" and file.path : "?:\\Windows\\System32\\spool\\drivers\\x64\\3\\*.dll" and
  not process.name : ("spoolsv.exe", "dllhost.exe", "explorer.exe")

## privilege_escalation_printspooler_suspicious_spl_file.toml

Обнаруживает попытки использования уязвимостей с повышением привилегий, связанных со службой диспетчера очереди печати, включая
CVE-2020-1048 и CVE-2020-1337.

file where host.os.type == "windows" and event.type != "deletion" and
  file.extension : "spl" and
  file.path : "?:\\Windows\\System32\\spool\\PRINTERS\\*" and
  not process.name : ("spoolsv.exe",
                      "printfilterpipelinesvc.exe",
                      "PrintIsolationHost.exe",
                      "splwow64.exe",
                      "msiexec.exe",
                      "poqexec.exe",
                      "System") and
  not user.id : "S-1-5-18" and
  not process.executable :
            ("?:\\Windows\\System32\\mmc.exe",
             "\\Device\\Mup\\*.exe",
             "?:\\Windows\\System32\\svchost.exe",
             "?:\\Windows\\System32\\mmc.exe",
             "?:\\Windows\\System32\\printui.exe",
             "?:\\Windows\\System32\\mstsc.exe",
             "?:\\Windows\\System32\\spool\\*.exe",
             "?:\\Program Files\\*.exe",
             "?:\\Program Files (x86)\\*.exe",
             "?:\\PROGRA~1\\*.exe",
             "?:\\PROGRA~2\\*.exe",
             "?:\\Windows\\System32\\rundll32.exe")

## privilege_escalation_reg_service_imagepath_mod.toml

Определяет изменения в реестре служб по умолчанию, которые могут привести к повышению привилегий СИСТЕМЫ. Злоумышленники, обладающие
привилегиями таких групп, как операторы сервера, могут изменять путь к изображениям служб, чтобы они могли выполнять исполняемые файлы, находящиеся под их контролем, или
выполнять команды.

registry where host.os.type == "windows" and event.type == "change" and process.executable != null and
  registry.data.strings != null and registry.value == "ImagePath" and
  registry.key : (
    "*\\ADWS", "*\\AppHostSvc", "*\\AppReadiness", "*\\AudioEndpointBuilder", "*\\AxInstSV", "*\\camsvc", "*\\CertSvc",
    "*\\COMSysApp", "*\\CscService", "*\\defragsvc", "*\\DeviceAssociationService", "*\\DeviceInstall", "*\\DevQueryBroker",
    "*\\Dfs", "*\\DFSR", "*\\diagnosticshub.standardcollector.service", "*\\DiagTrack", "*\\DmEnrollmentSvc", "*\\DNS",
    "*\\dot3svc", "*\\Eaphost", "*\\GraphicsPerfSvc", "*\\hidserv", "*\\HvHost", "*\\IISADMIN", "*\\IKEEXT",
    "*\\InstallService", "*\\iphlpsvc", "*\\IsmServ", "*\\LanmanServer", "*\\MSiSCSI", "*\\NcbService", "*\\Netlogon",
    "*\\Netman", "*\\NtFrs", "*\\PlugPlay", "*\\Power", "*\\PrintNotify", "*\\ProfSvc", "*\\PushToInstall", "*\\RSoPProv",
    "*\\sacsvr", "*\\SENS", "*\\SensorDataService", "*\\SgrmBroker", "*\\ShellHWDetection", "*\\shpamsvc", "*\\StorSvc",
    "*\\svsvc", "*\\swprv", "*\\SysMain", "*\\Themes", "*\\TieringEngineService", "*\\TokenBroker", "*\\TrkWks",
    "*\\UALSVC", "*\\UserManager", "*\\vm3dservice", "*\\vmicguestinterface", "*\\vmicheartbeat", "*\\vmickvpexchange",
    "*\\vmicrdv", "*\\vmicshutdown", "*\\vmicvmsession", "*\\vmicvss", "*\\vmvss", "*\\VSS", "*\\w3logsvc", "*\\W3SVC",
    "*\\WalletService", "*\\WAS", "*\\wercplsupport", "*\\WerSvc", "*\\Winmgmt", "*\\wisvc", "*\\wmiApSrv",
    "*\\WPDBusEnum", "*\\WSearch"
  ) and
  not (
    registry.data.strings : (
        "?:\\Windows\\system32\\*.exe",
        "%systemroot%\\system32\\*.exe",
        "%windir%\\system32\\*.exe",
        "%SystemRoot%\\system32\\svchost.exe -k *",
        "%windir%\\system32\\svchost.exe -k *"
    ) and
        not registry.data.strings : (
            "*\\cmd.exe",
            "*\\cscript.exe",
            "*\\ieexec.exe",
            "*\\iexpress.exe",
            "*\\installutil.exe",
            "*\\Microsoft.Workflow.Compiler.exe",
            "*\\msbuild.exe",
            "*\\mshta.exe",
            "*\\msiexec.exe",
            "*\\msxsl.exe",
            "*\\net.exe",
            "*\\powershell.exe",
            "*\\pwsh.exe",
            "*\\reg.exe",
            "*\\RegAsm.exe",
            "*\\RegSvcs.exe",
            "*\\regsvr32.exe",
            "*\\rundll32.exe",
            "*\\vssadmin.exe",
            "*\\wbadmin.exe",
            "*\\wmic.exe",
            "*\\wscript.exe"
        )
  )

## privilege_escalation_rogue_windir_environment_var.toml

Идентифицирует попытку повышения привилегий с помощью вредоносной переменной среды Windows directory (Windir). Это известный
примитив, который часто используется в сочетании с другими уязвимостями для повышения привилегий.

registry where host.os.type == "windows" and event.type == "change" and
registry.value : ("windir", "systemroot") and registry.data.strings != null and
registry.path : (
    "*\\Environment\\windir",
    "*\\Environment\\systemroot"
    ) and
 not registry.data.strings : ("C:\\windows", "%SystemRoot%")

## privilege_escalation_samaccountname_spoofing_attack.toml

Идентифицирует подозрительное событие переименования имени учетной записи компьютера, которое может указывать на попытку использования CVE-2021-42278 для
повышения привилегий от обычного пользователя домена до пользователя с правами администратора домена. CVE-2021-42278
- это уязвимость в системе безопасности, которая позволяет потенциальным злоумышленникам выдавать себя за контроллер домена с помощью подмены атрибута sAMAccountName.

iam where host.os.type == "windows" and event.action == "renamed-user-account" and
  /* machine account name renamed to user like account name */
  winlog.event_data.OldTargetUserName : "*$" and not winlog.event_data.NewTargetUserName : "*$"

## privilege_escalation_service_control_spawned_script_int.toml

Определяет управление службами (sc.exe), выполняемое процессами интерпретатора сценариев для создания, изменения или запуска служб.
Потенциально это может указывать на попытку повысить привилегии или сохранить постоянство.

process where host.os.type == "windows" and event.type == "start" and
  (process.name : "sc.exe" or ?process.pe.original_file_name == "sc.exe") and
  process.parent.name : ("cmd.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe",
                         "wmic.exe", "mshta.exe","powershell.exe", "pwsh.exe") and
  process.args:("config", "create", "start", "delete", "stop", "pause") and
  /* exclude SYSTEM SID - look for service creations by non-SYSTEM user */
  not user.id : "S-1-5-18"

## privilege_escalation_suspicious_dnshostname_update.toml

Определяет удаленное обновление атрибута DnsHostName учетной записи компьютера. Если новое установленное значение является допустимым
DNS-именем хоста контроллера домена, а имя компьютера-субъекта не является контроллером домена, то, скорее всего, это подготовительный
шаг к использованию CVE-2022-26923 в попытке повысить привилегии от обычного пользователя домена
до привилегий администратора домена.

iam where host.os.type == "windows" and event.action == "changed-computer-account" and
    user.id : ("S-1-5-21-*", "S-1-12-1-*") and

    winlog.event_data.DnsHostName : "??*" and

    not startswith~(winlog.event_data.DnsHostName, substring(winlog.event_data.TargetUserName, 0, length(winlog.event_data.TargetUserName) - 1))

## privilege_escalation_thread_cpu_priority_hijack.toml

Выявляет попытки использования привилегии SeIncreaseBasePriorityPrivilege необычным процессом. Это может быть связано с
перехватом потока выполнения процесса посредством манипулирования приоритетом угроз.

event.category:iam and host.os.type:"windows" and event.code:"4674" and
winlog.event_data.PrivilegeList:"SeIncreaseBasePriorityPrivilege" and event.outcome:"success" and
winlog.event_data.AccessMask:"512" and not winlog.event_data.SubjectUserSid:("S-1-5-18" or "S-1-5-19" or "S-1-5-20")

## privilege_escalation_tokenmanip_sedebugpriv_enabled.toml

Идентифицирует процесс, запущенный с внесистемной учетной записью, которая предоставляет привилегию SeDebugPrivilege. Злоумышленники могут
использовать эту привилегию для отладки и модификации других процессов, обычно зарезервированных для задач системного уровня, для повышения
привилегий и обхода контроля доступа.

any where host.os.type == "windows" and event.provider: "Microsoft-Windows-Security-Auditing" and
 event.action : "Token Right Adjusted Events" and

 winlog.event_data.EnabledPrivilegeList : "SeDebugPrivilege" and

 /* exclude processes with System Integrity  */
 not winlog.event_data.SubjectUserSid : ("S-1-5-18", "S-1-5-19", "S-1-5-20") and

 not winlog.event_data.ProcessName : (
        "?:\\Program Files (x86)\\*",
        "?:\\Program Files\\*",
        "?:\\Users\\*\\AppData\\Local\\Temp\\*-*\\DismHost.exe",
        "?:\\Windows\\System32\\auditpol.exe",
        "?:\\Windows\\System32\\cleanmgr.exe",
        "?:\\Windows\\System32\\lsass.exe",
        "?:\\Windows\\System32\\mmc.exe",
        "?:\\Windows\\System32\\MRT.exe",
        "?:\\Windows\\System32\\msiexec.exe",
        "?:\\Windows\\System32\\sdiagnhost.exe",
        "?:\\Windows\\System32\\ServerManager.exe",
        "?:\\Windows\\System32\\taskhostw.exe",
        "?:\\Windows\\System32\\wbem\\WmiPrvSe.exe",
        "?:\\Windows\\System32\\WerFault.exe",
        "?:\\Windows\\SysWOW64\\msiexec.exe",
        "?:\\Windows\\SysWOW64\\wbem\\WmiPrvSe.exe",
        "?:\\Windows\\SysWOW64\\WerFault.exe",
        "?:\\Windows\\WinSxS\\*"
    )

## privilege_escalation_uac_bypass_com_clipup.toml

Выявляет попытки обойти контроль учетных записей пользователей (UAC), используя COM-интерфейс с повышенными правами доступа для запуска вредоносной программы Windows
ClipUp. Злоумышленники могут попытаться обойти контроль учетных записей, чтобы незаметно выполнить код с повышенными правами доступа.

process where host.os.type == "windows" and event.type == "start" and process.name : "Clipup.exe" and
  not process.executable : "C:\\Windows\\System32\\ClipUp.exe" and process.parent.name : "dllhost.exe" and
  /* CLSID of the Elevated COM Interface IEditionUpgradeManager */
  process.parent.args : "/Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}"

## privilege_escalation_uac_bypass_com_ieinstal.toml

Выявляет попытки обхода контроля учетных записей пользователей (UAC) путем использования COM-интерфейса с повышенными правами доступа для запуска вредоносной
программы. Злоумышленники могут попытаться обойти контроль учетных записей, чтобы незаметно выполнить код с повышенными правами доступа.

process where host.os.type == "windows" and event.type == "start" and
 process.executable : "C:\\*\\AppData\\*\\Temp\\IDC*.tmp\\*.exe" and
 process.parent.name : "ieinstal.exe" and process.parent.args : "-Embedding"

## privilege_escalation_uac_bypass_com_interface_icmluautil.toml

Идентифицирует попытки обхода контроля учетных записей пользователей (UAC) через COM-интерфейс ICMLuaUtil с повышенными правами доступа. Злоумышленники могут попытаться
обойти контроль учетных записей, чтобы незаметно выполнить код с повышенными правами доступа.

process where host.os.type == "windows" and event.type == "start" and
 process.parent.name == "dllhost.exe" and
 process.parent.args in ("/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}", "/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}") and
 process.pe.original_file_name != "WerFault.exe"

## privilege_escalation_uac_bypass_diskcleanup_hijack.toml

Идентифицирует обход контроля учетных записей пользователей (UAC) с помощью запланированной задачи DiskCleanup. Злоумышленники обходят контроль учетных записей, чтобы
незаметно выполнить код с повышенными правами доступа.

process where host.os.type == "windows" and event.type == "start" and
 process.args : "/autoclean" and process.args : "/d" and process.executable != null and
 not process.executable : (
        "C:\\Windows\\System32\\cleanmgr.exe",
        "C:\\Windows\\SysWOW64\\cleanmgr.exe",
        "C:\\Windows\\System32\\taskhostw.exe",

        /* Crowdstrike specific exclusion as it uses NT Object paths */
        "\\Device\\HarddiskVolume*\\Windows\\System32\\cleanmgr.exe",
        "\\Device\\HarddiskVolume*\\Windows\\SysWOW64\\cleanmgr.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\taskhostw.exe"
 )

## privilege_escalation_uac_bypass_dll_sideloading.toml

Выявляет попытки обойти контроль учетных записей пользователей (UAC) с помощью сторонней загрузки библиотеки DLL. Злоумышленники могут попытаться обойти контроль учетных записей, чтобы
незаметно выполнить код с повышенными правами доступа.

file where host.os.type == "windows" and event.type : "change" and process.name : "dllhost.exe" and
  /* Known modules names side loaded into process running with high or system integrity level for UAC Bypass, update here for new modules */
  file.name : ("wow64log.dll", "comctl32.dll", "DismCore.dll", "OskSupport.dll", "duser.dll", "Accessibility.ni.dll") and
  /* has no impact on rule logic just to avoid OS install related FPs */
  not file.path : ("C:\\Windows\\SoftwareDistribution\\*", "C:\\Windows\\WinSxS\\*")

## privilege_escalation_uac_bypass_event_viewer.toml

Идентифицирует обход контроля учетных записей пользователей (UAC) с помощью eventvwr.exe. Злоумышленники обходят контроль учетных записей, чтобы незаметно выполнить код с
повышенными правами доступа.

process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "eventvwr.exe" and
  not process.executable : (
        "?:\\Windows\\SysWOW64\\mmc.exe",
        "?:\\Windows\\System32\\mmc.exe",
        "?:\\Windows\\SysWOW64\\WerFault.exe",
        "?:\\Windows\\System32\\WerFault.exe",

        /* Crowdstrike specific exclusion as it uses NT Object paths */
        "\\Device\\HarddiskVolume*\\Windows\\Sys?????\\mmc.exe",
        "\\Device\\HarddiskVolume*\\Windows\\Sys?????\\WerFault.exe"
  )

## privilege_escalation_uac_bypass_mock_windir.toml

Идентифицирует попытку обойти контроль учетных записей пользователей (UAC), маскируясь под доверенный каталог Microsoft Windows.
Злоумышленники могут обойти контроль учетных записей, чтобы незаметно выполнить код с повышенными правами доступа.

process where host.os.type == "windows" and event.type == "start" and
  process.args : ("C:\\Windows \\system32\\*.exe", "C:\\Windows \\SysWOW64\\*.exe")

## privilege_escalation_uac_bypass_winfw_mmc_hijack.toml

Выявляет попытки обойти систему контроля учетных записей пользователей (UAC) путем взлома консоли управления Microsoft (MMC) Windows
Оснастка брандмауэра. Злоумышленники обходят систему контроля учетных записей пользователей (UAC), чтобы незаметно выполнить код с повышенными правами доступа.

process where host.os.type == "windows" and event.type == "start" and
 process.parent.name == "mmc.exe" and
 /* process.Ext.token.integrity_level_name == "high" can be added in future for tuning */
 /* args of the Windows Firewall SnapIn */
  process.parent.args == "WF.msc" and process.name != "WerFault.exe"

## privilege_escalation_unquoted_service_path.toml

Злоумышленники могут использовать уязвимости в сервисных путях без кавычек для повышения привилегий. Помещая исполняемый файл в каталог более
высокого уровня в пределах пути к служебному исполняемому файлу без кавычек, Windows автоматически запускает этот исполняемый
файл из определенной переменной path, а не из незащищенного файла в более глубоком каталоге, что приводит к выполнению кода.

process where host.os.type == "windows" and event.type == "start" and
  (
    process.executable : "?:\\Program.exe" or
    process.executable regex """(C:\\Program Files \(x86\)\\|C:\\Program Files\\)\w+.exe"""
  )

## privilege_escalation_unusual_parentchild_relationship.toml

Определяет программы Windows, запущенные из неожиданных родительских процессов. Это может указывать на маскировку или другую странную
активность в системе.

process where host.os.type == "windows" and event.type == "start" and
process.parent.name != null and
 (
   /* suspicious parent processes */
   (process.name:"autochk.exe" and not process.parent.name:"smss.exe") or
   (process.name:("fontdrvhost.exe", "dwm.exe") and not process.parent.name:("wininit.exe", "winlogon.exe", "dwm.exe")) or
   (process.name:("consent.exe", "RuntimeBroker.exe", "TiWorker.exe") and not process.parent.name:("svchost.exe", "Workplace Container Helper.exe")) or
   (process.name:"SearchIndexer.exe" and not process.parent.name:"services.exe") or
   (process.name:"SearchProtocolHost.exe" and not process.parent.name:("SearchIndexer.exe", "dllhost.exe")) or
   (process.name:"dllhost.exe" and not process.parent.name:("services.exe", "svchost.exe")) or
   (process.name:"smss.exe" and not process.parent.name:("System", "smss.exe")) or
   (process.name:"csrss.exe" and not process.parent.name:("smss.exe", "svchost.exe")) or
   (process.name:"wininit.exe" and not process.parent.name:"smss.exe") or
   (process.name:"winlogon.exe" and not process.parent.name:"smss.exe") or
   (process.name:("lsass.exe", "LsaIso.exe") and not process.parent.name:"wininit.exe") or
   (process.name:"LogonUI.exe" and not process.parent.name:("wininit.exe", "winlogon.exe")) or
   (process.name:"services.exe" and not process.parent.name:"wininit.exe") or
   (process.name:"svchost.exe" and not process.parent.name:("MsMpEng.exe", "services.exe", "svchost.exe")) or
   (process.name:"spoolsv.exe" and not process.parent.name:("services.exe", "Workplace Starter.exe")) or
   (process.name:"taskhost.exe" and not process.parent.name:("services.exe", "svchost.exe", "ngentask.exe")) or
   (process.name:"taskhostw.exe" and not process.parent.name:("services.exe", "svchost.exe")) or
   (process.name:"userinit.exe" and not process.parent.name:("dwm.exe", "winlogon.exe", "KUsrInit.exe")) or
   (process.name:("wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe") and not process.parent.name:"svchost.exe") or
   /* suspicious child processes */
   (process.parent.name:("SearchProtocolHost.exe", "taskhost.exe", "csrss.exe") and not process.name:("werfault.exe", "wermgr.exe", "WerFaultSecure.exe", "conhost.exe", "ngentask.exe")) or
   (process.parent.name:"autochk.exe" and not process.name:("chkdsk.exe", "doskey.exe", "WerFault.exe")) or
   (process.parent.name:"smss.exe" and not process.name:("autochk.exe", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "setupcl.exe", "WerFault.exe", "wpbbin.exe", "PvsVmBoot.exe", "SophosNA.exe", "omnissa-ic-nga.exe", "icarus_rvrt.exe", "poqexec.exe")) or
   (process.parent.name:"wermgr.exe" and not process.name:("WerFaultSecure.exe", "wermgr.exe", "WerFault.exe")) or
   (process.parent.name:"conhost.exe" and not process.name:("mscorsvw.exe", "wermgr.exe", "WerFault.exe", "WerFaultSecure.exe"))
  )

## privilege_escalation_unusual_printspooler_childprocess.toml

Обнаруживает необычные дочерние процессы службы очереди печати (spoolsv.exe). Это может указывать на попытку
использования уязвимостей с повышением привилегий, связанных со службой печати в Windows.

process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "spoolsv.exe" and process.command_line != null and
 (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System") and

 not process.name : ("splwow64.exe", "PDFCreator.exe", "acrodist.exe", "spoolsv.exe", "msiexec.exe", "route.exe", "WerFault.exe") and
 not process.command_line : "*\\WINDOWS\\system32\\spool\\DRIVERS*" and
 not (process.name : "net.exe" and process.command_line : ("*stop*", "*start*")) and
 not (process.name : ("cmd.exe", "powershell.exe") and process.command_line : ("*.spl*", "*\\program files*", "*route add*")) and
 not (process.name : "netsh.exe" and process.command_line : ("*add portopening*", "*rule name*")) and
 not (process.name : "regsvr32.exe" and process.command_line : "*PrintConfig.dll*") and
 not process.executable : (
    "?:\\Program Files (x86)\\CutePDF Writer\\CPWriter2.exe",
    "?:\\Program Files (x86)\\GPLGS\\gswin32c.exe",
    "?:\\Program Files (x86)\\Acro Software\\CutePDF Writer\\CPWSave.exe",
    "?:\\Program Files (x86)\\Acro Software\\CutePDF Writer\\CPWriter2.exe",
    "?:\\Program Files (x86)\\CutePDF Writer\\CPWSave.exe",
    "?:\\Program Files (x86)\\TSplus\\UniversalPrinter\\CPWriter2.exe",
    "?:\\Program Files\\Seagull\\Printer Drivers\\Packages\\*\\DriverEnvironmentSetup.exe",
    "?:\\Windows\\system32\\CNAB4RPD.EXE",

    "\\Device\\HarddiskVolume*\\Program Files (x86)\\CutePDF Writer\\CPWriter2.exe",
    "\\Device\\HarddiskVolume*\\Program Files (x86)\\GPLGS\\gswin32c.exe",
    "\\Device\\HarddiskVolume*\\Program Files (x86)\\Acro Software\\CutePDF Writer\\CPWSave.exe",
    "\\Device\\HarddiskVolume*\\Program Files (x86)\\Acro Software\\CutePDF Writer\\CPWriter2.exe",
    "\\Device\\HarddiskVolume*\\Program Files (x86)\\CutePDF Writer\\CPWSave.exe",
    "\\Device\\HarddiskVolume*\\Program Files (x86)\\TSplus\\UniversalPrinter\\CPWriter2.exe",
    "\\Device\\HarddiskVolume*\\Program Files\\Seagull\\Printer Drivers\\Packages\\*\\DriverEnvironmentSetup.exe",
    "\\Device\\HarddiskVolume*\\Windows\\system32\\CNAB4RPD.EXE"
 )

## privilege_escalation_unusual_svchost_childproc_childless.toml

Определяет необычные дочерние процессы узла службы (svchost.exe), которые обычно не порождают дочерних процессов.
Это может указывать на внедрение кода или эквивалентную форму использования.

process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "svchost.exe" and

  /* based on svchost service arguments -s svcname where the service is known to be childless */
  process.parent.args : (
    "WdiSystemHost", "LicenseManager", "StorSvc", "CDPSvc", "cdbhsvc", "BthAvctpSvc", "SstpSvc", "WdiServiceHost",
    "imgsvc", "TrkWks", "WpnService", "IKEEXT", "PolicyAgent", "CryptSvc", "netprofm", "ProfSvc", "StateRepository",
    "camsvc", "LanmanWorkstation", "NlaSvc", "EventLog", "hidserv", "DisplayEnhancementService", "ShellHWDetection",
    "AppHostSvc", "fhsvc", "CscService", "PushToInstall"
  ) and

  /* unknown FPs can be added here */
  not process.name : ("WerFault.exe", "WerFaultSecure.exe", "wermgr.exe") and
  not (process.executable : "?:\\Windows\\System32\\RelPost.exe" and process.parent.args : "WdiSystemHost") and
  not (
    process.name : "rundll32.exe" and
    process.args : "?:\\WINDOWS\\System32\\winethc.dll,ForceProxyDetectionOnNextRun" and
    process.parent.args : "WdiServiceHost"
  ) and
  not (
    process.executable : (
      "?:\\Program Files\\*",
      "?:\\Program Files (x86)\\*",
      "?:\\Windows\\System32\\Kodak\\kds_?????\\lib\\lexexe.exe"
    ) and process.parent.args : "imgsvc"
  )

## privilege_escalation_via_ppid_spoofing.toml

Идентифицирует подмену родительского процесса, используемую для создания дочернего процесса с повышенными правами. Злоумышленники могут подделать идентификатор родительского процесса
(PPID) нового процесса, чтобы обойти средства защиты от мониторинга процессов или повысить привилегии.

 not process.executable : ("?:\\Windows\\System32\\WerFault.exe",
                           "?:\\Windows\\SysWOW64\\WerFault.exe",
                           "?:\\Windows\\System32\\WerFaultSecure.exe",
                           "?:\\Windows\\SysWOW64\\WerFaultSecure.exe",
                           "?:\\Windows\\System32\\Wermgr.exe",
                           "?:\\Windows\\SysWOW64\\Wermgr.exe",
                           "?:\\Windows\\SoftwareDistribution\\Download\\Install\\securityhealthsetup.exe") and

 not (process.parent.executable : "?:\\Windows\\System32\\Utilman.exe" and
     process.executable : ("?:\\Windows\\System32\\osk.exe",
                           "?:\\Windows\\System32\\Narrator.exe",
                           "?:\\Windows\\System32\\Magnify.exe",
                           "?:\\Windows\\System32\\VoiceAccess.exe")) and

 not process.parent.executable : "?:\\Windows\\System32\\AtBroker.exe" and

 not (process.code_signature.subject_name in
           ("philandro Software GmbH", "Freedom Scientific Inc.", "TeamViewer Germany GmbH", "Projector.is, Inc.",
            "TeamViewer GmbH", "Cisco WebEx LLC", "Dell Inc") and process.code_signature.trusted == true) and

 not (process.executable : ("?:\\Windows\\System32\\MpSigStub.exe", "?:\\Windows\\SysWOW64\\MpSigStub.exe") and
      process.parent.executable : ("?:\\Windows\\System32\\wuauclt.exe",
                                   "?:\\Windows\\SysWOW64\\wuauclt.exe",
                                   "?:\\Windows\\UUS\\Packages\\Preview\\*\\wuaucltcore.exe",
                                   "?:\\Windows\\UUS\\amd64\\wuauclt.exe",
                                   "?:\\Windows\\UUS\\amd64\\wuaucltcore.exe",
                                   "?:\\ProgramData\\Microsoft\\Windows\\UUS\\*\\wuaucltcore.exe")) and
 not (process.executable : ("?:\\Windows\\System32\\MpSigStub.exe", "?:\\Windows\\SysWOW64\\MpSigStub.exe") and process.parent.executable == null) and

 not process.parent.executable :
                   ("?:\\Program Files (x86)\\HEAT Software\\HEAT Remote\\HEATRemoteServer.exe",
                    "?:\\Program Files (x86)\\VisualCron\\VisualCronService.exe",
                    "?:\\Program Files\\BinaryDefense\\Vision\\Agent\\bds-vision-agent-app.exe",
                    "?:\\Program Files\\Tablet\\Wacom\\WacomHost.exe",
                    "?:\\Program Files (x86)\\LogMeIn\\x64\\LogMeIn.exe",
                    "?:\\Program Files (x86)\\EMC Captiva\\Captiva Cloud Runtime\\Emc.Captiva.WebCaptureRunner.exe",
                    "?:\\Program Files\\Freedom Scientific\\*.exe",
                    "?:\\Program Files (x86)\\Google\\Chrome Remote Desktop\\*\\remoting_host.exe",
                    "?:\\Program Files (x86)\\GoToAssist Remote Support Customer\\*\\g2ax_comm_customer.exe") and
 not (
    process.code_signature.trusted == true and process.code_signature.subject_name == "Netwrix Corporation" and
    process.name : "adcrcpy.exe" and process.parent.executable : (
      "?:\\Program Files (x86)\\Netwrix Auditor\\Active Directory Auditing\\Netwrix.ADA.EventCollector.exe",
      "?:\\Program Files (x86)\\Netwrix Auditor\\Active Directory Auditing\\Netwrix.ADA.Analyzer.exe",
      "?:\\Netwrix Auditor\\Active Directory Auditing\\Netwrix.ADA.EventCollector.exe"
    )
 )

## privilege_escalation_via_rogue_named_pipe.toml

Идентифицирует попытку повышения привилегий с помощью несанкционированного олицетворения именованного канала. Злоумышленник может злоупотреблять этим методом,
маскируясь под известный именованный канал и манипулируя привилегированным процессом для подключения к нему.

file where host.os.type == "windows" and
  event.provider == "Microsoft-Windows-Sysmon" and
  
  event.code == "17" and
  
  file.name : "\\*\\Pipe\\*"

## privilege_escalation_via_token_theft.toml

Идентифицирует создание процесса, работающего от имени SYSTEM и выдающего себя за Windows core с двоичными привилегиями. Злоумышленники
могут создать новый процесс с другим токеном для повышения привилегий и обхода контроля доступа.

 process.Ext.effective_parent.executable :
                ("?:\\Windows\\*.exe",
                 "?:\\Program Files\\*.exe",
                 "?:\\Program Files (x86)\\*.exe",
                 "?:\\ProgramData\\*") and

 not (process.Ext.effective_parent.executable : "?:\\Windows\\System32\\Utilman.exe" and
      process.parent.executable : "?:\\Windows\\System32\\Utilman.exe" and process.parent.args : "/debug") and

not (process.parent.executable : "?\\Windows\\System32\\spoolsv.exe" and
     process.executable: "?:\\Program Files*\\Access\\Intelligent Form\\*\\LaunchCreate.exe") and

 not process.executable : ("?:\\Windows\\System32\\WerFault.exe",
                           "?:\\Windows\\SysWOW64\\WerFault.exe",
                           "?:\\Windows\\System32\\WerFaultSecure.exe",
                           "?:\\Windows\\SysWOW64\\WerFaultSecure.exe",
                           "?:\\windows\\system32\\WerMgr.exe",
                           "?:\\Windows\\SoftwareDistribution\\Download\\Install\\securityhealthsetup.exe")  and

 not (process.parent.executable : "?:\\Windows\\WinSxS\\*\\TiWorker.exe" and
      process.executable : ("?:\\Windows\\Microsoft.NET\\Framework*.exe",
                            "?:\\Windows\\WinSxS\\*.exe",
                            "?:\\Windows\\System32\\inetsrv\\iissetup.exe",
                            "?:\\Windows\\SysWOW64\\inetsrv\\iissetup.exe",
                            "?:\\Windows\\System32\\inetsrv\\aspnetca.exe",
                            "?:\\Windows\\SysWOW64\\inetsrv\\aspnetca.exe",
                            "?:\\Windows\\System32\\lodctr.exe",
                            "?:\\Windows\\SysWOW64\\lodctr.exe",
                            "?:\\Windows\\System32\\netcfg.exe",
                            "?:\\Windows\\Microsoft.NET\\Framework*\\*\\ngen.exe",
                            "?:\\Windows\\Microsoft.NET\\Framework*\\*\\aspnet_regiis.exe")) and

 not process.parent.executable :
               ("?:\\Windows\\System32\\AtBroker.exe",
                "?:\\Windows\\system32\\svchost.exe",
                "?:\\Program Files (x86)\\*.exe",
                "?:\\Program Files\\*.exe",
                "?:\\Windows\\System32\\msiexec.exe",
                "?:\\Windows\\System32\\DriverStore\\*") and

 not (process.code_signature.trusted == true and
      process.code_signature.subject_name :
                ("philandro Software GmbH",
                 "Freedom Scientific Inc.",
                 "TeamViewer Germany GmbH",
                 "Projector.is, Inc.",
                 "TeamViewer GmbH",
                 "Cisco WebEx LLC",
                 "Dell Inc"))

## privilege_escalation_windows_service_via_unusual_client.toml

Идентифицирует создание службы Windows с помощью необычного клиентского процесса. Службы могут создаваться с правами администратора
, но запускаться с правами СИСТЕМЫ, поэтому злоумышленник может также использовать службу для повышения привилегий от
администратора к СИСТЕМЕ.

configuration where host.os.type == "windows" and
  event.action == "service-installed" and
  (winlog.event_data.ClientProcessId == "0" or winlog.event_data.ParentProcessId == "0") and
  startswith~(user.domain, winlog.computer_name) and winlog.event_data.ServiceAccount == "LocalSystem" and 
  not winlog.event_data.ServiceFileName : (
    "?:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe",
    "?:\\Windows\\VeeamLogShipper\\VeeamLogShipper.exe",
    "%SystemRoot%\\system32\\Drivers\\Crowdstrike\\*-CsInstallerService.exe",
    "\"%windir%\\AdminArsenal\\PDQInventory-Scanner\\service-1\\PDQInventory-Scanner-1.exe\" ",
    "\"%windir%\\AdminArsenal\\PDQDeployRunner\\service-1\\PDQDeployRunner-1.exe\" ",
    "\"%windir%\\AdminArsenal\\PDQInventoryWakeCommand\\service-1\\PDQInventoryWakeCommand-1.exe\" ",
    "\"%SystemRoot%\\nsnetpush.exe\"",
    "\"C:\\WINDOWS\\ccmsetup\\ccmsetup.exe\" /runservice /ignoreskipupgrade /config:MobileClient.tcf",
    "\"?:\\SMS\\bin\\x64\\srvboot.exe\"",
    "%SystemRoot%\\pbpsdeploy.exe")
