# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Backdoor_Goldbackdoor.yar
##  Windows_Backdoor_Goldbackdoor.yar
``` strings:
        $pdf = "D:\\Development\\GOLD-BACKDOOR\\"
        $agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.3112.113 Safari/537.36"
        $str0 = "client_id"
        $str1 = "client_secret"
        $str2 = "redirect_uri"
        $str3 = "refresh_token"
        $a = { 56 57 8B 7D 08 8B F1 6A 00 6A 00 6A 00 6A 00 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 46 30 85 C0 75 ?? 33 C0 5F 5E }
        $b = { 66 8B 02 83 C2 02 66 85 C0 75 ?? 2B D1 D1 FA 75 ?? 33 C0 E9 ?? ?? ?? ?? 6A 40 8D 45 ?? 6A 00 50 E8 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Clickfraud_LuckySlots.yar
##  Windows_Clickfraud_LuckySlots.yar
``` strings:
        $a1 = "lwxatisme" ascii fullword
        $a2 = "/{flag}/" ascii fullword
        $a3 = "\"KEYWORDS\"" ascii fullword
        $a4 = "WebKitFormBoundaryBHNkQBGxcQrf7zY1" ascii fullword
        $a5 = "baidu|sogou|360|yisou|bing|google|coccoc|byte" ascii fullword
        $a6 = "Video|xoso|dabong|nohu|bet|app|games|ios|Casino" ascii fullword
        $a7 = "baidu.com|so.com|sogou.com|sm.cn|bing.com|google|coccoc|toutiao" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Cryptominer_Generic.yar
## Windows_Cryptominer_Generic
``` strings:
        $a = { EF F9 66 0F EF FA 66 0F FE FE 66 0F 6F B0 B0 00 00 00 66 0F }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_ChromeKatz.yar
## Windows_Hacktool_ChromeKatz
``` strings:
        $s1 = "CookieKatz.exe"
        $s2 = "Targeting Chrome"
        $s3 = "Targeting Msedgewebview2"
        $s4 = "Failed to find the first pattern"
        $s5 = "WalkCookieMap"
        $s6 = "Found CookieMonster on 0x%p"
        $s7 = "Cookie Key:"
        $s8 = "Failed to read cookie value" wide
        $s9 = "Failed to read cookie struct" wide
        $s10 = "Error reading left node"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_CpuLocker.yar
## Windows_Hacktool_CpuLocker
``` strings:
        $str1 = "\\CPULocker.pdb"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharPersist.yar
## Windows_Hacktool_SharPersist
```    strings:
        $guid = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" ascii wide nocase
        $print_str0 = "schtaskbackdoor: backdoor scheduled task" ascii wide
        $print_str1 = "schtaskbackdoor -m list -n <schtask name>" ascii wide
        $print_str2 = "SharPersist" ascii wide
        $print_str3 = "[+] SUCCESS: Keepass persistence backdoor added" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpDump.yar
## Windows_Hacktool_SharpDump
```  strings:
        $guid = "9c9bba3-a0ea-431c-866c-77004802d" ascii wide nocase
        $print_str0 = "Please use \"SharpDump.exe [pid]\" format" ascii wide
        $print_str1 = "[*] Use \"sekurlsa::minidump debug.out\" \"sekurlsa::logonPasswords full\" on the same OS/arch" ascii wide
        $print_str2 = "[+] Dumping completed. Rename file to \"debug{0}.gz\" to decompress" ascii wide
        $print_str3 = "[X] Not in high integrity, unable to MiniDump!" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpGPOAbuse.yar
## Windows_Hacktool_SharpGPOAbuse
``` strings:
        $name = "SharpGPOAbuse" wide fullword
        $s1 = "AddUserTask" wide fullword
        $s2 = "AddComputerTask" wide fullword
        $s3 = "AddComputerScript" wide fullword
        $s4 = "AddUserScript" wide fullword
        $s5 = "GPOName" wide fullword
        $s6 = "ScheduledTasks" wide fullword
        $s7 = "NewImmediateTask" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Infostealer_Generic.yar
## Windows_Infostealer_Generic
``` strings:
        $str1 = "ChromeFuckNewCookies" ascii fullword
        $str2 = "/c timeout /t 10 & del /f /q \"" ascii fullword
        $str3 = "56574883EC2889D74889CEE8AAAAFFFF85FF74084889F1E8AAAAAAAA4889F04883C4285F5EC3CCCCCCCCCCCCCCCCCCCC56574883ECAA"
        $seq1 = { 81 FA 6B 03 EE 4C 74 ?? 81 FA 77 03 EE 4C 74 ?? 81 FA 80 68 55 FB 74 ?? 81 FA 92 68 55 FB }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Infostealer_NovaBlight.yar
## Windows_Infostealer_NovaBlight
```  strings:
        $a1 = "C:\\Users\\Administrateur\\Desktop\\Nova\\"
        $a2 = "[+] Recording..." fullword
        $a3 = "[+] Capture start" fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Azov.yar
## Windows_Ransomware_Azov
``` strings:
        $a = { 48 83 EC 20 40 80 E4 F0 C6 45 F3 56 C6 45 F4 69 C6 45 F5 72 C6 45 F6 74 C6 45 F7 75 C6 45 F8 61 C6 45 F9 6C C6 45 FA 41 C6 45 FB 6C C6 45 FC 6C C6 45 FD 6F C6 45 FE 63 C6 45 FF 00 }
        $b = "Local\\Kasimir_%c" wide fullword
        $s1 = "\\User Data\\Default\\Cache\\" wide fullword
        $s2 = "\\Low\\Content.IE5\\" wide fullword
        $s3 = "\\cache2\\entries" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Bitpaymer.yar
## Windows_Ransomware_Bitpaymer
``` strings:
        $a1 = "RWKGGE.PDB" fullword
        $a2 = "*Qf69@+mESRA.RY7*+6XEF#NH.pdb" fullword
        $a3 = "04QuURX.pdb" fullword
        $a4 = "9nuhuNN.PDB" fullword
        $a5 = "mHtXGC.PDB" fullword
        $a6 = "S:\\Work\\_bin\\Release-Win32\\wp_encrypt_new.pdb" fullword
        $a7 = "C:\\Work\\_bin\\Release-Win32\\wp_encrypt.pdb" fullword
        $a8 = "k:\\softcare\\release\\h2O.pdb" fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Shellcode_Generic.yar
## Windows_Shellcode_Generic
``` strings:
        $a = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Shellcode_Rdi.yar
## Windows_Shellcode_Rdi
``` strings:
        $a = { E8 00 00 00 00 59 49 89 C8 48 81 C1 23 0B 00 00 BA [10] 00 41 B9 04 00 00 00 56 48 89 E6 48 83 E4 F0 48 83 EC 30 C7 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_A310logger.yar
## Windows_Trojan_A310logger
``` strings:
        $a1 = "/dumps9taw" ascii fullword
        $a2 = "/logstatus" ascii fullword
        $a3 = "/checkprotection" ascii fullword
        $a4 = "[CLIPBOARD]<<" wide fullword
        $a5 = "&chat_id=" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_ACRStealer.yar
## Windows_Trojan_ACRStealer
``` strings:
        $a1 = { 55 8B EC 51 0F B6 45 ?? 83 F8 30 7C ?? 0F B6 4D ?? 83 F9 39 7E ?? 0F B6 55 ?? 83 FA 41 7C ?? 0F B6 45 ?? 83 F8 5A 7E ?? 0F B6 4D ?? 83 F9 61 7C ?? 0F B6 55 ?? 83 FA 7A 7E ?? 0F B6 45 ?? 83 F8 2B 74 ?? 0F B6 4D ?? 83 F9 2F 74 ?? C7 45 ?? ?? ?? ?? ?? EB ?? C7 45 }
        $a2 = "Error: no GetSystemMetrics" ascii fullword
        $a3 = "Error: no user32.dll" ascii fullword
        $a4 = { 8B ?? 24 C7 ?? ?? ?? ?? ?? 8B ?? F8 5? E8 ?? ?? ?? ?? 83 C4 04 8B ?? FC 5? FF 15 ?? ?? ?? ?? 33 C0 E9 }
        $a5 = { B8 ?? ?? ?? ?? EB ?? EB ?? B8 ?? ?? ?? ?? EB ?? 83 7D ?? 06 75 ?? 83 7D ?? 03 75 ?? B8 ?? ?? ?? ?? EB ?? 83 7D ?? 02 75 ?? B8 ?? ?? ?? ?? EB ?? 83 7D ?? 01 75 ?? B8 ?? ?? ?? ?? EB ?? 83 7D ?? 00 75 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Afdk.yar
## Windows_Trojan_Afdk
``` strings:
        $a = { 55 8B EC 51 51 83 65 F8 00 8D 45 F8 83 65 FC 00 50 E8 80 FF FF FF 59 85 C0 75 2B 8B 4D 08 8B 55 F8 8B 45 FC 89 41 04 8D 45 F8 89 11 83 CA 1F 50 89 55 F8 E8 7B FF FF FF 59 85 C0 75 09 E8 DA 98 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_AgentTesla.yar
## Windows_Trojan_AgentTesla
``` strings:
        $a1 = "GetMozillaFromLogins" ascii fullword
        $a2 = "AccountConfiguration+username" wide fullword
        $a3 = "MailAccountConfiguration" ascii fullword
        $a4 = "KillTorProcess" ascii fullword
        $a5 = "SmtpAccountConfiguration" ascii fullword
        $a6 = "GetMozillaFromSQLite" ascii fullword
        $a7 = "Proxy-Agent: HToS5x" wide fullword
        $a8 = "set_BindingAccountConfiguration" ascii fullword
        $a9 = "doUsernamePasswordAuth" ascii fullword
        $a10 = "SafariDecryptor" ascii fullword
        $a11 = "get_securityProfile" ascii fullword
        $a12 = "get_useSeparateFolderTree" ascii fullword
        $a13 = "get_DnsResolver" ascii fullword
        $a14 = "get_archivingScope" ascii fullword
        $a15 = "get_providerName" ascii fullword
        $a16 = "get_ClipboardHook" ascii fullword
        $a17 = "get_priority" ascii fullword
        $a18 = "get_advancedParameters" ascii fullword
        $a19 = "get_disabledByRestriction" ascii fullword
        $a20 = "get_LastAccessed" ascii fullword
        $a21 = "get_avatarType" ascii fullword
        $a22 = "get_signaturePresets" ascii fullword
        $a23 = "get_enableLog" ascii fullword
        $a24 = "TelegramLog" ascii fullword
        $a25 = "generateKeyV75" ascii fullword
        $a26 = "set_accountName" ascii fullword
        $a27 = "set_InternalServerPort" ascii fullword
        $a28 = "set_bindingConfigurationUID" ascii fullword
        $a29 = "set_IdnAddress" ascii fullword
        $a30 = "set_GuidMasterKey" ascii fullword
        $a31 = "set_username" ascii fullword
        $a32 = "set_version" ascii fullword
        $a33 = "get_Clipboard" ascii fullword
        $a34 = "get_Keyboard" ascii fullword
        $a35 = "get_ShiftKeyDown" ascii fullword
        $a36 = "get_AltKeyDown" ascii fullword
        $a37 = "get_Password" ascii fullword
        $a38 = "get_PasswordHash" ascii fullword
        $a39 = "get_DefaultCredentials" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Amadey.yar
## Windows_Trojan_Amadey
```  strings:
        $a = { 18 83 78 14 10 72 02 8B 00 6A 01 6A 00 6A 00 6A 00 6A 00 56 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Arechclient2.yar
## Windows_Trojan_Arechclient2
``` strings:
        $a = { 65 73 00 53 63 61 6E 6E 65 64 57 61 6C 6C 65 74 73 00 4E 6F 72 64 41 63 63 6F 75 6E 74 73 00 4F 70 65 6E 00 50 72 6F 74 6F 6E 00 4D 65 73 73 61 }
        $b = { 73 65 74 5F 53 63 61 6E 56 50 4E 00 67 65 74 5F 53 63 61 6E 53 74 65 61 6D 00 73 65 74 5F 53 63 61 6E 53 74 65 61 6D 00 67 65 74 5F 53 63 61 6E }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Clipbanker.yar
## Windows_Trojan_Clipbanker
``` strings:
        $a1 = "C:\\Users\\youar\\Desktop\\Allcome\\Source code\\Build\\Release\\Build.pdb" ascii fullword
        $b1 = "https://steamcommunity.com/tradeoffer" ascii fullword
        $b2 = "/Create /tn NvTmRep_CrashReport3_{B2FE1952-0186} /sc MINUTE /tr %s" ascii fullword
        $b3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0" ascii fullword
        $b4 = "ProcessHacker.exe" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Danabot.yar
## Windows_Trojan_Danabot
```  strings:
        $a1 = "%s.dll" ascii fullword
        $a2 = "del_ini://Main|Password|" wide fullword
        $a3 = "S-Password.txt" wide fullword
        $a4 = "BiosTime:" wide fullword
        $a5 = "%lu:%s:%s:%d:%s" ascii fullword
        $a6 = "DNS:%s" ascii fullword
        $a7 = "THttpInject&" ascii fullword
        $a8 = "TCookies&" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DarkCloud.yar
## Windows_Trojan_DarkCloud
```  strings:
        $a1 = { 8D 45 DC 57 57 6A 01 6A 11 50 6A 01 68 80 00 00 00 89 7D E8 89 }
        $a2 = { C8 33 FF 50 57 FF D6 8D 4D DC 51 57 FF D6 C3 8B 4D F0 8B 45 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DarkGate.yar
## Windows_Trojan_DarkGate
```  strings:
        $str0 = "DarkGate has recovered from a Critical error"
        $str1 = "Executing DarkGate inside the new desktop..."
        $str2 = "Restart Darkgate "
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DarkVNC.yar
## /Windows_Trojan_DarkVNC.yar
``` strings:
        $a1 = "BOT-%s(%s)_%S-%S%u%u" wide fullword
        $a2 = "{%08X-%04X-%04X-%04X-%08X%04X}" wide fullword
        $a3 = "monitor_off / monitor_on" ascii fullword
        $a4 = "bot_shell >" ascii fullword
        $a5 = "keyboard and mouse are blocked !" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Darkcomet.yar
## Windows_Trojan_Darkcomet
```  strings:
        $a1 = "BTRESULTHTTP Flood|Http Flood task finished!|" ascii fullword
        $a2 = "is now open!|" ascii fullword
        $a3 = "ActiveOnlineKeylogger" ascii fullword
        $a4 = "#BOT#RunPrompt" ascii fullword
        $a5 = "GETMONITORS" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Deimos.yar
## Windows_Trojan_Deimos
``` strings:
        $a1 = "\\APPDATA\\ROAMING" wide fullword
        $a2 = "{\"action\":\"ping\",\"" wide fullword
        $a3 = "Deimos" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_PowerSeal.yar
## Windows_Trojan_PowerSeal
```  strings:
        $a1 = "PowerSeal.dll" wide fullword
        $a2 = "InvokePs" ascii fullword
        $a3 = "amsiInitFailed" wide fullword
        $a4 = "is64BitOperatingSystem" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Qbot.yar
## Windows_Trojan_Qbot
``` strings:
        $a = { FE 8A 14 06 88 50 FF 8A 54 BC 11 88 10 8A 54 BC 10 88 50 01 47 83 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Quasarrat.yar
## Windows_Trojan_Quasarrat
``` strings:
        $a1 = "GetKeyloggerLogsResponse" ascii fullword
        $a2 = "DoDownloadAndExecute" ascii fullword
        $a3 = "http://api.ipify.org/" wide fullword
        $a4 = "Domain: {1}{0}Cookie Name: {2}{0}Value: {3}{0}Path: {4}{0}Expired: {5}{0}HttpOnly: {6}{0}Secure: {7}" wide fullword
        $a5 = "\" /sc ONLOGON /tr \"" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_STRRAT.yar
## Windows_Trojan_STRRAT
```  strings:
        $str1 = "strigoi/server/ping.php?lid="
        $str2 = "/strigoi/server/?hwid="
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_ServHelper.yar
## Windows_Trojan_ServHelper
```  strings:
        $a = { 48 8B 45 78 48 63 4D 44 48 8B 55 48 4C 63 45 44 48 0F B7 44 48 FE 66 42 33 44 42 FE 66 89 45 42 48 8D 4D 28 48 0F B7 55 42 E8 ?? ?? ?? ?? 48 8B 4D 70 48 8B 55 28 E8 ?? ?? ?? ?? 83 45 44 01 83 EB 01 85 DB 75 ?? }
        $b = { 39 5D ?? 0F 8F ?? ?? ?? ?? 2B D8 83 C3 01 48 8B 45 ?? 48 63 4D ?? 66 83 7C 48 ?? 20 72 ?? 48 8B 45 ?? 48 63 4D ?? 66 83 7C 48 ?? 7F 76 ?? 48 8B 45 ?? 48 63 4D ?? 48 0F B7 44 48 ?? 66 83 E8 08 66 83 F8 07 77 ?? B2 01 8B C8 80 E1 7F D3 E2 48 0F B6 05 ?? ?? ?? ?? 84 C2 0F 95 C0 EB ?? 33 C0 84 C0 74 ?? 83 45 ?? 01 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_ShelbyC2.yar
## Windows_Trojan_ShelbyC2
``` strings:
        $a0 = "File Uploaded Successfully" fullword
        $a1 = "/dlextract" fullword
        $a2 = "/evoke" fullword
        $a4 = { 22 73 68 61 22 3A 20 22 2E 2B 3F 22 }
        $a5 = { 22 2C 22 73 68 61 22 3A 22 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_WikiLoader.yar
## Windows_Trojan_WikiLoader
``` strings:
        $a = { 48 81 EC 08 01 00 00 48 89 CB 48 31 C0 48 89 E9 48 29 E1 48 89 E7 F3 AA 48 89 D9 48 89 4D 80 48 89 95 78 FF FF FF 4C 89 45 C0 4C 89 4D 88 4D 89 D4 4D 89 DD 4C 89 65 C8 49 83 ED 10 4C 89 6D 98 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_XWorm.yar
## Windows_Trojan_XWorm
```  strings:
        $str1 = "startsp" ascii wide fullword
        $str2 = "injRun" ascii wide fullword
        $str3 = "getinfo" ascii wide fullword
        $str4 = "Xinfo" ascii wide fullword
        $str5 = "openhide" ascii wide fullword
        $str6 = "WScript.Shell" ascii wide fullword
        $str7 = "hidefolderfile" ascii wide fullword
``` 
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Virus_Expiro.yar
## Windows_Virus_Expiro
``` strings:
        $a1 = { 50 51 52 53 55 56 57 E8 00 00 00 00 5B 81 EB ?? ?? ?? 00 BA 00 00 00 00 53 81 }
        $a2 = { 81 C2 00 04 00 00 81 C3 00 04 00 00 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_VulnDriver_Agent64.yar
## /Windows_VulnDriver_Agent64.yar
``` strings:
        $subject_name_1 = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 4C 74 64 }
        $subject_name_2 = { 06 03 55 04 03 [2] 65 53 75 70 70 6F 72 74 2E 63 6F 6D 2C 20 49 6E 63 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 [1-8] 41 00 67 00 65 00 6E 00 74 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $product_version = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E [1-8] 36 00 2E 00 30 }
        $product_name = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 [1-8] 44 00 72 00 69 00 76 00 65 00 72 00 41 00 67 00 65 00 6E 00 74 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_VulnDriver_Biostar.yar
## Windows_VulnDriver_Biostar
``` strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 48 00 57 00 4D 00 49 00 4F 00 36 00 34 00 5F 00 57 00 31 00 30 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x98][\x00-\x08]|[\x00-\xff][\x00-\x07])([\x00-\x0e][\x00-\x07]|[\x00-\xff][\x00-\x06])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x0d][\x00-\x07]|[\x00-\xff][\x00-\x06]))/
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_VulnDriver_WinFlash.yar
## Windows_VulnDriver_WinFlash
```  strings:
        $str1 = "\\WinFlash64.pdb"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_VulnDriver_Zam.yar
## Windows_VulnDriver_Zam
```strings:
        $pdb_64 = "AntiMalware\\bin\\zam64.pdb"
        $pdb_32 = "AntiMalware\\bin\\zam32.pdb"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Wiper_CaddyWiper.yar
## Windows_Wiper_CaddyWiper
``` strings:
        $a1 = { C6 45 AC 43 C6 45 AD 3A C6 45 AE 5C C6 45 AF 55 C6 45 B0 73 C6 45 B1 65 C6 45 B2 72 C6 45 B3 73 }
        $a2 = { C6 45 E0 44 C6 45 E1 3A C6 45 E2 5C }
        $a3 = { C6 45 9C 6E C6 45 9D 65 C6 45 9E 74 C6 45 9F 61 C6 45 A0 70 C6 45 A1 69 C6 45 A2 33 C6 45 A3 32 }
        $s1 = "DsRoleGetPrimaryDomainInformation"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Wiper_DoubleZero.yar
## Windows_Wiper_DoubleZero
``` strings:
        $s1 = "\\Users\\\\.*?\\\\AppData\\\\Roaming\\\\Microsoft.*" wide fullword
        $s2 = "\\Users\\\\.*?\\\\AppData\\\\Local\\\\Application Data.*" wide fullword
        $s3 = "\\Users\\\\.*?\\\\Local Settings.*" wide fullword
        $s4 = "get__beba00adeeb086e6" ascii fullword
        $s5 = "FileShareWrite" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Wiper_HermeticWiper.yar
## Windows_Wiper_HermeticWiper
```  strings:
        $a1 = "\\\\?\\C:\\Windows\\System32\\winevt\\Logs" wide fullword
        $a2 = "\\\\.\\EPMNTDRV\\%u" wide fullword
        $a3 = "tdrv.pdb" ascii fullword
        $a4 = "%s%.2s" wide fullword
        $a5 = "ccessdri" ascii fullword
        $a6 = "Hermetica Digital"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Wiper_IsaacWiper.yar
## Windows_Wiper_IsaacWiper
``` strings:
        $a1 = "C:\\ProgramData\\log.txt" wide fullword
        $a2 = "system physical drive -- FAILED" wide fullword
        $a3 = "-- system logical drive: " wide fullword
        $a4 = "start erasing system logical drive " wide fullword
        $a5 = "-- logical drive: " wide fullword
        $a6 = "-- start erasing logical drive " wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Cryptominer_Generic.yar
## Windows_Cryptominer_Generic
``` strings:
        $a = { EF F9 66 0F EF FA 66 0F FE FE 66 0F 6F B0 B0 00 00 00 66 0F }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Exploit_FakePipe.yar
## Windows_Exploit_FakePipe
``` strings:
        $api = "ImpersonateNamedPipeClient"
        $s1 = "\\\\.\\pipe\\%ws\\pipe\\" wide nocase
        $s2 = "\\\\.\\pipe\\%s\\pipe\\" wide nocase
        $s3 = { 5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 00 5C 00 00 19 5C 00 70 00 69 00 70 00 65 00 5C }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Exploit_IoRing.yar
## Windows_Exploit_IoRing
```  strings:
        $s1 = { 5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 00 5C 00 69 00 6F 00 72 00 69 00 6E 00 67 00 5F 00 6F 00 75 00 74 00 }
        $s2 = "ioring_read" wide nocase
        $s3 = "ioring_write" wide nocase
        $s4 = "IoRing->RegBuffers" nocase
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Exploit_Log4j.yar
## Windows_Exploit_Log4j
``` strings:
        $jndi1 = "jndi.ldap.LdapCtx.c_lookup"
        $jndi2 = "logging.log4j.core.lookup.JndiLookup.lookup"
        $jndi3 = "com.sun.jndi.url.ldap.ldapURLContext.lookup"
        $exp1 = "Basic/Command/Base64/"
        $exp2 = "java.lang.ClassCastException: Exploit"
        $exp3 = "WEB-INF/classes/Exploit"
        $exp4 = "Exploit.java"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Exploit_Perfusion.yar
## Windows_Exploit_Perfusion
```  strings:
        $s1 = "SYSTEM\\CurrentControlSet\\Services\\%ws\\Performance" wide
        $s2 = "Win32_Perf" wide
        $s3 = "CollectPerfData" wide
        $s4 = "%wsperformance_%d_%d_%d.dll" wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Exploit_RpcJunction.yar
## Windows_Exploit_RpcJunction
``` strings:
        $s1 = "NtSetInformationFile"
        $s2 = "DefineDosDevice"
        $s3 = "\\GLOBALROOT\\RPC Control\\" wide nocase
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Generic_MalCert.yar
## Windows_Generic_MalCert
``` strings:
        $a1 = { 01 02 02 0C 4D 60 69 B5 05 25 63 39 49 C1 2B 22 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Generic_Threat.yar
## Windows_Generic_Threat
``` strings:
        $a1 = { 4D 65 73 73 61 67 65 50 61 63 6B 4C 69 62 2E 4D 65 73 73 61 67 65 50 61 63 6B }
        $a2 = { 43 6C 69 65 6E 74 2E 41 6C 67 6F 72 69 74 68 6D }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_AskCreds.yar
## Windows_Hacktool_AskCreds
``` strings:
        $a1 = "Failed to create AskCreds thread."
        $a2 = "CredUIPromptForWindowsCredentialsW failed"
        $a3 = "[+] Password: %ls"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_BlackBone.yar
## Windows_Hacktool_BlackBone
``` strings:
        $str1 = "BlackBone: %s: ZwCreateThreadEx hThread 0x%X"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_COFFLoader.yar
## Windows_Hacktool_COFFLoader
``` strings:
        $a1 = "BeaconDataParse" ascii fullword
        $a2 = "BeaconDataInt" ascii fullword
        $a3 = "BeaconDataShort" ascii fullword
        $a4 = "BeaconDataLength" ascii fullword
        $a5 = "BeaconDataExtract" ascii fullword
        $a6 = "BeaconFormatAlloc" ascii fullword
        $a7 = "BeaconFormatReset" ascii fullword
        $a8 = "BeaconFormatFree" ascii fullword
        $a9 = "BeaconFormatAppend" ascii fullword
        $a10 = "BeaconFormatPrintf" ascii fullword
        $a11 = "BeaconFormatToString" ascii fullword
        $a12 = "BeaconFormatInt" ascii fullword
        $a13 = "BeaconPrintf" ascii fullword
        $a14 = "BeaconOutput" ascii fullword
        $a15 = "BeaconUseToken" ascii fullword
        $a16 = "BeaconRevertToken" ascii fullword
        $a17 = "BeaconDataParse" ascii fullword
        $a18 = "BeaconIsAdmin" ascii fullword
        $a19 = "BeaconGetSpawnTo" ascii fullword
        $a20 = "BeaconSpawnTemporaryProcess" ascii fullword
        $a21 = "BeaconInjectProcess" ascii fullword
        $a22 = "BeaconInjectTemporaryProcess" ascii fullword
        $a23 = "BeaconCleanupProcess" ascii fullword
        $b1 = "COFFLoader.x64.dll"
        $b2 = "COFFLoader.x86.dll"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_Capcom.yar
## Windows_Hacktool_Capcom
```  strings:
        $subject_name = { 06 03 55 04 03 [2] 43 41 50 43 4F 4D 20 43 6F 2E 2C 4C 74 64 2E }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_Certify.yar
## Windows_Hacktool_Certify
``` strings:
        $a1 = "<DisplayNtAuthCertificates>b_"
        $a2 = "<PrintAllowPermissions>b_"
        $a3 = "<ShowVulnerableTemplates>b_"
        $a4 = "<ParseCertificateApplicationPolicies>b_"
        $a5 = "<PrintCertTemplate>b_"
        $b1 = "64524ca5-e4d0-41b3-acc3-3bdbefd40c97" ascii wide nocase
        $b2 = "64524CA5-E4D0-41B3-ACC3-3BDBEFD40C97" ascii wide nocase
        $b3 = "Certify.exe find /vulnerable" wide
        $b4 = "Certify.exe request /ca" wide
``` 
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_CheatEngine.yar
## Windows_Hacktool_CheatEngine
``` strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 65 61 74 20 45 6E 67 69 6E 65 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_ChromeKatz.yar
## Windows_Hacktool_ChromeKatz
``` strings:
        $s1 = "CookieKatz.exe"
        $s2 = "Targeting Chrome"
        $s3 = "Targeting Msedgewebview2"
        $s4 = "Failed to find the first pattern"
        $s5 = "WalkCookieMap"
        $s6 = "Found CookieMonster on 0x%p"
        $s7 = "Cookie Key:"
        $s8 = "Failed to read cookie value" wide
        $s9 = "Failed to read cookie struct" wide
        $s10 = "Error reading left node"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_ClrOxide.yar
## Windows_Hacktool_ClrOxide
``` strings:
        $s1 = "clroxide..primitives..imethodinfo"
        $s2 = "clroxide..clr..Clr"
        $s3 = "\\src\\primitives\\icorruntimehost.rs"
        $s4 = "\\src\\primitives\\iclrruntimeinfo.rs"
        $s5 = "\\src\\primitives\\iclrmetahost.rs"
        $s6 = "clroxide\\src\\clr\\mod.rs"
        $s7 = "__clrcall"
``` 
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_CpuLocker.yar
## Windows_Hacktool_CpuLocker
``` strings:
        $str1 = "\\CPULocker.pdb"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_DarkLoadLibrary.yar
## Windows_Hacktool_DarkLoadLibrary
``` strings:
        $guid = "3DDD52BB-803A-40E7-90E4-A879A873DD8B" ascii wide nocase
        $print_str0 = "LocalLdrGetProcedureAddress: failed to resolve address of: %s" ascii fullword
        $print_str1 = "Not implemented yet, sorry" wide
        $print_str2 = "Failed to link module to PEB: %s" ascii wide fullword
        $print_str3 = "Failed to resolve imports: %s" ascii wide fullword
        $print_str4 = "Failed to map sections: %s" ascii wide fullword
        $print_str5 = "Failed to open local DLL file" wide fullword
        $print_str6 = "Failed to get DLL file size" wide fullword
        $print_str7 = "Failed to allocate memory for DLL data" wide fullword
        $print_str8 = "Failed to read data from DLL file" wide fullword
        $print_str9 = "Failed to close handle on DLL file" wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_Dcsyncer.yar
## Windows_Hacktool_Dcsyncer
``` strings:
        $a1 = "[x] dcsync: Error in ProcessGetNCChangesReply" wide fullword
        $a2 = "[x] getDCBind: RPC Exception 0x%08x (%u)" wide fullword
        $a3 = "[x] getDomainAndUserInfos: DomainControllerInfo: 0x%08x (%u)" wide fullword
        $a4 = "[x] ProcessGetNCChangesReply_decrypt: Checksums don't match (C:0x%08x - R:0x%08x)" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_DinvokeRust.yar
## Windows_Hacktool_DinvokeRust
``` strings:
        $s1 = { 64 69 6E 76 6F 6B 65 ?? ?? 67 65 74 5F }
        $s2 = { 64 69 6E 76 6F 6B 65 ?? ?? 6E 74 5F }
        $s3 = { 64 69 6E 76 6F 6B 65 ?? ?? 6C 69 74 63 72 79 70 74 }
        $s4 = { 64 69 6E 76 6F 6B 65 5C 73 72 63 5C 6C 69 62 2E 72 73 }
        $s5 = { 75 6E 77 69 6E 64 65 72 ?? ?? 63 61 6C 6C 5F 66 75 6E 63 74 69 6F 6E }
        $s6 = { 75 6E 77 69 6E 64 65 72 ?? ?? 69 6E 64 69 72 65 63 74 5F 73 79 73 63 61 6C 6C }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_EDRWFP.yar
## Windows_Hacktool_EDRWFP
```  strings:
        $s1 = "elastic-endpoint.exe"
        $s2 = "elastic-agent.exe"
        $s3 = "MsMpEng.exe"
        $s4 = "FwpmFilterAdd0"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_EDRrecon.yar
## Windows_Hacktool_EDRrecon
``` strings:
        $s01 = "WdFilter.sys" ascii wide fullword
        $s02 = "mpFilter.sys" ascii wide fullword
        $s03 = "SRTSP.sys" ascii wide fullword
        $s04 = "eeCtrl.sys" ascii wide fullword
        $s05 = "360AvFlt.sys" ascii wide fullword
        $s06 = "360fsflt.sys" ascii wide fullword
        $s07 = "esensor.sys" ascii wide fullword
        $s09 = "klflt.sys" ascii wide fullword
        $s10 = "klam.sys" ascii wide fullword
        $s11 = "SysmonDrv.sys" ascii wide fullword
        $s12 = "CarbonBlackK.sys" ascii wide fullword
        $s13 = "edrsensor.sys" ascii wide fullword
        $s14 = "naswSP.sys" ascii wide fullword
        $s15 = "symevnt.sys" ascii wide fullword
        $s16 = "symevnt32.sys" ascii wide fullword
        $s17 = "CyProtectDrv" ascii wide fullword
        $s18 = "mfeaskm.sys" ascii wide fullword
        $s19 = "SentinelMonitor.sys" ascii wide fullword
        $s20 = "sentinelelam.sys" ascii wide fullword
        $s21 = "SophosSupport.sys" ascii wide fullword
        $s22 = "CSDeviceControl.sys" ascii wide fullword
        $s23 = "csagent.sys" ascii wide fullword
        $s24 = "avgntflt.sys" ascii wide fullword
        $s25 = "bddevflt.sys" ascii wide fullword
        $s26 = "CiscoAMPHeurDriver.sys" ascii wide fullword
        $s27 = "DeepInsFS.sys" ascii wide fullword
        $s28 = "eamonm.sys" ascii wide fullword
        $s29 = "fortirmon.sys" ascii wide fullword
        $s30 = "FlightRecorder.sys" ascii wide fullword
        $s31 = "TmKmSnsr.sys" ascii wide fullword
        $s32 = "cpepmon.sys" ascii wide fullword
        $s33 = "cposfw.sys" ascii wide fullword
        $s34 = "cyvrmtgn.sys" ascii wide fullword
        $s35 = "elastic-endpoint-driver.sys" ascii wide fullword
        $s36 = "elasticelam.sys" ascii wide fullword
        $37 = "mbamwatchdog.sys" ascii wide fullword
        $38 = "FortiEDRWinDriver" ascii wide fullword
        $39 = "QaxNfDrv.sys" ascii wide fullword
        $40 = "qmnetmonw64.sys" ascii wide fullword
        $s41 = "TFsFlt.sys" ascii wide fullword
        $s42 = "DsArk64.sys" ascii wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_ExecuteAssembly.yar
## Windows_Hacktool_ExecuteAssembly
``` strings:
        $bytes0 = { 33 D8 8B C3 C1 E8 05 03 D8 8B C3 C1 E0 04 33 D8 8B C3 C1 E8 11 03 D8 8B C3 C1 E0 19 33 D8 8B C3 C1 E8 06 03 C3 }
        $bytes1 = { 81 F9 8E 4E 0E EC 74 10 81 F9 AA FC 0D 7C 74 08 81 F9 54 CA AF 91 75 43 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_Gmer.yar
## Windows_Hacktool_Gmer
``` strings:
        $str1 = "\\gmer64.pdb"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_GodPotato.yar
## Windows_Hacktool_GodPotato
``` strings:
        $a1 = "GodPotato" wide fullword
        $a2 = "GodPotatoContext was not initialized" wide fullword
        $a3 = "GodPotatoStorageTrigger" ascii fullword
        $a4 = "[*] DCOM obj GUID: {0}" wide fullword
        $a5 = "[*] DispatchTable: 0x{0:x}" wide fullword
        $a6 = "[*] UseProtseqFunction: 0x{0:x}" wide fullword
        $a7 = "[*] process start with pid {0}" wide fullword
        $a8 = "[!] ImpersonateNamedPipeClient fail error:{0}" wide fullword
        $a9 = "[*] CoGetInstanceFromIStorage: 0x{0:x}" wide fullword
        $a10 = "[*] Trigger RPCS" wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_Iox.yar
## Windows_Hacktool_Iox
``` strings:
        $param_check_b0 = { 48 83 FB 05 0F 85 ?? ?? ?? ?? 81 38 70 72 6F 78 66 0F 1F 44 00 00 0F 85 ?? ?? ?? ?? 80 78 04 79 0F 85 ?? ?? ?? ?? 48 83 F9 03 }
        $param_check_b1 = { 48 8B 14 24 4C 8B 5C 24 18 4C 8B 64 24 08 4C 8B 6C 24 08 4C 8B 7C 24 20 66 0F 1F 84 00 00 00 00 00 48 83 FB 03 0F 85 ?? ?? ?? ?? 66 81 38 66 77 0F 85 ?? ?? ?? ?? 80 78 02 64 }
        $param_check_b2 = { 81 38 2D 2D 6C 6F 0F 1F 44 00 00 0F 85 ?? ?? ?? ?? 66 81 78 04 63 61 0F 85 ?? ?? ?? ?? 80 78 06 6C }
        $param_check_b3 = { 83 FA 05 0F 85 ?? ?? ?? ?? 81 38 2D 2D 6B 65 0F 85 ?? ?? ?? ?? 80 78 04 79 90 }
``` 
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_LeiGod.yar
## Windows_Hacktool_LeiGod
``` strings:
        $str1 = "\\Device\\CtrlLeiGod" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_Mimikatz.yar
## Windows_Hacktool_Mimikatz
``` strings:
        $a1 = "   Password: %s" wide fullword
        $a2 = "  * Session Key   : 0x%08x - %s" wide fullword
        $a3 = "   * Injecting ticket : " wide fullword
        $a4 = " ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )" wide fullword
        $a5 = "Remove mimikatz driver (mimidrv)" wide fullword
        $a6 = "mimikatz(commandline) # %s" wide fullword
        $a7 = "  Password: %s" wide fullword
        $a8 = " - SCardControl(FEATURE_CCID_ESC_COMMAND)" wide fullword
        $a9 = " * to 0 will take all 'cmd' and 'mimikatz' process" wide fullword
        $a10 = "** Pass The Ticket **" wide fullword
        $a11 = "-> Ticket : %s" wide fullword
        $a12 = "Busylight Lync model (with bootloader)" wide fullword
        $a13 = "mimikatz.log" wide fullword
        $a14 = "Log mimikatz input/output to file" wide fullword
        $a15 = "ERROR kuhl_m_dpapi_masterkey ; kull_m_dpapi_unprotect_domainkey_with_key" wide fullword
        $a16 = "ERROR kuhl_m_lsadump_dcshadow ; unable to start the server: %08x" wide fullword
        $a17 = "ERROR kuhl_m_sekurlsa_pth ; GetTokenInformation (0x%08x)" wide fullword
        $a18 = "ERROR mimikatz_doLocal ; \"%s\" module not found !" wide fullword
        $a19 = "Install and/or start mimikatz driver (mimidrv)" wide fullword
        $a20 = "Target: %hhu (0x%02x - %s)" wide fullword
        $a21 = "mimikatz Ho, hey! I'm a DC :)" wide fullword
        $a22 = "mimikatz service (mimikatzsvc)" wide fullword
        $a23 = "[masterkey] with DPAPI_SYSTEM (machine, then user): " wide fullword
        $a24 = "$http://blog.gentilkiwi.com/mimikatz 0" ascii fullword
        $a25 = " * Username : %wZ" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_NetFilter.yar
## Windows_Hacktool_NetFilter
``` strings:
        $str1 = "[NetFlt]:CTRL NDIS ModifyARP"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_Nimhawk.yar
## Windows_Hacktool_Nimhawk
``` strings:
        $s1 = "NimHawk"
        $s2 = "BeaconInjectTemporaryProcess"
        $s3 = "BeaconSpawnTemporaryProcess"
        $s4 = "getImplantIDFromRegistry"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_Phant0m.yar
## Windows_Hacktool_Phant0m
``` strings:
        $api = "NtQueryInformationThread"
        $s1 = "Suspending EventLog thread %d with start address %p"
        $s2 = "Found the EventLog Module (wevtsvc.dll) at %p"
        $s3 = "Event Log service PID detected as %d."
        $s4 = "Thread %d is detected and successfully killed."
        $s5 = "Windows EventLog module %S at %p"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_PhysMem.yar
## Windows_Hacktool_PhysMem
```   strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 68 00 79 00 73 00 6D 00 65 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_ProcessHacker.yar
## Windows_Hacktool_ProcessHacker
``` strings:
        $original_file_name = "OriginalFilename\x00kprocesshacker.sys" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_RingQ.yar
## Windows_Hacktool_RingQ
``` strings:
        $a1 = "Loading Dir main.txt ..." ascii fullword
        $a2 = "Loading LocalFile ..." ascii fullword
        $a3 = "No Find main,txt and StringTable ..." ascii fullword
        $a4 = "https://github.com/T4y1oR/RingQ"
        $a5 = "RingQ :)" ascii fullword
        $a6 = "1. Create.exe fscan.exe" ascii fullword
        $a7 = "C:/Users/username/Documents/file.txt" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_Rubeus.yar
## Windows_Hacktool_Rubeus
```  strings:
        $guid = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii wide nocase
        $print_str0 = "[*] Printing argument list for use with Rubeus" ascii wide
        $print_str1 = "[+] Ticket successfully imported!" ascii wide
        $print_str2 = "[+] Tickets successfully purged!" ascii wide
        $print_str3 = "[*] Searching for accounts that support AES128_CTS_HMAC_SHA1_96/AES256_CTS_HMAC_SHA1_96" ascii wide
        $print_str4 = "[*] Action: TGT Harvesting (with auto-renewal)" ascii wide
        $print_str5 = "[X] Unable to retrieve TGT using tgtdeleg" ascii wide
        $print_str6 = "[!] Unhandled Rubeus exception:" ascii wide
        $print_str7 = "[*] Using a TGT /ticket to request service tickets" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SafetyKatz.yar
## Windows_Hacktool_SafetyKatz
``` strings:
        $guid = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" ascii wide nocase
        $print_str0 = "[X] Not in high integrity, unable to grab a handle to lsass!" ascii wide fullword
        $print_str1 = "[X] Dump directory \"{0}\" doesn't exist!" ascii wide fullword
        $print_str2 = "[X] Process is not 64-bit, this version of Mimikatz won't work yo'!" ascii wide fullword
        $print_str3 = "[+] Dump successful!" ascii wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_Seatbelt.yar
## Windows_Hacktool_Seatbelt
``` strings:
        $guid = "AEC32155-D589-4150-8FE7-2900DF4554C8" ascii wide nocase
        $str0 = "LogonId=\"(\\d+)" ascii wide
        $str1 = "Domain=\"(.*)\",Name=\"(.*)\"" ascii wide
        $str2 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" ascii wide
        $str3 = "KB\\d+" ascii wide
        $str4 = "(^https?://.+)|(^ftp://)" ascii wide
        $str5 = "[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}" ascii wide
        $str6 = "(http|ftp|https|file)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharPersist.yar
## Windows_Hacktool_SharPersist
```  strings:
        $guid = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" ascii wide nocase
        $print_str0 = "schtaskbackdoor: backdoor scheduled task" ascii wide
        $print_str1 = "schtaskbackdoor -m list -n <schtask name>" ascii wide
        $print_str2 = "SharPersist" ascii wide
        $print_str3 = "[+] SUCCESS: Keepass persistence backdoor added" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpAppLocker.yar
## Windows_Hacktool_SharpAppLocker
``` strings:
        $guid = "FE102D27-DEC4-42E2-BF69-86C79E08B67D" ascii wide nocase
        $print_str0 = "[+] Output written to:" ascii wide fullword
        $print_str1 = "[!] You can only select one Policy at the time." ascii wide fullword
        $print_str2 = "SharpAppLocker.exe --effective --allow --rules=\"FileHashRule,FilePathRule\" --outfile=\"C:\\Windows\\Tasks\\Rules.json\"" ascii wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpChromium.yar
## Windows_Hacktool_SharpChromium
``` strings:
        $guid = "F1653F20-D47D-4F29-8C55-3C835542AF5F" ascii wide nocase
        $print_str0 = "[X] Exception occurred while writing cookies to file: {0}" ascii wide fullword
        $print_str1 = "[*] All cookies written to {0}" ascii wide fullword
        $print_str2 = "\\{0}-cookies.json" ascii wide fullword
        $print_str3 = "[*] {0} {1} extraction." ascii wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpDump.yar
## Windows_Hacktool_SharpDump
``` strings:
        $guid = "9c9bba3-a0ea-431c-866c-77004802d" ascii wide nocase
        $print_str0 = "Please use \"SharpDump.exe [pid]\" format" ascii wide
        $print_str1 = "[*] Use \"sekurlsa::minidump debug.out\" \"sekurlsa::logonPasswords full\" on the same OS/arch" ascii wide
        $print_str2 = "[+] Dumping completed. Rename file to \"debug{0}.gz\" to decompress" ascii wide
        $print_str3 = "[X] Not in high integrity, unable to MiniDump!" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpGPOAbuse.yar
## Windows_Hacktool_SharpGPOAbuse
``` strings:
        $name = "SharpGPOAbuse" wide fullword
        $s1 = "AddUserTask" wide fullword
        $s2 = "AddComputerTask" wide fullword
        $s3 = "AddComputerScript" wide fullword
        $s4 = "AddUserScript" wide fullword
        $s5 = "GPOName" wide fullword
        $s6 = "ScheduledTasks" wide fullword
        $s7 = "NewImmediateTask" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpHound.yar
## Windows_Hacktool_SharpHound
``` strings:
        $guid0 = "A517A8DE-5834-411D-ABDA-2D0E1766539C" ascii wide nocase
        $guid1 = "90A6822C-4336-433D-923F-F54CE66BA98F" ascii wide nocase
        $print_str0 = "Initializing SharpHound at {time} on {date}" ascii wide
        $print_str1 = "SharpHound completed {Number} loops! Zip file written to {Filename}" ascii wide
        $print_str2 = "[-] Removed DCOM Collection" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpLAPS.yar
## Windows_Hacktool_SharpLAPS
```  strings:
        $guid = "1e0986b4-4bf3-4cea-a885-347b6d232d46" ascii wide nocase
        $str_name = "SharpLAPS.exe" ascii wide
        $str0 = "Using the current session" ascii wide
        $str1 = "Extracting LAPS password" ascii wide
        $str2 = "(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=" ascii wide
        $str4 = "Machine" ascii wide
        $str5 = "sAMAccountName" ascii wide
        $str6 = "ms-Mcs-AdmPwd" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpMove.yar
## Windows_Hacktool_SharpMove
``` strings:
        $guid = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" ascii wide nocase
        $print_str0 = "[X]  Failed to connecto to WMI: {0}" ascii wide fullword
        $print_str1 = "[+] Executing DCOM ShellBrowserWindow   : {0}" ascii wide fullword
        $print_str2 = "[+]  User credentials  : {0}" ascii wide fullword
        $print_str3 = "[+] Executing DCOM ExcelDDE   : {0}" ascii wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpRDP.yar
## Windows_Hacktool_SharpRDP
```  strings:
        $guid = "F1DF1D0F-FF86-4106-97A8-F95AAF525C54" ascii wide nocase
        $print_str0 = "[+] Another user is logged on, asking to take over session" ascii wide fullword
        $print_str1 = "[+] Execution priv type   :  {0}" ascii wide fullword
        $print_str2 = "[+] Sleeping for 30 seconds" ascii wide fullword
        $print_str3 = "[X] Error: A password is required" ascii wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpSCCM.yar
## Windows_Hacktool_SharpSCCM
``` strings:
        $name = "SharpSCCM" wide fullword
        $s1 = "--relay-server" wide fullword
        $s2 = "--username" wide fullword
        $s3 = "--domain" wide fullword
        $s4 = "--sms-provider" wide fullword
        $s5 = "--wmi-namespace" wide fullword
        $s6 = "--management-point" wide fullword
        $s7 = "--get-system" wide fullword
        $s8 = "--run-as-user" wide fullword
        $s9 = "--register-client" wide fullword
        $s10 = "MS_Collection" wide fullword
        $s11 = "SOFTWARE\\Microsoft\\CCM" wide fullword
        $s12 = "CCM_POST" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpShares.yar
## Windows_Hacktool_SharpShares
``` strings:
        $guid = "BCBC884D-2D47-4138-B68F-7D425C9291F9" ascii wide nocase
        $print_str0 = "all enabled computers with \"primary\" group \"Domain Computers\"" ascii wide
        $print_str1 = "all enabled Domain Controllers (not read-only DCs)" ascii wide
        $print_str2 = "all enabled servers excluding Domain Controllers or read-only DCs" ascii wide
        $str0 = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" ascii wide
        $str1 = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=8192))" ascii wide
        $str2 = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))" ascii wide
        $str3 = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))" ascii wide
        $str4 = "servers-exclude-dc" ascii wide
        $str5 = "all enabled servers" ascii wide
        $str6 = "[w] \\\\{0}\\{1}" ascii wide
        $str7 = "[-] \\\\{0}\\{1}" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpStay.yar
## Windows_Hacktool_SharpStay
```  strings:
        $guid = "2963C954-7B1E-47F5-B4FA-2FC1F0D56AEA" ascii wide nocase
        $print_str0 = "[+] Registry key HKCU:SOFTWARE\\Classes\\CLSID\\{0}\\InProcServer32 created" ascii wide fullword
        $print_str1 = "Sharpstay.exe action=ElevatedRegistryKey" ascii wide fullword
        $print_str2 = "[+] WMI Subscription {0} has been created to run at {1}" ascii wide fullword
        $print_str3 = "[+] Cleaned up %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\Indexing.{0}" ascii wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpUp.yar
## 
``` strings:
        $guid = "FDD654F5-5C54-4D93-BF8E-FAF11B00E3E9" ascii wide nocase
        $str0 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.bat|\\.ps1|\\.vbs))\\W*" ascii wide
        $str1 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" ascii wide
        $str2 = "SELECT * FROM win32_service WHERE Name LIKE '{0}'" ascii wide
        $print_str1 = "[!] Modifialbe scheduled tasks were not evaluated due to permissions." ascii wide
        $print_str2 = "[+] Potenatially Hijackable DLL: {0}" ascii wide
        $print_str3 = "Registry AutoLogon Found" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpView.yar 
## Windows_Hacktool_SharpView
``` strings:
        $guid = "22A156EA-2623-45C7-8E50-E864D9FC44D3" ascii wide nocase
        $print_str0 = "[Add-DomainObjectAcl] Granting principal {0} rights GUID '{1}' on {2}" ascii wide
        $print_str1 = "[Get-NetRDPSession] Error opening the Remote Desktop Session Host (RD Session Host) server for: {0}" ascii wide
        $print_str2 = "[Get-WMIProcess] Error enumerating remote processes on '{0}', access likely denied: {1}" ascii wide
        $print_str3 = "[Get-WMIRegLastLoggedOn] Error opening remote registry on $Computer. Remote registry likely not enabled." ascii wide
        $print_str4 = "[Get-DomainGUIDMap] Error in building GUID map: {e}" ascii wide
        $str0 = "^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$" ascii wide
        $str1 = "(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))" ascii wide
        $str2 = "^(CN|OU|DC)=" ascii wide
        $str3 = "(|(samAccountName={0})(name={1})(displayname={2}))" ascii wide
        $str4 = "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$" ascii wide
        $str5 = "LDAP://|^CN=.*" ascii wide
        $str6 = "(objectCategory=groupPolicyContainer)" ascii wide
        $str7 = "\\\\{0}\\SysVol\\{1}\\Policies\\{2}" ascii wide
        $str8 = "S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$" ascii wide
        $str9 = "^S-1-5-.*-[1-9]\\d{3,}$" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpWMI.yar
## Windows_Hacktool_SharpWMI
``` strings:
        $guid = "6DD22880-DAC5-4B4D-9C91-8C35CC7B8180" ascii wide nocase
        $str0 = "powershell -w hidden -nop -c \"$e=([WmiClass]'{0}:{1}').Properties['{2}'].Value;[IO.File]::WriteAllBytes('{3}',[Byte[]][Int[]]($e-split','))\"" ascii wide
        $str1 = "powershell -w hidden -nop -c \"iex($env:{0})\"" ascii wide
        $str2 = "SELECT * FROM Win32_Process" ascii wide
        $str3 = "DOWNLOAD_URL" ascii wide
        $str4 = "TARGET_FILE" ascii wide
        $str5 = "SELECT Enabled,DisplayName,Action,Direction,InstanceID from MSFT_NetFirewallRule WHERE Enabled=1" ascii wide
        $print_str0 = "This may indicate called SharpWMI did not invoked WMI using elevated/impersonated token." ascii wide
        $print_str1 = "[+] Attempted to terminate remote process ({0}). Returned: {1}" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SleepObfLoader.yar
## Windows_Hacktool_SleepObfLoader
```  strings:
        $a = { BA 01 00 00 00 41 B8 20 01 00 00 8B 48 3C 8B 4C 01 28 48 03 C8 48 89 0D ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? B9 01 00 00 00 }
        $b = { 8A 50 20 83 60 24 F0 80 E2 F8 48 8B ?? ?? ?? 4C 8B ?? ?? ?? 48 89 08 48 8B ?? ?? ?? 48 89 48 08 }
        $c = { 8B 46 FB 41 89 40 18 0F B7 46 FF 66 41 89 40 1C 8A 46 01 41 88 40 1E }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_WinPEAS_ng.yar
## Windows_Hacktool_WinPEAS_ng
``` strings:
        $win_0 = "Possible DLL Hijacking, folder is writable" ascii wide
        $win_1 = "FolderPerms:.*" ascii wide
        $win_2 = "interestingFolderRights" ascii wide
        $win_3 = "(Unquoted and Space detected)" ascii wide
        $win_4 = "interestingFolderRights" ascii wide
        $win_5 = "RegPerms: .*" ascii wide
        $win_6 = "Permissions file: {3}" ascii wide
        $win_7 = "Permissions folder(DLL Hijacking):" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Infostealer_EddieStealer.yar
## Windows_Infostealer_EddieStealer
```  strings:
        $a = { 48 8B 8C 24 ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 8B 94 24 ?? ?? ?? ?? E8 }
        $b = { 48 ?? AA AA 00 00 AA AA AA AA 4? 89 ?? 04 4? 89 ?? 0C 66 [1-2] AA AA }
        $c = { 4? 89 [1-2] 0F 28 05 ?? ?? ?? ?? 0F 11 ?? 08 0F 11 ?? 18 0F 11 ?? 23 0F 57 C0 }
        $d = { 4? 8B 14 ?? 48 33 14 08 48 89 94 0C ?? ?? ?? ?? 48 83 C1 08 EB }
        $e = { 48 83 EC 38 48 8B 09 48 8B 01 48 83 21 00 48 85 C0 0F 84 ?? ?? ?? ?? 48 8B 30 48 ?? ?? ?? ?? ?? ?? 48 8D 54 24 28 48 89 02 48 8B 0A C7 ?? ?? ?? ?? ?? 48 8D 7C 24 28 8B 17 E8 }
        $f = { E8 ?? ?? ?? ?? 4? 83 ?? ( 30 | 38 | C8 | D0 ) 4? 83 ?? ( 30 | 38 | C8 | D0 ) 4? 89 ?? EB }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Infostealer_Generic.yar
## Windows_Infostealer_Generic
```  strings:
        $str1 = "ChromeFuckNewCookies" ascii fullword
        $str2 = "/c timeout /t 10 & del /f /q \"" ascii fullword
        $str3 = "56574883EC2889D74889CEE8AAAAFFFF85FF74084889F1E8AAAAAAAA4889F04883C4285F5EC3CCCCCCCCCCCCCCCCCCCC56574883ECAA"
        $seq1 = { 81 FA 6B 03 EE 4C 74 ?? 81 FA 77 03 EE 4C 74 ?? 81 FA 80 68 55 FB 74 ?? 81 FA 92 68 55 FB }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Infostealer_NovaBlight.yar
## Windows_Infostealer_NovaBlight
```  strings:
        $a1 = "C:\\Users\\Administrateur\\Desktop\\Nova\\"
        $a2 = "[+] Recording..." fullword
        $a3 = "[+] Capture start" fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Infostealer_PhemedroneStealer.yar
## Windows_Infostealer_PhemedroneStealer
```  strings:
        $a1 = "<KillDebuggers>b_"
        $a2 = "<Key3Database>b_"
        $a3 = "<IsVM>b_"
        $a4 = "<ParseDatWallets>b_"
        $a5 = "<ParseExtensions>b_"
        $a6 = "<ParseDiscordTokens>b_"
        $b1 = "Phemedrone.Senders"
        $b2 = "Phemedrone.Protections"
        $b3 = "Phemedrone.Extensions"
        $b4 = "Phemedrone.Cryptography"
        $b5 = "Phemedrone-Report.zip"
        $b6 = "Phemedrone Stealer Report"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Infostealer_Strela.yar
## Windows_Infostealer_Strela
```  strings:
        $s1 = "strela" fullword
        $s2 = "/server.php" fullword
        $s3 = "/out.php" fullword
        $s4 = "%s%s\\key4.db" fullword
        $s5 = "%s%s\\logins.json" fullword
        $s6 = "%s,%s,%s\n" fullword
        $old_pdb = "Projects\\StrelaDLLCompile\\Release\\StrelaDLLCompile.pdb" fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_PUP_Generic.yar
## Windows_PUP_Generic
```  strings:
        $a1 = "[%i.%i]av=[error]" fullword
        $a2 = "not_defined" fullword
        $a3 = "osver=%d.%d-ServicePack %d" fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_PUP_MediaArena.yar
## Windows_PUP_Generic
```  strings:
        $a1 = "Going to change default browser to be MS Edge ..." wide
        $a2 = "https://www.searcharchiver.com/eula" wide
        $a3 = "Current default browser is unchanged!" wide
        $a4 = "You can terminate your use of the Search Technology and Search Technology services"
        $a5 = "The software may also offer to change your current web navigation access points"
        $a6 = "{{BRAND_NAME}} may have various version compatible with different platform,"
        $a7 = "{{BRAND_NAME}} is a powerful search tool" wide
``` 
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_PUP_Veriato.yar
## Windows_PUP_Veriato
``` strings:
        $s1 = "InitializeDll" fullword
        $a1 = "C:\\Windows\\winipbin\\svrltmgr.dll" fullword
        $a2 = "C:\\Windows\\winipbin\\svrltmgr64.dll" fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Agenda.yar
## Windows_Ransomware_Agenda
```  strings:
        $ = "-RECOVER-README.txt"
        $ = "/c vssadmin.exe delete shadows /all /quiet"
        $ = "directory_black_list"
        $ = "C:\\Users\\Public\\enc.exe"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Akira.yar
## Windows_Ransomware_Akira
``` strings:
        $a1 = "akira_readme.txt" ascii fullword
        $a2 = "Number of threads to encrypt = " ascii fullword
        $a3 = "write_encrypt_info error:" ascii fullword
        $a4 = "Log-%d-%m-%Y-%H-%M-%S" ascii fullword
        $a5 = "--encryption_path" wide fullword
        $a6 = "--encryption_percent" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Avoslocker.yar
## Windows_Ransomware_Avoslocker
``` strings:
        $a1 = "drive %s took %f seconds" ascii fullword
        $a2 = "client_rsa_priv: %s" ascii fullword
        $a3 = "drive: %s" ascii fullword
        $a4 = "Map: %s" ascii fullword
        $a5 = "encrypting %ls failed" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Azov.yar
## Windows_Ransomware_Azov
``` strings:
        $a = { 48 83 EC 20 40 80 E4 F0 C6 45 F3 56 C6 45 F4 69 C6 45 F5 72 C6 45 F6 74 C6 45 F7 75 C6 45 F8 61 C6 45 F9 6C C6 45 FA 41 C6 45 FB 6C C6 45 FC 6C C6 45 FD 6F C6 45 FE 63 C6 45 FF 00 }
        $b = "Local\\Kasimir_%c" wide fullword
        $s1 = "\\User Data\\Default\\Cache\\" wide fullword
        $s2 = "\\Low\\Content.IE5\\" wide fullword
        $s3 = "\\cache2\\entries" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Bitpaymer.yar
## Windows_Ransomware_Bitpaymer
``` strings:
        $a1 = "RWKGGE.PDB" fullword
        $a2 = "*Qf69@+mESRA.RY7*+6XEF#NH.pdb" fullword
        $a3 = "04QuURX.pdb" fullword
        $a4 = "9nuhuNN.PDB" fullword
        $a5 = "mHtXGC.PDB" fullword
        $a6 = "S:\\Work\\_bin\\Release-Win32\\wp_encrypt_new.pdb" fullword
        $a7 = "C:\\Work\\_bin\\Release-Win32\\wp_encrypt.pdb" fullword
        $a8 = "k:\\softcare\\release\\h2O.pdb" fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_BlackBasta.yar
## Windows_Ransomware_BlackBasta
```  strings:
        $a1 = "Done time: %.4f seconds, encrypted: %.4f gb" ascii fullword
        $a2 = "Creating readme at %s" wide fullword
        $a3 = "All of your files are currently encrypted by no_name_software." ascii fullword
        $a4 = "DON'T move or rename your files. These parameters can be used for encryption/decryption process." ascii fullword
        $b1 = "Your data are stolen and encrypted" ascii fullword
        $b2 = "bcdedit /deletevalue safeboot" ascii fullword
        $b3 = "Your company id for log in:"
        $byte_seq = { 0F AF 45 DC 8B CB 0F AF 4D DC 0F AF 5D D8 0F AF 55 D8 8B F9 }
        $byte_seq2 = { 18 FF 24 1E 18 FF 64 61 5D FF CF CF CF FF D0 D0 D0 FF D0 D0 D0 FF }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Cicada3301.yar
## Windows_Ransomware_Cicada3301
```  strings:
        $a1 = "sqldocrtfxlsjpgjpegpnggifwebptiffpsdrawbmppdfdocxdocmdotxdotmodtxlsxxlsmxltxxltmxlsbx"
        $a2 = "keypathhelpsleepno_implno_localno_netno_notesno_iconno_desktop" ascii fullword
        $a3 = "RECOVER--DATA.txt" ascii fullword
        $a4 = "CMD_BCDEDIT_SET_RECOVERY_DISABLED"
        $a5 = "CMD_WMIC_SHADOWCOPY_DELETE"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Clop.yar
## Windows_Ransomware_Clop
``` strings:
        $a1 = "-%s\\CIopReadMe.txt" wide fullword
        $a2 = "CIopReadMe.txt" wide fullword
        $a3 = "%s-CIop^_" wide fullword
        $a4 = "%s%s.CIop" wide fullword
        $a5 = "BestChangeT0p^_-666" ascii fullword
        $a6 = ".CIop" wide fullword
        $a7 = "A%s\\ClopReadMe.txt" wide fullword
        $a8 = "%s%s.Clop" wide fullword
        $a9 = "CLOP#666" wide fullword
        $a10 = "MoneyP#666" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Conti.yar
## Windows_Ransomware_Conti
```  strings:
        $a = { F7 FE 88 57 FF 83 EB 01 75 DA 8B 45 FC 5F 5B 40 5E 8B E5 5D C3 8D }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Crytox.yar
## Windows_Ransomware_Crytox
```  strings:
        $a = { 48 83 C7 20 D7 C1 C8 08 D7 C1 C8 08 D7 C1 C8 08 D7 C1 C8 10 33 C2 33 47 E0 D0 E2 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Cuba.yar
## Windows_Ransomware_Cuba
```  strings:
        $a1 = "We also inform that your databases, ftp server and file server were downloaded by us to our servers." ascii fullword
        $a2 = "Good day. All your files are encrypted. For decryption contact us." ascii fullword
        $a3 = ".cuba" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Darkside.yar
## Windows_Ransomware_Darkside
``` strings:
        $a1 = { 5F 30 55 56 BD 0A 00 00 00 8B 07 8B 5F 10 8B 4F 20 8B 57 30 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Dharma.yar
## Windows_Ransomware_Dharma
``` strings:
        $b1 = "sssssbsss" ascii fullword
        $b2 = "sssssbs" ascii fullword
        $b3 = "RSDS%~m" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Doppelpaymer.yar
## Windows_Ransomware_Doppelpaymer
``` strings:
        $a1 = "Setup run" wide fullword
        $a2 = "RtlComputeCrc32" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Egregor.yar
## Windows_Ransomware_Egregor
``` strings:
        $a1 = "M:\\sc\\p\\testbuild.pdb" ascii fullword
        $a2 = "C:\\Logmein\\{888-8888-9999}\\Logmein.log" wide fullword
        $a3 = "nIcG`]/h3kpJ0QEAC5OJC|<eT}}\\5K|h\\\\v<=lKfHKO~01=Lo0C03icERjo0J|/+|=P0<UeN|e2F@GpTe]|wpMP`AG+IFVCVbAErvTeBRgUN1vQHNp5FVtc1WVi/G"
        $a4 = "pVrGRgJui@6ejnOu@4KgacOarSh|firCToW1LoF]7BtmQ@2j|hup2owUHQ6W}\\U3gwV6OwSPTMQVq2|G=GKrHpjOqk~`Ba<qu\\2]r0RKkf/HGngsK7LhtvtJiR}+4J"
        $a5 = "Your network was ATTACKED, your computers and servers were LOCKED," ascii wide
        $a6 = "Do not redact this special technical block, we need this to authorize you." ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Generic.yar
## Windows_Ransomware_Generic
``` strings:
        $a1 = "stephanie.jones2024@protonmail.com"
        $a2 = "_/C_/projects/403forBiden/wHiteHousE.init" ascii fullword
        $a3 = "All your files, documents, photoes, videos, databases etc. have been successfully encrypted" ascii fullword
        $a4 = "<p>Do not try to decrypt then by yourself - it's impossible" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Hellokitty.yar
## Windows_Ransomware_Hellokitty
```  strings:
        $a1 = "HelloKittyMutex" wide fullword
        $a2 = "%s\\read_me_lkd.txt" wide fullword
        $a3 = "Win32_ShadowCopy.ID='%s'" wide fullword
        $a4 = "Trying to decrypt or modify the files with programs other than our decryptor can lead to permanent loss of data!" wide fullword
        $a5 = "%s/secret/%S" wide fullword
        $a6 = "DECRYPT_NOTE.txt" wide fullword
        $a7 = "Some data has been stored in our servers and ready for publish." wide fullword
        $a9 = "To contact with us you have ONE week from the encryption time, after decryption keys and your personal contact link will be dele" wide
        $a10 = "In case of your disregard, we reserve the right to dispose of the dumped data at our discretion including publishing." wide fullword
        $a11 = "IMPORTANT: Don't modify encrypted files or you can damage them and decryption will be impossible!" wide fullword
        $b1 = "/f /im \"%s\"" wide fullword
        $b2 = "stop \"%s\"" wide fullword
        $b3 = "/f /im %s" wide fullword
        $b4 = "stop %s" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Helloxd.yar
## Windows_Ransomware_Helloxd
```  strings:
        $mutex = "With best wishes And good intentions..."
        $ransomnote0 = ":: our TOX below >:)"
        $ransomnote1 = "You can download TOX here"
        $ransomnote2 = "...!XD ::"
        $productname = "HelloXD" ascii wide
        $legalcopyright = "uKn0w" ascii wide
        $description = "VhlamAV" ascii wide
        $companyname = "MicloZ0ft" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Hive.yar
## Windows_Ransomware_Hive
``` strings:
        $a1 = "bmr|sql|oracle|postgres|redis|vss|backup|sstp"
        $a2 = "key.hive"
        $a3 = "Killing processes"
        $a4 = "Stopping services"
        $a5 = "Removing itself"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Lockfile.yar
## Windows_Ransomware_Lockfile
```  strings:
        $a1 = "LOCKFILE-README"
        $a2 = "wmic process where \"name  like '%virtualbox%'\" call terminate"
        $a3 = "</computername>"
        $a4 = ".lockfile"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Makop.yar
## Windows_Ransomware_Makop
```  strings:
        $a1 = "MPR.dll" ascii fullword
        $a2 = "\"%s\" n%u" wide fullword
        $a3 = "\\\\.\\%c:" wide fullword
        $a4 = "%s\\%s\\%s" wide fullword
        $a5 = "%s\\%s" wide fullword
        $a6 = "Start folder" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Maui.yar
## Windows_Ransomware_Maui
``` strings:
        $a1 = "Please append it by <Godhead> using -maui option." wide fullword
        $a2 = "Please overwrite it by <Godhead> using -maui option." wide fullword
        $a3 = "maui.log" wide fullword
        $a4 = "maui.key" wide fullword
        $a5 = "maui.evd" wide fullword
        $a6 = "Encrypt[%s]: %s" wide fullword
        $a7 = "PROCESS_GOINGON[%d%% / %d%%]: %s" wide fullword
        $a8 = "PROCESS_REPLACECONFIRM: %s" wide fullword
        $seq_encrypt_priv_key = { 55 8B 6C 24 ?? 57 8B F9 85 DB 74 ?? 85 FF 74 ?? 85 ED 74 ?? 56 8D 87 ?? ?? ?? ?? 50 6A ?? E8 ?? ?? ?? ?? 8B 4D ?? 8B 51 ?? 6A ?? 52 8B F0 56 53 57 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 7F ?? E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 5E 5F 83 C8 ?? 5D C3 }
        $seq_get_private_key = { 57 8B F8 85 FF 75 ?? 5F C3 56 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 80 7F ?? ?? 8B F0 74 ?? 8B 07 50 56 E8 ?? ?? ?? ?? EB ?? 8B 0F 51 56 E8 ?? ?? ?? ?? 83 C4 ?? 85 F6 75 ?? 5E 33 C0 5F C3 }
        $seq_get_pub_key = { B9 F4 FF FF FF 2B 4C 24 ?? 6A 02 51 53 E8 ?? ?? ?? ?? 8B 54 24 ?? 8B 07 53 6A ?? 52 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 32 DB 8B C7 E8 ?? ?? ?? ?? 89 46 28 8B 0F 51 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 83 C4 ?? 5F 8B C6 5E 5B 33 CC E8 ?? ?? ?? ?? 81 C4 ?? ?? ?? ?? C3 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Maze.yar
## Windows_Ransomware_Maze
``` strings:
        $a1 = "Win32_ShadowCopy.id='%s'" wide fullword
        $a2 = "\"%s\" shadowcopy delete" wide fullword
        $a3 = "%spagefile.sys" wide fullword
        $a4 = "%sswapfile.sys" wide fullword
        $a5 = "Global\\%s" wide fullword
        $a6 = "DECRYPT-FILES.txt" wide fullword
        $a7 = "process call create \"cmd /c start %s\"" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Medusa.yar
## Windows_Ransomware_Medusa
``` strings:
        $a1 = "kill_processes %s" ascii fullword
        $a2 = "kill_services %s" ascii fullword
        $a3 = ":note path = %s" ascii fullword
        $a4 = "Write Note file error:%s" ascii fullword
        $a5 = "Rename file error:%s" ascii fullword
        $a6 = "G:\\Medusa\\Release\\gaze.pdb" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Mespinoza.yar
## Windows_Ransomware_Mespinoza
```  strings:
        $a1 = "Don't try to use backups because it were encrypted too." ascii fullword
        $a2 = "Every byte on any types of your devices was encrypted." ascii fullword
        $a3 = "n.pysa" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Mountlocker.yar
## Windows_Ransomware_Mountlocker
``` strings:
        $a1 = "[SKIP] locker.dir.check > black_list name=%s" wide fullword
        $a2 = "[OK] locker.dir.check > name=%s" wide fullword
        $a3 = "[ERROR] locker.worm > execute pcname=%s" wide fullword
        $a4 = "[INFO] locker.work.enum.net_drive > enum finish name=%s" wide fullword
        $a5 = "[WARN] locker.work.enum.server_shares > logon on server error=%u pcname=%s" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Nightsky.yar
## Windows_Ransomware_Nightsky
``` strings:
        $a1 = "\\NightSkyReadMe.hta" wide fullword
        $a2 = ".nightsky" wide fullword
        $a3 = "<h1 id=\"nightsky\"><center><span style=\"color: black; font-size: 48pt\">NIGHT SKY</span></center>" ascii fullword
        $a4 = "URL:https://contact.nightsky.cyou" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Pandora.yar
## Windows_Ransomware_Pandora
``` strings:
        $a1 = "/c vssadmin.exe delete shadows /all /quiet" wide fullword
        $a2 = "\\Restore_My_Files.txt" wide fullword
        $a3 = ".pandora" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Ragnarok.yar
## Windows_Ransomware_Ragnarok
``` strings:
        $a1 = "cmd_firewall" ascii fullword
        $a2 = "cmd_recovery" ascii fullword
        $a3 = "cmd_boot" ascii fullword
        $a4 = "cmd_shadow" ascii fullword
        $a5 = "readme_content" ascii fullword
        $a6 = "readme_name" ascii fullword
        $a8 = "rg_path" ascii fullword
        $a9 = "cometosee" ascii fullword
        $a10 = "&prv_ip=" ascii fullword
``` 
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Ransomexx.yar
## Windows_Ransomware_Ransomexx
```  strings:
        $a1 = "ransom.exx" ascii fullword
        $a2 = "Infrastructure rebuild will cost you MUCH more." wide fullword
        $a3 = "Your files are securely ENCRYPTED." wide fullword
        $a4 = "delete catalog -quiet" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Royal.yar
## Windows_Ransomware_Royal
```  strings:
        $a1 = "Try Royal today and enter the new era of data security" ascii fullword
        $a2 = "If you are reading this, it means that your system were hit by Royal ransomware." ascii fullword
        $a3 = "http://royal"
        $a4 = "\\README.TXT" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Ryuk.yar
## Windows_Ransomware_Ryuk
``` strings:
        $c1 = "/v \"svchos\" /f" wide fullword
        $c2 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii fullword
        $c3 = "lsaas.exe" wide fullword
        $c4 = "FA_Scheduler" wide fullword
        $c5 = "ocautoupds" wide fullword
        $c6 = "CNTAoSMgr" wide fullword
        $c7 = "hrmlog" wide fullword
        $c8 = "UNIQUE_ID_DO_NOT_REMOVE" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Snake.yar
## Windows_Ransomware_Snake
``` strings:
        $a1 = "Go build ID: \"X6lNEpDhc_qgQl56x4du/fgVJOqLlPCCIekQhFnHL/rkxe6tXCg56Ez88otHrz/Y-lXW-OhiIbzg3-ioGRz\"" ascii fullword
        $a2 = "We breached your corporate network and encrypted the data on your computers."
        $a3 = "c:\\users\\public\\desktop\\Fix-Your-Files.txt" nocase
        $a4 = "%System Root%\\Fix-Your-Files.txt" nocase
        $a5 = "%Desktop%\\Fix-Your-Files.txt" nocase
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Sodinokibi.yar
## Windows_Ransomware_Sodinokibi
```  strings:
        $d1 = { 03 C0 01 47 30 11 4F 34 01 57 30 8B 57 78 8B C2 11 77 34 8B 77 7C 8B CE 0F A4 C1 04 C1 E0 04 01 47 28 8B C2 11 4F 2C 8B CE 0F A4 C1 01 03 C0 01 47 28 11 4F 2C 01 57 28 8B 57 70 8B C2 11 77 2C 8B 77 74 8B CE 0F A4 C1 04 C1 E0 04 01 47 20 8B C2 11 4F 24 8B CE 0F A4 C1 01 03 C0 01 47 20 11 4F 24 01 57 20 8B 57 68 8B C2 11 77 24 8B 77 6C 8B CE 0F A4 C1 04 C1 E0 04 01 47 18 8B C2 11 4F 1C 8B CE 0F A4 C1 01 03 C0 01 47 18 11 4F 1C 01 57 18 8B 57 60 8B C2 11 77 1C 8B 77 64 }
        $d2 = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B 65 78 70 61 6E 64 20 31 36 2D 62 79 74 65 20 6B }
        $d3 = { F7 6F 38 03 C8 8B 43 48 13 F2 F7 6F 20 03 C8 8B 43 38 13 F2 F7 6F 30 03 C8 8B 43 40 13 F2 F7 6F 28 03 C8 8B 43 28 13 F2 F7 6F 40 03 C8 8B 45 08 13 F2 89 48 68 89 70 6C 8B 43 38 F7 6F 38 8B C8 8B F2 8B 43 28 F7 6F 48 03 C8 13 F2 8B 43 48 F7 6F 28 03 C8 8B 43 30 13 F2 F7 6F 40 0F A4 CE 01 03 C9 03 C8 8B 43 40 13 F2 F7 6F 30 03 C8 8B 45 08 13 F2 89 48 70 89 70 74 8B 43 38 F7 6F 40 8B C8 }
        $d4 = { 33 C0 8B 5A 68 8B 52 6C 0F A4 FE 08 C1 E9 18 0B C6 C1 E7 08 8B 75 08 0B CF 89 4E 68 8B CA 89 46 6C 33 C0 8B 7E 60 8B 76 64 0F A4 DA 19 C1 E9 07 0B C2 C1 E3 19 8B 55 08 0B CB 89 4A 60 8B CF 89 42 64 33 C0 8B 5A 10 8B 52 14 0F AC F7 15 C1 E1 0B C1 EE 15 0B C7 0B CE 8B 75 }
        $d5 = { C1 01 C1 EE 1F 0B D1 03 C0 0B F0 8B C2 33 43 24 8B CE 33 4B 20 33 4D E4 33 45 E0 89 4B 20 8B CB 8B 5D E0 89 41 24 8B CE 33 4D E4 8B C2 31 4F 48 33 C3 8B CF 31 41 4C 8B C7 8B CE 33 48 70 8B C2 33 47 74 33 4D E4 33 C3 89 4F 70 8B CF 89 41 74 8B }
        $d6 = { 8B 43 40 F7 6F 08 03 C8 8B 03 13 F2 F7 6F 48 03 C8 8B 43 48 13 F2 F7 2F 03 C8 8B 43 08 13 F2 F7 6F 40 03 C8 8B 43 30 13 F2 F7 6F 18 03 C8 8B 43 18 13 F2 F7 6F 30 03 C8 8B 43 38 13 F2 F7 6F 10 03 C8 8B 43 10 13 F2 F7 6F 38 03 C8 8B 43 28 13 F2 }
        $d7 = { 8B CE 33 4D F8 8B C2 33 C3 31 4F 18 8B CF 31 41 1C 8B C7 8B CE 33 48 40 8B C2 33 4D F8 33 47 44 89 4F 40 33 C3 8B CF 89 41 44 8B C7 8B CE 33 48 68 8B C2 33 47 6C 33 4D F8 33 C3 89 4F 68 8B CF 89 41 6C 8B CE 8B }
        $d8 = { 36 7D 49 30 85 35 C2 C3 68 60 4B 4B 7A BE 83 53 AB E6 8E 42 F9 C6 62 A5 D0 6A AD C6 F1 7D F6 1D 79 CD 20 FC E7 3E E1 B8 1A 43 38 12 C1 56 28 1A 04 C9 22 55 E0 D7 08 BB 9F 0B 1F 1C B9 13 06 35 }
        $d9 = { C2 C1 EE 03 8B 55 08 0B CE 89 4A 4C 8B CF 89 42 48 33 C0 8B 72 30 8B 52 34 C1 E9 0C 0F A4 DF 14 0B C7 C1 E3 14 8B 7D 08 0B CB 89 4F 30 8B CE 89 47 34 33 C0 C1 E1 0C 0F AC D6 14 0B C6 C1 EA 14 89 47 08 0B CA }
        $d10 = { 8B F2 8B 43 38 F7 6F 28 03 C8 8B 43 18 13 F2 F7 6F 48 03 C8 8B 43 28 13 F2 F7 6F 38 03 C8 8B 43 40 13 F2 F7 6F 20 0F A4 CE 01 03 C9 03 C8 8B 43 20 13 F2 F7 6F 40 03 C8 8B 43 30 13 F2 F7 6F 30 03 C8 }
        $d11 = { 33 45 FC 31 4B 28 8B CB 31 41 2C 8B CE 8B C3 33 48 50 8B C2 33 43 54 33 CF 33 45 FC 89 4B 50 8B CB 89 41 54 8B CE 8B C3 33 48 78 8B C2 33 43 7C 33 CF 33 45 FC 89 4B 78 8B CB 89 41 7C 33 B1 A0 }
        $d12 = { 52 24 0F A4 FE 0E C1 E9 12 0B C6 C1 E7 0E 8B 75 08 0B CF 89 4E 20 8B CA 89 46 24 33 C0 8B 7E 78 8B 76 7C 0F A4 DA 1B C1 E9 05 0B C2 C1 E3 1B 8B 55 08 0B CB 89 4A 78 8B CF 89 42 7C 33 C0 8B 9A }
        $d13 = { F2 8B 43 38 F7 6F 20 03 C8 8B 43 40 13 F2 F7 6F 18 03 C8 8B 43 10 13 F2 F7 6F 48 03 C8 8B 43 28 13 F2 F7 6F 30 03 C8 8B 43 20 13 F2 F7 6F 38 03 C8 8B 43 30 13 F2 F7 6F 28 03 C8 8B 43 48 13 F2 }
        $d14 = { 8B 47 30 13 F2 F7 6F 40 03 C8 13 F2 0F A4 CE 01 89 73 74 03 C9 89 4B 70 8B 47 30 F7 6F 48 8B C8 8B F2 8B 47 38 F7 6F 40 03 C8 13 F2 0F A4 CE 01 89 73 7C 03 C9 89 4B 78 8B 47 38 F7 6F 48 8B C8 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Stop.yar
## Windows_Ransomware_Stop
``` strings:
        $a = "E:\\Doc\\My work (C++)\\_Git\\Encryption\\Release\\encrypt_win_api.pdb" ascii fullword
        $b = { 68 FF FF FF 50 FF D3 8D 85 78 FF FF FF 50 FF D3 8D 85 58 FF FF FF C6 45 FC 01 50 FF D3 85 F6 79 36 56 68 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Thanos.yar
## Windows_Ransomware_Thanos
``` strings:
        $c1 = { 0C 89 45 F0 83 65 EC 00 EB 07 8B 45 EC 40 89 45 EC 83 7D EC 18 }
        $c2 = { E8 C1 E0 04 8B 4D FC C6 44 01 09 00 8B 45 E8 C1 E0 04 8B 4D FC 83 64 01 }
        $c3 = { 00 2F 00 18 46 00 54 00 50 00 20 00 55 00 73 00 65 00 72 00 4E 00 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Vgod.yar
## Windows_Ransomware_Vgod
```  strings:
        $a1 = "Vgod-Ransomware/configuration.init" fullword
        $a2 = "Vgod-Ransomware/encryption.EncryptFile" fullword
        $a3 = "/Vgod-Ransomware/Vgod-Ransomware/Encryptor/encryption/encryption.go" fullword
        $a4 = "main.removeBuiltExe" fullword
        $a5 = "Contact Mail: vgod@ro.ru" fullword
        $a6 = "Vgod-Built.exe" fullword
        $a7 = "indicate your ID and if you want attach 2-3 infected files to generate a private key and compile the decryptor" fullword
        $a8 = "--------- Attention ---------\nDo not rename encrypted files." fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Vhd.yar
## Windows_Ransomware_Vhd
``` strings:
        $binary_0 = { 57 8D 8D F0 FD FF FF 68 04 01 00 00 51 E8 ?? ?? ?? ?? 83 C4 0C 8D 95 CC FB FF FF 52 8D 85 F0 FD FF FF 68 04 01 00 00 }
        $binary_1 = { 8D 96 24 03 00 00 33 C0 C7 02 00 00 00 00 81 C3 24 03 00 00 8D 7A 04 B9 C8 00 00 00 F3 AB 8B 03 33 C9 89 02 85 C0 }
        $str_0 = "HowToDecrypt.txt" wide fullword
        $str_1 = "AEEAEE SET" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_WannaCry.yar
## Windows_Ransomware_WannaCry
``` strings:
        $a1 = "@WanaDecryptor@.exe" wide fullword
        $a2 = ".WNCRY" wide fullword
        $a3 = "$%d worth of bitcoin" fullword
        $a4 = "%d%d.bat" fullword
        $a5 = "This folder protects against ransomware. Modifying it will reduce protection" wide fullword
        $b1 = { 53 55 56 57 FF 15 D0 70 00 10 8B E8 A1 8C DD 00 10 85 C0 75 6A 68 B8 0B 00 00 FF 15 70 70 00 10 }
        $b2 = { A1 90 DD 00 10 53 56 57 85 C0 75 3E 8B 1D 60 71 00 10 8B 3D 70 70 00 10 6A 00 FF D3 83 C4 04 A3 }
        $b3 = { 56 8B 74 24 08 57 8B 3D 70 70 00 10 56 E8 2E FF FF FF 83 C4 04 A3 8C DD 00 10 85 C0 75 09 68 88 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_WhisperGate.yar
## Windows_Ransomware_WhisperGate
```  strings:
        $a1 = "cmd.exe /min /C ping 111.111.111.111 -n 5 -w 10 > Nul & Del /f /q \"%s\"" ascii fullword
        $a2 = "%.*s.%x" wide fullword
        $a3 = "A:\\Windows" wide fullword
        $a4 = ".ONETOC2" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_RemoteAdmin_UltraVNC.yar
## Windows_RemoteAdmin_UltraVNC
``` strings:
        $s1 = ".\\vncsockconnect.cpp"
        $s2 = ".\\vnchttpconnect.cpp"
        $s3 = ".\\vncdesktopthread.cpp"
        $s4 = "Software\\UltraVNC"
        $s5 = "VncCanvas.class"
        $s6 = "WinVNC_Win32_Instance_Mutex"
        $s7 = "WinVNC.AddClient"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Rootkit_AbyssWorker.yar
## Windows_Rootkit_AbyssWorker
``` strings:
        $a1 = "7N6bCAoECbItsUR5-h4Rp2nkQxybfKb0F-wgbJGHGh20pWUuN1-ZxfXdiOYps6HTp0X" wide fullword
        $a2 = "\\??\\fqg0Et4KlNt4s1JT" wide fullword
        $a3 = "\\device\\czx9umpTReqbOOKF" wide fullword
        $a4 = { 48 35 04 82 66 00 48 8B 4C 24 28 48 81 F1 17 24 53 00 48 03 C1 48 89 04 24 48 8B 04 24 48 C1 E0 05 48 8B 0C 24 48 C1 E9 1B 48 0B C1 }
        $a5 = { 48 35 04 82 66 00 48 8B 4C 24 08 48 0F AF C8 48 8B C1 48 8B 4C 24 08 48 81 E1 17 24 53 00 48 03 C1 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Rootkit_R77.yar
## Windows_Rootkit_R77
``` strings:
        $a = { 01 04 10 41 8B 4A 04 49 FF C1 48 8D 41 F8 48 D1 E8 4C 3B C8 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Shellcode_Generic.yar
## Windows_Shellcode_Generic
``` strings:
        $a1 = { FC 48 83 E4 F0 41 57 41 56 41 55 41 54 55 53 56 57 48 83 EC 40 48 83 EC 40 48 83 EC 40 48 89 E3 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Shellcode_Rdi.yar
## Windows_Shellcode_Rdi
``` strings:
        $a = { E8 00 00 00 00 59 49 89 C8 48 81 C1 23 0B 00 00 BA [10] 00 41 B9 04 00 00 00 56 48 89 E6 48 83 E4 F0 48 83 EC 30 C7 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_A310logger.yar
## Windows_Trojan_A310logger
``` strings:
        $a1 = "/dumps9taw" ascii fullword
        $a2 = "/logstatus" ascii fullword
        $a3 = "/checkprotection" ascii fullword
        $a4 = "[CLIPBOARD]<<" wide fullword
        $a5 = "&chat_id=" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_ACRStealer.yar
## Windows_Trojan_ACRStealer
``` strings:
        $a1 = { 55 8B EC 51 0F B6 45 ?? 83 F8 30 7C ?? 0F B6 4D ?? 83 F9 39 7E ?? 0F B6 55 ?? 83 FA 41 7C ?? 0F B6 45 ?? 83 F8 5A 7E ?? 0F B6 4D ?? 83 F9 61 7C ?? 0F B6 55 ?? 83 FA 7A 7E ?? 0F B6 45 ?? 83 F8 2B 74 ?? 0F B6 4D ?? 83 F9 2F 74 ?? C7 45 ?? ?? ?? ?? ?? EB ?? C7 45 }
        $a2 = "Error: no GetSystemMetrics" ascii fullword
        $a3 = "Error: no user32.dll" ascii fullword
        $a4 = { 8B ?? 24 C7 ?? ?? ?? ?? ?? 8B ?? F8 5? E8 ?? ?? ?? ?? 83 C4 04 8B ?? FC 5? FF 15 ?? ?? ?? ?? 33 C0 E9 }
        $a5 = { B8 ?? ?? ?? ?? EB ?? EB ?? B8 ?? ?? ?? ?? EB ?? 83 7D ?? 06 75 ?? 83 7D ?? 03 75 ?? B8 ?? ?? ?? ?? EB ?? 83 7D ?? 02 75 ?? B8 ?? ?? ?? ?? EB ?? 83 7D ?? 01 75 ?? B8 ?? ?? ?? ?? EB ?? 83 7D ?? 00 75 }
``` 
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Afdk.yar
## Windows_Trojan_Afdk
``` strings:
        $a1 = "Cannot set the log file name"
        $a2 = "Cannot install the hook procedure"
        $a3 = "Keylogger is up and running..."
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_AgentTesla.yar
## Windows_Trojan_AgentTesla
``` strings:
        $a1 = "GetMozillaFromLogins" ascii fullword
        $a2 = "AccountConfiguration+username" wide fullword
        $a3 = "MailAccountConfiguration" ascii fullword
        $a4 = "KillTorProcess" ascii fullword
        $a5 = "SmtpAccountConfiguration" ascii fullword
        $a6 = "GetMozillaFromSQLite" ascii fullword
        $a7 = "Proxy-Agent: HToS5x" wide fullword
        $a8 = "set_BindingAccountConfiguration" ascii fullword
        $a9 = "doUsernamePasswordAuth" ascii fullword
        $a10 = "SafariDecryptor" ascii fullword
        $a11 = "get_securityProfile" ascii fullword
        $a12 = "get_useSeparateFolderTree" ascii fullword
        $a13 = "get_DnsResolver" ascii fullword
        $a14 = "get_archivingScope" ascii fullword
        $a15 = "get_providerName" ascii fullword
        $a16 = "get_ClipboardHook" ascii fullword
        $a17 = "get_priority" ascii fullword
        $a18 = "get_advancedParameters" ascii fullword
        $a19 = "get_disabledByRestriction" ascii fullword
        $a20 = "get_LastAccessed" ascii fullword
        $a21 = "get_avatarType" ascii fullword
        $a22 = "get_signaturePresets" ascii fullword
        $a23 = "get_enableLog" ascii fullword
        $a24 = "TelegramLog" ascii fullword
        $a25 = "generateKeyV75" ascii fullword
        $a26 = "set_accountName" ascii fullword
        $a27 = "set_InternalServerPort" ascii fullword
        $a28 = "set_bindingConfigurationUID" ascii fullword
        $a29 = "set_IdnAddress" ascii fullword
        $a30 = "set_GuidMasterKey" ascii fullword
        $a31 = "set_username" ascii fullword
        $a32 = "set_version" ascii fullword
        $a33 = "get_Clipboard" ascii fullword
        $a34 = "get_Keyboard" ascii fullword
        $a35 = "get_ShiftKeyDown" ascii fullword
        $a36 = "get_AltKeyDown" ascii fullword
        $a37 = "get_Password" ascii fullword
        $a38 = "get_PasswordHash" ascii fullword
        $a39 = "get_DefaultCredentials" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Amadey.yar
## Windows_Trojan_Amadey
``` strings:
        $a = { 18 83 78 14 10 72 02 8B 00 6A 01 6A 00 6A 00 6A 00 6A 00 56 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Asyncrat.yar
## Windows_Trojan_Asyncrat
``` strings:
        $a1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" wide fullword
        $a2 = "Stub.exe" wide fullword
        $a3 = "get_ActivatePong" ascii fullword
        $a4 = "vmware" wide fullword
        $a5 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide fullword
        $a6 = "get_SslClient" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_AveMaria.yar
## Windows_Trojan_AveMaria
```  strings:
        $a1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " ascii fullword
        $a2 = "SMTP Password" wide fullword
        $a3 = "select signon_realm, origin_url, username_value, password_value from logins" ascii fullword
        $a4 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide fullword
        $a5 = "for /F \"usebackq tokens=*\" %%A in (\"" wide fullword
        $a6 = "\\Torch\\User Data\\Default\\Login Data" wide fullword
        $a7 = "/n:%temp%\\ellocnak.xml" wide fullword
        $a8 = "\"os_crypt\":{\"encrypted_key\":\"" wide fullword
        $a9 = "Hey I'm Admin" wide fullword
        $a10 = "\\logins.json" wide fullword
        $a11 = "Accounts\\Account.rec0" ascii fullword
        $a12 = "warzone160" ascii fullword
        $a13 = "Ave_Maria Stealer OpenSource github Link: https://github.com/syohex/java-simple-mine-sweeper" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Azorult.yar
## Windows_Trojan_Azorult
``` strings:
        $a1 = "/c %WINDIR%\\system32\\timeout.exe 3 & del \"" wide fullword
        $a2 = "%APPDATA%\\.purple\\accounts.xml" wide fullword
        $a3 = "%TEMP%\\curbuf.dat" wide fullword
        $a4 = "PasswordsList.txt" ascii fullword
        $a5 = "Software\\Valve\\Steam" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_BITSloth.yar
## Windows_Trojan_BITSloth
``` strings:
        $str_1 = "/%s/index.htm?RspID=%d" wide fullword
        $str_2 = "/%s/%08x.rpl" wide fullword
        $str_3 = "/%s/wu.htm" wide fullword
        $str_4 = "GET_DESKDOP" wide fullword
        $str_5 = "http://updater.microsoft.com/index.aspx" wide fullword
        $str_6 = "[U] update error..." wide fullword
        $str_7 = "RMC_KERNEL ..." wide fullword
        $seq_global_protocol_check = { 81 3D ?? ?? ?? ?? F9 03 00 00 B9 AC 0F 00 00 0F 46 C1 }
        $seq_exit_windows = { 59 85 C0 0F 84 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A 02 EB ?? 56 EB }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Babble.yar
## Windows_Trojan_Babble
```  strings:
        $a1 = { 24 48 0F B7 04 48 48 8B 4C 24 78 48 8B 09 8B 04 81 48 8B 4C 24 78 48 03 41 20 48 89 44 24 28 48 }
        $a2 = { 44 24 34 C1 E0 08 0F B6 4C 24 35 0F B7 54 24 20 03 CA 0B C1 48 8B 8C 24 80 00 00 00 89 01 EB 05 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Babylonrat.yar
## Windows_Trojan_Babylonrat
``` strings:
        $a1 = "BabylonRAT" wide fullword
        $a2 = "Babylon RAT Client" wide fullword
        $a3 = "ping 0 & del \"" wide fullword
        $a4 = "\\%Y %m %d - %I %M %p" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Backoff.yar
## Windows_Trojan_Backoff
```  strings:
        $str1 = "\\nsskrnl" fullword
        $str2 = "Upload KeyLogs" fullword
        $str3 = "&op=%d&id=%s&ui=%s&wv=%d&gr=%s&bv=%s" fullword
        $str4 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword
        $str5 = "\\OracleJava\\Log.txt" fullword
        $str6 = "[Ctrl+%c]" fullword
``` 
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Bandook.yar
## Windows_Trojan_Bandook
```  strings:
        $str1 = "%s~!%s~!%s~!%s~!%s~!%s~!"
        $str2 = "ammyy.abc"
        $str3 = "StealUSB"
        $str4 = "DisableMouseCapture"
        $str5 = "%sSkype\\%s\\config.xml"
        $str6 = "AVE_MARIA"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Bazar.yar
## Windows_Trojan_Bazar
``` strings:
        $a = { 0F 94 C3 41 0F 95 C0 83 FA 0A 0F 9C C1 83 FA 09 0F 9F C2 31 C0 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Beam.yar
## Windows_Trojan_Beam
``` strings:
        $a1 = { 69 70 22 3A 22 28 5B 30 2D 39 2E 5D 2B 29 }
        $a2 = { 63 6F 75 6E 74 72 79 5F 63 6F 64 65 22 3A 22 28 5C 77 2A 29 }
        $a3 = { 20 2F 66 20 26 20 65 72 61 73 65 20 }
        $a4 = "\\BeamWinHTTP2\\Release\\BeamWinHTTP.pdb"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Behinder.yar
## Windows_Trojan_Behinder
``` strings:
        $load = { 53 79 73 74 65 6D 2E 52 65 66 6C 65 63 74 69 6F 6E 2E 41 73 73 65 6D 62 6C 79 }
        $key = "e45e329feb5d925b" ascii wide
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Bitrat.yar
## Windows_Trojan_Bitrat
``` strings:
        $a1 = "crd_logins_report" ascii fullword
        $a2 = "drives_get" ascii fullword
        $a3 = "files_get" ascii fullword
        $a4 = "shell_stop" ascii fullword
        $a5 = "hvnc_start_ie" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_BlackShades.yar
## Windows_Trojan_BlackShades
``` strings:
        $a1 = "*\\AD:\\Blackshades Project\\bs_net\\server\\server.vbp" wide fullword
        $a2 = "@*\\AD:\\Blackshades Project\\bs_net\\server\\server.vbp" wide fullword
        $a3 = "D:\\Blackshades Project\\bs_net\\loginserver\\msvbvm60.dll\\3" ascii fullword
        $b1 = "modSniff" ascii fullword
        $b2 = "UDPFlood" ascii fullword
        $b3 = "\\nir_cmd.bss speak text " wide fullword
        $b4 = "\\pws_chro.bss" wide fullword
        $b5 = "tmrLiveLogger" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Blackwood.yar
## Windows_Trojan_Blackwood
``` strings:
        $a1 = { 5F 8C FB 62 69 00 65 00 78 00 70 00 6C 00 6F 00 72 00 65 00 2E 00 65 00 78 00 65 00 }
        $a2 = { C6 44 24 0C 6D C6 44 24 0D 73 C6 44 24 0E 68 C6 44 24 10 70 C6 44 24 11 2E C6 44 24 12 64 }
        $a3 = { 6D 79 6E 73 70 2E 64 6C 6C 00 4E 53 50 43 6C 65 61 6E 75 70 00 4E 53 50 53 74 61 72 74 75 70 }
        $b1 = "index.dat"
        $b2 = "Mozilla/4.0 (compatible;MSIE 5.0; Windows 98)"
        $b3 = "http://www.baidu.com/id=%s&ad=%d&os=%d.%d&t=%d"
        $b4 = "SetEntriesInAcl Error %u"
        $b5 = "AllocateAndInitializeSid Error %u"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_BloodAlchemy.yar
## Windows_Trojan_BloodAlchemy
```  strings:
        $a1 = { 55 8B EC 51 83 65 FC 00 53 56 57 BF 00 20 00 00 57 6A 40 FF 15 }
        $a2 = { 55 8B EC 81 EC 80 00 00 00 53 56 57 33 FF 8D 45 80 6A 64 57 50 89 7D E4 89 7D EC 89 7D F0 89 7D }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_BruteRatel.yar
## Windows_Trojan_BruteRatel
``` strings:
        $a1 = "[+] Spoofed PPID => %lu" wide fullword
        $a2 = "[-] Child process not set" wide fullword
        $a3 = "[+] Crisis Monitor: Already Running" wide fullword
        $a4 = "[+] Screenshot downloaded: %S" wide fullword
        $a5 = "s[-] Duplicate listener: %S" wide fullword
        $a6 = "%02d%02d%d_%02d%02d%2d%02d.png" wide fullword
        $a7 = "[+] Added Socks Profile" wide fullword
        $a8 = "[+] Dump Size: %d Mb" wide fullword
        $a9 = "[+] Enumerating PID: %lu [%ls]" wide fullword
        $a10 = "[+] Dump Size: %d Mb" wide fullword
        $a11 = "[+] SAM key: " wide fullword
        $a12 = "[+] Token removed: '%ls'" wide fullword
        $a13 = "[Tasks] %02d => 0x%02X 0x%02X" wide fullword
        $b1 = { 48 83 EC ?? 48 8D 35 ?? ?? ?? ?? 4C 63 E2 31 D2 48 8D 7C 24 ?? 48 89 CB 4D 89 E0 4C 89 E5 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 A4 31 F6 BF ?? ?? ?? ?? 39 F5 7E ?? E8 ?? ?? ?? ?? 99 F7 FF 48 63 D2 8A 44 14 ?? 88 04 33 48 FF C6 EB ?? }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Buerloader.yar
## Windows_Trojan_Buerloader
``` strings:
        $a1 = "User-Agent: Host:  HTTP/1.1" ascii fullword
        $a2 = "ServerHelloPayloadrandom" ascii fullword
        $a3 = "Bad JSON in payload" ascii fullword
        $a4 = { 7B 22 68 65 6C 6C 6F 22 3A 20 22 77 6F 72 6C 64 22 7D 48 54 54 50 2F 31 2E 31 20 33 30 31 20 46 6F 75 6E 64 }
        $a5 = "PayloadU24UnknownExtensiontyp" ascii fullword
        $a6 = " NTDLL.DLL" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Carberp.yar
## Windows_Trojan_Carberp
``` strings:
        $a1 = ".NET CLR Networking_Perf_Library_Lock_PID_0" ascii wide fullword
        $a2 = "FakeVNCWnd" ascii wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_CastleLoader.yar
## Windows_Trojan_CastleLoader
```  strings:
        $a = { 8B 34 BA 33 DB 03 F1 BA AA AA AA AA 38 1E 74 ?? 0F BE 0C 1E 8B C2 F6 C3 01 75 ?? C1 E8 03 0F AF C1 8B CA C1 E1 07 33 C1 EB ?? C1 E8 05 33 C1 8B CA C1 E1 0B 03 C1 F7 D0 43 33 D0 }
        $b = { 8D 42 ?? 83 E0 03 0F B6 80 ?? ?? ?? ?? 66 33 44 0C ?? 66 89 84 0C ?? ?? ?? ?? 8D 42 ?? 83 E0 03 0F B6 80 ?? ?? ?? ?? 66 33 44 0C ?? 66 89 84 0C }
        $c = { 3D 20 6C 72 70 75 ?? 81 7D F8 65 70 79 68 75 ?? 81 7D F4 20 20 76 72 75 ?? B9 01 }
        $d = { 69 C0 6D 4E C6 41 05 39 30 00 00 }
        $e = { 83 7C 24 ?? 20 0F 85 ?? ?? ?? ?? 80 7C 24 ?? B8 0F 85 ?? ?? ?? ?? B9 01 00 00 00 C7 44 24 ?? B8 BB 00 00 C7 44 24 ?? C0 C2 10 00 C7 44 24 ?? 00 00 00 00 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Clipbanker.yar
## Windows_Trojan_Clipbanker
``` strings:
        $a1 = "C:\\Users\\youar\\Desktop\\Allcome\\Source code\\Build\\Release\\Build.pdb" ascii fullword
        $b1 = "https://steamcommunity.com/tradeoffer" ascii fullword
        $b2 = "/Create /tn NvTmRep_CrashReport3_{B2FE1952-0186} /sc MINUTE /tr %s" ascii fullword
        $b3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0" ascii fullword
        $b4 = "ProcessHacker.exe" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_CobaltStrike.yar
## Windows_Trojan_CobaltStrike
``` strings:
        $a1 = "bypassuac.dll" ascii fullword
        $a2 = "bypassuac.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\bypassuac" ascii fullword
        $b1 = "\\System32\\sysprep\\sysprep.exe" wide fullword
        $b2 = "[-] Could not write temp DLL to '%S'" ascii fullword
        $b3 = "[*] Cleanup successful" ascii fullword
        $b4 = "\\System32\\cliconfg.exe" wide fullword
        $b5 = "\\System32\\eventvwr.exe" wide fullword
        $b6 = "[-] %S ran too long. Could not terminate the process." ascii fullword
        $b7 = "[*] Wrote hijack DLL to '%S'" ascii fullword
        $b8 = "\\System32\\sysprep\\" wide fullword
        $b9 = "[-] COM initialization failed." ascii fullword
        $b10 = "[-] Privileged file copy failed: %S" ascii fullword
        $b11 = "[-] Failed to start %S: %d" ascii fullword
        $b12 = "ReflectiveLoader"
        $b13 = "[-] '%S' exists in DLL hijack location." ascii fullword
        $b14 = "[-] Cleanup failed. Remove: %S" ascii fullword
        $b15 = "[+] %S ran and exited." ascii fullword
        $b16 = "[+] Privileged file copy success! %S" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DCRat.yar
## Windows_Trojan_DCRat
``` strings:
        $a1 = "havecamera" ascii fullword
        $a2 = "timeout 3 > NUL" wide fullword
        $a3 = "START \"\" \"" wide fullword
        $a4 = "L2Mgc2NodGFza3MgL2NyZWF0ZSAvZiAvc2Mgb25sb2dvbiAvcmwgaGlnaGVzdCAvdG4g" wide fullword
        $a5 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA==" wide fullword
        $b1 = "DcRatByqwqdanchun" ascii fullword
        $b2 = "DcRat By qwqdanchun1" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DTrack.yar
## Windows_Trojan_DTrack
``` strings:
        $str_0 = "%sExecute_%s.log" fullword
        $str_1 = "%02X:%02X:%02X:%02X:%02X:%02X" fullword
        $str_2 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d : " fullword
        $log_0 = "[+] DownloadToFile" fullword
        $log_1 = "[+] DownloadCommand" fullword
        $log_2 = "[+] StartupThread" fullword
        $log_3 = "[+] Connect" fullword
        $log_4 = "[+] CPT.." fullword
        $binary_0 = { 8B 45 ?? C1 E8 08 8B 4D ?? C1 E9 02 33 4D ?? 8B 55 ?? C1 EA 03 33 CA 8B 55 ?? C1 EA 07 33 CA }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Danabot.yar
## Windows_Trojan_Danabot
``` strings:
        $a1 = "%s.dll" ascii fullword
        $a2 = "del_ini://Main|Password|" wide fullword
        $a3 = "S-Password.txt" wide fullword
        $a4 = "BiosTime:" wide fullword
        $a5 = "%lu:%s:%s:%d:%s" ascii fullword
        $a6 = "DNS:%s" ascii fullword
        $a7 = "THttpInject&" ascii fullword
        $a8 = "TCookies&" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DarkVNC.yar
## Windows_Trojan_DarkVNC
```  strings:
        $a1 = "BOT-%s(%s)_%S-%S%u%u" wide fullword
        $a2 = "{%08X-%04X-%04X-%04X-%08X%04X}" wide fullword
        $a3 = "monitor_off / monitor_on" ascii fullword
        $a4 = "bot_shell >" ascii fullword
        $a5 = "keyboard and mouse are blocked !" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Darkcomet.yar
## Windows_Trojan_Darkcomet
``` strings:
        $a1 = "BTRESULTHTTP Flood|Http Flood task finished!|" ascii fullword
        $a2 = "is now open!|" ascii fullword
        $a3 = "ActiveOnlineKeylogger" ascii fullword
        $a4 = "#BOT#RunPrompt" ascii fullword
        $a5 = "GETMONITORS" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Deimos.yar
## Windows_Trojan_Deimos
```  strings:
        $a1 = "\\APPDATA\\ROAMING" wide fullword
        $a2 = "{\"action\":\"ping\",\"" wide fullword
        $a3 = "Deimos" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DiamondFox.yar
## Windows_Trojan_DiamondFox
```  strings:
        $a1 = "\\wscript.vbs" wide fullword
        $a2 = "\\snapshot.jpg" wide fullword
        $a3 = "&soft=" wide fullword
        $a4 = "ping -n 4 127.0.0.1 > nul" wide fullword
        $a5 = "Select Name from Win32_Process Where Name = '" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Diceloader.yar
## Windows_Trojan_Diceloader
``` strings:
        $a1 = "D$0GET " ascii fullword
        $a2 = "D$THostf" ascii fullword
        $a3 = "D$,POST" ascii fullword
        $a4 = "namef" ascii fullword
        $a5 = "send" ascii fullword
        $a6 = "log.ini" wide
        $a7 = { 70 61 73 73 00 00 65 6D 61 69 6C 00 00 6C 6F 67 69 6E 00 00 73 69 67 6E 69 6E 00 00 61 63 63 6F 75 6E 74 00 00 70 65 72 73 69 73 74 65 6E 74 00 00 48 6F 73 74 3A 20 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DoorMe.yar
## Windows_Trojan_DoorMe
``` strings:
        $seq_aes_crypto = { 8B 6C 24 ?? C1 E5 ?? 8B 5C 24 ?? 8D 34 9D ?? ?? ?? ?? 0F B6 04 31 32 44 24 ?? 88 04 29 8D 04 9D ?? ?? ?? ?? 0F B6 04 01 32 44 24 ?? 88 44 29 ?? 8D 04 9D ?? ?? ?? ?? 0F B6 04 01 44 30 F8 88 44 29 ?? 8D 04 9D ?? ?? ?? ?? 0F B6 04 01 44 30 E0 88 44 29 ?? 8B 74 24 ?? }
        $seq_copy_str = { 48 8B 44 24 ?? 48 89 58 ?? 48 89 F1 4C 89 F2 49 89 D8 E8 ?? ?? ?? ?? C6 04 1E ?? }
        $seq_md5 = { 89 F8 44 21 C8 44 89 C9 F7 D1 21 F1 44 01 C0 01 C8 44 8B AC 24 ?? ?? ?? ?? 8B 9C 24 ?? ?? ?? ?? 48 89 B4 24 ?? ?? ?? ?? 44 89 44 24 ?? 46 8D 04 28 41 81 C0 ?? ?? ?? ?? 4C 89 AC 24 ?? ?? ?? ?? 41 C1 C0 ?? 45 01 C8 44 89 C1 44 21 C9 44 89 C2 F7 D2 21 FA 48 89 BC 24 ?? ?? ?? ?? 8D 2C 1E 49 89 DC 01 D5 01 E9 81 C1 ?? ?? ?? ?? C1 C1 ?? 44 01 C1 89 CA 44 21 C2 89 CD F7 D5 44 21 CD 8B 84 24 ?? ?? ?? ?? 48 89 44 24 ?? 8D 1C 07 01 EB 01 DA 81 C2 ?? ?? ?? ?? C1 C2 ?? }
        $seq_calc_key = { 31 FF 48 8D 1D ?? ?? ?? ?? 48 83 FF ?? 4C 89 F8 77 ?? 41 0F B6 34 3E 48 89 F1 48 C1 E9 ?? 44 0F B6 04 19 BA ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? 83 E6 ?? 44 0F B6 04 1E BA ?? ?? ?? ?? 48 8B 4D ?? E8 ?? ?? ?? ?? 48 83 C7 ?? }
        $seq_base64 = { 8A 45 ?? 8A 4D ?? C0 E0 ?? 89 CA C0 EA ?? 80 E2 ?? 08 C2 88 55 ?? C0 E1 ?? 8A 45 ?? C0 E8 ?? 24 ?? 08 C8 88 45 ?? 41 83 C4 ?? 31 F6 44 39 E6 7D ?? 66 90 }
        $str_0 = ".?AVDoorme@@" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DoubleBack.yar
## Windows_Trojan_DoubleBack
``` strings:
        $s1 = "client.dll" ascii fullword
        $s2 = "=i.ext;" ascii fullword
        $s3 = "## dbg delay" ascii fullword
        $s4 = "ehost"
        $s5 = "msie"
        $s6 = "POST"
        $s7 = "%s(%04Xh:%u/%u)[%s %s]: %s" ascii fullword
        $x64_powershell_msi_check = { 81 3C 39 70 6F 77 65 74 ?? 81 3C 39 6D 73 69 65 41 }
        $x86_powershell_msi_check = { 81 3C 30 70 6F 77 65 74 ?? 81 3C 30 6D 73 69 65 6A 03 5A 0F }
        $x64_salted_hash_func = { 8B 7D ?? 4C 8D 45 ?? 81 C7 ?? ?? ?? ?? 48 8D 4D ?? BA 04 00 00 00 89 7D ?? }
        $x86_salted_hash_func = { 8B 75 ?? 8D 45 ?? 50 6A ?? 81 C6 ?? ?? ?? ?? 8D 4D ?? 5A 89 75 ?? }
        $x64_guid = { 48 83 EC ?? 45 33 C9 41 B8 DD CC BB AA 45 8D 51 ?? }
        $x86_guid = { 55 8B EC 83 EC ?? B8 DD CC BB AA 56 57 6A ?? 8D 75 ?? 5F }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DoubleLoader.yar
## Windows_Trojan_DoubleLoader
```  strings:
        $str1 = "GetSettingsFromRegistry failed" ascii fullword
        $str2 = "Install persistence failed" ascii fullword
        $str3 = "Connect to remote port using Afd driver failed" ascii fullword
        $str4 = "/obfdownload/DoubleLoaderDll.dll" ascii fullword
        $str5 = "Invalid response status code for download file. not 200 OK" ascii fullword
        $str6 = "Failed to send HTTP/1.1 request to server for download file" ascii fullword
        $path = "D:\\projects\\DoubleLoader_net4\\DoubleLoader\\x64\\Release\\Loader.pdb" ascii fullword
        $path2 = "d:\\projects\\doubleloader_net4\\doubleloader\\cryptopp\\sha_simd.cpp" ascii fullword
        $path3 = "d:\\projects\\doubleloader_net4\\doubleloader\\cryptopp\\gf2n_simd.cpp" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DownTown.yar
## Windows_Trojan_DownTown
``` strings:
        $a1 = "SendFileBuffer error -1 !!!" fullword
        $a2 = "ScheduledDownloadTasks CODE_FILE_VIEW " fullword
        $a3 = "ExplorerManagerC.dll" fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DragonBreath.yar
## Windows_Trojan_DragonBreath
``` strings:
        $a1 = { 50 6C 75 67 69 6E 4D 65 }
        $a2 = { 69 73 41 52 44 6C 6C }
        $a3 = { 25 64 2D 25 64 2D 25 64 20 25 64 3A 25 64 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DreamJob.yar
## Windows_Trojan_DreamJob
``` strings:
        $binary_0 = { 65 77 F2 CA [3-6] D1 BF 63 75 [3-6] C1 6D 7F BE [3-6] 6A 7E DE 87 [3-6] 9C D5 84 9A [3-6] C1 7E 92 D8 }
        $str_0 = "Cookie=Enable&CookieV=%d&Cookie_Time="
        $str_1 = "Authentication Success" fullword
        $str_2 = "Cookie=Enable" fullword
        $str_3 = "Authentication Error" fullword
        $str_4 = "%d-101010" fullword
        $str_5 = "%d-202020" fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_DustyWarehouse.yar
## Windows_Trojan_DustyWarehouse
```  strings:
        $a1 = "%4d.%2d.%2d-%2d:%2d:%2d" wide fullword
        $a2 = ":]%d-%d-%d %d:%d:%d" wide fullword
        $a3 = "\\sys.key" wide fullword
        $a4 = "[rwin]" wide fullword
        $a5 = "Software\\Tencent\\Plugin\\VAS" fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_FalseFont.yar
## Windows_Trojan_FalseFont
``` strings:
        $s1 = "KillById"
        $s2 = "KillByName"
        $s3 = "SignalRHub"
        $s4 = "ExecUseShell"
        $s5 = "ExecAndKeepAlive"
        $s6 = "SendAllDirectoryWithStartPath"
        $s7 = "AppLiveDirectorySendHard"
        $s8 = "AppLiveDirectorySendScreen"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_FinalDraft.yar
## Windows_Trojan_FinalDraft
```  strings:
        $seq_derive_encryption_key = { 4D 6B C0 1F 48 0F BE 02 4C 03 C0 48 03 D7 49 3B D2 }
        $seq_decrypt_configuration = { 48 8B ?? 83 E0 ?? [4-9] 30 04 0A 48 [2] 48 81 ?? 9A 14 00 00 72 }
        $seq_magic = { 12 34 AB CD FF FF CD AB 34 12 }
        $str_injection_target_0 = "%c:\\Windows\\SysWOW64\\mspaint.exe" fullword
        $str_injection_target_1 = "%c:\\Windows\\System32\\mspaint.exe" fullword
        $str_injection_target_2 = "%c:\\Windows\\SysWOW64\\conhost.exe" fullword
        $str_injection_target_3 = "%c:\\Windows\\System32\\conhost.exe" fullword
        $str_active_connections_fmt_str = "%-7s%-34s%-34s%-13s%-7s" fullword
        $str_graph_parameters = "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&grant_type=refresh" fullword
        $str_err_code = "err code: 0x%08x" fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_FlawedGrace.yar
## Windows_Trojan_FlawedGrace
``` strings:
        $a1 = "Grace finalized, no more library calls allowed." ascii fullword
        $a2 = ".?AVReadThread@TunnelIO@NS@@" ascii fullword
        $a3 = ".?AVTunnelClientDirectIO@NS@@" ascii fullword
        $a4 = ".?AVWireClientConnectionThread@NS@@" ascii fullword
        $a5 = ".?AVWireParam@NS@@" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Formbook.yar
## Windows_Trojan_Formbook
``` strings:
        $a1 = { 3C 30 50 4F 53 54 74 09 40 }
        $a2 = { 74 0A 4E 0F B6 08 8D 44 08 01 75 F6 8D 70 01 0F B6 00 8D 55 }
        $a3 = { 1A D2 80 E2 AF 80 C2 7E EB 2A 80 FA 2F 75 11 8A D0 80 E2 01 }
        $a4 = { 04 83 C4 0C 83 06 07 5B 5F 5E 8B E5 5D C3 8B 17 03 55 0C 6A 01 83 }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Gh0st.yar
## Windows_Trojan_Gh0st
``` strings:
        $a1 = ":]%d-%d-%d  %d:%d:%d" ascii fullword
        $a2 = "[Pause Break]" ascii fullword
        $a3 = "f-secure.exe" ascii fullword
        $a4 = "Accept-Language: zh-cn" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Glupteba.yar
## Windows_Trojan_Glupteba
``` strings:
        $a1 = "%TEMP%\\app.exe && %TEMP%\\app.exe"
        $a2 = "is unavailable%d smbtest"
        $a3 = "discovered new server %s"
        $a4 = "uldn't get usernamecouldn't hide servicecouldn't"
        $a5 = "TERMINATE PROCESS: %ws, %d, %d" ascii fullword
        $a6 = "[+] Extracting vulnerable driver as \"%ws\"" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Gozi.yar
## Windows_Trojan_Gozi
``` strings:
        $a1 = "/C ping localhost -n %u && del \"%s\"" wide fullword
        $a2 = "/C \"copy \"%s\" \"%s\" /y && \"%s\" \"%s\"" wide fullword
        $a3 = "/C \"copy \"%s\" \"%s\" /y && rundll32 \"%s\",%S\"" wide fullword
        $a4 = "ASCII.GetString(( gp \"%S:\\%S\").%s))',0,0)" wide
        $a5 = "filename=\"%.4u.%lu\""
        $a6 = "Urundll32 \"%s\",%S" wide fullword
        $a7 = "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s" ascii fullword
        $a8 = "%08X-%04X-%04X-%04X-%08X%04X" ascii fullword
        $a9 = "&whoami=%s" ascii fullword
        $a10 = "%u.%u_%u_%u_x%u" ascii fullword
        $a11 = "size=%u&hash=0x%08x" ascii fullword
        $a12 = "&uptime=%u" ascii fullword
        $a13 = "%systemroot%\\system32\\c_1252.nls" ascii fullword
        $a14 = "IE10RunOnceLastShown_TIMESTAMP" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Grandoreiro.yar
## Windows_Trojan_Grandoreiro
``` strings:
        $antivm0 = { B8 68 58 4D 56 BB 12 F7 6C 3C B9 0A 00 00 00 66 BA 58 56 ED B8 01 00 00 00 }
        $antivm1 = { B9 [4] 89 E5 53 51 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 BB 00 00 00 00 B8 01 00 00 00 0F 3F 07 0B }
        $xor0 = { 0F B7 44 70 ?? 33 D8 8D 45 ?? 50 89 5D ?? }
        $xor1 = { 8B 45 ?? 0F B7 44 70 ?? 33 C3 89 45 ?? }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_GuidLoader.yar
## Windows_Trojan_GuidLoader
``` strings:
        $seq1 = { 75 ?? B9 88 13 00 00 FF 15 ?? ?? ?? ?? 48 FF C? 48 83 F? }
        $seq2 = { 48 8B 55 ?? 48 83 FA 10 72 ?? 48 FF C2 48 8B 4D ?? 48 8B C1 48 81 FA 00 10 00 00 }
        $seq3 = { C1 E8 ?? 03 D0 0F BE C2 6B C8 ?? 41 0F B6 C0 41 FF C0 2A C1 04 ?? 41 30 41 ?? 41 83 F8 ?? 7C ?? }
        $seq4 = { 66 0F DB 15 ?? ?? 00 00 66 0F 67 D2 66 0F FC 15 ?? ?? 00 00 66 0F EF D0 66 0F 62 CB }
        $seq5 = "Download" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Guloader.yar
## Windows_Trojan_Guloader
```  strings:
        $a1 = "msvbvm60.dll" wide fullword
        $a2 = "C:\\Program Files\\qga\\qga.exe" ascii fullword
        $a3 = "C:\\Program Files\\Qemu-ga\\qemu-ga.exe" ascii fullword
        $a4 = "USERPROFILE=" wide fullword
        $a5 = "Startup key" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Hancitor.yar
## Windows_Trojan_Hancitor
``` strings:
        $a1 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d"
        $b1 = "Rundll32.exe %s, start" ascii fullword
        $b2 = "MASSLoader.dll" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Havoc.yar
## Windows_Trojan_Havoc
``` strings:
        $core = { 48 ?? ?? 2C 06 00 00 00 ?? ?? 48 ?? ?? 5C 06 00 00 00 ?? ?? ?? ?? ?? ?? 48 8B ?? 5C 06 00 00 ?? F6 99 5A 2E E8 ?? ?? ?? ?? 48 8B ?? 48 ?? ?? 4C 02 00 00 48 8B ?? 5C 06 00 00 ?? 23 DB 07 03 E8 ?? ?? ?? ?? 48 8B ?? 48 ?? ?? 44 02 00 00 48 8B ?? 5C 06 00 00 ?? DA 81 B3 C0 E8 ?? ?? ?? ?? 48 8B ?? 48 ?? ?? 54 02 00 00 48 8B ?? 5C 06 00 00 ?? D7 71 BA 70 E8 ?? ?? ?? ?? 48 8B ?? 48 ?? ?? 64 02 00 00 48 8B ?? 5C 06 00 00 ?? 88 2B 49 8E E8 ?? ?? ?? ?? 48 8B ?? 48 ?? ?? 84 02 00 00 48 8B ?? 5C 06 00 00 ?? EF F0 A1 3A E8 ?? ?? ?? ?? }
        $commands_table = { 0B 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 64 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 15 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 10 10 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 0C 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? [0-12] 0F 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 14 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 01 20 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 03 20 00 00 ?? ?? ?? ?? ?? ?? ?? ?? C4 09 00 00 ?? ?? ?? ?? ?? ?? ?? ?? CE 09 00 00 ?? ?? ?? ?? ?? ?? ?? ?? D8 09 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 34 08 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 16 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 18 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 1A 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 28 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 5C 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }
        $hashes_0 = { F6 99 5A 2E }
        $hashes_1 = { DA 81 B3 C0 }
        $hashes_2 = { D7 71 BA 70 }
        $hashes_3 = { 88 2B 49 8E }
        $hashes_4 = { EF F0 A1 3A }
        $hashes_5 = { F5 39 34 7C }
        $hashes_6 = { 2A 92 12 D8 }
        $hashes_7 = { 8D F1 4F 84 }
        $hashes_8 = { 5B BC CE 73 }
        $hashes_9 = { 59 24 93 B8 }
        $hashes_10 = { 02 9E D0 C2 }
        $hashes_11 = { E5 36 26 AE }
        $hashes_12 = { 5C 3C B4 F3 }
        $hashes_13 = { 2F 87 D8 1C }
        $hashes_14 = { D7 53 22 AC }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Hawkeye.yar
## Windows_Trojan_Hawkeye
``` strings:
        $a1 = "Logger - Key Recorder - [" wide fullword
        $a2 = "http://whatismyipaddress.com/" wide fullword
        $a3 = "Keylogger Enabled: " wide fullword
        $a4 = "LoadPasswordsSeaMonkey" wide fullword
        $a5 = "\\.minecraft\\lastlogin" wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_HazelCobra.yar
## Windows_Trojan_HazelCobra
``` strings:
        $a1 = { 83 E9 37 48 63 C2 F6 C2 01 75 0C C0 E1 04 48 D1 F8 88 4C 04 40 EB 07 }
        $s1 = "Data file loaded. Running..." fullword
        $s2 = "No key in args" fullword
        $s3 = "Can't read data file" fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_HiddenDriver.yar
## Windows_Trojan_HiddenDriver
``` strings:
        $activeProcessLinksOffsets = { C7 44 24 20 E8 00 00 00 C7 44 24 24 88 01 00 00 C7 44 24 28 E8 02 00 00 C7 44 24 2C F0 02 00 00 C7 44 24 30 48 04 00 00 }
        $alloc_table = { 48 83 63 78 00 48 8D 8B 88 00 00 00 83 A3 80 00 00 00 00 B8 01 00 00 00 8B D0 48 89 43 68 45 33 C0 89 43 70 }
        $str_0 = "InitializePsMonitor"
        $str_1 = "image load notify registartion failed with code:%08x"
        $str_2 = "file-system mini-filter haven't started"
        $str_3 = "can't activate stealth mode"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_HijackLoader.yar
## Windows_Trojan_HijackLoader
``` strings:
        $a1 = { 8B 45 ?? 40 89 45 ?? 8B 45 ?? 3B 45 ?? 73 ?? 8B 45 ?? 03 45 ?? 66 0F BE 00 66 89 45 ?? FF 75 ?? FF 75 ?? 8D 45 ?? 50 E8 [4] 83 C4 0C EB ?? }
        $a2 = { 8B 45 ?? 8B 4D ?? 8B [1-5] 0F AF [1-5] 0F B7 [2] 03 C1 8B 4D ?? 89 01 }
        $a3 = { 33 C0 40 74 ?? 8B 45 ?? 8B 4D ?? 8B 55 ?? 03 14 81 89 55 ?? FF 75 ?? FF 75 ?? E8 [4] 59 59 89 45 ?? 8B 45 ?? 8B 4D ?? 0F B7 04 41 8B 4D ?? 8B 55 ?? 03 14 81 89 55 ?? 8B 45 ?? 3B 45 ?? 75 ?? 8B 45 ?? EB ?? 8B 45 ?? 40 89 45 ?? EB ?? }
        $a4 = { 8B 45 ?? 8B 4D ?? 8B [1-5] 0F AF [1-5] 0F B7 4D ?? 03 C1 8B 4D ?? 89 01 }
        $a5 = { 8B 45 ?? 83 C0 04 89 45 ?? 8B 45 ?? 3B 45 ?? 73 ?? 8B 45 ?? 8B 4D ?? 8B 04 81 03 45 ?? 8B 4D ?? 8B 55 ?? 89 04 8A 8B 45 ?? 40 89 45 ?? EB ?? }
        $a6 = { 8B 45 ?? 83 C0 04 89 45 ?? 8B 45 ?? 3B 45 ?? 73 ?? 8B 45 ?? 03 45 ?? 89 45 ?? 8B 45 ?? 8B 00 89 45 ?? 8B 45 ?? 33 45 ?? 8B 4D ?? 89 01 EB ?? }
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_HotPage.yar
## Windows_Trojan_HotPage
``` strings:
        $SpcSpOpusInfo = { 30 48 A0 1A 80 18 6E 56 53 17 76 FE 7F 51 7F 51 7E DC 79 D1 62 80 67 09 96 50 51 6C 53 F8 }
        $s1 = "\\Device\\KNewTableBaseIo"
        $s2 = "Release\\DwAdsafeLoad.pdb"
        $s3 = "RedDriver.pdb"
        $s4 = "Release\\DwAdSafe.pdb"
        $s5 = "[%s] Begin injecting Broser pid=[%d]"
        $s6 = "[%s] ADDbrowser PID ->[%d]"
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_JesterStealer.yar
## Windows_Trojan_JesterStealer
``` strings:
        $a1 = "[Decrypt Chrome Password] {0}" wide fullword
        $a2 = "Passwords.txt" wide fullword
        $a3 = "9Stealer.Recovery.FTP.FileZilla+<EnumerateCredentials>d__0" ascii fullword
        $a4 = "/C chcp 65001 && ping 127.0.0.1 && DEL /F /S /Q /A \"" wide fullword
        $a5 = "citigroup.com" wide fullword
        $a6 = "Password: {1}" wide fullword
        $a7 = "set_steamLogin" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Jupyter.yar
## Windows_Trojan_Jupyter
``` strings:
        $a1 = "%appdata%\\solarmarker.dat" ascii fullword
        $a2 = "\\AppData\\Roaming\\solarmarker.dat" wide fullword
        $b1 = "steal_passwords" ascii fullword
        $b2 = "jupyter" ascii fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Kronos.yar
## Windows_Trojan_Kronos
``` strings:
        $a1 = "data_inject" ascii wide fullword
        $a2 = "set_filter" ascii wide fullword
        $a3 = "set_url" ascii wide fullword
        $a4 = "%ws\\%ws.cfg" ascii wide fullword
        $a5 = "D7T1H5F0F5A4C6S3" ascii wide fullword
        $a6 = "[DELETE]" ascii wide fullword
        $a7 = "Kronos" ascii wide fullword
```
# https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Latrodectus.yar
## Windows_Trojan_Latrodectus
``` strings:
        $Str1 = { 48 83 EC 38 C6 44 24 20 73 C6 44 24 21 63 C6 44 24 22 75 C6 44 24 23 62 C6 44 24 24 }
        $crc32_loadlibrary = { 48 89 44 24 40 EB 02 EB 90 48 8B 4C 24 20 E8 ?? ?? FF FF 48 8B 44 24 40 48 81 C4 E8 02 00 00 C3 }
        $delete_self = { 44 24 68 BA 03 00 00 00 48 8B 4C 24 48 FF 15 ED D1 00 00 85 C0 75 14 48 8B 4C 24 50 E8 ?? ?? 00 00 B8 FF FF FF FF E9 A6 00 }
        $Str4 = { 89 44 24 44 EB 1F C7 44 24 20 00 00 00 00 45 33 C9 45 33 C0 33 D2 48 8B 4C 24 48 FF 15 7E BB 00 00 89 44 24 44 83 7C 24 44 00 75 02 EB 11 48 8B 44 24 48 EB 0C 33 C0 85 C0 0F 85 10 FE FF FF 33 }
        $handler_check = { 83 BC 24 D8 01 00 00 12 74 36 83 BC 24 D8 01 00 00 0E 74 2C 83 BC 24 D8 01 00 00 0C 74 22 83 BC 24 D8 01 00 00 0D 74 18 83 BC 24 D8 01 00 00 0F 74 0E 83 BC 24 D8 01 00 00 04 0F 85 44 02 00 00 }
        $hwid_calc = { 48 89 4C 24 08 48 8B 44 24 08 69 00 0D 66 19 00 48 8B 4C 24 08 89 01 48 8B 44 24 08 8B 00 C3 }
        $string_decrypt = { 89 44 24 ?? 48 8B 44 24 ?? 0F B7 40 ?? 8B 4C 24 ?? 33 C8 8B C1 66 89 44 24 ?? 48 8B 44 24 ?? 48 83 C0 ?? 48 89 44 24 ?? 33 C0 66 89 44 24 ?? EB }
        $campaign_fnv = { 48 03 C8 48 8B C1 48 39 44 24 08 73 1E 48 8B 44 24 08 0F BE 00 8B 0C 24 33 C8 8B C1 89 04 24 69 04 24 93 01 00 01 89 04 24 EB BE }
        $sleep = { 81 BC 24 ?? ?? ?? ?? 08 07 00 00 7D ?? B9 64 00 00 00 E8 }
        $timeout = { B9 96 00 00 00 F7 F1 8B C2 05 C2 01 00 00 69 C0 E8 03 00 00 }
```
