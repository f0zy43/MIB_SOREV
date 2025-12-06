# https://github.com/mdecrevoisier/SIGMA-detection-rules/windows-active_directory

## win-ad-DPAPI attribute accessed (DCSync, Mimikatz, RiskySPN).yaml
```
title: Suspicious Active Directory DPAPI attributes accessed (Mimikatz, DCSync, RiskySPN)
name: dpapi_access # Rule Reference
description: Detects scenarios where an attacker attempts to extract sensitive DPAPI information from Active Directory (RiskySPN PowerShell tool, DCSync and Mimikatz may also trigger this rule).
requirements: extended rights auditing enabled (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html)
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1555-Credentials%20from%20Password%20Stores
  - https://docs.microsoft.com/en-us/windows/win32/adschema/extended-rights
  - https://github.com/PSGumshoe/PSGumshoe/blob/master/DirectoryService/PrivateFunctions.ps1
  - https://stealthbits.com/blog/detecting-persistence-through-active-directory-extended-rights/
  - https://cqureacademy.com/blog/extracting-roamed-private-keys
  - https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/
  - https://www.mandiant.com/resources/blog/apt29-windows-credential-roaming
  - https://www.dsinternals.com/en/retrieving-dpapi-backup-keys-from-active-directory/
tags:
  - attack.credential_access
  - attack.t1555.004 # Credentials from Password Stores: Windows Credential Manager
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - 612cb747-c0e8-4f92-9221-fdd5f15b550d # unixUserPassword
      - 6617e4ac-a2f1-43ab-b60c-11fbd1facf05 # ms-PKI-RoamingTimeStamp / Indicates the time of the last synchronization
      - b3f93023-9239-4f7c-b99c-6745d87adbc2 # ms-PKI-DPAPIMasterKeys / Stores the DPAPI Master Keys. These symmetric keys encrypt the private keys and are themselves encrypted.
      - b7ff5a38-0818-42b0-8110-d3d154c97f24 # ms-PKI-Credential-Roaming-Tokens > see Mandiant link
      - b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7 # ms-PKI-AccountCredentials / Stores certificates, certificate signing requests, private keys and saved passwords.
  filter:
    SubjectUserName|endswith: "$"
  condition: selection and not filter
falsepositives:
  - Active Directory Backup solutions
level: informational

---
title: Suspicious Active Directory DPAPI attributes accessed Count
status: experimental
correlation:
  type: value_count
  rules:
    - dpapi_access # Referenced here
  group-by:
    - Computer
  timespan: 30m
  condition:
    gte: 5
    field: ObjectName
level: high
```
## win-ad-DSRM configuration changed (Reg via PowerShell).yaml
```
title: DSRM password changed (Reg via PowerShell)
description: Detects scenarios where an attacker reset or synchronize with another domain account the DSRM (Directory Services Restore Mode) password in order to escalate privileges.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1003-Credential%20dumping
- https://adsecurity.org/?p=1714
- https://adsecurity.org/?p=1785
- https://book.hacktricks.xyz/windows/active-directory-methodology/dsrm-credentials
- https://www.hackingarticles.in/domain-persistence-dsrm/
- https://azurecloudai.blog/2020/06/19/how-to-reset-the-directory-service-restore-mode-dsrm-password/
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  category:
    - ps_module
    - ps_classic_script
    - ps_script
detection: # full command: 'Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2'
  selection_powershell_native:
    EventID: 800
    EventData|contains|all:
      - '-ItemProperty' # Entry doesn't exist per default. Can be New-* or Set-*
      - '\SYSTEM\CurrentControlSet\Control\Lsa'
      - DsrmAdminLogonBehavior
      #- path # parameter is optional

  selection_powershell_modern:
    EventID: 4103
    Payload|contains|all:
      - '-ItemProperty' # Entry doesn't exist per default. Can be New-* or Set-*
      - '\SYSTEM\CurrentControlSet\Control\Lsa'
      - DsrmAdminLogonBehavior
      #- path # parameter is optional

  selection_powershell_block:
    EventID: 4104
    ScriptBlockText|contains|all:
      - '-ItemProperty' # Entry doesn't exist per default. Can be New-* or Set-*
      - '\SYSTEM\CurrentControlSet\Control\Lsa'
      - DsrmAdminLogonBehavior
      #- path # parameter is optional

  condition: 1 of selection*
falsepositives:
- Disaster recovery situation
level: high
```
## win-ad-DSRM configuration changed (Reg via command).yaml
```
title: DSRM password changed (Reg via command)
description: Detects scenarios where an attacker reset or synchronize with another domain account the DSRM (Directory Services Restore Mode) password in order to escalate privileges.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1003-Credential%20dumping
- https://adsecurity.org/?p=1714
- https://adsecurity.org/?p=1785
- https://book.hacktricks.xyz/windows/active-directory-methodology/dsrm-credentials
- https://www.hackingarticles.in/domain-persistence-dsrm/
- https://azurecloudai.blog/2020/06/19/how-to-reset-the-directory-service-restore-mode-dsrm-password/
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    NewProcessName|endswith: \reg.exe
    CommandLine|contains|all:
      - REG ADD
      - '\SYSTEM\CurrentControlSet\Control\Lsa'
      - DsrmAdminLogonBehavior
  condition: selection
falsepositives:
- Disaster recovery situation
level: high
```
## win-ad-DSRM password changed.yaml
```
title: DSRM password changed (native)
description: Detects scenarios where an attacker reset or synchronize with another domain account the DSRM (Directory Services Restore Mode) password in order to escalate privileges.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1003-Credential%20dumping
- https://adsecurity.org/?p=1714
- https://adsecurity.org/?p=1785
- https://book.hacktricks.xyz/windows/active-directory-methodology/dsrm-credentials
- https://www.hackingarticles.in/domain-persistence-dsrm/
- https://azurecloudai.blog/2020/06/19/how-to-reset-the-directory-service-restore-mode-dsrm-password/
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection: # full command: NTDSUTIL >> set dsrm password >> reset password on server null >> <password>
  selection:
    EventID: 4794
  condition: selection
falsepositives:
- Disaster recovery situation
level: high
```
## win-ad-GPO permissions changed.yaml
```
title: Permissions changed on a Group Policy (GPO)
description: Detects scenarios where an attacker will attempt to take control over a group policy.
requirements: auditing SACL "Modify permissions" must be placed on the "Policies" container using the Active Directory console (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html).
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0005-Defense%20Evasion/T1222.001-File%20and%20Directory%20Permissions%20Modification
tags:
- attack.privilege_escalation
- attack.t1484.001
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName: ntSecurityDescriptor
    ObjectClass: groupPolicyContainer
    OperationType: '%%14674' # Value is added
  filter:
    SubjectUserName: # AGPM servers (to customize)
      - SRVAGPM01$
      - SRVAGPM02$
  condition: selection and not filter
falsepositives:
- Group policy administrator activity / AGPM activity
level: medium
```
## win-ad-GPO sensitive modified.yaml
```
title: Suspicious modification of a sensitive Group Policy (GPO)
description: Detects scenarios where an attacker will attempt to take control over a group policy.
requirements: native and existing auditing SACL ("Write all properties") should already be present on "Policies" container.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0004-Privilege%20Escalation/T1484.001-Domain%20Policy%20Modification-Group%20Policy%20Modification
tags:
- attack.privilege_escalation
- attack.t1484.001
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName: versionNumber
    ObjectClass: groupPolicyContainer
    OperationType: '%%14674' # Value is added
    ObjectGUID|contains:     # List of sensitive GPO GUID
      - xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  filter:
    AttributeValue: '0' # First value when GPO is created. Refers to the GPO version number.
  condition: selection and not filter
falsepositives:
- Group policy administrator activity / AGPM activity
level: medium
```
## win-ad-Host set with constrainted delegation.yaml
```
title: Host set with constrained delegation
description: Detects scenarios where an attacker modifies host delegation settings for privilege escalation.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://www.alsid.com/crb_article/kerberos-delegation/
- https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation
- https://www.guidepointsecurity.com/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/
- https://stealthbits.com/blog/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/
- https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
- https://www.thehacker.recipes/ad/movement/kerberos/delegations#talk
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection: # Delegation to specified service, any protocol
    EventID: 4742
  
  selection1:
    UserAccountControl: '%%2098' # Enable option "Approved for authenticated delegation"
  
  selection2:
    AllowedToDelegateTo: '-' # Can be: "cifs/srv01 cifs/srv02.demo.lan dcom/dc03..."
    
  condition: selection and (selection1 OR NOT selection2) 
falsepositives:
- Rare administrator modifying host delegation settings
level: high
```
## win-ad-Host set with unconstrainted delegation.yaml
```
title: Host set with unconstrained delegation
description: Detects scenarios where an attacker modifies host delegation settings for privilege escalation.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://www.alsid.com/crb_article/kerberos-delegation/
- https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation
- https://www.guidepointsecurity.com/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/
- https://stealthbits.com/blog/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/
- https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
- https://pentestlab.blog/2022/03/21/unconstrained-delegation/
- https://www.thehacker.recipes/ad/movement/kerberos/delegations#talk
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection: # Delegation to any service, Kerberos only
    EventID: 4742
    UserAccountControl: '%%2093' # Enable option "Trust this computer for delegation to any service (Kerberos only)"
  condition: selection
falsepositives:
- Rare administrator modifying host delegation settings
level: high
```
## win-ad-IFM created (command).yaml
```
title: IFM creation detected from commandline (installation from media)
description: Detects scenarios where an attacker attempts to create an IFM image (usually used for deploying domain controllers to reduce replication traffic) for dumping credentials.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1003-Credential%20dumping
- https://blog.menasec.net/2019/11/forensics-traces-of-ntdsdit-dumping.html
- https://adsecurity.org/?p=2398
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
- https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc753343(v=ws.11)
- https://www.microsoft.com/security/blog/2021/11/08/threat-actor-dev-0322-exploiting-zoho-manageengine-adselfservice-plus/
- https://twitter.com/JohnLaTwC/status/1416382178380767233?s=09
- https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/
- https://blog.talosintelligence.com/2022/08/recent-cyber-attack.html
- https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/
- https://blog.sekoia.io/lucky-mouse-incident-response-to-detection-engineering/
- https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
- https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
- https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
- https://medium.com/@simone.kraus/part-2-sensor-mapping-reverse-engineering-ntds-a73bde69031e
tags:
- attack.credential_dumping
- attack.t1003.003
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection_baseline:
    NewProcessName|endswith: 
      - '\ntdsutil.exe'
      - '\dsdbutil.exe'

  selection_creation_basic: # full command: "ntdsutil "activate instance ntds" ifm "create full c:\data" quit quit"
    CommandLine|contains|all:
      - ifm
      - create

  selection_creation_obfuscated:
    CommandLine|contains|all:
      - ' i '  # ifm
      - ' c '  # create

  selection_activation_basic: # full command "ntdsutil.exe "act i ntds" i "c full c:\hacker" q q"
    CommandLine|contains|all:
      - activate
      - instance
      - ntds

  selection_activation_obfuscated:
    CommandLine|contains|all:
      - 'ac ' # activate
      - ntds

  condition: selection_baseline and 1 of selection_*
falsepositives:
- Administrator creating a IFM image
- Backup program or script
level: high
```
## win-ad-IFM created (native).yaml
```
title: IFM detected - ESENT (installation from media)
description: Detects scenarios where an attacker attempts to create an IFM image (usually used for deploying domain controllers to reduce replication traffic) for dumping credentials.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1003-Credential%20dumping
- https://adsecurity.org/?p=2398
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
tags:
- attack.credential_dumping
- attack.t1003.003
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: application # provider: ESENT
detection:
  selection:
    EventID:
      - 325 # The database engine created a new database
      - 326 # The database engine attached a new database
      - 327 # The database engine detached a database
    EventData|contains:
      - '\ntds.dit'
  filter:
      - '<normal backup path>'
  condition: selection and not filter
falsepositives:
- Administrator creating a IFM image
- Backup program or script
level: high
```
## win-ad-Kerberos brutforce enumeration with unexisting users.yaml
```
title: Brutforce enumeration with unexisting users (Kerberos)
name: bruteforce_non_existing_users_kerberos
description: Detects scenarios where an attacker attempts to enumerate potential existing users, resulting in failed Kerberos TGT requests with unexisting or invalid accounts.
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force
  - https://github.com/ropnop/kerbrute
tags:
  - attack.credential_access
  - attack.t1110
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4771
      - 4768
    Status: "0x6" # KDC_ERR_C_PRINCIPAL_UNKNOWN
  filter:
    - IpAddress: "%domain_controllers_ips%" # reduce amount of false positives
    - TicketOptions: 0x50800000 # covered by Kerbrute rule
  condition: selection and not filter
falsepositives:
  - Missconfigured application or identity services
level: high

---
title: Brutforce enumeration with unexisting users (Kerberos) Count
status: experimental
correlation:
  type: value_count
  rules:
    - bruteforce_non_existing_users_kerberos # Referenced here
  group-by:
    - Computer
  timespan: 30m
  condition:
    gte: 20
    field: TargetUserName # Count how many failed logins with non existing users were reported on the domain controller.
level: high
```
## win-ad-Kerberos AS-REP Roasting.yaml
```
title: Kerberos AS-REP Roasting ticket request detected
description: Detects scenarios where an attacker abuse an account with UAC settings set to "Accounts Does not Require Pre-Authentication" in order to perform offline TGT brutforce. May also be triggered by an attacker performing some Kerberos user enumration with tools like "Kerbrute".
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1558-Steal%20or%20Forge%20Kerberos%20Tickets
- https://github.com/HarmJ0y/ASREPRoast
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat
- https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html#as-rep-roasting
- https://medium.com/@jsecurity101/ioc-differences-between-kerberoasting-and-as-rep-roasting-4ae179cdf9ec
- https://rioasmara.com/2020/07/04/kerberoasting-as-req-pre-auth-vs-non-pre-auth/
- https://www.hackingarticles.in/as-rep-roasting/
tags:
- attack.credential_access
- attack.t1558.004
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    Status: 0x0 # Success
    ServiceSid|endswith: '-502'
    PreAuthType: 0  # Logon without Pre-Authentication.
    #TicketOptions:
    #  - 0x40800010 # triggered by ASREPRoast & Rubeus
    #  - 0x50800000 # user enumeration triggered by Kerbrute (proxiable ticket)
  filter:
    - IpAddress: '%domain_controllers_ips%' # reduce amount of false positives
  condition: selection and not filter
falsepositives:
- Account configured to not require pre-authentication
level: high
```
## win-ad-Kerberos constrained delegation abuse (S4U2Proxy).yaml
```
title: Rubeus Kerberos constrained delegation abuse (S4U2Proxy)
description: Detects scenarios where an attacker abuse Kerberos constrained delegation in order to escalate privileges.
references:
- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation
- https://www.guidepointsecurity.com/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/
- https://stealthbits.com/blog/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/
- https://www.thehacker.recipes/ad/movement/kerberos/delegations#talk
tags:
- attack.credential_access
- attack.t1558
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TransmittedServices|contains: '@'
  filter:
    - ServiceSid|endswith: '-502' # Krbtgt account SID is excluded as it may be related to "Unconstrained Domain Persistence" (see other rule)
    - TargetUserName: '%allowed_S4U2Proxy_accounts%' # User accounts allowed to perform constrained delegation
    - IpAddress: '%domain_controllers_ips%'          # reduce amount of false positives
  condition: selection and not filter
falsepositives:
- Accounts with constrained delegation enabled
level: high
```
## win-ad-Kerberos constrained delegation settings changed (Rubeus) - Any protocol.yaml
```
title: Host constrained delegation settings changed for potential abuse (Rubeus) - Any protocol
description: Detects scenarios where an attacker modifies host delegation settings for privilege escalation.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://www.alsid.com/crb_article/kerberos-delegation/
- https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation
- https://www.guidepointsecurity.com/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/
- https://stealthbits.com/blog/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/
- https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
- https://www.thehacker.recipes/ad/movement/kerberos/delegations#talk
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection: # Delegation to specified service, any protocol
    EventID: 4742
    UserAccountControl: '%%2098' # Enable option "Approved for authenticated delegation"
  filter:
    AllowedToDelegateTo: '-' # Can be: "cifs/srv01 cifs/srv02.demo.lan dcom/dc03..."
  condition: selection and not filter
falsepositives:
- Rare administrator modifying host delegation settings
level: high
```
## win-ad-Kerberos constrained delegation settings changed (Rubeus) - Kerberos.yaml
```
title: Host constrained delegation settings changed for potential abuse (Rubeus) - Kerberos only
description: Detects scenarios where an attacker modifies host delegation settings for privilege escalation.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://www.alsid.com/crb_article/kerberos-delegation/
- https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation
- https://www.guidepointsecurity.com/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/
- https://stealthbits.com/blog/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/
- https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
- https://www.thehacker.recipes/ad/movement/kerberos/delegations#talk
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection: # Delegation to specified service, Kerberos only
    EventID: 4742
    UserAccountControl: '-'  # Avoid duplicate with with "constrained delegation to any protocol"
  filter:
    AllowedToDelegateTo: '-' # Can be: "cifs/srv01 cifs/srv02.demo.lan dcom/dc03..."
  condition: selection and not filter
falsepositives:
- Rare administrator modifying host delegation settings
level: high
```
## win-ad-Kerberos enumeration with existing-unexsting users (Kerbrute).yaml
```
title: Kerberos enumeration with existing/unexisting users (Kerbrute)
name: kerbrute_enumeration
description: Detects scenarios where an attacker attempts to enumerate existing or non existing users using "Kerbrute". This use case can also be related to spot vulnearbility "MS14-068".
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force
  - https://github.com/ropnop/kerbrute
  - https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf
tags:
  - attack.credential_access
  - attack.t1110
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4771
      - 4768
    Status: "0x6" # KDC_ERR_C_PRINCIPAL_UNKNOWN
    TicketOptions: 0x50800000
  filter:
    - IpAddress: "%domain_controllers_ips%" # reduce amount of false positives
    - TargetUserName: "%account_allowed_proxy%" # accounts allowed to perform proxiable requests
  condition: selection and not filter
falsepositives:
  - Missconfigured application or identity services
level: high

---
title: Kerberos enumeration with existing/unexisting users (Kerbrute) Count
status: experimental
correlation:
  type: value_count
  rules:
    - kerbrute_enumeration # Referenced here
  group-by:
    - Computer
  timespan: 30m
  condition:
    gte: 20
    field: TargetUserName # Count how many failed logins were reported on the domain controller.
level: high
```
## win-ad-Kerberos key list attack.yaml
```
title: Kerberos key list attack for credential dumping
description: Detects scenarios where an attacker attempts to forge a special Kerberos service ticket in order to extract credentials from Read Only Domain Controllers (RODC).
references:
- https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/
- https://www.tarlogic.com/blog/how-to-attack-kerberos/
tags:
- attack.credential_access
- attack.t1003 # credential dumping
- attack.t1558 # forget ticket
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    Status: 0x0 # Success
    TicketOptions: '0x10000' # proxiable ticket
  filter:
    - IpAddress: '%domain_controllers_ips%'     # reduce amount of false positives
    - TargetUserName: '%account_allowed_proxy%' # accounts allowed to perform proxiable requests
  condition: selection and not filter
falsepositives:
- Applications or services performing delegation activities, ADFS servers
level: high
```
## win-ad-Kerberos krbtgt password reset (Golden ticket).yaml
```
title: Suspicious Kerberos password account reset to issue potential Golden ticket
description: Detects scenarios where a suspicious password reset of the Krbtgt account is performed by attacker to issue a potential Golden ticket.
references:
- https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_14_07_PassTheGolden_Ticket_v1_1.pdf
- https://adsecurity.org/?p=483
tags:
- attack.credential_access
- attack.t1558.001
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4724
    TargetSid|endswith: '-502' # Krbtgt account SID
  condition: selection
falsepositives:
- Administrators following best practices and reseting the Krbtgt password 1 or 2 times a year
level: medium
```
## win-ad-Kerberos suspicious proxiable ticket.yaml
```
title: Suspicious Kerberos proxiable/S4U2self ticket (CVE-2021-42278/42287)
description: Detects scenarios where an attacker attempts to request a proxiable ticket. This action may trigger while attempting to identify a vulnerable target or using some offsensive Kerberos tools like Kerbrute, Impacket...
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1558-Steal%20or%20Forge%20Kerberos%20Tickets
- https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html
- https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing
- https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041
- https://github.com/WazeHell/sam-the-admin
- https://github.com/cube0x0/noPac
- https://github.com/ly4k/Pachine
- https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf
tags:
- attack.credential_access
- attack.t1558 # forged ticket
- attack.privilege_escalation
- attack.t1068 # exploitation for privilege escalation
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    Status: 0x0 # Success
    ServiceSid|endswith: '-502' # Krbtgt account SID
    TicketOptions: '0x50800000' # Forwardable, Proxiable, Renewable ticket
  filter:
    - IpAddress: '%domain_controllers_ips%'     # reduce amount of false positives
    - TargetUserName: '%account_allowed_proxy%' # accounts allowed to perform proxiable requests
  condition: selection and not filter
falsepositives:
- Applications or services performing delegation activities
level: high
```
## win-ad-Kerberos ticket related to a potential Golden ticket.yaml
```
title: Kerberos TGS ticket request related to a potential Golden ticket
description: Detects scenarios where an attacker request a potential Golden ticket. Findings returned by this rule may not confirm at 100% that a Golden ticket was generated and further investigations would be required to confirm it. Another indicator (in case of a lazy Golden ticket) to check would be to check if the TargetUserName refers to an existing user in the domain.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1558-Steal%20or%20Forge%20Kerberos%20Tickets
- https://infosecwriteups.com/forest-an-asreproast-dcsync-and-golden-ticket-hackthebox-walkthrough-ade8dcdd1ee5
- https://attack.stealthbits.com/how-golden-ticket-attack-works
- https://www.hackingarticles.in/domain-persistence-golden-ticket-attack/
- https://adsecurity.org/?p=1515
- https://en.it-pirate.eu/azure-atp-golden-ticket-attack-how-golden-ticket-attacks-work/
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets
- https://bond-o.medium.com/golden-ticket-attack-ea89553cf9c0
- https://www.blackhat.com/docs/us-15/materials/us-15-Metcalf-Red-Vs-Blue-Modern-Active-Directory-Attacks-Detection-And-Protection-wp.pdf
tags:
- attack.credential_access
- attack.t1558.001
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    TargetDomainName|re: <domain_in_lowercase.xxx> # adapt REGEXP according your SIEM
    TicketOptions:
      - 0x40810000
      - 0x60810010 # ServiceName: krbtgt
    TicketEncryptionType: 0x12
    Status: 0x0
  filter:
    IpAddress:
      - '::1'
      - '127.0.0.1'
      - '%domain_controllers_ips%' # reduce amount of false positives
  condition: selection and not filter
falsepositives:
- Unknown
level: high
```
## win-ad-Kerberos ticket without a trailing $ (CVE-2021-42278).yaml
```
title: Kerberos ticket without a trailing $ (CVE-2021-42278/42287)
description: Detects scenarios where an attacker attempts to spoof the SAM account name of a a domain controller in order to impersonate it. Vulnerability comes from that computer accounts should have a trailing $ in their name (i.e. sAMAccountName attribute) but no validation process existed until the patch was released. During the offensive phase, attacker will create and rename the sAMAccountName of a computer account to look like the one of a domain controller.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1558-Steal%20or%20Forge%20Kerberos%20Tickets
- https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html
- https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing
- https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041
- https://github.com/WazeHell/sam-the-admin
- https://github.com/cube0x0/noPac
- https://github.com/ly4k/Pachine
- https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing/
tags:
- attack.credential_access
- attack.t1558 # forged ticket
- attack.privilege_escalation
- attack.t1068 # exploitation for privilege escalation
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection_tgt:
    EventID: 4768
    Status: 0x0 # Success
    ServiceSid|endswith: '-502' # Krbtgt account SID
    #TargetUserName.lower() == Computer.split(".")[0].lower() # normal behavior would be that TargetUsername and Computer are different (DC01$ and DC01.domain.lan). Having both matching is suspicious.

  selection_tgs:
    EventID: 4769
    Status: 0x0 # Success
    ServiceName|endswith: $
    #TargetUserName.split("@")[0].lower() == Computer.split(".")[0].lower() # normal behavior would be that TargetUsername and Computer are different (DC01$@domain.lan vs DC01.domain.lan). Having both matching is suspicious.

  selection_host:
    TargetUserName|contains: "$"

  condition: (selection_tgt or selection_tgs) and not selection_host
falsepositives:
- None
level: high
```
## win-ad-Kerberos unconstrained delegation settings changed (Rubeus).yaml

```
title: Host unconstrained delegation settings changed for potential abuse (Rubeus)
description: Detects scenarios where an attacker modifies host delegation settings for privilege escalation.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://www.alsid.com/crb_article/kerberos-delegation/
- https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation
- https://www.guidepointsecurity.com/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/
- https://stealthbits.com/blog/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/
- https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
- https://pentestlab.blog/2022/03/21/unconstrained-delegation/
- https://www.thehacker.recipes/ad/movement/kerberos/delegations#talk
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection: # Delegation to any service, Kerberos only
    EventID: 4742
    UserAccountControl: '%%2093' # Enable option "Trust this computer for delegation to any service (Kerberos only)"
  condition: selection
falsepositives:
- Rare administrator modifying host delegation settings
level: high
```
## win-ad-Kerberos unconstrained domain persistence.yaml
```
title: Rubeus Kerberos unconstrained delegation abuse
description: Detects scenarios where an attacker abuse Kerberos unconstrained delegation for domain persistence.
references:
- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation
- https://www.guidepointsecurity.com/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/
- https://stealthbits.com/blog/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/
- https://www.thehacker.recipes/ad/movement/kerberos/delegations#talk
tags:
- attack.credential_access
- attack.t1558
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TransmittedServices|contains: '@'
    ServiceSid|endswith: '-502' # Krbtgt account SID
  filter:
    - TargetUserName: '%allowed_unconstrained_accounts%' # User accounts allowed to perform unconstrained delegation
    - IpAddress: '%domain_controllers_ips%'              # reduce amount of false positives
  condition: selection and not filter
falsepositives:
- Accounts with unconstrained delegation enabled
level: high
```
## win-ad-PowerShell Active Directory Forest class called from a non admin host.yaml
```
title: Active Directory Forest PowerShell class called from a non administrative host
description: Detects scenarios where an attacker attempts to call the Active Directory Forest PowerShell class on a non administrative host in order to enumerate trusts, forests, domains, sites and subnet information.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1087-Account%20discovery
- https://podalirius.net/en/articles/active-directory-sites-and-subnets-enumeration/
- https://adsecurity.org/?p=192
- https://github.com/PyroTek3/PowerShell-AD-Recon/blob/master/Get-PSADForestInfo
- https://hochwald.net/powershell-retrieve-information-an-active-directory-forest/
tags:
- attack.discovery
- attack.t1482
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  category:
    - ps_module
    - ps_classic_script
    - ps_script
detection:
  selection_powershell_native:
    EventID: 800
    EventData|contains: System.DirectoryServices.ActiveDirectory

  selection_powershell_modern:
    EventID: 4103
    Payload|contains: System.DirectoryServices.ActiveDirectory

  selection_powershell_block:
    EventID: 4104
    ScriptBlockText|contains: System.DirectoryServices.ActiveDirectory

  filter:
    - Computer: '%admin_workstation%'
    - Computer: '%domain_controllers%'

  condition: 1 of selection* and not filter
falsepositives:
- Adminitrative host, jump host, domain controllers, Exchange servers, application interacting with Active Directory modules
level: medium
```
## win-ad-PowerShell Active Directory module called from a non administrative host.yaml
```
title: Active Directory PowerShell module called from a non administrative host
description: Detects scenarios where an attacker attempts to load the Active Directory PowerShell module on a non administrative host in order to enumerate users, groups, ... Also note that no user information is reported by this event ID and that some correation would be required.
correlation: correlate EventID 600 with ID 800 using field "HostId" or "RunspaceId" to obtain the user that triggered the action.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1087-Account%20discovery
tags:
- attack.discovery
- attack.t1087.002
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 600
    ProviderName: ActiveDirectory
  filter:
    - Computer: '%admin_workstation%'
    - Computer: '%domain_controllers%'
  condition: selection and not filter
falsepositives:
- Adminitrative host, jump host, domain controllers, Exchange servers, application interacting with Active Directory modules
level: medium
```
## win-ad-SAM database access during DCshadow.yaml
```
title: Potential SAM database user credentials dumped with DCshadow
description: Detects scenarios where an attacker would dump user passwords using the DCshadow attack.
correlation: correlate TargetLogonId from ID 4624 with SubjectLogonId from ID 4661 to identify the source of the enumeration.
requirements: extended rights auditing enabled (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html)
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1003-Credential%20dumping
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow
- https://medium.com/@maarten.goet/dcshadow-detecting-a-rogue-domain-controller-replicating-malicious-changes-to-your-active-1e22440df9ad
- https://github.com/AlsidOfficial/UncoverDCShadow
- https://github.com/shellster/DCSYNCMonitor
- https://blog.alsid.eu/dcshadow-explained-4510f52fc19d
- https://stealthbits.com/blog/detecting-dcshadow-with-event-logs/
- https://www.labofapenetrationtester.com/2018/05/dcshadow-sacl.html
- https://blog.stealthbits.com/creating-persistence-with-dcshadow/
- https://book.hacktricks.xyz/windows/active-directory-methodology/dcshadow
tags:
- attack.credential_access
- attack.t1003.001
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4661
    SubjectUserSid: S-1-5-18
    ProcessName|endswith: '\lsass.exe'
    ObjectServer: Security Account Manager
    ObjectType:
      - SAM_SERVER
      - SAM_DOMAIN
    ObjectName|startswith:
      - CN=
      - DC=
    AccessList|contains|all:
      - '%%5392' # ReadPasswordParameters
      - '%%5447' # SetPassword
  condition: selection | count(ObjectName) by Computer > 10
falsepositives:
- None
level: high
```
## win-ad-SAM database user credentials dump with Mimikatz.yaml
```
title: SAM database user credentials dump with Mimikatz
description: Detects scenarios where an attacker dump the LSASS memory content using Mimikatz (sekurlsa module).
correlation: correlate TargetLogonId from ID 4624 with SubjectLogonId from ID 4661 to identify the source of the enumeration.
requirements: extended rights auditing enabled (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html)
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1003-Credential%20dumping
- https://ivanitlearning.wordpress.com/2019/09/07/mimikatz-and-password-dumps/
tags:
- attack.credential_access
- attack.t1003.001
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4661
    ProcessName|endswith: '\lsass.exe'
    ObjectServer: Security Account Manager
    ObjectType: SAM_USER
    ObjectName|startswith: 'S-1-5-21-' # User SID dumped
    AccessList|contains|all:
      - '%%5446' # ChangePassword
      - '%%5447' # SetPassword
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter | count(ObjectName) by Computer > 10
falsepositives:
- None
level: high
```
## win-ad-SAM domain users & groups massive enumeration.yaml

```
title: Massive SAM users/groups enumeration (native)
name: SAM_enumeration_user_group
description: Detects scenarios where an attacker attempts to enumerate sensitive domain users/groups settings and membership. Correlate TargetLogonId from ID 4624 with SubjectLogonId from ID 4661 to identify the source of the enumeration.
requirements: extended rights auditing enabled (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html)
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1069-Permission%20Groups%20Discovery
  - https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html
tags:
  - attack.discovery
  - attack.t1069.002
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection: # net group <domain_group> /domain
  selection:
    EventID: 4661
    ProcessName|endswith: '\lsass.exe'
    ObjectServer: "Security Account Manager"
    ObjectName|startswith:
      - S-1-5-32- # refers to builtin domain local groups
      - S-1-5-21- # refers to domain users and groups
    ObjectType:
      - SAM_USER
      - SAM_GROUP
  filter:
    - SubjectUserName|endswith: "$"
    - ObjectName|endswith: # already covered in a separated rule for sensitive user & group enumeration
        - "-500" # local administrator
        - "-512" # Domain Admins
        - "-513" # Domain users (less critical)
  condition: selection and not filter
falsepositives:
  - Administrator activity
level: informational

---
title: Massive SAM users/groups enumeration (native)
status: experimental
correlation:
  type: value_count
  rules:
    - SAM_enumeration_user_group
  group-by:
    - Computer
  timespan: 15m
  condition:
    gte: 30
    field: ObjectName
level: high
```
## win-ad-SAM sensitive domain user & groups enumeration.yaml
```
title: Sensitive SAM domain user & groups discovery (native)
description: Detects scenarios where an attacker attempts to enumerate sensitive domain group settings and membership.
correlation: correlate TargetLogonId from ID 4624 with SubjectLogonId from ID 4661 to identify the source of the enumeration.
requirements: extended rights auditing enabled (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html)
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1069-Permission%20Groups%20Discovery
- https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html
tags:
- attack.discovery
- attack.t1069.002
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4661
    ProcessName|endswith: '\lsass.exe'
    ObjectServer: 'Security Account Manager'
    ObjectName|startswith:
      - S-1-5-32- # refers to builtin domain local groups
      - S-1-5-21- # refers to domain users andgroups
    ObjectType:
      - SAM_USER
      - SAM_GROUP
    ObjectName|endswith:
      - '-500' # local administrator / "net user administrator /domain"
      - '-512' # Domain Admins       / "net group "Domain Admins" /domain"
      - '-513' # Domain users
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
falsepositives:
- Administrator activity
level: high
```
## win-ad-SharpHound host enumeration over Kerberos.yaml
```
title: SharpHound host enumeration over Kerberos
name: sharphound_enumeration_kerberos
description: Detect if a source host is requesting multiple Kerberos Service tickets (TGS) for different assets in a short period of time.
references:
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1087-Account%20discovery
  - https://www.splunk.com/en_us/blog/security/sharing-is-not-caring-hunting-for-file-share-discovery.html
tags:
  - attack.discovery
  - attack.t1069.002
  - attack.t1087.002
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    ServiceName|endswith: "$"
    Status: 0x0
  filter:
    - IpAddress:
        - "::1"
        - "%domain_controllers_ip%"
    - TargetUserName|contains: "$@" # excludes computer accounts
  condition: selection and not filter
falsepositives:
  - Administrator activity, backup software
level: medium

---
title: SharpHound host enumeration over Kerberos Count
status: experimental
correlation:
  type: value_count
  rules:
    - sharphound_enumeration_kerberos
  group-by:
    - ServiceName
  timespan: 5m
  condition:
    gte: 20
    field: IpAddress
level: high
```
## win-ad-adminsdholder permissions changed.yaml
```
title: AdminSDHolder permissions changed for persistence
description: Detects scenarios where an attacker changes permissions on the AdminSDHolder container to establish persistence.
requirements: auditing SACL "Modify permissions" must be placed on the "AdminSDHolder" container using the Active Directory console (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html).
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1546-Event%20Triggered%20Execution
- https://adsecurity.org/?p=1906
- https://stealthbits.com/blog/20170619persistence-using-adminsdholder-and-sdprop/
- https://attack.stealthbits.com/adminsdholder-modification-ad-persistence
- https://adds-security.blogspot.com/2017/08/adminsdholder-backdoor-via-substitution.html
- https://www.netwrix.com/adminsdholder_modification_ad_persistence.html
- https://www.sentinelone.com/blog/protecting-your-active-directory-from-adminsdholder-attacks/
- https://pentestlab.blog/2022/01/04/domain-persistence-adminsdholder/
tags:
- attack.persistence
- attack.t1546
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    OperationType: '%%14674' # Value added
    AttributeLDAPDisplayName: nTSecurityDescriptor
    ObjectDN|startswith: CN=AdminSDHolder,CN=System,*
  condition: selection
falsepositives:
- Unknown
level: high
```
## win-ad-bruteforce via password reset.yaml
```
title: Bruteforce via password reset
name: bruteforce_password_reset
description: Detects if a attacker attempts to reset multiple times a user password to perform a bruteforce attack.
references:
  - https://twitter.com/mthcht/status/1705164058343756005?s=08
tags:
  - attack.credential_access
  - attack.t1110.001 # brutforce: Password Guessing
  - attack.t1110.003 # brutforce: Password spraying
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4723 # reset of own user's password
      - 4724 # reset of user's password by another user
  condition: selection
falsepositives:
  - ADFS, DirSync
level: informational

---
title: Bruteforce via password reset Count
status: experimental
correlation:
  type: value_count
  rules:
    - bruteforce_password_reset
  group-by:
    - TargetSid
  timespan: 10m
  condition:
    gte: 10
    field: host
level: high
```
## win-ad-computer account created by a computer account.yaml
```
title: Suspicious computer account created by a computer account
description: Detects scenarios where an attacker abuse MachineAccountQuota privilege and pre-create a computer object for abusing RBCD delegation.
references:
- https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/
tags:
- attack.persistence
- attack.t1136
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4741
    SubjectUserName|endswith: '$'
    SubjectUserSid|startswith: 'S-1-5-21-' # SYSTEM account 'S-1-5-18' would trigger a false positive
    TargetUserName|endswith: '$'
  condition: selection
falsepositives:
- Offline domain join host  
- Windows Autopilot Hybrid Azure AD Join
level: high
```
## win-ad-computer account created with privileges.yaml
```
title: Computer account created with privileges
description: Detects scenarios where an attacker creates a computer account with privileges for later exploitation.
correlation: correlate with ID 4763 (privileges) using field SubjectLogonId. See rule "Privilege SeMachineAccountPrivilege abuse" for advance correlation.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1136-Create%20account
- https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html
- https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing
- https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041
- https://github.com/WazeHell/sam-the-admin
- https://github.com/cube0x0/noPac
- https://github.com/ly4k/Pachine
- https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing/
tags:
- attack.persistence
- attack.t1098 # account manipulation
- attack.t1136 # user creation
- attack.privilege_escalation
- attack.t1068 # exploitation for privilege escalation
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4741
  filter:
    PrivilegeList: "-" # Interesting privileges would be "SeMachineAccountPrivilege"
  condition: selection and not filter
falsepositives:
- None
level: high
```
## win-ad-computer account modifying AD permissions.yaml
```
title: Computer account modifying Active Directory permissions
description: Detects scenarios where an attacker compromise a server with high privileges to perform permissions changes. Note that a dedicated rule for Exchange exists.
requirements: auditing SACL "Modify permissions" must be placed on the AD root container using the Active Directory console (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html).
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0005-Defense%20Evasion/T1222.001-File%20and%20Directory%20Permissions%20Modification
tags:
- attack.defense_evasion
- attack.t1222.001
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName: ntSecurityDescriptor
    OperationType: '%%14674' # Value added
    SubjectUserName|endswith: '$'
    #SubjectUserSid|startswith: 'S-1-5-21-' # SYSTEM account 'S-5-18' would trigger a false positive
  condition: selection
falsepositives:
- Unknown
level: high
```
## win-ad-computer account renamed without a trailing $ (CVE-2021-42278).yaml
```
title: Computer account renamed without a trailing $ (CVE-2021-42278/42287)
description: Detects scenarios where an attacker attempts to spoof the SAM account name of a a domain controller in order to impersonate it. Vulnerability comes from that computer accounts should have a trailing $ in their name (i.e. sAMAccountName attribute) but no validation process existed until the patch was released. During the offensive phase, attacker will create and rename the sAMAccountName of a computer account to look like the one of a domain controller. Once the attack is done, attacker will rollback the sAMAccountName to its original name.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html
- https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing
- https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041
- https://github.com/WazeHell/sam-the-admin
- https://github.com/cube0x0/noPac
- https://github.com/ly4k/Pachine
- https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing/
- https://medium.com/@mvelazco/hunting-for-samaccountname-spoofing-cve-2021-42287-and-domain-controller-impersonation-f704513c8a45
tags:
- attack.persistence
- attack.t1098 # account manipulation
- attack.defense_evasion
- attack.t1036 # masquerading
- attack.privilege_escalation
- attack.t1068 # exploitation for privilege escalation
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection_baseline:
    EventID: 4781 # account renamed

  selection_change:
    OldTargetUserName|endswith: $
  filter_change:
    NewTargetUserName|endswith: $ # new name looks a user account (no '$' at the end)

  selection_rollback:
    NewTargetUserName|endswith: $
  filter_rollback:
    OldTargetUserName|endswith: $

  condition: selection_baseline and ((selection_change and not filter_change) or (selection_rollback and not filter_rollback))
falsepositives:
- None
level: high
```
## win-ad-computer account set for RBCD delegation.yaml
```
title: Computer account manipulation for delegation (RBCD)
description: Detects scenarios where an attacker manipulate a computer object and updates its attribute 'msDS-AllowedToActOnBehalfOfOtherIdentity' to enable a resource to impersonate and authenticate any domain user.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation
- https://pentestlab.blog/2021/10/18/resource-based-constrained-delegation/
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution
- https://blog.netwrix.com/2022/09/29/resource-based-constrained-delegation-abuse/
- https://www.fortalicesolutions.com/posts/hunting-resource-based-constrained-delegation-in-active-directory
requirements: auditing SACL ("Write all properties") must be placed on the "domain" partition.
tags:
- attack.persistence
- attack.t1098 # account manipulation
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    DSType: '%%14676' # value added 
    ObjectClass: computer 
    AttributeLDAPDisplayName: 'msDS-AllowedToActOnBehalfOfOtherIdentity'
  condition: selection
falsepositives:
- Computer account set for delegation by a sysadmin
level: high
```
## win-ad-diskshadow abuse.yaml
```
title: Diskshadow command abuse to expose VSS backup
description: Detects scenarios where an attacker attemps to create an IFM for dumping credentials.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1003-Credential%20dumping
- https://blog.menasec.net/2019/11/forensics-traces-of-ntdsdit-dumping.html
- https://adsecurity.org/?p=2398
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
- https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/
tags:
- attack.credential_dumping
- attack.t1003
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection: # Full command: "diskshadow.exe /s shadow.txt"
    EventID: 4688
    NewProcessName|endswith: \diskshadow.exe
    CommandLine|contains: diskshadow
    CommandLine|contains:
      - /s
      - -s
  condition: selection
falsepositives:
- Administrator manipulating VSS backup
level: high
```
## win-ad-domain group membership change (high risk).yaml
```
title: High risk Active Directory group membership change
description: Detects scenarios where a suspicious group membership is changed.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://ss64.com/nt/syntax-groups.html
- https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4728 # security global group member added
      - 4756 # universal group member added
      #- 4732 # local and domain local group are covered in another rule
    TargetSid|startswith: 'S-1-5-21-'
    TargetSid|endswith:
      - '-512' # Domain Admins (global)
      - '-518' # Schema Admins (universal)
      - '-519' # Enterprise Admins (universal)
      - '-520' # Group Policy Creator Owners (global)
      #- '-525' # Protected users (global) > focus only on removal actions, not adding . See dedicated rule
      - '-526' # Key Admins (global)
      - '-527' # Enterprise Key Admins (universal)
  condition: selection
falsepositives:
- Administrator activity
level: high
```
## win-ad-domain group membership change (medium risk).yaml
```
title: Medium risk Active Directory group membership change
description: Detects scenarios where a suspicious group membership is changed.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://ss64.com/nt/syntax-groups.html
- https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4728 # security global group member added
      - 4756 # universal group member added
      #- 4732 # local and domain local group are covered in another rule
    TargetSid|startswith: 'S-1-5-21-'
    TargetSid|endswith:
      - '-514' # Domain Guests
      - '-517' # Cert Publishers
      - '-520' # Group Policy Creator Owners
  condition: selection
falsepositives:
- Administrator activity
level: medium
```
## win-ad-extended rights backdoor obfuscation (via localizationDisplayId attr.).yaml
```
title: Extended rights backdoor obfuscation (via localizationDisplayId attribute)
description: Detects scenarios where an attacker modifies the "configuration" partition in order to obfuscate sneaky changes that will allow him to introduce a stealthy AdminSDholder backdoor.
requirements: auditing SACL ("Write all properties") must be placed on the "configuration" partition using the ADSI console (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html). More precisely, you need to browse to Configuration > CN=Configuration > CN=ExtendedRights.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1546-Event%20Triggered%20Execution
- https://adds-security.blogspot.com/2017/08/adminsdholder-backdoor-via-substitution.html
tags:
- attack.defense_evasion
- attack.t1564
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    OperationType: '%%14674' # Value added
    AttributeLDAPDisplayName: localizationDisplayId
    ObjectDN|contains: "CN=Extended-Rights,CN=Configuration"
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
falsepositives:
- Unknown
level: high
```
## win-ad-gMSA password dump - GoldenGMSA.yaml
```
title: Group Managed Service Accounts password dump - GoldenGMSA
description: Detects scenarios where an attacker attempts to dump Group Managed Services account (GMSA) passwords stored on writable domain controllers.
correlation: correlate TargetLogonId from ID 4624 with SubjectLogonId from ID 4662 to identify the source of the dump.
requirements: extended rights auditing enabled
references:
- https://www.semperis.com/blog/golden-gmsa-attack/
- https://twitter.com/cnotin/status/1498952017263353858?t=PX9bWqa2SZLOZnpXbOScUg&s=09
tags:
- attack.credential_access
- attack.t1003
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    ObjectServer: DS
    ObjectType: msKds-ProvRootKey
  filter:
    SubjectUserSid: 'S-1-5-18'
  condition: selection and not filter
falsepositives:
- None
level: high
```
## win-ad-group domain enumeration (CME).yaml

```
title: Domain group enumeration
description: Detects scenarios where an attacker enumerates domain group with tools like CME (--groups).
correlation: correlate TargetLogonId from ID 4624 with SubjectLogonId from ID 4661 to identify the source of the enumeration.
requirements: extended rights auditing enabled (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html)
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1069-Permission%20Groups%20Discovery
- https://hideandsec.sh/books/cheatsheets/page/crackmapexec
- https://www.infosecmatter.com/crackmapexec-module-library/
- https://docs.microsoft.com/en-us/windows/win32/adschema/extended-rights
tags:
- attack.discovery
- attack.t1069.002
- attack.t1087.002
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    ObjectType|contains: '{bf967a9c-0de6-11d0-a285-00aa003049e2}' # Groups class
    ObjectServer: DS
    OperationType: Object Access
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter | count(ObjectName) by Computer > 30 # Count how many different ObjectName (GUID of the group) were enumerated.
  timeframe: 15m
falsepositives:
- Administrator activity
level: high
```
## win-ad-group massive membership changes.yaml
```
title: Massive group membership changes detected
name: massive_group_changes
description: Detects scenarios where an attacker will add a compromised account into different domain groups in order to gain access to all the assets under the control of those concerned groups.
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
tags:
  - attack.persistence
  - attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4728 # security global group member added
      - 4756 # universal group member added
      - 4732 # local and domain local group member added
  condition: selection
falsepositives:
  - Automatic scripts, provisionning accounts
level: medium

---
title: Massive group membership changes detected Count
status: experimental
correlation:
  type: value_count
  rules:
    - massive_group_changes # Referenced here
  group-by:
    - SubjectUserSid
  timespan: 15m
  condition:
    gte: 20
    field: TargetSid # Count how many different groups had a member added in a short period by the same user
level: high
```
## win-ad-honeypot account discovery.yaml
```
title: Active Directory honeypot enumerated by a suspicious host (Bloodhound)
description: Detects scenarios where an attacker is attempting to discover sensitive accounts using tools like Bloodhound. To find out the source of the enumeration, correlate the SubjectLogonId from ID 4662 with TargetLogonId from ID 4624.
requirements: ensure that those accounts are "attractive", documented, do not create any breach and cannot be used against your organization. Moreover, specific SACL for "Everyone" with "ReadProperties" need to be configured on each honeypot object.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1087-Account%20discovery
- https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
- http://www.labofapenetrationtester.com/2018/10/deploy-deception.html
- https://jblog.javelin-networks.com/blog/the-honeypot-buster/
tags:
- attack.discovery
- attack.t1087
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    ObjectName: '%honeypot_guid_list%' # GUID of pre-configured honeypot object(s). Eg: '%{259162f1-58e4-4ee9-9b9c-2baf2a03d376}'
  condition: selection
falsepositives:
- LDAP explorer tools, pentest
level: high
```
## win-ad-honeypot object usage detected.yaml
```
title: Active Directory honeypot used for lateral movement
description: Detects scenarios where an attacker is using
requirements: ensure that those accounts are "attractive", documented, do not create any breach and cannot be used against your organization.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1087-Account%20discovery
- http://www.labofapenetrationtester.com/2018/10/deploy-deception.html
- https://jblog.javelin-networks.com/blog/the-honeypot-buster/
tags:
- attack.lateral_movement
- attack.t1021
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4624
      - 4625
      - 4768
      - 4769
      - 4770
      - 4771
      - 5140
      - 5145
    TargetUserName: '%honeypot_account_list%'
  condition: selection
falsepositives:
- pentest
level: high
```
## win-ad-kerberoast ticket detected.yaml
```
title: Kerberoast ticket request detected
name: kerberoast_ticket_request
description: Detects scenarios where an attacker requests a Kerberoast ticket with low encryption to perform offline brutforce and forge a new ticket to get access to the targeted resource.
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1558-Steal%20or%20Forge%20Kerberos%20Tickets
  - https://www.trustedsec.com/blog/the-art-of-bypassing-kerberoast-detections-with-orpheus/
  - https://blog.harmj0y.net/redteaming/kerberoasting-revisited/
  - https://blog.harmj0y.net/powershell/kerberoasting-without-mimikatz/
  - https://www.hackingarticles.in/as-rep-roasting/
  - https://adsecurity.org/?p=2293
  - https://adsecurity.org/?p=3458
  - https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/
  - https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/
  - https://github.com/nidem/kerberoast
  - https://github.com/skelsec/kerberoast
  - https://posts.specterops.io/capability-abstraction-fbeaeeb26384
  - https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity
  - https://m365internals.com/2021/11/08/kerberoast-with-opsec/
  - https://redcanary.com/blog/marshmallows-and-kerberoasting/
  - https://www.semperis.com/blog/new-attack-paths-as-requested-sts/
  - https://www.trustedsec.com/blog/the-art-of-bypassing-kerberoast-detections-with-orpheus/
  - https://nored0x.github.io/red-teaming/Kerberos-Attacks-Kerbroasting/
tags:
  - attack.credential_access
  - attack.t1558.003
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    #TicketOptions: # depending on the source/tool, the options may change.
    #- 0x40810000
    #- 0x40800000
    #- 0x40810010
    #- 0x40800010
    TicketEncryptionType: 0x17 # RC4-HMAC
    Status: 0x0 # Success
  filter:
    - ServiceName|endswith: "$" # Exclude computer account services
    - ServiceSid: "S-1-5-21-*-0" # Exclude domain Service
    - ServiceSid|endswith: "-502" # Exclude Krbtgt service
    - TargetUserName|contains: "$@" # Exclude computer accounts requests
    - IpAddress:
        - "::1"
        - "127.0.0.1"
        - "%domain_controllers_ips%"
    #- ServiceName NOT IN TargetUserName (NOT SUPPORTED BY ALL SIEM)
  condition: selection and not filter
falsepositives:
  - Applications using RC4 encryption (SAP, Azure AD, legacy applications...)
level: high

---
title: Kerberoast ticket request detected Count
status: experimental
correlation:
  type: value_count
  rules:
    - kerberoast_ticket_request
  group-by:
    - ServiceName
  timespan: 30m
  condition:
    gte: 2
    field: IpAddress
level: high
```
## win-ad-local group enumeration (CME).yaml
```
title: Local domain group enumeration
description: Detects scenarios where an attacker attempts to enumerate domain local groups with tools like CME (--local-groups).
correlation: correlate TargetLogonId from ID 4624 with SubjectLogonId from ID 4661 to identify the source of the enumeration.
requirements: extended rights auditing enabled (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html)
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1069-Permission%20Groups%20Discovery
- https://hideandsec.sh/books/cheatsheets/page/crackmapexec
- https://www.infosecmatter.com/crackmapexec-module-library/
- https://docs.microsoft.com/en-us/windows/win32/adschema/extended-rights?redirectedfrom=MSDN
tags:
- attack.discovery
- attack.t1069.001
- attack.t1087.001
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4661
    ProcessName|endswith: '\lsass.exe'
    ObjectServer: 'Security Account Manager'
    ObjectType: SAM_ALIAS
    ObjectName|startswith:
      - S-1-5-32- # refers to builtin domain local groups
      - S-1-5-21- # refers to others domain local groups
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter | count(Computer) by IpAddress > 30
  timeframe: 15m
falsepositives:
- Administrator activity
level: high
```
## win-ad-local-domain local group membership change (high risk).yaml
```
title: High risk local/domain local group membership change
description: Detects scenarios where a suspicious group membership is changed. Having Microsoft LAPS installed may trigger false positive events for the builtin administrators group triggered by the system account (S-1-5-18).
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://ss64.com/nt/syntax-groups.html
- https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4732 # local and domain local group
    TargetSid|startswith: 'S-1-5-32'
    TargetSid|endswith:
      - '-544' # Administrators
      - '-547' # Power Users
      - '-548' # Account Operators
      - '-549' # Server Operators
      - '-551' # Backup Operators
      - '-578' # Hyper-V Administrators
  filter:
    SubjectUserSid: 'S-1-5-18' # LAPS or others IAM solutions may trigger this as a false positive
  condition: selection and not filter
falsepositives:
- Administrator activity
level: high
```
## win-ad-local-domain local group membership change (medium risk).yaml
```
title: Medium risk local/domain local group membership change
description: Detects scenarios where a suspicious group membership is changed.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://ss64.com/nt/syntax-groups.html
- https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4732 # local and domain local group
    TargetSid|startswith: 'S-1-5-32'
    TargetSid|endswith:
      - '-546'  # Guests
      - '-550'  # Print Operators
      - '-555'  # Remote Desktop Users
      - '-556'  # Network Configuration Operators
      - '-557'  # Incoming Forest Trust Builders
      - '-560'  # Windows Authorization Access Group
      - '-562'  # Distributed COM Users
      - '-568'  # IIS_IUSRS
      - '-569'  # Cryptographic Operators
      - '-573'  # Event Log Readers
      - '-574'  # Certificate Service DCOM Access
      - '-579'  # Access Control Assistance Operators
      - '-580'  # Remote Management Users
      - '-582'  # Storage Replica Administrators
      # add DnsAdmins group but has no default RID
  filter_sytem:
    SubjectUserSid: 'S-1-5-18' # LAPS or others IAM solutions may trigger this as a false positive
  filter_iis:
    TargetSid: "S-1-5-32-568" # IIS_IUSRS
    MemberSid: "S-1-5-20"     # Network service account
  condition: selection and not (filter_sytem OR filter_iis)
falsepositives:
- Administrator activity
level: high
```
## win-ad-login with administrator forged Golden Ticket.yaml
```
title: Administrator login impersonation with forged Golden ticket
description: Detects scenarios where an attacker used a forged Golden ticket to login on a remote host. Per default or if specified, the ticket will be forged using the builtin administrator account (SID *-500). However, and it frequent cases, a non suspicious user name will be specificied during the forge in order to evade security monitoring. The rule works based on this trick.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1558-Steal%20or%20Forge%20Kerberos%20Tickets
- https://infosecwriteups.com/forest-an-asreproast-dcsync-and-golden-ticket-hackthebox-walkthrough-ade8dcdd1ee5
- https://attack.stealthbits.com/how-golden-ticket-attack-works
- https://www.hackingarticles.in/domain-persistence-golden-ticket-attack/
- https://adsecurity.org/?p=1515
- https://en.it-pirate.eu/azure-atp-golden-ticket-attack-how-golden-ticket-attacks-work/
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets
- https://bond-o.medium.com/golden-ticket-attack-ea89553cf9c0
- https://social.technet.microsoft.com/wiki/contents/articles/13813.localized-names-for-administrator-account-in-windows.aspx
- https://www.blackhat.com/docs/us-15/materials/us-15-Metcalf-Red-Vs-Blue-Modern-Active-Directory-Attacks-Detection-And-Protection-wp.pdf
tags:
- attack.credential_access
- attack.t1558.001
author: mdecrevoisier
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    TargetUserSid|endswith: '-500' # Refers to builtin Administrator SID account
    LogonProcessName: Kerberos
  filter:
    TargetUserName: # Excludes builtin admin account names when using a localized Windows OS version (select the ones applicable)
      - 'Administrator'  # Default
      - 'Järjestelmänvalvoja' # Finnish
      - 'Administrateur' # French
      - 'Administrador'  # Spanish / Portuguese
      - 'Administratör'  # Swedish
      - 'Rendszergazda'  # Hungarian
      - 'Администратор'  # Russian
  condition: selection and not filter
falsepositives:
- login with renamed builtin administrator account ("administrator" renamed to "admin_org")
level: high
```
## win-ad-netsync attack.yaml

```
title: NetSYnc attack
description: NetSync allows an attacker to take the NTLM hash of a Domain Controller (DC) machine account ("usually" identified by ending in "$") and using it to obtain the NTLM machine account hash of another machine account through impersonation (similar to, but different from, DCSync). Where DCSync can obtain user account passwords, NetSync is limited to machine accounts. The other main differentiator between DCSync and NetSync is that DCSync will make use of Microsoft's Directory Replication Service (DRS) Remote Protocol, whereas NetSync uses the older Netlogon Remote Protocol (MS-NRPC)
correlation: ID 5145 SubjectLogonId 0x1f4a6c852 AND ID 4624 TargetLogonId 0x1f4a6c852
references:
- https://github.com/Neo23x0/sigma/blob/c56cd2dfff6343f3694ef4fd606a305415599737/rules-unsupported/win_dumping_ntdsdit_via_netsync.yml
- https://fr.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
- https://www.trustedsec.com/blog/the-tale-of-the-lost-but-not-forgotten-undocumented-netsync-part-1/
- https://www.trustedsec.com/blog/the-tale-of-the-lost-but-not-forgotten-undocumented-netsync-part-2/
tags:
- attack.credential_access
- attack.t1003.006
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection: #  lsadump::netsync /dc:<dc_fqdn> /user:dc1$ /ntlm:<ntlmhash> /account:srv02$

  selection_login:
    EventID: 4624
    Computer: '%domain_controllers%'
    TargetUserSid: S-1-5-21-
    LogonType: 3
    AuthenticationPackageName: Kerberos

  selection_share:
    EventID: 5145
    Computer: '%domain_controllers%'
    ShareName: \\*\IPC$
    RelativeTargetName: NETLOGON

  filter:
    - SubjectUserName|endswith: $
    - SubjectUserSid: S-1-5-7 #  ANONYMOUS LOGON
    - IpAddress:
      - '%domain_controllers%'
      - '%exchange_servers%'

  condition: selection_login and selection_share and not filter
falsepositives:
- Exchange servers
level: high
```
## win-ad-password domain policy enumeration.yaml
```
title: Domain password policy enumeration
description: Detects scenarios where an attacker attempts to enumerate the domain password policy with native commands or tools like CME (--pass-pol).
correlation: correlate TargetLogonId from ID 4624 with SubjectLogonId from ID 4661 to identify the source of the enumeration.
requirements: extended rights auditing enabled (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html)
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1201-Password%20Policy%20Discovery
- https://hideandsec.sh/books/cheatsheets/page/crackmapexec
- https://www.infosecmatter.com/crackmapexec-module-library/
- https://github.com/PSGumshoe/PSGumshoe/blob/master/DirectoryService/PrivateFunctions.ps1
tags:
- attack.discovery
- attack.t1201
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4661
    ProcessName|endswith: '\lsass.exe'
    ObjectServer: 'Security Account Manager'
    ObjectName|startswith: DC=
    ObjectType: SAM_DOMAIN
    Properties|contains|all:
      - 'c7407360-20bf-11d0-a768-00aa006e0529' # Domain-Password property set
      - 'bf9679a4-0de6-11d0-a285-00aa003049e2' # lockOutObservationWindow
      - 'bf9679a5-0de6-11d0-a285-00aa003049e2' # Lockout-Duration
      - 'bf9679a6-0de6-11d0-a285-00aa003049e2' # lockoutThreshold
      - 'bf9679bb-0de6-11d0-a285-00aa003049e2' # Max-Pwd-Age attribute
      - 'bf9679c2-0de6-11d0-a285-00aa003049e2' # Min-Pwd-Age
      - 'bf9679c3-0de6-11d0-a285-00aa003049e2' # Min-Pwd-Length
      - 'bf967a09-0de6-11d0-a285-00aa003049e2' # Pwd-History-Length
      - 'bf967a0b-0de6-11d0-a285-00aa003049e2' # Pwd-Properties
      - 'bf967977-0de6-11d0-a285-00aa003049e2' # Force-Logoff
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
falsepositives:
- Administrator activity
level: high
```
## win-ad-password reset on a domain controller (Zero logon).yaml
```
title: Remote domain controller password reset (Zerologon) 
description: Detects scenarios where an attacker attempts to exploit the Zerologon vulnerabiliy which triggers, bsides others things, a password reset on a domain controller.
references:
- https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
- https://stealthbits.com/blog/zerologon-from-zero-to-hero-part-2/
- https://www.lares.com/blog/from-lares-labs-defensive-guidance-for-zerologon-cve-2020-1472/
- https://blog.nviso.eu/2020/09/17/sentinel-query-detect-zerologon-cve-2020-1472/
- https://blog.zsec.uk/zerologon-attacking-defending/
tags:
- attack.lateral_movement
- attack.t1210 # Exploitation of Remote Services 
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  domain_controller:
    Computer: '%domain_controllers%'

  selection_account_changed:
    EventID: 4742 # computer account changed
    TargetUserName|endswith: '$' # focus only on computer accounts

  filter_account_changed:
    PasswordLastSet: '-'
  
  selection_reset:
    EventID: 4724

  condition: domain_controller and (selection_reset or (selection_account_changed and not filter_account_changed) )
falsepositives:
- None 
level: high
```
## win-ad-privilege SeMachineAccountPrivilege abuse.yaml
```
title: Privilege SeMachineAccountPrivilege abuse
description: Detects scenarios where an attacker abuse the SeMachineAccountPrivilege which allows per default any authenticated user to join a computer to the domain. Later on, this computer account can be manipulated in order to elevate privileges.
requirements: despite of this event marked as a "sensitive privilege", I was only able to trigger it by having the audit for "non sensitive privileges" activated.
correlation: correlate with ID 4741 (computer created) using field SubjectLogonId. See rule "Computer account created with privileges" for advance correlation.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation
- https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html
- https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing
- https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041
- https://github.com/WazeHell/sam-the-admin
- https://github.com/cube0x0/noPac
- https://github.com/ly4k/Pachine
- https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing/
tags:
- attack.privilege_escalation
- attack.t1068
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4673
    PrivilegeList: SeMachineAccountPrivilege
    #ProcessName|endswith: \Windows\System32\lsass.exe
  filter:
    - SubjectUserSid: "S-1-5-18"
    - SubjectUserName: '%admin_acounts%'
  condition: selection and not filter
falsepositives:
- Users (shouldn't) or administrators joining a computer to the domain, server provisionning software
level: medium
```
## win-ad-remote local group enumeration (SharpHound).yaml
```
title: Remote local admin group enumeration via SharpHound
description: Detects scenarios where an attacker enumerates local administratos group on multiple hosts via SharpHound.
correlation: correlate SubjectLogonId from ID 4799 with TargetLogonId from ID 4624 to identify the source of the enumeration.
requirements: Windows 10 / Server 2016 and higher
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1069-Permission%20Groups%20Discovery
- https://docs.google.com/presentation/d/1OdufXKGYPgoV1d5jDrMYSe-SYKZ7lcA4w2MFn8AkUWE/edit
- https://www.youtube.com/watch?v=_GJDkbUTSLY
- https://community.rsa.com/t5/rsa-netwitness-platform-blog/keeping-an-eye-on-your-hounds/ba-p/519889
- https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html
- https://twitter.com/SBousseaden/status/1617856006255673345
tags:
- attack.discovery
- attack.t1069.001 # Permission Groups Discovery: Local Groups 
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4799 # Local group membership enumeration
    SubjectUserSid|startswith: 'S-1-5-21-' # Exclude false positives like local system accounts (eg: S-1-5-19 for Local Service)
    TargetSid:
      - 'S-1-5-32-544' # Administrators
      - 'S-1-5-32-555' # Remote Desktop Users
      - 'S-1-5-32-580' # Remote Management Users
    CallerProcessName: '-'  # Process is empty when call is done remotely. Process ID can also be used for the same purpose when it equals to '0x0'.
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter | count(Computer) by SubjectUserSid > 20 # Count on how many hosts this event was produced.
falsepositives:
- Administrators
- Azure Advanced Threat Protection (ATP) sensor
level: medium
```
## win-ad-replication privilege accessed (SecretDump, DCsync).yaml

```
title: Replication privileges accessed to perform DCSync attack
description: Detects scenarios where an attacker use DCSync or SecretDump tool to exfiltrate Active Directory credentials
requirements: extended rights auditing enabled (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html)
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync
- https://attack.stealthbits.com/privilege-escalation-using-mimikatz-dcsync
- https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/
- https://simondotsh.com/infosec/2022/07/11/dirsync.html
- https://www.logpoint.com/en/blog/compromises-in-azure-ad-through-aad-connect/
- https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment/
tags:
  - attack.credential_access
  - attack.t1003.006
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    AccessMask: 0x100
    Properties|contains:
      - 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 # DS-Replication-Get-Changes
      - 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 # DS-Replication-Get-Changes-All
      - 89e95b76-444d-4c62-991a-0facbeda640c # DS-Replication-Get-Changes-In-Filtered-Set
  filter:
    SubjectUserName|endswith: $
  condition: selection and not filter
falsepositives:
- SharePoint accounts (FIM usage)
level: high
```
## win-ad-replication privilege granted (SecretDump, DCsync).yaml
```
title: Replication privileges granted to perform DCSync attack
description: Detects scenarios where an attacker grants replication privilege to an account to exflitrate Active Directory credentials
requirements: auditing SACL "Modify permissions" must be placed on the root domain container (otherwise not visible) using the Active Directory console (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html).
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync
- https://attack.stealthbits.com/privilege-escalation-using-mimikatz-dcsync
- https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/
- https://simondotsh.com/infosec/2022/07/11/dirsync.html
- https://www.logpoint.com/en/blog/compromises-in-azure-ad-through-aad-connect/
tags:
  - attack.credential_access
  - attack.t1222.001
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName: ntSecurityDescriptor
    OperationType: '%%14674'  # value added  
    AttributeValue|contains:
      - 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 # DS-Replication-Get-Changes
      - 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 # DS-Replication-Get-Changes-All
      - 89e95b76-444d-4c62-991a-0facbeda640c # DS-Replication-Get-Changes-In-Filtered-Set
  filter:
    SubjectUserName|endswith: $
  condition: selection and not filter
falsepositives:
- Unknown
level: high
```
## win-ad-sensitive attributes accessed (DCshadow).yaml

```
title: Account accessed to attributes related to DCshadow
description: Detects scenarios where an attacker accessed attributes related to DCshadow attack in order to create a fake domain controller.
correlation: correlate TargetLogonId from ID 4624 with SubjectLogonId from ID 4661 to identify the source of the enumeration.
requirements: extended rights auditing enabled (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html)
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0005-Defense%20Evasion/T1207-Rogue%20domain%20controller
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow
- https://medium.com/@maarten.goet/dcshadow-detecting-a-rogue-domain-controller-replicating-malicious-changes-to-your-active-1e22440df9ad
- https://github.com/AlsidOfficial/UncoverDCShadow
- https://github.com/shellster/DCSYNCMonitor
- https://blog.alsid.eu/dcshadow-explained-4510f52fc19d
- https://stealthbits.com/blog/detecting-dcshadow-with-event-logs/
- https://www.labofapenetrationtester.com/2018/05/dcshadow-sacl.html
- https://blog.stealthbits.com/creating-persistence-with-dcshadow/
- https://book.hacktricks.xyz/windows/active-directory-methodology/dcshadow
tags:
  - attack.defense_evasion
  - attack.t1207
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - 1131f6ac-9c07-11d1-f79f-00c04fc2dcd2 # DS-Replication-Manage-Topology
      - 9923a32a-3607-11d2-b9be-0000f87a36b2 # DS-Install-Replicaextendedright
      #- f0f8ffab-1191-11d0-a060-00aa006c33ed # NTDS-DSA
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
falsepositives:
- new domain controller registration
level: high
```
## win-ad-share access with administrator forged Golden Ticket.yaml
```
title: Shared folder access with forged Golden ticket
description: Detects scenarios where an attacker used a forged Golden ticket to login on a remote shared folder. Per default or if specified, the ticket will be forged using the builtin administrator account (SID *-500). However, and it frequent cases, a non suspicious user name will be specificied during the forge in order to evade security monitoring. The rule works based on this trick.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0006-Credential%20Access/T1558-Steal%20or%20Forge%20Kerberos%20Tickets
- https://infosecwriteups.com/forest-an-asreproast-dcsync-and-golden-ticket-hackthebox-walkthrough-ade8dcdd1ee5
- https://attack.stealthbits.com/how-golden-ticket-attack-works
- https://www.hackingarticles.in/domain-persistence-golden-ticket-attack/
- https://adsecurity.org/?p=1515
- https://en.it-pirate.eu/azure-atp-golden-ticket-attack-how-golden-ticket-attacks-work/
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets
- https://bond-o.medium.com/golden-ticket-attack-ea89553cf9c0
- https://social.technet.microsoft.com/wiki/contents/articles/13813.localized-names-for-administrator-account-in-windows.aspx
- https://www.blackhat.com/docs/us-15/materials/us-15-Metcalf-Red-Vs-Blue-Modern-Active-Directory-Attacks-Detection-And-Protection-wp.pdf
tags:
- attack.credential_access
- attack.t1558.001
author: mdecrevoisier
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 5140
      - 5145
    SubjectUserSid|startswith: 'S-1-5-21'
    SubjectUserSid|endswith: '-500' # Refers to builtin Administrator SID account
  filter:
    SubjectUserName: # Excludes builtin admin account names when using a localized Windows OS version (select the ones applicable)
      - 'Administrator'  # Default
      - 'Järjestelmänvalvoja' # Finnish
      - 'Administrateur' # French
      - 'Administrador'  # Spanish / Portuguese
      - 'Administratör'  # Swedish
      - 'Rendszergazda'  # Hungarian
      - 'Администратор'  # Russian
  condition: selection and not filter
falsepositives:
- login with renamed builtin administrator account ("administrator" renamed to "admin_org")
level: high
```
## win-ad-spn added to an account (command).yaml
```
title: SPN added to an account by command line
description: Detects scenarios where an attacker adds a SPN to an account in order to perform different type of abuse (Kerberoast, delegation abuse, ...)
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://petri.com/how-to-use-setspn-to-set-active-directory-service-principal-names-2
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  category: process_creation
detection: # SetSPN -a MSSQLSvc/srv01.demo.lan demo\srv01
  selection:
    NewProcessName|endswith: '\setspn.exe'
    CommandLine|contains:
      - '/a ' # in 2012: Replaced references to using the –A parameter with reference to use –S instead.
      - '-a '
      - '/s ' # -S will verify that there are no duplicate SPNs
      - '-s '
  condition: selection
falsepositives:
- Administrators adding SPN
- SPN linked to a load balancer
level: high
```
## win-ad-spn enumeration (PowerShell).yaml
```
title: Suspicious SPN enumeration previous to Kerberoasting attack (PowerShell)
description: Detects scenarios where an attacker attempts to retrieve SPN using PowerShell and native tools.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1087-Account%20discovery
- https://github.com/nidem/kerberoast
- https://github.com/cyberark/RiskySPN
- https://pentestlab.blog/2018/06/04/spn-discovery/
- https://adsecurity.org/?p=3458
- https://redcanary.com/blog/marshmallows-and-kerberoasting/
- https://www.security.com/threat-intelligence/us-china-espionage
tags:
- attack.account_discovery
- attack.t1087.002
- attack.credential_access
- attack.t1558.003
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  category:
    - ps_module
    - ps_classic_script
    - ps_script
detection:
  selection1_powershell_native:
    EventID: 800
    EventData|contains:
      - 'System.IdentityModel.Tokens.KerberosRequestorSecurityToken'
      - 'Add-Type -AssemblyName System.IdentityModel'

  selection2_powershell_modern:
    EventID: 4103
    Payload|contains:
      - 'System.IdentityModel.Tokens.KerberosRequestorSecurityToken'
      - 'Add-Type -AssemblyName System.IdentityModel'

  selection3_powershell_block:
    EventID: 4104
    ScriptBlockText|contains:
      - 'System.IdentityModel.Tokens.KerberosRequestorSecurityToken'
      - 'Add-Type -AssemblyName System.IdentityModel'

  condition: 1 of selection*
falsepositives:
- Administrators
level: high
```
## win-ad-spn enumeration (command).yaml
```
title: Suspicious SPN enumeration previous to Kerberoasting attack (native commands)
description: Detects scenarios where an attacker attempts to retrieve SPN using commandline and native tools.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0007-Discovery/T1087-Account%20discovery
- https://github.com/nidem/kerberoast
- https://github.com/cyberark/RiskySPN
- https://pentestlab.blog/2018/06/04/spn-discovery/
- https://adsecurity.org/?p=3458
- https://www.security.com/threat-intelligence/us-china-espionage
tags:
- attack.account_discovery
- attack.t1087.002 # Account Discovery: Domain Account
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  category: process_creation
detection: # full command : 'setspn -T my_domain -Q */*'
  selection:
    NewProcessName|endswith: \setspn.exe
    CommandLine|contains: # Perform query on the specified domain
      - '/Q'
      - '-Q'
  condition: selection
falsepositives:
- Administrators
level: high
```
## win-ad-spn modification of a computer account (DCshadow) (Directory Services).yaml
```
title: Suspicious modification of a fake domain controller SPN (DCshadow) (Directory Services)
description: Detects scenarios where an attacker update the Service Principal Name (SPN) of a computer account in order to perform "Kerberos redirection" and escalate privileges.
requirements: auditing SACL ("Write all properties") must be placed on the OU to monitor using the Active Directory console (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html).
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow
- https://medium.com/@maarten.goet/dcshadow-detecting-a-rogue-domain-controller-replicating-malicious-changes-to-your-active-1e22440df9ad
- https://github.com/AlsidOfficial/UncoverDCShadow
- https://github.com/shellster/DCSYNCMonitor
- https://blog.alsid.eu/dcshadow-explained-4510f52fc19d
- https://stealthbits.com/blog/detecting-dcshadow-with-event-logs/
- https://www.labofapenetrationtester.com/2018/05/dcshadow-sacl.html
- https://blog.stealthbits.com/creating-persistence-with-dcshadow/
- https://book.hacktricks.xyz/windows/active-directory-methodology/dcshadow
tags:
- attack.persistence
- attack.t1098 # Account Manipulation 
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName: servicePrincipalName
    ObjectClas: computer
    OperationType: '%%14674' # Value is added
    AttributeValue|startswith: 'GC/'
  condition: selection
falsepositives:
- Rare administrator modifications on user objects
level: high
```
## win-ad-spn modification of a computer account (DCshadow).yaml
```
title: Suspicious modification of a fake domain controller SPN (DCshadow)
description: Detects scenarios where an attacker updates the Service Principal Name (SPN) of a fake domain controller account in order to perform DCshadow attack.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow
- https://medium.com/@maarten.goet/dcshadow-detecting-a-rogue-domain-controller-replicating-malicious-changes-to-your-active-1e22440df9ad
- https://github.com/shellster/DCSYNCMonitor
- https://stealthbits.com/blog/detecting-dcshadow-with-event-logs/
- https://www.labofapenetrationtester.com/2018/05/dcshadow-sacl.html
- https://blog.stealthbits.com/creating-persistence-with-dcshadow/
- https://book.hacktricks.xyz/windows/active-directory-methodology/dcshadow
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4742
    ServicePrincipalNames|contains: 'GC/'
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
falsepositives:
- New domain controller registration
level: high
```
## win-ad-spn modification of a computer account.yaml
```
title: Suspicious modification of a computer account SPN
description: Detects scenarios where an attacker update the Service Principal Name (SPN) of a computer account in order to perform "Kerberos redirection" and escalate privileges.
references:
- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4742
  filter:
    SubjectUserName|endswith: '$'
    ServicePrincipalNames: '-'
    ServicePrincipalNames|contains: 'GC/' # covered by dedicated DCshadow rule
  condition: selection and not filter
falsepositives:
- Rare administrator modifications on computer objects
level: high
```
## win-ad-spn modification of a user account (Kerberoasting).yaml

```
title: Suspicious modification of a user account SPN to enable Kerberoast attack
description: Detects scenarios where an attacker update the Service Principal Name (SPN) of a user account in order to enable Kerberoast attack and crack its password.
requirements: auditing SACL ("Write all properties") must be placed on the OU to monitor using the Active Directory console (https://www.manageengine.com/products/active-directory-audit/active-directory-auditing-configuration-guide-configure-object-level-auditing-manually.html).
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136
- https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#force-set-spn
- https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/use-audit-active-directory-objects-track-events
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5136 # ID 4738 doesn't report any changes about SPN changes
    AttributeLDAPDisplayName: servicePrincipalName
    ObjectClass: user
    OperationType: '%%14674' # Value is added
  filter:
    AttributeValue: '-'
  condition: selection and not filter
falsepositives:
- Rare administrator modifications on user objects
level: high
```
## win-ad-user account created by a computer account.yaml
```
title: User account created by a computer account
description: Detects scenarios where an attacker would abuse some privileges while realying host credentials to escalate privileges.
references:
- https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4741
tags:
- attack.persistence
- attack.t1136 # user creation
- attack.defense_evesion
- attack.t1036 # masquerading
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
    SubjectUserName|endswith: '$' # Computer account
    SubjectUserSid|startswith: 'S-1-5-21-' # SYSTEM account 'S-1-5-18' would trigger a false positive
  filter:
    TargetUserName|endswith: '$' # covered in another rule: User account creation disguised in a computer account
  condition: selection
falsepositives:
- Exchange servers
level: high
```
## win-ad-user account creation disguised in a computer account.yaml
```
title: User account creation disguised in a computer account
description: Detects scenarios where an attacker creates a user account that fakes a computer account.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1136-Create%20account
- https://www.securonix.com/blog/securonix-threat-labs-security-advisory-threat-actors-target-mssql-servers-in-dbjammer-to-deliver-freeworld-ransomware/
tags:
- attack.persistence
- attack.t1098 # account manipulation
- attack.t1136 # user creation
- attack.defense_evesion
- attack.t0136 # masquerading
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:

  selection_creation:
    EventID: 4720 # User account creation
    TargetUserName|endswith: '$'

  selection_renamed:
    EventID: 4781 # User account name change
    NewTargetUserName|endswith: '$' 

  filter:
    OldTargetUserName|endswith: '$' 

  condition: selection_creation or (selection_renamed and not filter)
falsepositives:
- None
level: high
```
## win-ad-user password change with changeNTLM (Mimikatz).yaml

```
title: User password change using current hash password - ChangeNTLM (Mimikatz)
description: Detects scenarios where an attacker resets a user account by using the compromised NTLM password hash. The newly clear text password defined by the attacker can be then used in order to login into services like Outlook Web Access (OWA), RDP, SharePoint... As ID 4723 refers to user changing is own password, the SubjectSid and TargetSid should be equal. However in a change initiated by Mimikatz, they will be different. Correlate the event ID 4723, 4624 and 5145 using the "SubjectLogonId" field to identify the source of the reset.
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
  - https://stealthbits.com/blog/manipulating-user-passwords-with-mimikatz/
  - https://www.trustedsec.com/blog/azure-account-hijacking-using-mimikatzs-lsadumpsetntlm/
  - https://www.trustedsec.com/blog/manipulating-user-passwords-without-mimikatz/
tags:
  - attack.persistence
  - attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4723 # Self password reset
    TargetSid|startswith: S-1-5-21-
    SubjectUserSid|startswith: S-1-5-21-
    #SubjectUserSid != TargetSid # comparing 2 fields is not possible in SIGMA language
  condition: selection
falsepositives:
  - Admin changing is own account directly using the Active Directory console and not the GUI (ctrl alt suppr)
  - ADFS, MSOL, DirSync, Azure AD Sync
level: high
```
## win-ad-user password change with setNTLM (Mimikatz).yaml
```
title: User password change without previous password known - SetNTLM (Mimikatz)
description: Detects scenarios where an attacker perform a password reset event. This does not require any knowledge of a user’s current password, but it does require to have the "Reset Password" right. Correlate the event ID 4724, 4624 and 5145 using the "SubjectLogonId" field to identify the source of the reset.
references:
  - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
  - https://stealthbits.com/blog/manipulating-user-passwords-with-mimikatz/
  - https://www.trustedsec.com/blog/azure-account-hijacking-using-mimikatzs-lsadumpsetntlm/
  - https://www.trustedsec.com/blog/manipulating-user-passwords-without-mimikatz/
tags:
  - attack.persistence
  - attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection_reset:
    EventID: 4724 # Non self password reset
    TargetSid|startswith: S-1-5-21-
    SubjectUserSid|startswith: S-1-5-21-

  selection_share:
    EventID: 5145
    ShareName: \\*\IPC$
    RelativeTargetName: samr

  selection_login:
    EventID: 4624
    AuthenticationPackageName: NTLM

  filter:
    IpAddress:
      - "127.0.0.1"
      - "::1"

  condition: (selection_reset and selection_share and selection_login) and not filter
falsepositives:
  - None
level: high
```
## wwin-ad-user password set to never expire.yaml
```
title: Account password set to never expire.
description: Detects scenarios where an account password is set to never expire.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4738
    UserAccountControl: '%%2089' # Account never expires - TRUE
  condition: selection
falsepositives:
- IAM solution, User Management solutions
level: medium
```
## win-ad-user renamed to admin to bypass vigilance.yaml
```
title: Account renamed to admin (or likely) account to evade defense
description: Detects scenarios where an attacker rename a non admin account in order to evade SOC & operations vigilance
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
tags:
- attack.persistence
- attack.t1078.002
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4781 # Account name change

  selection_pattern:
    - NewTargetUserName|startswith:
      - admin-
      - adm-
      - <customer pattern>
    - NewTargetUserName|endswith:
      - -admin
      - -adm
      - <customer pattern>
  filter:
    - OldTargetUserName|startswith: # Original target account name should not be already an admin account
      - admin-
      - adm-
      - <customer pattern>
    - OldTargetUserName|endswith:
      - -admin
      - -adm
      - <customer pattern>
    - TargetSid|endswith: '-500' # Exclude default builtin account
  condition: selection_event and selection_pattern and not filter
falsepositives:
- builtin admin account renamed for obfuscation
level: high
```
## win-ad-user set as sensitive had protection removed.yaml
```
title: Account marked as sensitive and cannot be delegated had its protection removed (weakness introduction)
description: Detects scenarios where an attacker removes security protection from a sensitive account to escalate privileges
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://www.sans.org/blog/protecting-privileged-domain-accounts-safeguarding-access-tokens/
- https://www.cyberark.com/resources/threat-research-blog/weakness-within-kerberos-delegation
- https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#protected-users
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4738
    UserAccountControl: '%%2062' # Account is sensitive and cannot be delegated - FALSE
  condition: selection
falsepositives:
- none
level: high
```
## win-ad-user set to use Kerberso DES encryption.yaml
```
title: Account set with Kerberos DES encryption activated (weakness introduction)
description: Detects scenarios where an attacker set an account with DES Kerberos encryption to perform ticket brutforce.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://docs.microsoft.com/en-us/services-hub/health/remediation-steps-ad/remove-the-highly-insecure-des-encryption-from-user-accounts
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4738
    UserAccountControl: '%%2095' # Use only Kerberos DES encryption types - TRUE
  condition: selection
falsepositives:
- None
level: high
```
## win-ad-user set with Kerberos pre-authentication not required (AS-REP Roasting).yaml
```
title: Account set with Kerberos pre-authentication not required (AS-REP Roasting)
description: Detects scenarios where an attacker set an account with Kerberos pre-authentication not required to perform offline brutforce. Account with this status can be checked with the following command > "Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol".
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://social.technet.microsoft.com/wiki/contents/articles/23559.kerberos-pre-authentication-why-it-should-not-be-disabled.aspx
- https://docs.microsoft.com/en-us/services-hub/health/remediation-steps-ad/remove-the-highly-insecure-des-encryption-from-user-accounts
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4738
    UserAccountControl: '%%2096' # Do not require Kerberos preauthentication - TRUE
  condition: selection
falsepositives:
- None
level: high
```
## win-ad-user set with password not required.yaml
```
title: Account set with password not required (weakness introduction)
description: Detects scenarios where an attacker set an account with password not required to perform privilege escalation attack.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/password_never_expires.yaml
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4738
    UserAccountControl: '%%2082' # User account with password set to not require - TRUE
  condition: selection
falsepositives:
- IAM solutions generating accounts
level: medium
```
## win-ad-user set with reversible password encryption.yaml
```
title: Account set with reversible encryption (weakness introduction)
description: Detects scenarios where an attacker set an account with reversible encryption to facilitate brutforce or cracking operations.
references:
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0003-Persistence/T1098.xxx-Account%20manipulation
- https://www.blackhillsinfosec.com/how-i-cracked-a-128-bit-password/
tags:
- attack.persistence
- attack.t1098
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4738
    UserAccountControl: '%%2091' # Store password using reversible encryption - True
  condition: selection
falsepositives:
- None
level: high
```



# https://github.com/mdecrevoisier/SIGMA-detection-rules/windows-azure

## win-os-AD Connect credentials dump via network share.yaml

```
title: Azure Active Directory Connect credentials dump via network share
description: Detects scenarios where an attacker attempt to dump Azure Active Directory Connect credentials via network share.
references:
- https://github.com/fox-it/adconnectdump
- https://o365blog.com/post/adsync/
- https://dirkjanm.io/updating-adconnectdump-a-journey-into-dpapi/
tags:
- attack.credential_access
- attack.t1555
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    ShareName: '\\*\C$'
    RelativeTargetName|contains: '\Windows\ServiceProfiles\ADSync\AppData\Local\Microsoft\Credentials\'
  condition: selection
falsepositives:
- None
level: high
```
## win-os-cmd shell via serial cable (command).yaml
```
title: Serial console process spawning CMD shell (via command)
description: Detects if an attacker open a privileged CMD shell while accessing to an Azure virtual machine via serial cable.
references:
- https://www.mandiant.com/resources/blog/sim-swapping-abuse-azure-serial
tags:
- attack.execution
- attack.t1059.003 # Command and Scripting Interpreter: Windows Command Shell 
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\sacsess.exe' # C:\Windows\System32\sacsess.exe 
    Image|endswith: '\cmd.exe'
  condition: selection
falsepositives:
- Virtual machine recovery by administrator
level: high
```
## win-os-local group enumeration via Azure Virtual machine recovery tool.yaml
```
title: Local group enumeration triggered by Azure Virtual machine recovery tool
description: Detects scenarios where an attacker having compromised a virtual machine via serial cable attempts to enumerate local groups.
references:
- https://www.mandiant.com/resources/blog/sim-swapping-abuse-azure-serial
tags:
- attack.discovery
- attack.t1069.001 # Permission Groups Discovery: Local Groups 
author: mdecrevoisier
status: stable
logsource:
  product: windows
  service: security
detection:
  selection: # C:\Packages\Plugins\Microsoft.Compute.VMAccessAgent\2.4.8\bin\JsonVMAccessExtension.exe
    EventID: 4799
    CallerProcessName|contains: 'Microsoft.Compute.VMAccessAgent'
  condition: selection
falsepositives:
- Virtual machine recovery by administrator 
level: high
```
## win-os-login via Azure serial console.yaml
```
title: Azure Windows virtual machine login via serial console
description: Detects if an attacker logs on using the serial console.
references:
- https://msrc.microsoft.com/blog/2023/08/azure-serial-console-attack-and-defense-part-1/
- https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/serial-console-cmd-ps-commands
- https://www.mandiant.com/resources/blog/sim-swapping-abuse-azure-serial
tags:
- attack.initial_access
- attack.privilege_escalation
- attack.t1078 # valid accounts
author: mdecrevoisier
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonProcess|contains: 'sacsess.exe'
    LogonType: 2
  condition: selection
falsepositives:
- Virtual machine recovery by administrator
level: high
```