WITH IOC_LIST AS ( WITH RECURSIVE ttp_input (techniqueID, techniqueName, name, method, indicator) AS (
    VALUES
    ('T1003', 'OS Credential Dumping', 'Detect mimikatz by process name', 'process', '{"name": "%mimikatz%"}'),
    ('T1003', 'OS Credential Dumping', 'Detect mimikatz by cmdline args', 'process', '{"anyCmdlines": ["%sekurlsa::%", "%lsadump::%", "%kerberos::%", "%misc::%", "%privilege::%", "%token::%"]}'),
    ('T1003', 'OS Credential Dumping', 'Dumping lsass memory with procdump', 'process', '{"name": "%procdump%", "cmdline": "%ma%lsass.exe%"}'),
    ('T1003', 'OS Credential Dumping', 'Invoke-Mimikatz in Powershell', 'powershell', '{"includes": ["%mimikatz%", "%DumpCreds%"]}'),
    ('T1003', 'OS Credential Dumping', 'Search registry for values named password', 'process', '{"name": "%reg.exe", "cmdline": "%/f%password%"}'),

    ('T1005', 'Data from Local System', 'Find sensitive files in Powershell', 'powershell', '{"includes": ["%Get-ChildItem C:\\Users -Recurse -Include%"]}'),

    ('T1010', 'Application Window Discovery', 'Listing windows with Powershell', 'powershell', '{"includes": ["%MainWindowTitle%"]}'),

    ('T1012', 'Query Registry', 'Querying for proxy configuration', 'process', '{"name": "reg.exe", "cmdline": "%query%software\\microsoft\\windows\\currentversion\\internet settings%"}'),
    ('T1012', 'Query Registry', 'Querying for proxy configuration', 'powershell', '{"includes": ["%Get-ItemProperty%HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion%"]}'),

    ('T1016', 'System Network Configuration Discovery', 'WiFi configuration discovery via netsh wlan', 'process', '{"name": "netsh.exe", "cmdline": "%wlan%"}'),
    ('T1016', 'System Network Configuration Discovery', 'Interface configuration discovery via netsh interface', 'process', '{"name": "netsh.exe", "cmdline": "%interface%"}'),
    ('T1016', 'System Network Configuration Discovery', 'Interface configuration discovery via ipconfig', 'process', '{"name": "ipconfig.exe", "notParentNames": ["WindowsAzureGuestAgent.exe", "WaAppAgent.exe"]}'),
    ('T1016', 'System Network Configuration Discovery', 'Ping the network in order to build the ARP cache', 'process', '{"name": "ping.exe"}'),

    ('T1018', 'Remote System Discovery', 'Listing domain controllers with nltest', 'process','{"name": "nltest.exe", "cmdline": "%/dclist%"}'),
    ('T1018', 'Remote System Discovery', 'Get ARP entries with arp.exe', 'process', '{"name": "arp.exe", "cmdline": "%-a%"}'),
    ('T1018', 'Remote System Discovery', 'Get DNS entries with nslookup', 'process', '{"name": "nslookup.exe"}'),
    ('T1018', 'Remote System Discovery', 'Get NetBIOS data with nbtstat', 'process', '{"name": "nbtstat.exe"}'),
    ('T1018', 'Remote System Discovery', 'List of computers in the Domain with PowerShell', 'powershell', '{"includes": ["%Get-NetComputer%", "%Get-DomainComputer%"]}'),

    ('T1021.001', 'Remote Services: Remote Desktop Protocol', 'Change in connection limits for RDP', 'registry', '{"keyName": "\\registry\\machine\\software\\policies\\microsoft\\windows nt\\terminal services", "valueName": "maxinstancecount"}'),
    ('T1021.001', 'Remote Services: Remote Desktop Protocol', 'Change to termsrv.dll', 'file', '{"pathname": "c:\\windows\\system32\\termsrv%.dll", "eventType": 3}'),
    ('T1021.001', 'Remote Services: Remote Desktop Protocol', 'RDP network connections', 'network', '{"port": 3389}'),
    ('T1021.001', 'Remote Services: Remote Desktop Protocol', 'Process launches of mstsc', 'process', '{"name": "mstsc.exe"}'),

    ('T1021.002', 'Remote Services: SMB/Windows Admin Shares', 'SMB file activity', 'file', '{"pathname": "%\\Device\\Mup\\%", "notProcessCmdlines": ["C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s gpsvc"]}'),
    ('T1021.002', 'Remote Services: SMB/Windows Admin Shares', 'Mounts a network file share on a target computer', 'process', '{"name": "net.exe", "cmdline": "%use%/user:%"}'),

    ('T1031', 'Modify Existing Service', 'Replace a service binary with alternate binary', 'powershell', '{"includes": ["%Get-Service%-Name%Stop-Service%Copy-Item -Path%"]}'),

    ('T1033', 'System Owner/User Discovery', 'Find the current user with whoami', 'process', '{"name": "whoami.exe"}'),
    ('T1033', 'System Owner/User Discovery', 'Find the current user in Powershell', 'powershell', '{"includes": ["%$env:username%", "%Get-NetUser%"]}'),

    ('T1036.005', 'Masquerading: Match Legitimate Name or Location', 'Process called svchost running from non standard location', 'process', '{"name": "svchost.exe", "notPaths": ["C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System64\\svchost.exe"]}'),

    ('T1041', 'Exfiltration Over Command and Control Channel', 'Exfil staged directory', 'powershell', '{"includes": ["%/file/upload%"]}'),

    ('T1047', 'Windows Management Instrumentation', 'Capture process id executable path pid and parent pid before writing to disk', 'process','{"name": "%wmic%", "cmdline": "%process%get%executablepath%name%processid%parentprocessid%"}'),
    ('T1047', 'Windows Management Instrumentation', 'Remotely executes a process over WMI', 'process','{"name": "%wmic%", "cmdline": "%/node%process%call%"}'),

    ('T1053.005', 'Scheduled Task/Job: Scheduled Task', 'Windows events found for new scheduled task', 'winevt', '{"eventId": 4698}'),

    ('T1055', 'Process Injection', 'PowerSploit inject command found in Powershell', 'powershell', '{"includes": ["%Invoke-ReflectivePEInjection%"]}'),
    ('T1055', 'Process Injection', 'Leverage Mavinject for DLL injection', 'process', '{"name": "%nmavinject.exe"}'),

    ('T1057', 'Process Discovery', 'Discover processes in PowerShell', 'powershell', '{"includes": ["%Get-Process%"]}'),
    ('T1057', 'Process Discovery', 'Discover process owners in PowerShell', 'powershell', '{"includes": ["%owner%%get-process%"]}'),
    ('T1057', 'Process Discovery', 'Find LSASS in PowerShell', 'powershell', '{"includes": ["%Get-Process%lsass%"]}'),
    ('T1057', 'Process Discovery', 'tasklist Process Enumeration', 'process', '{"name": "%tasklist%"}'),
    ('T1057', 'Process Discovery', 'SysInternals PSTool Process Discovery', 'process', '{"name": "%pslist%"}'),

    ('T1059.001', 'Command and Scripting Interpreter: PowerShell', 'PowerShell block logging events', 'powershell-block', '{"exclude": ["prompt", "$global:?"]}'),
    ('T1059.001', 'Command and Scripting Interpreter: PowerShell', 'Kill all PowerShell processes', 'powershell', '{"includes": ["%Get-Process%-Name%powershell%Stop-Process%"]}'),
    ('T1059.001', 'Command and Scripting Interpreter: PowerShell', 'Deploy downloaded software', 'powershell', '{"includes": ["%server=%%url=%System.Net.WebClient%"]}'),
    ('T1059.001', 'Command and Scripting Interpreter: PowerShell', 'Impersonate user', 'powershell', '{"includes": ["%.exe -NoNewWindow -PassThru -Credential%"]}'),
    ('T1059.001', 'Command and Scripting Interpreter: PowerShell', 'Bypass ExecutionPolicy', 'registry', '{"keyName": "%Software\\Policies\\Microsoft\\Windows\\PowerShell", "valueName": "ExecutionPolicy", "anyValues": ["ByPass%"]}'),
    ('T1059.001', 'Command and Scripting Interpreter: PowerShell', 'Encoded powershell', 'process', '{"name": "%powershell%", "cmdline": "%-enc%"}'),
    ('T1059.001', 'Command and Scripting Interpreter: PowerShell', 'PowerShell bitly Link Download', 'powershell', '{"includes": ["%https://bit.ly%"]}'),
    ('T1059.001', 'Command and Scripting Interpreter: PowerShell', 'Install PSTools', 'powershell', '{"includes": ["%New-Item%PSTools%"]}'),
    ('T1059.001', 'Command and Scripting Interpreter: PowerShell', 'Move Powershell & triage', 'powershell', '{"includes": ["%Copy-Item%PowerShell%"]}'),

    ('T1059.003', 'Command and Scripting Interpreter: Windows Command Shell', 'Windows Command shell processes', 'process', '{"name": "cmd.exe", "notParentNames": ["CollectGuestLogs.exe"]}'),

    ('T1059.005,007', 'Command and Scripting Interpreter: Visual Basic, JavaScript/JScript', 'Cscript processes', 'process', '{"name": "cscript.exe"}'),
    ('T1059.005,007', 'Command and Scripting Interpreter: Visual Basic, JavaScript/JScript', 'Wscript processes', 'process', '{"name": "wscript.exe"}'),

    ('T1069', 'Permission Groups Discovery', 'Listing permission groups with gpresults', 'process', '{"name": "gpresult.exe", "cmdline": "%/r%"}'),
    ('T1069', 'Permission Groups Discovery', 'Identify all local users', 'powershell', '{"includes": ["%Get-WmiObject%-Class%Win32_UserAccount%"]}'),

    ('T1070.001', 'Indicator Removal on Host: Clear Windows Event Logs', 'Clear Windows Event Logs in PowerShell', 'powershell', '{"includes": ["%Clear-Eventlog%"]}'),

    ('T1070.004', 'Indicator Removal on Host: File Deletion', 'Clear Windows Event Logs in PowerShell', 'powershell', '{"includes": ["%Clear-History%"]}'),

    ('T1074', 'Data Staged', 'Staging files in PowerShell', 'powershell', '{"includes": ["%Copy-Item%", "%New-Item%-Path%-ItemType%"]}'),

    ('T1082', 'System Information Discovery', 'Find OS Version in PowerShell', 'powershell', '{"includes": ["%PSVersionTable%", "%OSVersion.Version%"]}'),
    ('T1082', 'System Information Discovery', 'Run systeminfo', 'process', '{"name": "systeminfo.exe"}'),
    ('T1082', 'System Information Discovery', 'Get OS info from WMI in PowerShell', 'powershell', '{"includes": ["%Get-WmiObject%-class%win32_operatingsystem%"]}'),

    ('T1083', 'File and Directory Discovery', 'Listing files/directories in cmd command line', 'process', '{"name": "cmd.exe", "cmdline": "% dir %"}'),
    ('T1083', 'File and Directory Discovery', 'Listing files/directories in Powershell', 'powershell', '{"includes": ["%Get-ChildItem%-Path%"]}'),

    ('T1087', 'Account Discovery', 'Listing user details with net,exe', 'process', '{"name": "net.exe", "cmdline": "%user%"}'),

    ('T1090', 'Proxy', 'netsh used to set a proxy', 'process', '{"name": "%netsh.exe", "cmdline": "%winhttp%set%proxy%"}'),

    ('T1105', 'Ingress Tool Transfer', 'Listing web requests in powershell', 'powershell', '{"includes": ["%Invoke-WebRequest%", "%iwr %", "%System.Net.WebClient%", "%Start-BitsTransfer %"]}'),

    ('T1113', 'Screen Capture', 'Listing screen captures in powershell', 'powershell', '{"includes": ["%CopyFromScreen%"]}'),

    ('T1135', 'Network Share Discovery', 'Listing network shares in Powershell', 'powershell', '{"includes": ["%Get-SmbShare%"]}'),

    ('T1136.001', 'Create Account: Local Account', 'Windows event for new account', 'winevt', '{"eventId": 4720}'),

    ('T1204.002', 'User Execution - Malicious File', 'Office launching processes', 'process', '{"anyParentNames": ["%outlook%", "%word%", "%excel%", "%powerpnt%", "%msaccess%", "%onenote%"]}'),

    ('T1218.005', 'Signed Binary Proxy Execution: Mshta', 'Mshta processes', 'process', '{"name": "mshta.exe"}'),

    ('T1218.008', 'Signed Binary Proxy Execution: Odbcconf', 'Odbcconf processes', 'process', '{"name": "%odbcconf.exe"}'),

    ('T1218.011', 'Signed Binary Proxy Execution: Rundll32', 'Rundll32 processes', 'process', '{"name": "rundll32.exe"}'),

    ('T1219', 'Remote Access Tools', 'Check for Ammyy Admin execution', 'process', '{"name": "Ammyy%Admin.exe", "cmdline": "%-connect%"}'),
    ('T1219', 'Remote Access Tools', 'Check for TeamViewer execution', 'process', '{"name": "TeamViewer.exe", "cmdline": "%assign%"}'),
    ('T1219', 'Remote Access Tools', 'Check for VNC server execution', 'process', '{"name": "vncserver.exe", "anyCmdlines": ["%-connect%", "%-proxy%"]}'),
    ('T1219', 'Remote Access Tools', 'Check for TightVNC execution', 'process', '{"name": "tvnserver.exe", "cmdline": "%-connect%"}'),

    ('T1497', 'Virtualization Sandbox Evasion', 'Determine if the system is virtualized or physical', 'process', '{"name": "powershell.exe", "cmdline": "%get-wmiobject win32_computersystem | fl model"}'),

    ('T1543.003', 'Create or Modify System Process: Windows Service', 'Service creation detected in the registry', 'registry', '{"keyName": "%System\\%ControlSet%\\Services\\%", "valueName": "Start", "eventType": 5, "anyValues": [0, 1, 2], "notKeyNames": ["%\\BITS", "%\\SntpService", "%\\sntp"]}'),

    ('T1546.011', 'Event Triggered Execution: Application Shimming', 'New shim database file created', 'file', '{"pathname": "C:\\Windows\\AppPatch\\Custom\\%.sdb", "eventType": 0}'),
    ('T1546.011', 'Event Triggered Execution: Application Shimming', 'Shim registry key creation and/or modification', 'registry', '{"keyName": "%SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom%", "eventType": 5}'),
    ('T1546.011', 'Event Triggered Execution: Application Shimming', 'Shim registry key creation and/or modification', 'registry', '{"keyName": "%SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB%", "eventType": 5}'),
    ('T1546.011', 'Event Triggered Execution: Application Shimming', 'sdbinst.exe was executed', 'process', '{"name": "sdbinst.exe"}'),

    ('T1547.001', 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder', 'Added registry run key', 'registry', '{"anyKeyNames": ["%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run%", "%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices%", "%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run%"], "eventType": 5}'),
    ('T1547.001', 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder', 'Added registry run key', 'registry', '{"keyName": "%SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "anyValueNames": ["Userinit", "Shell", "Load"] , "eventType": 5}'),
    ('T1547.001', 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder', 'Added registry run key', 'registry', '{"keyName": "%System\\CurrentControlSet\\Control\\Session Manager", "valueName": "BootExecute", "eventType": 5}'),
    ('T1547.001', 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder', 'Added to the startup folder', 'file', '{"anyPathnames": ["%\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\%", "%\\Users\\%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup%"], "anyEventTypes": [0, 1, 3]}'),

    ('T1548.002', 'Abuse Elevation Control Mechanism: Bypass User Access Control', 'Registry keys used for UAC bypass', 'registry', '{"anyKeyNames": ["\\REGISTRY\\USER\\%\\ms-settings\\shell\\Open\\Command", "\\REGISTRY\\USER\\%\\mscfile\\shell\\Open\\Command", "\\REGISTRY\\USER\\%\\exefile\\shell\\Runas\\Command\\isolatedCommand", "\\REGISTRY\\USER\\%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe", "\\REGISTRY\\USER\\%\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\Open\\Command"], "notValueNames": ["DelegateExecute"], "eventType": 5}'),
    ('T1548.002', 'Abuse Elevation Control Mechanism: Bypass User Access Control', 'Registry keys used for UAC bypass', 'registry', '{"keyNames": "\\REGISTRY\\MACHINE\\Software\\%", "valueName": "EnableLUA", "anyValues": [0]}'),
    ('T1548.002', 'Abuse Elevation Control Mechanism: Bypass User Access Control', 'Get UAC Status', 'powershell', '{"includes": ["%get-uac%"]}'),
    ('T1548.002', 'Abuse Elevation Control Mechanism: Bypass User Access Control', 'DLL Hijack using Akagi.exe', 'process', '{"name": "%akagi64%"}'),
    ('T1548.002', 'Abuse Elevation Control Mechanism: Bypass User Access Control', 'Bypass-UAC PowerShell', 'powershell', '{"includes": ["%Bypass-UAC%"]}'),

    ('T1559.002', 'Inter-Process Communication: Dynamic Data Exchange', 'DDE configuration modified in the registry', 'registry', '{"keyName": "%Software\\Microsoft\\Office\\%", "anyValueNames": ["DontUpdateLinks", "DisableEmbeddedFiles", "DDEAllowed", "DDECleaned"]}'),

    ('T1560', 'Archive Collected Data', 'Listing launched rar processes', 'process', '{"name": "rar.exe", "cmdline": "% a %"}'),
    ('T1560', 'Archive Collected Data', 'Listing launched 7z processes', 'process', '{"name": "7z.exe", "cmdline": "% a %"}'),
    ('T1560', 'Archive Collected Data', 'Listing launched winzip processes', 'process', '{"name": "winzip%.exe", "cmdline": "% -a %"}'),
    ('T1560', 'Archive Collected Data', 'Compress archive in PowerShell', 'powershell', '{"includes": ["%Compress-Archive%", "%[System.IO.Compression.ZipFile]::CreateFromDirectory%"]}'),

    ('T1562.001', 'Impair Defenses: Disable or Modify Tools', 'Disable Windows Defender', 'powershell', '{"includes": ["%Set-MpPreference%-DisableIOAVProtection%", "%Set-MpPreference%-DisableRealtimeMonitoring%", "%Set-MpPreference%-DisableIntrusionPreventionSystem%", "%Set-MpPreference%-DisableScriptScanning%", "%Set-MpPreference%-EnableControlledFolderAccess%Disabled%"]}'),

    ('T1562.004', 'Impair Defenses: Disable or Modify System Firewall', 'Firewall rules change detected in the registry', 'registry', '{"anyKeyNames": ["\\REGISTRY\\Machine\\SYSTEM\\%\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules", "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules"], "anyEventTypes": [5, 6], "notProcessCmdlines": ["C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s gpsvc"]}'),

    ('T1569.002', 'System Services: Service Execution', 'Using sc directly to manipulate a service', 'process', '{"name": "sc.exe", "anyCmdlines": ["% start %", "% pause %", "% interrogate %", "% continue %", "% stop %", "% config %", "% description %", "% failure %", "% failureflag %", "% sidtype %", "% privs %", "% managedaccount %", "% delete %", "% create %", "% control %", "% sdset %", "% triggerinfo %", "% preferrednode %"], "notCmdlines": ["% wuauserv", "% w32time task_started"]}'),

    ('T1570', 'Lateral Tool Transfer', 'Using PsExec', 'process', '{"name": "%PsExec%"}'),
    ('T1570', 'Lateral Tool Transfer', 'Launch Remote PSession', 'powershell', '{"includes": ["%New-PSSession%-ComputerName%"]}'),

    ('TXXXX', 'Empire temp', 'Empire temp', 'powershell', '{"includes": ["% -NoP -sta -NonI -W Hidden -Enc %", "% -noP -sta -w 1 -enc %", "% -NoP -NonI -W Hidden -enc %", "% -noP -sta -w 1 -enc%", "% -enc  SQB%", "% -nop -exec bypass -EncodedCommand SQB%"]}')
), ttp AS (
    SELECT
        techniqueID,
        CAST (techniqueName AS TEXT) TechniqueName,
        CAST (name AS TEXT) Name,
        CAST (method AS TEXT) Method,
        CASE method
            WHEN 'file' THEN json_patch('{"pathname": "%", "anyPathnames": ["%"], "eventType": "%", "anyEventTypes": ["%"]}', indicator)
            WHEN 'network' THEN json_patch('{"port": "%"}', indicator)
            WHEN 'powershell' THEN json_patch('{"includes": ["%"]}', indicator)
            WHEN 'powershell-block' THEN json_patch('{"excludes": ["%"]}', indicator)
            WHEN 'process' THEN json_patch('{"name": "%", "cmdline": "%", "anyCmdlines": ["%"], "anyParentNames": ["%"]}', indicator)
            WHEN 'registry' THEN json_patch('{"keyName": "%", "anyKeyNames": ["%"], "valueName": "%", "anyValueNames": ["%"], "eventType": "%", "anyEventTypes": ["%"], "anyValues": ["%"]}', indicator)
            WHEN 'winevt' THEN json_patch('{"eventId": "%"}', indicator)
            ELSE indicator
        END indicator
    FROM ttp_input
), for(x) AS (
   VALUES (CAST($$startTime$$ AS INT))
   UNION ALL
   SELECT x + 60 FROM for WHERE x <= $$endTime$$
)

SELECT NULL Time, NULL TechniqueID, NULL TechniqueName, NULL QueryName, NULL Evidence WHERE 1 = 2

UNION ALL

SELECT
    datetime(file.time, 'unixepoch'),
    ttp.techniqueID,
    ttp.techniqueName,
    ttp.name,
    printf(
        "%s (%s) %s %s",
        process.processName,
        process.sophosPID,
        CASE file.eventType
            WHEN 0 THEN 'created'
            WHEN 1 THEN 'renamed'
            WHEN 2 THEN 'deleted'
            WHEN 3 THEN 'modified'
            WHEN 4 THEN 'hardlinked'
            WHEN 5 THEN 'modified timestamps of'
            WHEN 6 THEN 'modified permissions of'
            WHEN 7 THEN 'modified ownership of'
            WHEN 8 THEN 'accessed'
            WHEN 9 THEN 'mapped'
        END,
        file.pathname
    ) "Evidence"
FROM for
LEFT JOIN sophos_file_journal file ON (file.time >= for.x AND file.time <= for.x + 60 AND subject IN ('FileBinaryChanges', 'FileDataChanges', 'FileOtherChanges'))
JOIN ttp ON (
    ttp.method = 'file'
    AND
    file.pathname LIKE json_extract(ttp.indicator, '$.pathname')
    AND
    (file.pathname LIKE json_extract(ttp.indicator, '$.pathname') OR file.targetPathname LIKE json_extract(ttp.indicator, '$.pathname'))
    AND
    (select count(*) from json_each(ttp.indicator, '$.anyPathnames') where file.pathname LIKE value OR file.targetPathname LIKE value) > 0
    AND
    file.eventType LIKE json_extract(ttp.indicator, '$.eventType')
    AND
    (select count(*) from json_each(ttp.indicator, '$.anyEventTypes') where file.eventType LIKE value) > 0
    AND
    (select count(*) from json_each(ttp.indicator, '$.notProcessNames') where process.processName LIKE value) = 0
    AND
    (select count(*) from json_each(ttp.indicator, '$.notProcessPaths') where process.pathName LIKE value) = 0
    AND
    (select count(*) from json_each(ttp.indicator, '$.notProcessCmdlines') where process.cmdline LIKE value) = 0
)
LEFT JOIN sophos_process_journal process USING (sophosPID)

UNION ALL

SELECT
    datetime(network.time, 'unixepoch'),
    ttp.techniqueID,
    ttp.techniqueName,
    ttp.name,
    printf(
        "%s (%s) connected to %s:%s from %s:%s",
        process.processName,
        process.sophosPID,
        network.destination,
        network.destinationPort,
        network.source,
        network.sourcePort
    )
FROM for
LEFT JOIN sophos_network_journal network ON (network.time >= for.x AND network.time <= for.x + 60)
JOIN ttp ON (
    ttp.method = 'network'
    AND
    (
        network.sourcePort LIKE json_extract(ttp.indicator, '$.port')
        OR
        network.destinationPort LIKE json_extract(ttp.indicator, '$.port')
    )
)
LEFT JOIN sophos_process_journal process USING (sophosPID)


UNION ALL

SELECT
    datetime(process.time, 'unixepoch'),
    ttp.techniqueID,
    ttp.techniqueName,
    ttp.name,
    printf(
        "%s (%s) launched %s (%s) with the command line %s",
        parent.processName,
        parent.sophosPID,
        process.processName,
        process.sophosPID,
        process.cmdline
    )
FROM for
LEFT JOIN sophos_process_journal process ON (process.time >= for.x AND process.time <= for.x + 60 AND process.eventType = 0)
LEFT JOIN sophos_process_journal parent ON parent.sophosPID = process.parentSophosPID
JOIN ttp ON (
    (
        ttp.method = 'powershell'
        AND
        process.processName LIKE 'powershell.exe'
        AND
        (select count(*) from json_each(ttp.indicator, '$.includes') where process.cmdline LIKE value) > 0
    )
    OR
    (
        ttp.method = 'process'
        AND
        process.processName LIKE json_extract(ttp.indicator, '$.name')
        AND
        process.cmdline LIKE json_extract(ttp.indicator, '$.cmdline')
        AND
        (select count(*) from json_each(ttp.indicator, '$.anyCmdlines') where process.cmdline LIKE value) > 0
        AND
        (select count(*) from json_each(ttp.indicator, '$.notCmdlines') where process.cmdline LIKE value) = 0
        AND
        (select count(*) from json_each(ttp.indicator, '$.notPaths') where process.pathName LIKE value) = 0
        AND
        (select count(*) from json_each(ttp.indicator, '$.anyParentNames') where parent.processName LIKE value) > 0
        AND
        (select count(*) from json_each(ttp.indicator, '$.notParentNames') where parent.processName LIKE value) = 0
    )
)

UNION ALL

SELECT
    datetime(registry.time, 'unixepoch'),
    ttp.techniqueID,
    ttp.techniqueName,
    ttp.name,
    printf(
        "%s (%s) %s %s%s",
        process.processName,
        process.sophosPID,
        CASE registry.eventType
            WHEN 0 THEN 'created'
            WHEN 1 THEN 'renamed'
            WHEN 2 THEN 'deleted'
            WHEN 3 THEN 'changed permissions of'
            WHEN 4 THEN 'changed ownership of'
            WHEN 5 THEN 'set'
            WHEN 6 THEN 'deleted'
        END,
        registry.keyName,
        CASE registry.eventType
            WHEN 5 THEN "\" || registry.valueName || ' to ' || registry.value
            WHEN 6 THEN "\" || registry.valueName
            ELSE ''
        END,
        registry.valueName,
        registry.value
    )
FROM for
LEFT JOIN sophos_registry_journal registry ON (registry.time >= for.x and registry.time <= for.x + 60)
JOIN ttp ON (
    ttp.method = 'registry'
    AND
    registry.keyName LIKE json_extract(ttp.indicator, '$.keyName')
    AND
    (select count(*) from json_each(ttp.indicator, '$.notKeyNames') where registry.keyName LIKE value) = 0
    AND
    (select count(*) from json_each(ttp.indicator, '$.anyKeyNames') where registry.keyName LIKE value) > 0
    AND
    registry.valueName LIKE json_extract(ttp.indicator, '$.valueName')
    AND
    (select count(*) from json_each(ttp.indicator, '$.notValueNames') where registry.valueName LIKE value) = 0
    AND
    (select count(*) from json_each(ttp.indicator, '$.anyValueNames') where registry.valueName LIKE value) > 0
    AND
    registry.eventType LIKE json_extract(ttp.indicator, '$.eventType')
    AND
    (select count(*) from json_each(ttp.indicator, '$.anyEventTypes') where registry.eventType LIKE value) > 0
    AND
    (select count(*) from json_each(ttp.indicator, '$.anyValues') where registry.value LIKE value) > 0
    AND
    (select count(*) from json_each(ttp.indicator, '$.notProcessCmdlines') where process.cmdline LIKE value) = 0
)
LEFT JOIN sophos_process_journal process USING (sophosPID)
WHERE
    registry.keyName NOT LIKE '%Local Settings\MrtCache\C:%5CWindows%5CSystemResources%5CWindows.UI.SettingsAppThreshold%5CWindows.UI.SettingsAppThreshold.pri\1d54da15a9ebcee\28a69d01'
    AND registry.keyName NOT LIKE '%Local Settings\MrtCache\C:%5CWindows%5CSystemResources%5CMicrosoft.Windows.SecHealthUI%5CMicrosoft.Windows.SecHealthUI.pri\1d5b0a114be9cf1\28a69d01'

UNION ALL

SELECT
    datetime(time, 'unixepoch'),
    ttp.techniqueID,
    ttp.techniqueName,
    ttp.name,
    printf(
        "Executed block id %s%s%s%s",
        script_block_id,
        CASE script_path
            WHEN  '' THEN ''
            ELSE ' (' || script_path || ')'
        END,
        CHAR(10),
        SUBSTR(script_text, 1, 32766)
    )
FROM (
    SELECT *
    FROM sophos_powershell_events process
    WHERE time > $$startTime$$ AND time < $$endTime$$
    LIMIT -1 OFFSET 0
)
JOIN ttp ON (
    (
        ttp.method = 'powershell'
        AND
        (select count(*) from json_each(ttp.indicator, '$.includes') where script_text LIKE value) > 0
    )
    OR
    (
        ttp.method = 'powershell-block'
        AND
        (select count(*) from json_each(ttp.indicator, '$.exclude') where script_text LIKE value) = 0
    )
)

UNION ALL

SELECT
    datetime(time, 'unixepoch'),
    ttp.techniqueID,
    ttp.techniqueName,
    ttp.name,
    data
FROM (
    SELECT *
    FROM sophos_windows_events process
    WHERE time > $$startTime$$ AND time < $$endTime$$
    LIMIT -1 OFFSET 0
)
JOIN ttp ON (
    ttp.method = 'winevt'
    AND
    eventId LIKE json_extract(ttp.indicator, '$.eventId')
)

ORDER BY Time )
SELECT * FROM IOC_LIST

UNION ALL

SELECT
    datetime(file.time, 'unixepoch') "Time",
    "T1555.003" "TechniqueID",
    "Credentials from Password Stores: Credentials from Web Browsers" "TechniqueName",
    "Chrome login data" "QueryName",
    printf(
        "%s (%s) unexpectedly read %s",
        process.processName,
        process.sophosPID,
        file.pathname
    ) "Evidence"
FROM
    sophos_file_journal file
    LEFT JOIN sophos_process_journal process ON process.sophosPID = file.sophosPID
WHERE
    subject = 'FileOtherReads'
    AND file.pathname LIKE '%\AppData\Local\Google\Chrome\User Data\%\Login Data'
    AND process.processName NOT LIKE 'chrome.exe'
    AND process.pathname NOT LIKE 'C:\Program Files\Sophos\Endpoint Defense\SSPService.exe'
    AND file.time > $$startTime$$
    AND file.time < $$endTime$$
UNION
SELECT
    datetime(file.time, 'unixepoch') "Time",
    "T1555.003" "TechniqueID",
    "Credentials from Password Stores: Credentials from Web Browsers" "Technique Name",
    "Firefox login data" "Query Name",
    printf(
        "%s (%s) unexpectedly read %s",
        process.processName,
        process.sophosPID,
        file.pathname
    ) "Evidence"
FROM
    sophos_file_journal file
    LEFT JOIN sophos_process_journal process ON process.sophosPID = file.sophosPID
WHERE
    subject = 'FileOtherReads'
    AND file.pathname LIKE '%\AppData\%\\Mozilla\Firefox\Profiles\%\key4.db'
    AND process.processName NOT LIKE 'firefox.exe'
    AND process.pathname NOT LIKE 'C:\Program Files\Sophos\Endpoint Defense\SSPService.exe'
    AND file.time > $$startTime$$
    AND file.time < $$endTime$$
UNION
SELECT
    datetime(file.time, 'unixepoch') "Time",
    "T1555.003" "TechniqueID",
    "Credentials from Password Stores: Credentials from Web Browsers" "TechniqueName",
    "Edge login data" "QueryName",
    printf(
        "%s (%s) unexpectedly read %s",
        process.processName,
        process.sophosPID,
        file.pathname
    ) "Evidence"
FROM
    sophos_file_journal file
    LEFT JOIN sophos_process_journal process ON process.sophosPID = file.sophosPID
WHERE
    subject = 'FileOtherReads'
    AND file.pathname LIKE '%\AppData\Local\Microsoft\Edge\User Data\%\Login Data'
    AND process.processName NOT LIKE 'msedge.exe'
    AND process.pathname NOT LIKE 'C:\Program Files\Sophos\Endpoint Defense\SSPService.exe'
    AND file.time > $$startTime$$
    AND file.time < $$endTime$$

UNION ALL

SELECT
    datetime(time, 'unixepoch') "Time",
    "T1078" "TechniqueID",
    "Valid Accounts" "TechniqueName",
    "First time log in from a remote address" "QueryName",
    printf(
        "%s logged in from %s for the first time in the time window",
        JSON_EXTRACT(data, '$.targetUserName'),
        JSON_EXTRACT(data, '$.ipAddress')
    ) "Evidence"
FROM
    sophos_winsec_journal
WHERE
    time > ($$endTime$$ - (60 * 60 * 24))
    AND time < $$endTime$$
    AND eventType = 4624
    AND JSON_EXTRACT(data, '$.ipAddress') != "::1"
    AND JSON_EXTRACT(data, '$.ipAddress') != '127.0.0.1'
    AND JSON_EXTRACT(data, '$.ipAddress') != ''
GROUP BY
    JSON_EXTRACT(data, '$.ipAddress')
HAVING
    MIN(time) > CAST($$startTime$$ AS INT)
UNION
SELECT
    datetime(time, 'unixepoch') "Time",
    "T1078" "TechniqueID",
    "Valid Accounts" "TechniqueName",
    "First time log in from a remote address by a user" "QueryName",
    printf(
        "%s logged in from %s for the first time in the time window",
        JSON_EXTRACT(data, '$.targetUserName'),
        JSON_EXTRACT(data, '$.ipAddress')
    ) "Evidence"
FROM
    sophos_winsec_journal
WHERE
    time > ($$endTime$$ - (60 * 60 * 24))
    AND time < $$endTime$$
    AND eventType = 4624
    AND JSON_EXTRACT(data, '$.ipAddress') != "::1"
    AND JSON_EXTRACT(data, '$.ipAddress') != '127.0.0.1'
    AND JSON_EXTRACT(data, '$.ipAddress') != ''
GROUP BY
    JSON_EXTRACT(data, '$.ipAddress'),
    JSON_EXTRACT(data, '$.targetUserName')
HAVING
    MIN(time) > CAST($$startTime$$ AS INT)
UNION
SELECT
    datetime(time, 'unixepoch') "Time",
    "T1078" "TechniqueID",
    "Valid Accounts" "TechniqueName",
    "First time log in by a user" "QueryName",
    printf(
        "%s logged in from %s for the first time in the time window",
        JSON_EXTRACT(data, '$.targetUserName'),
        JSON_EXTRACT(data, '$.ipAddress')
    ) "Evidence"
FROM
    sophos_winsec_journal
WHERE
    time > ($$endTime$$ - (60 * 60 * 24))
    AND time < $$endTime$$
    AND eventType = 4624
GROUP BY
    JSON_EXTRACT(data, '$.targetUserName')
HAVING
    MIN(time) > CAST($$startTime$$ AS INT)

UNION ALL

SELECT
    datetime(time, 'unixepoch') "Time",
    "T1110.001" "TechniqueID",
    "Brute Force" "TechniqueName",
    "Password Guessing" "QueryName",
    printf(
        "20 or more failed login attempts for user: %s",
        JSON_EXTRACT(data, '$.targetUserName')
    ) "Evidence"
FROM
  sophos_winsec_journal
WHERE
  eventType = 4625
  AND time > $$startTime$$
  AND time < $$endTime$$
GROUP BY
  JSON_EXTRACT(data, '$.targetUserName')
HAVING
  COUNT(*) >= 20