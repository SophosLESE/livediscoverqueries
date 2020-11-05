--Linux and Mac
SELECT 
   datetime(time,'unixepoch') Date_Time, 
   path, cmdline, cwd, pid, parent
FROM process_events pe WHERE pe.path LIKE '%/bin/%' AND pe.path NOT LIKE '/opt/sophos%' ORDER by pe.path ASC, Date_Time