SELECT datetime(time,'unixepoch') Date_Time, sophospid, subject, action, keyname, valuename, value 
FROM sophos_process_activity 
WHERE subject = 'Registry' 
   AND time > strftime('%s','now','-$$Hours to look back from now$$ hours') 
   AND keyname LIKE '%Image File Execution Options%'