--Windows Only
SELECT * FROM sophos_process_activity WHERE subject = 'Process' AND time > strftime ('%s','now','-240 hours') AND (cmdline LIKE '%save HKLM\sam%' OR cmdline LIKE '%save HKLM\system%' OR cmdline LIKE '%save HKLM\security%')