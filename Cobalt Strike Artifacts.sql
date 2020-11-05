/* Find artifacts related to cobalt strike */
SELECT 
   datetime,
   eventid,
   JSON_EXTRACT(data, '$.EventData.AccountName') AS AccountName,
   JSON_EXTRACT(data, '$.EventData.ServiceName') AS ServiceName,
   JSON_EXTRACT(data, '$.EventData.ImagePath') AS ImagePath,
   JSON_EXTRACT(data, '$.EventData.ServiceType') AS ServiceType,
   JSON_EXTRACT(data, '$.EventData.StartType') AS StartType
FROM sophos_windows_events
WHERE source = 'System' 
   AND ImagePath LIKE '%powershell%' 
   AND eventid = 7045
   AND (ImagePath LIKE '%JAB%' OR ImagePath LIKE '%SQB%' OR ImagePath LIKE '%H4s%' OR ImagePath LIKE '%invoke%' OR ImagePath LIKE '%-enc%' OR ImagePath LIKE '%IEX%' OR ImagePath LIKE '%downloadstring%');
