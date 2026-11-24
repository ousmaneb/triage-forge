# TR-2026-006: Shadow copy deletion as a ransomware precursor

ATT&CK: T1490, T1053.005

Summary: Minutes before encryption began, vssadmin delete shadows /all /quiet and bcdedit recoveryenabled no ran on file servers, followed by a scheduled task that relaunched the encryptor every 15 minutes.

Indicators: shadow copy deletion; recovery disabled; scheduled tasks every few minutes pointing at Public or Temp folders or encoded PowerShell.

Response: isolate affected servers at once, protect backups, and remove the persistence task. vssadmin list shadows and wbadmin queries are routine and benign.
