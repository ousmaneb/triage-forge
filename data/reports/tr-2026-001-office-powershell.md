# TR-2026-001: Office documents launching encoded PowerShell

ATT&CK: T1059.001

Summary: A phishing wave delivered Word documents whose macros started powershell.exe with a hidden window and an -enc argument. The decoded payload used Net.WebClient DownloadString to fetch a second-stage script from hosts in 185.220.101.0/24, then opened a reverse TCP connection on port 443.

Indicators: parent process winword.exe or outlook.exe; arguments -nop -w hidden -enc; outbound connection shortly after launch.

Response: isolate the host, collect the decoded script and the original document, reset the user's credentials, and block the download host. Search for the same parent-child pair across the fleet.
