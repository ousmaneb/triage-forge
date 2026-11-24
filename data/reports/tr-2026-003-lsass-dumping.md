# TR-2026-003: LSASS dumping with built-in Windows tools

ATT&CK: T1003.001

Summary: After gaining a foothold, the actor dumped LSASS memory with rundll32 and comsvcs.dll MiniDump, writing the dump to C:\temp. In a second case procdump -ma lsass.exe wrote to C:\Users\Public. Stolen hashes were used for lateral movement within hours.

Indicators: rundll32 loading comsvcs.dll with MiniDump; procdump targeting lsass.exe; dump files in Temp or Public folders.

Response: isolate the host immediately, treat every credential used on it as compromised, and reset privileged accounts first. Defender scans and WerFault activity against LSASS are expected and should be closed as benign.
