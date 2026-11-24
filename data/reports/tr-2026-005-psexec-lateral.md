# TR-2026-005: Lateral movement with PsExec and admin shares

ATT&CK: T1021.002

Summary: Using a stolen admin password, the actor ran psexec -s against dozens of workstations within minutes and mounted ADMIN$ shares to stage tools. WMIC process call create was used where PsExec was blocked.

Indicators: psexec or wmic launched by cmd.exe or powershell.exe on a user workstation; many distinct destination hosts; net use to ADMIN$.

Response: disable the account, isolate the source host, and review every destination for staged binaries. Patch jobs run from services.exe or SCCM and are not lateral movement.
