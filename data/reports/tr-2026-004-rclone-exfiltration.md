# TR-2026-004: Data theft with rclone and 7-Zip before ransomware

ATT&CK: T1048

Summary: Before encrypting systems, the group compressed finance and HR shares with password-protected 7-Zip archives and uploaded them with rclone to a cloud storage provider. Transfers reached tens of gigabytes over a few hours, mostly overnight.

Indicators: rclone.exe or curl uploads to external hosts; 7z archives with -p passwords; outbound volume far above the host baseline.

Response: block the destination, preserve rclone configuration files, and scope which shares were read. Nightly Veeam or robocopy jobs to internal backup servers are normal at similar volumes.
