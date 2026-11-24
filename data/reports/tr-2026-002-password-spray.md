# TR-2026-002: Password spraying against VPN and Microsoft 365

ATT&CK: T1110, T1078

Summary: An external actor tried a small set of common passwords against hundreds of accounts from rotating IP addresses in 45.155.205.0/24. Each account saw dozens of failures, and two accounts later had successful sign-ins from a new country.

Indicators: failure counts above 25 per account from external addresses; success after failures; sign-in location mismatch.

Response: force password resets for accounts with a success after failures, require MFA re-registration, and block the source range. Accounts with only failures need monitoring, not containment.
