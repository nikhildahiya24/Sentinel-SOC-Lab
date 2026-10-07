# Lab Scenarios

Each scenario: **generate → detect → investigate → respond → document.**
Analytics rules run every 10–30 min, so expect a short wait before an incident shows up.

| # | Scenario | How to generate | Expected incident |
|---|---|---|---|
| 1 | Brute force → success | `python generate_logs.py --scenario bruteforce` | SOCLab - Brute force followed by successful sign-in (High) |
| 2 | Password spray | `python generate_logs.py --scenario spray` | SOCLab - Password spray from single IP (Medium) |
| 3 | Impossible travel | `python generate_logs.py --scenario travel` | SOCLab - Impossible travel (Medium) |
| 4 | Off-hours Global Admin grant | `python generate_logs.py --scenario privrole` (run outside 08:00–18:00 UTC, or on a weekend) | SOCLab - Privileged role assigned outside business hours (High) |
| 5 | Failed Windows logons | See below | SOCLab - Multiple failed Windows logons (Medium) |
| 6 | Local admin added | See below | SOCLab - User added to local Administrators (High) |

Run `--scenario baseline` first and keep it running now and then (e.g. every 30 min) so the
detections have normal traffic to stand out against. Watching for false positives here is part of tuning.

## Scenario 5: Failed Windows logons (on your own lab VM)
1. Open Remote Desktop to the VM's public IP (only your IP is allowed by the NSG).
2. Type a **wrong password** 6–8 times for `labadmin`, then sign in correctly.
3. Within about 10 minutes, check that the events arrived:
   ```kql
   SecurityEvent | where EventID == 4625 | take 20
   ```

## Scenario 6: Local admin added (on your own lab VM)
In an elevated PowerShell on the VM:
```powershell
net user labtest01 "Lab-Temp-Pass-2026!" /add
net localgroup Administrators labtest01 /add
```
That produces EventID 4720 (user created) and 4732 (added to Administrators).
**Clean-up (part of the response!):**
```powershell
net localgroup Administrators labtest01 /delete
net user labtest01 /delete
```

## Investigation checklist (every incident)
1. Open the incident → **View full details** → review the entities (Account, IP, Host).
2. Click **Investigate** to open the investigation graph and look for related alerts on the same entities.
3. Run the `H3` pivot query in `hunting/hunting-queries.kql` against the source IP.
4. Decide: True Positive / Benign Positive / False Positive.
5. Record your actions as incident comments, set the classification, and close.
6. Write up the report with `incident-report-template.md`.
