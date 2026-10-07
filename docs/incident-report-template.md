# Incident Report: INC-<number>

| Field | Value |
|---|---|
| Incident title | |
| Sentinel incident # | |
| Severity | High / Medium / Low |
| Classification | True Positive / Benign Positive / False Positive |
| Analyst | |
| Detected (UTC) | |
| Contained (UTC) | |
| Closed (UTC) | |
| MITRE ATT&CK | e.g. T1110.001 Brute Force: Password Guessing |

## 1. Executive summary
Two or three sentences for a non-technical reader: what happened, the impact, and the current status.

## 2. Detection
- Analytics rule that fired:
- Data source(s):
- Why it fired (the key query output):

## 3. Affected entities
| Type | Value | Notes |
|---|---|---|
| Account | | |
| IP | | Geo / reputation |
| Host | | |

## 4. Timeline (UTC)
| Time | Event | Source |
|---|---|---|
| | First failed sign-in | SOCLabAuth_CL |
| | Successful sign-in | SOCLabAuth_CL |
| | Incident created | Sentinel |
| | Playbook notified SOC | Logic App |
| | Containment action | Analyst |

## 5. Investigation
KQL queries run (paste them) and what they showed. Screenshots of the investigation graph.

## 6. Response actions
- Containment:
- Eradication:
- Recovery:

## 7. Root cause & lessons learned
- Root cause:
- What went well:
- What to improve (detection tuning, controls like MFA/CA/JIT):

## 8. Evidence
Links or screenshots: incident page, query results, playbook run history.
