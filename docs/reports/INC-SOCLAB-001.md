# Security Incident Report: INC-SOCLAB-001

**Microsoft Sentinel SOC Monitoring & Incident Response Lab**

| Field | Value |
|---|---|
| Incident ID | INC-SOCLAB-001 |
| Title | SOCLab: Brute Force Attack Followed by Successful Sign-In |
| Severity | **High** |
| Classification | True Positive (simulated attack, controlled lab environment) |
| Status | Analysis complete. Sentinel timestamps and evidence pending lab execution |
| Analyst | Nikhil Dahiya |
| Detection time (UTC) | ⟨Sentinel `CreatedTime`⟩ |
| Containment time (UTC) | ⟨from incident comments⟩ |
| Closure time (UTC) | ⟨Sentinel `ClosedTime`⟩ |
| MITRE ATT&CK | T1110.001 Brute Force: Password Guessing → T1078 Valid Accounts |
| Response framework | NIST SP 800-61 |

---

## 1. Executive Summary

Microsoft Sentinel raises a High-severity incident for a suspicious authentication pattern against
**mallory@contoso-lab.com**: **25 failed sign-ins** from **203.0.113.50** over roughly eight minutes,
followed by a **successful sign-in** from the same IP to the same account.

Four indicators together point to a credential-guessing attack that succeeded:

- **Volume:** 25 failures, well above the detection threshold of 10
- **Automation:** attempts arrive at regular ~20-second intervals
- **Location:** the IP geolocates to the Netherlands, while the account's baseline is the United States (Seattle, Austin)
- **Outcome:** a successful sign-in immediately follows the failures

The account is treated as compromised. Response actions are revoking sessions, blocking the
source IP, forcing a password reset, requiring MFA, and reviewing the account for persistence.
No follow-on attacker activity appears in the lab data set.

**Assessment:** High-severity simulated credential compromise. True Positive.

---

## 2. Detection

**Analytics rule:** `SOCLab - Brute force followed by successful sign-in`
([detections/01-bruteforce-then-success.kql](../../detections/01-bruteforce-then-success.kql))

| Setting | Value |
|---|---|
| Data source | `SOCLabAuth_CL` |
| Frequency / lookback | Every 15 min / 1 h |
| Logic | ≥ 10 failures for one user from one IP, then a success from the same user and IP within 30 min |
| Entity mapping | Account (UserPrincipalName), IP (SourceIP) |

**Observed activity**

| User | Source IP | Country | Failed | Successful | Application |
|---|---|---|---|---|---|
| `mallory@contoso-lab.com` | `203.0.113.50` | Netherlands | 25 | 1 | Azure Portal |

Because the rule requires the **failure → success** sequence, it reports a likely compromise rather than isolated failed logons.

---

## 3. Affected Entities

| Type | Value | Notes |
|---|---|---|
| Account | `mallory@contoso-lab.com` | Baseline sign-ins from Seattle and Austin, US |
| Source IP | `203.0.113.50` | Amsterdam, NL; absent from the user's 7-day baseline |
| Application | Azure Portal | Administrative cloud interface, so access could expose further resources |

---

## 4. Timeline

Relative to T0, the first failed attempt. Exact UTC times will be added from Sentinel after the scenario is executed.

| Time | Event | Source |
|---|---|---|
| T0 | First failed sign-in from `203.0.113.50` | `SOCLabAuth_CL` |
| T0 → T0 + 8 min | 25 failed sign-ins, ~1 every 20 s | `SOCLabAuth_CL` |
| T0 + 8 min 50 s | **Successful sign-in**, same IP and account | `SOCLabAuth_CL` |
| ≤ 15 min later | Analytics rule runs, High-severity incident created | Microsoft Sentinel |
| Seconds later | Playbook posts Teams alert and adds triage comment | Azure Logic App |
| ⟨UTC⟩ | Investigation, containment and closure | Analyst |

---

## 5. Investigation

### 5.1 Source IP activity
```kql
SOCLabAuth_CL
| where SourceIP == "203.0.113.50"
| summarize Attempts = count(), Users = make_set(UserPrincipalName),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by Result, EventType
```
**Finding:** 25 failures and 1 success, all against the same account from the same IP. This ties the failures directly to the successful sign-in.

### 5.2 Geographic baseline
```kql
SOCLabAuth_CL
| where UserPrincipalName == "mallory@contoso-lab.com" and Result == "Success"
| summarize SignIns = count() by Country, City
```
**Finding:** the baseline is the United States only, and the Netherlands is new for this account.
On its own a new location isn't proof of compromise (travel, VPNs and proxies all cause it), but combined
with the failure volume and the success, it significantly raises the risk.

### 5.3 Automation assessment
**Finding:** the attempts are evenly spaced (~20 s) and all target the same application. That
regularity fits a script or authentication tool, not a user mistyping a password.

### 5.4 False-positive assessment
| Alternative explanation | Why it doesn't fit |
|---|---|
| Forgotten password | 25 attempts in 8 minutes far exceeds normal typo behavior (baseline ≈ 5% isolated failures) |
| Travel or VPN | Doesn't explain the machine-regular timing or the failure volume |
| Repeated manual retries | Human retries are irregular, not exactly 20 s apart |

**Conclusion:** True Positive. In production, confirm with the user over a separate channel before closing.

---

## 6. Attack Chain

```
Repeated failures  →  Password guessing  →  Successful sign-in  →  Valid-account compromise
                       T1110.001                                     T1078
```

---

## 7. Response (NIST 800-61)

| Phase | Action | Objective |
|---|---|---|
| **Containment** | Revoke all sessions for `mallory@contoso-lab.com` | Invalidate the attacker's access |
| | Block `203.0.113.50` (Conditional Access named location / NSG) | Stop further attempts |
| **Eradication** | Force password reset; require MFA re-registration | Remove the compromised credential |
| | Review for persistence after T0 + 8m50s: new MFA methods, app consents, inbox rules, role assignments, new accounts | Find any foothold the attacker left behind |
| **Recovery** | Restore access only after remediation, with MFA enforced | Safe return to service |
| | Monitor the account and IP for 7 days (hunting query H3) | Detect any return activity |

Each action is recorded as a comment on the Sentinel incident.

---

## 8. Root Cause

The account relied on **password-only authentication**. Without MFA, a correctly guessed password was enough to sign in.

---

## 9. Lessons Learned

**What worked**
- **Correlated detection:** the rule linked failures to a success, which reduces noise from isolated typos.
- **Baseline analysis:** the new location stood out immediately against the user's history.
- **SOAR automation:** the Teams alert and triage comment removed manual notification steps.

**Improvements: identity controls**
- Enforce **MFA** for all users, especially those with Azure Portal access.
- Use **Conditional Access** to restrict risky sign-ins to administrative apps.
- Enable **smart lockout** to blunt password guessing.

**Improvements: detection engineering**

| Tier | Signal | Severity |
|---|---|---|
| 1 | ≥ 10 failures, no success (new rule) | Low/Medium |
| 2 | Failures followed by success (this rule) | High |
| 3 | Success followed by privileged activity from the same IP/account | Critical |

**Correlation opportunity:** if `203.0.113.50` later assigns a privileged role
(see [detections/04-offhours-privileged-role.kql](../../detections/04-offhours-privileged-role.kql)),
group both alerts into one incident and escalate. That sequence indicates post-compromise privilege
escalation.

---

## 10. Evidence

To be attached after executing `python generate_logs.py --scenario bruteforce`:

- [ ] **Incident overview:** number, severity, status, entities
- [ ] **Detection query results:** 25 failures, 1 success, IP, account, application
- [ ] **Geographic baseline:** query 5.2 output
- [ ] **Investigation graph:** Account ↔ IP
- [ ] **SOAR notification:** Teams alert card
- [ ] **Incident comments:** investigation, classification, containment, closure

---

## 11. Analyst Conclusion

This incident is a simulated brute-force attack against `mallory@contoso-lab.com`: 25 failed
sign-ins from `203.0.113.50`, followed by a successful sign-in from the same source. The geographic
anomaly and machine-regular timing support a **High-severity True Positive** classification.

The scenario exercises the full SOC workflow:
**Detection → Triage → Investigation → Classification → Containment → Recovery → Documentation → Closure**.
It also validates Microsoft Sentinel, KQL detection engineering, MITRE ATT&CK mapping, SOAR automation
and NIST 800-61 procedures as parts of a practical SOC operation.
