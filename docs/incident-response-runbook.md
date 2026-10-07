# Incident Response Runbook (NIST SP 800-61 r2)

## Severity & SLA

| Severity | Example | Triage within | Contain within |
|---|---|---|---|
| High | Brute force → success, Global Admin off-hours, local admin added | 15 min | 1 h |
| Medium | Password spray, impossible travel, failed logons | 1 h | 4 h |
| Low | Single anomaly, informational | 8 h | — |

## Phase 1: Preparation
- Analysts have the **Microsoft Sentinel Responder** role.
- The playbook posts every new incident to the SOC Teams channel.
- Contacts: identity team, server owners, management escalation.

## Phase 2: Detection & Analysis (all incidents)
1. **Assign** the incident to yourself and set Status = *Active*.
2. **Scope:** which accounts, IPs and hosts are involved? Are there other incidents with the same entities?
3. **Timeline:** first and last events (use the alert's query results and the H3 pivot query).
4. **Validate:** is the IP known, the user travelling, the change approved (check the change ticket)?
5. **Classify:** TP / BP / FP. Note your reasoning in a comment.

## Phase 3: Containment, Eradication, Recovery (per detection)

### Brute force followed by success (High)
- **Contain:** disable the account or revoke its sessions (Entra ID → user → *Revoke sessions*); block the source IP (Conditional Access named location / NSG).
- **Eradicate:** force a password reset; check for MFA methods, inbox rules or app consents added after the success time.
- **Recover:** re-enable the account with MFA enforced; watch it for 7 days.

### Password spray (Medium)
- **Contain:** block the source IP.
- **Analyze:** did *any* targeted account succeed from that IP? If yes, escalate to the brute-force playbook for that account.
- **Harden:** check that legacy auth is blocked and MFA covers all the targeted users.

### Impossible travel (Medium)
- **Validate** with the user over a separate channel (VPN? travelling?).
- If not legitimate: revoke sessions, reset the password, review the activity from the foreign IP.

### Privileged role off-hours (High)
- **Validate** the change against change management.
- If not approved: remove the role assignment, investigate the *InitiatedBy* account as compromised, and review everything the new admin did.

### Multiple failed Windows logons (Medium)
- Check whether a 4624 (success) followed from the same IP.
- Confirm the NSG only allows trusted IPs; consider Just-In-Time VM access or Azure Bastion.

### User added to local Administrators (High)
- Identify who made the change (SubjectAccount) and whether it was approved.
- If not approved: remove the user from the group, disable/delete the account, and review 4688 process events around that time.

## Phase 4: Post-Incident Activity
- Close the incident with the right classification and a closing comment.
- Write the incident report (template).
- Tuning: did the rule fire correctly? Adjust thresholds or add exclusions (e.g. watchlists) for false positives.
- Lessons learned: what would have prevented this? (MFA, Conditional Access, JIT, PIM.)
