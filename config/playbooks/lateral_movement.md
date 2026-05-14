# Playbook: Lateral Movement / Process Injection

**Applies to:** Rules 100400, 100600, MITRE T1055, T1082, T1033
**Trigger:** CreateRemoteThread injection, recon burst chain (3+ commands in 60s)

---

## Investigation Steps

1. Identify the source process performing injection or recon and its parent
2. Identify the target process (for injection) or the full list of recon commands executed
3. Check if the source process is a legitimate admin tool or known-good application
4. Extract the user account context — is this an admin account or standard user?
5. Query SIEM for the full activity of this account across ALL hosts in the past 24 hours
6. Map the path of lateral movement: which hosts were accessed and in what order?
7. Check for credential theft indicators: LSASS access (Rule 100200), mimikatz patterns
8. Check for persistence established on any host the attacker touched (rules 100100–100102)
9. Identify the ultimate objective: what was the attacker trying to reach?
10. Enrich any external IPs seen in outbound connections during this activity
11. Identify all accounts and hosts that may be compromised
12. Document the complete lateral movement chain with timestamps
13. **[REQUIRES APPROVAL]** Disable the compromised user account
14. **[REQUIRES APPROVAL]** Isolate all affected hosts from the network
15. **[REQUIRES APPROVAL]** Reset credentials for all accounts the attacker accessed
16. Generate full incident report documenting scope of compromise
