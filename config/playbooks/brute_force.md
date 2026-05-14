# Playbook: Brute Force Authentication Attack

**Applies to:** Rules 100500, Wazuh level 14, MITRE T1110.001
**Trigger:** 10+ failed logons from the same IP within 60 seconds

---

## Investigation Steps

1. Confirm the source IP and target host from the alert data
2. Query SIEM for the full timeline of authentication attempts (expand window to 2 hours)
3. Check if any logon attempts SUCCEEDED after the brute force — this is the critical escalation point
4. If successful authentication found: escalate to Critical immediately and move to containment
5. Identify the targeted user account(s) and check if they have elevated privileges
6. Enrich the source IP via threat intelligence (VirusTotal, AbuseIPDB)
7. Check for activity from the source IP against other hosts in the environment (lateral scanning)
8. Check for any post-authentication activity from the targeted account (if logon succeeded)
9. Review whether the targeted service (SMB/RDP/SSH) should be internet-facing
10. Document all findings in the case with timestamps and evidence
11. **[REQUIRES APPROVAL]** Block the source IP at the firewall if attack is ongoing
12. **[REQUIRES APPROVAL]** Lock the targeted user account if successful logon occurred
13. **[REQUIRES APPROVAL]** Isolate the target host if post-exploitation activity is confirmed
14. Generate full incident report and update case severity accordingly
