# Feeding the landing zone scorecard with real data

`execlens lz` and `execlens serve --inventory` read a JSON file:

```json
{"accounts": [{"id": "123456789012", "name": "prod-payments", "ou": "Prod", "env": "prod",
               "config": {"root_mfa": true, "users_without_mfa": 0, "...": "see table"}}]}
```

ExecLens does **not** call cloud APIs and needs no credentials. Export the inventory with your own
read-only collector (a scheduled job, a pipeline step, or a security tool you already run) and drop the
JSON where ExecLens can read it. `examples/landing_zone_inventory.json` is a complete sample with every key.

| config key | meaning | typical AWS source | typical Azure source |
|---|---|---|---|
| `root_mfa` | root/owner protected by MFA | IAM account summary | Entra security defaults / CA policy |
| `users_without_mfa` | console users with no MFA | IAM credential report | Entra authentication methods report |
| `sso_federated` | access via central IdP | IAM Identity Center | Entra SSO config |
| `unused_privileged_90d` | idle admin identities | IAM Access Analyzer | Entra access reviews |
| `password_policy_ok` | credential policy at baseline | IAM password policy | Entra password protection |
| `org_trail` | org-wide audit logging | CloudTrail org trail | Activity log diagnostic settings |
| `log_retention_days`, `log_immutable` | retention, WORM storage | S3 Object Lock, log group retention | Storage immutability policy |
| `threat_detection`, `alerting_wired` | detection on, routed to SOC | GuardDuty, Security Hub | Defender for Cloud, Sentinel |
| `open_admin_ports` | rules open to 0.0.0.0/0 on 22/3389 | Security group scan | NSG rule scan |
| `public_buckets` | publicly readable storage | S3 Block Public Access, Config | Storage account public access |
| `hub_peered`, `flow_logs`, `default_vpc_used`, `waf` | network posture | Transit Gateway, VPC flow logs | vWAN/hub peering, NSG flow logs |
| `encryption_at_rest_pct`, `kms_rotation`, `tls_min_12` | data protection | AWS Config rules | Azure Policy |
| `data_residency_ok`, `allowed_regions_only` | jurisdiction control | SCP region deny, Config | Azure Policy allowed locations |
| `secrets_in_code` | leaked secrets found | secret scanner output | secret scanner output |
| `scp_guardrails`, `tags_pct`, `budget_alerts`, `owner_assigned` | governance | Organizations, Tag Policies, Budgets | Management groups, Policy, Cost Mgmt |
| `backup_policy`, `restore_tested_90d`, `multi_az`, `patch_sla_pct`, `dr_runbook` | resilience | AWS Backup, patch manager | Azure Backup, Update Manager |

To add or change a control, edit `CONTROLS` in `src/execlens/landingzone.py`. Each control is one entry: id,
title, domain, weight (5 = critical), framework tags, remediation text and a check function.
