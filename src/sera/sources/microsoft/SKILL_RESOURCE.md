# Microsoft Source Plugin (`source="microsoft"`)

## 1. Adding the Source & Auth (`sera source add microsoft ...`)
Configure Microsoft-specific options (`proxy_url`, `ca_bundle`, `default_workspace_id`, `default_subscription_id`) and out-of-band authentication credentials together in a single command (secrets are stored strictly in `<workspace>/.sera/creds/` and never enter chat):

- **Device-Code OAuth (MSAL) + Optional Microsoft Proxy:**
  ```bash
  sera source add microsoft --auth-mode device-code --opt tenant_id=<TENANT_ID> --opt proxy_url=socks5://127.0.0.1:1080
  ```
- **Interactive Browser OAuth (MSAL):**
  ```bash
  sera source add microsoft --auth-mode browser --opt tenant_id=<TENANT_ID>
  ```
- **App Registration Client Secret or Certificate (MSAL):**
  ```bash
  sera source add microsoft --auth-mode secret --opt tenant_id=<TENANT_ID> --opt client_id=<APP_ID>
  sera source add microsoft --auth-mode cert --opt tenant_id=<TENANT_ID> --opt client_id=<APP_ID> --opt private_key_path=/path/to/key.pem --opt thumbprint=<SHA1>
  ```
- **MDE 180-Day Host Timeline Portal Session (`security.microsoft.com`):**
  ```bash
  sera source add microsoft --name mde_portal --auth-mode portal-session
  ```

### Source-Specific Options (`--opt KEY=VALUE`)
| Option | Default | Description |
| :--- | :--- | :--- |
| `proxy_url` | `""` | HTTP/HTTPS/SOCKS5 proxy URL scoped strictly to Microsoft authentication and API endpoints |
| `ca_bundle` | `""` | Custom CA certificate PEM path for Microsoft proxy |
| `default_workspace_id` | `""` | Default Log Analytics / Sentinel Workspace GUID |
| `default_subscription_id` | `""` | Default Azure Subscription GUID for ARM Activity Logs |

---

## 2. Supported `sub_source`s & `target` Values

Each `sub_source` uses **one canonical full-event query template** (`params={}` pulls 100% of events in `[start, end)`; optional typed `params` apply safe server-side filters):

1. **`entra`** (MS Graph OData `/v1.0/auditLogs/...`; requires MSAL profile; default 24h slices):
   - `target`: `signIns` | `directoryAudits` | `provisioning` | `riskDetections`
   - Optional `params`: `equals`, `in_list`, `contains`, `startswith`
2. **`purview_ual`** (MS Graph GA async `/v1.0/security/auditLog/queries`; requires MSAL `AuditLogsQuery.Read.All`; bisects when `isRecordCountLimitExceeded` or near 1M cap):
   - `target`: `auditLogRecords`
   - Optional `params`: `users`, `ips`, `operations`, `services`, `record_types`, `object_ids`, `administrative_unit_ids`, `keyword`
3. **`log_analytics`** (Azure Monitor / Sentinel KQL via `https://api.loganalytics.azure.com`; requires `target_id` = Workspace GUID or `default_workspace_id`; bisects on `PartialError` / 500k cap):
   - `target`: Exact table name (e.g. `SigninLogs`, `AuditLogs`, `AADNonInteractiveUserSignInLogs`, `AzureActivity`, `SecurityEvent`, `Syslog`, `CommonSecurityLog`)
   - Optional `params`: `equals`, `in_list`, `contains`, `startswith`
4. **`defender_hunting`** (Defender XDR KQL `/v1.0/security/runHuntingQuery` with explicit `Timespan`; bisects at 100k row ceiling):
   - `target`: Exact XDR table (e.g. `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `EmailEvents`, `IdentityLogonEvents`, `CloudAppEvents`)
   - Optional `params`: `equals`, `in_list`, `contains`, `startswith`
5. **`defender_timeline`** (MDE **180-Day Host Timeline** via `security.microsoft.com/apiproxy/mtp/mdeTimelineExperience`; requires `portal-session` profile with `sccauth` Cookie + `X-XSRF-TOKEN`; default 7d slices):
   - `target`: Target host's MDE `machine_id` (40-hex DeviceId)
   - `profile`: e.g. `mde_portal`
   - Optional `params`: `action_types`, `search_text`
6. **`arm_activity`** (Azure Subscription Activity Logs via `Microsoft.Insights`, 90d lookback; requires `target_id` = Subscription GUID or `default_subscription_id`):
   - `target`: `management`
   - Optional `params`: single `equals` predicate on `resourceGroupName`, `resourceUri`, `resourceProvider`, or `correlationId`

---

## 3. Typed Filter `params` Examples (`collect`)

Open column surfaces (`entra`, `log_analytics`, `defender_hunting`):
```json
{
  "equals": {"userPrincipalName": "alice@contoso.com"},
  "in_list": {"ipAddress": ["198.51.100.10", "203.0.113.42"]},
  "contains": {"ProcessCommandLine": "encodedcommand"},
  "startswith": {"appDisplayName": "Microsoft"}
}
```
Field names are validated identifiers (`^[A-Za-z_][A-Za-z0-9_./-]*$`) and values are literal-encoded per dialect—never pass raw KQL/OData operators (`| project`, `| summarize`, `$select`).

### Example Calls (MCP `collect` == CLI `sera collect`)
- **MCP `collect`:**
  ```json
  {
    "source": "microsoft",
    "sub_source": "entra",
    "target": "signIns",
    "start": "2026-11-17T00:00:00Z",
    "end": "2026-11-24T00:00:00Z"
  }
  ```
- **CLI `sera collect`:**
  ```bash
  sera collect --source microsoft --sub-source entra --target signIns --start 2026-11-17T00:00:00Z --end 2026-11-24T00:00:00Z
  ```
