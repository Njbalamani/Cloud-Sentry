# API Reference

## Base information

- Base path: `/api/v1/`
- OpenAPI schema: `/api/schema/`
- Swagger UI: `/api/docs/`
- ReDoc: `/api/redoc/`
- Authentication: Django session cookies or DRF tokens.
- Default access: active organization membership with analyst level or higher.
- Administrative actions: organization administrator level or higher.

Send tokens with the `Authorization: Token <token>` header. Every API response includes an `X-Request-ID` header.

Errors use this shape:

```json
{
  "error": {
    "code": "http_403",
    "message": "You do not have access to this organization.",
    "details": {"detail": "You do not have access to this organization."},
    "request_id": "uuid"
  }
}
```

## Resources

| Path | Methods | Description |
| --- | --- | --- |
| `/api/v1/organizations/` | GET | Organizations available to the authenticated user. |
| `/api/v1/organization-members/` | GET | Active members of the active organization. |
| `/api/v1/cloud-accounts/` | GET, POST | Cloud accounts in the active organization. |
| `/api/v1/cloud-accounts/{id}/` | GET, PUT, PATCH, DELETE | Cloud account detail and management. |
| `/api/v1/cloud-resources/` | GET | Discovered resources. Supports `cloud_account` and `resource_type` filters. |
| `/api/v1/scan-runs/` | GET, POST | Assessment records. Creating a scan requires administrator access. |
| `/api/v1/scan-runs/{id}/run/` | POST | Execute a read-only assessment. |
| `/api/v1/scan-runs/{id}/findings/` | GET | Findings produced by one assessment. |
| `/api/v1/findings/` | GET | Findings in the active organization. Supports `severity`, `status`, and `include_remediated` filters. |
| `/api/v1/remediation-reviews/` | GET, POST | Advisory remediation reviews. Writes require administrator access. |
| `/api/v1/iam-analyses/` | GET | IAM analysis results. Supports `cloud_account` filter. |
| `/api/v1/risk-assessments/` | GET | AI/hybrid risk scores for findings. |
| `/api/v1/compliance-assessments/` | GET | CIS compliance assessment history. |
| `/api/v1/compliance-controls/` | GET | Enabled compliance controls. |
| `/api/v1/reports/` | GET | Generated reports. |
| `/api/v1/reports/generate/` | POST | Generate a PDF or CSV report. Requires administrator access. |
| `/api/v1/reports/{id}/download/` | GET | Download a generated report file. |
| `/api/v1/dashboard/metrics/` | GET | Database-derived dashboard metrics. |
| `/api/v1/dashboard/topology/` | GET | Cloud resource topology nodes and links. |

## Report generation payload

```json
{
  "report_type": "findings",
  "file_format": "csv",
  "scan_run": 12,
  "include_demo": false
}
```

Valid report types are `security_assessment`, `findings`, `compliance`, and `iam_risk`. Valid formats are `pdf` and `csv`.

## Scan creation payload

```json
{
  "cloud_account": 4,
  "scan_mode": "demo"
}
```

Valid scan modes are `live`, `demo`, and `prowler`. Demo mode is rejected when `DEMO_MODE=False`; Prowler mode requires a configured binary.

## Data classification

Findings, resources, scan runs, IAM analyses, and reports carry classification signals. Synthetic demo records are labelled with `is_demo` or `synthetic_data` and must never be presented as live assessment results.
