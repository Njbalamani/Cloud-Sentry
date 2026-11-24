# CloudSentry Database ER Diagram

```mermaid
erDiagram
    USER ||--o{ ORGANIZATION_MEMBERSHIP : joins
    USER ||--o{ SCAN_RUN : starts
    USER ||--o{ REMEDIATION_REVIEW : reviews
    USER ||--o{ REPORT : generates

    ORGANIZATION ||--o{ ORGANIZATION_MEMBERSHIP : has
    ORGANIZATION ||--o{ CLOUD_ACCOUNT : owns
    ORGANIZATION ||--o{ SCAN_RUN : contains
    ORGANIZATION ||--o{ COMPLIANCE_ASSESSMENT : contains
    ORGANIZATION ||--o{ REPORT : produces

    CLOUD_ACCOUNT ||--o{ CLOUD_RESOURCE : includes
    CLOUD_ACCOUNT ||--o{ SCAN_RUN : assessed_by
    CLOUD_ACCOUNT ||--o{ IAM_ANALYSIS : analyzed_by

    SCAN_RUN ||--o{ FINDING : produces
    SCAN_RUN ||--o{ COMPLIANCE_ASSESSMENT : evaluated_by
    SCAN_RULE ||--o{ FINDING : defines

    CLOUD_RESOURCE ||--o{ FINDING : affected_by
    FINDING ||--o{ RISK_ASSESSMENT : scored_by
    FINDING ||--o{ REMEDIATION_REVIEW : reviewed_by

    COMPLIANCE_CONTROL ||--o{ CONTROL_RESULT : checked_by
    COMPLIANCE_ASSESSMENT ||--o{ CONTROL_RESULT : records

    USER {
        bigint id PK
        string email UK
        string role
        boolean is_active
        datetime date_joined
    }

    ORGANIZATION {
        bigint id PK
        string name
        string slug UK
        text description
        boolean is_active
    }

    ORGANIZATION_MEMBERSHIP {
        bigint id PK
        bigint user_id FK
        bigint organization_id FK
        string role
        boolean is_active
    }

    CLOUD_ACCOUNT {
        bigint id PK
        bigint organization_id FK
        string name
        string provider
        string account_identifier
        string region
        text encrypted_credentials
        boolean is_read_only
        string status
    }

    CLOUD_RESOURCE {
        bigint id PK
        bigint cloud_account_id FK
        string resource_id
        string resource_type
        string region
        jsonb metadata
        string risk_level
        boolean is_demo
    }

    SCAN_RULE {
        bigint id PK
        string rule_id UK
        string title
        string severity
        string cis_control
        boolean enabled
    }

    SCAN_RUN {
        bigint id PK
        bigint organization_id FK
        bigint cloud_account_id FK
        bigint initiated_by_id FK
        string status
        string scan_mode
        datetime started_at
        datetime finished_at
        integer findings_count
    }

    FINDING {
        bigint id PK
        bigint scan_run_id FK
        bigint cloud_account_id FK
        bigint resource_id FK
        bigint rule_id FK
        string title
        string severity
        string status
        float risk_score
        jsonb evidence
        jsonb remediation
        boolean is_demo
    }

    IAM_ANALYSIS {
        bigint id PK
        bigint cloud_account_id FK
        string principal_arn
        string policy_name
        jsonb policy_document
        float risk_score
        jsonb findings
        jsonb recommendations
    }

    RISK_ASSESSMENT {
        bigint id PK
        bigint finding_id FK
        float score
        string model_version
        jsonb factors
        text explanation
        text remediation_summary
    }

    COMPLIANCE_CONTROL {
        bigint id PK
        string framework
        string control_id
        string title
        string severity
    }

    COMPLIANCE_ASSESSMENT {
        bigint id PK
        bigint organization_id FK
        bigint scan_run_id FK
        float score
        integer passed
        integer failed
        integer total
    }

    CONTROL_RESULT {
        bigint id PK
        bigint assessment_id FK
        bigint control_id FK
        string status
        jsonb evidence
    }

    REMEDIATION_REVIEW {
        bigint id PK
        bigint finding_id FK
        bigint reviewer_id FK
        string decision
        text notes
    }

    REPORT {
        bigint id PK
        bigint organization_id FK
        bigint created_by_id FK
        string report_type
        string file_format
        file file
        datetime created_at
    }
```

## Tenancy and data integrity rules

- Every tenant-owned record has a direct or indirect `organization_id`.
- `CloudResource.resource_id` is unique per cloud account.
- `Finding.evidence` and `Finding.remediation` are JSON documents validated by the service layer.
- Risk assessments are immutable once created.
- Reports are linked to the organization that generated them and stored under `media/reports/`.
- All demo-created records set `is_demo=True` so they can be identified and excluded.
