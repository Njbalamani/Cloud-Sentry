# CloudSentry Architecture

## System overview

```mermaid
flowchart TB
    UI[Premium responsive web UI\nHTML CSS JavaScript Chart.js Three.js] --> Django[Django MVT application]
    API[REST API v1\nDjango REST Framework] --> Django
    Docs[OpenAPI docs\nSwagger and ReDoc] --> API

    Django --> Auth[accounts\n authentication and RBAC]
    Django --> Org[organizations\n tenancy and membership]
    Django --> Cloud[cloud_accounts\n encrypted AWS credentials]
    Django --> Scan[cloud_scanner\n read-only scanners and findings]
    Django --> IAM[iam_analyzer\n policy analysis]
    Django --> Risk[risk_engine\n scikit-learn and optional Gemini]
    Django --> Comp[compliance\n CIS controls]
    Django --> Reports[reports\n PDF and CSV]
    Django --> Dash[dashboard\n live aggregations]

    Scan --> AWS[AWS APIs\nSTS IAM S3 EC2 EBS RDS]
    Scan --> Prowler[Optional Prowler CLI\n read-only assessment]
    Risk --> Gemini[Optional Gemini API\n explanations only]
    Org --> DB[(PostgreSQL)]
    Cloud --> DB
    Scan --> DB
    IAM --> DB
    Risk --> DB
    Comp --> DB
    Reports --> DB
    Reports --> Files[(Media reports)]
```

## Request and tenancy flow

```mermaid
sequenceDiagram
    participant User as Analyst
    participant Web as Django view or API
    participant Middleware as Organization middleware
    participant Permission as RBAC permission
    participant Service as Domain service
    participant DB as PostgreSQL

    User->>Web: Request with session or token
    Web->>Middleware: Resolve active organization
    Middleware->>DB: Load memberships
    Web->>Permission: Check role and organization
    Permission-->>Web: Allow or deny
    Web->>Service: Execute use case
    Service->>DB: Scoped query by organization
    DB-->>Service: Results
    Service-->>Web: Context or serialized data
    Web-->>User: Rendered page or JSON
```

## Scanning flow

```mermaid
flowchart LR
    Start[Authorized user starts scan] --> Mode{Scan mode}
    Mode -->|Live| AWS[Read-only AWS API collector]
    Mode -->|Demo| Demo[Synthetic demo collector\nlabelled is_demo]
    AWS --> Rules[Rule engine and CIS mappings]
    Demo --> Rules
    Prowler[Optional Prowler adapter] --> Rules
    Rules --> Findings[Normalized findings]
    Findings --> IAM[IAM analyzer]
    Findings --> Risk[AI risk scoring]
    Risk --> Compliance[Compliance scoring]
    Compliance --> Reports[PDF and CSV exports]
```

## Security controls

- All cloud scanning uses read-only AWS APIs. The platform never calls write APIs.
- Credentials are encrypted at rest with Fernet using `FIELD_ENCRYPTION_KEY` and are never serialized to templates, API responses, or logs.
- Organization scoping is enforced in permissions and querysets.
- Remediation is advisory only. Cloud changes require explicit out-of-band approval by an administrator.
- Demo data is generated only when explicitly requested and is always marked as synthetic.
- Dashboard metrics are calculated from database records at request time.

## Deployment topology

```mermaid
flowchart LR
    Client[Browser] --> ReverseProxy[Reverse proxy with TLS]
    ReverseProxy --> Gunicorn[Gunicorn Django application]
    Gunicorn --> Postgres[(PostgreSQL)]
    Gunicorn --> Static[WhiteNoise static assets]
    Gunicorn --> Media[Report files]
```
