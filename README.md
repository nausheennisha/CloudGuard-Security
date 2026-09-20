# CloudGuard — Cloud Security Analysis System

CloudGuard scans an AWS account, builds a graph of how an attacker could move
from the public internet to sensitive data, scores every misconfiguration it
finds, and produces a ranked remediation plan. It ships with a realistic
mock dataset so the whole system runs and looks correct without any AWS
credentials, and switches to live scanning the moment credentials are
provided.

```
┌─────────────┐      REST/JSON      ┌──────────────────┐      boto3      ┌───────────┐
│  React SPA  │ ◄─────────────────► │   FastAPI backend │ ◄─────────────► │    AWS    │
│ (frontend)  │                     │    (backend)       │   (optional)    │  account  │
└─────────────┘                     └──────────────────┘                 └───────────┘
                                            │
                                            ▼
                                  networkx attack graph +
                                    risk scoring engine
```

## Features

- **Attack path visualization** — an interactive, force-free layered graph
  (React Flow) showing every route from an entry point (internet, an
  unprotected IAM user, an open security group) to a "crown jewel" resource
  (an RDS instance, a sensitive S3 bucket), with a plain-English narrative
  of each hop.
- **Vulnerability detection** — IAM over-privilege, public storage, missing
  encryption, open network ingress, missing MFA, disabled logging, and more,
  each mapped to relevant compliance frameworks (CIS AWS, PCI-DSS, NIST,
  SOC 2, HIPAA).
- **Risk-based prioritization** — every finding gets a 0–100 risk score from
  its impact, exploitability, and exposure; the remediation plan re-ranks by
  risk-reduction-per-unit-of-effort so genuine quick wins surface first.
- **Live AWS mode** — `POST /api/scan` with `use_live_aws: true` runs
  read-only `describe`/`list`/`get` calls against EC2, S3, IAM, RDS, Lambda,
  KMS, and VPC. No resource is ever modified.

## Project layout

```
cloudguard/
├── backend/
│   ├── app/
│   │   ├── main.py                 FastAPI app & routes
│   │   ├── models/schemas.py       Pydantic models
│   │   ├── services/
│   │   │   ├── aws_scanner.py      boto3 collection + mock fallback
│   │   │   ├── graph_builder.py    networkx attack graph + path search
│   │   │   └── risk_engine.py      risk scoring & remediation ranking
│   │   └── data/mock_data.py       bundled sample cloud environment
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.jsx                 tab navigation & data fetching
│   │   ├── components/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── AttackPathGraph.jsx
│   │   │   ├── VulnerabilityTable.jsx
│   │   │   ├── RemediationPanel.jsx
│   │   │   └── Badges.jsx
│   │   └── services/api.js
│   ├── package.json
│   ├── Dockerfile
│   └── .env.example
└── docker-compose.yml
```

## Quick start (Docker)

```bash
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000 (interactive docs at `/docs`)

## Quick start (manual)

**Backend**

```bash
cd backend
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                # fill in AWS creds only if using live mode
uvicorn app.main:app --reload
```

**Frontend**

```bash
cd frontend
npm install
cp .env.example .env
npm start
```

The app boots with the bundled mock scan pre-loaded, so both dashboards work
immediately — no AWS account required.

## Running a live scan

1. Provide AWS credentials to the backend process (env vars in `.env`, a
   shared credentials file, or an attached IAM role — standard boto3
   resolution order).
2. The scanning role needs read-only access; the AWS-managed
   `SecurityAudit` and `ReadOnlyAccess` policies are sufficient.
3. Click **Run scan** in the UI, or:
   ```bash
   curl -X POST http://localhost:8000/api/scan \
     -H "Content-Type: application/json" \
     -d '{"regions": ["us-east-1", "us-west-2"], "use_live_aws": true}'
   ```

If credentials are missing or a call fails, the backend logs a warning and
falls back to mock data rather than returning an error.

## API reference

| Method | Path                  | Description                                   |
|--------|-----------------------|------------------------------------------------|
| GET    | `/api/health`         | Liveness check                                 |
| POST   | `/api/scan`            | Run a scan (mock or live) and refresh state    |
| GET    | `/api/resources`       | List discovered cloud resources                |
| GET    | `/api/vulnerabilities` | List findings (filter by `severity`, `category`)|
| GET    | `/api/attack-graph`    | Graph nodes/edges + ranked attack paths        |
| GET    | `/api/remediation`     | Prioritized remediation plan                   |
| GET    | `/api/dashboard`       | Summary stats for the dashboard                |

## How risk scoring works

Each finding carries `impact`, `exploitability`, and `exposure` (0–10):

```
risk_score = (impact * 0.45 + exploitability * 0.35 + exposure * 0.20)
             * severity_weight * 10        # 0–100
```

The remediation plan multiplies `risk_score` by an effort weight
(low-effort fixes score higher) so that, e.g., a one-click "enable Block
Public Access" fix outranks a multi-week RDS re-encryption project even if
the latter's raw risk score is slightly higher.

## How the attack graph works

`graph_builder.py` builds a directed graph with `networkx`:

- **Entry points**: the internet node, any publicly exposed resource, and
  any IAM user without MFA.
- **Crown jewels**: RDS instances and S3 buckets holding sensitive/PII data.
- **Edges**: inferred from real configuration — an open security group
  reaching an EC2 instance, an instance assuming an over-privileged IAM
  role, a role's policy granting reach to S3/RDS/KMS, and internet-facing
  resources with a critical/high finding.

`find_attack_paths` enumerates simple paths from every entry point to every
crown jewel, scores each by cumulative edge likelihood × target value, and
returns the highest-risk, de-duplicated paths.

## Extending CloudGuard

- **Persistence**: state is currently in-memory per backend process; swap
  `_state` in `main.py` for a database (Postgres + SQLAlchemy is a natural
  fit) to support multi-account, historical scans.
- **More resource types**: add a `_scan_<service>` method to `AWSScanner`
  and matching edge/finding rules in `graph_builder.py` / `aws_scanner.py`.
- **Auth**: add an auth dependency to `main.py`'s routes before exposing
  this outside a trusted network — it currently has no authentication.
- **Multi-account**: run `AWSScanner` per assumed role/account and merge
  results before building the graph.
