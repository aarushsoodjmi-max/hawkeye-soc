# HawkEye SOC — Dataset Generation & Preprocessing Module

This folder contains **only** the dataset generation and preprocessing
layer for the HawkEye SOC hackathon prototype ("Causal SOC Alert
Correlation & Root Cause Intelligence"). It intentionally does **not**
include any API, frontend, correlation engine, or ML model — those are
separate modules/services that consume the CSV this module produces.

```
backend/
└── app/
    └── data/
        ├── generate_dataset.py   # synthetic alert generator
        ├── preprocess.py         # load / clean / encode / sort
        ├── alerts.csv            # generated dataset (~1000 rows)
        └── README.md
```

## What `generate_dataset.py` does

Generates ~1000 fully synthetic SOC alerts and writes them to
`alerts.csv`. Nothing here is real telemetry — every user, device, IP,
and timestamp is randomly generated (seeded for reproducibility,
`RANDOM_SEED = 42`).

**Columns**

| Column        | Description                                              |
|---------------|-----------------------------------------------------------|
| `timestamp`   | `YYYY-MM-DD HH:MM:SS`, spread over a 30-day window        |
| `user`        | synthetic username, e.g. `james.k`                        |
| `device`      | synthetic hostname, e.g. `WIN10-042`                       |
| `ip_address`  | synthetic internal (`10.x.x.x`) or external IP             |
| `alert_type`  | one of the 8 alert types below                             |
| `severity`    | `low` / `medium` / `high` / `critical`                     |
| `source`      | detector source, e.g. `EDR`, `SIEM`, `Firewall`, `AD`, ...  |
| `root_cause`  | one of the 5 root causes below                              |
| `incident_id` | shared ID for causally-linked alerts, e.g. `INC-0001`; empty if not part of an incident |

**Alert types:** `login_anomaly`, `powershell_exec`, `privilege_escalation`,
`data_access`, `malware_detected`, `phishing_email`,
`outbound_connection`, `credential_dump`

**Root causes:** `compromised_account`, `malware`, `phishing`, `insider`,
`benign`

**Distribution**

- ~700 benign alerts (`root_cause = benign`, no `incident_id`)
- ~300 malicious alerts, made up of:
  - **30 incidents**, each a causally-linked chain of **3–6 alerts**
    sharing one `incident_id` and one `root_cause`. Each incident
    follows a plausible attack-stage "playbook" for its root cause
    (e.g. `phishing_email → login_anomaly → powershell_exec →
    privilege_escalation → data_access → outbound_connection`), with
    timestamps ordered and clustered close together to simulate a
    real attack timeline.
  - The remaining malicious alerts are **standalone** (malicious, but
    not linked into any labeled incident chain) — useful as "noise"
    for a correlation engine to filter out.

Run it with:

```bash
cd backend/app/data
python generate_dataset.py
```

This overwrites `alerts.csv` in the current directory and prints a
summary (total / benign / malicious / incident counts).

## What `preprocess.py` does

Exposes four functions only, each returning a `pandas.DataFrame`:

- **`load_dataset(path=None)`** — reads `alerts.csv` (defaults to the
  copy in this folder) into a DataFrame.
- **`clean_data(df)`** — strips whitespace, parses `timestamp` to a
  proper datetime dtype, normalizes empty `incident_id` values to the
  literal string `"NONE"`, drops exact duplicate rows, and drops rows
  with an unparseable timestamp.
- **`encode_severity(df)`** — adds a `severity_encoded` column using a
  plain dictionary mapping (`low=1, medium=2, high=3, critical=4`,
  unknown/missing = 0). No `sklearn` involved.
- **`sort_by_timestamp(df)`** — returns the DataFrame sorted ascending
  by `timestamp`.

Each function takes a DataFrame (or path, for `load_dataset`) and
returns a new DataFrame — none of them mutate their input in place.

**Explicitly out of scope for this module** (by design):

- No alert correlation, incident linking, or graph-building logic.
- No prediction, scoring, anomaly detection, or modeling of any kind.
- No `sklearn` or other ML library usage.
- No API layer (FastAPI or otherwise) and no frontend.

Typical usage from another module:

```python
from preprocess import load_dataset, clean_data, encode_severity, sort_by_timestamp

df = load_dataset("alerts.csv")
df = clean_data(df)
df = encode_severity(df)
df = sort_by_timestamp(df)
```

## Regenerating the dataset

To get a different sample, either change `RANDOM_SEED` in
`generate_dataset.py` or remove the seeding call, then re-run the
script. The distribution constants (`BENIGN_COUNT`, `MALICIOUS_COUNT`,
`NUM_INCIDENTS`, `MIN_ALERTS_PER_INCIDENT`, `MAX_ALERTS_PER_INCIDENT`)
are all defined at the top of the file for easy tuning.
