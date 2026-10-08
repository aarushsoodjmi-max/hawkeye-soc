# HawkEye SOC — Attack Simulator

Synthetic SOC alert-data generator for **detection engineering, SOC analyst
training, dashboard demos, and automated testing**.

This module produces realistic, multi-stage attack alert data as
`pandas.DataFrame` objects. It is **fully self-contained**:

- ❌ No API routes
- ❌ No FastAPI integration
- ❌ No frontend
- ✅ Pure Python + pandas, importable anywhere in the backend (scripts,
  notebooks, pytest, Jupyter, data pipelines, etc.)

---

## Folder structure

```
backend/app/simulator/
├── __init__.py          # package exports
├── attack_simulator.py  # AttackSimulator class + simulate() convenience fn
├── scenarios.py         # 5 attack-chain scenario definitions
├── event_generator.py   # low-level synthetic data building blocks
├── seed.py               # deterministic RNG utilities
└── README.md
```

---

## Supported scenarios

| Scenario           | Key               | Attack chain summary                                                                 |
|---------------------|-------------------|-----------------------------------------------------------------------------------------|
| Credential Theft    | `credential_theft`| Failed logins → brute force → anomalous login → MFA bypass → credential dumping → lateral movement |
| Phishing            | `phishing`        | Email delivered → link clicked → credential harvest → attachment opened → macro exec → C2 beacon |
| Malware             | `malware`         | File dropped → AV detection → process injection → persistence → C2 beacon → lateral spread → containment |
| Insider Threat      | `insider_threat`  | After-hours access → abnormal data access → bulk download → removable media / cloud upload → HR correlation |
| Ransomware          | `ransomware`      | Initial access → credential access → shadow copy deletion → mass encryption → ransom note → C2 → containment |

Each scenario instance generates **5–12 alerts**, each tagged with a MITRE
ATT&CK technique ID where applicable, and shares a single `incident_id`,
`username`, and `hostname` across its alert chain (so a scenario reads as
one coherent incident, not unrelated random rows).

---

## Alert schema

Every alert row (DataFrame column) contains:

| Column            | Description                                         |
|-------------------|-------------------------------------------------------|
| `alert_id`        | Unique alert identifier (`ALRT-XXXXXXXXXX`)           |
| `incident_id`     | Shared identifier for the whole scenario (`INC-######`) |
| `timestamp`       | UTC datetime of the alert, ascending within a scenario |
| `scenario`        | Scenario key, e.g. `ransomware`                        |
| `username`        | Synthetic user involved (`first.last`)                 |
| `department`      | Synthetic user's department                            |
| `hostname`        | Synthetic device hostname                               |
| `os`              | Synthetic device operating system                       |
| `src_ip`          | Source IP address (internal or external)                |
| `dst_ip`          | Destination IP address (internal or external)            |
| `event_type`      | Short event/alert category                               |
| `description`     | Human-readable alert description                          |
| `severity`        | `Low` / `Medium` / `High` / `Critical`                    |
| `mitre_technique` | MITRE ATT&CK technique ID (if applicable, else empty)      |

---

## Usage

### Class-based API

```python
from app.simulator import AttackSimulator

# Deterministic: same seed -> same dataset every run
sim = AttackSimulator(seed=42)

# One scenario -> one DataFrame (5-12 rows)
df = sim.generate_scenario("phishing")
print(df.head())

# All 5 scenario types combined into one DataFrame
all_df = sim.generate_all()

# Multiple independent incidents per scenario type
big_df = sim.generate_all(scenarios_per_type=3)   # 5 types x 3 = 15 incidents

# List available scenario keys
sim.available_scenarios()
# -> ['credential_theft', 'phishing', 'malware', 'insider_threat', 'ransomware']
```

### Functional convenience API

```python
from app.simulator import simulate

df = simulate("ransomware", seed=7)        # single scenario
df_all = simulate(seed=7)                  # all scenarios, 1 incident each
df_many = simulate(seed=7, scenarios_per_type=5)
```

### Fixed incident ID

```python
sim = AttackSimulator(seed=1)
df = sim.generate_scenario("malware", incident_id="INC-999999")
```

---

## Determinism / reproducibility

All scenario randomness (which alerts appear, users, devices, IPs, timing,
severities) flows through a single seeded `random.Random` instance.

- `AttackSimulator(seed=42)` → fully reproducible: the same seed, called in
  the same sequence, always yields the same scenario content.
- `AttackSimulator(seed=None)` → non-deterministic, seeded from OS entropy.
- The `alert_id` column uses `uuid4` and is **intentionally** not
  seed-derived (it's a uniqueness key, not simulation logic), so it will
  differ between runs even with the same seed — everything else will match.

For quick scripts that want module-level determinism instead of an
explicit generator instance:

```python
from app.simulator import set_global_seed
set_global_seed(42)
```

---

## Extending the simulator

To add a new scenario:

1. Add a `generate_<name>(rng, incident_id=None)` function to
   `scenarios.py` following the existing pattern (build a `steps` list of
   `(event_type, description, mitre_technique, severity)` tuples, slice to
   `n = _alert_count(rng)`, and call `build_alert(...)` for each).
2. Register it in `SCENARIO_GENERATORS` and add its key to
   `SCENARIO_NAMES`.
3. No changes are needed in `attack_simulator.py` — it reads scenario
   metadata from `scenarios.py` automatically.

---

## Testing example (pytest)

```python
from app.simulator import AttackSimulator

def test_ransomware_scenario_shape():
    sim = AttackSimulator(seed=123)
    df = sim.generate_scenario("ransomware")
    assert 5 <= len(df) <= 12
    assert df["incident_id"].nunique() == 1
    assert set(df.columns) == {
        "alert_id", "incident_id", "timestamp", "scenario", "username",
        "department", "hostname", "os", "src_ip", "dst_ip", "event_type",
        "description", "severity", "mitre_technique",
    }

def test_seed_reproducibility():
    df1 = AttackSimulator(seed=99).generate_scenario("phishing")
    df2 = AttackSimulator(seed=99).generate_scenario("phishing")
    cols = [c for c in df1.columns if c != "alert_id"]
    assert df1[cols].equals(df2[cols])
```
