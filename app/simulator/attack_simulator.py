"""
attack_simulator.py
--------------------
High-level orchestration API for the HawkEye SOC simulator. Wraps
scenarios.py + event_generator.py behind a simple class/function interface
that returns pandas DataFrames, suitable for feeding into detection-rule
tests, dashboards, or analyst training exercises.

This module is intentionally standalone: no API routes, no FastAPI
dependency, no frontend wiring. Import and call it directly from Python
(scripts, notebooks, pytest, etc).
"""

import pandas as pd

from .scenarios import SCENARIO_GENERATORS, SCENARIO_NAMES
from .event_generator import make_incident_id
from .seed import get_rng

ALERT_COLUMNS = [
    "alert_id", "incident_id", "timestamp", "scenario", "username",
    "department", "hostname", "os", "src_ip", "dst_ip", "event_type",
    "description", "severity", "mitre_technique",
]


DEFAULT_BACKEND_URL = "http://127.0.0.1:8000/alerts/batch"


class AttackSimulator:
    """
    Generates synthetic SOC alert data for one or more attack scenarios.

    Example:
        sim = AttackSimulator(seed=42)
        df = sim.generate_scenario("ransomware")
        full_df = sim.generate_all(scenarios_per_type=2)
    """

    def __init__(self, seed: int = None):
        self.seed = seed
        self.rng = get_rng(seed)

    def available_scenarios(self):
        """Return the list of supported scenario names."""
        return list(SCENARIO_NAMES)

    def generate_scenario(self, scenario_name: str, incident_id: str = None) -> pd.DataFrame:
        """
        Generate a single scenario's alerts (5-12 rows) as a DataFrame.

        Args:
            scenario_name: one of SCENARIO_NAMES.
            incident_id: optional fixed incident ID; auto-generated if omitted.

        Returns:
            pandas.DataFrame with columns defined in ALERT_COLUMNS,
            sorted by timestamp ascending.
        """
        if scenario_name not in SCENARIO_GENERATORS:
            raise ValueError(
                f"Unknown scenario '{scenario_name}'. "
                f"Available scenarios: {', '.join(SCENARIO_NAMES)}"
            )
        generator = SCENARIO_GENERATORS[scenario_name]
        alerts = generator(self.rng, incident_id=incident_id)
        df = pd.DataFrame(alerts, columns=ALERT_COLUMNS)
        df = df.sort_values("timestamp").reset_index(drop=True)
        return df

    def generate_all(self, scenarios_per_type: int = 1) -> pd.DataFrame:
        """
        Generate alerts across every supported scenario type and concatenate
        them into a single DataFrame, each occurrence tagged with its own
        incident_id.

        Args:
            scenarios_per_type: how many independent incidents to generate
                per scenario type (default 1).

        Returns:
            pandas.DataFrame combining all generated alerts, sorted by
            timestamp ascending.
        """
        frames = []
        for name in SCENARIO_NAMES:
            for _ in range(scenarios_per_type):
                frames.append(self.generate_scenario(name))
        combined = pd.concat(frames, ignore_index=True)
        combined = combined.sort_values("timestamp").reset_index(drop=True)
        return combined

    def new_incident_id(self) -> str:
        """Convenience helper: mint a fresh incident ID using this sim's RNG."""
        return make_incident_id(self.rng)

    def post_to_backend(self, scenario_name: str = "ransomware", backend_url: str = DEFAULT_BACKEND_URL, token: str = None) -> dict:
        """
        Generates real attack events and HTTP POSTs them to the backend alerts ingestion endpoint.
        Returns the backend response dict.
        """
        import json
        import urllib.error
        import urllib.request

        df = self.generate_scenario(scenario_name)
        alerts_payload = df.to_dict(orient="records")

        # Normalize timestamp format for JSON serialization
        for a in alerts_payload:
            if hasattr(a.get("timestamp"), "isoformat"):
                a["timestamp"] = a["timestamp"].isoformat()
            else:
                a["timestamp"] = str(a.get("timestamp"))

        data = json.dumps(alerts_payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(backend_url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return {"status": "success", "http_code": resp.status, "data": result}
        except urllib.error.HTTPError as e:
            hint = " (backend requires a token: pass --token or --user/--password)" if e.code == 401 else ""
            return {"status": "error", "message": f"HTTP {e.code}{hint}", "alerts_generated": len(alerts_payload)}
        except Exception as e:
            return {"status": "error", "message": str(e), "alerts_generated": len(alerts_payload)}


def simulate(scenario_name: str = None, seed: int = None,
             scenarios_per_type: int = 1) -> pd.DataFrame:
    """
    Functional convenience wrapper around AttackSimulator.

    Usage:
        simulate("phishing", seed=1)           # single scenario DataFrame
        simulate(seed=1)                       # all scenarios, 1 each
        simulate(seed=1, scenarios_per_type=3)  # all scenarios, 3 each
    """
    sim = AttackSimulator(seed=seed)
    if scenario_name:
        return sim.generate_scenario(scenario_name)
    return sim.generate_all(scenarios_per_type=scenarios_per_type)


def _login(base: str, username: str, password: str, workspace: str = "default") -> str:
    """Obtain a JWT from POST /api/auth/token on the same host as the ingestion URL."""
    import json
    import urllib.request
    from urllib.parse import urlparse

    u = urlparse(base)
    url = f"{u.scheme}://{u.netloc}/api/auth/token"
    body = json.dumps({"username": username, "password": password, "workspace": workspace}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())["access_token"]


if __name__ == "__main__":
    import argparse
    import os

    parser = argparse.ArgumentParser(description="HawkEye Attack Simulator CLI")
    parser.add_argument("--scenario", default="ransomware", choices=SCENARIO_NAMES, help="Scenario name")
    parser.add_argument("--seed", type=int, default=None, help="Random seed")
    parser.add_argument("--url", default=DEFAULT_BACKEND_URL, help="Backend ingestion URL (backend runs on :8000)")
    parser.add_argument("--token", default=os.getenv("HAWKEYE_TOKEN"), help="Bearer JWT (or env HAWKEYE_TOKEN)")
    parser.add_argument("--user", default=None, help="Log in as this user (needs admin or analyst) to get a token")
    parser.add_argument("--password", default=None)
    parser.add_argument("--workspace", default="default")
    parser.add_argument("--no-post", action="store_true", help="Only generate and print alerts; do not POST")
    args = parser.parse_args()

    simulator = AttackSimulator(seed=args.seed)
    print(f"[*] Simulating scenario: {args.scenario} ...")
    if args.no_post:
        df = simulator.generate_scenario(args.scenario)
        print(f"[+] Generated {len(df)} alerts:\n", df[["alert_id", "timestamp", "severity", "event_type"]])
    else:
        token = args.token
        if not token and args.user:
            try:
                token = _login(args.url, args.user, args.password or "", args.workspace)
            except Exception as exc:
                print(f"[-] Login failed: {exc}")
                raise SystemExit(1)
        res = simulator.post_to_backend(args.scenario, backend_url=args.url, token=token)
        print(f"[+] Post result: {res}")
        raise SystemExit(0 if res.get("status") == "success" else 1)
