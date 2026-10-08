"""Tenant-scoped durable incident memory."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List
from collections import Counter
from app.db import PersistentStateRepository


def _get(o: Any, k: str, d=None):
    return o.get(k, d) if isinstance(o, dict) else getattr(o, k, d)

def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class IncidentMemoryService:
    def __init__(self, store: PersistentStateRepository | None = None):
        self._store = store or PersistentStateRepository()

    @staticmethod
    def _require_workspace(workspace_id: str) -> str:
        if not isinstance(workspace_id, str) or not workspace_id.strip():
            raise ValueError("workspace_id is required for incident memory operations")
        return workspace_id.strip()

    def signature(self, incident: Any) -> Dict[str, Any]:
        root = _get(incident, "rootCause", None)
        techniques = sorted({str(_get(e, "techniqueId", "")).upper() for e in (_get(incident, "timelineEvents", []) or []) if _get(e, "techniqueId")})
        sources = sorted({str(_get(e, "source", "")).lower() for e in (_get(incident, "timelineEvents", []) or []) if _get(e, "source")})
        criticalities = sorted({str(_get(a, "criticality", "")).upper() for a in (_get(incident, "affectedAssets", []) or []) if _get(a, "criticality")})
        return {"root_cause": str(_get(root, "primary", "") or _get(root, "vector", "")).lower(), "techniques": techniques, "source_mix": sources, "criticality_tiers": criticalities, "threat_actor": str(_get(incident, "threatActor", "")).lower()}

    def record_closed(self, incident: Any, workspace_id: str) -> Dict[str, Any]:
        ws = self._require_workspace(workspace_id); iid = str(_get(incident, "id", _get(incident, "incident_id", "")))
        if not iid: raise ValueError("incident_id is required for incident memory")
        sig = self.signature(incident)
        successful = [str(_get(a, "playbookId", "")) for a in (_get(incident, "recommendedActions", []) or []) if str(_get(a, "status", "")).upper() == "COMPLETED" and _get(a, "playbookId")]
        record = {"id": f"MEM-{ws}-{iid}", "incident_id": iid, "workspace_id": ws, "summary": str(_get(incident, "impactSummary", _get(incident, "title", ""))), "resolution_status": str(_get(incident, "status", "CLOSED")), "playbooks_used": successful, "playbook_successful": bool(successful), "root_cause": sig["root_cause"], "signature": sig, "closed_at": _now()}
        self._store.upsert("incident_memory", ws, iid, record)
        key = self._pattern_key(sig); patterns = self._store.list("incident_memory", ws, 10000)
        related = [p["incident_id"] for p in patterns if isinstance(p, dict) and p.get("type") not in {"pattern", "note"} and p.get("signature") == sig and p.get("incident_id")]
        pattern = {"id": f"PAT-{abs(hash((ws, key))) % 10**8}", "workspace_id": ws, "pattern_signature": sig, "occurrence_count": len(related), "first_seen": min([p.get("closed_at", _now()) for p in patterns if isinstance(p, dict) and p.get("signature") == sig] or [_now()]), "last_seen": _now(), "related_incident_ids": list(dict.fromkeys(related + [iid]))}
        self._store.upsert("incident_memory", ws, f"pattern:{key}", {"type": "pattern", **pattern})
        return record

    @staticmethod
    def _pattern_key(sig):
        return "|".join([sig["root_cause"], ",".join(sig["techniques"]), ",".join(sig["criticality_tiers"])])

    def similar(self, incident: Any, workspace_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        ws = self._require_workspace(workspace_id); target = self.signature(incident); iid = str(_get(incident, "id", _get(incident, "incident_id", "")))
        def score(sig):
            sets=[(set(target["techniques"]),set(sig["techniques"])),(set(target["source_mix"]),set(sig["source_mix"])),(set(target["criticality_tiers"]),set(sig["criticality_tiers"]))]
            vals=[len(a&b)/max(1,len(a|b)) for a,b in sets]; root=1.0 if target["root_cause"] and target["root_cause"]==sig["root_cause"] else 0.0; actor=1.0 if target["threat_actor"] and target["threat_actor"]==sig["threat_actor"] else 0.0
            return round(.5*vals[0]+.15*vals[1]+.2*vals[2]+.1*root+.05*actor,4)
        out=[]
        for r in self._store.list("incident_memory", ws, 10000):
            if r.get("type") == "pattern" or r.get("incident_id") == iid: continue
            if r.get("workspace_id") != ws: continue
            out.append({"incident_id":r["incident_id"],"workspace_id":ws,"similarity_score":score(r["signature"]),"playbook_successful":r["playbook_successful"],"playbooks_used":r["playbooks_used"],"root_cause":r["root_cause"],"closed_at":r["closed_at"]})
        return sorted(out,key=lambda x:x["similarity_score"],reverse=True)[:max(1,limit)]

    def add_note(self, incident_id: str, note: str, workspace_id: str, author_id: str = "analyst") -> Dict[str, Any]:
        ws=self._require_workspace(workspace_id)
        if not incident_id: raise ValueError("incident_id is required for incident memory")
        item={"id":f"NOTE-{abs(hash((ws,incident_id,note)))%10**10}","incident_id":incident_id,"workspace_id":ws,"author_id":author_id,"note":note,"created_at":_now()}
        self._store.upsert("incident_memory",ws,item["id"],{"type":"note",**item}); return item

    def get_notes(self, incident_id: str, workspace_id: str):
        ws=self._require_workspace(workspace_id)
        rows = [x for x in self._store.list("incident_memory",ws,10000) if x.get("type")=="note" and x.get("incident_id")==incident_id]
        unique = {}
        for row in rows:
            unique[str(row.get("id") or row.get("note"))] = row
        return list(unique.values())

    def get_patterns(self, workspace_id: str):
        ws=self._require_workspace(workspace_id)
        return sorted([x for x in self._store.list("incident_memory",ws,10000) if x.get("type")=="pattern"], key=lambda p:p.get("occurrence_count",0), reverse=True)

    def get_record(self, incident_id: str, workspace_id: str):
        ws=self._require_workspace(workspace_id); value=self._store.get("incident_memory",ws,incident_id)
        return value if value and value.get("type") != "note" and value.get("type") != "pattern" else None

memory_service = IncidentMemoryService()
