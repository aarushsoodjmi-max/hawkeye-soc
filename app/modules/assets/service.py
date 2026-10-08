from __future__ import annotations

from typing import Any, Dict, List


def _name(asset: Any) -> str:
    if isinstance(asset, dict):
        return str(asset.get("id") or asset.get("name") or "")
    return str(getattr(asset, "id", None) or getattr(asset, "name", ""))


def build_asset_dependencies(assets: List[Any]) -> Dict[str, List[Dict[str, Any]]]:
    nodes = [_name(asset) for asset in (assets or []) if _name(asset)]
    graph: Dict[str, List[Dict[str, Any]]] = {node: [] for node in nodes}
    for idx, node in enumerate(nodes):
        if idx + 1 < len(nodes):
            graph[node].append({"asset_id": nodes[idx + 1], "confidence": 0.72})
    return graph
