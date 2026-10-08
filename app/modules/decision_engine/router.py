from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from app.repositories import repository
from app.core.auth import Principal, require_roles
from .service import generate_strategies
from .schemas import StrategyResponse

router = APIRouter()


@router.get('/incidents/{incident_id}/strategies', response_model=StrategyResponse)
def strategies(incident_id: str, principal: Principal = Depends(require_roles("admin", "analyst"))):
    x = repository.get_incident_by_id(incident_id, workspace=principal.workspace)
    if not x:
        raise HTTPException(404, 'Incident not found')
    # GET is strictly read-only. Strategy generation is deterministic and
    # advisory; approval state is owned by the explicit playbook approval flow.
    return StrategyResponse(
        incident_id=incident_id,
        strategies=generate_strategies(x),
        generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
