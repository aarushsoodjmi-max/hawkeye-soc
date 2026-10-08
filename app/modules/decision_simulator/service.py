from collections import defaultdict, deque
from typing import Any, Dict
from .schemas import SimulationResponse,CascadeAsset,RecoveryStep
def _get(o,k,d=None): return o.get(k,d) if isinstance(o,dict) else getattr(o,k,d)
def simulate(incident:Any,dependencies:Dict[str,list]|None=None,max_depth:int=5,decay:float=.7,confidence_floor:float=.25):
    assets=_get(incident,'affectedAssets',[]) or []; deps=dependencies or _get(incident,'assetDependencies',{}) or {}
    ids=[str(_get(a,'id',_get(a,'name',''))) for a in assets]
    graph=defaultdict(list); business={str(_get(a,'id',_get(a,'name',''))):str(_get(a,'business_unit',_get(a,'businessUnit','Unknown'))) for a in assets}
    for src,targets in deps.items():
        for t in targets:
            if isinstance(t,dict): tid=str(t.get('asset_id') or t.get('id')); conf=float(t.get('confidence',1))
            else: tid=str(t); conf=1.0
            graph[str(src)].append((tid,conf))
    seen={i:(0,1.0) for i in ids}; q=deque(ids)
    while q:
        src=q.popleft(); hop,impact=seen[src]
        if hop>=max_depth: continue
        for dst,conf in graph[src]:
            if conf<confidence_floor: continue
            nh=hop+1; ni=impact*decay*conf
            if dst not in seen or ni>seen[dst][1]: seen[dst]=(nh,ni); q.append(dst)
    casc=[CascadeAsset(asset_id=k,hop_distance=h,decayed_impact=round(v,3),reason='Dependency cascade') for k,(h,v) in seen.items() if k not in ids]
    downtime=round(max(1,len(assets))*2+sum(x.decayed_impact for x in casc)*1.5,2)
    recovery=round(downtime*1.4,2); cost=round(1500*len(seen)+500*len(casc),2)
    seq=[RecoveryStep(asset_id=k,estimated_start_offset_hours=round(h*.5,2),estimated_duration_hours=round(1+(0.5 if h else 0),2)) for k,(h,_) in sorted(seen.items(),key=lambda x:-x[1][0])]
    return SimulationResponse(incident_id=str(_get(incident,'id','')),cascade_depth=max([x.hop_distance for x in casc] or [0]),cascading_affected_assets=casc,affected_departments=sorted({business.get(x,'Unknown') for x in seen}),estimated_downtime_hours=downtime,recovery_time_hours=recovery,operational_cost=cost,confidence_score=round(max(.4,min(.98,1/(1+len(casc)*.12))),3),recovery_sequence=seq)
