// Replace only the existing entry selectors; role-specific Host/Ops/Partner
// selectors remain as they were. No cross-origin credential request is made.
ZR=()=>{
  const [params]=ZI(), role=params.get("role")||"",
    next=params.get("return_to")||params.get("returnTo")||"";
  if (["ops","ops_manager","super_admin"].includes(role)||next.startsWith("/ops/")) {
    const query=new URLSearchParams;
    if(role)query.set("role",role);
    query.set("return_to",next||"/ops/command");
    return a.jsx(q,{replace:true,to:`/ops/login?${query.toString()}`});
  }
  const target=role==="host"||role==="owner"||role==="landlord"?"host":
    role==="partner"||role==="agent"?"partner":
    role==="connect"||role==="connector_admin"?"connect":"";
  if(target)return a.jsx(JR,{role:target});
  if(typeof window!=="undefined"&&["liveuin.com","www.liveuin.com"].includes(window.location.hostname))
    return a.jsx(auth02PublicHandoff,{});
  return a.jsx($j,{});
}
