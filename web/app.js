(() => {
  "use strict";
  const state = { base: (window.SENTINEL_API_BASE || "").replace(/\/$/, ""), accessToken: "", refreshToken: "", user: null, roles: [], sessions: [], audit: [], permissions: [] };
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => [...document.querySelectorAll(s)];
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
  const relative = (value) => { if (!value) return "—"; const d = new Date(value); if (Number.isNaN(d.getTime())) return esc(value); const m = Math.max(0, Math.floor((Date.now()-d.getTime())/60000)); return m < 1 ? "just now" : m < 60 ? m+"m ago" : m < 1440 ? Math.floor(m/60)+"h ago" : Math.floor(m/1440)+"d ago"; };
  function toast(message) { const el=$("#toast"); if (!el) return; el.textContent=message; el.classList.add("show"); clearTimeout(window.__toast); window.__toast=setTimeout(()=>el.classList.remove("show"),3000); }
  async function request(path, options={}) {
    if (!state.base) throw new Error("Set the Sentinel API base URL first.");
    const headers = { Accept:"application/json", ...(options.body ? {"Content-Type":"application/json"} : {}), ...(state.accessToken ? {Authorization:"Bearer "+state.accessToken} : {}), ...(options.headers||{}) };
    const res = await fetch(state.base+path,{...options,headers});
    const text = await res.text(); let body={}; try { body=text ? JSON.parse(text) : {}; } catch { body={message:text}; }
    if (!res.ok) throw new Error(body.message || body.error?.message || body.error || ("Request failed ("+res.status+")"));
    return body.data ?? body.result ?? body;
  }
  function showConnectDialog() {
    const old=$("#sentinelDialog"); if(old) old.remove();
    const d=document.createElement("dialog"); d.id="sentinelDialog";
    d.innerHTML='<form method="dialog" class="connect-form"><button class="dialog-close" aria-label="Close">×</button><p class="eyebrow">SENTINEL API</p><h2>Connect security console</h2><p>Sign in to your running Sentinel API. Your access token stays in memory and is cleared when this page is refreshed.</p><label>API base URL<input id="apiBaseInput" type="url" required placeholder="https://api.example.com" value="'+esc(state.base)+'"></label><label>Email<input id="apiEmail" type="email" required autocomplete="username" placeholder="admin@example.com"></label><label>Password<input id="apiPassword" type="password" required autocomplete="current-password"></label><label>Authenticator code <span>(if MFA is enabled)</span><input id="apiMfa" inputmode="numeric" autocomplete="one-time-code" placeholder="123456"></label><p class="form-error" id="connectError" role="alert"></p><button class="primary-btn" id="connectSubmit" value="connect">Sign in securely</button><small>Tokens are not written to localStorage or sessionStorage.</small></form>';
    document.body.append(d); d.showModal();
    $("#connectSubmit").addEventListener("click",async e=>{e.preventDefault(); const btn=$("#connectSubmit"),err=$("#connectError"); btn.disabled=true;btn.textContent="Connecting…";err.textContent="";
      try { state.base=$("#apiBaseInput").value.trim().replace(/\/$/,""); const login=await request("/api/v1/auth/login",{method:"POST",body:JSON.stringify({email:$("#apiEmail").value.trim(),password:$("#apiPassword").value,mfa_code:$("#apiMfa").value.trim()})}); if(!login.access_token) throw new Error("Login succeeded but the API did not return an access token. Check whether production mode suppresses tokens."); state.accessToken=login.access_token;state.refreshToken=login.refresh_token||"";state.user=login.user||null;state.roles=login.roles||[];d.close();d.remove();await loadLiveData();toast("Connected to Sentinel API."); }
      catch(ex){err.textContent=ex.message;btn.disabled=false;btn.textContent="Sign in securely";}
    });
    d.addEventListener("close",()=>d.remove(),{once:true});
  }
  function setConnection(connected) {
    const pill=$(".demo-pill"); if(pill){pill.innerHTML='<i></i> '+(connected?"Live API connected":"Demo environment");pill.classList.toggle("live-pill",connected);}
    let b=$("#connectButton"); if(!b){b=document.createElement("button");b.id="connectButton";b.className="connect-button";$(".top-actions")?.prepend(b);b.addEventListener("click",()=>state.accessToken ? disconnect() : showConnectDialog());}
    b.textContent=connected?"Disconnect":"Connect API";
  }
  function disconnect(){state.accessToken="";state.refreshToken="";state.user=null;state.roles=[];state.sessions=[];state.audit=[];state.permissions=[];setConnection(false);toast("API disconnected. No tokens were persisted.");}
  function renderUserIdentity() {
    const u=state.user;if(!u)return;
    const name=u.full_name||u.email||"Authenticated user";
    const initials=name.split(/[\s@._-]+/).filter(Boolean).slice(0,2).map(x=>x[0].toUpperCase()).join("")||"U";
    $$(".profile-mini strong").forEach(x=>x.textContent=name); $$(".profile-mini span:not(.chevron)").forEach(x=>x.textContent=state.roles.join(", ")||"Authenticated");
    $$(".profile-btn").forEach(x=>x.innerHTML=esc(name.split(" ")[0])+' <span>⌄</span>');
    $$(".profile-mini .avatar,.top-actions .avatar").forEach(x=>x.textContent=initials);
    const pill=$(".demo-pill"); if(pill) pill.title="Authenticated as "+name;
  }
  function renderSessions() {
    const body=$("#sessionsTable"); if(!body)return;
    body.innerHTML=state.sessions.length?state.sessions.map(s=>'<tr><td>'+esc(s.id||s.session_id||"Session")+'</td><td>'+esc(s.device_info?.user_agent||s.user_agent||s.device||"Unknown device")+'</td><td>'+esc(s.ip_address||s.ip||"—")+'</td><td>'+esc(relative(s.created_at||s.last_seen_at))+'</td><td><span class="status active">● Active</span></td></tr>').join(""):'<tr><td colspan="5">No active sessions returned by the API.</td></tr>';
  }
  function renderAudit() {
    const body=$("#auditTable"); if(!body)return;
    body.innerHTML=state.audit.length?state.audit.slice(0,12).map(a=>'<tr><td>'+esc(relative(a.created_at))+'</td><td>'+esc(a.action||"Event")+'</td><td>'+esc(a.user_id||a.actor_id||"System")+'</td><td>'+esc(a.ip_address||"—")+'</td><td><span class="event success">● Recorded</span></td></tr>').join(""):'<tr><td colspan="5">No audit events returned by the API.</td></tr>';
    const count=$$(".metric-card strong"); if(count[2])count[2].textContent=String(state.audit.filter(a=>/fail|denied|blocked/i.test(a.action||"")).length);
  }
  function renderRoles() {
    const body=$("#rolesTable");if(!body)return;
    body.innerHTML=state.rolesData?.length?state.rolesData.map(r=>'<tr><td><b>'+esc(r.name)+'</b></td><td>'+esc(r.description||"—")+'</td><td>'+esc(relative(r.created_at))+'</td></tr>').join(""):'<tr><td colspan="3">No role data available.</td></tr>';
  }
  function renderPermissions() {
    const body=$("#permissionsTable");if(!body)return;
    body.innerHTML=state.permissions.length?state.permissions.map(p=>'<tr><td><b>'+esc(p.name)+'</b></td><td>'+esc(p.resource)+'</td><td>'+esc(p.action)+'</td><td>'+esc(p.description||"—")+'</td></tr>').join(""):'<tr><td colspan="4">No permission data available.</td></tr>';
  }
  async function loadLiveData() {
    const [me,sessions,roles,permissions,audit]=await Promise.allSettled([
      request("/api/v1/users/me"),request("/api/v1/sessions"),request("/api/v1/admin/roles"),request("/api/v1/admin/permissions"),request("/api/v1/admin/audit-logs")
    ]);
    const value=(result,key)=>result.status==="fulfilled"?(result.value[key]??result.value):[];
    if(me.status==="fulfilled")state.user=me.value.user||me.value;
    if(sessions.status==="fulfilled")state.sessions=value(sessions,"sessions");
    if(roles.status==="fulfilled")state.rolesData=value(roles,"roles");
    if(permissions.status==="fulfilled")state.permissions=value(permissions,"permissions");
    if(audit.status==="fulfilled")state.audit=value(audit,"audit_logs");
    if(me.status==="rejected")toast("Signed in, but profile could not load: "+me.reason.message);
    renderUserIdentity();renderSessions();renderAudit();renderRoles();renderPermissions();
    const cards=$(".metric-card");
    if(cards[0]){const label=cards[0].querySelector(".metric-label"),value=cards[0].querySelector("strong"),note=cards[0].querySelector("small");if(label)label.textContent="Signed-in Identity";if(value)value.textContent=state.user?"1":"—";if(note)note.innerHTML="Authenticated <em>current account only</em>";}
    if(cards[1]){const label=cards[1].querySelector(".metric-label"),value=cards[1].querySelector("strong"),note=cards[1].querySelector("small");if(label)label.textContent="My Active Sessions";if(value)value.textContent=String(state.sessions.length);if(note)note.innerHTML="From API <em>visible to this account</em>";}
    if(cards[2]){const label=cards[2].querySelector(".metric-label"),value=cards[2].querySelector("strong"),note=cards[2].querySelector("small");if(label)label.textContent="Failure Events Loaded";if(value)value.textContent=String(state.audit.filter(a=>/fail|denied|blocked/i.test(a.action||"")).length);if(note)note.innerHTML="Audit sample <em>not a time-series total</em>";}
    if(cards[3]){const label=cards[3].querySelector(".metric-label"),value=cards[3].querySelector("strong"),note=cards[3].querySelector("small");if(label)label.textContent="MFA Adoption";if(value)value.textContent="N/A";if(note)note.textContent="API status endpoint not available";}
    const userHead=$(".tables-grid .table-panel .panel-head h2");if(userHead)userHead.textContent="Sample Users (Not Live)";
    const auditHeads=$(".tables-grid .table-panel .panel-head h2");if(auditHeads[1])auditHeads[1].textContent="Sample Security Events (Not Live)";
    const chartDesc=$(".chart-panel .panel-head p");if(chartDesc)chartDesc.textContent="Illustrative chart — the API does not currently expose aggregated activity time series.";
    const distDesc=$(".distribution .panel-head p");if(distDesc)distDesc.textContent="Illustrative distribution — an admin user-directory endpoint is not yet available.";
    const subtitle=$("#pageSubtitle");if(subtitle&&state.accessToken)subtitle.textContent="Live API data is shown in the connected tables below. Clearly labelled sample widgets are illustrative.";
    $(".panel-head p").forEach(p=>{if(state.accessToken&&/demo/i.test(p.textContent))p.textContent=p.textContent.replace(/demo/ig,"live");});
    setConnection(true);
    const failures=[me,sessions,roles,permissions,audit].filter(x=>x.status==="rejected").length;
    if(failures)toast("Connected with "+failures+" API view(s) unavailable. Check permissions and API routes.");
  }
  const titles={overview:["Security Overview","Monitor your identity and access infrastructure in real time."],users:["Users","Identity data available through the current API permissions."],roles:["Roles & Permissions","Database-backed roles and permissions returned by Sentinel."],sessions:["Sessions","Active sessions returned for the signed-in identity."],audit:["Audit Logs","Recent audit events recorded by the Sentinel backend."],authentication:["Authentication","Password-based login and JWT-backed API access."],mfa:["Multi-Factor Authentication","Configure TOTP using the authenticated MFA endpoints."],oauth:["OAuth Providers","Google and GitHub OAuth login routes exposed by the backend."],security:["Security","Health, readiness and API security controls."],settings:["Settings","API connection and session controls."]};
  function setPage(p){const [t,s]=titles[p]||titles.overview;$("#pageTitle").textContent=t;$("#pageSubtitle").textContent=s;$$(".nav-item").forEach(b=>b.classList.toggle("active",b.dataset.page===p));if(p==="users"&&!state.accessToken)toast("Connect the API to load live identity data.");else if(p==="roles"&&state.accessToken)toast(state.rolesData?.length+" roles loaded from API.");else if(p==="sessions"&&state.accessToken)toast(state.sessions.length+" sessions returned for your account.");else if(p==="audit"&&state.accessToken)toast(state.audit.length+" audit events loaded.");else if(p!=="overview"&&!state.accessToken)toast(t+" — demo preview");}
  function addDataTables(){
    const tableSection=document.createElement("section");tableSection.className="tables-grid live-data-tables";
    tableSection.innerHTML='<article class="panel table-panel"><div class="panel-head"><div><h2>Active Sessions</h2><p>Sessions visible to the signed-in identity.</p></div></div><div class="table-wrap"><table><thead><tr><th>SESSION</th><th>DEVICE</th><th>IP ADDRESS</th><th>CREATED</th><th>STATUS</th></tr></thead><tbody id="sessionsTable"><tr><td colspan="5">Connect to load sessions.</td></tr></tbody></table></div></article><article class="panel table-panel"><div class="panel-head"><div><h2>Live Audit Events</h2><p>Latest audit records returned by the backend.</p></div></div><div class="table-wrap"><table><thead><tr><th>TIME</th><th>ACTION</th><th>ACTOR / USER</th><th>IP ADDRESS</th><th>STATUS</th></tr></thead><tbody id="auditTable"><tr><td colspan="5">Connect to load audit events.</td></tr></tbody></table></div></article><article class="panel table-panel"><div class="panel-head"><div><h2>Backend Roles</h2><p>Actual role definitions from PostgreSQL.</p></div></div><div class="table-wrap"><table><thead><tr><th>ROLE</th><th>DESCRIPTION</th><th>CREATED</th></tr></thead><tbody id="rolesTable"><tr><td colspan="3">Connect as an administrator.</td></tr></tbody></table></div></article><article class="panel table-panel"><div class="panel-head"><div><h2>Backend Permissions</h2><p>Actual permission catalogue from PostgreSQL.</p></div></div><div class="table-wrap"><table><thead><tr><th>PERMISSION</th><th>RESOURCE</th><th>ACTION</th><th>DESCRIPTION</th></tr></thead><tbody id="permissionsTable"><tr><td colspan="4">Connect as an administrator.</td></tr></tbody></table></div></article>';
    $(".content").append(tableSection);
  }
  function buildChart(){const bars=[52,64,72,82,96,88,122,108,142,128,162,149,176,156,136,112,101,88,112,82,108,67],chart=$("#activityChart");if(!chart)return;bars.forEach(v=>{const b=document.createElement("div"),s=document.createElement("i"),f=document.createElement("i"),m=document.createElement("i");b.className="bar";s.className="s";f.className="f";m.className="m";s.style.height=Math.max(20,v)+"%";f.style.height=Math.max(5,v*.14)+"%";m.style.height=Math.max(7,v*.22)+"%";b.append(s,f,m);chart.appendChild(b);});}
  document.addEventListener("DOMContentLoaded",()=>{buildChart();addDataTables();setConnection(false);
    $$(".nav-item").forEach(b=>b.addEventListener("click",()=>setPage(b.dataset.page)));
    $$("[data-page-jump]").forEach(b=>b.addEventListener("click",()=>setPage(b.dataset.pageJump)));
    $$("[data-action]").forEach(b=>b.addEventListener("click",()=>{const a=b.dataset.action;if(a==="docs")window.open("https://github.com/017Mehul/sentinel","_blank","noopener");else if(a==="add-user")toast("User creation endpoint is not exposed by the current API.");else setPage(a)}));
    $(".select-btn")?.addEventListener("click",()=>toast("Time range filtering is not exposed by the current API."));
    $(".profile-btn")?.addEventListener("click",()=>state.accessToken?disconnect():showConnectDialog());
    const search=$("#globalSearch");search?.addEventListener("keydown",e=>{if(e.key==="Enter"&&search.value.trim()){const q=search.value.trim().toLowerCase();const match=state.audit.find(a=>JSON.stringify(a).toLowerCase().includes(q));toast(match?"Matching audit event found: "+(match.action||"event"):"Search is limited to data currently loaded in this console.");}});
    document.addEventListener("keydown",e=>{if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==="k"){e.preventDefault();search?.focus();}});
    if(state.base)toast("API URL configured. Select Connect API to sign in.");
  });
  window.SentinelConsole={connect:showConnectDialog,disconnect,refresh:loadLiveData};
})();