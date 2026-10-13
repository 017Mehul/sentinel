(() => {
  "use strict";
  const state = { base: (window.SENTINEL_API_BASE || "").replace(/\/$/, ""), accessToken: "", refreshToken: "", csrfToken: "", user: null, roles: [], sessions: [], audit: [], permissions: [], rolesData: [], users: [], mfa: {enabled:false,configured:false}, health: null, mfaSetup: null, refreshing: null };
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => [...document.querySelectorAll(s)];
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
  const relative = (value) => { if (!value) return "—"; const d = new Date(value); if (Number.isNaN(d.getTime())) return esc(value); const m = Math.max(0, Math.floor((Date.now()-d.getTime())/60000)); return m < 1 ? "just now" : m < 60 ? m+"m ago" : m < 1440 ? Math.floor(m/60)+"h ago" : Math.floor(m/1440)+"d ago"; };
  function toast(message) { const el=$("#toast"); if (!el) return; el.textContent=message; el.classList.add("show"); clearTimeout(window.__toast); window.__toast=setTimeout(()=>el.classList.remove("show"),3000); }
  async function refreshAccessToken() {
    if (state.refreshing) return state.refreshing;
    if (!state.base) return false;
    state.refreshing = (async () => {
      try {
        const options = { method:"POST", credentials:"include", headers:{Accept:"application/json", ...(state.csrfToken?{"X-CSRF-Token":state.csrfToken}:{})} };
        if (state.refreshToken) { options.headers["Content-Type"]="application/json"; options.body=JSON.stringify({refresh_token:state.refreshToken}); }
        const res = await fetch(state.base+"/api/v1/auth/refresh",options);
        const text = await res.text(); const body = text ? JSON.parse(text) : {};
        const payload = body.data ?? body.result ?? body;
        if (!res.ok || !payload.access_token) return false;
        state.accessToken=payload.access_token;
        state.refreshToken=payload.refresh_token||state.refreshToken;
        state.csrfToken=payload.csrf_token||state.csrfToken;
        return true;
      } catch { return false; }
      finally { state.refreshing=null; }
    })();
    return state.refreshing;
  }
  async function request(path, options={}, retried=false) {
    if (!state.base) throw new Error("Set the Sentinel API base URL first.");
    const headers = { Accept:"application/json", ...(options.body ? {"Content-Type":"application/json"} : {}), ...(state.accessToken ? {Authorization:"Bearer "+state.accessToken} : {}), ...((state.csrfToken && (path.endsWith("/api/v1/auth/refresh") || path.endsWith("/api/v1/auth/logout"))) ? {"X-CSRF-Token":state.csrfToken} : {}), ...(options.headers||{}) };
    const fetchOptions={...options,headers,credentials:"include"};
    delete fetchOptions.skipRefresh;
    const res = await fetch(state.base+path,fetchOptions);
    if (res.status===401 && !retried && state.accessToken && path!=="/api/v1/auth/login" && path!=="/api/v1/auth/refresh" && !options.skipRefresh) {
      try { await refreshAccessToken(); return request(path,options,true); }
      catch { state.accessToken=""; state.refreshToken=""; state.csrfToken=""; state.user=null; disconnect(); }
    }
    const text = await res.text(); let body={}; try { body=text ? JSON.parse(text) : {}; } catch { body={message:text}; }
    if (!res.ok) throw new Error(body.message || body.error?.message || body.error || ("Request failed ("+res.status+")"));
    return body.data ?? body.result ?? body;
  }
  function showConnectDialog() {
    const old=$("#sentinelDialog"); if(old) old.remove();
    const d=document.createElement("dialog"); d.id="sentinelDialog";
    d.innerHTML='<form method="dialog" class="connect-form"><button class="dialog-close" aria-label="Close">×</button><p class="eyebrow">SENTINEL API</p><h2>Connect security console</h2><p>Sign in to your running Sentinel API. Your access token stays in memory and is cleared when this page is refreshed.</p><label>API base URL<input id="apiBaseInput" type="url" required placeholder="http://localhost:8080" value="'+esc(state.base)+'"></label><label>Email<input id="apiEmail" type="email" required autocomplete="username" placeholder="admin@example.com"></label><label>Password<input id="apiPassword" type="password" required autocomplete="current-password"></label><label>Authenticator code <span>(if MFA is enabled)</span><input id="apiMfa" inputmode="numeric" autocomplete="one-time-code" placeholder="123456"></label><p class="form-error" id="connectError" role="alert"></p><button class="primary-btn" id="connectSubmit" value="connect">Sign in securely</button><small>Tokens are not written to localStorage or sessionStorage.</small></form>';
    document.body.append(d); d.showModal();
    if(window.SENTINEL_API_BASE || window.SENTINEL_ALLOW_API_URL_OVERRIDE===false) $("#apiBaseInput").readOnly=true;
    $("#connectSubmit").addEventListener("click",async e=>{e.preventDefault(); const btn=$("#connectSubmit"),err=$("#connectError"); btn.disabled=true;btn.textContent="Connecting…";err.textContent="";
      try { state.base=$("#apiBaseInput").value.trim().replace(/\/$/,""); if(!state.base) throw new Error("Set the production API URL in web/config.js before connecting."); const apiURL=new URL(state.base); if(!/^https?:$/.test(apiURL.protocol)) throw new Error("Use an HTTP(S) API URL."); if(apiURL.username||apiURL.password||apiURL.search||apiURL.hash||(apiURL.pathname!=="/"&&apiURL.pathname!=="")) throw new Error("Enter an API origin only, without credentials, path, query, or fragment."); if(apiURL.protocol!=="https:" && !["localhost","127.0.0.1"].includes(apiURL.hostname)) throw new Error("HTTPS is required except for localhost development."); state.base=apiURL.origin; const login=await request("/api/v1/auth/login",{method:"POST",body:JSON.stringify({email:$("#apiEmail").value.trim(),password:$("#apiPassword").value,mfa_code:$("#apiMfa").value.trim()}),credentials:"include"}); if(!login.access_token) throw new Error("No access token was returned. The API must return a short-lived access token and keep refresh tokens in HttpOnly cookies."); state.accessToken=login.access_token;state.refreshToken=login.refresh_token||"";state.csrfToken=login.csrf_token||"";state.user=login.user||null;state.roles=login.roles||[];d.close();d.remove();await loadLiveData();toast("Connected to Sentinel API."); }
      catch(ex){err.textContent=ex.message;btn.disabled=false;btn.textContent="Sign in securely";}
    });
    d.addEventListener("close",()=>d.remove(),{once:true});
  }
  function setConnection(connected) {
    const pill=$(".demo-pill"); if(pill){pill.innerHTML='<i></i> '+(connected?"Live API connected":"Demo environment");pill.classList.toggle("live-pill",connected);}
    let b=$("#connectButton"); if(!b){b=document.createElement("button");b.id="connectButton";b.className="connect-button";$(".top-actions")?.prepend(b);b.addEventListener("click",()=>state.accessToken ? disconnect() : showConnectDialog());}
    b.textContent=connected?"Disconnect":"Connect API";
  }
  function disconnect(){state.accessToken="";state.refreshToken="";state.csrfToken="";state.user=null;state.roles=[];state.sessions=[];state.audit=[];state.permissions=[];state.rolesData=[];state.users=[];state.mfa={enabled:false,configured:false};state.health=null;toast("API disconnected. No tokens were persisted.");setTimeout(()=>window.location.reload(),350);}
  function renderUserIdentity() {
    const u=state.user;if(!u)return;
    const name=u.full_name||u.email||"Authenticated user";
    const initials=name.split(/[\s@._-]+/).filter(Boolean).slice(0,2).map(x=>x[0].toUpperCase()).join("")||"U";
    $$(".profile-mini strong").forEach(x=>x.textContent=name); $$(".profile-mini span:not(.chevron)").forEach(x=>x.textContent=state.roles.join(", ")||"Authenticated");
    $$(".profile-btn").forEach(x=>x.innerHTML=esc(name.split(" ")[0])+' <span>⌄</span>');
    $$(".profile-mini .avatar,.top-actions .avatar").forEach(x=>x.textContent=initials);
    const pill=$(".demo-pill"); if(pill) pill.title="Authenticated as "+name;
  }
  async function revokeCurrentSession(){
    if(!state.accessToken)return toast("Connect to the Sentinel API first.");
    try{await request("/api/v1/sessions/current",{method:"DELETE"});toast("Current session revoked. Signing out…");disconnect();}
    catch(ex){toast("Could not revoke the current session: "+ex.message);}
  }
  function renderSessions() {
    const body=$("#sessionsTable"); if(!body)return;
    body.innerHTML=state.sessions.length?state.sessions.map(s=>'<tr><td>'+esc(s.id||s.session_id||"Session")+'</td><td>'+esc(s.email||s.device_info?.user_agent||s.user_agent||s.device||"Unknown device")+'</td><td>'+esc(s.ip_address||s.ip||"—")+'</td><td>'+esc(relative(s.created_at||s.last_active_at||s.last_seen_at))+'</td><td><span class="status active">● Active</span>'+(s.user_id? ' <button class="text-btn" data-revoke-session="'+esc(s.id||s.session_id||"")+'">Revoke session</button>':'')+'</td></tr>').join(""):'<tr><td colspan="5">No active sessions returned by the API.</td></tr>';
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
  async function searchAdminUsers(query="",role="") {
    const params=new URLSearchParams({page:"1",page_size:"100"});
    if(query.trim())params.set("search",query.trim());
    if(role.trim())params.set("role",role.trim());
    const data=await request("/api/v1/admin/users?"+params.toString());
    state.users=data.users||[];
    renderOverviewUsers();
    return state.users;
  }
  function renderOverviewUsers() {
    const body=$("#usersTable"); if(!body)return;
    body.innerHTML=state.users.length?state.users.slice(0,5).map(u=>{
      const name=u.full_name||u.email||"User";
      const initials=name.split(/[\s@._-]+/).filter(Boolean).slice(0,2).map(x=>x[0].toUpperCase()).join("")||"U";
      const roleNames=(u.roles||[]).join(", ")||"No roles";
      const status=u.is_locked?"Locked":u.is_verified?"Verified":"Unverified";
      const mfaStatus=state.user&&u.id===state.user.id?(state.mfa.enabled?"Enabled":"Disabled"):"—";
      return '<tr><td><div class="user-cell"><span class="user-avatar">'+esc(initials)+'</span><div><b>'+esc(name)+'</b><small>'+esc(u.email)+'</small></div></div></td><td><span class="tag blue-tag">'+esc(roleNames)+'</span></td><td><span class="status '+(u.is_locked?"invited":"active")+'">● '+esc(status)+'</span></td><td><span class="tag gray-tag">'+esc(mfaStatus)+'</span></td><td>'+esc(relative(u.last_login_at))+'</td><td></td></tr>';
    }).join(""):'<tr><td colspan="6">No users returned by the admin API.</td></tr>';
  }
  function renderOverviewAudit() {
    const body=$("#overviewAuditTable"); if(!body)return;
    body.innerHTML=state.audit.length?state.audit.slice(0,7).map(a=>{
      const failed=/fail|denied|blocked/i.test(a.action||"");
      return '<tr><td>'+esc(relative(a.created_at))+'</td><td>'+esc(a.action||"Event")+'</td><td>'+esc(a.actor_id||a.user_id||"System")+'</td><td>'+esc(a.ip_address||"—")+'</td><td><span class="event '+(failed?"blocked":"success")+'">● '+(failed?"Review":"Recorded")+'</span></td></tr>';
    }).join(""):'<tr><td colspan="5">No audit events returned by the API.</td></tr>';
  }
  async function logoutSession() {
    if(!state.accessToken)return disconnect();
    try { await request("/api/v1/auth/logout",{method:"POST",body:state.refreshToken?JSON.stringify({refresh_token:state.refreshToken}):undefined,skipRefresh:true}); }
    catch(err) { toast("Server logout could not be confirmed: "+err.message); }
    disconnect();
  }
  async function loadLiveData() {
    const [me,mySessions,adminSessions,roles,permissions,audit,users,mfa,healthz,health,version]=await Promise.allSettled([
      request("/api/v1/users/me"),request("/api/v1/sessions"),request("/api/v1/admin/sessions"),request("/api/v1/admin/roles"),request("/api/v1/admin/permissions"),request("/api/v1/admin/audit-logs"),request("/api/v1/admin/users?page=1&page_size=100"),request("/api/v1/mfa/status"),request("/healthz"),request("/ready"),request("/version")
    ]);
    const value=(result,key)=>result.status==="fulfilled"?(result.value[key]??result.value):[];
    if(me.status==="fulfilled")state.user=me.value.user||me.value;
    if(adminSessions.status==="fulfilled")state.sessions=value(adminSessions,"sessions"); else if(mySessions.status==="fulfilled")state.sessions=value(mySessions,"sessions");
    if(roles.status==="fulfilled")state.rolesData=value(roles,"roles");
    if(permissions.status==="fulfilled")state.permissions=value(permissions,"permissions");
    if(audit.status==="fulfilled")state.audit=value(audit,"audit_logs");
    if(users.status==="fulfilled")state.users=value(users,"users");
    if(mfa.status==="fulfilled")state.mfa={enabled:!!mfa.value.enabled,configured:!!mfa.value.configured};
    state.health={live:healthz.status==="fulfilled",ready:health.status==="fulfilled",version:version.status==="fulfilled"?version.value:null};
    const statusPill=$(".system-status .status-pill"); if(statusPill)statusPill.textContent=state.health.live&&state.health.ready?"● API and dependencies ready":state.health.live?"● API responding; dependencies not ready":"● API not responding";
    const statusRows=$$(".system-status .system-list div");
    if(statusRows[0]?.querySelector("b"))statusRows[0].querySelector("b").textContent=state.health.live?"● Responding":"● Not responding";
    if(statusRows[1]?.querySelector("b"))statusRows[1].querySelector("b").textContent=state.health.ready?"● Ready":"● Not ready";
    if(statusRows[2]?.querySelector("b"))statusRows[2].querySelector("b").textContent="● Configuration not exposed";
    if(statusRows[3]?.querySelector("b"))statusRows[3].querySelector("b").textContent="● Configuration not exposed";

    if(me.status==="rejected")toast("Signed in, but profile could not load: "+me.reason.message);
    renderUserIdentity();renderSessions();renderAudit();renderRoles();renderPermissions();renderOverviewUsers();renderOverviewAudit();
    const cards=$$(".metric-card");
    if(cards[0]){const label=cards[0].querySelector(".metric-label"),value=cards[0].querySelector("strong"),note=cards[0].querySelector("small");if(label)label.textContent="Signed-in Identity";if(value)value.textContent=state.user?"1":"—";if(note)note.innerHTML="Authenticated <em>current account only</em>";}
    if(cards[1]){const label=cards[1].querySelector(".metric-label"),value=cards[1].querySelector("strong"),note=cards[1].querySelector("small");if(label)label.textContent="My Active Sessions";if(value)value.textContent=String(state.sessions.length);if(note)note.innerHTML="From API <em>visible to this account</em>";}
    if(cards[2]){const label=cards[2].querySelector(".metric-label"),value=cards[2].querySelector("strong"),note=cards[2].querySelector("small");if(label)label.textContent="Failure Events Loaded";if(value)value.textContent=String(state.audit.filter(a=>/fail|denied|blocked/i.test(a.action||"")).length);if(note)note.innerHTML="Audit sample <em>not a time-series total</em>";}
    if(cards[3]){const label=cards[3].querySelector(".metric-label"),value=cards[3].querySelector("strong"),note=cards[3].querySelector("small");if(label)label.textContent="MFA for Account";if(value)value.textContent=state.mfa.enabled?"Enabled":"Disabled";if(note)note.textContent=state.mfa.configured?"Factor configured":"No factor configured";}
    const userHead=$(".tables-grid .table-panel .panel-head h2");if(userHead)userHead.textContent="Recent Users";
    const auditHeads=$$(".tables-grid .table-panel .panel-head h2");if(auditHeads[1])auditHeads[1].textContent="Recent Security Events";
    const chartDesc=$(".chart-panel .panel-head p");if(chartDesc)chartDesc.textContent="Illustrative chart — the API does not currently expose aggregated activity time series.";
    const distDesc=$(".distribution .panel-head p");if(distDesc)distDesc.textContent="Illustrative distribution — aggregate role counts are not exposed by the API.";
    const subtitle=$("#pageSubtitle");if(subtitle&&state.accessToken)subtitle.textContent="Live API data is shown in the connected tables below. Clearly labelled sample widgets are illustrative.";
    setConnection(true);
    const failures=[me,mySessions,roles,permissions,audit,users,mfa,healthz,health].filter(x=>x.status==="rejected").length;
    if(failures)toast("Connected with "+failures+" API view(s) unavailable. Check permissions and API routes.");
  }
  const titles={overview:["Security Overview","Monitor your identity and access infrastructure in real time."],users:["Users","Identity data available through the current API permissions."],roles:["Roles & Permissions","Database-backed roles and permissions returned by Sentinel."],sessions:["Sessions","Active sessions returned for the signed-in identity."],audit:["Audit Logs","Recent audit events recorded by the Sentinel backend."],authentication:["Authentication","Password-based login and JWT-backed API access."],mfa:["Multi-Factor Authentication","Configure TOTP using the authenticated MFA endpoints."],oauth:["OAuth Providers","Google and GitHub OAuth login routes exposed by the backend."],security:["Security","Health, readiness and API security controls."],settings:["Settings","API connection and session controls."]};
  function renderFeaturePanel(page) {
    const panel=$("#featureContent"); if(!panel)return;
    if(page==="users"){
      panel.innerHTML='<div class="panel-head"><div><h2>Identity Directory</h2><p>Live directory from the authenticated admin API.</p></div><span class="tag blue-tag">'+state.users.length+' loaded</span></div><div class="table-wrap"><table><thead><tr><th>NAME</th><th>EMAIL</th><th>ID</th><th>ROLES</th><th>STATUS</th><th>LAST LOGIN</th></tr></thead><tbody>'+ (state.users.length?state.users.map(u=>'<tr><td>'+esc(u.full_name||"—")+'</td><td>'+esc(u.email)+'</td><td><button class="text-btn" data-copy-id="'+esc(u.id)+'">Copy ID</button></td><td>'+esc((u.roles||[]).join(", ")||"No roles")+'</td><td><span class="status '+(u.is_locked?"invited":"active")+'">'+(u.is_locked?"Locked":u.is_verified?"Verified":"Unverified")+'</span></td><td>'+esc(relative(u.last_login_at))+'</td></tr>').join(""):'<tr><td colspan="6">No users returned. Connect with an admin account.</td></tr>')+'</tbody></table></div><form id="roleAssignmentForm" class="feature-form"><h3>Assign or revoke a role</h3><label>User ID<input name="user_id" required placeholder="UUID from directory"></label><label>Role name<input name="role_name" required placeholder="admin / user"></label><div class="feature-actions"><button class="primary-btn" name="operation" value="assign">Assign role</button><button class="outline-btn" name="operation" value="remove">Revoke role</button></div><p class="form-error" id="roleError" role="alert"></p></form>';
    } else if(page==="mfa"){
      panel.innerHTML='<div class="panel-head"><div><h2>Multi-Factor Authentication</h2><p>Configure an authenticator app for your account.</p></div><span class="status '+(state.mfa.enabled?"active":"invited")+'">'+(state.mfa.enabled?"Enabled":state.mfa.configured?"Configured, disabled":"Not configured")+'</span></div><p class="feature-copy">MFA status is read from Sentinel. Setup secrets and recovery codes are shown only after an authenticated setup request.</p><div class="feature-actions"><button class="primary-btn" data-feature-action="mfa-setup">Start setup</button><button class="outline-btn" data-feature-action="mfa-refresh">Refresh status</button></div>'+(state.mfaSetup?'<div class="mfa-setup-result"><h3>Scan with your authenticator</h3><img alt="Authenticator QR code" class="mfa-qr" src="data:image/png;base64,'+esc(state.mfaSetup.qr_code_base64||"")+'"><p>Manual key: <code>'+esc(state.mfaSetup.secret||"")+'</code></p><h4>Recovery codes — store securely</h4><pre>'+esc((state.mfaSetup.backup_codes||[]).join("\n"))+'</pre></div>':'')+'<form id="mfaCodeForm" class="feature-form"><label>Authenticator code or recovery code<input name="code" required autocomplete="one-time-code" placeholder="6-digit or recovery code"></label><div class="feature-actions"><button class="primary-btn" name="operation" value="enable">Enable MFA</button><button class="outline-btn" name="operation" value="disable">Disable MFA</button></div><p class="form-error" id="mfaError" role="alert"></p></form>';
    } else if(page==="settings"){
      const u=state.user||{};
      panel.innerHTML='<div class="panel-head"><div><h2>Profile &amp; Session Settings</h2><p>Update only the fields supported by the current API.</p></div></div><form id="profileForm" class="feature-form"><label>Full name<input name="full_name" required maxlength="120" value="'+esc(u.full_name||"")+'"></label><label>Avatar URL<input name="avatar_url" type="url" maxlength="2048" value="'+esc(u.avatar_url||"")+'"></label><label>Email<input value="'+esc(u.email||"")+'" disabled></label><p class="form-error" id="profileError" role="alert"></p><button class="primary-btn">Save profile</button></form><div class="feature-form"><h3>Authentication</h3><p>Access tokens are memory-only. Production refresh tokens are stored in a Secure, HttpOnly cookie.</p><button class="outline-btn" data-feature-action="logout">Sign out</button></div>';
    } else if(page==="oauth"){
      panel.innerHTML='<div class="panel-head"><div><h2>OAuth Sign-in</h2><p>Start the configured provider flow on the Sentinel API.</p></div></div><p class="feature-copy">Provider secrets remain server-side. OAuth callbacks return JSON and do not establish this console session; use password login here.</p><div class="feature-actions"><button class="primary-btn" data-feature-action="oauth-google">Open Google API flow</button><button class="outline-btn" data-feature-action="oauth-github">Open GitHub API flow</button></div>';
    } else if(page==="security" || page==="authentication"){
      panel.innerHTML='<div class="panel-head"><div><h2>'+(page==="security"?"Live System Readiness":"Authentication Controls")+'</h2><p>Values below are queried from the connected backend.</p></div><button class="text-btn" data-feature-action="refresh-health">Refresh</button></div><div class="system-list"><div><span>API liveness</span><b>'+(state.health?.live?"● Responding":"● Not responding")+'</b></div><div><span>Database &amp; Redis readiness</span><b>'+(state.health?.ready?"● Ready":"● Not ready / unavailable")+'</b></div><div><span>Service version</span><b>'+esc(state.health?.version?.version||state.health?.version?.data?.version||"Unknown")+'</b></div><div><span>MFA for this account</span><b>'+(state.mfa.enabled?"● Enabled":"● Not enabled")+'</b></div></div><p class="feature-copy">This is service readiness, not a claim that every optional integration (OAuth, SMTP, tracing) is operational.</p>';
    } else {
      panel.innerHTML='<div class="panel-head"><div><h2>Sentinel API</h2><p>Connect the console to view real backend data.</p></div></div><p class="feature-copy">Use Connect API to authenticate. Administrative actions require an account with the appropriate role.</p>';
    }
  }
  function bindFeatureForms() {
    const mfaForm=$("#mfaCodeForm");
    if(mfaForm)mfaForm.addEventListener("submit",async e=>{
      e.preventDefault();
      const submitter=e.submitter; const operation=submitter?.value;
      if(!["enable","disable"].includes(operation))return;
      const code=new FormData(mfaForm).get("code")?.toString().trim()||"";
      const error=$("#mfaError"); if(error)error.textContent="";
      mfaForm.querySelectorAll("button").forEach(b=>b.disabled=true);
      try {
        await request("/api/v1/mfa/"+operation,{method:"POST",body:JSON.stringify({code})});
        state.mfaSetup=null;
        const status=await request("/api/v1/mfa/status");
        state.mfa={enabled:!!status.enabled,configured:!!status.configured};
        renderFeaturePanel("mfa"); bindFeatureForms();
        toast("MFA "+(operation==="enable"?"enabled":"disabled")+".");
      } catch(err) { if(error)error.textContent=err.message; toast("MFA update failed: "+err.message); }
      finally { mfaForm.querySelectorAll("button").forEach(b=>b.disabled=false); }
    });
    const profileForm=$("#profileForm");
    if(profileForm)profileForm.addEventListener("submit",async e=>{
      e.preventDefault();
      const error=$("#profileError"); if(error)error.textContent="";
      const data=new FormData(profileForm);
      const payload={full_name:data.get("full_name")?.toString().trim()||"",avatar_url:data.get("avatar_url")?.toString().trim()||""};
      try {
        const updated=await request("/api/v1/users/me",{method:"PATCH",body:JSON.stringify(payload)});
        state.user=updated.user||updated;
        renderUserIdentity(); renderFeaturePanel("settings"); bindFeatureForms();
        toast("Profile saved.");
      } catch(err) { if(error)error.textContent=err.message; toast("Profile update failed: "+err.message); }
    });
  }
  async function loadAdminSessions() {
    const data=await request("/api/v1/admin/sessions");
    state.sessions=data.sessions||[];
    renderSessions();
  }
  async function revokeAdminSession(id) {
    if(!id)return toast("Missing session ID.");
    if(!window.confirm("Revoke this user's session? This immediately signs that session out."))return;
    try {
      await request("/api/v1/admin/sessions/"+encodeURIComponent(id),{method:"DELETE"});
      state.sessions=state.sessions.filter(s=>String(s.id)!==String(id));
      renderSessions(); toast("Session revoked.");
    } catch(err) { toast("Session revocation failed: "+err.message); }
  }
  async function loadAdminSessions() {
    const data=await request("/api/v1/admin/sessions");
    state.sessions=data.sessions||[];renderSessions();
  }
  async function revokeAdminSession(id) {
    if(!id)return toast("Missing session ID.");
    if(!window.confirm("Revoke this user's session? This immediately signs that session out."))return;
    try{await request("/api/v1/admin/sessions/"+encodeURIComponent(id),{method:"DELETE"});state.sessions=state.sessions.filter(x=>String(x.id)!==String(id));renderSessions();toast("Session revoked.");}
    catch(err){toast("Session revocation failed: "+err.message);}
  }
  async function runFeatureAction(action) {
    try {
      if(action==="mfa-setup"){state.mfaSetup=await request("/api/v1/mfa/setup",{method:"POST",body:"{}"});const st=await request("/api/v1/mfa/status");state.mfa={enabled:!!st.enabled,configured:!!st.configured};renderFeaturePanel("mfa");bindFeatureForms();}
      else if(action==="mfa-refresh"){const st=await request("/api/v1/mfa/status");state.mfa={enabled:!!st.enabled,configured:!!st.configured};renderFeaturePanel("mfa");bindFeatureForms();}
      else if(action==="logout"){await logoutSession();}
      else if(action==="refresh-health"){await loadLiveData();renderFeaturePanel("security");}
      else if(action==="oauth-google"||action==="oauth-github"){const provider=action==="oauth-google"?"google":"github";window.open(state.base+"/api/v1/oauth/"+provider+"/login","_blank","noopener,noreferrer");}
    }catch(err){toast(err.message||"Action failed.");}
  }
  function setPage(p){
    const [t,sub]=titles[p]||titles.overview;
    $("#pageTitle").textContent=t; $("#pageSubtitle").textContent=sub;
    $$(".nav-item").forEach(b=>b.classList.toggle("active",b.dataset.page===p));
    const overview=p==="overview";
    [$(".metrics-grid"),$(".overview-grid"),$(".tables-grid"),$(".bottom-grid")].forEach(el=>{if(el)el.hidden=!overview;});
    const live=$(".live-data-tables"); if(live){live.hidden=overview;live.querySelectorAll("article").forEach(article=>{const h=article.querySelector("h2")?.textContent||"";article.hidden=!(p==="sessions"&&h==="Active Sessions"||p==="audit"&&h==="Live Audit Events"||p==="roles"&&(h==="Backend Roles"||h==="Backend Permissions"));});}
    const feature=$("#featurePanel"); if(feature){feature.hidden=overview||["roles","sessions","audit"].includes(p);if(!feature.hidden){renderFeaturePanel(p);bindFeatureForms();}}
    if(p==="users"&&state.accessToken)toast(state.users.length+" users loaded from API.");
    else if(p==="roles"&&state.accessToken)toast((state.rolesData?.length||0)+" roles loaded from API.");
    else if(p==="sessions"&&state.accessToken)toast(state.sessions.length+" sessions loaded from API.");
    else if(p==="audit"&&state.accessToken)toast(state.audit.length+" audit events loaded.");
    else if(p!=="overview"&&!state.accessToken)toast(t+" — connect the API to load live data");
  }
  function addDataTables(){
    const tableSection=document.createElement("section");tableSection.className="tables-grid live-data-tables";
    tableSection.innerHTML='<article class="panel table-panel"><div class="panel-head"><div><h2>Active Sessions</h2><p>Sessions visible to the signed-in identity.</p></div><button class="text-btn" data-action="revoke-current-session">Revoke current session</button></div><div class="table-wrap"><table><thead><tr><th>SESSION</th><th>DEVICE</th><th>IP ADDRESS</th><th>CREATED</th><th>STATUS</th></tr></thead><tbody id="sessionsTable"><tr><td colspan="5">Connect to load sessions.</td></tr></tbody></table></div></article><article class="panel table-panel"><div class="panel-head"><div><h2>Live Audit Events</h2><p>Latest audit records returned by the backend.</p></div></div><div class="table-wrap"><table><thead><tr><th>TIME</th><th>ACTION</th><th>ACTOR / USER</th><th>IP ADDRESS</th><th>STATUS</th></tr></thead><tbody id="auditTable"><tr><td colspan="5">Connect to load audit events.</td></tr></tbody></table></div></article><article class="panel table-panel"><div class="panel-head"><div><h2>Backend Roles</h2><p>Actual role definitions from PostgreSQL.</p></div></div><div class="table-wrap"><table><thead><tr><th>ROLE</th><th>DESCRIPTION</th><th>CREATED</th></tr></thead><tbody id="rolesTable"><tr><td colspan="3">Connect as an administrator.</td></tr></tbody></table></div></article><article class="panel table-panel"><div class="panel-head"><div><h2>Backend Permissions</h2><p>Actual permission catalogue from PostgreSQL.</p></div></div><div class="table-wrap"><table><thead><tr><th>PERMISSION</th><th>RESOURCE</th><th>ACTION</th><th>DESCRIPTION</th></tr></thead><tbody id="permissionsTable"><tr><td colspan="4">Connect as an administrator.</td></tr></tbody></table></div></article>';
    $(".content").append(tableSection);
    const feature=document.createElement("section");feature.id="featurePanel";feature.className="feature-panel";feature.hidden=true;
    feature.innerHTML='<article class="panel" id="featureContent"></article>';
    $(".content").append(feature);
    feature.addEventListener("click",async e=>{
      const copyButton=e.target.closest("[data-copy-id]");
      if(copyButton){const input=$("#roleAssignmentForm input[name=\"user_id\"]");if(input)input.value=copyButton.dataset.copyId;try{await navigator.clipboard.writeText(copyButton.dataset.copyId);toast("User ID copied and filled in the role form.");}catch{toast("User ID filled in the role form.");}return;}
      const action=e.target.closest("[data-feature-action]")?.dataset.featureAction;
      if(!action)return;
      try{
        if(action==="mfa-setup"){state.mfaSetup=await request("/api/v1/mfa/setup",{method:"POST",body:"{}"});state.mfa=await request("/api/v1/mfa/status");renderFeaturePanel("mfa");}
        else if(action==="mfa-refresh"){state.mfa=await request("/api/v1/mfa/status");renderFeaturePanel("mfa");}
        else if(action==="refresh-health"){await request("/healthz");await request("/ready");const version=await request("/version");state.health={live:true,ready:true,version};renderFeaturePanel("security");}
        else if(action==="oauth-google"||action==="oauth-github"){if(!state.base)throw new Error("Connect API first.");window.location.assign(state.base+"/api/v1/oauth/"+(action==="oauth-google"?"google":"github")+"/login");}
        else if(action==="logout"){const options={method:"POST"};if(state.refreshToken)options.body=JSON.stringify({refresh_token:state.refreshToken});try{await request("/api/v1/auth/logout",options);}finally{disconnect();}}
      }catch(ex){toast(ex.message||"Action failed.");}
    });
    feature.addEventListener("submit",async e=>{
      e.preventDefault();const form=e.target;
      try{
        if(form.id==="profileForm"){
          const data=Object.fromEntries(new FormData(form));if(!data.avatar_url)delete data.avatar_url;const profile=await request("/api/v1/users/me",{method:"PATCH",body:JSON.stringify(data)});
          state.user=profile.user||profile;renderUserIdentity();toast("Profile saved.");renderFeaturePanel("settings");
        }else if(form.id==="mfaCodeForm"){
          const code=new FormData(form).get("code");const op=e.submitter?.value;
          await request("/api/v1/mfa/"+(op==="disable"?"disable":"enable"),{method:"POST",body:JSON.stringify({code})});
          state.mfa=await request("/api/v1/mfa/status");state.mfaSetup=null;renderFeaturePanel("mfa");toast(op==="disable"?"MFA disabled.":"MFA enabled.");
        }else if(form.id==="roleAssignmentForm"){
          const data=Object.fromEntries(new FormData(form));const op=e.submitter?.value;
          await request("/api/v1/admin/users/roles",{method:op==="remove"?"DELETE":"POST",body:JSON.stringify({user_id:data.user_id,role_name:data.role_name})});
          toast(op==="remove"?"Role revoked.":"Role assigned.");await loadLiveData();renderFeaturePanel("users");
        }
      }catch(ex){const err=form.querySelector(".form-error");if(err)err.textContent=ex.message;else toast(ex.message);}
    });


  }
  function buildChart(){const bars=[52,64,72,82,96,88,122,108,142,128,162,149,176,156,136,112,101,88,112,82,108,67],chart=$("#activityChart");if(!chart)return;bars.forEach(v=>{const b=document.createElement("div"),s=document.createElement("i"),f=document.createElement("i"),m=document.createElement("i");b.className="bar";s.className="s";f.className="f";m.className="m";s.style.height=Math.max(20,v)+"%";f.style.height=Math.max(5,v*.14)+"%";m.style.height=Math.max(7,v*.22)+"%";b.append(s,f,m);chart.appendChild(b);});}
  document.addEventListener("DOMContentLoaded",()=>{buildChart();addDataTables();setConnection(false);
    $$(".nav-item").forEach(b=>b.addEventListener("click",()=>setPage(b.dataset.page)));
    $$("[data-page-jump]").forEach(b=>b.addEventListener("click",()=>setPage(b.dataset.pageJump)));
    document.addEventListener("click",e=>{const revoke=e.target.closest("[data-revoke-session]");if(revoke){e.preventDefault();revokeAdminSession(revoke.dataset.revokeSession);}});
    $$("[data-action]").forEach(b=>b.addEventListener("click",()=>{const a=b.dataset.action;if(a==="docs")window.open("https://github.com/017Mehul/sentinel","_blank","noopener");else if(a==="add-user")toast("User creation endpoint is not exposed by the current API.");else if(a==="revoke-current-session")revokeCurrentSession();else setPage(a)}));
    $(".select-btn")?.addEventListener("click",()=>toast("Time range filtering is not exposed by the current API."));
    $(".profile-btn")?.addEventListener("click",()=>state.accessToken?disconnect():showConnectDialog());
    const search=$("#globalSearch");search?.addEventListener("keydown",e=>{if(e.key==="Enter"&&search.value.trim()){const q=search.value.trim().toLowerCase();const match=state.audit.find(a=>JSON.stringify(a).toLowerCase().includes(q));toast(match?"Matching audit event found: "+(match.action||"event"):"Search is limited to data currently loaded in this console.");}});
    document.addEventListener("keydown",e=>{if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==="k"){e.preventDefault();search?.focus();}});
    setPage("overview");
    if(state.base)toast("API URL configured. Select Connect API to sign in.");
  });
  window.SentinelConsole={connect:showConnectDialog,disconnect,refresh:loadLiveData,revokeCurrentSession,refreshAccessToken,logoutSession,loadAdminSessions,revokeAdminSession,searchAdminUsers};
})();