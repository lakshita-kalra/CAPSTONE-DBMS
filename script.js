

<script>
// ============================================================
//  STATE
// ============================================================
const S = {
  events:[], alerts:[], threats:[], vulns:[], mitigations:[],
  iocs:[], timeline:[],
  ec:0, alc:0, thc:0, vc:0, mc:0, resolved:0,
  surface:{ web:10, net:15, ep:8, id:5, cloud:12 },
  currentRole:'SOC Analyst', currentUser:'analyst@cyberwatch.io',
  sessionStart: new Date(),
  alertFilter:'ALL', vulnFilter:'ALL',
  loginTimes:[], resolveTimes:[],
};

// ============================================================
//  KNOWLEDGE BASE
// ============================================================
const KB = {
  alerts:{
    'Brute Force':       { type:'Authentication Storm',       sev:'HIGH',     rule:'RULE-BF-001', desc:'Multiple failed logins from single IP. Pattern matches credential stuffing.' },
    'SQL Injection':     { type:'SQL Injection Detected',     sev:'CRITICAL', rule:'RULE-WA-002', desc:'Malicious SQL in HTTP params. WAF evasion techniques observed.' },
    'XSS Attack':        { type:'Cross-Site Scripting',       sev:'HIGH',     rule:'RULE-WA-003', desc:'Reflected XSS in user input. Session hijack risk identified.' },
    'Port Scan':         { type:'Network Reconnaissance',     sev:'MEDIUM',   rule:'RULE-NW-004', desc:'Systematic port sweep. Pre-attack reconnaissance confirmed.' },
    'Malware Download':  { type:'Malicious Payload Download', sev:'CRITICAL', rule:'RULE-EP-005', desc:'Known malware hash matched. C2 channel established.' },
    'Ransomware':        { type:'Ransomware Execution',       sev:'CRITICAL', rule:'RULE-EP-006', desc:'Mass file encryption active. LockBit 3.0 signature confirmed.' },
    'Phishing':          { type:'Spear Phishing Detected',    sev:'HIGH',     rule:'RULE-EM-007', desc:'Credential harvesting page visited. Domain spoofing confirmed.' },
    'DDoS Attack':       { type:'DDoS Volumetric Flood',      sev:'HIGH',     rule:'RULE-NW-008', desc:'95Gbps inbound UDP flood. Scrubbing centre activated.' },
    'Privilege Escalation':{ type:'Privilege Escalation',     sev:'CRITICAL', rule:'RULE-ID-009', desc:'Escalation to SYSTEM via token impersonation exploit.' },
    'Data Exfiltration': { type:'Data Exfiltration Attempt',  sev:'CRITICAL', rule:'RULE-DLP-010', desc:'8.4GB outbound to external IP. DLP triggered.' },
    'Zero-Day Exploit':  { type:'Zero-Day Exploitation',      sev:'CRITICAL', rule:'RULE-ZD-011', desc:'Unknown exploit — no CVE match. Sandbox engaged.' },
    'Insider Threat':    { type:'Insider Threat Activity',    sev:'HIGH',     rule:'RULE-IT-012', desc:'Anomalous data access at 03:22 AM. Outside normal hours.' },
    'MITM Attack':       { type:'Man-in-the-Middle Attack',   sev:'HIGH',     rule:'RULE-NW-013', desc:'ARP spoofing detected. Traffic interception in progress.' },
    'Crypto-jacking':    { type:'Cryptomining Detected',      sev:'MEDIUM',   rule:'RULE-EP-014', desc:'Unauthorised CPU spike. Monero mining process identified.' },
    'Supply Chain Attack':{ type:'Supply Chain Compromise',   sev:'CRITICAL', rule:'RULE-SC-015', desc:'Tampered software package detected in CI/CD pipeline.' },
  },
  threats:{
    'Brute Force':       { name:'Credential Stuffing Campaign', actor:'Unknown Actor',        vec:'Network',  conf:72 },
    'SQL Injection':     { name:'Web App Compromise',           actor:'APT-29 (Cozy Bear)',   vec:'App',      conf:88 },
    'XSS Attack':        { name:'Session Hijacking Op',         actor:'FIN-7 Group',          vec:'App',      conf:65 },
    'Port Scan':         { name:'Infrastructure Recon',         actor:'Unknown',              vec:'Network',  conf:45 },
    'Malware Download':  { name:'Trojan Deployment',            actor:'Lazarus Group',        vec:'Endpoint', conf:91 },
    'Ransomware':        { name:'Ransomware Campaign',          actor:'LockBit 3.0',          vec:'Endpoint', conf:96 },
    'Phishing':          { name:'Spear Phishing Op',            actor:'APT-41',               vec:'Email',    conf:78 },
    'DDoS Attack':       { name:'DDoS Botnet Activation',       actor:'Killnet',              vec:'Network',  conf:83 },
    'Privilege Escalation':{ name:'Domain Takeover Attempt',   actor:'APT-28 (Fancy Bear)',  vec:'Identity', conf:89 },
    'Data Exfiltration': { name:'Corporate Espionage Op',       actor:'APT-10 (Stone Panda)', vec:'Data',     conf:85 },
    'Zero-Day Exploit':  { name:'Advanced Persistent Threat',   actor:'Nation-State Actor',   vec:'Endpoint', conf:94 },
    'Insider Threat':    { name:'Insider Data Theft',           actor:'Malicious Insider',    vec:'Internal', conf:70 },
    'MITM Attack':       { name:'Network Interception',         actor:'Unknown Actor',        vec:'Network',  conf:75 },
    'Crypto-jacking':    { name:'Cryptomining Botnet',          actor:'TeamTNT',              vec:'Endpoint', conf:68 },
    'Supply Chain Attack':{ name:'Supply Chain Infiltration',   actor:'SolarWinds-type APT',  vec:'Software', conf:92 },
  },
  vulns:{
    'SQL Injection':      { cve:'CVE-2024-1234', name:'SQL Injection in Login Module',   cvss:9.8, sys:'Web App v2.3.1',        patch:false },
    'XSS Attack':         { cve:'CVE-2024-5678', name:'Reflected XSS in Search Param',   cvss:7.4, sys:'Frontend v1.8.0',       patch:true  },
    'Malware Download':   { cve:'CVE-2024-9012', name:'RCE via Unpatched Service',        cvss:9.9, sys:'Windows Server 2019',    patch:false },
    'Ransomware':         { cve:'CVE-2023-4789', name:'EternalBlue SMB Vulnerability',    cvss:9.8, sys:'SMB Service v1',         patch:false },
    'Privilege Escalation':{ cve:'CVE-2024-21413', name:'Windows Kernel Token Exploit',  cvss:9.8, sys:'Windows 11 22H2',        patch:false },
    'Zero-Day Exploit':   { cve:'CVE-2024-XXXX', name:'Zero-Day — Under Analysis',        cvss:10.0,sys:'Core Infrastructure',    patch:false },
    'Data Exfiltration':  { cve:'CVE-2024-3344', name:'Insufficient Access Controls',    cvss:8.1, sys:'File Server v3.1',       patch:true  },
    'MITM Attack':        { cve:'CVE-2024-7890', name:'Weak TLS Configuration',          cvss:7.5, sys:'API Gateway v2.0',       patch:true  },
    'Supply Chain Attack':{ cve:'CVE-2024-8811', name:'Dependency Confusion Attack',      cvss:9.0, sys:'CI/CD Pipeline',         patch:false },
  },
  mitigations:{
    'Brute Force':       [['Block source IP at firewall','R. Mehta',3,'CONTAIN'],['Enable account lockout','S. Park',4,'HARDEN'],['Enforce MFA all accounts','L. Nguyen',5,'PREVENT']],
    'SQL Injection':     [['Deploy WAF SQLi rules','T. Okafor',3,'DETECT'],['Patch vulnerable endpoint','A. Kumar',6,'PATCH'],['Audit input validation','R. Mehta',4,'HARDEN']],
    'Ransomware':        [['Isolate infected hosts','R. Mehta',2,'CONTAIN'],['Kill malicious processes','T. Okafor',3,'ERADICATE'],['Restore from backup','L. Nguyen',5,'RECOVER'],['Apply SMB patches','A. Kumar',4,'PATCH']],
    'Malware Download':  [['Quarantine endpoint','S. Park',2,'CONTAIN'],['Block C2 IP perimeter','R. Mehta',3,'CONTAIN'],['Full AV scan all hosts','T. Okafor',4,'DETECT']],
    'Privilege Escalation':[['Revoke elevated permissions','S. Park',3,'CONTAIN'],['Reset compromised creds','L. Nguyen',4,'ERADICATE'],['Deploy kernel patch','A. Kumar',5,'PATCH']],
    'DDoS Attack':       [['Activate DDoS scrubbing','R. Mehta',2,'CONTAIN'],['Rate-limit ingress traffic','T. Okafor',3,'CONTAIN']],
    'Data Exfiltration': [['Block outbound connection','R. Mehta',2,'CONTAIN'],['Forensic capture session','A. Kumar',4,'DETECT'],['Notify DPO — GDPR review','Compliance',3,'REPORT']],
    'Zero-Day Exploit':  [['Emergency isolation','R. Mehta',2,'CONTAIN'],['Submit to sandbox','T. Okafor',4,'ANALYZE'],['Contact vendor','L. Nguyen',3,'PATCH']],
    'Phishing':          [['Block phishing domain','T. Okafor',2,'CONTAIN'],['Force password reset','S. Park',3,'ERADICATE'],['User awareness alert','Compliance',2,'PREVENT']],
    'MITM Attack':       [['Revoke compromised certs','A. Kumar',3,'CONTAIN'],['Re-key TLS endpoints','L. Nguyen',4,'HARDEN']],
    'Supply Chain Attack':[['Quarantine affected packages','R. Mehta',3,'CONTAIN'],['Audit all dependencies','A. Kumar',5,'ANALYZE'],['Rebuild CI pipeline','T. Okafor',6,'RECOVER']],
    'Insider Threat':    [['Revoke user access','S. Park',2,'CONTAIN'],['Preserve evidence','A. Kumar',4,'DETECT'],['HR + Legal notification','Compliance',3,'REPORT']],
    'Crypto-jacking':    [['Kill mining process','T. Okafor',2,'CONTAIN'],['Remove persistence','R. Mehta',3,'ERADICATE']],
  },
  iocs:{
    'Brute Force':       [['IP',''],[  'USR','admin,root,administrator']],
    'SQL Injection':     [['IP',''],[  'URL',"/api/login?id=1 OR 1=1--"],['HASH','a3f4...9c2d']],
    'Malware Download':  [['IP',''],[  'HASH','bd7c...3a1f (SHA256)'],['URL','c2srv[.]ru/payload.exe']],
    'Ransomware':        [['IP',''],[  'HASH','e5ab...7f9c (LockBit)'],['EXT','.lockbit .encrypted']],
    'Zero-Day Exploit':  [['IP',''],[  'HASH','UNKNOWN — analysis pending'],['SIG','ZD-YARA-2024-001']],
    'DDoS Attack':       [['ASN','AS14061 AS16276'],['PROTO','UDP/53 TCP/80 TCP/443']],
    'MITM Attack':       [['IP',''],[  'MAC','SPOOFED 00:1A:2B:3C'],['CERT','Invalid TLS cert detected']],
    'Supply Chain Attack':[['PKG','compromised-lib v2.1.3'],['HASH','9f8c...2a1b'],['REPO','npm registry injection']],
  },
  nodeMap:{ 'Web Server':'nn-web','Database':'nn-db','Auth Server':'nn-auth','Domain Controller':'nn-dc','Workstation':'nn-ws','Firewall':'nn-fw','File Server':'nn-db','Email Gateway':'nn-web','VPN Server':'nn-fw','Cloud Storage':'nn-db' },
  surface:{
    'SQL Injection':{ web:35 },'XSS Attack':{ web:28 },'DDoS Attack':{ net:50 },'Port Scan':{ net:32 },
    'Brute Force':{ id:40 },'Privilege Escalation':{ id:65 },'Malware Download':{ ep:50 },'Ransomware':{ ep:75 },
    'Data Exfiltration':{ net:40, ep:32 },'Zero-Day Exploit':{ ep:85, net:55 },'Phishing':{ id:45 },
    'Insider Threat':{ id:55 },'MITM Attack':{ net:45 },'Crypto-jacking':{ ep:40 },'Supply Chain Attack':{ ep:60, net:40 }
  },
};

// ============================================================
//  HELPERS
// ============================================================
const $$    = id => document.getElementById(id);
const el    = (tag,cls='',html='') => { const e=document.createElement(tag); if(cls)e.className=cls; if(html)e.innerHTML=html; return e; };
const now   = () => new Date().toISOString().replace('T',' ').slice(0,19);
const nowT  = () => new Date().toTimeString().slice(0,8);
const uid   = () => Math.random().toString(36).slice(2,8).toUpperCase();
const delay = ms => new Promise(r=>setTimeout(r,ms));
const cvssToSev = s => s>=9?'CRITICAL':s>=7?'HIGH':s>=4?'MEDIUM':'LOW';

// ============================================================
//  LOADING SCREEN
// ============================================================
const msgs = ['INITIALIZING SECURITY ENGINES...','LOADING THREAT INTELLIGENCE...','CONNECTING TO SIEM PLATFORM...','SYNCING 40+ IOC FEEDS...','CALIBRATING DETECTION RULES...','READY.'];
let loadProgress = 0;
const loadInterval = setInterval(()=>{
  loadProgress += Math.random()*22;
  if(loadProgress>=100){ loadProgress=100; clearInterval(loadInterval);
    setTimeout(()=>$$('loading-screen').classList.add('hide'),400);
  }
  $$('load-bar').style.width = loadProgress+'%';
  $$('load-msg').textContent = msgs[Math.min(Math.floor(loadProgress/20), msgs.length-1)];
}, 200);

// ============================================================
//  PARTICLE CANVAS
// ============================================================
const pc = $$('particle-canvas');
const ctx2 = pc?.getContext('2d');
let particles = [];

function initParticles(){
  if(!pc||!ctx2) return;
  pc.width = window.innerWidth; pc.height = window.innerHeight;
  particles = Array.from({length:60},()=>({
    x:Math.random()*pc.width, y:Math.random()*pc.height,
    vx:(Math.random()-.5)*.4, vy:(Math.random()-.5)*.4,
    r:Math.random()*1.5+.5,
    a:Math.random()*.5+.1
  }));
}

function drawParticles(){
  if(!ctx2) return;
  ctx2.clearRect(0,0,pc.width,pc.height);
  particles.forEach(p=>{
    p.x+=p.vx; p.y+=p.vy;
    if(p.x<0||p.x>pc.width)  p.vx*=-1;
    if(p.y<0||p.y>pc.height) p.vy*=-1;
    ctx2.beginPath();
    ctx2.arc(p.x,p.y,p.r,0,Math.PI*2);
    ctx2.fillStyle=`rgba(0,255,136,${p.a})`;
    ctx2.fill();
    // Draw lines to nearby particles
    particles.forEach(q=>{
      const d=Math.hypot(p.x-q.x,p.y-q.y);
      if(d<100){
        ctx2.beginPath();
        ctx2.moveTo(p.x,p.y); ctx2.lineTo(q.x,q.y);
        ctx2.strokeStyle=`rgba(0,255,136,${0.04*(1-d/100)})`;
        ctx2.stroke();
      }
    });
  });
  requestAnimationFrame(drawParticles);
}

// Live counter animation on login page
function animateLoginCounters(){
  let e=0,b=0;
  const iv=setInterval(()=>{
    e+=Math.floor(Math.random()*50)+10;
    b+=Math.floor(Math.random()*8)+2;
    $$('ls-events') && ($$('ls-events').textContent=e.toLocaleString());
    $$('ls-blocked') && ($$('ls-blocked').textContent=b.toLocaleString());
    if(e>12000) clearInterval(iv);
  },80);
}

window.onload = ()=>{ initParticles(); drawParticles(); animateLoginCounters(); };
window.onresize = initParticles;

// ============================================================
//  LOGIN
// ============================================================
let selectedRole = 'SOC Analyst';

function selectRole(btn, role){
  document.querySelectorAll('.role-btn').forEach(b=>b.classList.remove('selected'));
  btn.classList.add('selected');
  selectedRole = role;
}

function toggle2FA(){
  const t=$$('twofa-toggle');
  t.classList.toggle('on');
}

function autofill(){
  $$('login-user').value='analyst@cyberwatch.io';
  $$('login-pass').value='CyberWatch@2024';
  setTimeout(doLogin,300);
}

function doLogin(){
  const user=$$('login-user').value.trim();
  const pass=$$('login-pass').value.trim();
  if(!user||!pass){ toast('Error','Please enter credentials','danger'); return; }

  const btn=$$('login-btn');
  btn.textContent='AUTHENTICATING...';
  btn.disabled=true;

  setTimeout(()=>{
    S.currentUser = user;
    S.currentRole = selectedRole;
    S.sessionStart = new Date();

    // Update UI
    $$('user-name').textContent = S.currentRole;
    $$('user-avatar').textContent = S.currentRole.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
    $$('set-user').textContent = S.currentUser;
    $$('set-role').textContent = S.currentRole;
    $$('set-time').textContent = S.sessionStart.toTimeString().slice(0,8);

    // Switch pages
    $$('login-page').classList.remove('active');
    $$('app-page').classList.add('active');
    drawNetLines();
    alog(`[SYSTEM] ${S.currentRole} logged in — ${S.currentUser}`, 'var(--accent)');
    alog('[SYSTEM] All detection engines ONLINE', 'var(--text2)');
    alog('[SYSTEM] Threat feeds connected — 24,847 IOCs loaded', 'var(--text2)');
    toast('Access Granted',`Welcome, ${S.currentRole} • Session started`,'success');

    btn.textContent='AUTHENTICATE →';
    btn.disabled=false;
  }, 1400);
}

function doLogout(){
  $$('app-page').classList.remove('active');
  $$('login-page').classList.add('active');
  toast('Logged Out','Session terminated securely','info');
}

// ============================================================
//  NAV
// ============================================================
function switchView(name, btn){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.tb-nav-btn').forEach(b=>b.classList.remove('active'));
  $$('view-'+name).classList.add('active');
  if(btn) btn.classList.add('active');
  if(name==='reports') updateReports();
}

// ============================================================
//  TOAST
// ============================================================
function toast(title, msg, type='success', dur=4000){
  const zone=$$('toast-zone');
  const t=el('div','toast-item '+type);
  t.innerHTML=`<div class="ti-title">${title}</div><div class="ti-msg">${msg}</div>`;
  zone.appendChild(t);
  setTimeout(()=>{ t.style.cssText='opacity:0;transform:translateX(16px);transition:.3s'; setTimeout(()=>t.remove(),300); }, dur);
}

// ============================================================
//  ANALYST LOG
// ============================================================
function alog(msg, color='var(--text2)'){
  const log=$$('analyst-log');
  const d=el('div','alog-line');
  d.style.color=color;
  d.textContent=`[${nowT()}] ${msg}`;
  log.prepend(d);
  // Keep log trim
  while(log.children.length>50) log.removeChild(log.lastChild);
}

// ============================================================
//  STATS UPDATE
// ============================================================
function updateStats(){
  const crit = S.alerts.filter(a=>a.sev==='CRITICAL'&&a.status!=='RESOLVED').length;
  const openA = S.alerts.filter(a=>a.status!=='RESOLVED').length;
  const actT  = S.threats.filter(t=>t.status==='ACTIVE').length;
  const openV = S.vulns.filter(v=>!v.patched).length;

  $$('sc-critical').textContent=crit;
  $$('sc-alerts').textContent=openA;
  $$('sc-threats').textContent=actT;
  $$('sc-vulns').textContent=openV;
  $$('sc-resolved').textContent=S.resolved;
  $$('sc-events').textContent=S.events.length;
  $$('event-count').textContent=S.events.length;

  // Nav badges
  setNB('nb-events', S.events.length);
  setNB('nb-alerts', openA);
  setNB('nb-threats', actT);
  setNB('nb-vulns', openV);

  // Labels
  $$('alert-count-lbl').textContent=openA;
  $$('vuln-count-lbl').textContent=openV;

  // MTTR
  if(S.resolveTimes.length>0){
    const avg = S.resolveTimes.reduce((a,b)=>a+b,0)/S.resolveTimes.length;
    $$('sc-mttr').textContent=avg.toFixed(1)+'m';
  }

  // Avg risk
  if(S.vulns.length>0){
    const avg = S.vulns.reduce((a,v)=>a+v.cvss,0)/S.vulns.length;
    $$('sc-risk').textContent=avg.toFixed(1)+'/10';
  }

  // Threat meter
  const tm=$$('threat-meter'), tmt=$$('tm-text'), tmd=$$('tm-dot');
  if(crit>=3){
    tm.style.cssText='border-color:rgba(255,34,68,.4);background:rgba(255,34,68,.08)';
    tmt.style.color='var(--red)'; tmt.textContent='CRITICAL ALERT'; tmd.style.background='var(--red)';
  } else if(actT>=2){
    tm.style.cssText='border-color:rgba(255,102,0,.4);background:rgba(255,102,0,.08)';
    tmt.style.color='var(--orange)'; tmt.textContent='HIGH THREAT'; tmd.style.background='var(--orange)';
  } else if(openA>=1){
    tm.style.cssText='border-color:rgba(255,204,0,.3);background:rgba(255,204,0,.06)';
    tmt.style.color='var(--yellow)'; tmt.textContent='ELEVATED'; tmd.style.background='var(--yellow)';
  } else {
    tm.style.cssText='border-color:rgba(0,255,136,.3);background:rgba(0,255,136,.06)';
    tmt.style.color='var(--accent)'; tmt.textContent='MONITORING'; tmd.style.background='var(--accent)';
  }
}

function setNB(id, n){
  const e=$$('nb-'+id.replace('nb-',''));
  if(!e) return;
  const nb=$$( id );
  if(!nb) return;
  nb.textContent=n; nb.className='nav-badge'+(n>0?' show':'');
}

// ============================================================
//  NETWORK MAP
// ============================================================
function drawNetLines(){
  const svg=$$('net-svg');
  if(!svg) return;
  svg.innerHTML='';
  const links=[['nn-fw','nn-web'],['nn-fw','nn-db'],['nn-fw','nn-ws'],['nn-web','nn-auth'],['nn-web','nn-ws'],['nn-db','nn-dc'],['nn-auth','nn-dc']];
  links.forEach(([a,b])=>{
    const na=$$( a ), nb=$$( b );
    if(!na||!nb) return;
    const ax=parseInt(na.style.left)+17, ay=parseInt(na.style.top)+17;
    const bx=parseInt(nb.style.left)+17, by=parseInt(nb.style.top)+17;
    const line=document.createElementNS('http://www.w3.org/2000/svg','line');
    line.setAttribute('x1',ax); line.setAttribute('y1',ay);
    line.setAttribute('x2',bx); line.setAttribute('y2',by);
    line.setAttribute('stroke','#1a2d45'); line.setAttribute('stroke-width','1');
    svg.appendChild(line);
  });
}

function setNode(sys, status){
  const id=KB.nodeMap[sys]; if(!id) return;
  const n=$$(id); if(!n) return;
  n.className='nnode '+status;
}

// ============================================================
//  IOC UPDATE
// ============================================================
function updateIOC(type, srcIP){
  const tpls=KB.iocs[type]||[['IP',srcIP]];
  const newIOCs=tpls.map(([t,v])=>[t, t==='IP'?srcIP:v]);
  newIOCs.forEach(ioc=>{ if(!S.iocs.find(x=>x[1]===ioc[1])) S.iocs.unshift(ioc); });
  S.iocs=S.iocs.slice(0,15);
  const list=$$('ioc-list');
  list.innerHTML=S.iocs.map(([t,v])=>`
    <div class="ioc-row">
      <span class="ioc-type">${t}</span>
      <span class="ioc-val" title="${v}">${v||'—'}</span>
      <span class="badge ACTIVE" style="font-size:8px;padding:1px 5px">HOT</span>
    </div>`).join('');
}

// ============================================================
//  ATTACK SURFACE
// ============================================================
function updateSurface(type){
  const d=KB.surface[type]||{};
  Object.entries(d).forEach(([k,v])=>{ S.surface[k]=Math.min(95,Math.max(S.surface[k],v)); });
  ['web','net','ep','id','cloud'].forEach(k=>{
    const val=S.surface[k];
    const fill=$$('as-'+k), pct=$$('asp-'+k);
    if(!fill||!pct) return;
    fill.style.width=val+'%';
    pct.textContent=val+'%';
    fill.style.background=val>=60?'var(--red)':val>=40?'var(--orange)':val>=25?'var(--yellow)':val>=15?'var(--blue)':'var(--accent)';
  });
}

// ============================================================
//  CORE: INJECT EVENT
// ============================================================
async function injectEvent(){
  const type=$$('ev-type').value;
  const sev=$$('ev-severity').value;
  const src=$$('ev-src').value||'185.220.101.'+Math.floor(Math.random()*254+1);
  const target=$$('ev-target').value;
  const desc=$$('ev-desc').value||`${type} detected from ${src}`;

  S.ec++;
  const evt={ id:uid(), seq:S.ec, type, sev, src, target, desc, ts:now(), status:'OPEN' };
  S.events.unshift(evt);

  renderFeedRow(evt);
  renderFeedRowFull(evt);
  updateIOC(type, src);
  updateSurface(type);
  setNode(target, sev==='CRITICAL'?'critical':sev==='HIGH'?'danger':sev==='MEDIUM'?'warn':'safe');
  alog(`📥 EVT-${S.ec}: ${type} from ${src} → ${target}`, 'var(--text2)');
  toast(`New Event Detected`,`${type} from ${src}`,'success');

  await delay(700);  triggerAlert(evt);
  await delay(500);  identifyThreat(evt);
  if(KB.vulns[type]){ await delay(400); discoverVuln(evt); }
  if(KB.mitigations[type]){ await delay(900); createMitigations(evt); }

  updateStats();
}

// ============================================================
//  RENDER FEED ROW
// ============================================================
function renderFeedRow(evt){
  const feed=$$('event-feed');
  const empty=feed.querySelector('.empty'); if(empty) empty.remove();
  const row=el('div','feed-row');
  row.innerHTML=`
    <span class="fr-time">${evt.ts.slice(11,19)}</span>
    <span class="fr-type">${evt.type}</span>
    <span class="fr-ip">${evt.src}</span>
    <span class="fr-desc">${evt.desc}</span>
    <span class="fr-ip">${evt.target}</span>
    <span><span class="badge ${evt.sev}">${evt.sev}</span></span>`;
  row.onclick=()=>showEventModal(evt);
  feed.prepend(row);
  while(feed.children.length>60) feed.removeChild(feed.lastChild);
}

function renderFeedRowFull(evt){
  const list=$$('events-full-list');
  const empty=list.querySelector('.empty'); if(empty) empty.remove();
  const row=el('div','feed-row');
  row.innerHTML=`
    <span class="fr-time">${evt.ts.slice(11,19)}</span>
    <span class="fr-type">${evt.type}</span>
    <span class="fr-ip">${evt.src}</span>
    <span class="fr-desc">${evt.desc}</span>
    <span class="fr-ip">${evt.target}</span>
    <span><span class="badge ${evt.sev}">${evt.sev}</span></span>`;
  row.onclick=()=>showEventModal(evt);
  list.prepend(row);
}

// ============================================================
//  ALERT
// ============================================================
function triggerAlert(evt){
  const t=KB.alerts[evt.type]; if(!t) return;
  S.alc++;
  const a={ id:uid(), seq:S.alc, type:t.type, sev:t.sev||evt.sev, rule:t.rule, desc:t.desc,
             src:evt.src, target:evt.target, evtId:evt.seq, ts:nowT(), status:'ACTIVE', created:Date.now() };
  S.alerts.unshift(a);
  renderAlert(a);
  addDashAlert(a);
  addTimeline(`ALERT: ${a.type}`, a.desc, a.sev);
  alog(`🔔 ALERT: ${a.type} [${a.sev}] — ${a.rule}`, 'var(--orange)');
  toast(`🚨 ALERT: ${a.type}`,`${a.rule} • ${a.sev}`,'danger',5000);
  if(a.sev==='CRITICAL') switchView('alerts', document.querySelector('.tb-nav-btn:nth-child(3)'));
}

function renderAlert(a, prepend=true){
  const list=$$('alerts-list');
  const empty=list.querySelector('.empty'); if(empty) empty.remove();
  const c=el('div',`alert-card ${a.sev}`);
  c.id=`alc-${a.id}`;
  c.innerHTML=`
    <div class="ac-header">
      <span class="ac-id">ALT-${a.seq}</span>
      <span class="ac-type">${a.type}</span>
      <span class="badge ${a.sev}">${a.sev}</span>
      <span class="ac-time">${a.ts}</span>
      <span class="badge ${a.status}">${a.status}</span>
    </div>
    <div class="ac-meta">
      <span>📍 ${a.src}</span><span>🎯 ${a.target}</span><span>🔖 ${a.rule}</span>
    </div>
    <div class="ac-desc">${a.desc}</div>
    <div class="ac-actions">
      <button class="btn sm primary" onclick="ackAlert('${a.id}')">✓ Acknowledge</button>
      <button class="btn sm info" onclick="showAlertModal('${a.id}')">🔍 Investigate</button>
      <button class="btn sm warn" onclick="escalateAlert('${a.id}')">⬆ Escalate</button>
      <button class="btn sm danger" onclick="resolveAlert('${a.id}')">✗ Resolve</button>
    </div>`;
  c.onclick=e=>{ if(e.target.tagName!=='BUTTON') showAlertModal(a.id); };
  if(prepend) list.prepend(c); else list.appendChild(c);
}

function addDashAlert(a){
  const list=$$('dash-alerts-list');
  const empty=list.querySelector('.empty'); if(empty) empty.remove();
  const c=el('div',`alert-card ${a.sev}`);
  c.style.cssText='margin-bottom:8px;cursor:pointer';
  c.innerHTML=`<div class="ac-header"><span class="ac-id">ALT-${a.seq}</span><span class="ac-type">${a.type}</span><span class="badge ${a.sev}">${a.sev}</span><span class="ac-time">${a.ts}</span></div>`;
  c.onclick=()=>switchView('alerts', null);
  list.prepend(c);
  while(list.children.length>5) list.removeChild(list.lastChild);
}

// Alert actions
function ackAlert(id){
  const a=S.alerts.find(x=>x.id===id); if(!a) return;
  a.status='MITIGATING';
  const c=$$(`alc-${id}`); if(c){ const b=c.querySelector('.badge[class*="ACTIVE"]'); if(b){ b.textContent='MITIGATING'; b.className='badge MITIGATING'; } }
  alog('✓ Alert acknowledged'); toast('Alert Acknowledged','Working on mitigation...','info'); updateStats();
}

function escalateAlert(id){
  const a=S.alerts.find(x=>x.id===id); if(!a) return;
  a.sev='CRITICAL';
  const c=$$(`alc-${id}`); if(c){ c.className='alert-card CRITICAL'; c.style.borderLeftColor='var(--red)'; }
  alog('⬆ Alert escalated to CRITICAL','var(--red)'); toast('Escalated','Tier 2 notified via PagerDuty','danger'); updateStats();
}

function resolveAlert(id){
  const a=S.alerts.find(x=>x.id===id); if(!a||a.status==='RESOLVED') return;
  const elapsed=(Date.now()-a.created)/60000;
  S.resolveTimes.push(elapsed);
  a.status='RESOLVED'; S.resolved++;
  const c=$$(`alc-${id}`); if(c){ c.className='alert-card RESOLVED'; c.querySelectorAll('.badge').forEach(b=>{ if(['ACTIVE','MITIGATING'].includes(b.textContent)){ b.textContent='RESOLVED'; b.className='badge RESOLVED'; } }); }
  setNode(a.target,'safe');
  alog('✅ Alert resolved','var(--purple)'); toast('Resolved','Incident closed','success'); updateStats();
}

function acknowledgeAll(){
  S.alerts.filter(a=>a.status==='ACTIVE').forEach(a=>ackAlert(a.id));
  toast('Bulk Action','All open alerts acknowledged','info');
}

function filterAlerts(f){
  S.alertFilter=f;
  const list=$$('alerts-list'); list.innerHTML='';
  const filtered=f==='ALL'?S.alerts:S.alerts.filter(a=>a.sev===f||a.status===f);
  if(filtered.length===0){ list.innerHTML='<div class="empty"><div class="empty-icon">🔔</div>No alerts match filter</div>'; return; }
  filtered.forEach(a=>renderAlert(a, true));
}

// ============================================================
//  THREAT
// ============================================================
function identifyThreat(evt){
  const t=KB.threats[evt.type]; if(!t) return;
  S.thc++;
  const th={ id:uid(), seq:S.thc, name:t.name, actor:t.actor, vec:t.vec, conf:Math.min(99,t.conf+Math.floor(Math.random()*6)),
              evtId:evt.seq, status:'ACTIVE', ts:now() };
  S.threats.unshift(th);
  renderThreat(th);
  addTimeline(`THREAT: ${th.name}`, `Actor: ${th.actor} | Confidence: ${th.conf}%`, 'HIGH');
  alog(`🎯 Threat: ${th.name} — ${th.actor}`, 'var(--red)');
  toast('Threat Identified',`${th.actor} — ${th.name}`,'warning',5000);
}

function renderThreat(th){
  const list=$$('threats-list');
  const empty=list.querySelector('.empty'); if(empty) empty.remove();
  const c=el('div','threat-card');
  c.id=`thc-${th.id}`;
  c.innerHTML=`
    <div class="tc-header">
      <div><div class="tc-name">🎯 ${th.name}</div><div class="tc-actor">Actor: ${th.actor}</div></div>
      <span class="badge ${th.status}">${th.status}</span>
    </div>
    <div class="tc-meta">
      <div class="tc-chip">Vector: <span>${th.vec}</span></div>
      <div class="tc-chip">Conf: <span>${th.conf}%</span></div>
      <div class="tc-chip">EVT-<span>${th.evtId}</span></div>
      <div class="tc-chip">THR-<span>${th.seq}</span></div>
    </div>
    <div class="confidence-bar">
      <div class="cb-label"><span>Threat Confidence</span><span id="conf-${th.id}">${th.conf}%</span></div>
      <div class="cb-track"><div class="cb-fill" id="cfill-${th.id}" style="width:${th.conf}%"></div></div>
    </div>
    <div class="tc-actions">
      <button class="btn sm info" onclick="analyzeThreat('${th.id}')">🔬 Analyze</button>
      <button class="btn sm warn" onclick="containThreat('${th.id}')">🔒 Contain</button>
      <button class="btn sm danger" onclick="neutralizeThreat('${th.id}')">💀 Neutralize</button>
      <button class="btn sm purple" onclick="showThreatModal('${th.id}')">📊 Details</button>
    </div>`;
  list.prepend(c);
}

function analyzeThreat(id){
  const th=S.threats.find(t=>t.id===id); if(!th) return;
  th.conf=Math.min(99,th.conf+5);
  $$(`conf-${id}`).textContent=th.conf+'%';
  $$(`cfill-${id}`).style.width=th.conf+'%';
  alog(`🔬 Analysis complete — confidence ${th.conf}%`,'var(--blue)'); toast('Analysis','Threat confidence updated','info');
}

function containThreat(id){
  const th=S.threats.find(t=>t.id===id); if(!th) return;
  th.status='CONTAINED';
  const c=$$(`thc-${id}`); if(c){ const b=c.querySelector('.badge.ACTIVE'); if(b){ b.textContent='CONTAINED'; b.className='badge CONTAINED'; } }
  alog('🔒 Threat contained','var(--yellow)'); toast('Contained','Threat actor blocked','success'); updateStats();
}

function neutralizeThreat(id){
  const th=S.threats.find(t=>t.id===id); if(!th) return;
  th.status='RESOLVED'; S.resolved++;
  const c=$$(`thc-${id}`); if(c){ c.querySelectorAll('.badge').forEach(b=>{ if(b.textContent!=='RESOLVED'){ b.textContent='RESOLVED'; b.className='badge RESOLVED'; } }); c.style.opacity='.5'; }
  alog(`💀 Threat neutralized: ${th.actor}`,'var(--accent)'); toast('Neutralized',`${th.actor} blocked`,'success'); updateStats();
}

// ============================================================
//  VULNERABILITY
// ============================================================
function discoverVuln(evt){
  const t=KB.vulns[evt.type]; if(!t||S.vulns.find(v=>v.cve===t.cve)) return;
  S.vc++;
  const v={ id:uid(), seq:S.vc, ...t, patched:false, ts:now() };
  S.vulns.unshift(v);
  renderVuln(v);
  addTimeline(`VULN: ${t.cve}`, `${t.name} — CVSS ${t.cvss}`, t.cvss>=9?'CRITICAL':'HIGH');
  alog(`🔓 Vuln: ${t.cve} CVSS ${t.cvss} — ${t.name}`,'var(--yellow)');
  toast('Vulnerability',`${t.cve} • CVSS ${t.cvss}`,'warning');
}

function renderVuln(v){
  const list=$$('vulns-list');
  const empty=list.querySelector('.empty'); if(empty) empty.remove();
  const sev=cvssToSev(v.cvss);
  const c=el('div','vuln-card');
  c.id=`vc-${v.id}`;
  c.innerHTML=`
    <div class="cvss-ring ${sev}">${v.cvss}</div>
    <div>
      <div class="vi-cve">${v.cve}</div>
      <div class="vi-name">${v.name}</div>
      <div class="vi-system">${v.sys}</div>
      <div style="margin-top:4px;display:flex;gap:4px">
        <span class="badge ${sev}">${sev}</span>
        ${v.patch?'<span class="badge RESOLVED">PATCH AVAIL</span>':'<span class="badge ACTIVE">NO PATCH</span>'}
      </div>
    </div>
    <div class="vc-actions">
      <button class="btn sm primary" onclick="patchVuln('${v.id}')">🔧 Patch</button>
      <button class="btn sm info" onclick="showVulnModal('${v.id}')">📊 Details</button>
    </div>`;
  c.onclick=e=>{ if(e.target.tagName!=='BUTTON') showVulnModal(v.id); };
  list.prepend(c);
}

function patchVuln(id){
  const v=S.vulns.find(x=>x.id===id); if(!v||v.patched) return;
  v.patched=true; S.resolved++;
  const c=$$(`vc-${id}`); if(c) c.style.opacity='.5';
  alog(`🔧 Patched: ${v.cve}`,'var(--accent)'); toast('Patched',`${v.cve} remediated`,'success'); updateStats();
}

function filterVulns(f){
  const list=$$('vulns-list'); list.innerHTML='';
  const filtered=f==='ALL'?S.vulns:S.vulns.filter(v=>cvssToSev(v.cvss)===f);
  if(!filtered.length){ list.innerHTML='<div class="empty"><div class="empty-icon">🔓</div>No vulns match filter</div>'; return; }
  filtered.forEach(v=>renderVuln(v));
}

// ============================================================
//  MITIGATION
// ============================================================
function createMitigations(evt){
  const tpls=KB.mitigations[evt.type]; if(!tpls) return;
  tpls.forEach(([task,assignee,steps,type],i)=>{
    setTimeout(()=>{
      S.mc++;
      const m={ id:uid(), seq:S.mc, task, assignee, steps, type, done:0, status:'ACTIVE', evtType:evt.type, created:Date.now() };
      S.mitigations.unshift(m);
      renderMitigation(m);
      alog(`🛡️ Mitigation: ${task} → ${assignee}`,'var(--accent)');
    }, i*350);
  });
}

function renderMitigation(m){
  const list=$$('mitigation-list');
  const empty=list.querySelector('.empty'); if(empty) empty.remove();
  const c=el('div','mit-card');
  c.id=`mc-${m.id}`;
  const pips=Array.from({length:m.steps},(_,i)=>`<div class="step-pip ${i<m.done?'done':i===m.done?'active':''}" id="pip-${m.id}-${i}"></div>`).join('');
  c.innerHTML=`
    <div class="mc-header"><div><div class="mc-task">${m.task}</div></div><span class="badge ${m.status}">${m.status}</span></div>
    <div class="mc-meta">👤 ${m.assignee} &nbsp;•&nbsp; <span class="badge INFO" style="font-size:9px">${m.type}</span></div>
    <div class="mc-steps">${pips}</div>
    <div class="mc-footer">
      <span class="mc-pct" id="mcp-${m.id}">${m.done}/${m.steps} steps</span>
      <div class="mc-actions">
        <button class="btn sm primary" onclick="advanceMit('${m.id}')">▶ Next</button>
        <button class="btn sm danger" onclick="completeMit('${m.id}')">✓ Complete</button>
      </div>
    </div>`;
  list.prepend(c);
}

function advanceMit(id){
  const m=S.mitigations.find(x=>x.id===id); if(!m||m.done>=m.steps) return;
  const prev=$$(`pip-${id}-${m.done}`); if(prev){ prev.classList.remove('active'); prev.classList.add('done'); }
  m.done++;
  const next=$$(`pip-${id}-${m.done}`); if(next) next.classList.add('active');
  $$(`mcp-${m.id}`).textContent=`${m.done}/${m.steps} steps`;
  if(m.done>=m.steps) completeMit(id);
  alog(`▶ Step ${m.done}/${m.steps}: ${m.task}`);
}

function completeMit(id){
  const m=S.mitigations.find(x=>x.id===id); if(!m) return;
  m.done=m.steps; m.status='RESOLVED'; S.resolved++;
  for(let i=0;i<m.steps;i++){ const p=$$(`pip-${id}-${i}`); if(p){ p.classList.remove('active'); p.classList.add('done'); } }
  const c=$$(`mc-${id}`); if(c){ c.querySelectorAll('.badge').forEach(b=>{ if(b.textContent!=='RESOLVED'&&!b.classList.contains('INFO')){ b.textContent='RESOLVED'; b.className='badge RESOLVED'; } }); c.style.opacity='.6'; }
  $$(`mcp-${m.id}`).textContent=`${m.steps}/${m.steps} steps`;
  alog(`✅ Mitigation complete: ${m.task}`,'var(--accent)'); toast('Complete',m.task,'success'); updateStats();
}

// ============================================================
//  TIMELINE (reports)
// ============================================================
function addTimeline(title, desc, sev){
  S.timeline.unshift({ title, desc, sev, ts:nowT() });
  S.timeline=S.timeline.slice(0,50);
}

function updateReports(){
  $$('rp-events').textContent=S.events.length;
  $$('rp-alerts').textContent=S.alerts.length;
  $$('rp-resolved').textContent=S.resolved;
  $$('rp-threats').textContent=S.threats.length;
  $$('rp-vulns').textContent=S.vulns.length;
  $$('rp-mttr').textContent=S.resolveTimes.length?( S.resolveTimes.reduce((a,b)=>a+b,0)/S.resolveTimes.length).toFixed(1):'—';

  const tl=$$('incident-timeline'); tl.innerHTML='';
  if(!S.timeline.length){ tl.innerHTML='<div class="empty"><div class="empty-icon">📋</div>No incidents yet</div>'; return; }
  S.timeline.forEach(e=>{
    const d=el('div','timeline-entry');
    d.innerHTML=`<div class="te-time">${e.ts}</div><div class="te-body"><div class="te-title"><span class="badge ${e.sev}" style="margin-right:6px">${e.sev}</span>${e.title}</div><div class="te-desc">${e.desc}</div></div>`;
    tl.appendChild(d);
  });
}

// ============================================================
//  QUICK INJECT / CHAIN
// ============================================================
const QS={
  ransomware:{ type:'Ransomware', sev:'CRITICAL', src:'185.220.101.45', target:'File Server',       desc:'LockBit 3.0 mass encryption — 23 hosts affected' },
  apt:        { type:'Data Exfiltration', sev:'CRITICAL', src:'91.108.4.33',    target:'Database',         desc:'APT exfil — 8.4GB customer database outbound' },
  sqli:       { type:'SQL Injection', sev:'HIGH',     src:'193.32.162.12', target:'Web Server',       desc:"UNION-based SQLi in /api/login 'username' param" },
  ddos:       { type:'DDoS Attack', sev:'HIGH',     src:'45.147.231.10', target:'Firewall',          desc:'UDP flood 95Gbps — CDN absorbing, origin exposed' },
  insider:    { type:'Insider Threat', sev:'HIGH',     src:'10.0.0.55',     target:'Domain Controller', desc:'Auth user accessing HR records at 03:22 AM' },
  zeroday:    { type:'Zero-Day Exploit', sev:'CRITICAL', src:'176.31.225.204', target:'Auth Server',       desc:'Unknown exploit against auth daemon — no signature match' },
  mitm:       { type:'MITM Attack', sev:'HIGH',     src:'192.168.1.99',  target:'VPN Server',        desc:'ARP spoofing detected — traffic interception active' },
  crypto:     { type:'Crypto-jacking', sev:'MEDIUM',   src:'10.1.2.88',     target:'Workstation',      desc:'Monero mining detected — 98% CPU utilisation' },
};

function quickInject(key){
  const s=QS[key]; if(!s) return;
  $$('ev-type').value=s.type; $$('ev-severity').value=s.sev;
  $$('ev-src').value=s.src;  $$('ev-target').value=s.target; $$('ev-desc').value=s.desc;
  injectEvent();
}

async function simulateChain(){
  alog('⚠️ SIMULATING FULL APT ATTACK CHAIN...','var(--red)');
  toast('🔴 Attack Chain','Multi-stage attack initiated...','danger',3000);
  const chain=[
    { type:'Port Scan',         sev:'MEDIUM',   src:'185.220.101.45', target:'Firewall',          desc:'Systematic recon — scanning /24 subnet ports' },
    { type:'Phishing',          sev:'HIGH',     src:'185.220.101.45', target:'Email Gateway',     desc:'Spear-phishing email opened — fake MFA login page' },
    { type:'Malware Download',  sev:'CRITICAL', src:'185.220.101.45', target:'Workstation',       desc:'Dropper executed — establishing persistence & C2' },
    { type:'Privilege Escalation',sev:'CRITICAL',src:'185.220.101.45',target:'Domain Controller', desc:'Token impersonation — escalated to Domain Admin' },
    { type:'Data Exfiltration', sev:'CRITICAL', src:'185.220.101.45', target:'Database',          desc:'Mass PII exfil — 12.6GB to external C2 server' },
    { type:'Ransomware',        sev:'CRITICAL', src:'185.220.101.45', target:'File Server',       desc:'LockBit deployed — 47 hosts encrypting NOW' },
  ];
  for(let i=0;i<chain.length;i++){
    const s=chain[i];
    $$('ev-type').value=s.type; $$('ev-severity').value=s.sev;
    $$('ev-src').value=s.src;   $$('ev-target').value=s.target; $$('ev-desc').value=s.desc;
    await injectEvent();
    alog(`⚡ Attack stage ${i+1}/${chain.length}: ${s.type}`,'var(--red)');
    await delay(1600);
  }
  alog('🚨 INCIDENT DECLARED — Activate IRP immediately!','var(--red)');
  toast('🚨 INCIDENT DECLARED','Full attack chain executed. Activate IRP!','danger',8000);
}

// ============================================================
//  BULK / EXPORT
// ============================================================
function exportReport(){
  const data={ exported:now(), events:S.events.length, alerts:S.alerts.length, threats:S.threats.length, vulns:S.vulns.length, resolved:S.resolved, timeline:S.timeline };
  const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='cyberwatch-report.json'; a.click();
  toast('Export','Report downloaded as JSON','success');
}

function clearAll(){
  if(!confirm('Clear all incident data?')) return;
  ['events','alerts','threats','vulns','mitigations','iocs','timeline'].forEach(k=>S[k]=[]);
  S.ec=S.alc=S.thc=S.vc=S.mc=S.resolved=0;
  S.surface={web:10,net:15,ep:8,id:5,cloud:12};
  ['event-feed','events-full-list','alerts-list','threats-list','vulns-list','mitigation-list','dash-alerts-list','ioc-list','incident-timeline'].forEach(id=>{
    const el=$$( id ); if(el) el.innerHTML='<div class="empty"><div class="empty-icon">📡</div>No data</div>';
  });
  ['web','net','ep','id','cloud'].forEach(k=>{ $$('as-'+k).style.width='0%'; $$('asp-'+k).textContent='0%'; });
  document.querySelectorAll('.nnode').forEach(n=>n.className='nnode safe');
  $$('analyst-log').innerHTML='';
  alog('[SYSTEM] All data cleared','var(--text3)');
  updateStats(); toast('Cleared','All incident data removed','info');
}

// ============================================================
//  MODALS
// ============================================================
function showEventModal(evt){
  const m=$$('modal-content');
  m.innerHTML=`
    <button class="modal-close" onclick="$$('modal-bg').classList.remove('show')">✕</button>
    <div class="modal-title">${evt.type}</div>
    <div class="modal-sub">EVT-${evt.seq} • ${evt.ts} • <span class="badge ${evt.sev}">${evt.sev}</span></div>
    <div class="modal-section-title" style="margin-bottom:8px">Event Details</div>
    <div class="detail-grid" style="margin-bottom:16px">
      <div class="detail-box"><div class="db-key">Source IP</div><div class="db-val" style="color:var(--red)">${evt.src}</div></div>
      <div class="detail-box"><div class="db-key">Target System</div><div class="db-val">${evt.target}</div></div>
      <div class="detail-box"><div class="db-key">Type</div><div class="db-val">${evt.type}</div></div>
      <div class="detail-box"><div class="db-key">Severity</div><div class="db-val"><span class="badge ${evt.sev}">${evt.sev}</span></div></div>
      <div class="detail-box" style="grid-column:1/-1"><div class="db-key">Description</div><div class="db-val">${evt.desc}</div></div>
    </div>
    <div class="modal-section-title" style="margin-bottom:8px">Automated Response</div>
    <div class="tl-modal">
      <div class="tl-m-item"><div class="tl-m-key">${evt.ts.slice(11,19)}</div><div class="tl-m-val">Event detected by SIEM correlation engine</div></div>
      <div class="tl-m-item"><div class="tl-m-key">+0.8s</div><div class="tl-m-val">Signature matched against threat intelligence database</div></div>
      <div class="tl-m-item"><div class="tl-m-key">+1.4s</div><div class="tl-m-val">Alert generated — analyst notified via PagerDuty</div></div>
      <div class="tl-m-item"><div class="tl-m-key">+2.1s</div><div class="tl-m-val">SOAR playbook triggered — mitigation tasks created</div></div>
    </div>`;
  $$('modal-bg').classList.add('show');
}

function showAlertModal(id){
  const a=typeof id==='string'?S.alerts.find(x=>x.id===id):id;
  if(!a) return;
  const m=$$('modal-content');
  m.innerHTML=`
    <button class="modal-close" onclick="$$('modal-bg').classList.remove('show')">✕</button>
    <div class="modal-title">${a.type}</div>
    <div class="modal-sub">ALT-${a.seq} • ${a.ts} • <span class="badge ${a.sev}">${a.sev}</span></div>
    <div class="modal-section-title" style="margin-bottom:8px">Alert Intelligence</div>
    <div class="detail-grid" style="margin-bottom:16px">
      <div class="detail-box"><div class="db-key">Detection Rule</div><div class="db-val" style="color:var(--blue)">${a.rule}</div></div>
      <div class="detail-box"><div class="db-key">Status</div><div class="db-val"><span class="badge ${a.status}">${a.status}</span></div></div>
      <div class="detail-box"><div class="db-key">Source IP</div><div class="db-val" style="color:var(--red)">${a.src}</div></div>
      <div class="detail-box"><div class="db-key">Target</div><div class="db-val">${a.target}</div></div>
      <div class="detail-box" style="grid-column:1/-1"><div class="db-key">Analysis</div><div class="db-val" style="line-height:1.7">${a.desc}</div></div>
    </div>
    <div class="modal-section-title" style="margin-bottom:8px">Incident Response Steps (PICERL)</div>
    <div class="tl-modal">
      <div class="tl-m-item"><div class="tl-m-key">PREPARE</div><div class="tl-m-val">Verify alert, assign priority analyst, open war room</div></div>
      <div class="tl-m-item"><div class="tl-m-key">IDENTIFY</div><div class="tl-m-val">Correlate with threat intel, confirm breach scope</div></div>
      <div class="tl-m-item"><div class="tl-m-key">CONTAIN</div><div class="tl-m-val">Block source IP, isolate affected hosts immediately</div></div>
      <div class="tl-m-item"><div class="tl-m-key">ERADICATE</div><div class="tl-m-val">Remove malware, patch vulnerabilities, reset credentials</div></div>
      <div class="tl-m-item"><div class="tl-m-key">RECOVER</div><div class="tl-m-val">Restore from verified backups, verify clean state</div></div>
      <div class="tl-m-item"><div class="tl-m-key">LEARN</div><div class="tl-m-val">Write post-incident report, update detection rules</div></div>
    </div>`;
  $$('modal-bg').classList.add('show');
}

function showThreatModal(id){
  const th=S.threats.find(x=>x.id===id); if(!th) return;
  const m=$$('modal-content');
  m.innerHTML=`
    <button class="modal-close" onclick="$$('modal-bg').classList.remove('show')">✕</button>
    <div class="modal-title">${th.name}</div>
    <div class="modal-sub">THR-${th.seq} • ${th.ts} • Actor: ${th.actor}</div>
    <div class="modal-section-title" style="margin-bottom:8px">Threat Profile</div>
    <div class="detail-grid" style="margin-bottom:16px">
      <div class="detail-box"><div class="db-key">Threat Actor</div><div class="db-val" style="color:var(--orange)">${th.actor}</div></div>
      <div class="detail-box"><div class="db-key">Status</div><div class="db-val"><span class="badge ${th.status}">${th.status}</span></div></div>
      <div class="detail-box"><div class="db-key">Attack Vector</div><div class="db-val">${th.vec}</div></div>
      <div class="detail-box"><div class="db-key">Confidence</div><div class="db-val" style="color:var(--red)">${th.conf}%</div></div>
      <div class="detail-box"><div class="db-key">Linked Event</div><div class="db-val">EVT-${th.evtId}</div></div>
      <div class="detail-box"><div class="db-key">First Seen</div><div class="db-val">${th.ts}</div></div>
    </div>
    <div class="modal-section-title" style="margin-bottom:8px">MITRE ATT&CK Mapping</div>
    <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px">
      ${['Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion','Lateral Movement'].map(t=>`<span class="badge INFO">${t}</span>`).join('')}
    </div>`;
  $$('modal-bg').classList.add('show');
}

function showVulnModal(id){
  const v=S.vulns.find(x=>x.id===id); if(!v) return;
  const sev=cvssToSev(v.cvss);
  const m=$$('modal-content');
  m.innerHTML=`
    <button class="modal-close" onclick="$$('modal-bg').classList.remove('show')">✕</button>
    <div class="modal-title">${v.cve}</div>
    <div class="modal-sub">${v.name} • CVSS <span style="color:var(--red);font-weight:bold">${v.cvss}</span></div>
    <div class="modal-section-title" style="margin-bottom:8px">Vulnerability Details</div>
    <div class="detail-grid" style="margin-bottom:16px">
      <div class="detail-box"><div class="db-key">CVE ID</div><div class="db-val" style="color:var(--blue)">${v.cve}</div></div>
      <div class="detail-box"><div class="db-key">CVSS Score</div><div class="db-val"><span class="badge ${sev}">${v.cvss} ${sev}</span></div></div>
      <div class="detail-box"><div class="db-key">Affected System</div><div class="db-val">${v.sys}</div></div>
      <div class="detail-box"><div class="db-key">Patch Available</div><div class="db-val">${v.patch?'<span class="badge RESOLVED">YES</span>':'<span class="badge ACTIVE">NO</span>'}</div></div>
      <div class="detail-box"><div class="db-key">Status</div><div class="db-val">${v.patched?'<span class="badge RESOLVED">PATCHED</span>':'<span class="badge OPEN">OPEN</span>'}</div></div>
      <div class="detail-box"><div class="db-key">Discovered</div><div class="db-val">${v.ts?.slice(0,16)||'Now'}</div></div>
    </div>
    <div class="modal-section-title" style="margin-bottom:8px">Remediation</div>
    <div class="tl-modal">
      <div class="tl-m-item"><div class="tl-m-key">ASSESS</div><div class="tl-m-val">Identify all affected systems and exposure scope</div></div>
      <div class="tl-m-item"><div class="tl-m-key">ISOLATE</div><div class="tl-m-val">Network segmentation to limit blast radius</div></div>
      <div class="tl-m-item"><div class="tl-m-key">PATCH</div><div class="tl-m-val">${v.patch?'Apply available vendor patch immediately':'Apply virtual WAF patch — vendor patch pending'}</div></div>
      <div class="tl-m-item"><div class="tl-m-key">VERIFY</div><div class="tl-m-val">Rescan all systems to confirm remediation success</div></div>
    </div>`;
  $$('modal-bg').classList.add('show');
}

function closeModal(e){ if(e.target===$$('modal-bg')) $$('modal-bg').classList.remove('show'); 
</body>
</html>
