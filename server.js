require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const { Pool } = require('pg');

const app  = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     process.env.DB_PORT     || 5432,
  database: process.env.DB_NAME     || 'cyberwatch_db',
  user:     process.env.DB_USER     || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres123',
});

pool.connect()
  .then(c => { c.release(); console.log(' PostgreSQL connected!'); })
  .catch(e => console.error(' DB Error:', e.message));

app.use(cors());
app.use(express.json());

// Serve frontend files
app.use(express.static(path.join(__dirname, '../frontend')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// AUTH
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const r = await pool.query(
      `SELECT user_id, email, username, role FROM users
       WHERE email=$1 AND password=$2 AND is_active=TRUE`,
      [email, password]
    );
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    await pool.query(`UPDATE users SET last_login=NOW() WHERE user_id=$1`, [r.rows[0].user_id]);
    res.json({ success: true, user: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// EVENTS
app.get('/api/events', async (req, res) => {
  try {
    const r = await pool.query(`SELECT * FROM events ORDER BY created_at DESC LIMIT 200`);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/events', async (req, res) => {
  const { event_type, source_ip, target_system, severity, description } = req.body;
  const client = await pool.connect();
  const ALERT_MAP = {
    'Brute Force':['Authentication Storm','HIGH','RULE-BF-001'],
    'SQL Injection':['SQL Injection Detected','CRITICAL','RULE-WA-002'],
    'XSS Attack':['Cross-Site Scripting','HIGH','RULE-WA-003'],
    'Port Scan':['Network Reconnaissance','MEDIUM','RULE-NW-004'],
    'Malware Download':['Malicious Payload Download','CRITICAL','RULE-EP-005'],
    'Ransomware':['Ransomware Execution','CRITICAL','RULE-EP-006'],
    'Phishing':['Spear Phishing Detected','HIGH','RULE-EM-007'],
    'DDoS Attack':['DDoS Volumetric Flood','HIGH','RULE-NW-008'],
    'Privilege Escalation':['Privilege Escalation','CRITICAL','RULE-ID-009'],
    'Data Exfiltration':['Data Exfiltration Attempt','CRITICAL','RULE-DLP-010'],
    'Zero-Day Exploit':['Zero-Day Exploitation','CRITICAL','RULE-ZD-011'],
    'Insider Threat':['Insider Threat Activity','HIGH','RULE-IT-012'],
    'MITM Attack':['Man-in-the-Middle Attack','HIGH','RULE-NW-013'],
    'Crypto-jacking':['Cryptomining Detected','MEDIUM','RULE-EP-014'],
    'Supply Chain Attack':['Supply Chain Compromise','CRITICAL','RULE-SC-015'],
  };
  const THREAT_MAP = {
    'Brute Force':['Credential Stuffing Campaign','Unknown Actor','Network',72],
    'SQL Injection':['Web App Compromise','APT-29 Cozy Bear','App',88],
    'XSS Attack':['Session Hijacking Op','FIN-7 Group','App',65],
    'Port Scan':['Infrastructure Recon','Unknown','Network',45],
    'Malware Download':['Trojan Deployment','Lazarus Group','Endpoint',91],
    'Ransomware':['Ransomware Campaign','LockBit 3.0','Endpoint',96],
    'Phishing':['Spear Phishing Op','APT-41','Email',78],
    'DDoS Attack':['DDoS Botnet Activation','Killnet','Network',83],
    'Privilege Escalation':['Domain Takeover Attempt','APT-28 Fancy Bear','Identity',89],
    'Data Exfiltration':['Corporate Espionage Op','APT-10 Stone Panda','Data',85],
    'Zero-Day Exploit':['Advanced Persistent Threat','Nation-State Actor','Endpoint',94],
    'Insider Threat':['Insider Data Theft','Malicious Insider','Internal',70],
    'MITM Attack':['Network Interception','Unknown Actor','Network',75],
    'Crypto-jacking':['Cryptomining Botnet','TeamTNT','Endpoint',68],
    'Supply Chain Attack':['Supply Chain Infiltration','SolarWinds APT','Software',92],
  };
  const VULN_MAP = {
    'SQL Injection':['CVE-2024-1234','SQL Injection in Login Module',9.8,'Web App v2.3.1',false],
    'XSS Attack':['CVE-2024-5678','Reflected XSS in Search Param',7.4,'Frontend v1.8.0',true],
    'Malware Download':['CVE-2024-9012','RCE via Unpatched Service',9.9,'Windows Server 2019',false],
    'Ransomware':['CVE-2023-4789','EternalBlue SMB Vulnerability',9.8,'SMB Service v1',false],
    'Privilege Escalation':['CVE-2024-21413','Windows Kernel Token Exploit',9.8,'Windows 11 22H2',false],
    'Zero-Day Exploit':['CVE-2024-XXXX','Zero-Day Under Analysis',10.0,'Core Infrastructure',false],
    'Data Exfiltration':['CVE-2024-3344','Insufficient Access Controls',8.1,'File Server v3.1',true],
    'MITM Attack':['CVE-2024-7890','Weak TLS Configuration',7.5,'API Gateway v2.0',true],
    'Supply Chain Attack':['CVE-2024-8811','Dependency Confusion Attack',9.0,'CI/CD Pipeline',false],
  };
  const MIT_MAP = {
    'Brute Force':[['Block source IP at firewall','R. Mehta',3,'CONTAIN'],['Enable account lockout','S. Park',4,'HARDEN'],['Enforce MFA','L. Nguyen',5,'PREVENT']],
    'SQL Injection':[['Deploy WAF SQLi rules','T. Okafor',3,'DETECT'],['Patch vulnerable endpoint','A. Kumar',6,'PATCH']],
    'Ransomware':[['Isolate infected hosts','R. Mehta',2,'CONTAIN'],['Kill malicious processes','T. Okafor',3,'ERADICATE'],['Restore from backup','L. Nguyen',5,'RECOVER'],['Apply SMB patches','A. Kumar',4,'PATCH']],
    'Malware Download':[['Quarantine endpoint','S. Park',2,'CONTAIN'],['Block C2 IP','R. Mehta',3,'CONTAIN'],['Full AV scan','T. Okafor',4,'DETECT']],
    'Privilege Escalation':[['Revoke elevated perms','S. Park',3,'CONTAIN'],['Reset compromised creds','L. Nguyen',4,'ERADICATE'],['Deploy kernel patch','A. Kumar',5,'PATCH']],
    'DDoS Attack':[['Activate DDoS scrubbing','R. Mehta',2,'CONTAIN'],['Rate-limit ingress','T. Okafor',3,'CONTAIN']],
    'Data Exfiltration':[['Block outbound connection','R. Mehta',2,'CONTAIN'],['Forensic capture','A. Kumar',4,'DETECT'],['Notify DPO GDPR','Compliance',3,'REPORT']],
    'Zero-Day Exploit':[['Emergency isolation','R. Mehta',2,'CONTAIN'],['Submit to sandbox','T. Okafor',4,'ANALYZE'],['Contact vendor','L. Nguyen',3,'PATCH']],
    'Phishing':[['Block phishing domain','T. Okafor',2,'CONTAIN'],['Force password reset','S. Park',3,'ERADICATE']],
    'MITM Attack':[['Revoke compromised certs','A. Kumar',3,'CONTAIN'],['Re-key TLS endpoints','L. Nguyen',4,'HARDEN']],
    'Supply Chain Attack':[['Quarantine packages','R. Mehta',3,'CONTAIN'],['Audit dependencies','A. Kumar',5,'ANALYZE']],
    'Insider Threat':[['Revoke user access','S. Park',2,'CONTAIN'],['Preserve evidence','A. Kumar',4,'DETECT']],
    'Crypto-jacking':[['Kill mining process','T. Okafor',2,'CONTAIN'],['Remove persistence','R. Mehta',3,'ERADICATE']],
  };
  try {
    await client.query('BEGIN');
    const evRes = await client.query(
      `INSERT INTO events (event_type,source_ip,target_system,severity,description,payload_data)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [event_type,source_ip,target_system,severity,description,JSON.stringify({injected_at:new Date()})]
    );
    const ev = evRes.rows[0];
    let alertId=null, threatId=null;
    const ai=ALERT_MAP[event_type];
    if(ai){
      const aRes=await client.query(
        `INSERT INTO alerts (event_id,alert_type,severity,detection_rule,description,source_ip,target_system)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING alert_id`,
        [ev.event_id,ai[0],ai[1],ai[2],`Auto-detected: ${event_type} from ${source_ip}`,source_ip,target_system]
      );
      alertId=aRes.rows[0].alert_id;
    }
    const ti=THREAT_MAP[event_type];
    if(ti){
      const tRes=await client.query(
        `INSERT INTO threats (event_id,threat_name,threat_actor,attack_vector,confidence_score,ioc_data)
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING threat_id`,
        [ev.event_id,ti[0],ti[1],ti[2],ti[3]+Math.floor(Math.random()*5),JSON.stringify({source_ip})]
      );
      threatId=tRes.rows[0].threat_id;
    }
    const vi=VULN_MAP[event_type];
    if(vi){
      await client.query(
        `INSERT INTO vulnerabilities (event_id,cve_id,vuln_name,cvss_score,affected_system,patch_available)
         VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (cve_id) DO NOTHING`,
        [ev.event_id,vi[0],vi[1],vi[2],vi[3],vi[4]]
      );
    }
    const mits=MIT_MAP[event_type]||[];
    for(const [task,assignee,steps,type] of mits){
      await client.query(
        `INSERT INTO mitigation_actions (event_id,threat_id,alert_id,task_name,action_type,assigned_to,total_steps)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [ev.event_id,threatId,alertId,task,type,assignee,steps]
      );
    }
    await client.query('COMMIT');
    console.log(` ${event_type} saved to DB!`);
    res.json({success:true,event:ev});
  } catch(e){
    await client.query('ROLLBACK');
    res.status(500).json({error:e.message});
  } finally { client.release(); }
});

// ALERTS
app.get('/api/alerts', async (req,res)=>{
  try{ const r=await pool.query(`SELECT a.*,e.event_type FROM alerts a JOIN events e ON e.event_id=a.event_id ORDER BY a.created_at DESC LIMIT 200`); res.json(r.rows); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.patch('/api/alerts/:id/acknowledge', async (req,res)=>{
  try{ const r=await pool.query(`UPDATE alerts SET status='MITIGATING',acknowledged_by=$2 WHERE alert_id=$1 RETURNING *`,[req.params.id,req.body.analyst||'Analyst']); res.json(r.rows[0]); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.patch('/api/alerts/:id/resolve', async (req,res)=>{
  try{ const r=await pool.query(`UPDATE alerts SET status='RESOLVED',resolved_at=NOW(),acknowledged_by=$2 WHERE alert_id=$1 RETURNING *`,[req.params.id,req.body.analyst||'Analyst']); res.json(r.rows[0]); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.patch('/api/alerts/:id/escalate', async (req,res)=>{
  try{ const r=await pool.query(`UPDATE alerts SET severity='CRITICAL' WHERE alert_id=$1 RETURNING *`,[req.params.id]); res.json(r.rows[0]); }
  catch(e){ res.status(500).json({error:e.message}); }
});

// THREATS
app.get('/api/threats', async (req,res)=>{
  try{ const r=await pool.query(`SELECT t.*,e.event_type,e.source_ip FROM threats t JOIN events e ON e.event_id=t.event_id ORDER BY t.created_at DESC`); res.json(r.rows); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.patch('/api/threats/:id/status', async (req,res)=>{
  try{ const r=await pool.query(`UPDATE threats SET status=$2 WHERE threat_id=$1 RETURNING *`,[req.params.id,req.body.status]); res.json(r.rows[0]); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.patch('/api/threats/:id/analyze', async (req,res)=>{
  try{ const r=await pool.query(`UPDATE threats SET confidence_score=LEAST(99,confidence_score+5) WHERE threat_id=$1 RETURNING *`,[req.params.id]); res.json(r.rows[0]); }
  catch(e){ res.status(500).json({error:e.message}); }
});

// VULNS
app.get('/api/vulns', async (req,res)=>{
  try{ const r=await pool.query(`SELECT v.*,e.event_type FROM vulnerabilities v JOIN events e ON e.event_id=v.event_id ORDER BY v.cvss_score DESC`); res.json(r.rows); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.patch('/api/vulns/:id/patch', async (req,res)=>{
  try{ const r=await pool.query(`UPDATE vulnerabilities SET patched=TRUE,patched_at=NOW() WHERE vuln_id=$1 RETURNING *`,[req.params.id]); res.json(r.rows[0]); }
  catch(e){ res.status(500).json({error:e.message}); }
});

// MITIGATIONS
app.get('/api/mitigations', async (req,res)=>{
  try{ const r=await pool.query(`SELECT m.*,e.event_type,e.severity FROM mitigation_actions m JOIN events e ON e.event_id=m.event_id ORDER BY CASE e.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,m.created_at DESC`); res.json(r.rows); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.patch('/api/mitigations/:id/advance', async (req,res)=>{
  try{ const r=await pool.query(`UPDATE mitigation_actions SET completed_steps=LEAST(total_steps,completed_steps+1),status=CASE WHEN completed_steps+1>=total_steps THEN 'RESOLVED' ELSE 'IN_PROGRESS' END,completed_at=CASE WHEN completed_steps+1>=total_steps THEN NOW() ELSE NULL END WHERE action_id=$1 RETURNING *`,[req.params.id]); res.json(r.rows[0]); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.patch('/api/mitigations/:id/complete', async (req,res)=>{
  try{ const r=await pool.query(`UPDATE mitigation_actions SET completed_steps=total_steps,status='RESOLVED',completed_at=NOW() WHERE action_id=$1 RETURNING *`,[req.params.id]); res.json(r.rows[0]); }
  catch(e){ res.status(500).json({error:e.message}); }
});

// DASHBOARD
app.get('/api/dashboard', async (req,res)=>{
  try{
    const r=await pool.query(`SELECT
      (SELECT COUNT(*) FROM events WHERE created_at>=NOW()-INTERVAL '24 hours') AS events_today,
      (SELECT COUNT(*) FROM alerts WHERE status!='RESOLVED') AS open_alerts,
      (SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL' AND status!='RESOLVED') AS critical_alerts,
      (SELECT COUNT(*) FROM threats WHERE status='ACTIVE') AS active_threats,
      (SELECT COUNT(*) FROM vulnerabilities WHERE patched=FALSE) AS open_vulns,
      (SELECT COUNT(*) FROM alerts WHERE status='RESOLVED') AS resolved_count,
      (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (resolved_at-created_at))/60),1) FROM alerts WHERE resolved_at IS NOT NULL) AS avg_mttr_minutes,
      (SELECT ROUND(AVG(cvss_score),1) FROM vulnerabilities WHERE patched=FALSE) AS avg_risk_score`);
    res.json(r.rows[0]);
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.get('/api/reports/full', async (req,res)=>{
  try{
    const r=await pool.query(`SELECT e.event_type,e.source_ip,e.severity,e.created_at,a.alert_type,a.status AS alert_status,t.threat_name,t.threat_actor,v.cve_id,v.cvss_score,m.task_name,m.assigned_to FROM events e LEFT JOIN alerts a ON a.event_id=e.event_id LEFT JOIN threats t ON t.event_id=e.event_id LEFT JOIN vulnerabilities v ON v.event_id=e.event_id LEFT JOIN mitigation_actions m ON m.event_id=e.event_id ORDER BY e.created_at DESC LIMIT 100`);
    res.json(r.rows);
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.listen(PORT, ()=>{
  console.log(`\n CyberWatch SOC running at http://localhost:${PORT}`);
  console.log(` Open browser: http://localhost:${PORT}\n`);
});
