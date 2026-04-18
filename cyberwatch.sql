-- ================================================================
--  CyberWatch SOC — Complete Database File
--  File: database/cyberwatch.sql
--
--  VS Code mein kaise chalao:
--  1. SQLTools extension install karo
--  2. PostgreSQL se connect karo
--  3. Is file ko select karke Run karo
--
--  Ya terminal mein:
--  psql -U postgres -d cyberwatch_db -f cyberwatch.sql
-- ================================================================


-- ----------------------------------------------------------------
--  STEP 1: DATABASE BANAO
-- ----------------------------------------------------------------
-- Pehle terminal mein ye chalao:
-- CREATE DATABASE cyberwatch_db;
-- \c cyberwatch_db


-- ----------------------------------------------------------------
--  STEP 2: EXTENSION (UUID ke liye)
-- ----------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "pgcrypto";


-- ----------------------------------------------------------------
--  STEP 3: PURANI TABLES DELETE KARO (Fresh start)
-- ----------------------------------------------------------------
DROP TABLE IF EXISTS mitigation_steps    CASCADE;
DROP TABLE IF EXISTS mitigation_actions  CASCADE;
DROP TABLE IF EXISTS vulnerabilities     CASCADE;
DROP TABLE IF EXISTS threats             CASCADE;
DROP TABLE IF EXISTS alerts              CASCADE;
DROP TABLE IF EXISTS events              CASCADE;
DROP TABLE IF EXISTS users               CASCADE;


-- ================================================================
--  STEP 4: TABLES BANAO
-- ================================================================

-- ----------------------------------------------------------------
--  TABLE 1: USERS
-- ----------------------------------------------------------------
CREATE TABLE users (
    user_id     UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    email       VARCHAR(150) UNIQUE NOT NULL,
    username    VARCHAR(80)  NOT NULL,
    role        VARCHAR(30)  CHECK (role IN ('SOC Analyst','IR Lead','CISO','Admin')),
    password    VARCHAR(255) NOT NULL,
    is_active   BOOLEAN      DEFAULT TRUE,
    last_login  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  DEFAULT NOW()
);

COMMENT ON TABLE users IS 'System users — analysts, IR leads, CISO';


-- ----------------------------------------------------------------
--  TABLE 2: EVENTS  (Main Table — sab yahan se start hota hai)
-- ----------------------------------------------------------------
CREATE TABLE events (
    event_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type    VARCHAR(50) NOT NULL,
    source_ip     INET,
    target_system VARCHAR(80),
    severity      VARCHAR(10) CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    description   TEXT,
    status        VARCHAR(20) DEFAULT 'OPEN'
                              CHECK (status IN ('OPEN','INVESTIGATING','RESOLVED')),
    payload_data  JSONB,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE events IS 'Raw security events detected by SIEM';


-- ----------------------------------------------------------------
--  TABLE 3: ALERTS  (Event ke baad automatically generate hoti hai)
-- ----------------------------------------------------------------
CREATE TABLE alerts (
    alert_id        UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        UUID         REFERENCES events(event_id) ON DELETE CASCADE,
    alert_type      VARCHAR(100) NOT NULL,
    severity        VARCHAR(10)  CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    detection_rule  VARCHAR(30),
    description     TEXT,
    source_ip       INET,
    target_system   VARCHAR(80),
    status          VARCHAR(20)  DEFAULT 'ACTIVE'
                                 CHECK (status IN ('ACTIVE','MITIGATING','RESOLVED')),
    acknowledged_by VARCHAR(100),
    created_at      TIMESTAMPTZ  DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

COMMENT ON TABLE alerts IS 'Auto-generated alerts from events via detection rules';


-- ----------------------------------------------------------------
--  TABLE 4: THREATS  (Attack ke peeche kaun hai)
-- ----------------------------------------------------------------
CREATE TABLE threats (
    threat_id        UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id         UUID         REFERENCES events(event_id) ON DELETE CASCADE,
    threat_name      VARCHAR(150) NOT NULL,
    threat_actor     VARCHAR(120),
    attack_vector    VARCHAR(50),
    confidence_score DECIMAL(5,2) CHECK (confidence_score BETWEEN 0 AND 100),
    ioc_data         JSONB,
    status           VARCHAR(20)  DEFAULT 'ACTIVE'
                                  CHECK (status IN ('ACTIVE','CONTAINED','RESOLVED')),
    created_at       TIMESTAMPTZ  DEFAULT NOW()
);

COMMENT ON TABLE threats IS 'Identified threat actors and campaigns';


-- ----------------------------------------------------------------
--  TABLE 5: VULNERABILITIES  (System ki weakness)
-- ----------------------------------------------------------------
CREATE TABLE vulnerabilities (
    vuln_id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        UUID         REFERENCES events(event_id) ON DELETE CASCADE,
    cve_id          VARCHAR(25)  UNIQUE,
    vuln_name       VARCHAR(200) NOT NULL,
    cvss_score      DECIMAL(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
    affected_system TEXT,
    patch_available BOOLEAN      DEFAULT FALSE,
    patched         BOOLEAN      DEFAULT FALSE,
    patched_at      TIMESTAMPTZ,
    discovered_at   TIMESTAMPTZ  DEFAULT NOW()
);

COMMENT ON TABLE vulnerabilities IS 'CVE vulnerabilities discovered during incidents';


-- ----------------------------------------------------------------
--  TABLE 6: MITIGATION_ACTIONS  (Kya karna hai fix ke liye)
-- ----------------------------------------------------------------
CREATE TABLE mitigation_actions (
    action_id       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        UUID        REFERENCES events(event_id)  ON DELETE CASCADE,
    threat_id       UUID        REFERENCES threats(threat_id) ON DELETE SET NULL,
    alert_id        UUID        REFERENCES alerts(alert_id)   ON DELETE SET NULL,
    task_name       VARCHAR(200) NOT NULL,
    action_type     VARCHAR(20) CHECK (action_type IN (
                        'CONTAIN','ERADICATE','RECOVER',
                        'PATCH','DETECT','PREVENT',
                        'REPORT','ANALYZE','HARDEN'
                    )),
    assigned_to     VARCHAR(100),
    total_steps     SMALLINT    DEFAULT 3,
    completed_steps SMALLINT    DEFAULT 0,
    status          VARCHAR(20) DEFAULT 'ACTIVE'
                                CHECK (status IN ('ACTIVE','IN_PROGRESS','RESOLVED')),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

COMMENT ON TABLE mitigation_actions IS 'Response tasks assigned to analysts';


-- ----------------------------------------------------------------
--  TABLE 7: MITIGATION_STEPS  *** WEAK ENTITY ***
--  (Ye apne aap exist nahi kar sakti — action_id chahiye)
-- ----------------------------------------------------------------
CREATE TABLE mitigation_steps (
    step_number  SMALLINT    NOT NULL,
    action_id    UUID        NOT NULL
                             REFERENCES mitigation_actions(action_id)
                             ON DELETE CASCADE,
    description  TEXT        NOT NULL,
    completed    BOOLEAN     DEFAULT FALSE,
    executor     VARCHAR(100),
    executed_at  TIMESTAMPTZ,

    -- Composite Primary Key (WEAK ENTITY ki pehchaan)
    PRIMARY KEY (action_id, step_number)
);

COMMENT ON TABLE mitigation_steps IS 'WEAK ENTITY — individual steps within a mitigation action';


-- ================================================================
--  STEP 5: INDEXES (Search fast karne ke liye)
-- ================================================================
CREATE INDEX idx_events_severity  ON events(severity);
CREATE INDEX idx_events_created   ON events(created_at DESC);
CREATE INDEX idx_events_source_ip ON events(source_ip);
CREATE INDEX idx_alerts_status    ON alerts(status);
CREATE INDEX idx_alerts_severity  ON alerts(severity);
CREATE INDEX idx_threats_status   ON threats(status);
CREATE INDEX idx_threats_actor    ON threats(threat_actor);
CREATE INDEX idx_vulns_cvss       ON vulnerabilities(cvss_score DESC);
CREATE INDEX idx_vulns_patched    ON vulnerabilities(patched);


-- ================================================================
--  STEP 6: DEMO DATA DAALO (Testing ke liye)
-- ================================================================

-- Users
INSERT INTO users (email, username, role, password) VALUES
('analyst@cyberwatch.io', 'SOC Analyst', 'SOC Analyst', 'CyberWatch@2024'),
('lead@cyberwatch.io',    'IR Lead',     'IR Lead',     'CyberWatch@2024'),
('ciso@cyberwatch.io',    'CISO',        'CISO',        'CyberWatch@2024');

-- Demo Event 1: Ransomware
INSERT INTO events (event_type, source_ip, target_system, severity, description)
VALUES ('Ransomware', '185.220.101.45', 'File Server', 'CRITICAL',
        'LockBit 3.0 mass file encryption detected on File Server');

-- Demo Event 2: SQL Injection
INSERT INTO events (event_type, source_ip, target_system, severity, description)
VALUES ('SQL Injection', '193.32.162.12', 'Web Server', 'CRITICAL',
        'UNION-based SQL injection in /api/login parameter');

-- Demo Event 3: Port Scan
INSERT INTO events (event_type, source_ip, target_system, severity, description)
VALUES ('Port Scan', '176.31.225.204', 'Firewall', 'MEDIUM',
        'Systematic port sweep across /24 subnet — 2400 packets/min');


-- ================================================================
--  STEP 7: SQL QUERIES — YE WO QUERIES HAIN JO BACKEND USE KARTA HAI
-- ================================================================


-- ----------------------------------------------------------------
--  QUERY 1: EVENT CORRELATION
--  Ek event ke saath uski saari related data ek saath lao
-- ----------------------------------------------------------------
SELECT
    e.event_id,
    e.event_type,
    e.source_ip,
    e.severity,
    e.created_at,
    COUNT(DISTINCT a.alert_id)              AS alert_count,
    COUNT(DISTINCT t.threat_id)             AS threat_count,
    COUNT(DISTINCT v.vuln_id)               AS vuln_count,
    MAX(v.cvss_score)                       AS max_cvss,
    STRING_AGG(DISTINCT t.threat_actor, ', ') AS threat_actors
FROM      events           e
LEFT JOIN alerts           a ON a.event_id = e.event_id
LEFT JOIN threats          t ON t.event_id = e.event_id
LEFT JOIN vulnerabilities  v ON v.event_id = e.event_id
WHERE  e.created_at >= NOW() - INTERVAL '24 hours'
GROUP  BY e.event_id, e.event_type, e.source_ip, e.severity, e.created_at
HAVING COUNT(DISTINCT a.alert_id) > 0
    OR COUNT(DISTINCT t.threat_id) > 0
ORDER  BY
    CASE e.severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH'     THEN 2
        WHEN 'MEDIUM'   THEN 3
        ELSE 4
    END,
    e.created_at DESC;


-- ----------------------------------------------------------------
--  QUERY 2: ATTACK PATTERN DETECTION
--  Kaunsi IP baar baar alag alag attacks kar rahi hai
-- ----------------------------------------------------------------
WITH ip_events AS (
    SELECT
        source_ip,
        event_type,
        DATE_TRUNC('hour', created_at)  AS hour_bucket,
        COUNT(*)                         AS event_count
    FROM  events
    GROUP BY 1, 2, 3
),
suspects AS (
    SELECT
        ie.source_ip,
        COUNT(DISTINCT ie.event_type)    AS distinct_attack_types,
        SUM(ie.event_count)              AS total_events,
        MIN(ie.hour_bucket)              AS first_seen,
        MAX(ie.hour_bucket)              AS last_seen,
        COUNT(DISTINCT t.threat_actor)   AS linked_actors
    FROM      ip_events  ie
    LEFT JOIN events     e  USING (source_ip)
    LEFT JOIN threats    t  ON t.event_id = e.event_id
    GROUP BY  ie.source_ip
    HAVING    COUNT(DISTINCT ie.event_type) >= 2
           OR SUM(ie.event_count) > 5
)
SELECT *,
    ROUND(total_events::NUMERIC / NULLIF(distinct_attack_types, 0), 2)
        AS events_per_type
FROM  suspects
ORDER BY total_events DESC
LIMIT 20;


-- ----------------------------------------------------------------
--  QUERY 3: RISK ASSESSMENT (Composite Score)
--  CVSS (40%) + Confidence (30%) + Alert Severity (20%) + No Patch (10%)
-- ----------------------------------------------------------------
SELECT
    v.vuln_id,
    v.cve_id,
    v.cvss_score,
    v.affected_system,
    v.patch_available,
    t.threat_actor,
    t.attack_vector,
    t.confidence_score,
    a.severity                              AS alert_severity,
    ROUND(
        (v.cvss_score          * 0.40)
      + (t.confidence_score    * 0.30 / 10)
      + (CASE a.severity
             WHEN 'CRITICAL' THEN 3.0
             WHEN 'HIGH'     THEN 2.0
             WHEN 'MEDIUM'   THEN 1.0
             ELSE 0.5
         END                   * 0.20)
      + (CASE WHEN v.patch_available THEN 0 ELSE 1.5 END),
    2)                                      AS composite_risk_score,
    CASE
        WHEN v.cvss_score >= 9.0 THEN 'CRITICAL'
        WHEN v.cvss_score >= 7.0 THEN 'HIGH'
        WHEN v.cvss_score >= 4.0 THEN 'MEDIUM'
        ELSE                          'LOW'
    END                                     AS risk_band
FROM       vulnerabilities  v
JOIN       threats          t  ON t.event_id  = v.event_id
JOIN       events           e  ON e.event_id  = v.event_id
LEFT JOIN  alerts           a  ON a.event_id  = e.event_id
WHERE  t.status IN ('ACTIVE', 'CONTAINED')
  AND  v.patched = FALSE
ORDER  BY composite_risk_score DESC;


-- ----------------------------------------------------------------
--  QUERY 4: THREAT INTELLIGENCE PROFILE
--  Har threat actor ka poora profile — kaun kitni baar aaya
-- ----------------------------------------------------------------
SELECT
    t.threat_actor,
    t.attack_vector,
    COUNT(DISTINCT t.threat_id)             AS incident_count,
    COUNT(DISTINCT v.cve_id)               AS cves_exploited,
    ROUND(AVG(v.cvss_score)::NUMERIC, 2)   AS avg_cvss,
    MAX(t.confidence_score)                AS max_confidence,
    ARRAY_AGG(DISTINCT e.source_ip::TEXT)  AS observed_ips,
    JSONB_AGG(DISTINCT t.ioc_data->> 'type')  AS ioc_types,
    MIN(e.created_at)                      AS first_observed,
    MAX(e.created_at)                      AS last_observed
FROM      threats          t
JOIN      events           e  ON e.event_id = t.event_id
LEFT JOIN vulnerabilities  v  ON v.event_id = t.event_id
WHERE  t.threat_actor IS NOT NULL
GROUP  BY t.threat_actor, t.attack_vector
HAVING COUNT(DISTINCT t.threat_id) >= 1
ORDER  BY incident_count DESC, avg_cvss DESC;


-- ----------------------------------------------------------------
--  QUERY 5: PRIORITIZE INCIDENT RESPONSE TASKS
--  Kaun sa kaam pehle karo — severity + completion status
-- ----------------------------------------------------------------
SELECT
    m.action_id,
    m.task_name,
    m.assigned_to,
    m.action_type,
    m.completed_steps,
    m.total_steps,
    ROUND(
        m.completed_steps::NUMERIC
        / NULLIF(m.total_steps, 0) * 100, 1
    )                                       AS pct_complete,
    e.severity,
    e.event_type,
    CASE e.severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH'     THEN 2
        WHEN 'MEDIUM'   THEN 3
        ELSE 4
    END                                     AS priority_rank,
    m.status,
    m.created_at,
    -- Kitna time ho gaya
    ROUND(
        EXTRACT(EPOCH FROM (NOW() - m.created_at)) / 60
    , 0)                                    AS age_minutes
FROM   mitigation_actions  m
JOIN   events              e  ON e.event_id = m.event_id
WHERE  m.status != 'RESOLVED'
ORDER  BY priority_rank ASC, m.created_at ASC;


-- ----------------------------------------------------------------
--  BONUS QUERY: DASHBOARD STATS (Ek query mein sab numbers)
-- ----------------------------------------------------------------
SELECT
    (SELECT COUNT(*)
     FROM   events
     WHERE  created_at >= NOW() - INTERVAL '24 hours')  AS events_today,

    (SELECT COUNT(*)
     FROM   alerts
     WHERE  status != 'RESOLVED')                        AS open_alerts,

    (SELECT COUNT(*)
     FROM   alerts
     WHERE  severity = 'CRITICAL'
       AND  status   != 'RESOLVED')                      AS critical_alerts,

    (SELECT COUNT(*)
     FROM   threats
     WHERE  status = 'ACTIVE')                           AS active_threats,

    (SELECT COUNT(*)
     FROM   vulnerabilities
     WHERE  patched = FALSE)                             AS open_vulns,

    (SELECT COUNT(*)
     FROM   alerts
     WHERE  status = 'RESOLVED')                         AS resolved_count,

    (SELECT ROUND(AVG(
         EXTRACT(EPOCH FROM (resolved_at - created_at)) / 60
     ), 1)
     FROM   alerts
     WHERE  resolved_at IS NOT NULL)                     AS avg_mttr_minutes,

    (SELECT ROUND(AVG(cvss_score), 1)
     FROM   vulnerabilities
     WHERE  patched = FALSE)                             AS avg_risk_score;


-- ================================================================
--  VERIFY: Sab tables check karo
-- ================================================================
SELECT
    tablename,
    pg_size_pretty(pg_total_relation_size(quote_ident(tablename))) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;
