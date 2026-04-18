// ================================================================
//  frontend/api.js
//  Ye file frontend ko backend se connect karti hai
//  Har button click pe ye file backend ko request bhejti hai
//  Backend us request ko database se handle karta hai
// ================================================================

const API = 'http://localhost:3000/api';

// ── Logged in user ───────────────────────────────────────────
let currentUser = null;

// ================================================================
//  HELPER: fetch wrapper
// ================================================================
async function apiFetch(url, options = {}) {
  try {
    const res = await fetch(API + url, {
      headers: { 'Content-Type': 'application/json' },
      ...options
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Server error');
    }
    return await res.json();
  } catch (e) {
    // Agar server nahi chala toh demo mode mein fallback
    console.warn('API unavailable — demo mode:', e.message);
    return null;
  }
}

// ================================================================
//  AUTH API
// ================================================================
async function apiLogin(email, password) {
  const data = await apiFetch('/login', {
    method: 'POST',
    body: JSON.stringify({ email, password })
  });
  if (data?.success) {
    currentUser = data.user;
    return data.user;
  }
  return null;
}

// ================================================================
//  EVENTS API
// ================================================================
async function apiInjectEvent(eventData) {
  // Database mein save karo
  const data = await apiFetch('/events', {
    method: 'POST',
    body: JSON.stringify(eventData)
  });
  return data;
}

async function apiGetEvents() {
  return await apiFetch('/events') || [];
}

// ================================================================
//  ALERTS API
// ================================================================
async function apiGetAlerts() {
  return await apiFetch('/alerts') || [];
}

async function apiAcknowledgeAlert(alertId) {
  return await apiFetch(`/alerts/${alertId}/acknowledge`, {
    method: 'PATCH',
    body: JSON.stringify({ analyst: currentUser?.username || 'Analyst' })
  });
}

async function apiResolveAlert(alertId) {
  return await apiFetch(`/alerts/${alertId}/resolve`, {
    method: 'PATCH',
    body: JSON.stringify({ analyst: currentUser?.username || 'Analyst' })
  });
}

async function apiEscalateAlert(alertId) {
  return await apiFetch(`/alerts/${alertId}/escalate`, {
    method: 'PATCH'
  });
}

// ================================================================
//  THREATS API
// ================================================================
async function apiGetThreats() {
  return await apiFetch('/threats') || [];
}

async function apiAnalyzeThreat(threatId) {
  return await apiFetch(`/threats/${threatId}/analyze`, { method: 'PATCH' });
}

async function apiContainThreat(threatId) {
  return await apiFetch(`/threats/${threatId}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status: 'CONTAINED' })
  });
}

async function apiNeutralizeThreat(threatId) {
  return await apiFetch(`/threats/${threatId}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status: 'RESOLVED' })
  });
}

// ================================================================
//  VULNERABILITIES API
// ================================================================
async function apiGetVulns() {
  return await apiFetch('/vulns') || [];
}

async function apiPatchVuln(vulnId) {
  return await apiFetch(`/vulns/${vulnId}/patch`, { method: 'PATCH' });
}

// ================================================================
//  MITIGATIONS API
// ================================================================
async function apiGetMitigations() {
  return await apiFetch('/mitigations') || [];
}

async function apiAdvanceMitigation(actionId) {
  return await apiFetch(`/mitigations/${actionId}/advance`, { method: 'PATCH' });
}

async function apiCompleteMitigation(actionId) {
  return await apiFetch(`/mitigations/${actionId}/complete`, { method: 'PATCH' });
}

// ================================================================
//  DASHBOARD / REPORTS API
// ================================================================
async function apiGetDashboard() {
  return await apiFetch('/dashboard');
}

async function apiGetRiskReport() {
  return await apiFetch('/reports/risk') || [];
}

async function apiGetFullReport() {
  return await apiFetch('/reports/full') || [];
}

async function apiGetPatterns() {
  return await apiFetch('/reports/patterns') || [];
}

// ================================================================
//  AUTO-REFRESH: Har 10 second mein dashboard update karo
// ================================================================
async function startAutoRefresh() {
  setInterval(async () => {
    const stats = await apiGetDashboard();
    if (stats) {
      // Update header stats from real DB
      const el = id => document.getElementById(id);
      if (el('sc-critical')) el('sc-critical').textContent = stats.critical_alerts || 0;
      if (el('sc-alerts'))   el('sc-alerts').textContent   = stats.open_alerts     || 0;
      if (el('sc-threats'))  el('sc-threats').textContent  = stats.active_threats  || 0;
      if (el('sc-vulns'))    el('sc-vulns').textContent    = stats.open_vulns      || 0;
      if (el('sc-resolved')) el('sc-resolved').textContent = stats.resolved_count  || 0;
      if (el('sc-events'))   el('sc-events').textContent   = stats.events_today    || 0;
      if (stats.avg_mttr_minutes) {
        if (el('sc-mttr')) el('sc-mttr').textContent = stats.avg_mttr_minutes + 'm';
      }
      if (stats.avg_risk_score) {
        if (el('sc-risk')) el('sc-risk').textContent = stats.avg_risk_score + '/10';
      }
    }
  }, 10000); // har 10 second
}
