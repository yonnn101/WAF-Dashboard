/* ============================================================
   WAF Security Console -- Application Logic
   ============================================================ */

const REFRESH_INTERVAL = 10000;
let autoRefresh = true;
let refreshTimer = null;
let countdownTimer = null;
let lastDataHash = '';
let isRefreshing = false;

document.addEventListener('DOMContentLoaded', () => {
  // Load Theme
  const savedTheme = localStorage.getItem('waf_theme');
  if (savedTheme === 'light') {
    document.documentElement.classList.add('light-mode');
    if (typeof updateChartColors === 'function') updateChartColors(true);
  }

  // Theme Toggle Listener
  const themeToggleBtn = document.getElementById('themeToggle');
  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      document.documentElement.classList.toggle('light-mode');
      const isLight = document.documentElement.classList.contains('light-mode');
      localStorage.setItem('waf_theme', isLight ? 'light' : 'dark');
      if (typeof updateChartColors === 'function') updateChartColors(isLight);
      manualRefresh();
    });
  }

  loadPreferences();
  fetchData(true);
  startAutoRefresh();
  startHealthCheck();
  setupScrollSpy();
});

/* ---------- Drawer ---------- */
function openDrawer() {
  document.getElementById('drawerOverlay').classList.add('open');
  document.getElementById('filterDrawer').classList.add('open');
}
function closeDrawer() {
  document.getElementById('drawerOverlay').classList.remove('open');
  document.getElementById('filterDrawer').classList.remove('open');
}

/* ---------- Data Fetching ---------- */
let eventsVisibleLimit = 20;

async function fetchData(silent = false) {
  if (isRefreshing) return;
  if (!silent) eventsVisibleLimit = 20;
  isRefreshing = true;
  if (!silent) document.getElementById('refreshBtn').disabled = true;

  const form = document.getElementById('filterForm');
  const params = new URLSearchParams(new FormData(form));
  params.append('action', 'fetch_data');

  try {
    const t0 = performance.now();
    const res = await fetch('/api', {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
      body: params
    });
    const data = await res.json();
    const latency = Math.round(performance.now() - t0);

    if (data.error) {
      showError(data.error);
      updateHealth(false, latency);
    } else {
      hideError();
      renderDashboard(data);
      updateHealth(true, data.latency || latency);
      document.getElementById('lastUpdate').textContent = 'Updated ' + new Date().toLocaleTimeString();
    }
  } catch (e) {
    showError('Network error: ' + e.message);
    updateHealth(false, 0);
  } finally {
    isRefreshing = false;
    document.getElementById('refreshBtn').disabled = false;
  }
}

let refreshDebounce = null;
function manualRefresh() {
  if (refreshDebounce) clearTimeout(refreshDebounce);
  refreshDebounce = setTimeout(() => { fetchData(); }, 300);
}

/* ---------- Dashboard Rendering ---------- */
function renderDashboard(d) {
  // Stats
  updateStatValue('stTotal', d.stats.total);
  updateStatValue('stBlocked', d.stats.blocked);
  updateStatValue('stPassed', d.stats.passed);
  document.getElementById('stRate').textContent    = d.stats.block_rate + '%';
  document.getElementById('stRateSub').textContent = d.stats.total > 0 ? (d.stats.blocked + ' of ' + d.stats.total) : 'No data';
  updateStatValue('stNginx', d.server_counts.nginx ?? 0);
  updateStatValue('stApache', d.server_counts.apache ?? 0);

  // Charts
  renderStatusChart(d.stats.blocked, d.stats.passed);
  renderSevChart(d.sev_counts);
  renderTrendChart(d.hourly);
  renderRuleChart(d.top_rules);
  renderIpChart(d.top_ips);
  renderUrlChart(d.top_urls);
  renderStatusDistChart(d.status_counts);
  if (typeof renderBotClassChart === 'function' && d.bot_counts) renderBotClassChart(d.bot_counts);
  
  // Threat Index
  if (d.threat_index) {
      const ti = d.threat_index;
      
      const elScore = document.getElementById('threatScore');
      if (elScore) {
          elScore.textContent = ti.score;
          elScore.style.color = ti.color;
      }
      
      const elLevel = document.getElementById('threatLevel');
      if (elLevel) {
          elLevel.textContent = ti.level;
          elLevel.style.color = ti.color;
      }
      
      const elSafety = document.getElementById('safetyScore');
      if (elSafety) {
          elSafety.textContent = ti.safety_score;
      }
      
      const circumference = 339.292;
      const offset = circumference - (ti.score / 100) * circumference;
      const gaugeFills = document.querySelectorAll('.gauge-fill');
      gaugeFills.forEach(g => {
          g.style.setProperty('--gauge-color', ti.color);
          g.style.strokeDashoffset = offset;
      });
      
      let arrow = '−';
      if (ti.trend === 'rising') arrow = '↑';
      else if (ti.trend === 'falling') arrow = '↓';
      
      const trendEl = document.getElementById('threatTrend');
      if (trendEl) {
          trendEl.textContent = `${arrow} ${Math.abs(ti.trend_percent)}%`;
          trendEl.className = ti.trend;
          trendEl.style.color = ti.trend === 'rising' ? 'var(--warn)' : (ti.trend === 'falling' ? 'var(--ok)' : 'var(--muted)');
      }
      
      if (ti.components) {
          ['Volume', 'Severity', 'Spread', 'Velocity'].forEach(comp => {
              const val = ti.components[comp];
              const elVal = document.getElementById('val' + comp);
              const elBar = document.getElementById('bar' + comp);
              if (elVal) elVal.textContent = val;
              if (elBar) {
                  elBar.style.width = (val / 25 * 100) + '%';
                  elBar.style.setProperty('--gauge-color', ti.color);
              }
          });
      }
      
      document.title = `[${ti.level}] WAF Security Console`;
      
      if (typeof renderThreatSparkline === 'function' && d.hourly_threat_index) {
          renderThreatSparkline(d.hourly_threat_index, ti.color);
      }
  }

  // Sections
  renderInsights(d.insights, d.insight_summary);
  renderTopBotIps(d.top_bot_ips);
  renderAiAgents(d.ai_agents);
  renderThreatActors(d.ip_reputation, d.top_ips);
  renderEvents(d.events, d.stats.total);
  renderAccessLogs(d.access_rows);
  renderErrorLogs(d.error_rows);
  renderGeoSection(d.geo_countries, d.geo_markers);

  // Alert on new blocked events
  const hash = d.stats.blocked + '|' + d.stats.total;
  if (lastDataHash && hash !== lastDataHash && d.stats.blocked > 0) {
    const prevBlocked = parseInt(lastDataHash.split('|')[0]) || 0;
    if (d.stats.blocked > prevBlocked) {
      showToast('ALERT: ' + (d.stats.blocked - prevBlocked) + ' new blocked event(s) detected', 'error');
    }
  }
  lastDataHash = hash;
}

/* ---------- Section Renderers ---------- */

function renderInsights(insights, summary) {
  const section = document.getElementById('insightsSection');
  const container = document.getElementById('insightsContainer');
  const badge = document.getElementById('insightBadge');
  
  if (!section || !container) return;
  
  if (!insights || insights.length === 0) {
    section.style.display = 'none';
    container.style.display = 'none';
    return;
  }
  
  section.style.display = 'block';
  container.style.display = 'block';
  badge.textContent = `${summary.needs_action} Actionable`;
  
  badge.className = 'pill ' + (summary.critical > 0 ? 'crit' : summary.needs_action > 0 ? 'warn' : 'neutral');
  
  const typeIcons = {
    'brute_force': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--crit)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
    'escalation': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 7 13.5 15.5 8.5 10.5 2 17"></polyline><polyline points="16 7 22 7 22 13"></polyline></svg>',
    'new_attack_pattern': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--crit)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>',
    'coverage_gap': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
    'sensitive_probe': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
    'false_positive': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--ok)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>',
    'geo_anomaly': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>',
    'bot_campaign': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--crit)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"></rect><circle cx="12" cy="5" r="2"></circle><path d="M12 7v4"></path><line x1="8" y1="16" x2="8.01" y2="16"></line><line x1="16" y1="16" x2="16.01" y2="16"></line></svg>'
  };

  let html = `<div style="display:flex; flex-direction:column;">`;
  
  window.currentInsights = insights;
  
  insights.forEach(insight => {
    const icon = typeIcons[insight.type] || '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>';
    const conf = Math.round(insight.confidence * 100);
    
    let isLikelyFp = false;
    if (insight.confidence <= 0.7 && insight.affected_paths && insight.affected_paths.length > 0) {
       const staticPaths = ['/favicon.ico', '/robots.txt', '.png', '.jpg', '.css', '.js'];
       isLikelyFp = insight.affected_paths.some(p => staticPaths.some(sp => p.endsWith(sp) || p === sp));
    }
    const fpTag = isLikelyFp ? `<span class="pill" style="color:#58a6ff; border-color:#58a6ff;">Likely FP</span>` : '';
    
    html += `
    <div class="insight-row">
      <div class="insight-chk-wrap">
        <input type="checkbox" class="insight-chk" value="${insight.id}" onchange="onInsightChkChange(this)">
      </div>
      <div style="font-size:24px;">${icon}</div>
      <div style="flex:1;">
        <div style="display:flex; justify-content:space-between; margin-bottom:4px; align-items:center;">
          <h3 style="margin:0; font-size:14px; color:var(--text); cursor:pointer;" onclick="openInsightDetail('${insight.id}')" title="Click to view details">${esc(insight.title)}</h3>
          <div style="display:flex; gap:8px;">
            ${fpTag}
            <span class="pill" style="color:${insight.severity_color}; border-color:${insight.severity_color};">${insight.severity_label}</span>
            <span class="pill neutral">${conf}% Conf</span>
          </div>
        </div>
        <p style="margin:4px 0 8px 0; font-size:13px; color:var(--muted); line-height:1.4;">${esc(insight.description)}</p>
        
        <div style="display:flex; gap:16px; font-size:12px; color:var(--muted); margin-bottom:12px;">
          ${insight.affected_ips.length ? `<div><strong style="color:var(--text-light)">IPs:</strong> ${esc(insight.affected_ips.slice(0,3).join(', '))}${insight.affected_ips.length>3?'...':''}</div>` : ''}
          ${insight.affected_paths.length ? `<div><strong style="color:var(--text-light)">Paths:</strong> ${esc(insight.affected_paths.slice(0,2).join(', '))}${insight.affected_paths.length>2?'...':''}</div>` : ''}
          <div><strong style="color:var(--text-light)">Events:</strong> ${insight.event_count}</div>
        </div>
        
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <button class="btn primary" style="padding:4px 10px; font-size:12px;" onclick="openActionModal('${insight.id}', 'block')">Block IPs</button>
            <button class="btn" style="padding:4px 10px; font-size:12px;" onclick="openActionModal('${insight.id}', 'whitelist')">Whitelist Path</button>
            <button class="btn" style="padding:4px 10px; font-size:12px;" onclick="openActionModal('${insight.id}', 'rule')">Create Rule</button>
            <button class="btn" style="padding:4px 10px; font-size:12px;" onclick="openInsightDetail('${insight.id}')">View Details</button>
            <button class="btn" style="padding:4px 10px; font-size:12px;" onclick="dismissInsight('${insight.id}')">Dismiss</button>
        </div>
        
        ${insight.recommendation ? `
        <div style="margin-top:8px; padding:8px 12px; background:var(--panel-2); border-left:3px solid var(--accent); border-radius:4px; font-size:12px;">
          <strong style="color:var(--accent)">Recommendation:</strong> ${esc(insight.recommendation)}
        </div>` : ''}
      </div>
    </div>`;
  });
  
  html += `</div>`;
  container.innerHTML = html;
  toggleBulkBlockBtn();
}

let currentActionContext = { insightId: null, actionType: null, lang: 'nginx' };

window.switchConfigLang = function(lang) {
   currentActionContext.lang = lang;
   ['nginx', 'apache', 'modsec', 'iptables'].forEach(l => {
      const el = document.getElementById('lang-' + l);
      if (el) el.className = (l === lang) ? 'pill' : 'pill neutral';
   });
   
   const applyBtn = document.getElementById('actionModalApplyBtn');
   if (applyBtn) {
       applyBtn.style.display = (lang === 'modsec') ? 'inline-block' : 'none';
   }
   
   if (currentActionContext.insightId) {
      generateActionConfig();
   }
};

window.openActionModal = function(insightId, actionType) {
  const insight = (window.currentInsights || []).find(i => i.id === insightId);
  if (!insight) return;
  
  document.getElementById('actionModalTitle').textContent = `Review Action: ${insight.title}`;
  
  currentActionContext = { insightId, actionType, lang: 'nginx' };
  switchConfigLang('nginx');
  
  const resolveBtn = document.getElementById('actionModalResolveBtn');
  resolveBtn.onclick = () => window.markResolved(insightId);
  
  document.getElementById('actionModal').style.display = 'flex';
};

window.generateActionConfig = function() {
  const { insightId, actionType, lang } = currentActionContext;
  const insight = (window.currentInsights || []).find(i => i.id === insightId);
  if (!insight) return;

  let config = '';
  const ips = insight.affected_ips || [];
  const paths = insight.affected_paths || [];

  if (actionType === 'block') {
      if (lang === 'nginx') {
          if (insight.type === 'brute_force') {
              config = `# Nginx Rate Limiting\nlimit_req_zone $binary_remote_addr zone=auth_limit:10m rate=5r/m;\n\nlocation ${paths[0] || '/'} {\n    limit_req zone=auth_limit burst=10 nodelay;\n}`;
          } else {
              config = `# Nginx Deny\n`;
              if (ips.length) {
                  ips.forEach(ip => config += `deny ${ip};\n`);
              } else {
                  config += `# No specific IPs specified to block.\n`;
              }
          }
      } else if (lang === 'apache') {
          if (ips.length) {
              config = `<RequireAll>\n    Require all granted\n`;
              ips.forEach(ip => config += `    Require not ip ${ip}\n`);
              config += `</RequireAll>`;
          } else {
              config = `# No specific IPs specified to block.`;
          }
      } else if (lang === 'iptables') {
          if (ips.length) {
              config = `# iptables Block\n`;
              ips.forEach(ip => config += `iptables -A INPUT -s ${ip} -j DROP\n`);
          } else {
              config = `# No specific IPs specified to block.`;
          }
      } else if (lang === 'modsec') {
          config = `# ModSecurity IP Block Rule\n`;
          if (ips.length) {
              config += `SecRule REMOTE_ADDR "@pm ${ips.join(' ')}" \\\n  "id:10005,phase:1,deny,status:403,msg:'Blocked Malicious IP'"`;
          } else {
              config += `# No specific IPs specified to block.`;
          }
      }
  } else if (actionType === 'whitelist') {
      if (lang === 'nginx') {
          config = `location ${paths[0] || '/'} {\n    modsecurity off;\n    allow all;\n}`;
      } else if (lang === 'apache') {
          config = `<Location ${paths[0] || '/'}>\n    SecRuleEngine Off\n</Location>`;
      } else if (lang === 'modsec') {
          const rules = insight.affected_rules || [];
          if (rules.length) {
              config = `# Whitelist path for specific rules\n`;
              config += `SecRule REQUEST_URI "@beginsWith ${paths[0] || '/'}" \\\n  "id:10001,phase:1,pass,nolog,ctl:ruleRemoveById=${rules.join(',')}"`;
          } else {
              config = `# Disable ModSec engine for path\nSecRule REQUEST_URI "@beginsWith ${paths[0] || '/'}" \\\n  "id:10001,phase:1,pass,nolog,ctl:ruleEngine=Off"`;
          }
      } else if (lang === 'iptables') {
          config = `# iptables cannot whitelist HTTP paths.\n# Please use Nginx, Apache, or ModSecurity.`;
      }
  } else if (actionType === 'rule') {
      if (lang === 'modsec') {
          if (insight.type === 'new_attack_pattern') {
              config = `SecRule REQUEST_URI "@contains ${paths[0] || '/'}" \\\n  "id:10002,phase:2,block,t:none,t:lowercase,msg:'Custom rule blocking new attack pattern',logdata:'%{MATCHED_VAR}',tag:'custom_rule',severity:'CRITICAL',setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'"`;
          } else {
              config = `SecRule REQUEST_HEADERS:User-Agent "@contains BadBot" \\\n  "id:10003,phase:1,deny,status:403,msg:'Blocked Custom Bot'"`;
          }
      } else {
          config = `# Custom rules are best implemented in ModSecurity.\n# Select ModSecurity from the language switcher.`;
      }
  }

  document.getElementById('actionModalConfig').textContent = config;
};

window.closeActionModal = function() {
  document.getElementById('actionModal').style.display = 'none';
};

window.copyActionText = function() {
  const text = document.getElementById('actionModalConfig').textContent;
  navigator.clipboard.writeText(text).then(() => {
    showToast('Config copied to clipboard!', 'success');
  });
};

window.markResolved = function(insightId) {
  closeActionModal();
  dismissInsight(insightId, true);
};

window.applyActionLive = function() {
    const configText = document.getElementById('actionModalConfig').textContent;
    if (!configText || !configText.includes('SecRule')) {
        return showToast('Only ModSecurity rules can be applied live directly from the dashboard.', 'error');
    }
    
    const btn = document.getElementById('actionModalApplyBtn');
    const ogText = btn.textContent;
    btn.textContent = 'Applying...';
    btn.disabled = true;
    
    const payload = new URLSearchParams();
    payload.append('action', 'add_custom_rule');
    payload.append('raw_text', configText);
    
    fetch('/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: payload
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            showToast('Action applied successfully!', 'success');
            if (currentActionContext.insightId) {
                window.markResolved(currentActionContext.insightId);
            } else {
                closeActionModal();
            }
            if (typeof loadRuleExplorer === 'function') loadRuleExplorer();
        } else {
            showToast(data.error || 'Failed to apply rule', 'error');
        }
    })
    .catch(err => showToast('Network error', 'error'))
    .finally(() => {
        btn.textContent = ogText;
        btn.disabled = false;
    });
};

window.dismissInsight = function(id, reload = true) {
  if (!id) return Promise.resolve();
  
  const idArray = (typeof id === 'string' ? id.split(',') : [id]).map(s => String(s).trim()).filter(Boolean);
  const idSet = new Set(idArray);
  
  if (window.currentInsights) {
    window.currentInsights = window.currentInsights.filter(i => !idSet.has(i.id));
    const openCount = window.currentInsights.filter(i => i.severity >= 3).length;
    const critCount = window.currentInsights.filter(i => i.severity >= 5).length;
    renderInsights(window.currentInsights, {
      total: window.currentInsights.length,
      critical: critCount,
      needs_action: openCount
    });
  }
  
  return fetch('/api', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'action=dismiss_insight&insight_id=' + encodeURIComponent(id)
  }).then(res => res.json()).then(data => {
    if (data.success && reload) {
      fetchData(); 
    }
    return data;
  });
};

window.onInsightChkChange = function(chk) {
  const row = chk.closest('.insight-row');
  if (row) {
    if (chk.checked) row.classList.add('selected');
    else row.classList.remove('selected');
  }
  toggleBulkBlockBtn();
};

window.selectAllInsights = function() {
  document.querySelectorAll('.insight-chk').forEach(chk => {
    chk.checked = true;
    const row = chk.closest('.insight-row');
    if (row) row.classList.add('selected');
  });
  toggleBulkBlockBtn();
};

window.deselectAllInsights = function() {
  document.querySelectorAll('.insight-chk').forEach(chk => {
    chk.checked = false;
    const row = chk.closest('.insight-row');
    if (row) row.classList.remove('selected');
  });
  toggleBulkBlockBtn();
};

window.openInsightDetail = function(insightId) {
  const insight = (window.currentInsights || []).find(i => i.id === insightId);
  if (!insight) return;
  
  const modal = document.getElementById('detailModal');
  const modalBody = document.getElementById('modalBody');
  if (!modal || !modalBody) return;
  
  const title = modal.querySelector('h3');
  if (title) title.textContent = 'Insight Details';
  
  const esc = (str) => {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  };
  
  let html = `<div style="margin-bottom:16px;">
    <h4 style="margin:0 0 8px 0; color:var(--text-strong)">${esc(insight.title)}</h4>
    <p style="color:var(--muted); font-size:13px; line-height:1.5;">${esc(insight.description)}</p>
  </div>`;
  
  if (insight.affected_ips && insight.affected_ips.length > 0) {
    html += `<div style="margin-bottom:12px;">
      <strong style="display:block; margin-bottom:4px; font-size:12px; color:var(--text-light)">Affected IPs:</strong>
      <div style="background:var(--panel-2); padding:8px; border-radius:4px; font-family:monospace; font-size:12px; max-height:100px; overflow-y:auto;">
        ${insight.affected_ips.map(ip => `<div>${esc(ip)}</div>`).join('')}
      </div>
    </div>`;
  }
  
  if (insight.affected_paths && insight.affected_paths.length > 0) {
    html += `<div style="margin-bottom:12px;">
      <strong style="display:block; margin-bottom:4px; font-size:12px; color:var(--text-light)">Affected Paths:</strong>
      <div style="background:var(--panel-2); padding:8px; border-radius:4px; font-family:monospace; font-size:12px; max-height:100px; overflow-y:auto;">
        ${insight.affected_paths.map(p => `<div>${esc(p)}</div>`).join('')}
      </div>
    </div>`;
  }
  
  if (insight.recommendation) {
    html += `<div style="margin-bottom:12px; padding:8px 12px; background:var(--panel-2); border-left:3px solid var(--accent); border-radius:4px; font-size:12px;">
      <strong style="color:var(--accent)">Recommendation:</strong> ${esc(insight.recommendation)}
    </div>`;
  }
  
  modalBody.innerHTML = html;
  modal.style.display = 'flex';
};

window.toggleBulkBlockBtn = function() {
    const total = document.querySelectorAll('.insight-chk').length;
    const checked = document.querySelectorAll('.insight-chk:checked');
    const bulkBtn = document.getElementById('bulkBlockBtn');
    const bulkDismissBtn = document.getElementById('bulkDismissBtn');
    const selectAllBtn = document.getElementById('selectAllBtn');
    const deselectAllBtn = document.getElementById('deselectAllBtn');

    if (bulkBtn) {
      bulkBtn.style.display = checked.length > 0 ? 'inline-flex' : 'none';
      bulkBtn.textContent = checked.length > 1 ? `Block Selected (${checked.length})` : 'Block Selected';
    }
    if (bulkDismissBtn) {
      bulkDismissBtn.style.display = checked.length > 0 ? 'inline-flex' : 'none';
      bulkDismissBtn.textContent = checked.length > 1 ? `Dismiss Selected (${checked.length})` : 'Dismiss Selected';
    }
    if (selectAllBtn) {
      selectAllBtn.style.display = (total > 0 && checked.length < total) ? 'inline-flex' : 'none';
    }
    if (deselectAllBtn) {
      deselectAllBtn.style.display = checked.length > 0 ? 'inline-flex' : 'none';
    }
};

window.bulkBlockSelected = function() {
    const checked = Array.from(document.querySelectorAll('.insight-chk:checked')).map(cb => cb.value);
    if (checked.length === 0) return;
    
    let allIps = new Set();
    checked.forEach(id => {
        const insight = window.currentInsights.find(i => i.id === id);
        if (insight && insight.affected_ips) {
            insight.affected_ips.forEach(ip => allIps.add(ip));
        }
    });
    
    const mockInsight = {
        id: checked.join(','), 
        title: `Bulk Block (${checked.length} selected insights)`,
        type: 'bulk',
        affected_ips: Array.from(allIps),
        affected_paths: []
    };
    
    window.currentInsights.push(mockInsight);
    openActionModal(mockInsight.id, 'block');
};

window.bulkDismissSelected = function() {
    const checked = Array.from(document.querySelectorAll('.insight-chk:checked')).map(cb => cb.value);
    if (checked.length === 0) return;
    
    if (!confirm(`Are you sure you want to dismiss ${checked.length} selected insights?`)) return;
    
    dismissInsight(checked.join(','), true)
      .then(() => showToast(`Dismissed ${checked.length} insights`, 'success'))
      .catch(() => showToast('Error dismissing insights', 'error'));
};

function renderThreatActors(rep, topIps) {
  const panel = document.getElementById('threatActorsPanel');
  if (!rep || !Object.keys(rep).length) {
    panel.innerHTML = '<p class="notice">No threat data available.</p>';
    return;
  }

  const rows = Object.entries(rep).slice(0, 6).map(([ip, score]) => {
    const level = score >= 20 ? 'critical' : score >= 10 ? 'high' : score >= 5 ? 'medium' : 'low';
    const color = level === 'critical' ? '#f85149' : level === 'high' ? '#ff8a3d' : level === 'medium' ? '#e3b341' : '#3fb950';
    const hits = topIps[ip] || 0;
    return `<div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border)">
      <div style="width:120px;font-family:monospace;font-size:.9em">${esc(ip)}</div>
      <div style="flex:1"><div style="height:6px;background:var(--panel-2);border-radius:3px;overflow:hidden">
        <div style="width:${Math.min(score * 3, 100)}%;height:100%;background:${color};border-radius:3px;transition:width .5s"></div>
      </div></div>
      <div style="width:70px;text-align:right;font-size:.85em;font-weight:700;color:${color}">${level.toUpperCase()}</div>
      <div style="width:60px;text-align:right;color:var(--muted);font-size:.8em">${hits} hits</div>
    </div>`;
  }).join('');
  panel.innerHTML = rows;
}

function renderTopBotIps(ips) {
  const panel = document.getElementById('topBotIpsPanel');
  if (!panel) return;
  if (!ips || !Object.keys(ips).length) {
    panel.innerHTML = '<div class="notice" style="padding:16px;">No bot IPs detected.</div>';
    return;
  }
  
  const classNames = {
    'human': 'Human',
    'verified_bot': 'Verified Bot',
    'likely_bot': 'Likely Bot',
    'ai_agent': 'AI Agent'
  };
  const classColors = {
    'human': 'ok',
    'verified_bot': 'neutral',
    'likely_bot': 'crit',
    'ai_agent': 'warn'
  };

  panel.innerHTML = `<table><thead><tr><th>IP Address</th><th>Avg Score</th><th>Type</th></tr></thead><tbody>` +
    Object.entries(ips).map(([ip, data]) => {
      let score = data;
      let type = 'unknown';
      if (typeof data === 'object') {
        score = data.score;
        type = data.class || 'unknown';
      }
      
      const typeLabel = classNames[type] || type;
      const typeColor = classColors[type] || 'neutral';
      
      return `<tr><td class="mono">${esc(ip)}</td><td><span class="pill ${score >= 60 ? 'crit' : 'warn'}">${score}</span></td><td><span class="pill ${typeColor}">${esc(typeLabel)}</span></td></tr>`;
    }).join('') + '</tbody></table>';
}

function renderAiAgents(agents) {
  const panel = document.getElementById('aiAgentsPanel');
  if (!panel) return;
  if (!agents || !agents.length) {
    panel.innerHTML = '<div class="notice" style="padding:16px;">No AI agents detected.</div>';
    return;
  }
  const recent = agents.slice(0, 10);
  panel.innerHTML = `<table><thead><tr><th>Time</th><th>User Agent</th></tr></thead><tbody>` +
    recent.map(a => `<tr><td style="white-space:nowrap">${timeAgo(a.event_time)}</td><td title="${esc(a.user_agent)}">${esc((a.user_agent||'').slice(0,40))}${a.user_agent?.length>40?'...':''}</td></tr>`).join('') + '</tbody></table>';
}

function renderEvents(events, total) {
  document.getElementById('eventCount').textContent = (events?.length || 0) + ' of ' + total.toLocaleString();
  const container = document.getElementById('eventsContainer');
  const btnWrap = document.getElementById('eventsShowMoreWrap');
  if (!events || !events.length) {
    container.innerHTML = '<div class="notice">No ModSecurity events match your filters. Try adjusting the time range or clearing filters.</div>';
    if(btnWrap) btnWrap.style.display = 'none';
    return;
  }

  const sevColor = s => ({
    CRITICAL: '#f85149', ERROR: '#ff8a3d', WARNING: '#e3b341', NOTICE: '#58a6ff'
  }[s?.toUpperCase()] || '#8b949e');

  const visibleEvents = events.slice(0, eventsVisibleLimit);

  container.innerHTML = '<div class="timeline">' + visibleEvents.map((e, idx) => {
    let rules = [];
    try {
      rules = Array.isArray(e.rules) ? e.rules : (typeof e.rules === 'string' ? JSON.parse(e.rules || '[]') : []);
    } catch(x) {}
    const isBlocked = !!e.blocked;
    return `<div class="tl-item ${isBlocked ? 'blocked' : ''}" onclick="openEventDetail(${idx})">
      <div class="tl-status">
        <span class="pill ${isBlocked ? 'crit' : 'ok'}">${isBlocked ? 'BLOCKED' : 'PASSED'}</span>
        <span class="pill neutral">${esc(e.server || '?')}</span>
        <span class="tl-time">${fmtTime(e.event_time)}<br><span style="opacity:0.7">${timeAgo(e.event_time)}</span></span>
      </div>
      <div class="tl-body">
        <div class="req">${esc(e.request_line || '')}</div>
        <div class="meta-row">
          <span>IP: ${esc(e.client_ip || '?')}</span>
          ${e.http_status ? `<span>Status: ${esc(e.http_status)}</span>` : ''}
          <span>${rules.length} rule${rules.length === 1 ? '' : 's'} matched</span>
          ${e.user_agent ? `<span title="${esc(e.user_agent)}">UA: ${esc(e.user_agent.slice(0, 40))}${e.user_agent.length > 40 ? '...' : ''}</span>` : ''}
        </div>
        ${rules.length ? `<div class="rules">${rules.map(r =>
          `<span class="rule-tag"><span class="sev-dot" style="background:${sevColor(r.severity)}"></span>#${esc(r.id || '?')} ${esc(r.msg || '')}</span>`
        ).join('')}</div>` : ''}
      </div>
    </div>`;
  }).join('') + '</div>';

  window._events = events;

  if (btnWrap) {
    btnWrap.style.display = events.length > eventsVisibleLimit ? 'flex' : 'none';
  }
}

function renderAccessLogs(rows) {
  window._accessRows = rows;
  document.getElementById('accessCount').textContent = (rows?.length || 0) + ' requests';
  const panel = document.getElementById('accessPanel');
  if (!rows || !rows.length) {
    panel.innerHTML = '<div class="notice">No access log entries.</div>';
    return;
  }

  panel.innerHTML = `<table><thead><tr><th>Server</th><th>IP</th><th>Time</th><th>Request</th><th>Status</th><th>Size</th></tr></thead><tbody>` +
    rows.map((r, idx) => {
      const s = r.http_status || '';
      const sClass = s ? (s[0] === '2' ? 'ok' : s[0] === '3' ? 'warn' : 'crit') : 'neutral';
      return `<tr onclick="openAccessLogDetail(${idx})" title="Click to view details">
        <td><span class="pill ${esc(r.server || '')==='nginx'?'ok':'crit'}">${esc(r.server || '?')}</span></td>
        <td>${esc(r.ip || '')}</td>
        <td>${esc(r.log_time || '')}</td>
        <td class="req-cell" title="${esc(r.request || '')}">${esc(r.request || '')}</td>
        <td><span class="pill ${sClass}">${esc(s)}</span></td>
        <td>${esc(r.size || '')}</td>
      </tr>`;
    }).join('') + '</tbody></table>';
}

function renderErrorLogs(rows) {
  document.getElementById('errorCount').textContent = 'last ' + (rows?.length || 0);
  const panel = document.getElementById('errorPanel');
  if (!rows || !rows.length) {
    panel.innerHTML = '<div class="notice">No recent errors.</div>';
    return;
  }
  panel.innerHTML = '<div class="errlog">' + rows.map(r =>
    `<pre>[${esc(r.server || '?')}] ${esc(r.message || '')}</pre>`
  ).join('') + '</div>';
}

/* ---------- Geolocation (Interactive Leaflet Map) ---------- */
let geoMap = null;
let markerClusterGroup = null;
let heatLayer = null;
let attackLinesGroup = null;
let currentMapView = 'markers';
let currentMarkers = [];
let serverLocation = { lat: 9.02, lng: 38.75 }; // Default: Addis Ababa

function renderGeoSection(countries, markers) {
  renderGeoCountries(countries);
  renderGeoMap(markers, countries);
  const total = (countries || []).reduce((s, c) => s + c.count, 0);
  document.getElementById('geoCount').textContent = total + ' geolocated hits';
}

function renderGeoMap(markers, countries) {
  const container = document.getElementById('geoMap');
  if (!container) return;

  currentMarkers = markers || [];

  const isLight = document.documentElement.classList.contains('light-mode');
  const tileUrl = isLight
    ? 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'
    : 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';

  if (!geoMap) {
    geoMap = L.map('geoMap', {
      center: [20, 15],
      zoom: 2,
      minZoom: 2,
      maxZoom: 18,
      zoomControl: true,
      scrollWheelZoom: true,
      worldCopyJump: true,
    });

    L.tileLayer(tileUrl, {
      attribution: '&copy; <a href="https://carto.com/">CARTO</a>',
      subdomains: 'abcd',
      maxZoom: 19,
    }).addTo(geoMap);

    markerClusterGroup = L.markerClusterGroup({
      maxClusterRadius: 50,
      spiderfyOnMaxZoom: true,
      showCoverageOnHover: true,
      zoomToBoundsOnClick: true,
      iconCreateFunction: function(cluster) {
        const count = cluster.getChildCount();
        let size = 'small';
        let radius = 30;
        if (count > 50) { size = 'large'; radius = 50; }
        else if (count > 10) { size = 'medium'; radius = 40; }
        return L.divIcon({
          html: `<div class="cluster-inner cluster-${size}">${count}</div>`,
          className: 'custom-cluster',
          iconSize: L.point(radius, radius),
        });
      },
    });

    heatLayer = L.heatLayer([], {
      radius: 30,
      blur: 20,
      maxZoom: 10,
      max: 1.0,
      gradient: { 0.2: '#3b82f6', 0.4: '#06b6d4', 0.6: '#22c55e', 0.8: '#f59e0b', 1.0: '#ef4444' },
    });

    attackLinesGroup = L.layerGroup();

    // Add default layer
    geoMap.addLayer(markerClusterGroup);
  } else {
    // Update tiles on theme change
    geoMap.eachLayer(l => { if (l instanceof L.TileLayer) geoMap.removeLayer(l); });
    L.tileLayer(tileUrl, {
      attribution: '&copy; <a href="https://carto.com/">CARTO</a>',
      subdomains: 'abcd',
      maxZoom: 19,
    }).addTo(geoMap);
  }

  // Clear all layers
  markerClusterGroup.clearLayers();
  heatLayer.setLatLngs([]);
  attackLinesGroup.clearLayers();

  if (!markers || !markers.length) return;

  const maxHits = Math.max(...markers.map(m => m.hits), 1);
  const heatPoints = [];
  const bounds = [];

  markers.forEach(m => {
    const lat = parseFloat(m.lat);
    const lng = parseFloat(m.lng);
    if (isNaN(lat) || isNaN(lng)) return;

    bounds.push([lat, lng]);

    // Heatmap point
    const intensity = Math.max(0.3, m.hits / maxHits);
    heatPoints.push([lat, lng, intensity]);

    // Create marker with custom icon
    const isBlocked = m.blocked;
    const markerColor = isBlocked ? '#ef4444' : '#3b82f6';
    const markerSize = Math.max(8, Math.min(24, 8 + (m.hits / maxHits) * 16));
    const flag = countryFlag(m.countryCode || '');

    const icon = L.divIcon({
      className: 'custom-marker-icon',
      html: `<div class="marker-dot" style="
        width:${markerSize}px;height:${markerSize}px;
        background:${markerColor};
        box-shadow:0 0 ${markerSize}px ${markerColor}80;
      "></div>`,
      iconSize: [markerSize, markerSize],
      iconAnchor: [markerSize / 2, markerSize / 2],
    });

    const marker = L.marker([lat, lng], { icon });

    // Rich popup
    const popupContent = `
      <div class="map-popup">
        <div class="popup-header">
          <span class="popup-flag">${flag}</span>
          <span class="popup-country">${esc(m.country || 'Unknown')}</span>
          ${m.city ? `<span class="popup-city">${esc(m.city)}</span>` : ''}
        </div>
        <div class="popup-details">
          <div class="popup-row"><span class="popup-label">IP Address</span><span class="popup-value mono">${esc(m.ip)}</span></div>
          <div class="popup-row"><span class="popup-label">Total Hits</span><span class="popup-value">${m.hits}</span></div>
          <div class="popup-row"><span class="popup-label">Status</span><span class="popup-value popup-status-${isBlocked ? 'blocked' : 'passed'}">${isBlocked ? '🚫 BLOCKED' : '✅ PASSED'}</span></div>
          <div class="popup-row"><span class="popup-label">Coordinates</span><span class="popup-value mono">${lat.toFixed(4)}, ${lng.toFixed(4)}</span></div>
        </div>
      </div>
    `;

    marker.bindPopup(popupContent, {
      className: 'custom-popup',
      maxWidth: 300,
      closeButton: true,
    });

    marker.on('mouseover', function() { this.openPopup(); });

    markerClusterGroup.addLayer(marker);

    // Attack lines from IP to server
    const line = L.polyline([[lat, lng], [serverLocation.lat, serverLocation.lng]], {
      color: isBlocked ? '#ef4444' : '#3b82f6',
      weight: Math.max(1, Math.min(4, m.hits / maxHits * 4)),
      opacity: 0.5,
      dashArray: '8,6',
      className: 'attack-line-animated',
    });

    line.bindPopup(`
      <div class="map-popup">
        <div class="popup-header">
          <span class="popup-flag">${flag}</span>
          <span class="popup-country">${esc(m.ip)} → Server</span>
        </div>
        <div class="popup-details">
          <div class="popup-row"><span class="popup-label">Origin</span><span class="popup-value">${esc(m.country || 'Unknown')}</span></div>
          <div class="popup-row"><span class="popup-label">Hits</span><span class="popup-value">${m.hits}</span></div>
          <div class="popup-row"><span class="popup-label">Action</span><span class="popup-value popup-status-${isBlocked ? 'blocked' : 'passed'}">${isBlocked ? 'BLOCKED' : 'PASSED'}</span></div>
        </div>
      </div>
    `, { className: 'custom-popup' });

    attackLinesGroup.addLayer(line);
  });

  // Add a server marker
  const serverIcon = L.divIcon({
    className: 'custom-marker-icon',
    html: `<div class="server-marker">🖥️</div>`,
    iconSize: [32, 32],
    iconAnchor: [16, 16],
  });
  const serverMarker = L.marker([serverLocation.lat, serverLocation.lng], { icon: serverIcon });
  serverMarker.bindPopup('<div class="map-popup"><div class="popup-header"><span class="popup-flag">🖥️</span><span class="popup-country">Your Server</span></div></div>', { className: 'custom-popup' });
  attackLinesGroup.addLayer(serverMarker);

  heatLayer.setLatLngs(heatPoints);

  // Fit bounds
  if (bounds.length) {
    geoMap.fitBounds(bounds, { padding: [40, 40], maxZoom: 6 });
  }

  // Apply current view
  setMapView(currentMapView);
}

function setMapView(view, btn) {
  currentMapView = view;

  // Update button states
  if (btn) {
    document.querySelectorAll('.geo-view-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
  }

  if (!geoMap) return;

  // Remove all overlay layers
  if (markerClusterGroup) geoMap.removeLayer(markerClusterGroup);
  if (heatLayer) geoMap.removeLayer(heatLayer);
  if (attackLinesGroup) geoMap.removeLayer(attackLinesGroup);

  // Add the selected layer
  switch (view) {
    case 'markers':
      geoMap.addLayer(markerClusterGroup);
      break;
    case 'heat':
      geoMap.addLayer(heatLayer);
      break;
    case 'lines':
      geoMap.addLayer(attackLinesGroup);
      break;
  }
}

function renderGeoCountries(countries) {
  const list = document.getElementById('geoCountryList');
  if (!countries || !countries.length) {
    list.innerHTML = '<div class="notice" style="text-align:center;color:var(--muted);padding:24px;">No geolocation data available.</div>';
    return;
  }

  const maxCount = countries[0].count;

  list.innerHTML = countries.map((c, i) => {
    const pct = maxCount > 0 ? Math.round((c.count / maxCount) * 100) : 0;
    const barColor = c.blocked > c.count / 2 ? 'var(--crit)' : 'var(--accent)';
    const flag = countryFlag(c.code);
    return `<div class="country-row">
      <div class="country-rank">${i + 1}</div>
      <div class="country-flag">${flag}</div>
      <div class="country-info">
        <div class="country-name-line">
          <span class="country-name">${esc(c.name)}</span>
          <span class="country-code">${esc(c.code)}</span>
        </div>
        <div class="country-bar-wrap"><div class="country-bar" style="width:${pct}%;background:${barColor}"></div></div>
      </div>
      <div class="country-stats">
        <div class="country-count">${c.count.toLocaleString()}</div>
        ${c.blocked > 0 ? '<div class="country-blocked">' + c.blocked + ' blocked</div>' : ''}
      </div>
    </div>`;
  }).join('');
}

function countryFlag(code) {
  if (!code || code.length !== 2 || code === 'XX') return '\u{1F310}';
  const lowerCode = code.toLowerCase();
  return `<img src="https://flagcdn.com/w20/${lowerCode}.png" srcset="https://flagcdn.com/w40/${lowerCode}.png 2x" alt="${code}" style="vertical-align: middle; border-radius: 2px; box-shadow: 0 0 2px rgba(0,0,0,0.3);">`;
}

/* ---------- Modal ---------- */
window.openEventDetail = function(idx) {
  const e = window._events?.[idx];
  if (!e) return;

  let rules = [];
  try {
    rules = Array.isArray(e.rules) ? e.rules : (typeof e.rules === 'string' ? JSON.parse(e.rules || '[]') : []);
  } catch(x) {}

  const sevColor = s => ({
    CRITICAL: '#f85149', ERROR: '#ff8a3d', WARNING: '#e3b341', NOTICE: '#58a6ff'
  }[s?.toUpperCase()] || '#8b949e');

  const html = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
      <div><label style="color:var(--muted);font-size:.75em">Server</label><div style="font-weight:700">${esc(e.server || '?')}</div></div>
      <div><label style="color:var(--muted);font-size:.75em">Time</label><div style="font-weight:700">${fmtTime(e.event_time)}</div></div>
      <div><label style="color:var(--muted);font-size:.75em">Client IP</label><div style="font-weight:700;font-family:monospace">${esc(e.client_ip || '?')}</div></div>
      <div><label style="color:var(--muted);font-size:.75em">HTTP Status</label><div style="font-weight:700">${esc(e.http_status || '--')}</div></div>
      <div><label style="color:var(--muted);font-size:.75em">Action</label><div style="font-weight:700;color:${e.blocked ? '#f85149' : '#2ea043'}">${e.blocked ? 'BLOCKED' : 'PASSED'}</div></div>
      <div><label style="color:var(--muted);font-size:.75em">Rules Matched</label><div style="font-weight:700">${rules.length}</div></div>
    </div>
    <div style="margin-bottom:16px"><label style="color:var(--muted);font-size:.75em">Request Line</label>
      <pre style="margin-top:6px">${esc(e.request_line || '--')}</pre>
    </div>
    ${e.user_agent ? `<div style="margin-bottom:16px"><label style="color:var(--muted);font-size:.75em">User-Agent</label>
      <pre style="margin-top:6px;white-space:pre-wrap">${esc(e.user_agent)}</pre>
    </div>` : ''}
    ${rules.length ? `<div><label style="color:var(--muted);font-size:.75em">Matched Rules</label>
      <div style="display:flex;flex-direction:column;gap:8px;margin-top:8px">
        ${rules.map(r => `<div style="padding:12px;background:var(--panel-2);border:1px solid var(--border);border-radius:8px;border-left:3px solid ${sevColor(r.severity)}">
          <div style="font-weight:700;margin-bottom:4px">#${esc(r.id || '?')} -- ${esc(r.msg || '')}</div>
          <div style="font-size:.85em;color:var(--muted)">Severity: <span style="color:${sevColor(r.severity)};font-weight:700">${esc(r.severity || '?')}</span></div>
        </div>`).join('')}
      </div>
    </div>` : ''}
    ${e.bot_analysis ? `<div style="margin-top:16px"><label style="color:var(--muted);font-size:.75em">Bot Analysis</label>
      <div style="display:flex;gap:8px;margin-top:6px;align-items:center;">
        <span class="pill ${e.bot_analysis.is_bot ? 'crit' : 'ok'}">Class: ${esc(e.bot_analysis.bot_class)}</span>
        <span class="pill neutral">Score: ${e.bot_analysis.bot_score}</span>
        ${e.bot_analysis.is_ai_agent ? '<span class="pill crit">AI Agent</span>' : ''}
      </div>
      ${e.bot_analysis.bot_signals && e.bot_analysis.bot_signals.length ? `
      <ul style="margin-top:8px;padding-left:20px;font-size:0.85em;color:var(--muted)">
        ${e.bot_analysis.bot_signals.map(s => `<li>${esc(s)}</li>`).join('')}
      </ul>` : ''}
    </div>` : ''}
    <div style="margin-top:16px"><label style="color:var(--muted);font-size:.75em">Raw JSON</label>
      <pre style="margin-top:6px;font-size:.8em">${esc(JSON.stringify(e, null, 2))}</pre>
    </div>
  `;
  document.getElementById('modalBody').innerHTML = html;
  document.getElementById('detailModal').classList.add('open');
};

window.openAccessLogDetail = function(idx) {
  const r = window._accessRows?.[idx];
  if (!r) return;

  const s = r.http_status || '';
  const sClass = s ? (s[0] === '2' ? '#16a34a' : s[0] === '3' ? '#d97706' : '#dc2626') : 'var(--text)';

  const html = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
      <div><label style="color:var(--muted);font-size:.75em">Server</label><div style="font-weight:700">${esc(r.server || '?')}</div></div>
      <div><label style="color:var(--muted);font-size:.75em">Log Time</label><div style="font-weight:700">${esc(r.log_time || '--')}</div></div>
      <div><label style="color:var(--muted);font-size:.75em">Client IP</label><div style="font-weight:700;font-family:monospace">${esc(r.ip || '?')}</div></div>
      <div><label style="color:var(--muted);font-size:.75em">HTTP Status</label><div style="font-weight:700;color:${sClass}">${esc(s || '--')}</div></div>
      <div><label style="color:var(--muted);font-size:.75em">Response Size</label><div style="font-weight:700">${esc(r.size || '--')} bytes</div></div>
    </div>
    <div style="margin-bottom:16px"><label style="color:var(--muted);font-size:.75em">Request Line</label>
      <pre style="margin-top:6px;white-space:pre-wrap;font-family:monospace">${esc(r.request || '--')}</pre>
    </div>
    <div style="margin-top:16px"><label style="color:var(--muted);font-size:.75em">Raw Log Object</label>
      <pre style="margin-top:6px;font-size:.8em">${esc(JSON.stringify(r, null, 2))}</pre>
    </div>
  `;
  document.getElementById('modalBody').innerHTML = html;
  document.getElementById('detailModal').classList.add('open');
};

window.openInsightDetail = function(insightId) {
  const insight = (window.currentInsights || []).find(i => i.id === insightId);
  if (!insight) return;

  const matchingEvents = (window._events || []).filter(e => {
    const ipMatch = (insight.affected_ips || []).includes(e.client_ip);
    const pathMatch = (insight.affected_paths || []).some(p => (e.request_line || '').includes(p));
    return ipMatch || pathMatch;
  });

  let eventsHtml = '';
  if (matchingEvents.length > 0) {
    eventsHtml = `
      <div style="margin-top:16px;">
        <label style="color:var(--muted);font-size:.75em;text-transform:uppercase;font-weight:600;">Triggered WAF Events (${matchingEvents.length})</label>
        <div style="display:flex; flex-direction:column; gap:8px; margin-top:8px; max-height:220px; overflow-y:auto;">
          ${matchingEvents.map((e) => {
            const isBlocked = !!e.blocked;
            const originalIndex = (window._events || []).indexOf(e);
            return `
              <div style="padding:10px 12px; background:var(--panel-2); border:1px solid var(--border); border-radius:6px; cursor:pointer; display:flex; justify-content:space-between; align-items:center;" onclick="openEventDetail(${originalIndex})">
                <div>
                  <div style="font-family:monospace; font-size:12px; font-weight:600; color:var(--text-strong);">${esc(e.request_line || '')}</div>
                  <div style="font-size:11px; color:var(--muted); margin-top:2px;">IP: ${esc(e.client_ip || '?')} &bull; ${fmtTime(e.event_time)}</div>
                </div>
                <span class="pill ${isBlocked ? 'crit' : 'ok'}">${isBlocked ? 'BLOCKED' : 'PASSED'}</span>
              </div>`;
          }).join('')}
        </div>
      </div>`;
  }

  const html = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
      <h2 style="margin:0; font-size:18px; color:var(--text-strong);">${esc(insight.title)}</h2>
      <span class="pill" style="color:${insight.severity_color}; border-color:${insight.severity_color};">${insight.severity_label}</span>
    </div>
    <p style="color:var(--text); font-size:14px; margin-bottom:16px; line-height:1.5;">${esc(insight.description)}</p>

    <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:16px; background:var(--panel-2); padding:14px; border-radius:8px; border:1px solid var(--border);">
      <div><label style="color:var(--muted);font-size:.75em">Confidence Score</label><div style="font-weight:700; font-size:14px; color:var(--accent);">${Math.round(insight.confidence * 100)}%</div></div>
      <div><label style="color:var(--muted);font-size:.75em">Total Events</label><div style="font-weight:700; font-size:14px;">${insight.event_count}</div></div>
      <div><label style="color:var(--muted);font-size:.75em">Affected IPs</label><div style="font-weight:600; font-size:12px; font-family:monospace;">${esc(insight.affected_ips.join(', ') || 'None')}</div></div>
      <div><label style="color:var(--muted);font-size:.75em">Target Paths</label><div style="font-weight:600; font-size:12px; font-family:monospace;">${esc(insight.affected_paths.join(', ') || 'None')}</div></div>
    </div>

    ${insight.recommendation ? `
    <div style="margin-bottom:16px; padding:12px 14px; background:var(--panel-2); border-left:4px solid var(--accent); border-radius:6px;">
      <strong style="color:var(--accent); font-size:13px;">Analyst Recommendation:</strong>
      <p style="margin:4px 0 0 0; font-size:13px; color:var(--text);">${esc(insight.recommendation)}</p>
    </div>` : ''}

    ${eventsHtml}

    <div style="margin-top:20px; display:flex; justify-content:flex-end; gap:8px;">
      <button class="btn primary" onclick="closeModal(); openActionModal('${insight.id}', 'block');">Block IPs</button>
      <button class="btn" onclick="closeModal(); dismissInsight('${insight.id}');">Dismiss Insight</button>
    </div>
  `;

  document.getElementById('modalBody').innerHTML = html;
  document.getElementById('detailModal').classList.add('open');
};

function closeModal() {
  document.getElementById('detailModal').classList.remove('open');
}

/* ---------- Filters ---------- */
function applyFilters(e) {
  if (e) e.preventDefault();
  const form = document.getElementById('filterForm');
  const params = new URLSearchParams(new FormData(form));
  const url = new URL(window.location.href);
  url.search = params.toString();
  window.history.replaceState({}, '', url);
  fetchData();
  savePreferences();
  closeDrawer();
}

function resetFilters() {
  document.getElementById('filterForm').reset();
  window.history.replaceState({}, '', window.location.pathname);
  fetchData();
  savePreferences();
}

function savePreferences() {
  const form = document.getElementById('filterForm');
  const prefs = {};
  new FormData(form).forEach((v, k) => prefs[k] = v);
  localStorage.setItem('waf_filters', JSON.stringify(prefs));
}

function loadPreferences() {
  try {
    const p = JSON.parse(localStorage.getItem('waf_filters') || '{}');
    const form = document.getElementById('filterForm');
    for (const [k, v] of Object.entries(p)) {
      const el = form.querySelector('[name="' + k + '"]');
      if (el) el.value = v;
    }
  } catch(e) {}
}

/* ---------- Auto Refresh ---------- */
function startAutoRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => { if (autoRefresh) fetchData(true); }, REFRESH_INTERVAL);
  startCountdown();
}

function toggleAuto() {
  autoRefresh = !autoRefresh;
  document.getElementById('autoBtn').textContent = autoRefresh ? 'Pause' : 'Resume';
  showToast(autoRefresh ? 'Auto-refresh enabled' : 'Auto-refresh paused', 'info');
}

function startCountdown() {
  let remaining = REFRESH_INTERVAL / 1000;
  if (countdownTimer) clearInterval(countdownTimer);
  countdownTimer = setInterval(() => {
    remaining--;
    if (remaining <= 0) remaining = REFRESH_INTERVAL / 1000;
    document.getElementById('refreshLabel').textContent = autoRefresh ? '(' + remaining + 's)' : '(paused)';
  }, 1000);
}

/* ---------- Health Check ---------- */
async function startHealthCheck() {
  const check = async () => {
    try {
      const fd = new FormData();
      fd.append('action', 'health_check');
      const res = await fetch('', {
        method: 'POST',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        body: fd
      });
      const d = await res.json();
      updateHealth(d.ok, d.latency);
    } catch(e) { updateHealth(false, 0); }
  };
  check();
  setInterval(check, 30000);
}

function updateHealth(ok, latency) {
  const pill = document.getElementById('healthPill');
  const txt  = document.getElementById('healthText');
  if (ok) {
    pill.classList.remove('error');
    txt.textContent = 'Healthy (' + latency + 'ms)';
  } else {
    pill.classList.add('error');
    txt.textContent = 'Unhealthy';
  }
}

/* ---------- UI Utilities ---------- */
function showError(msg) {
  const el = document.getElementById('errorBanner');
  el.textContent = 'Error: ' + msg;
  el.style.display = 'flex';
}

function hideError() {
  document.getElementById('errorBanner').style.display = 'none';
}

function showToast(msg, type = 'info') {
  const c = document.getElementById('toastContainer');
  const t = document.createElement('div');
  t.className = 'toast ' + type;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 5000);
}

async function exportCSV() {
  const form = document.getElementById('filterForm');
  const params = new URLSearchParams(new FormData(form));
  params.append('action', 'export_csv');
  try {
    const res = await fetch('/api', {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
      body: params
    });
    if (!res.ok) { showToast('Export failed', 'error'); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'waf-events-' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-') + '.csv';
    a.click();
    URL.revokeObjectURL(url);
    showToast('CSV exported successfully', 'info');
  } catch(e) {
    showToast('Export error: ' + e.message, 'error');
  }
}

/* ---------- Helpers ---------- */
function esc(s) {
  const d = document.createElement('div');
  d.textContent = String(s ?? '');
  return d.innerHTML;
}

function fmtTime(iso) {
  if (!iso) return '--';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}

function timeAgo(iso) {
  if (!iso) return '--';
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diff < 60)   return diff + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400)return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

function setupScrollSpy() {
  const navItems = document.querySelectorAll('.sidebar-nav .nav-item');
  if (!navItems.length) return;
  const observer = new IntersectionObserver((entries) => {
    let visibleId = null;
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        visibleId = entry.target.id;
      }
    });
    if (visibleId) {
      navItems.forEach(nav => {
        nav.classList.remove('active');
        if (nav.getAttribute('href') === '#' + visibleId) {
          nav.classList.add('active');
        }
      });
    }
  }, { rootMargin: '-10% 0px -70% 0px', threshold: 0 });

  navItems.forEach(nav => {
    const id = nav.getAttribute('href').substring(1);
    const el = document.getElementById(id);
    if (el) observer.observe(el);
  });
}

function animateValue(obj, start, end, duration) {
  if (!obj) return;
  let startTimestamp = null;
  const step = (timestamp) => {
    if (!startTimestamp) startTimestamp = timestamp;
    const progress = Math.min((timestamp - startTimestamp) / duration, 1);
    obj.innerHTML = Math.floor(progress * (end - start) + start).toLocaleString();
    if (progress < 1) {
      window.requestAnimationFrame(step);
    } else {
      obj.innerHTML = end.toLocaleString();
    }
  };
  window.requestAnimationFrame(step);
}

function updateStatValue(id, newValue) {
  const el = document.getElementById(id);
  if (!el) return;
  const current = parseInt(el.textContent.replace(/,/g, '')) || 0;
  if (current !== newValue) {
    animateValue(el, current, newValue, 800);
  }
}

window.toggleSidebar = function() {
  const sidebar = document.getElementById('sidebar');
  if (sidebar) sidebar.classList.toggle('mobile-open');
}

window.showMoreEvents = function() {
  eventsVisibleLimit += 20;
  if (window._events) {
    const totalEl = document.getElementById('stTotal');
    const total = totalEl ? parseInt(totalEl.textContent.replace(/,/g, '')) : window._events.length;
    renderEvents(window._events, total);
  }
}

// --- CRS Rule Explorer ---
let allCrsRules = [];

window.openRuleModal = function() {
  document.getElementById('ruleModal').classList.add('open');
  document.getElementById('ruleTerminalWrapper').style.display = 'block';
  document.getElementById('ruleTerminalOutput').textContent = '> WAF Admin Console Ready.\n> Waiting for commands...\n';
  loadRuleExplorer();
};

window.closeRuleModal = function() {
  document.getElementById('ruleModal').classList.remove('open');
  document.getElementById('addRuleRaw').value = '';
  const searchInput = document.getElementById('ruleSearchInput');
  if (searchInput) searchInput.value = '';
  if (document.getElementById('ruleStatusFilter')) document.getElementById('ruleStatusFilter').value = 'all';
  if (document.getElementById('ruleTypeFilter')) document.getElementById('ruleTypeFilter').value = 'all';
  if (document.getElementById('ruleHitFilter')) document.getElementById('ruleHitFilter').value = 'all';
  if (document.getElementById('ruleSortFilter')) document.getElementById('ruleSortFilter').value = 'default';
};

window.refreshRulesList = function(btnElement) {
  const origText = btnElement ? btnElement.innerHTML : '🔄 Refresh Rules';
  if (btnElement) {
      btnElement.disabled = true;
      btnElement.innerHTML = '🔄 Loading...';
  }
  
  fetch('/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'action=get_all_rules'
  }).then(r => r.json()).then(data => {
      if(data.success && data.data) {
          allCrsRules = data.data;
          renderRuleExplorer();
          showToast('Rule list refreshed');
      } else {
          showToast('Failed to refresh rules', 'error');
      }
  }).catch(e => {
      console.error(e);
      showToast('Error refreshing rules', 'error');
  }).finally(() => {
      if (btnElement) {
          btnElement.disabled = false;
          btnElement.innerHTML = origText;
      }
  });
};

window.loadRuleExplorer = function() {
  const listEl = document.getElementById('ruleExplorerList');
  listEl.innerHTML = '<div style="padding:16px; text-align:center; color:var(--muted); font-size:12px;">Loading rules from upstream...</div>';
  
  // Also check CRS version status when modal opens
  checkCrsStatus();

  fetch('/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'action=get_all_rules'
  }).then(r => r.json()).then(data => {
      if(data.success && data.data) {
          allCrsRules = data.data;
          renderRuleExplorer();
      } else {
          listEl.innerHTML = '<div style="padding:16px; color:var(--warn); font-size:12px;">Failed to load rules.</div>';
      }
  }).catch(e => {
      console.error(e);
      listEl.innerHTML = '<div style="padding:16px; color:var(--warn); font-size:12px;">Error connecting to API.</div>';
  });
};

window.checkCrsStatus = function() {
    const btn = document.getElementById('crsUpdateBtn');
    btn.textContent = 'Checking CRS version...';
    btn.disabled = true;

    fetch('/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=crs_status'
    }).then(r => r.json()).then(data => {
        if(data.success && data.data) {
            const st = data.data;
            if (st.up_to_date === 'false' || st.current !== st.latest) {
                btn.textContent = 'Update to latest CRS';
                btn.disabled = false;
                btn.classList.add('primary');
            } else {
                btn.textContent = 'Your CRS is up to date';
                btn.disabled = true;
                btn.classList.remove('primary');
                btn.style.opacity = '0.5';
            }
        }
    }).catch(e => {
        console.error('Error fetching CRS status:', e);
        btn.textContent = 'Failed to check CRS version';
    });
};

window.filterRules = function() {
    renderRuleExplorer();
};

window.renderRuleExplorer = function() {
  const listEl = document.getElementById('ruleExplorerList');
  listEl.innerHTML = '';
  
  if (allCrsRules.length === 0) {
      listEl.innerHTML = '<div style="padding:16px; text-align:center; color:var(--muted); font-size:12px;">No rules found.</div>';
      return;
  }
  
  const searchInput = document.getElementById('ruleSearchInput');
  const query = searchInput ? searchInput.value.toLowerCase().trim() : '';

  const statusFilter = document.getElementById('ruleStatusFilter') ? document.getElementById('ruleStatusFilter').value : 'all';
  const typeFilter = document.getElementById('ruleTypeFilter') ? document.getElementById('ruleTypeFilter').value : 'all';
  const hitFilter = document.getElementById('ruleHitFilter') ? document.getElementById('ruleHitFilter').value : 'all';
  const sortFilter = document.getElementById('ruleSortFilter') ? document.getElementById('ruleSortFilter').value : 'default';

  const filteredRules = allCrsRules.filter(r => {
      // Search query
      if (query) {
          const matchId = r.id ? r.id.toString().toLowerCase().includes(query) : false;
          const matchMsg = r.msg ? r.msg.toLowerCase().includes(query) : false;
          if (!matchId && !matchMsg) return false;
      }

      // Status filter
      if (statusFilter === 'active' && r.disabled) return false;
      if (statusFilter === 'disabled' && !r.disabled) return false;

      // Type filter (custom vs crs)
      const isCustom = r.is_custom || (r.file && (r.file.includes('REQUEST-948') || r.file.includes('local-rules.conf') || r.file.includes('custom')));
      if (typeFilter === 'custom' && !isCustom) return false;
      if (typeFilter === 'crs' && isCustom) return false;

      // Frequency / Hit filter
      if (hitFilter === 'frequent' && !r.hit) return false;

      return true;
  });

  // Apply sorting
  filteredRules.sort((a, b) => {
      if (sortFilter === 'newest_edited') {
          const aOrder = a.custom_order || 0;
          const bOrder = b.custom_order || 0;
          if (aOrder !== bOrder) return bOrder - aOrder;
          if (a.hit !== b.hit) return a.hit ? -1 : 1;
          return parseInt(a.id) - parseInt(b.id);
      } else if (sortFilter === 'id_asc') {
          return parseInt(a.id) - parseInt(b.id);
      } else if (sortFilter === 'id_desc') {
          return parseInt(b.id) - parseInt(a.id);
      } else {
          if (a.hit !== b.hit) return a.hit ? -1 : 1;
          return parseInt(a.id) - parseInt(b.id);
      }
  });

  if (filteredRules.length === 0) {
      listEl.innerHTML = '<div style="padding:16px; text-align:center; color:var(--muted); font-size:12px;">No matching rules found.</div>';
      return;
  }
  
  filteredRules.forEach(r => {
      const row = document.createElement('div');
      row.className = 'rule-row';
      row.style.cssText = `position:relative; z-index:1; display:grid; grid-template-columns: 80px 1fr 140px; gap:8px; padding:10px 12px; border-bottom:1px solid #222; align-items:center; background: ${r.disabled ? 'rgba(255,255,255,0.02)' : (r.hit ? 'rgba(255,255,255,0.04)' : 'transparent')};`;
      
      const idCol = document.createElement('div');
      idCol.style.cssText = `font-family:monospace; font-size:12px; color: ${r.disabled ? 'var(--muted)' : (r.hit ? 'var(--warn)' : 'var(--text)')}; font-weight:700; ${r.disabled ? 'opacity:0.6;' : ''}`;
      idCol.innerHTML = `${r.id} ${r.disabled ? '<span style="font-size:10px; color:var(--muted); font-weight:normal;">(Off)</span>' : (r.hit ? '<span title="Triggered in events" style="color:var(--warn)">🔥</span>' : '')}`;
      
      const descCol = document.createElement('div');
      descCol.style.cssText = `font-size:12px; color:${r.disabled ? 'var(--muted)' : 'var(--text)'}; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; ${r.disabled ? 'text-decoration:line-through; opacity:0.6;' : ''}`;
      descCol.title = r.msg;
      descCol.textContent = r.msg;
      
      const actCol = document.createElement('div');
      actCol.style.cssText = 'text-align:right; display:flex; gap:6px; justify-content:flex-end; align-items:center;';
      
      const menuWrap = document.createElement('div');
      menuWrap.className = 'rule-menu-wrap';
      
      const dotsBtn = document.createElement('button');
      dotsBtn.className = 'rule-dots-btn';
      dotsBtn.innerHTML = '&#8942;';
      dotsBtn.title = 'Rule Actions';
      dotsBtn.onclick = (e) => {
          e.stopPropagation();
          e.preventDefault();
          const isShown = dropdown.classList.contains('show');
          document.querySelectorAll('.rule-menu-dropdown').forEach(d => {
              d.classList.remove('show');
              const parentRow = d.closest('.rule-row');
              if (parentRow) parentRow.style.zIndex = '1';
          });
          if (!isShown) {
              dropdown.classList.add('show');
              row.style.zIndex = '100';
          }
      };
      
      const dropdown = document.createElement('div');
      dropdown.className = 'rule-menu-dropdown';
      
      // 1. Edit
      const itemEdit = document.createElement('button');
      itemEdit.className = 'rule-menu-item';
      itemEdit.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg> Edit';
      itemEdit.onclick = (e) => {
          e.stopPropagation();
          dropdown.classList.remove('show');
          openEditRuleModal(r.id);
      };
      
      // 2. Disable / Restore
      const itemToggle = document.createElement('button');
      itemToggle.className = 'rule-menu-item';
      if (r.disabled) {
          itemToggle.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--ok)" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg> <span style="color:var(--ok)">Restore</span>';
          itemToggle.onclick = (e) => {
              e.stopPropagation();
              dropdown.classList.remove('show');
              submitRuleAction('restore_rule', e.target, r.id);
          };
      } else {
          itemToggle.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg> <span style="color:var(--warn)">Disable</span>';
          itemToggle.onclick = (e) => {
              e.stopPropagation();
              dropdown.classList.remove('show');
              submitRuleAction('remove_rule', e.target, r.id);
          };
      }
      
      // 3. Delete
      const itemDelete = document.createElement('button');
      itemDelete.className = 'rule-menu-item danger';
      itemDelete.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg> Delete';
      itemDelete.onclick = (e) => {
          e.stopPropagation();
          dropdown.classList.remove('show');
          submitRuleAction('delete_rule', e.target, r.id);
      };
      
      dropdown.appendChild(itemEdit);
      dropdown.appendChild(itemToggle);
      dropdown.appendChild(itemDelete);
      
      menuWrap.appendChild(dotsBtn);
      menuWrap.appendChild(dropdown);
      
      actCol.appendChild(menuWrap);
      
      row.appendChild(idCol);
      row.appendChild(descCol);
      row.appendChild(actCol);
      listEl.appendChild(row);
  });
};

window.openEditRuleModal = function(ruleId) {
  const rule = allCrsRules.find(r => r.id == ruleId);
  if (!rule) return showToast('Rule not found', 'error');
  
  document.getElementById('editRuleId').value = rule.id;
  document.getElementById('editRuleRaw').value = rule.raw;
  document.getElementById('editRuleModal').classList.add('open');
};

window.submitRuleAction = function(action, btnElement, targetId) {
  const payload = { action: action };
  
  if (action === 'add_custom_rule') {
      const rawText = document.getElementById('addRuleRaw').value.trim();
      if (!rawText) return showToast('Rule code cannot be empty', 'error');
      
      const idMatch = rawText.match(/id\s*:\s*'?(\d+)'?/);
      if (idMatch) {
          const newId = idMatch[1];
          if (allCrsRules.some(r => r.id == newId)) {
              return showToast(`Error: Rule ID ${newId} already exists!`, 'error');
          }
      } else {
          return showToast('Warning: Could not detect a valid id: in your rule.', 'error');
      }

      if (!confirm(`Are you sure you want to add this custom rule?\nThis will validate the syntax and reload Nginx.`)) return;
      payload.raw_text = rawText;
  }
  else if (action === 'edit_rule') {
      const ruleId = document.getElementById('editRuleId').value;
      const rawText = document.getElementById('editRuleRaw').value.trim();
      if (!ruleId || !rawText) return showToast('Rule ID and raw text required', 'error');
      if (!confirm(`Are you sure you want to edit rule ${ruleId}?\nThis will validate syntax and reload Nginx.`)) return;
      payload.rule_id = ruleId;
      payload.raw_text = rawText;
  }
  else if (action === 'remove_rule') {
      const id = targetId;
      if(!id) return showToast('Rule ID required', 'error');
      if(!confirm(`Are you sure you want to disable rule ${id}?`)) return;
      payload.rule_id = id;
  }
  else if (action === 'restore_rule') {
      const id = targetId;
      if(!id) return showToast('Rule ID required', 'error');
      if(!confirm(`Are you sure you want to restore rule ${id}?`)) return;
      payload.rule_id = id;
  }
  else if (action === 'delete_rule') {
      const id = targetId;
      if(!id) return showToast('Rule ID required', 'error');
      if(!confirm(`Are you sure you want to PERMANENTLY delete rule ${id}?\nThis action cannot be undone.`)) return;
      payload.rule_id = id;
  }
  else if (action === 'update_crs') {
      if(!confirm('This will pull the latest ModSecurity Core Rule Set from upstream and reload Nginx. Continue?')) return;
  }
  
  const ogText = btnElement ? btnElement.textContent : '';
  if (btnElement) {
      btnElement.textContent = '...';
      btnElement.disabled = true;
  }
  
  document.getElementById('ruleTerminalWrapper').style.display = 'block';
  const term = document.getElementById('ruleTerminalOutput');
  term.textContent += `\n> ${action} ${payload.rule_id ? payload.rule_id : (payload.raw_text ? '...' : '')}\n`;
  term.scrollTop = term.scrollHeight;

  fetch('/api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
  }).then(r => r.json()).then(data => {
      if(data.output) term.textContent += data.output + '\n';
      
      if(data.success) {
          showToast(data.message || 'Operation successful');
          if (action === 'add_custom_rule') {
              document.getElementById('addRuleRaw').value = '';
          }
          if (action === 'edit_rule') {
              document.getElementById('editRuleModal').classList.remove('open');
          }
          if (action === 'add_custom_rule' || action === 'update_crs' || action === 'remove_rule' || action === 'restore_rule' || action === 'edit_rule' || action === 'delete_rule') {
              loadRuleExplorer();
          }
      } else {
          showToast(data.error || 'Operation failed', 'error');
          if(data.details) term.textContent += '\nDETAILS:\n' + data.details + '\n';
      }
  }).catch(err => {
      showToast('Network error', 'error');
  }).finally(() => {
      if (btnElement) {
          btnElement.textContent = ogText;
          btnElement.disabled = false;
      }
  });
};

document.addEventListener('click', (e) => {
    if (!e.target.closest('.rule-menu-wrap')) {
        document.querySelectorAll('.rule-menu-dropdown').forEach(d => {
            d.classList.remove('show');
            const parentRow = d.closest('.rule-row');
            if (parentRow) parentRow.style.zIndex = '1';
        });
    }
});
