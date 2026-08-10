/* ============================================================
   WAF Security Console -- Chart Renderers
   ============================================================ */

let charts = {};

function chartDefaults() {
  Chart.defaults.color = '#a1a1aa';
  Chart.defaults.borderColor = '#27272a';
  Chart.defaults.font.family = "'Inter', -apple-system, sans-serif";
  Chart.defaults.animation = {
    duration: 600,
    easing: 'easeOutQuart'
  };
  
  // Explicitly configure high-contrast tooltips for all charts with formatted total counts and percentages
  Chart.defaults.plugins.tooltip.enabled = true;
  Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(20, 20, 23, 0.95)';
  Chart.defaults.plugins.tooltip.titleColor = '#ffffff';
  Chart.defaults.plugins.tooltip.bodyColor = '#e4e4e7';
  Chart.defaults.plugins.tooltip.borderColor = '#3f3f46';
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.padding = 12;
  Chart.defaults.plugins.tooltip.cornerRadius = 8;
  Chart.defaults.plugins.tooltip.displayColors = true;
  Chart.defaults.plugins.tooltip.callbacks = {
    label: function(context) {
      const label = context.label || context.dataset.label || '';
      const rawVal = context.raw !== undefined ? context.raw : context.parsed;
      const valNum = typeof rawVal === 'number' ? rawVal : Number(rawVal || 0);
      
      const chartType = context.chart.config.type;
      if (chartType === 'doughnut' || chartType === 'pie') {
        const dataset = context.dataset;
        const total = dataset.data.reduce((acc, curr) => acc + (Number(curr) || 0), 0);
        const pct = total > 0 ? ((valNum / total) * 100).toFixed(1) + '%' : '0%';
        return ` ${label}: ${valNum.toLocaleString()} (${pct})`;
      }
      return ` ${label}: ${valNum.toLocaleString()}`;
    }
  };
}
chartDefaults();

function updateChartColors(isLight) {
  Chart.defaults.color = isLight ? '#71717a' : '#a1a1aa';
  Chart.defaults.borderColor = isLight ? '#e4e4e7' : '#27272a';
  
  // Re-render all charts to pick up the new colors immediately
  Object.values(charts).forEach(chart => {
      if (chart && typeof chart.update === 'function') {
          chart.update('none');
      }
  });
}

function renderStatusChart(blocked, passed) {
  const ctx = document.getElementById('statusChart');
  if (charts.status) {
    charts.status.data.datasets[0].data = [blocked, passed];
    charts.status.update('none');
    return;
  }
  
  charts.status = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Blocked','Passed'],
      datasets: [{
        data: [blocked, passed],
        backgroundColor: ['#dc2626','#16a34a'],
        borderWidth: 0,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: { display: true, text: 'Blocked vs Passed', font: { size: 13, weight: '600' } },
        legend: { position: 'bottom', labels: { usePointStyle: true } }
      },
      cutout: '70%'
    }
  });
}

function renderSevChart(sev) {
  const ctx = document.getElementById('sevChart');
  const labels = ['Critical','Error','Warning','Notice','Other'];
  const data   = [sev.CRITICAL||0, sev.ERROR||0, sev.WARNING||0, sev.NOTICE||0, sev.OTHER||0];
  
  if (charts.sev) {
    charts.sev.data.datasets[0].data = data;
    charts.sev.update('none');
    return;
  }

  const colors = ['#dc2626','#d97706','#eab308','#3b82f6','#a1a1aa'];
  charts.sev = new Chart(ctx, {
    type: 'pie',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0 }] },
    options: {
      responsive: true,
      plugins: {
        title: { display: true, text: 'Severity Distribution', font: { size: 13, weight: '600' } },
        legend: { position: 'bottom', labels: { usePointStyle: true, boxWidth: 8 } }
      }
    }
  });
}

function renderTrendChart(hourly) {
  const ctx = document.getElementById('trendChart');
  const labels = Object.keys(hourly).map(h => h.replace('T',' '));
  const data   = Object.values(hourly);

  if (charts.trend) {
    charts.trend.data.labels = labels;
    charts.trend.data.datasets[0].data = data;
    charts.trend.update('none');
    return;
  }

  const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 300);
  gradient.addColorStop(0, 'rgba(59,130,246,0.3)');
  gradient.addColorStop(1, 'rgba(59,130,246,0.0)');

  charts.trend = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Events',
        data,
        borderColor: '#3b82f6',
        backgroundColor: gradient,
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 6
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: { display: true, text: 'Event Trend', font: { size: 13, weight: '600' } },
        legend: { display: false }
      },
      scales: {
        x: { ticks: { maxTicksLimit: 8 } },
        y: { beginAtZero: true }
      }
    }
  });
}

function renderRuleChart(rules) {
  const ctx = document.getElementById('ruleChart');
  const labels = Object.keys(rules).map(k => k.length > 40 ? k.slice(0,40)+'...' : k);
  const data = Object.values(rules);
  
  if (charts.rule) {
    charts.rule.data.labels = labels;
    charts.rule.data.datasets[0].data = data;
    charts.rule.update('none');
    return;
  }

  charts.rule = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Hits',
        data,
        backgroundColor: '#3b82f6',
        borderRadius: 4,
        maxBarThickness: 28
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: {
        title: { display: true, text: 'Top Triggered Rules', font: { size: 13, weight: '600' } },
        legend: { display: false }
      },
      scales: {
        y: { grid: { display: false }, ticks: { font: { size: 11 } } }
      }
    }
  });
}

function renderIpChart(ips) {
  const ctx = document.getElementById('ipChart');
  const labels = Object.keys(ips);
  const data = Object.values(ips);
  
  if (charts.ip) {
    charts.ip.data.labels = labels;
    charts.ip.data.datasets[0].data = data;
    charts.ip.update('none');
    return;
  }

  charts.ip = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Requests',
        data,
        backgroundColor: '#d97706',
        borderRadius: 4,
        maxBarThickness: 32
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: { display: true, text: 'Top Source IPs', font: { size: 13, weight: '600' } },
        legend: { display: false }
      },
      scales: {
        x: { grid: { display: false } }
      }
    }
  });
}

function renderUrlChart(urls) {
  const ctx = document.getElementById('urlChart');
  const labels = Object.keys(urls).map(u => u.length > 35 ? u.slice(0,35)+'...' : u);
  const data = Object.values(urls);

  if (charts.url) {
    charts.url.data.labels = labels;
    charts.url.data.datasets[0].data = data;
    charts.url.update('none');
    return;
  }

  charts.url = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Hits',
        data,
        backgroundColor: '#8b5cf6',
        borderRadius: 4,
        maxBarThickness: 28
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: {
        title: { display: true, text: 'Top Attacked URLs', font: { size: 13, weight: '600' } },
        legend: { display: false }
      },
      scales: {
        y: { grid: { display: false }, ticks: { font: { size: 11 } } }
      }
    }
  });
}

function renderStatusDistChart(statuses) {
  const ctx = document.getElementById('statusDistChart');
  const labels = Object.keys(statuses);
  const data   = Object.values(statuses);
  const colors = labels.map(s =>
    s[0]==='2' ? '#16a34a' :
    s[0]==='3' ? '#d97706' :
    s[0]==='4' ? '#f97316' : '#dc2626'
  );

  if (charts.statusDist) {
    charts.statusDist.data.labels = labels;
    charts.statusDist.data.datasets[0].data = data;
    charts.statusDist.data.datasets[0].backgroundColor = colors;
    charts.statusDist.update('none');
    return;
  }

  charts.statusDist = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Count',
        data,
        backgroundColor: colors,
        borderRadius: 4,
        maxBarThickness: 36
      }]
    },
    options: {
      responsive: true,
      plugins: {
        title: { display: true, text: 'HTTP Status Distribution', font: { size: 13, weight: '600' } },
        legend: { display: false }
      },
      scales: {
        x: { grid: { display: false } }
      }
    }
  });
}

function renderBotClassChart(botCounts) {
  const ctx = document.getElementById('botClassChart');
  if (!ctx) return;
  
  const labels = Object.keys(botCounts);
  const data = Object.values(botCounts);
  const colors = labels.map(l => {
    if (l === 'human') return '#16a34a';
    if (l === 'verified_bot') return '#3b82f6';
    if (l === 'ai_agent') return '#8b5cf6';
    return '#dc2626';
  });

  if (charts.botClass) {
    charts.botClass.data.labels = labels;
    charts.botClass.data.datasets[0].data = data;
    charts.botClass.data.datasets[0].backgroundColor = colors;
    charts.botClass.update('none');
    return;
  }

  charts.botClass = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }] },
    options: {
      responsive: true,
      plugins: {
        title: { display: true, text: 'Traffic Classification', font: { size: 13, weight: '600' } },
        legend: { position: 'bottom', labels: { usePointStyle: true, boxWidth: 8 } }
      },
      cutout: '70%'
    }
  });
}

function renderThreatSparkline(hourlyThreatData, color) {
  const ctx = document.getElementById('threatSparkline');
  if (!ctx) return;
  
  const labels = Object.keys(hourlyThreatData || {});
  const data = Object.values(hourlyThreatData || {});

  const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 80);
  gradient.addColorStop(0, color + '80'); 
  gradient.addColorStop(1, color + '00'); 

  if (charts.threatSparkline) {
    charts.threatSparkline.data.labels = labels;
    charts.threatSparkline.data.datasets[0].data = data;
    charts.threatSparkline.data.datasets[0].borderColor = color;
    charts.threatSparkline.data.datasets[0].backgroundColor = gradient;
    charts.threatSparkline.update('none');
    return;
  }

  charts.threatSparkline = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        data: data,
        borderColor: color,
        borderWidth: 2,
        backgroundColor: gradient,
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        pointHoverRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          displayColors: false,
          callbacks: {
            label: function(context) { return 'Threat Index: ' + context.raw; }
          }
        }
      },
      scales: {
        x: { display: false },
        y: { 
          display: false,
          min: 0,
          max: 100 
        }
      },
      interaction: {
        mode: 'index',
        intersect: false
      }
    }
  });
}
