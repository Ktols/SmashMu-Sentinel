// SMASH MU SENTINEL - FRONTEND CONTROLLER

let soundEnabled = true;
let isSimulating = false; // APAGADA POR DEFECTO: Captura 100% real
let socket = null;
let currentAlerts = [];
let currentPlayers = [];
let currentTeleKills = [];

// Audio Synthesizer para alertas
const audioCtx = new (window.AudioContext || window.webkitAudioContext)();

function playAlertSound(severity = 'CRITICAL') {
  if (!soundEnabled) return;
  try {
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);

    if (severity === 'CRITICAL') {
      // Tono agudo doble de alerta crítica
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, audioCtx.currentTime); // La5
      osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.15);
      gain.gain.setValueAtTime(0.2, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.15);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.15);
    } else {
      // Beep suave de advertencia
      osc.type = 'sine';
      osc.frequency.setValueAtTime(587.33, audioCtx.currentTime);
      gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.1);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.1);
    }
  } catch (e) {}
}

// Inicialización de WebSocket
function connectWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  socket = new WebSocket(`${protocol}//${window.location.host}`);

  socket.onopen = () => {
    document.getElementById('connection-status').textContent = 'MONITOR EN VIVO';
    document.querySelector('.badge-live').style.borderColor = 'rgba(16, 185, 129, 0.3)';
  };

  socket.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleSocketMessage(msg);
    } catch (e) {}
  };

  socket.onclose = () => {
    document.getElementById('connection-status').textContent = 'RECONECTANDO...';
    document.querySelector('.badge-live').style.borderColor = 'rgba(239, 68, 68, 0.3)';
    setTimeout(connectWebSocket, 2000);
  };
}

function handleSocketMessage(msg) {
  if (msg.type === 'INIT') {
    if (msg.data.status) {
      const st = msg.data.status;
      if (st.isSniffing) {
        document.getElementById('connection-status').textContent = `NPCAP ACTIVO: ${st.adapter}`;
      } else {
        document.getElementById('connection-status').textContent = 'ESPERANDO JUEGO';
      }
    }
    if (msg.data.windows) {
      renderWindows(msg.data.windows, msg.data.selectedWindow || 'ALL');
    }
    if (msg.data.snapshot) {
      renderRadar(msg.data.snapshot.players, msg.data.snapshot.alerts);
    }
    if (msg.data.teleKills) {
      renderTeleKills(msg.data.teleKills);
    }
    if (msg.data.hackers) {
      renderBlacklist(msg.data.hackers);
    }
  } else if (msg.type === 'HACKERS_UPDATE') {
    renderBlacklist(msg.data);
  } else if (msg.type === 'WINDOWS_UPDATE') {
    renderWindows(msg.data.windows, msg.data.selected);
  } else if (msg.type === 'PACKET_HEARTBEAT') {
    const el = document.getElementById('packet-counter');
    if (el) el.textContent = `${msg.data.packetCount.toLocaleString()} pkts`;
    const dot = document.getElementById('pulse-dot');
    if (dot) {
      dot.style.backgroundColor = '#38bdf8';
      setTimeout(() => { if (dot) dot.style.backgroundColor = '#10b981'; }, 200);
    }
  } else if (msg.type === 'RADAR_UPDATE') {
    renderRadar(msg.data.players, msg.data.alerts);
  } else if (msg.type === 'ALERT') {
    addAlert(msg.data);
    playAlertSound(msg.data.severity);
  } else if (msg.type === 'TELE_KILL_ALERT') {
    addTeleKill(msg.data);
    playAlertSound(msg.data.severity);
  } else if (msg.type === 'CLEARED') {
    currentPlayers = [];
    currentAlerts = [];
    renderRadar([], []);
  }
}

// Histórico de Hackers (Lista Negra)
let historicalHackers = [];
let blacklistQuery = '';

function renderBlacklist(hackers) {
  if (hackers) historicalHackers = hackers;

  const tbody = document.getElementById('blacklist-tbody');
  const badge = document.getElementById('hackers-count-badge');
  if (badge) badge.textContent = `${historicalHackers.length} Infractores`;

  if (!tbody) return;

  const filtered = blacklistQuery
    ? historicalHackers.filter(h => 
        (h.name || '').toLowerCase().includes(blacklistQuery) || 
        (h.characterClass || '').toLowerCase().includes(blacklistQuery) ||
        (h.primaryHack || '').toLowerCase().includes(blacklistQuery)
      )
    : historicalHackers;

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 2rem;">${blacklistQuery ? 'No se encontraron infractores para: "' + blacklistQuery + '"' : 'No hay infractores registrados aún.'}</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(h => {
    const lastDate = new Date(h.lastSeen);
    const dateStr = `📅 ${lastDate.toLocaleDateString()} 🕒 ${lastDate.toLocaleTimeString()}`;
    const profileUrl = `https://www.smashmu.com/es/profile/${encodeURIComponent(h.name)}?realm=smash`;

    return `
      <tr>
        <td>
          <div style="display: flex; align-items: center; gap: 0.5rem;">
            <strong style="color: #f87171; font-size: 1rem;">${h.name}</strong>
            <a href="${profileUrl}" target="_blank" class="btn" style="padding: 0.2rem 0.5rem; font-size: 0.7rem; background: #0284c7; color: white;">
              🌐 SmashMU ↗
            </a>
          </div>
        </td>
        <td style="color: #cbd5e1;">${h.characterClass}</td>
        <td>
          <span class="badge critical">${h.primaryHack.replace(/_/g, ' ')}</span>
        </td>
        <td style="font-family: monospace; font-weight: 700; color: #f87171; font-size: 0.95rem;">
          ${h.worstMetric}
        </td>
        <td>
          <span class="badge suspicious">${h.infractionsCount} ${h.infractionsCount === 1 ? 'captura' : 'capturas'}</span>
        </td>
        <td style="color: #94a3b8; font-family: monospace; font-size: 0.78rem;">
          ${dateStr}
        </td>
        <td>
          <button class="btn active" onclick="generateTicketForHacker('${h.name}')" style="padding: 0.3rem 0.7rem; font-size: 0.75rem;">
            📋 Generar Ticket GM
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

window.filterBlacklist = function(query) {
  blacklistQuery = (query || '').toLowerCase().trim();
  renderBlacklist();
};

window.exportBlacklist = function() {
  const blob = new Blob([JSON.stringify(historicalHackers, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `smashmu_lista_negra_hackers_${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
};

window.generateTicketForHacker = function(name) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  const repBtn = document.querySelector('[data-tab="tab-reports"]');
  const repTab = document.getElementById('tab-reports');
  if (repBtn) repBtn.classList.add('active');
  if (repTab) repTab.classList.add('active');

  const hackerAlerts = currentAlerts.filter(a => (a.playerName || '').toLowerCase() === name.toLowerCase());
  updateReportText(hackerAlerts.length > 0 ? hackerAlerts : null);
};

let currentWindows = [];
let selectedWindowPort = 'ALL';

function renderWindows(windows, selected) {
  currentWindows = windows || [];
  if (selected !== undefined) selectedWindowPort = selected;

  const container = document.getElementById('windows-pills');
  const countEl = document.getElementById('windows-count');
  if (countEl) {
    countEl.textContent = `${currentWindows.length} Ventana(s) Activa(s)`;
    countEl.className = currentWindows.length > 0 ? 'badge clean' : 'badge suspicious';
  }

  if (!container) return;

  let html = `
    <button class="win-pill ${selectedWindowPort === 'ALL' ? 'active' : ''}" onclick="selectWindow('ALL')">
      🌐 Todas las Ventanas <span class="win-pill-badge">${currentPlayers.length} PJs</span>
    </button>
  `;

  currentWindows.forEach(w => {
    const isAct = String(selectedWindowPort) === String(w.port);
    const label = w.charName && !w.charName.startsWith('Ventana_') 
      ? `🪟 ${w.charName}` 
      : `🪟 Ventana (Puerto ${w.port})`;
    const sub = w.characterClass && w.characterClass !== 'Smash MU' ? ` · ${w.characterClass}` : '';
    html += `
      <button class="win-pill ${isAct ? 'active' : ''}" onclick="selectWindow(${w.port})" title="PID: ${w.pid} · Puerto TCP: ${w.port}">
        ${label}${sub} <span class="win-pill-badge">PID ${w.pid}</span>
      </button>
    `;
  });

  container.innerHTML = html;
}

window.selectWindow = function(port) {
  selectedWindowPort = port;
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ type: 'SELECT_WINDOW', port: port }));
  }
  renderWindows(currentWindows, selectedWindowPort);
};

// Seguimiento de estado para evitar parpadeo y cierre de acordiones al actualizar radar
const openForensics = new Set();
let lastRenderedAlertsCount = -1;
let lastRenderedFirstAlertId = null;

// Renderizado de Radar de Jugadores
function renderRadar(players, alerts) {
  currentPlayers = players || [];
  
  if (alerts) {
    const hasAlertsChanged = 
      alerts.length !== lastRenderedAlertsCount || 
      (alerts.length > 0 && alerts[0].id !== lastRenderedFirstAlertId);
      
    currentAlerts = alerts;
    
    if (hasAlertsChanged) {
      lastRenderedAlertsCount = alerts.length;
      lastRenderedFirstAlertId = alerts.length > 0 ? alerts[0].id : null;
      renderAlertsList();
      updateReportText();
    }
  }

  const tbody = document.getElementById('players-tbody');
  document.getElementById('players-count').textContent = `${currentPlayers.length} Jugadores`;

  if (currentPlayers.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 2rem;">No hay jugadores en rango...</td></tr>`;
    return;
  }

  tbody.innerHTML = currentPlayers.map(p => {
    // Velocidad física
    let speedColor = '#34d399';
    let speedLabel = 'Normal';
    if (p.currentSpeed >= 14) {
      speedColor = '#f87171';
      speedLabel = '🚨 SPEEDHACK';
    } else if (p.currentSpeed >= 11) {
      speedColor = '#fbbf24';
      speedLabel = 'Acelerado';
    }

    // Cadencia combo
    let comboColor = '#94a3b8';
    let comboText = 'Sin combo';
    if (p.lastComboCadence > 0) {
      if (p.lastComboCadence <= 160) {
        comboColor = '#f87171';
        comboText = `🚨 ${p.lastComboCadence}ms (BOT)`;
      } else if (p.lastComboCadence <= 500) {
        comboColor = '#fbbf24';
        comboText = `⚡ ${p.lastComboCadence}ms`;
      } else {
        comboColor = '#34d399';
        comboText = `🟢 ${p.lastComboCadence}ms`;
      }
    }

    // Auto pot
    let potColor = '#94a3b8';
    let potText = `${p.lastPotRate} p/s`;
    if (p.lastPotRate >= 18) {
      potColor = '#f87171';
      potText = `🚨 ${p.lastPotRate} p/s (AUTO)`;
    } else if (p.lastPotRate >= 10) {
      potColor = '#fbbf24';
      potText = `⚡ ${p.lastPotRate} p/s`;
    }

    // Status badge
    let badgeClass = 'clean';
    let badgeText = 'LEGAL';
    if (p.status === 'MY_CHAR') {
      badgeClass = 'clean';
      badgeText = '🛡️ MI CUENTA';
    } else if (p.status === 'CRITICAL') {
      badgeClass = 'critical';
      badgeText = '🚨 INFRACCIÓN';
    } else if (p.status === 'SUSPICIOUS') {
      badgeClass = 'suspicious';
      badgeText = '⚠️ SOSPECHOSO';
    }

    const smashLink = p.name.startsWith('Jugador_') 
      ? '' 
      : `<a href="https://www.smashmu.com/es/profile/${encodeURIComponent(p.name)}?realm=smash" target="_blank" class="btn" style="background: #0284c7; border: 1px solid #38bdf8; color: white; font-weight: 700; padding: 0.25rem 0.6rem; font-size: 0.75rem; border-radius: 4px; text-decoration: none; display: inline-flex; align-items: center; gap: 0.35rem; margin-top: 0.35rem;" title="Abrir perfil oficial en SmashMU.com">🌐 Ver en SmashMU ↗</a>`;

    return `
      <tr>
        <td>
          <div style="display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap;">
            <strong style="color: #38bdf8; font-size: 1rem;">${p.name}</strong>
            ${p.isMyAccount ? `<span class="badge clean" style="font-size: 0.65rem;">🛡️ MI PJ</span>` : ''}
            <span style="font-size: 0.75rem; color: #64748b; cursor: pointer;" title="Clic para renombrar ID" onclick="editPlayerName('${p.id}', '${p.name}')">✏️</span>
          </div>
          <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 0.15rem;">
            ${p.characterClass}${p.gearScore ? ' · GS: ' + p.gearScore : ''}
          </div>
          <div>${smashLink}</div>
        </td>
        <td>
          <span class="badge clean" style="font-size: 0.72rem; background: #1e293b; border: 1px solid #334155; color: #38bdf8; display: inline-flex; align-items: center; gap: 0.25rem;">
            ${p.windowOwner || 'Ventana Principal'}
          </span>
        </td>
        <td style="font-family: monospace; color: #94a3b8;">(${p.x}, ${p.y})</td>
        <td style="color: ${speedColor}; font-weight: 700; font-family: monospace;">
          ${p.currentSpeed} casillas/s <span style="font-size: 0.7rem; font-weight: 400;">(${speedLabel})</span>
        </td>
        <td style="color: ${comboColor}; font-weight: 700; font-family: monospace;">
          ${comboText}
        </td>
        <td style="color: ${potColor}; font-weight: 700; font-family: monospace;">
          ${potText}
        </td>
        <td>
          <span class="badge ${badgeClass}">${badgeText}</span>
        </td>
      </tr>
    `;
  }).join('');
}

let alertsSearchQuery = '';

window.onSearchAlerts = function(query) {
  alertsSearchQuery = (query || '').toLowerCase().trim();
  renderAlertsList();
};

function addAlert(alert) {
  if (!currentAlerts.some(a => a.id === alert.id)) {
    currentAlerts.unshift(alert);
    if (currentAlerts.length > 2000) currentAlerts.pop();
  }
  renderAlertsList();
  updateReportText();
}

function renderAlertsList() {
  const container = document.getElementById('alerts-feed');
  
  const filtered = alertsSearchQuery 
    ? currentAlerts.filter(a => 
        (a.playerName || '').toLowerCase().includes(alertsSearchQuery) || 
        (a.type || '').toLowerCase().includes(alertsSearchQuery) ||
        (a.characterClass || '').toLowerCase().includes(alertsSearchQuery)
      )
    : currentAlerts;

  const countEl = document.getElementById('alerts-count');
  if (countEl) {
    countEl.textContent = alertsSearchQuery 
      ? `${filtered.length} de ${currentAlerts.length} Alertas` 
      : `${currentAlerts.length} Alertas Históricas`;
  }

  if (filtered.length === 0) {
    container.innerHTML = `<div style="text-align: center; color: #64748b; padding: 2rem; font-size: 0.85rem;">
      ${alertsSearchQuery ? 'No se encontraron infracciones para: "' + alertsSearchQuery + '"' : 'No se registran infracciones en este momento.'}
    </div>`;
    return;
  }

  container.innerHTML = filtered.map(a => {
    const d = new Date(a.timestamp);
    const dateStr = d.toLocaleDateString();
    const timeStr = d.toLocaleTimeString();
    const isCritical = a.severity === 'CRITICAL';
    const profileUrl = `https://www.smashmu.com/es/profile/${encodeURIComponent(a.playerName)}?realm=smash`;
    const isExpanded = openForensics.has(a.id);

    return `
      <div class="alert-item ${isCritical ? 'critical' : 'warning'}">
        <div class="alert-head">
          <span style="color: ${isCritical ? '#f87171' : '#fbbf24'}; font-size: 0.85rem;">
            ${isCritical ? '🚨' : '⚠️'} ${a.type.replace(/_/g, ' ')}
          </span>
          <span class="alert-time" style="background: #1e293b; padding: 0.2rem 0.5rem; border-radius: 4px; font-family: monospace; color: #38bdf8; font-size: 0.72rem; border: 1px solid #334155;" title="Fecha y Hora exacta de la detección">
            📅 ${dateStr} · 🕒 ${timeStr}
          </span>
        </div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
          <div>
            <strong>Jugador:</strong> 
            ${!a.playerName.startsWith('Jugador_') ? `
              <a href="${profileUrl}" target="_blank" style="color: #38bdf8; text-decoration: underline; font-weight: 700;">
                ${a.playerName} ↗
              </a>
            ` : `
              <span style="color: #cbd5e1; font-weight: 700;">${a.playerName}</span>
              <span style="font-size: 0.72rem; color: #94a3b8; background: #334155; padding: 0.1rem 0.4rem; border-radius: 4px; margin-left: 0.3rem;">ID en telemetría</span>
            `}
            <span style="color: #94a3b8;">· Registro:</span> <span class="alert-metric">${a.metric}</span>
            <span style="font-size: 0.7rem; color: #64748b;">(Legal: ${a.limit})</span>
          </div>
          ${!a.playerName.startsWith('Jugador_') ? `
            <a href="${profileUrl}" target="_blank" class="btn" style="padding: 0.2rem 0.5rem; font-size: 0.7rem;">
              Ver Perfil ↗
            </a>
          ` : ''}
        </div>
        <div class="alert-details">${a.details}</div>
        ${a.forensics ? `
          <button id="btn-forensic-${a.id}" class="btn-forensic" onclick="toggleForensics('${a.id}')">
            ${isExpanded ? '🔼 Ocultar Desglose Técnico' : '🔬 Ver Desglose Forense Técnico ▼'}
          </button>
          <div id="forensic-${a.id}" class="forensic-box" style="display: ${isExpanded ? 'block' : 'none'};">
            <div class="forensic-row"><span class="forensic-label">📡 Método de Captura:</span> <span class="forensic-val">${a.forensics.method}</span></div>
            <div class="forensic-row"><span class="forensic-label">🎯 Socket Destino:</span> <span class="forensic-val">${a.forensics.serverTarget}</span></div>
            <div class="forensic-row"><span class="forensic-label">📐 Cálculo Físico:</span> <span class="forensic-val">${a.forensics.formula}</span></div>
            <div class="forensic-row"><span class="forensic-label">⚖️ Límite Motor S6:</span> <span class="forensic-val">${a.forensics.engineLimit}</span></div>
            <div class="forensic-row"><span class="forensic-label">📊 Desviación:</span> <span class="forensic-val" style="color: #f87171; font-weight: 700;">${a.forensics.deviation}</span></div>
            <div class="forensic-row" style="margin-top: 0.4rem; padding-top: 0.35rem; border-top: 1px solid #1e293b;">
              <span class="forensic-label">🛡️ Dictamen Técnico:</span> <div style="color: #cbd5e1; margin-top: 0.15rem;">${a.forensics.technicalVerdict}</div>
            </div>
          </div>
        ` : ''}
      </div>
    `;
  }).join('');
}

window.toggleForensics = function(alertId) {
  if (openForensics.has(alertId)) {
    openForensics.delete(alertId);
  } else {
    openForensics.add(alertId);
  }
  const el = document.getElementById('forensic-' + alertId);
  const btn = document.getElementById('btn-forensic-' + alertId);
  const isOpen = openForensics.has(alertId);
  if (el) {
    el.style.display = isOpen ? 'block' : 'none';
  }
  if (btn) {
    btn.textContent = isOpen ? '🔼 Ocultar Desglose Técnico' : '🔬 Ver Desglose Forense Técnico ▼';
  }
};

function addTeleKill(alert) {
  currentTeleKills.unshift(alert);
  if (currentTeleKills.length > 30) currentTeleKills.pop();
  renderTeleKills(currentTeleKills);
}

function renderTeleKills(teleKills) {
  currentTeleKills = teleKills || [];
  const tbody = document.getElementById('telekills-tbody');
  if (currentTeleKills.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 2rem;">Esperando registros de la siguiente ventana de invasión...</td></tr>`;
    return;
  }

  tbody.innerHTML = currentTeleKills.map(k => {
    const timeStr = new Date(k.timestamp).toLocaleTimeString();
    return `
      <tr>
        <td style="color: #94a3b8; font-family: monospace;">${timeStr}</td>
        <td><strong style="color: #38bdf8;">${k.playerName}</strong></td>
        <td><span style="color: #cbd5e1;">${k.guildName}</span></td>
        <td style="color: #f59e0b;">${k.firstBoss}</td>
        <td style="color: #ef4444;">${k.secondBoss}</td>
        <td style="font-family: monospace; font-weight: 700; color: #f87171;">${k.deltaSec} segundos</td>
        <td>
          <span class="badge ${k.severity === 'CRITICAL' ? 'critical' : 'suspicious'}">
            ${k.severity === 'CRITICAL' ? '🚨 IMPOSIBLE' : '⚠️ SOSPECHOSO'}
          </span>
        </td>
      </tr>
    `;
  }).join('');
}

// Inspector de Jugadores
async function inspectPlayer() {
  const name = document.getElementById('inspect-input').value.trim();
  if (!name) return;

  const btn = document.getElementById('btn-inspect');
  btn.textContent = 'Consultando...';
  btn.disabled = true;

  try {
    const res = await fetch(`/api/inspect/${encodeURIComponent(name)}`);
    const data = await res.json();

    if (!res.ok || data.error) {
      alert(data.error || 'Personaje no encontrado en Smash MU.');
      return;
    }

    document.getElementById('inspect-result').style.display = 'block';
    document.getElementById('char-name').textContent = data.character.name;
    document.getElementById('char-sub').textContent = `${data.character.className} · Resets: ${data.character.resets} · Guild: ${data.character.guild?.name || 'Sin Hermandad'}`;
    document.getElementById('char-link').href = `https://www.smashmu.com/es/profile/${encodeURIComponent(data.character.name)}?realm=smash`;

    document.getElementById('stat-gs').textContent = data.character.gearScore || 0;
    document.getElementById('stat-ddi').textContent = `${data.defenseScore.ddiPieces} / 5 piezas`;
    document.getElementById('stat-sd').textContent = data.defenseScore.hasSdRatio ? '✅ Sí (Ratio 8%)' : '❌ No posee';
    document.getElementById('stat-verdict').textContent = data.defenseScore.assessment;

    if (data.defenseScore.ddiPieces >= 5) {
      document.getElementById('stat-explanation').textContent = 
        'Este personaje posee la reducción de daño máxima legítima (DDI completo). Su resistencia en PvP puede explicarse por su equipamiento.';
    } else {
      document.getElementById('stat-explanation').textContent = 
        `ALERTA TÉCNICA: Solo posee ${data.defenseScore.ddiPieces} piezas de reducción. Si en combate soporta combos continuos de BK armado sin que su escudo baje, la única explicación física es el uso de un bot de Auto-Pot a milisegundos.`;
    }
  } catch (e) {
    alert('Error al conectar con la API de Smash MU.');
  } finally {
    btn.textContent = 'Auditar Perfil';
    btn.disabled = false;
  }
}

// Generador de Reporte para GM / Discord
function updateReportText(overrideAlerts = null) {
  const reportBox = document.getElementById('report-text');
  const now = new Date().toLocaleString();

  let text = `================================================================================\n`;
  text += `🛡️ INFORME FORENSE DE AUDITORÍA & DETECCIÓN DE HACKS - SMASH MU\n`;
  text += `Estación de Análisis: Sentinel Engine v2.0 (Inspección Pasiva Npcap Kernel Ring-0)\n`;
  text += `Fecha y Hora: ${now}\n`;
  text += `Servidor Objetivo: 143.14.179.89 (Puertos TCP GameServer: 55100 / 55101)\n`;
  text += `================================================================================\n\n`;

  text += `1. METODOLOGÍA FORENSE & CAPTURA DE DATOS:\n`;
  text += `--------------------------------------------------------------------------------\n`;
  text += `• Tipo de Captura: Análisis pasivo de tramas TCP en capa de transporte de red local.\n`;
  text += `• Driver de Captura: Npcap en Ring-0 (Kernel) en interfaz activa de red.\n`;
  text += `• Protocolo: Tramas de red Mu Online Season 6 (Encabezados C1/C2/C3/C4).\n`;
  text += `• Opcodes de Protocolo Inspeccionados:\n`;
  text += `    - Opcode 0xD7 / 0x15 : Físicas y trayectoria de desplazamiento (Pathing Vector).\n`;
  text += `    - Opcode 0x19 / 0x1E : Cadencia e intervalos entre skills de ataque (Combat Cadence).\n`;
  text += `    - Opcode 0x26        : Paquetes de consumibles y pociones SD/HP (Consumable Frequency).\n`;
  text += `• Validación Cruzada: Sincronización en vivo con API Oficial de Smash MU (Perfil y GS).\n\n`;

  const criticals = (overrideAlerts || currentAlerts).filter(a => a.severity === 'CRITICAL');

  if (criticals.length === 0) {
    text += `2. ESTADO ACTUAL:\n`;
    text += `No se registran infracciones críticas en el búfer de sesión actual.\n`;
  } else {
    text += `2. EXPEDIENTE DETALLADO DE INFRACCIONES CRÍTICAS CONFIRMADAS:\n`;
    text += `--------------------------------------------------------------------------------\n`;
    criticals.slice(0, 10).forEach((a, idx) => {
      const d = new Date(a.timestamp);
      const localDate = d.toLocaleDateString();
      const localTime = d.toLocaleTimeString();
      const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'GMT-5';

      text += `[CASO #${idx + 1}] INFRACTOR: ${a.playerName}\n`;
      text += `• FECHA Y HORA DE LA INFRACCIÓN:\n`;
      text += `    - Hora Local (PC Denunciante) : ${localDate} a las ${localTime} (${timeZone})\n`;
      text += `    - Hora Servidor (UTC/GMT)     : ${d.toUTCString()}\n`;
      text += `    - Timestamp Unix (ms)         : ${a.timestamp}\n`;
      text += `• Clase de Personaje : ${a.characterClass}\n`;
      text += `• Perfil Oficial Web : https://www.smashmu.com/es/profile/${encodeURIComponent(a.playerName)}?realm=smash\n`;
      text += `• Falta Detectada    : ${a.type.replace(/_/g, ' ')}\n`;
      text += `• Medición Registrada: ${a.metric}\n`;
      text += `• Límite Motor S6    : ${a.limit}\n`;
      if (a.forensics) {
        text += `• Desviación Física  : ${a.forensics.deviation}\n`;
        text += `• Fórmula Aplicada   : ${a.forensics.formula}\n`;
        text += `• Dictamen Pericial  : ${a.forensics.technicalVerdict}\n`;
      }
      text += `\n`;
    });

    text += `3. GUÍA DE TRAZABILIDAD & VERIFICACIÓN EN LOGS (PARA EL GM / STAFF):\n`;
    text += `--------------------------------------------------------------------------------\n`;
    text += `Para verificar y confirmar la sanción de inmediato sin margen de duda:\n\n`;
    text += `A. ARCHIVO DE LOG A REVISAR EN EL SERVIDOR:\n`;
    text += `   • Ubicación típica : GameServer\\LOG\\ o MServer\\Log\\ (Fecha: ${new Date(criticals[0]?.timestamp || Date.now()).toISOString().slice(0, 10)})\n`;
    text += `   • Sub-Servidor     : 143.14.179.89:55101 / 55100\n\n`;
    text += `B. COMANDO DE BÚSQUEDA RÁPIDA (PowerShell / Linux):\n`;
    text += `   powershell: Get-Content GameServer.log | Select-String "${criticals[0]?.playerName || 'DaiKambe'}"\n`;
    text += `   linux/grep: grep -i "${criticals[0]?.playerName || 'DaiKambe'}" GameServer*.log\n\n`;
    text += `C. LO QUE EL GM ENCONTRARÁ EN EL LOG (LA FIRMA DEL HACK):\n`;
    text += `   • En Auto-Combo Bot: El log mostrará la secuencia de skills de BK con diferencias\n`;
    text += `     temporales de <100ms entre Skill 19 (Arma) -> Skill 41 (Twisting) -> Skill 43 (Death Stab).\n`;
    text += `   • En Auto-Pot SD   : Ráfagas continuas de paquetes 0x26 superando las 25-35 pociones/segundo\n`;
    text += `     sin interrupción de delay de interfaz gráfica.\n`;
    text += `   • En Speedhack     : Saltos de posición física mayores a 14 casillas por segundo en coordenadas.\n\n`;
    text += `4. SOLICITUD FORMAL:\n`;
    text += `--------------------------------------------------------------------------------\n`;
    text += `Se solicita aplicar la sanción estipulada en el reglamento de Smash MU por el uso\n`;
    text += `de herramientas de automatización de combate e inyección de paquetes externos.\n`;
  }

  reportBox.textContent = text;
}

// Tabs
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    const target = btn.dataset.tab;
    const el = document.getElementById(target);
    if (el) el.classList.add('active');
  });
});

// Eventos de botones
document.getElementById('btn-sound').addEventListener('click', (e) => {
  soundEnabled = !soundEnabled;
  e.target.textContent = soundEnabled ? '🔊 Alarma Sonora: ON' : '🔈 Alarma Sonora: OFF';
  e.target.classList.toggle('active', soundEnabled);
});

document.getElementById('btn-simulation').addEventListener('click', async (e) => {
  const res = await fetch('/api/simulation/toggle', { method: 'POST' });
  const data = await res.json();
  isSimulating = data.isSimulating;
  e.target.textContent = isSimulating ? '🎮 Simulación: ACTIVA' : '⏸️ Simulación: PAUSADA';
  e.target.classList.toggle('active', isSimulating);
});

document.getElementById('btn-clear').addEventListener('click', async () => {
  await fetch('/api/clear', { method: 'POST' });
});

document.getElementById('btn-inspect').addEventListener('click', inspectPlayer);
document.getElementById('inspect-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') inspectPlayer();
});

document.getElementById('btn-copy-report').addEventListener('click', () => {
  const text = document.getElementById('report-text').textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById('btn-copy-report');
    const orig = btn.textContent;
    btn.textContent = '✅ ¡Copiado al portapapeles!';
    setTimeout(() => btn.textContent = orig, 2000);
  });
});

window.editPlayerName = function(playerId, currentName) {
  const newName = prompt(`Asigna el nombre real del personaje (ID: ${playerId}):`, currentName.startsWith('Jugador_') ? '' : currentName);
  if (newName && newName.trim()) {
    const clean = newName.trim();
    // Actualizar localmente
    const p = currentPlayers.find(x => String(x.id) === String(playerId));
    if (p) p.name = clean;
    // Enviar al servidor para recordar este ID -> Nombre
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'SET_PLAYER_NAME', playerId, name: clean }));
    }
    renderRadar(currentPlayers, currentAlerts);
  }
};

// Iniciar WebSocket al cargar
window.addEventListener('load', () => {
  connectWebSocket();
});
