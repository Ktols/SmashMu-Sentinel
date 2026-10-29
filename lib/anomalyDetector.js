import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { THRESHOLDS, BK_COMBO_SKILLS } from './muProtocol.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ALERTS_FILE = path.join(__dirname, '..', 'data', 'alerts_history.json');

export const WHITELIST = new Set(['KTOL', 'KTOLDROSSA', 'ARKANTOS97', 'FEDOR', 'LYANDRID', 'MGZAQKRA']);

export class AnomalyDetector {
  constructor(eventEmitter) {
    this.emitter = eventEmitter;
    this.players = new Map();
    this.alerts = [];
    this.maxAlerts = 5000;
    this.loadAlertsFromDisk();
  }

  loadAlertsFromDisk() {
    try {
      if (fs.existsSync(ALERTS_FILE)) {
        const raw = fs.readFileSync(ALERTS_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          this.alerts = parsed;
          console.log(`[STORAGE] 📂 ${parsed.length} evidencias cargadas desde el almacenamiento permanente.`);
        }
      }
    } catch (e) {
      console.error('[STORAGE] Error leyendo historial de alertas:', e.message);
    }
  }

  saveAlertsToDisk() {
    try {
      const dir = path.dirname(ALERTS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(ALERTS_FILE, JSON.stringify(this.alerts.slice(0, 5000), null, 2), 'utf8');
    } catch (e) {
      console.error('[STORAGE] Error guardando historial de alertas:', e.message);
    }
  }

  removePlayer(playerId) {
    if (this.players.has(playerId)) {
      this.players.delete(playerId);
    }
  }

  getOrCreatePlayer(playerId, name = 'Desconocido', characterClass = 'Desconocida', clientPort = null, windowOwner = null) {
    if (!this.players.has(playerId)) {
      this.players.set(playerId, {
        id: playerId,
        name: name,
        characterClass: characterClass,
        clientPort: clientPort,
        windowOwner: windowOwner || (clientPort ? `Ventana_${clientPort}` : 'Principal'),
        x: 0,
        y: 0,
        lastX: 0,
        lastY: 0,
        lastMoveTime: 0,
        currentSpeed: 0,
        speedHistory: [],
        comboHistory: [],
        potHistory: [],
        lastComboCadence: 0,
        lastPotRate: 0,
        suspiciousScore: 0,
        lastAlertTimes: new Map(),
        consecutiveFastTicks: 0
      });
    }
    const p = this.players.get(playerId);
    if (name !== 'Desconocido') p.name = name;
    if (characterClass !== 'Desconocida') p.characterClass = characterClass;
    if (clientPort && !p.clientPort) p.clientPort = clientPort;
    if (windowOwner) p.windowOwner = windowOwner;
    return p;
  }

  /**
   * Registra un movimiento con suavizado de ventana
   */
  recordMovement(playerId, name, x, y, timestamp = Date.now(), clientPort = null, windowOwner = null) {
    const p = this.getOrCreatePlayer(playerId, name, 'Desconocida', clientPort, windowOwner);
    
    if (p.lastMoveTime === 0) {
      p.x = x;
      p.y = y;
      p.lastX = x;
      p.lastY = y;
      p.lastMoveTime = timestamp;
      return null;
    }

    const deltaMs = timestamp - p.lastMoveTime;
    if (deltaMs < 70) {
      p.x = x;
      p.y = y;
      return null;
    }

    const deltaX = x - p.x;
    const deltaY = y - p.y;
    const distanceTiles = Math.sqrt(deltaX * deltaX + deltaY * deltaY);

    if (distanceTiles === 0) {
      p.lastMoveTime = timestamp;
      return null;
    }

    if (distanceTiles > 14) {
      // Salto instantáneo por Warp, Teletransporte de Mago, Gate o Respawn tras morir
      p.speedHistory = [];
      p.consecutiveFastTicks = 0;
      p.x = x;
      p.y = y;
      p.lastX = x;
      p.lastY = y;
      p.lastMoveTime = timestamp;
      return null;
    }

    const speedTilesSec = (distanceTiles / (deltaMs / 1000));
    const smoothSpeed = Math.round(speedTilesSec * 10) / 10;
    
    p.speedHistory.push({ time: timestamp, speed: smoothSpeed, dist: distanceTiles, deltaMs });
    if (p.speedHistory.length > 5) p.speedHistory.shift();

    const avgSpeed = Math.round(
      (p.speedHistory.reduce((acc, h) => acc + h.speed, 0) / p.speedHistory.length) * 10
    ) / 10;

    p.currentSpeed = avgSpeed;
    p.lastX = p.x;
    p.lastY = p.y;
    p.x = x;
    p.y = y;
    p.lastMoveTime = timestamp;

    // Blindar personajes del usuario
    if (WHITELIST.has((p.name || '').toUpperCase())) {
      return { playerId, speed: p.currentSpeed, x, y };
    }

    // Solo alertar si la velocidad extrema se sostiene por al menos 3 pasos
    if (avgSpeed >= THRESHOLDS.CRITICAL_SPEEDHACK_TILES_SEC) {
      p.consecutiveFastTicks++;
      if (p.consecutiveFastTicks >= 3) {
        p.suspiciousScore += 30;
        this.emitAlert({
          id: `speed_${Date.now()}_${playerId}`,
          timestamp,
          type: 'SPEEDHACK_MOVIMIENTO',
          severity: 'CRITICAL',
          playerId,
          playerName: p.name,
          characterClass: p.characterClass,
          metric: `${avgSpeed} casillas/s (Sostenida)`,
          limit: `${THRESHOLDS.MAX_LEGAL_MOUNT_SPEED} casillas/s`,
          details: `Velocidad física sobrehumana continua durante múltiples pasos (${avgSpeed} cas/s).`,
          forensics: {
            method: 'Inspección de tramas TCP de movimiento en tiempo real (Opcode 0xD7 / 0x15 via Npcap Kernel)',
            serverTarget: '143.14.179.89:55100/55101 (Smash MU GameServer)',
            formula: `Distancia Euclidiana / Tiempo: Δd=${Math.round(distanceTiles * 10) / 10} casillas en Δt=${deltaMs}ms -> Velocidad instantánea ${smoothSpeed} cas/s (Promedio ventana móvil: ${avgSpeed} cas/s)`,
            pathCoordinates: `De (${p.lastX}, ${p.lastY}) a (${x}, ${y})`,
            engineLimit: `${THRESHOLDS.MAX_LEGAL_MOUNT_SPEED} casillas/s (Dark Horse / Fenrir con Agilidad máxima)`,
            deviation: `+${Math.round(((avgSpeed / THRESHOLDS.MAX_LEGAL_MOUNT_SPEED) - 1) * 100)}% por encima del límite físico del motor`,
            technicalVerdict: 'Violación del bucle de físicas cliente-servidor de Mu Online Season 6. Demuestra manipulación del reloj del juego (Speed Gear / Cheat Engine / Bypass de velocidad en main.exe).'
          }
        });
      }
    } else {
      p.consecutiveFastTicks = Math.max(0, p.consecutiveFastTicks - 1);
    }

    return { playerId, speed: p.currentSpeed, x, y };
  }

  /**
   * Registra un combo. EXCLUSIVO para Blade Knights confirmados.
   */
  recordComboHit(playerId, name, skillId, timestamp = Date.now(), clientPort = null, windowOwner = null) {
    const p = this.getOrCreatePlayer(playerId, name, 'Desconocida', clientPort, windowOwner);

    // 1. Blindar personajes propios del usuario
    if (WHITELIST.has((p.name || '').toUpperCase())) return;

    // 2. Filtro estricto de clases que NO tienen combo en Mu Online Season 6
    // Dark Lords, Magos, Elfas, Magic Gladiators y Rage Fighters NO TIENEN COMBO
    const lowerClass = (p.characterClass || '').toLowerCase();
    const isLordOrMageOrElf = 
      lowerClass.includes('lord') || lowerClass.includes('emperor') || 
      lowerClass.includes('wizard') || lowerClass.includes('soul master') || lowerClass.includes('grand master') ||
      lowerClass.includes('elf') || lowerClass.includes('gladiator') || lowerClass.includes('duel') ||
      lowerClass.includes('fighter') || lowerClass.includes('fist') || lowerClass.includes('summoner') || lowerClass.includes('dimension');

    if (isLordOrMageOrElf) {
      return; // Descartar: esta clase no tiene sistema de combos en Mu Online
    }

    // 3. Validar que la habilidad pertenezca EXCLUSIVAMENTE al combo de Blade Knight
    // 19-23 (Skills de Arma), 41 (Twisting), 42 (Rageful), 43 (Death Stab), 44 (Crescent), 48 (Destruction), 232 (Strike of Destruction), 235 (Blood Storm), 236-238 (Master Enhancers)
    const VALID_COMBO_SKILLS = new Set([
      19, 20, 21, 22, 23,
      41, 42, 43, 44, 48,
      232, 235, 236, 237, 238,
      326, 327, 328, 329, 330, 331, 332, 333
    ]);
    if (!skillId || !VALID_COMBO_SKILLS.has(skillId)) {
      return; // No es una habilidad de combo de BK
    }

    // Auto-asignar clase Blade Knight si aún era desconocida
    if (!p.characterClass || p.characterClass === 'Desconocida') {
      p.characterClass = 'Blade Knight';
    }

    // 4. Registrar secuencia de habilidades para verificar alternancia (Combo real)
    if (!p.comboSkillHistory) p.comboSkillHistory = [];
    p.comboSkillHistory.push({ skillId, timestamp });
    if (p.comboSkillHistory.length > 6) p.comboSkillHistory.shift();

    if (p.comboSkillHistory.length >= 2) {
      const prev = p.comboSkillHistory[p.comboSkillHistory.length - 2];
      const deltaMs = timestamp - prev.timestamp;

      // Si repite la misma skill (ej: spam continuo de Twisting Slash 41 -> 41), NO es combo
      if (prev.skillId === skillId) {
        return;
      }

      p.lastComboCadence = deltaMs;

      // Un combo legítimo humano en Season 6 requiere mínimo 300ms a 650ms de retardo
      if (deltaMs <= THRESHOLDS.CRITICAL_COMBO_BOT_MS && deltaMs > 25) {
        p.suspiciousScore += 40;
        this.emitAlert({
          id: `combo_${Date.now()}_${playerId}`,
          timestamp,
          type: 'AUTO_COMBO_BOT',
          severity: 'CRITICAL',
          playerId,
          playerName: p.name,
          characterClass: p.characterClass || 'Blade Knight',
          clientPort: p.clientPort,
          windowOwner: p.windowOwner,
          metric: `${deltaMs} ms`,
          limit: `${THRESHOLDS.MIN_LEGAL_COMBO_CADENCE_MS} ms (Humano)`,
          details: `Ráfaga de combo de BK alternando skills a cadencia sobrehumana (${deltaMs}ms). Cancelación forzada de animación detectada.`,
          forensics: {
            method: 'Inspección de secuencias de paquetes de ataque (Opcode 0x19 Magic/Skill + Opcode 0x1E Hit via Npcap Kernel)',
            serverTarget: '143.14.179.89:55100/55101 (Smash MU GameServer)',
            formula: `Secuencia: Skill ID ${prev.skillId} ➔ Skill ID ${skillId} en Δt=${deltaMs}ms`,
            engineLimit: `Límite biológico y de animación de Mu S6: >= 250ms`,
            deviation: `Cadencia de ${deltaMs}ms (${Math.round((1 - (deltaMs / THRESHOLDS.MIN_LEGAL_COMBO_CADENCE_MS)) * 100)}% más veloz que el límite de reacción humana)`,
            technicalVerdict: 'Inyección de paquetes en socket o macro con hook de corte de animación. Ningún jugador humano puede ejecutar la secuencia de 3 skills con este retardo de milisegundos.'
          }
        });
      }
    }
  }

  /**
   * Registra consumo de pociones y calcula tasa por segundo
   */
  recordPotionConsumption(playerId, name, potType = 'SD/HP', timestamp = Date.now(), clientPort = null, windowOwner = null) {
    const p = this.getOrCreatePlayer(playerId, name, 'Desconocida', clientPort, windowOwner);
    p.potHistory.push(timestamp);

    const thresholdWindow = timestamp - 3000;
    p.potHistory = p.potHistory.filter(t => t >= thresholdWindow);

    const potsPerSec = Math.round((p.potHistory.length / 3) * 10) / 10;
    p.lastPotRate = potsPerSec;

    // Blindar personajes del usuario
    if (WHITELIST.has((p.name || '').toUpperCase())) return;

    // Solo alertar en PvP extremo (> 30 pots/segundo reales de SD/HP)
    if (potsPerSec >= 32) {
      p.suspiciousScore += 35;
      this.emitAlert({
        id: `pot_${Date.now()}_${playerId}`,
        timestamp,
        type: 'AUTO_POT_BOT',
        severity: 'CRITICAL',
        playerId,
        playerName: p.name,
        characterClass: p.characterClass,
        clientPort: p.clientPort,
        windowOwner: p.windowOwner,
        metric: `${potsPerSec} pots/seg`,
        limit: `10 pots/seg (Límite humano/helper)`,
        details: `Consumo desmedido de pociones (${p.potHistory.length} pots en 3s). Explica invulnerabilidad continua de SD en combate.`,
        forensics: {
          method: 'Captura de tramas de uso de consumibles (Opcode 0x26 Potion Use via Npcap Kernel)',
          serverTarget: '143.14.179.89:55100/55101 (Smash MU GameServer)',
          formula: `Frecuencia: ${p.potHistory.length} paquetes de poción en una ventana de 3.0s -> ${potsPerSec} pociones/segundo`,
          engineLimit: 'Pulsación humana máxima: ~7-9 clicks/s. MU Helper oficial: limitado a ~2-4 pots/s.',
          deviation: `+${Math.round(((potsPerSec / 10) - 1) * 100)}% superior al límite operativo de interfaz`,
          technicalVerdict: 'Macro de inyección directa de teclado o inyección de tramas 0x26 en loop sin retardo de UI. Mantiene el escudo de SD regenerado artificialmente de forma instantánea.'
        }
      });
    }
  }

  emitAlert(alert) {
    if (WHITELIST.has((alert.playerName || '').toUpperCase())) return;

    const p = this.players.get(alert.playerId);
    const now = Date.now();

    if (p) {
      const lastTime = p.lastAlertTimes.get(alert.type) || 0;
      if (now - lastTime < 15000) {
        return; // Cooldown de 15s para evitar spam
      }
      p.lastAlertTimes.set(alert.type, now);
    }

    console.log(`\n🚨 [TELEMETRÍA] ${alert.severity === 'CRITICAL' ? '🔴 ALERTA CRÍTICA' : '🟡 ADVERTENCIA'}:`);
    console.log(`   👤 Infractor: ${alert.playerName} (${alert.characterClass}) [Ventana: ${alert.windowOwner || alert.clientPort || 'N/A'}]`);
    console.log(`   🚩 Tipo: ${alert.type} | Métrica: ${alert.metric} (Límite: ${alert.limit})`);
    console.log(`   ⏱️ Hora Local: ${new Date().toLocaleTimeString()} | Epoch: ${Date.now()}\n`);

    this.alerts.unshift(alert);
    if (this.alerts.length > this.maxAlerts) this.alerts.pop();
    this.saveAlertsToDisk();

    if (this.emitter) {
      this.emitter({ type: 'ALERT', data: alert });
    }
  }

  getSnapshot(selectedPort = 'ALL') {
    const now = Date.now();
    const KNOWN_GUILDS = new Set(['TEMPLARS', 'SICARIOS', 'THEKINGZ', '0GENOCIDAS', 'PARAGON', 'B2FR', 'BADBOYZ', 'VEXOR', 'AIDA']);

    // Deduplicar estrictamente por nombre de personaje
    const byName = new Map();

    for (const [id, p] of this.players.entries()) {
      if (KNOWN_GUILDS.has(p.name.toUpperCase())) {
        this.players.delete(id);
        continue;
      }
      // Limpiar personajes remotos que no han tenido actividad ni movimiento en los últimos 30 segundos
      if (p.lastMoveTime > 0 && now - p.lastMoveTime > 30000 && !id.endsWith('_self')) {
        this.players.delete(id);
        continue;
      }

      // Filtrar por ventana seleccionada si no es 'ALL'
      if (selectedPort && selectedPort !== 'ALL') {
        if (p.clientPort && p.clientPort !== Number(selectedPort)) {
          continue;
        }
      }

      const isMyChar = WHITELIST.has(p.name.toUpperCase());
      if (isMyChar) p.suspiciousScore = 0;

      const key = p.name.toLowerCase().trim();
      if (!byName.has(key) || byName.get(key).lastMoveTime < p.lastMoveTime) {
        byName.set(key, p);
      }
    }

    const playersList = Array.from(byName.values()).map(p => {
      const isMyChar = WHITELIST.has(p.name.toUpperCase());
      return {
        id: p.id,
        name: p.name,
        characterClass: p.characterClass,
        clientPort: p.clientPort,
        windowOwner: p.windowOwner || (p.clientPort ? `Ventana_${p.clientPort}` : 'Principal'),
        x: p.x,
        y: p.y,
        currentSpeed: p.currentSpeed,
        lastComboCadence: p.lastComboCadence,
        lastPotRate: p.lastPotRate,
        suspiciousScore: isMyChar ? 0 : p.suspiciousScore,
        verified: p.verified || false,
        gearScore: p.gearScore || 0,
        isMyAccount: isMyChar,
        status: isMyChar ? 'MY_CHAR' : p.suspiciousScore >= 50 ? 'CRITICAL' : p.suspiciousScore >= 20 ? 'SUSPICIOUS' : 'CLEAN'
      };
    });

    return {
      players: playersList,
      alerts: this.alerts.slice(0, 500)
    };
  }

  getHistoricalHackers() {
    const hackersMap = new Map();
    for (const a of this.alerts) {
      if (a.severity !== 'CRITICAL') continue;
      const name = a.playerName;
      if (!name || name.startsWith('Jugador_')) continue;
      const key = name.toLowerCase().trim();
      if (!hackersMap.has(key)) {
        hackersMap.set(key, {
          name: a.playerName,
          characterClass: a.characterClass || 'Desconocida',
          infractionsCount: 0,
          primaryHack: a.type,
          worstMetric: a.metric,
          firstSeen: a.timestamp,
          lastSeen: a.timestamp,
          records: []
        });
      }
      const h = hackersMap.get(key);
      h.infractionsCount++;
      h.records.push(a);
      if (a.timestamp < h.firstSeen) h.firstSeen = a.timestamp;
      if (a.timestamp > h.lastSeen) h.lastSeen = a.timestamp;
      if (a.type === 'AUTO_COMBO_BOT') {
        h.primaryHack = 'AUTO_COMBO_BOT';
        h.worstMetric = a.metric;
      }
    }
    return Array.from(hackersMap.values()).sort((a, b) => b.lastSeen - a.lastSeen);
  }

  clear() {
    this.players.clear();
    this.alerts = [];
  }
}
