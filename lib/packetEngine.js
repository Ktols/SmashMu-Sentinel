import fs from 'fs';
import { execSync } from 'child_process';
import CapPkg from 'cap';
import { WHITELIST } from './anomalyDetector.js';

const { Cap, decoders } = CapPkg;
const PROTOCOL = decoders.PROTOCOL;

export class PacketEngine {
  constructor(anomalyDetector, apiHunter, emitter) {
    this.detector = anomalyDetector;
    this.apiHunter = apiHunter;
    this.emitter = emitter;
    this.hasNpcap = this.checkNpcapInstalled();
    this.isSimulating = false; // DESACTIVADA POR DEFECTO
    this.simInterval = null;
    this.simStep = 0;
    
    this.cap = null;
    this.capBuffer = Buffer.alloc(65535);
    this.activeDevice = null;
    this.isSniffing = false;

    // Cache de IDs de jugadores a Nombres reales vistos en paquetes
    this.playerIndexToName = new Map();
    this.lowByteToName = new Map(); // clientPort_lowByte -> { name, x, y }

    // Gestor de Múltiples Ventanas / Clientes de MU
    this.windows = new Map(); // clientPort -> { port, pid, charName, characterClass, lastSeen }
    this.selectedWindow = 'ALL';

    // Iniciar escaneo periódico de ventanas de MU activas
    this.scanActiveWindows();
    setInterval(() => this.scanActiveWindows(), 3500);

    // Intentar iniciar el sniffer real de inmediato
    this.startLiveSniffer();
  }

  checkNpcapInstalled() {
    const p1 = 'C:\\Windows\\System32\\Npcap\\wpcap.dll';
    const p2 = 'C:\\Windows\\System32\\wpcap.dll';
    return fs.existsSync(p1) || fs.existsSync(p2);
  }

  /**
   * Inicia la captura de paquetes REAL en la tarjeta de red activa
   */
  startLiveSniffer() {
    if (!this.hasNpcap) {
      console.log('[SNIFFER] ⚠️ Npcap no detectado.');
      return;
    }

    try {
      const deviceList = Cap.deviceList();
      
      // 1. Detectar la IP local exacta con la que main.exe está conectado al GameServer
      let targetIp = null;
      try {
        const netstat = execSync('netstat -ano | findstr 143.14.179.89', { encoding: 'utf8', timeout: 1500 });
        for (const line of netstat.trim().split('\n')) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 4 && parts[3] === 'ESTABLISHED') {
            targetIp = parts[1].split(':')[0];
            break;
          }
        }
      } catch (e) {}

      // 2. Si no hay conexión de MU aún, obtener la IP de la interfaz default (puerta de enlace)
      if (!targetIp) {
        try {
          const route = execSync('route print 0.0.0.0', { encoding: 'utf8', timeout: 1500 });
          const m = route.match(/0\.0\.0\.0\s+0\.0\.0\.0\s+[^\s]+\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/);
          if (m) targetIp = m[1];
        } catch (e) {}
      }

      // 3. Buscar el adaptador exacto en deviceList que coincida con esa IP
      let selected = null;
      if (targetIp) {
        selected = deviceList.find(d => d.addresses && d.addresses.some(a => a.addr === targetIp));
      }

      // 4. Si no coincide, priorizar Ethernet físico sobre Wi-Fi o adaptadores virtuales
      if (!selected) {
        selected = deviceList.find(d => 
          d.description?.toLowerCase().includes('ethernet') && !d.description?.includes('Virtual') && !d.description?.includes('Hyper-V') &&
          d.addresses && d.addresses.some(a => a.addr && (a.addr.startsWith('192.168.') || a.addr.startsWith('10.')))
        ) || deviceList.find(d => 
          !d.description?.includes('Hyper-V') && !d.description?.includes('Virtual') &&
          d.addresses && d.addresses.some(a => a.addr && (a.addr.startsWith('192.168.') || a.addr.startsWith('10.')))
        ) || deviceList[0];
      }

      if (!selected) {
        console.error('[SNIFFER] ❌ No se encontró ningún adaptador de red compatible.');
        return;
      }

      this.packetCount = 0;
      this.lastHeartbeat = 0;

      // Filtro para capturar tráfico TCP real de Smash MU (sub-servidores 55100..55150, GS 55901 y host del juego)
      const filter = 'tcp and (portrange 55100-55150 or portrange 55900-55910 or host 143.14.179.89 or host 186.2.162.247)';
      const bufSize = 10 * 1024 * 1024; // 10MB buffer

      this.cap = new Cap();
      const linkType = this.cap.open(selected.name, filter, bufSize, this.capBuffer);
      if (this.cap.setMinBytes) this.cap.setMinBytes(0);

      this.activeDevice = selected;
      this.isSniffing = true;
      console.log(`[SNIFFER] 🔴 CAPTURA REAL ACTIVA en: ${selected.description} (${selected.addresses?.[0]?.addr || 'Red'})`);
      console.log(`[SNIFFER] 📡 Escuchando servidor de Smash MU: 143.14.179.89 (Puertos 55100, 55101, 55901)`);

      this.cap.on('packet', (nbytes, trunc) => {
        this.packetCount++;
        const now = Date.now();
        if (now - this.lastHeartbeat > 800) {
          this.lastHeartbeat = now;
          if (this.emitter) {
            this.emitter({
              type: 'PACKET_HEARTBEAT',
              data: {
                packetCount: this.packetCount,
                serverIp: '143.14.179.89',
                ports: '55100 / 55101'
              }
            });
          }
        }
        this.processRawPacket(nbytes);
      });

    } catch (err) {
      console.error('[SNIFFER] ❌ Error abriendo adaptador de red:', err.message);
      this.isSniffing = false;
    }
  }

  scanActiveWindows() {
    try {
      const netstat = execSync('netstat -ano | findstr 143.14.179.89', { encoding: 'utf8', timeout: 1500 });
      const lines = netstat.trim().split('\n');
      const currentPorts = new Set();
      let changed = false;

      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 5 && parts[3] === 'ESTABLISHED') {
          const local = parts[1];
          const port = parseInt(local.split(':')[1], 10);
          const pid = parseInt(parts[4], 10);
          if (port) {
            currentPorts.add(port);
            if (!this.windows.has(port)) {
              this.windows.set(port, {
                port,
                pid,
                charName: null,
                characterClass: null,
                lastSeen: Date.now()
              });
              changed = true;
              console.log(`[WINDOWS] 🪟 Nueva ventana de MU detectada: Puerto ${port} (PID ${pid})`);
            } else {
              const win = this.windows.get(port);
              win.pid = pid;
            }
          }
        }
      }

      // Eliminar ventanas cerradas
      for (const [port, win] of this.windows.entries()) {
        if (!currentPorts.has(port)) {
          console.log(`[WINDOWS] 🚪 Ventana de MU cerrada: Puerto ${port} (${win.charName || 'Desconocido'})`);
          this.windows.delete(port);
          changed = true;
        }
      }

      if (changed) {
        this.broadcastWindows();
      }
    } catch (e) {}
  }

  getWindowsList() {
    return Array.from(this.windows.values()).map(w => ({
      port: w.port,
      pid: w.pid,
      charName: w.charName || `Ventana_${w.port}`,
      characterClass: w.characterClass || 'Smash MU',
      active: Date.now() - w.lastSeen < 60000
    }));
  }

  broadcastWindows() {
    if (this.emitter) {
      this.emitter({
        type: 'WINDOWS_UPDATE',
        data: {
          windows: this.getWindowsList(),
          selected: this.selectedWindow
        }
      });
    }
  }

  processRawPacket(nbytes) {
    try {
      let ret = decoders.Ethernet(this.capBuffer);
      if (ret.info.type !== PROTOCOL.ETHERNET.IPV4) return;

      const ipInfo = decoders.IPV4(this.capBuffer, ret.offset);
      if (ipInfo.info.protocol !== PROTOCOL.IP.TCP) return;

      let datalen = ipInfo.info.totallen - ipInfo.hdrlen;
      const tcpInfo = decoders.TCP(this.capBuffer, ipInfo.offset);
      datalen -= tcpInfo.hdrlen;

      if (datalen <= 0) return;

      const srcPort = tcpInfo.info.srcport;
      const dstPort = tcpInfo.info.dstport;
      const isOutbound = (dstPort >= 55100 && dstPort <= 55150) || (dstPort >= 55900 && dstPort <= 55910) || ipInfo.info.dstaddr === '143.14.179.89';
      const clientPort = isOutbound ? srcPort : dstPort;

      // Actualizar timestamp de la ventana
      if (this.windows.has(clientPort)) {
        this.windows.get(clientPort).lastSeen = Date.now();
      }

      const payload = this.capBuffer.slice(tcpInfo.offset, tcpInfo.offset + datalen);
      this.parseMuPayload(payload, clientPort, isOutbound);
    } catch (e) {
      // Ignorar paquetes corruptos o malformados
    }
  }

  parseMuPayload(buffer, clientPort = 0, isOutbound = false) {
    let offset = 0;
    const now = Date.now();

    while (offset < buffer.length) {
      const header = buffer[offset];
      if (header !== 0xC1 && header !== 0xC2 && header !== 0xC3 && header !== 0xC4) {
        offset++;
        continue;
      }

      let packetSize = 0;
      let headCode = 0;

      if (header === 0xC1 || header === 0xC3) {
        if (offset + 2 >= buffer.length) break;
        packetSize = buffer[offset + 1];
        headCode = buffer[offset + 2];
      } else {
        if (offset + 3 >= buffer.length) break;
        packetSize = (buffer[offset + 1] << 8) | buffer[offset + 2];
        headCode = buffer[offset + 3];
      }

      if (packetSize <= 0 || offset + packetSize > buffer.length) {
        break;
      }

      const pkt = buffer.slice(offset, offset + packetSize);
      this.analyzeMuPacket(header, headCode, pkt, now, clientPort, isOutbound);

      offset += packetSize;
    }
  }

  resolvePlayerName(clientPort, pId) {
    const sessionKey = `${clientPort}_${pId}`;
    let name = this.playerIndexToName.get(sessionKey);
    if (!name || name.startsWith('Jugador_')) {
      const low = pId & 0xFF;
      const lbInfo = this.lowByteToName.get(`${clientPort}_${low}`);
      if (lbInfo && lbInfo.name) {
        name = lbInfo.name;
        this.playerIndexToName.set(sessionKey, name);
      }
    }
    return name || `Jugador_${pId}`;
  }

  analyzeMuPacket(header, headCode, pkt, now, clientPort = 0, isOutbound = false) {
    const win = this.windows.get(clientPort);

    // 1. Identificación de Ventana mediante paquetes salientes (Outbound)
    if (isOutbound && pkt.length >= 6) {
      for (let i = 2; i <= pkt.length - 3; i++) {
        let candidate = '';
        for (let j = 0; j < 10 && i + j < pkt.length; j++) {
          const b = pkt[i + j];
          if (b === 0) break;
          if ((b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b === 95) {
            candidate += String.fromCharCode(b);
          } else {
            candidate = '';
            break;
          }
        }
        const upper = candidate.toUpperCase();
        if (WHITELIST.has(upper) && win && win.charName !== candidate) {
          win.charName = candidate;
          console.log(`[WINDOWS] 🎯 Ventana (Puerto ${clientPort}) identificada permanentemente como: ${candidate}`);
          if (this.apiHunter) {
            this.apiHunter.getPlayerProfile(candidate).then(prof => {
              if (prof && prof.character) {
                win.characterClass = prof.character.className;
                this.broadcastWindows();
              }
            }).catch(() => {});
          }
          this.broadcastWindows();
          break;
        }
      }
    }

    // 2. Control de Viewport Oficial de Smash MU (0xF3 subcódigos 0xA1 y 0xA2: Jugadores en Rango de Pantalla)
    const isC2 = (header === 0xC2 || header === 0xC4);
    if (headCode === 0xF3 && isC2 && !isOutbound) {
      const sub = pkt[4];
      if (sub === 0xA1 || sub === 0xA2) {
        const count = pkt[5];
        let recOffset = 6;
        for (let i = 0; i < count && recOffset + 16 <= pkt.length; i++) {
          const lowByte = pkt[recOffset];
          const posX = pkt[recOffset + 1];
          const posY = pkt[recOffset + 2];
          let name = '';
          for (let j = 0; j < 10; j++) {
            const b = pkt[recOffset + 5 + j];
            if (b === 0) break;
            if ((b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b === 95) {
              name += String.fromCharCode(b);
            }
          }
          name = name.trim();
          if (name.length >= 3) {
            this.lowByteToName.set(`${clientPort}_${lowByte}`, { name, x: posX, y: posY });

            // Si la ventana aún no tiene nombre y este personaje es de la whitelist
            if (WHITELIST.has(name.toUpperCase()) && win && !win.charName) {
              win.charName = name;
            }

            // Actualizar entidades existentes en esta ventana que tengan este lowByte
            for (const [key, pObj] of this.detector.players.entries()) {
              if (pObj.clientPort === clientPort) {
                const parts = key.split('_');
                const pIdVal = Number(parts[1]);
                if (!isNaN(pIdVal) && (pIdVal & 0xFF) === lowByte) {
                  pObj.name = name;
                  pObj.x = posX;
                  pObj.y = posY;
                  pObj.lastMoveTime = now;
                  this.playerIndexToName.set(key, name);

                  if (this.apiHunter && !pObj.verified && !name.startsWith('Jugador_')) {
                    this.apiHunter.getPlayerProfile(name).then(prof => {
                      if (prof && prof.character) {
                        pObj.characterClass = prof.character.className || 'Personaje MU';
                        pObj.verified = true;
                        pObj.gearScore = prof.character.gearScore || 0;
                      }
                    }).catch(() => {});
                  }
                }
              }
            }
          }
          recOffset += 16;
        }
      }
    }

    // 3. Salida de Jugadores de Pantalla (Opcode 0x14: Viewport Destroy / Despawn)
    if (headCode === 0x14 && !isOutbound) {
      const count = pkt[3];
      let recOffset = 4;
      for (let i = 0; i < count && recOffset + 2 <= pkt.length; i++) {
        const pId = ((pkt[recOffset] & 0x7F) << 8) | pkt[recOffset + 1];
        if (pId > 0) {
          const sessionKey = `${clientPort}_${pId}`;
          const lowByte = pkt[recOffset + 1];
          this.lowByteToName.delete(`${clientPort}_${lowByte}`);
          this.playerIndexToName.delete(sessionKey);
          this.detector.removePlayer(sessionKey);
        }
        recOffset += 2;
      }
    }

    // 4. Cambio de Mapa / Warp / Teletransporte (0xF3 subcódigo 0x03 o 0xF1)
    if (!isC2 && headCode === 0xF3 && (pkt[3] === 0x03 || pkt[3] === 0xF1) && !isOutbound) {
      for (const [key, p] of this.detector.players.entries()) {
        if (p.clientPort === clientPort && !key.endsWith('_self')) {
          this.detector.removePlayer(key);
          this.playerIndexToName.delete(key);
        }
      }
      for (const k of this.lowByteToName.keys()) {
        if (k.startsWith(`${clientPort}_`)) this.lowByteToName.delete(k);
      }
    }

    const windowLabel = win?.charName ? `🪟 ${win.charName}` : `Ventana_${clientPort}`;

    // 2. Paquete de Movimiento (0x15, 0xD4, 0xD6, 0xD7, 0xD9)
    if (headCode === 0x15 || headCode === 0xD4 || headCode === 0xD6 || headCode === 0xD7 || headCode === 0xD9) {
      if (isOutbound && pkt.length >= 5) {
        // Movimiento originado por nuestro cliente (C1 06 D4 [X] [Y] [Dir])
        const posX = pkt[3];
        const posY = pkt[4];
        const sessionKey = `${clientPort}_self`;
        const charName = win?.charName || `Ventana_${clientPort}`;
        if (posX > 0 && posY > 0 && posX < 256 && posY < 256) {
          this.detector.recordMovement(sessionKey, charName, posX, posY, now, clientPort, windowLabel);
        }
      } else if (!isOutbound && pkt.length >= 7) {
        // Movimiento de otros personajes enviado por el servidor (C1 [len] 15 [pIdH] [pIdL] [X] [Y] ...)
        const pId = ((pkt[3] & 0x7F) << 8) | pkt[4];
        const posX = pkt[5];
        const posY = pkt[6];

        if (posX > 0 && posY > 0 && posX < 256 && posY < 256 && pId > 0) {
          const sessionKey = `${clientPort}_${pId}`;
          const charName = this.resolvePlayerName(clientPort, pId);
          this.detector.recordMovement(sessionKey, charName, posX, posY, now, clientPort, windowLabel);
        }
      }
    }

    // 3. Paquetes de Habilidades Mágicas y Combo de Blade Knight (0x19, 0x1E)
    if (headCode === 0x19 || headCode === 0x1E) {
      if (isOutbound) {
        // Cliente emitiendo habilidad: C3 [len] 19 [skillH] [skillL] [targetH] [targetL]
        if (pkt.length >= 5) {
          const skillId = (pkt[3] << 8) | pkt[4];
          const sessionKey = `${clientPort}_self`;
          const charName = win?.charName || `Ventana_${clientPort}`;
          if (skillId > 0) {
            this.detector.recordComboHit(sessionKey, charName, skillId, now, clientPort, windowLabel);
          }
        }
      } else {
        // Servidor notificando habilidad/golpe a rango de visión:
        // Opcode 0x19 (Magic Attack): C1 09 19 [skillH] [skillL] [sourceH] [sourceL] [targetH] [targetL]
        // Opcode 0x1E (Duration Hit): C1 0A 1E [skillH] [skillL] [sourceH] [sourceL] [x] [y] [dir]
        if (pkt.length >= 7) {
          const skillId = (pkt[3] << 8) | pkt[4];
          const pId = ((pkt[5] & 0x7F) << 8) | pkt[6];

          if (pId > 0 && skillId > 0) {
            const sessionKey = `${clientPort}_${pId}`;
            const charName = this.resolvePlayerName(clientPort, pId);
            this.detector.recordComboHit(sessionKey, charName, skillId, now, clientPort, windowLabel);
          }
        }
      }
    }

    // 4. Paquete de Consumo de Poción (SOLO Outbound del cliente, longitud corta)
    // C1 14 26 FF es sincronización de barra de vida del servidor, NUNCA una poción
    if ((headCode === 0x26 || headCode === 0x27) && isOutbound && pkt.length <= 6) {
      const pId = ((pkt[3] & 0x7F) << 8) | pkt[4];
      const sessionKey = `${clientPort}_${pId || 'self'}`;
      const charName = this.playerIndexToName.get(sessionKey) || win?.charName || `Ventana_${clientPort}`;
      this.detector.recordPotionConsumption(sessionKey, charName, 'SD/HP', now, clientPort, windowLabel);
    }
  }

  // Control de Simulación (Apagada por defecto)
  startSimulation() {
    if (this.isSimulating) return;
    this.isSimulating = true;
    this.simStep = 0;
    console.log('[ENGINE] 🎮 MODO SIMULACIÓN MANUAL ACTIVADO');

    this.simInterval = setInterval(() => {
      this.simStep++;
      const now = Date.now();

      // Jugador legal
      const legitX = 125 + Math.sin(this.simStep * 0.2) * 8;
      const legitY = 125 + Math.cos(this.simStep * 0.2) * 8;
      this.detector.recordMovement(101, 'LegitPlayer', Math.round(legitX), Math.round(legitY), now);
      if (this.simStep % 4 === 0) {
        this.detector.recordComboHit(101, 'LegitPlayer', 41, now);
        this.detector.recordPotionConsumption(101, 'LegitPlayer', 'HP', now);
      }

      // Speedrunner
      if (this.simStep % 3 === 0) {
        const speedX = 100 + (this.simStep * 6) % 100;
        const speedY = 110 + (this.simStep * 4) % 90;
        this.detector.recordMovement(102, 'SpeedRunnerX', speedX, speedY, now);
      }

      // Auto combo bot
      if (this.simStep % 2 === 0) {
        this.detector.recordComboHit(103, 'MacroKing_BK', 41, now);
        this.detector.recordComboHit(103, 'MacroKing_BK', 41, now + 42);
        this.detector.recordPotionConsumption(103, 'MacroKing_BK', 'SD', now);
      }

      if (this.emitter) {
        this.emitter({
          type: 'RADAR_UPDATE',
          data: this.detector.getSnapshot()
        });
      }
    }, 500);
  }

  stopSimulation() {
    this.isSimulating = false;
    if (this.simInterval) clearInterval(this.simInterval);
    this.detector.clear();
    console.log('[ENGINE] ⏹️ Simulación detenida. Esperando paquetes de jugadores reales.');
    if (this.emitter) {
      this.emitter({ type: 'CLEARED' });
    }
  }

  getStatus() {
    return {
      npcapInstalled: this.hasNpcap,
      isSniffing: this.isSniffing,
      adapter: this.activeDevice ? `${this.activeDevice.description} (${this.activeDevice.addresses?.[0]?.addr || 'Wi-Fi'})` : 'Sin adaptador',
      isSimulating: this.isSimulating,
      monitoredPorts: [55901, 55902, 55903, 55904, 55905, 44405]
    };
  }
}
