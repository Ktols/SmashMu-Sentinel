import { THRESHOLDS } from './muProtocol.js';

export class SmashApiHunter {
  constructor(emitter) {
    this.emitter = emitter;
    this.isPolling = false;
    this.pollInterval = null;
    this.playerLastKill = new Map(); // charName -> { monsterName, killedAt, timestamp }
    this.teleKillAlerts = [];
    this.cachedProfiles = new Map();
  }

  start(intervalMs = 4000) {
    if (this.isPolling) return;
    this.isPolling = true;
    this.poll();
    this.pollInterval = setInterval(() => this.poll(), intervalMs);
    console.log(`[HUNTER] 📡 Monitoreo de API Smash MU activado (${intervalMs / 1000}s)`);
  }

  stop() {
    this.isPolling = false;
    if (this.pollInterval) clearInterval(this.pollInterval);
    console.log('[HUNTER] ⏹️ Monitoreo de API Smash MU pausado');
  }

  async poll() {
    try {
      const res = await fetch('https://www.smashmu.com/api/guild-leagues', { cache: 'no-store' });
      if (!res.ok) return;
      const data = await res.json();
      if (!data || !data.recentKillsByLeague) return;

      const allKills = [];
      for (const [league, kills] of Object.entries(data.recentKillsByLeague)) {
        if (Array.isArray(kills)) allKills.push(...kills);
      }

      // Ordenar por fecha más reciente
      allKills.sort((a, b) => new Date(b.killed_at) - new Date(a.killed_at));

      for (const kill of allKills) {
        if (!kill || !kill.character_name) continue;
        const charName = kill.character_name.trim();
        const killTime = new Date(kill.killed_at).getTime();

        if (this.playerLastKill.has(charName)) {
          const prev = this.playerLastKill.get(charName);
          const deltaSec = Math.round((killTime - prev.timestamp) / 1000);

          // Si mató otro boss en menos de 25 segundos y son monstruos distintos
          if (deltaSec > 0 && deltaSec < THRESHOLDS.MIN_LEGAL_MAP_TRANSIT_SEC && prev.monsterName !== kill.monster_name) {
            const alertKey = `${charName}_${killTime}_${prev.timestamp}`;
            if (!this.teleKillAlerts.some(a => a.key === alertKey)) {
              const alert = {
                key: alertKey,
                timestamp: Date.now(),
                type: 'TELE_KILL_INVASION',
                severity: deltaSec <= 10 ? 'CRITICAL' : 'WARNING',
                playerName: charName,
                guildName: kill.guild_name || 'Sin Guild',
                deltaSec,
                firstBoss: prev.monsterName,
                secondBoss: kill.monster_name,
                details: `Eliminó a [${prev.monsterName}] y luego a [${kill.monster_name}] con una diferencia de solo ${deltaSec} segundos. Imposible sin Speedhack / Teleport.`
              };
              this.teleKillAlerts.unshift(alert);
              if (this.teleKillAlerts.length > 50) this.teleKillAlerts.pop();

              if (this.emitter) {
                this.emitter({ type: 'TELE_KILL_ALERT', data: alert });
              }
            }
          }
        }

        // Actualizar último kill del jugador
        this.playerLastKill.set(charName, {
          monsterName: kill.monster_name,
          killedAt: kill.killed_at,
          timestamp: killTime
        });
      }
    } catch (err) {
      // Ignorar errores transitorios de red
    }
  }

  async getPlayerProfile(name) {
    if (!name) return null;
    const cleanName = name.trim().toLowerCase();
    if (this.cachedProfiles.has(cleanName)) {
      return this.cachedProfiles.get(cleanName);
    }

    try {
      const url = `https://www.smashmu.com/api/profile/${encodeURIComponent(cleanName)}?realm=smash`;
      const res = await fetch(url);
      if (!res.ok) return null;
      const data = await res.json();
      if (data && data.success && data.character) {
        // Analizar opciones defensivas (DDI, SD Ratio)
        let totalDdiPieces = 0;
        let hasSdRatio = false;
        const items = data.equipment || [];

        for (const item of items) {
          if (!item || item.isEmpty) continue;
          if (item.harmonyOption?.name?.toLowerCase().includes('decrease') || 
              item.harmonyOption?.label?.toLowerCase().includes('ddi')) {
            totalDdiPieces++;
          }
          if (item.harmonyOption?.name?.toLowerCase().includes('sd') || 
              item.harmonyOption?.label?.toLowerCase().includes('sd')) {
            hasSdRatio = true;
          }
        }

        const analysis = {
          character: data.character,
          equipment: items,
          defenseScore: {
            ddiPieces: totalDdiPieces,
            hasSdRatio,
            gearScore: data.character.gearScore || 0,
            assessment: totalDdiPieces >= 5 
              ? 'Tanque Legítimo (Set DDI Completo)' 
              : totalDdiPieces >= 2 
                ? 'Defensa Media (Parcial DDI)' 
                : 'Defensa Baja / Vulnerable (Sospecha alta si es inmortal en PvP)'
          }
        };

        this.cachedProfiles.set(cleanName, analysis);
        return analysis;
      }
    } catch (e) {
      return null;
    }
    return null;
  }

  getAlerts() {
    return this.teleKillAlerts;
  }
}
