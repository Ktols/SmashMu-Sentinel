/**
 * MU ONLINE SEASON 6 - CONSTANTES DE FÍSICA Y PROTOCOLO
 * SmashMu Sentinel Forensics Engine
 */

export const THRESHOLDS = {
  // Velocidad de movimiento físico (Casillas / Tiles por segundo)
  MAX_LEGAL_WALK_SPEED: 6.5,        // Caminando a pie con botas +15 y buff de velocidad
  MAX_LEGAL_MOUNT_SPEED: 11.5,      // Con Dark Horse de Dark Lord o Fenrir
  SUSPICIOUS_SPEED_TILES_SEC: 14.5, // Buffer de lag o tirón de red
  CRITICAL_SPEEDHACK_TILES_SEC: 18.0, // Speedhack flagrante (avanza a velocidad inhumana sostenida)

  // Cadencia de Combo EXCLUSIVO de Blade Knight (milisegundos entre combos completos)
  MIN_LEGAL_COMBO_CADENCE_MS: 650,  // Humano competitivo top (~800ms promedio)
  SUSPICIOUS_COMBO_MS: 300,         // Macro rápido
  CRITICAL_COMBO_BOT_MS: 160,       // Inyector de memoria / AHK 1ms (Inhumano)

  // Consumo de Pociones (Pots / segundo)
  MAX_HUMANO_POTS_SEC: 8,           // Spammeando QWE rápido a mano
  SUSPICIOUS_POTS_SEC: 15,          // Macro de pociones
  CRITICAL_AUTO_POT_SEC: 22,        // Auto-QWE Potion Bot (Inmortalidad)

  // Invasiones & Warps (segundos mínimos para cambiar de mapa y hallar mob)
  MIN_LEGAL_MAP_TRANSIT_SEC: 25     // Tiempo mínimo de warp + carga + recorrido
};

// Habilidades que componen el Combo de Blade Knight en Season 6
export const BK_COMBO_SKILLS = [19, 41, 42, 43, 44, 48, 232];

export const MU_MAPS = {
  0: 'Lorencia',
  1: 'Dungeon',
  2: 'Devias',
  3: 'Noria',
  4: 'Lost Tower',
  6: 'Arena / Stadium',
  7: 'Atlans',
  8: 'Tarkan',
  10: 'Icarus',
  30: 'Valley of Loren',
  31: 'Land of Trials',
  33: 'Aida',
  34: 'Crywolf',
  36: 'Kanturu Ruin',
  37: 'Kanturu Remain',
  51: 'Elbeland',
  56: 'Swamp of Peace',
  57: 'Raklion',
  58: 'Santa Town',
  62: 'Vulcanus',
  63: 'Duel Arena',
  64: 'Karutan 1',
  65: 'Karutan 2'
};

export const MU_CLASSES = {
  0: 'Dark Wizard', 1: 'Soul Master', 2: 'Grand Master', 3: 'Grand Master',
  16: 'Dark Knight', 17: 'Blade Knight', 18: 'Blade Master', 19: 'Blade Master',
  32: 'Fairy Elf', 33: 'Muse Elf', 34: 'High Elf', 35: 'High Elf',
  48: 'Magic Gladiator', 49: 'Duel Master', 50: 'Duel Master',
  64: 'Dark Lord', 65: 'Lord Emperor', 66: 'Lord Emperor',
  80: 'Summoner', 81: 'Bloody Summoner', 82: 'Dimension Master', 83: 'Dimension Master',
  96: 'Rage Fighter', 97: 'Fist Master', 98: 'Fist Master'
};
