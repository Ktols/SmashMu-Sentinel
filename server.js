import express from 'express';
import http from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import path from 'path';
import { fileURLToPath } from 'url';
import { AnomalyDetector } from './lib/anomalyDetector.js';
import { SmashApiHunter } from './lib/smashApiHunter.js';
import { PacketEngine } from './lib/packetEngine.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
wss.on('error', () => {});

const PORT = process.env.PORT || 4444;

app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// Función para broadcast de WebSocket a todos los clientes
function broadcast(payload) {
  const msg = JSON.stringify(payload);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(msg);
    }
  });
}

// Inicializar Módulos de Detección
const anomalyDetector = new AnomalyDetector((event) => broadcast(event));
const apiHunter = new SmashApiHunter((event) => broadcast(event));
const packetEngine = new PacketEngine(anomalyDetector, apiHunter, (event) => broadcast(event));

// Iniciar monitoreo pasivo de invasiones de Smash MU por defecto
apiHunter.start(3500);

// Sincronización continua en vivo del radar PvP hacia los navegadores (1 segundo)
setInterval(() => {
  if (wss.clients.size > 0) {
    broadcast({
      type: 'RADAR_UPDATE',
      data: anomalyDetector.getSnapshot(packetEngine.selectedWindow)
    });
  }
}, 1000);

// Rutas de API REST
app.get('/api/status', (req, res) => {
  res.json({
    engine: packetEngine.getStatus(),
    hunterActive: apiHunter.isPolling,
    playersTracked: anomalyDetector.players.size,
    alertsCount: anomalyDetector.alerts.length
  });
});

app.get('/api/snapshot', (req, res) => {
  res.json(anomalyDetector.getSnapshot());
});

app.get('/api/tele-kills', (req, res) => {
  res.json(apiHunter.getAlerts());
});

app.get('/api/inspect/:name', async (req, res) => {
  const name = req.params.name;
  const profile = await apiHunter.getPlayerProfile(name);
  if (!profile) {
    return res.status(404).json({ error: 'Personaje no encontrado en la API oficial de Smash MU' });
  }
  res.json(profile);
});

app.post('/api/simulation/toggle', (req, res) => {
  if (packetEngine.isSimulating) {
    packetEngine.stopSimulation();
  } else {
    packetEngine.startSimulation();
  }
  res.json({ isSimulating: packetEngine.isSimulating });
});

app.post('/api/clear', (req, res) => {
  anomalyDetector.clear();
  broadcast({ type: 'CLEARED' });
  res.json({ success: true });
});

app.get('/api/windows', (req, res) => {
  res.json(packetEngine.getWindowsList());
});

app.get('/api/hackers', (req, res) => {
  res.json(anomalyDetector.getHistoricalHackers());
});

// Manejo de conexiones WebSocket
wss.on('connection', (ws) => {
  console.log('[WS] 🖥️ Cliente conectado a la estación Sentinel');

  // Enviar estado inicial
  ws.send(JSON.stringify({
    type: 'INIT',
    data: {
      status: packetEngine.getStatus(),
      snapshot: anomalyDetector.getSnapshot(packetEngine.selectedWindow),
      teleKills: apiHunter.getAlerts(),
      windows: packetEngine.getWindowsList(),
      selectedWindow: packetEngine.selectedWindow,
      hackers: anomalyDetector.getHistoricalHackers()
    }
  }));

  ws.on('message', async (raw) => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === 'INSPECT') {
        const profile = await apiHunter.getPlayerProfile(msg.name);
        ws.send(JSON.stringify({ type: 'PROFILE_RESULT', data: profile }));
      } else if (msg.type === 'SELECT_WINDOW') {
        packetEngine.selectedWindow = msg.port;
        ws.send(JSON.stringify({
          type: 'RADAR_UPDATE',
          data: anomalyDetector.getSnapshot(packetEngine.selectedWindow)
        }));
      } else if (msg.type === 'SET_PLAYER_NAME') {
        packetEngine.playerIndexToName.set(Number(msg.playerId), msg.name);
        const p = anomalyDetector.players.get(Number(msg.playerId));
        if (p) p.name = msg.name;
        broadcast({ type: 'RADAR_UPDATE', data: anomalyDetector.getSnapshot(packetEngine.selectedWindow) });
      }
    } catch (e) {}
  });
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.log('================================================================');
    console.log('ℹ️  EL SERVIDOR SENTINEL YA ESTÁ EN EJECUCIÓN ACTIVA');
    console.log(`🌐  Tu radar está abierto y funcionando en: http://localhost:${PORT}`);
    console.log('================================================================');
    setTimeout(() => process.exit(0), 1000);
  } else {
    console.error('Error en el servidor:', err.message);
  }
});

server.listen(PORT, () => {
  console.log('================================================================');
  console.log('🛡️  SMASH MU SENTINEL & AUDIT STATION INICIADA');
  console.log(`🌐  Interfaz Gráfica disponible en: http://localhost:${PORT}`);
  console.log('📡  Monitoreando: Invasiones, Speedhack de movimiento y Auto-Combos');
  console.log('================================================================');
});
