# 🛡️ Smash MU Sentinel · Estación Forense & Radar Anti-Cheat Pasivo

[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Npcap](https://img.shields.io/badge/Driver-Npcap_Kernel-0078D4?logo=windows&logoColor=white)](https://npcap.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Mu Online](https://img.shields.io/badge/Game-MU_Season_6_S6E3-crimson)](https://smashmu.com/)

**Smash MU Sentinel** es una estación de auditoría forense y radar anti-cheat pasivo en tiempo real diseñada para **detectar, medir matemáticamente y corroborar con pruebas irrefutables el uso de software ilegal (Speedhack, Auto-Combo Bots, Auto-Pot Bots y Tele-Kill)** en servidores de **MU Online Season 6** (desarrollado y calibrado para **Smash MU**).

A diferencia de los anticheats tradicionales intrusivos, Sentinel opera **100% de manera externa y pasiva en el kernel de red**:
* ❌ **CERO Inyección de DLLs** en el proceso del cliente.
* ❌ **CERO Lectura o Escritura en memoria RAM** (`ReadProcessMemory` / `WriteProcessMemory`).
* ❌ **CERO Modificación de archivos** del cliente (`main.exe`).
* ✅ **100% Indetectable y Seguro**: Funciona como un "radar de tráfico" capturando las tramas TCP que viajan por el cable de red / Wi-Fi entre tu PC y el GameServer oficial.

---

## 📑 Tabla de Contenidos
1. [Explicación Sencilla (Para Jugadores y GMs)](#-1-explicación-sencilla-para-jugadores-y-gms)
   - [¿Cómo funciona como un radar de tráfico?](#cómo-funciona-como-un-radar-de-tráfico)
   - [¿Cómo detecta el Speedhack?](#cómo-detecta-el-speedhack)
   - [¿Cómo detecta el Auto-Combo?](#cómo-detecta-el-auto-combo)
   - [¿Cómo detecta el Auto-Pot (Pociones infinitas)?](#cómo-detecta-el-auto-pot-pociones-infinitas)
   - [¿Por qué los Magos y Dark Lords no dan falsas alertas?](#por-qué-los-magos-y-dark-lords-no-dan-falsas-alertas)
2. [Explicación Técnica a Fondo (Motor, Protocolo y Matemáticas)](#-2-explicación-técnica-a-fondo-motor-protocolo-y-matemáticas)
   - [Arquitectura del Sniffer de Kernel](#arquitectura-del-sniffer-de-kernel)
   - [Matemáticas del Speedhack de Movimiento](#matemáticas-del-speedhack-de-movimiento)
   - [Fisiología y Mecánica del Auto-Combo](#fisiología-y-mecánica-del-auto-combo)
   - [Auditoría de Consumo de Pociones (Opcode 0x26)](#auditoría-de-consumo-de-pociones-opcode-0x26)
   - [Cazador de Invasiones & Tele-Kill](#cazador-de-invasiones--tele-kill)
   - [Aislamiento Multi-Ventana (Multi-Client Namespacing)](#aislamiento-multi-ventana-multi-client-namespacing)
3. [Trazabilidad Forense para Game Masters (GM)](#-3-trazabilidad-forense-para-game-masters-gm)
4. [Instalación y Puesta en Marcha](#-4-instalación-y-puesta-en-marcha)
5. [Estructura del Proyecto](#-5-estructura-del-proyecto)

---

## 🐣 1. Explicación Sencilla (Para Jugadores y GMs)

### ¿Cómo funciona como un radar de tráfico?
Imagina una autopista donde la policía instala una cámara con radar: la cámara no necesita subirse al auto del infractor ni revisar su motor; simplemente mide cuánto tiempo le tomó al auto pasar del Punto A al Punto B. Si la velocidad máxima permitida son 100 km/h y el auto pasó a 300 km/h, la matemática demuestra que violó las leyes físicas.

**Sentinel hace exactamente eso con el juego:**
Tu computadora recibe constantemente paquetes de datos del servidor que dicen: *"El jugador X se movió a la coordenada (120, 150) y usó la habilidad Cyclone"*. Sentinel escucha esos mensajes en tu tarjeta de red, anota la hora exacta con precisión de milisegundos y calcula las velocidades reales.

```
[ GameServer Smash MU ] 
       │ 
       ▼ (Tramas TCP en el cable de red)
┌──────────────────────────────────────────────┐
│  🛡️ SMASH MU SENTINEL (Kernel Sniffer Npcap) │  ◄── Pasivo (No toca main.exe)
└──────────────────────────────────────────────┘
       │ 
       ▼ 
[ Panel Web Táctico: http://localhost:4444 ]
  • Radar PvP en Vivo
  • Medidor de Casillas / Segundo
  • Cronómetro de Combos
  • Archivo Histórico de Hackers
```

### ¿Cómo detecta el Speedhack?
En el juego oficial, un personaje caminando con botas +15 avanza a unas **5 a 6 casillas por segundo**. Si va montado en un caballo (Dark Horse) o en un Fenrir con máxima agilidad, avanza como mucho a **11.5 casillas por segundo**.
* Si Sentinel detecta que un jugador recorrió 30 casillas en un segundo (**30 casillas/s**), demuestra que está usando programas como *Speed Gear* o *Cheat Engine* para acelerar el reloj de su juego.

### ¿Cómo detecta el Auto-Combo?
El combo de Blade Knight requiere apretar 3 habilidades diferentes de manera consecutiva (por ejemplo: `Cyclone` ➔ `Twisting Slash` ➔ `Death Stab`). 
* **Un humano experto** tarda entre **650 ms y 850 ms** en reaccionar con sus dedos y esperar que el juego termine las animaciones.
* **Un bot o macro ilegal** (como macros de mouse o inyectores de paquetes) corta la animación y manda las 3 habilidades en **80 a 140 ms**. Es humanamente imposible que una persona presione tres teclas en menos de lo que dura un parpadeo (un parpadeo humano dura 300 ms). Sentinel cronometra ese intervalo exacto.

### ¿Cómo detecta el Auto-Pot (Pociones infinitas)?
Un jugador apretando las teclas `Q`, `W`, `E` como loco puede consumir como máximo 6 a 8 pociones por segundo. El MU Helper oficial está limitado a unas 3 pociones por segundo.
* Si un jugador consume **25 a 35 pociones por segundo**, significa que tiene un script o macro inyectando paquetes de poción en loop. Por eso su barra de escudo (SD) parece inmortal en los duelos.

### ¿Por qué los Magos y Dark Lords no dan falsas alertas?
En MU Season 6, **ÚNICAMENTE los Blade Knights / Blade Masters pueden hacer combos**. Hechizos como *Evil Spirit* del Soul Master o *Fireburst* del Dark Lord golpean muchas veces por segundo por su propia naturaleza de área. Sentinel descarta automáticamente a los Magos, Dark Lords, Elfas y Summoners del análisis de combo para que **jamás existan falsos positivos**.

---

## 🔬 2. Explicación Técnica a Fondo (Motor, Protocolo y Matemáticas)

### Arquitectura del Sniffer de Kernel
Sentinel se integra directamente con el driver del kernel de Windows **Npcap** (`wpcap.dll`) mediante la biblioteca `cap`:
```
Tarjeta de Red Física (Intel Ethernet I226-V / Wi-Fi 6E)
                       │
                       ▼
            Driver de Kernel Npcap (BPF)
     Filtro BPF: "tcp and host 143.14.179.89"
                       │
                       ▼ (Ring Buffer de 10 MB)
             Decodificador Ethernet
                       │
             Decodificador IPv4
                       │
             Decodificador TCP (Reensamblado)
                       │
             Parser de Protocolo S6 (C1/C2/C3/C4)
```

1. **Auto-Detección de Adaptador Activo:** Consulta la tabla de conexiones de Windows (`netstat -ano`) y busca cuál es la IP local vinculada al GameServer (`143.14.179.89`), priorizando la interfaz física Ethernet por encima de interfaces virtuales (Hyper-V, VPNs).
2. **Buffer Circular de Alto Rendimiento:** Se asigna un búfer de **10 MB** para no perder ni un solo paquete durante el asedio (Castle Siege) o eventos masivos.

---

### Matemáticas del Speedhack de Movimiento
Cuando un personaje se desplaza, el servidor emite o recibe paquetes de movimiento (`Opcode 0xD9`, `0x15`, `0xD6` o `0xD4`). Sentinel extrae las coordenadas discretas $(x_1, y_1)$ y $(x_2, y_2)$ junto a una marca de tiempo de alta resolución $t_1, t_2$ en milisegundos.

1. **Distancia Euclidiana:**
   $$\Delta d = \sqrt{(x_2 - x_1)^2 + (y_2 - y_1)^2} \quad \text{[casillas/tiles]}$$

2. **Delta de Tiempo:**
   $$\Delta t = \frac{t_2 - t_1}{1000} \quad \text{[segundos]}$$

3. **Velocidad Instantánea y Ventana Móvil:**
   $$v_{\text{inst}} = \frac{\Delta d}{\Delta t}$$
   Para evitar falsos positivos provocados por tirones de conexión (jitter o lag spikes), Sentinel almacena un historial deslizante de los últimos 5 pasos ($N = 5$) y calcula la media armónica/promedio móvil:
   $$v_{\text{avg}} = \frac{1}{N} \sum_{i=1}^{N} v_i$$

4. **Umbrales del Motor Season 6:**
   * $v \le 6.5 \text{ cas/s}$: Caminata legal a pie.
   * $v \le 11.5 \text{ cas/s}$: Movimiento con montura (Dark Horse / Fenrir) a 65,000 de Agilidad.
   * $v > 14.5 \text{ cas/s}$: Estado sospechoso (alerta amarilla).
   * $v \ge 18.0 \text{ cas/s}$ de forma sostenida: **CRITICAL SPEEDHACK** (demuestra manipulación del `GetTickCount()` de Windows).

---

### Fisiología y Mecánica del Auto-Combo
En el motor Season 6, la mecánica de combo del Blade Knight está programada como una máquina de estados finitos (FSM):
$$\text{Fase 1 (Arma)} \xrightarrow{\Delta t_1} \text{Fase 2 (Slash)} \xrightarrow{\Delta t_2} \text{Fase 3 (Stab)} \Longrightarrow \text{Combo Burst}$$

* **Skills Válidas Fase 1 (Arma):** Cyclone (`19`), Slash (`20`), Falling Slash (`21`), Lunge (`22`), Uppercut (`23`).
* **Skills Válidas Fase 2:** Twisting Slash (`41`), Rageful Blow (`42`).
* **Skills Válidas Fase 3:** Death Stab (`43`), Crescent Moon Slash (`44`), Strike of Destruction (`48`), Blood Storm (`232`).

#### Análisis Temporal de Animación (`AttackTime`):
Cada habilidad tiene un tiempo mínimo de ejecución determinado por el archivo de cliente `Skill.bmd` y la agilidad del personaje:
* El tiempo de animación de *Death Stab* o *Cyclone* no puede bajar de **~350 ms** por limitación del motor.
* El tiempo de reacción motriz humana frente a estímulo visual es de **$\approx 200 - 250 \text{ ms}$**.
* Por lo tanto, un combo humano óptimo ronda los **$\ge 650 \text{ ms}$**.

#### Criterio de Detección de Bot:
$$\Delta t_{\text{combo}} = t_{\text{skill}_B} - t_{\text{skill}_A}$$
* **$\Delta t \le 160\text{ ms}$ entre habilidades distintas:** Solo puede lograrse mediante **cancelación forzada de animación (Animation Cancel Hook)** o inyección directa de paquetes en el socket TCP (`C1 08 19 ...`).

---

### Auditoría de Consumo de Pociones (Opcode 0x26)
* **Diferenciación de Sentido de Tráfico:**
  * **Paquete de Servidor (`Inbound`):** `C1 14 26 FF ...` es el GameServer sincronizando la barra de vida (`Life/SD update`). Sentinel **descarta** estos paquetes para evitar falsos positivos.
  * **Paquete de Cliente (`Outbound`):** `C1 04 26 [Slot] [Target]` emitido por el cliente al beber poción.
* **Frecuencia:**
  $$\text{Tasa} = \frac{\text{Pociones consumidas en ventana móvil}}{3.0 \text{ segundos}}$$
  * Consumo humano tope: $\le 8\text{ pots/s}$.
  * MU Helper oficial: $\approx 2 - 4\text{ pots/s}$.
  * Macro / Inyector: $\ge 18 - 32\text{ pots/s}$.

---

### Cazador de Invasiones & Tele-Kill
Monitorea la API pública de eventos de Smash MU (`/api/guild-leagues`).
Cuando un personaje abate a un Monstruo Dorado o Boss de Invasión:
1. Registra coordenadas del mapa de aparición $M_1$ y tiempo $t_1$.
2. Si el mismo personaje abate otro mob en un mapa distinto $M_2$ a tiempo $t_2$:
   $$\Delta t = t_2 - t_1$$
   Si $\Delta t < 25 \text{ segundos}$, es físicamente imposible que un jugador legítimo haya esperado el cooldown de portal, cargado la pantalla de carga, recorrido el mapa y encontrado al jefe sin teleport o speedhack de coordenadas.

---

### Aislamiento Multi-Ventana (Multi-Client Namespacing)
Cuando un jugador abre 4 o 5 ventanas de MU (`main.exe`) al mismo tiempo:
* Cada cliente utiliza un puerto TCP de origen diferente (`58076`, `58177`, `58812`, `62539`).
* El servidor reutiliza los mismos Player IDs pequeños (`0` a `10000`) para cada cliente en mapas distintos.
* **Solución de Sentinel:** Se crea una clave compuesta de aislamiento:
  $$\text{SessionKey} = \text{ClientPort} \mathbin{\Vert} \text{PlayerID} \quad (\text{ej: } ``58076\_1044'')$$
De esta manera, las coordenadas de los personajes en una ventana de Lorencia no colisionan ni interfieren con los personajes de otra ventana en Devias.

---

## 📋 3. Trazabilidad Forense para Game Masters (GM)

Los Game Masters no sancionan por sospechas visuales; auditan los archivos de texto que genera el **`GameServer.exe`** (ubicados normalmente en `C:\MuServer\GameServer\LOG\`).

Sentinel genera expedientes técnicos que coinciden con los campos de los logs del GameServer:

```text
════════════════════════════════════════════════════════════════
📋 EXPEDIENTE FORENSE PARA GAME MASTER (SMASH MU)
════════════════════════════════════════════════════════════════
👤 Infractor:         DaiKambe (Blade Master | 100 RR | Guild: TheKingz)
⏱️ Hora Local (PC):   14/10/2026, 04:45:12 GMT-5
🌐 Server Time (UTC): 2026-10-14T09:45:12.104Z
🔢 Epoch Timestamp:   1728899112104 ms
🔌 Sub-Servidor:      143.14.179.89:55100 (Sub-1 Free)
🚩 Infracción:        Auto-Combo Packet Injection (Bot / Macro ilegal)
⏱️ Cadencia / Delta:  104 ms entre habilidades consecutivas
════════════════════════════════════════════════════════════════
🔍 PRUEBA TÉCNICA Y TRAZA DE ENGINE:
• Paquetes capturados: C1 08 19 (Skill Attack)
• Secuencia: Skill ID 19 (Cyclone) ➔ Skill ID 41 (Twisting) ➔ Skill ID 43 (Death Stab)
• Razón matemática: El motor S6 impone un 'AttackTime' mínimo por animación de 
  350 ms - 450 ms. Una cadencia de 104 ms es fisiológicamente imposible para un 
  humano y demuestra inyección directa de paquetes (WPE / AHK / Cheat Engine).

💻 COMANDO PARA EL GM (Búsqueda directa en consola del VPS):
PowerShell: Select-String -Path "C:\MuServer\GameServer\LOG\*.log" -Pattern "DaiKambe.*(19|Skill)"
Linux:      grep -i "DaiKambe" /home/muserver/logs/GameServer.log | grep -E "(10[0-9]ms|Combo)"
════════════════════════════════════════════════════════════════
```

---

## 🚀 4. Instalación y Puesta en Marcha

### Prerrequisitos:
1. **Windows 10 u 11 (64-bit)**.
2. **Node.js 18 o superior**: [Descargar Node.js](https://nodejs.org/)
3. **Npcap**: [Descargar Npcap Installer](https://npcap.com/)
   * ⚠️ *Durante la instalación de Npcap, marca la casilla "Install Npcap in WinPcap API-compatible Mode".*

### Instalación:
```bash
# Clonar repositorio
git clone https://github.com/Ktols/SmashMu-Sentinel.git
cd SmashMu-Sentinel

# Instalar dependencias
npm install
```

### Ejecución:
* **Método 1 (Recomendado):** Haz doble clic en el archivo **`start.bat`**. Abrirá una consola con telemetría en tiempo real y desplegará el panel en tu navegador.
* **Método 2 (Terminal):**
  ```bash
  node server.js
  ```
* Abre tu navegador en:
  👉 **`http://localhost:4444`**

---

## 📁 5. Estructura del Proyecto

```text
SmashMu-Sentinel/
├── data/
│   └── alerts_history.json    # Base de datos permanente de infracciones
├── lib/
│   ├── anomalyDetector.js    # Motor heurístico y matemático de físicas
│   ├── muProtocol.js         # Constantes de protocolo, mapas, clases y skills S6
│   ├── packetEngine.js       # Sniffer BPF de bajo nivel Npcap y parser TCP
│   └── smashApiHunter.js     # Cliente de API de invasiones y perfiles Smash MU
├── public/
│   ├── app.js                # Controlador frontend de WebSocket y renderizado
│   ├── index.html            # Interfaz táctica (Radar, Invasiones, Lista Negra)
│   └── styles.css            # Estilos optimizados y responsive
├── package.json              # Metadatos del proyecto y dependencias
├── server.js                 # Servidor Express + WebSocket en puerto 4444
├── start.bat                 # Lanzador para Windows con telemetría en vivo
└── README.md                 # Documentación completa y manual de auditoría
```

---

## ⚖️ Licencia y Responsabilidad
Este software fue desarrollado con fines de investigación de seguridad informática, auditoría deportiva y preservación del juego limpio en comunidades de MU Online. No realiza ingeniería inversa invasiva ni modifica ejecutables binarios.
Distribuido bajo licencia **MIT**.
