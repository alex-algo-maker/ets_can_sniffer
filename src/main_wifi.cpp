/*
 * ETS CAN Bus Sniffer - WiFi Version
 *
 * Same passive CAN sniffer as main.cpp but adds a WiFi access point and
 * web interface so you can view live traffic from a phone or tablet
 * without needing a serial cable. Useful when the ESP32 is mounted in
 * the engine bay and the laptop is at the helm.
 *
 * The ESP32 creates its own WiFi network (access point mode, no router
 * needed). Connect to it and browse to the web UI to see messages,
 * change baud rate, and download CSV logs.
 *
 * WiFi AP: "ETS_Sniffer" / password: "canbuslog"
 * Web UI:  http://192.168.4.1
 *
 * CAN bus operation is identical to the serial version: listen-only mode,
 * no transmissions, no ACKs, invisible on the bus.
 *
 * Wiring (ESP32 to MCP2515 + SN65HVD230 module, 8 MHz crystal):
 *   ESP32 GPIO23  -> MCP2515 MOSI  (SPI data out)
 *   ESP32 GPIO19  -> MCP2515 MISO  (SPI data in)
 *   ESP32 GPIO18  -> MCP2515 SCK   (SPI clock)
 *   ESP32 GPIO5   -> MCP2515 CS    (SPI chip select)
 *   ESP32 GPIO4   -> MCP2515 INT   (interrupt, active low)
 *   ESP32 3.3V    -> MCP2515 VCC
 *   ESP32 GND     -> MCP2515 GND
 *   MCP2515 CANH  -> ETS CAN Bus High (parallel tap)
 *   MCP2515 CANL  -> ETS CAN Bus Low  (parallel tap)
 */

#include <Arduino.h>
#include <SPI.h>
#include <mcp_can.h>
#include <WiFi.h>
#include <WebServer.h>

// ============== CONFIGURATION ==============

#define CAN_CS_PIN 5
#define CAN_INT_PIN 4

MCP_CAN CAN(CAN_CS_PIN);

const char* AP_SSID = "ETS_Sniffer";
const char* AP_PASS = "canbuslog";

typedef enum { BAUD_125K, BAUD_250K, BAUD_500K, BAUD_1M } can_baud_t;
can_baud_t currentBaud = BAUD_250K;

// ============== GLOBALS ==============

WebServer server(80);

unsigned long messageCount = 0;
unsigned long errorCount = 0;
unsigned long startTime = 0;

// Ring buffer for CAN messages and inline annotations.
// Annotations use isMark=true and store text in markText.
#define LOG_BUFFER_SIZE 500
struct LogEntry {
    unsigned long timestamp;
    uint32_t seq;           // Monotonic sequence number for dedup by polling clients
    uint32_t id;
    bool extended;
    bool rtr;
    uint8_t dlc;
    uint8_t data[8];
    bool isMark;
    char markText[40];
};
LogEntry logBuffer[LOG_BUFFER_SIZE];
int logHead = 0;
int logCount = 0;
uint32_t nextSeq = 1;      // Global sequence counter, never resets to 0

// Unique ID tracking with last-seen data for the web UI.
#define MAX_UNIQUE_IDS 256
uint32_t seenIds[MAX_UNIQUE_IDS];
unsigned long idCounts[MAX_UNIQUE_IDS];
uint8_t lastData[MAX_UNIQUE_IDS][8];
int uniqueIdCount = 0;

// ============== CAN FUNCTIONS ==============

const char* baudToString(can_baud_t baud) {
    switch(baud) {
        case BAUD_125K: return "125kbps";
        case BAUD_250K: return "250kbps";
        case BAUD_500K: return "500kbps";
        case BAUD_1M:   return "1Mbps";
        default:        return "Unknown";
    }
}

byte getMcpBaud(can_baud_t baud) {
    switch(baud) {
        case BAUD_125K: return CAN_125KBPS;
        case BAUD_250K: return CAN_250KBPS;
        case BAUD_500K: return CAN_500KBPS;
        case BAUD_1M:   return CAN_1000KBPS;
        default:        return CAN_250KBPS;
    }
}

bool initCAN(can_baud_t baud) {
    byte result = CAN.begin(MCP_ANY, getMcpBaud(baud), MCP_8MHZ);
    if (result != CAN_OK) return false;

    CAN.setMode(MCP_LISTENONLY);
    return true;
}

int findOrAddId(uint32_t id, uint8_t* data, uint8_t dlc) {
    for (int i = 0; i < uniqueIdCount; i++) {
        if (seenIds[i] == id) {
            idCounts[i]++;
            memcpy(lastData[i], data, dlc);
            return i;
        }
    }

    if (uniqueIdCount < MAX_UNIQUE_IDS) {
        seenIds[uniqueIdCount] = id;
        idCounts[uniqueIdCount] = 1;
        memcpy(lastData[uniqueIdCount], data, dlc);
        uniqueIdCount++;
        return uniqueIdCount - 1;
    }
    return -1;
}

// Adds a CAN frame to the ring buffer.
void addToLog(uint32_t id, bool extended, bool rtr, uint8_t dlc, uint8_t* data) {
    LogEntry* entry = &logBuffer[logHead];
    entry->timestamp = millis() - startTime;
    entry->seq = nextSeq++;
    entry->id = id;
    entry->extended = extended;
    entry->rtr = rtr;
    entry->dlc = dlc;
    memcpy(entry->data, data, 8);
    entry->isMark = false;
    entry->markText[0] = '\0';

    logHead = (logHead + 1) % LOG_BUFFER_SIZE;
    if (logCount < LOG_BUFFER_SIZE) logCount++;
}

// Adds an annotation mark to the ring buffer, inline with CAN data.
void addMarkToLog(const char* text) {
    LogEntry* entry = &logBuffer[logHead];
    entry->timestamp = millis() - startTime;
    entry->seq = nextSeq++;
    entry->id = 0;
    entry->extended = false;
    entry->rtr = false;
    entry->dlc = 0;
    memset(entry->data, 0, 8);
    entry->isMark = true;
    strncpy(entry->markText, text, sizeof(entry->markText) - 1);
    entry->markText[sizeof(entry->markText) - 1] = '\0';

    logHead = (logHead + 1) % LOG_BUFFER_SIZE;
    if (logCount < LOG_BUFFER_SIZE) logCount++;

    // Mirror to serial
    Serial.printf("%lu,MARK,0,0,0,%s\n", entry->timestamp, entry->markText);
}

// ============== WEB HANDLERS ==============

void handleRoot() {
    String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
    <title>ETS CAN Sniffer</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: monospace; margin: 10px; background: #1a1a2e; color: #eee; }
        h1 { color: #00d4ff; margin: 10px 0; }
        h2 { margin: 15px 0 8px 0; }
        .status { background: #16213e; padding: 12px; border-radius: 8px; margin-bottom: 12px; }
        .controls { margin-bottom: 12px; }
        button { background: #00d4ff; color: #000; border: none; padding: 10px 16px; margin: 3px; cursor: pointer; border-radius: 4px; font-size: 14px; }
        button:hover { background: #00a8cc; }
        button:active { background: #0088aa; }
        table { border-collapse: collapse; width: 100%; background: #16213e; }
        th, td { border: 1px solid #333; padding: 6px 8px; text-align: left; }
        th { background: #0f3460; }
        .data { font-family: monospace; color: #00ff88; }
        #log { max-height: 400px; overflow-y: auto; }
        .id-summary { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px; }
        .id-card { background: #0f3460; padding: 10px; border-radius: 4px; }
        .mark-section { background: #1e2a3a; padding: 12px; border-radius: 8px; margin-bottom: 12px; border: 1px solid #00d4ff44; }
        .mark-buttons { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 8px; }
        .mark-buttons button { background: #e67e22; font-weight: bold; }
        .mark-buttons button:hover { background: #d35400; }
        .mark-buttons button:active { background: #a04000; }
        .mark-custom { display: flex; gap: 6px; }
        .mark-custom input { flex: 1; padding: 10px; border-radius: 4px; border: 1px solid #555; background: #0f1a2e; color: #eee; font-size: 14px; font-family: monospace; }
        .mark-row { background: #3d1f00 !important; }
        .mark-row td { color: #e67e22; font-weight: bold; border-color: #e67e2244; }
        .flash { animation: flashbg 0.3s; }
        @keyframes flashbg { 0% { background: #e67e22; } 100% { background: transparent; } }
    </style>
</head>
<body>
    <h1>ETS CAN Bus Sniffer</h1>

    <div class="status">
        <strong>Status:</strong> <span id="status">Loading...</span> |
        <strong>Baud:</strong> <span id="baud">--</span> |
        <strong>Msgs:</strong> <span id="msgcount">0</span> |
        <strong>Err:</strong> <span id="errcount">0</span> |
        <strong>IDs:</strong> <span id="idcount">0</span>
    </div>

    <div class="mark-section">
        <strong>Helm Action Markers</strong>
        <div class="mark-buttons">
            <button onclick="mark('Shift FWD')">Shift FWD</button>
            <button onclick="mark('Shift NEU')">Shift NEU</button>
            <button onclick="mark('Shift REV')">Shift REV</button>
            <button onclick="mark('Throttle UP')">Throt UP</button>
            <button onclick="mark('Throttle DOWN')">Throt DOWN</button>
            <button onclick="mark('Throttle IDLE')">Throt IDLE</button>
            <button onclick="mark('Throttle FULL')">Throt FULL</button>
            <button onclick="mark('Key ON')">Key ON</button>
            <button onclick="mark('Key OFF')">Key OFF</button>
            <button onclick="mark('Engine START')">Eng START</button>
            <button onclick="mark('Engine STOP')">Eng STOP</button>
        </div>
        <div class="mark-custom">
            <input type="text" id="custommark" placeholder="Custom note..." onkeydown="if(event.key==='Enter')markCustom()">
            <button onclick="markCustom()">Mark</button>
        </div>
    </div>

    <div class="controls">
        <strong>Baud Rate:</strong>
        <button onclick="setBaud(1)">125k</button>
        <button onclick="setBaud(2)">250k</button>
        <button onclick="setBaud(3)">500k</button>
        <button onclick="setBaud(4)">1M</button>
        <button onclick="clearLog()">Clear</button>
        <button onclick="downloadCSV()">Download CSV</button>
        <button onclick="runScan()" id="scanbtn" style="background:#e67e22;font-weight:bold">Scan Baud Rates</button>
    </div>

    <div id="scanresults" style="display:none; background:#16213e; padding:12px; border-radius:8px; margin-bottom:12px;"></div>

    <h2>Unique IDs (Live Values)</h2>
    <div id="ids" class="id-summary"></div>

    <h2>Recent Messages</h2>
    <div id="log">
        <table>
            <thead><tr><th>Time (ms)</th><th>ID</th><th>DLC</th><th>Data</th></tr></thead>
            <tbody id="logtable"></tbody>
        </table>
    </div>

    <script>
        function mark(msg) {
            fetch('/mark?msg=' + encodeURIComponent(msg));
            // Flash the button for feedback
            event.target.classList.add('flash');
            setTimeout(() => event.target.classList.remove('flash'), 300);
        }

        function markCustom() {
            let input = document.getElementById('custommark');
            let msg = input.value.trim();
            if (msg) {
                fetch('/mark?msg=' + encodeURIComponent(msg));
                input.value = '';
            }
            input.focus();
        }

        function updateStatus() {
            fetch('/status').then(r => r.json()).then(data => {
                document.getElementById('status').textContent = data.running ? 'Running' : 'Stopped';
                document.getElementById('baud').textContent = data.baud;
                document.getElementById('msgcount').textContent = data.messages;
                document.getElementById('errcount').textContent = data.errors;
                document.getElementById('idcount').textContent = data.uniqueIds;
            });
        }

        function updateIds() {
            fetch('/ids').then(r => r.json()).then(data => {
                let html = '';
                data.forEach(id => {
                    html += `<div class="id-card">
                        <strong>0x${id.id.toString(16).toUpperCase().padStart(3,'0')}</strong>
                        (${id.count})<br>
                        <span class="data">${id.data}</span>
                    </div>`;
                });
                document.getElementById('ids').innerHTML = html;
            });
        }

        function updateLog() {
            fetch('/log').then(r => r.json()).then(data => {
                let html = '';
                data.reverse().forEach(msg => {
                    if (msg.mark) {
                        html += `<tr class="mark-row">
                            <td>${msg.t}</td>
                            <td colspan="3">>>> ${msg.mark}</td>
                        </tr>`;
                    } else {
                        html += `<tr>
                            <td>${msg.t}</td>
                            <td>0x${msg.id.toString(16).toUpperCase().padStart(3,'0')}</td>
                            <td>${msg.dlc}</td>
                            <td class="data">${msg.data}</td>
                        </tr>`;
                    }
                });
                document.getElementById('logtable').innerHTML = html;
            });
        }

        function setBaud(b) {
            fetch('/baud?v=' + b).then(() => updateStatus());
        }

        function clearLog() {
            fetch('/clear').then(() => { updateStatus(); updateIds(); updateLog(); });
        }

        function downloadCSV() {
            window.location.href = '/csv';
        }

        function runScan() {
            let btn = document.getElementById('scanbtn');
            let div = document.getElementById('scanresults');
            btn.textContent = 'Scanning (~12s)...';
            btn.disabled = true;
            div.style.display = 'block';
            div.innerHTML = '<strong>Scanning all baud rates (3s each)...</strong>';
            fetch('/scan', {timeout: 20000}).then(r => r.json()).then(data => {
                let html = '<strong>Baud Rate Scan Results:</strong><br><table style="margin-top:8px"><tr><th>Baud</th><th>Msgs</th><th>Unique IDs</th><th>Repeat Rate</th><th>Verdict</th></tr>';
                data.forEach(r => {
                    let style = r.verdict === 'LIKELY CORRECT' ? ' style="color:#00ff88;font-weight:bold"' : '';
                    html += '<tr'+style+'><td>'+r.baud+'</td><td>'+r.msgs+'</td><td>'+r.ids+'</td><td>'+r.repeat+'</td><td>'+r.verdict+'</td></tr>';
                    if (r.idList) {
                        html += '<tr'+style+'><td></td><td colspan="4">';
                        r.idList.forEach(id => { html += id.id+'('+id.n+') '; });
                        html += '</td></tr>';
                    }
                });
                html += '</table>';
                div.innerHTML = html;
                btn.textContent = 'Scan Baud Rates';
                btn.disabled = false;
                updateStatus();
            }).catch(() => {
                div.innerHTML = '<strong style="color:red">Scan timed out or failed</strong>';
                btn.textContent = 'Scan Baud Rates';
                btn.disabled = false;
            });
        }

        setInterval(updateStatus, 2000);
        setInterval(updateIds, 1000);
        setInterval(updateLog, 500);

        updateStatus();
        updateIds();
        updateLog();
    </script>
</body>
</html>
)rawliteral";
    server.send(200, "text/html", html);
}

void handleStatus() {
    String json = "{";
    json += "\"running\":true,";
    json += "\"baud\":\"" + String(baudToString(currentBaud)) + "\",";
    json += "\"messages\":" + String(messageCount) + ",";
    json += "\"errors\":" + String(errorCount) + ",";
    json += "\"uniqueIds\":" + String(uniqueIdCount);
    json += "}";
    server.send(200, "application/json", json);
}

void handleIds() {
    String json = "[";
    for (int i = 0; i < uniqueIdCount; i++) {
        if (i > 0) json += ",";
        json += "{\"id\":" + String(seenIds[i]);
        json += ",\"count\":" + String(idCounts[i]);
        json += ",\"data\":\"";
        for (int j = 0; j < 8; j++) {
            if (j > 0) json += " ";
            if (lastData[i][j] < 16) json += "0";
            json += String(lastData[i][j], HEX);
        }
        json += "\"}";
    }
    json += "]";
    server.send(200, "application/json", json);
}

void handleLog() {
    String json = "[";
    int count = min(100, logCount);
    int idx = (logHead - count + LOG_BUFFER_SIZE) % LOG_BUFFER_SIZE;

    for (int i = 0; i < count; i++) {
        if (i > 0) json += ",";
        LogEntry* e = &logBuffer[idx];

        if (e->isMark) {
            json += "{\"s\":" + String(e->seq);
            json += ",\"t\":" + String(e->timestamp);
            json += ",\"mark\":\"" + String(e->markText) + "\"}";
        } else {
            json += "{\"s\":" + String(e->seq);
            json += ",\"t\":" + String(e->timestamp);
            json += ",\"id\":" + String(e->id);
            json += ",\"dlc\":" + String(e->dlc);
            json += ",\"data\":\"";
            for (int j = 0; j < e->dlc; j++) {
                if (j > 0) json += " ";
                if (e->data[j] < 16) json += "0";
                json += String(e->data[j], HEX);
            }
            json += "\"}";
        }
        idx = (idx + 1) % LOG_BUFFER_SIZE;
    }
    json += "]";
    server.send(200, "application/json", json);
}

void handleBaud() {
    if (server.hasArg("v")) {
        int v = server.arg("v").toInt();
        switch(v) {
            case 1: currentBaud = BAUD_125K; break;
            case 2: currentBaud = BAUD_250K; break;
            case 3: currentBaud = BAUD_500K; break;
            case 4: currentBaud = BAUD_1M; break;
        }
        initCAN(currentBaud);
    }
    server.send(200, "text/plain", "OK");
}

// GET /mark?msg=... -- adds an annotation to the log at the current timestamp.
void handleMark() {
    if (server.hasArg("msg")) {
        String msg = server.arg("msg");
        msg.trim();
        if (msg.length() > 0) {
            addMarkToLog(msg.c_str());
        }
    }
    server.send(200, "text/plain", "OK");
}

// GET /scan -- tries each baud rate for 3 seconds and returns JSON results.
// Blocks for ~12 seconds total. The web UI shows a results table.
void handleScan() {
    can_baud_t rates[] = { BAUD_125K, BAUD_250K, BAUD_500K, BAUD_1M };
    int bestRate = -1;
    float bestScore = 0;

    String json = "[";

    for (int r = 0; r < 4; r++) {
        if (r > 0) json += ",";

        if (!initCAN(rates[r])) {
            json += "{\"baud\":\"" + String(baudToString(rates[r])) + "\",\"msgs\":0,\"ids\":0,\"repeat\":0,\"verdict\":\"INIT FAIL\"}";
            continue;
        }

        int scanUniqueIds = 0;
        unsigned long scanMsgCount = 0;
        uint32_t scanIds[64];
        unsigned long scanIdCounts[64];
        memset(scanIds, 0, sizeof(scanIds));
        memset(scanIdCounts, 0, sizeof(scanIdCounts));

        unsigned long scanStart = millis();
        while (millis() - scanStart < 3000) {
            if (digitalRead(CAN_INT_PIN) == LOW) {
                unsigned long rxId;
                uint8_t dlc;
                uint8_t data[8];

                if (CAN.readMsgBuf(&rxId, &dlc, data) == CAN_OK) {
                    uint32_t canId = rxId & 0x1FFFFFFF;
                    scanMsgCount++;

                    bool found = false;
                    for (int i = 0; i < scanUniqueIds; i++) {
                        if (scanIds[i] == canId) {
                            scanIdCounts[i]++;
                            found = true;
                            break;
                        }
                    }
                    if (!found && scanUniqueIds < 64) {
                        scanIds[scanUniqueIds] = canId;
                        scanIdCounts[scanUniqueIds] = 1;
                        scanUniqueIds++;
                    }
                }
            }
        }

        float repeatRate = 0;
        if (scanUniqueIds > 0 && scanMsgCount > 0) {
            repeatRate = (float)scanMsgCount / (float)scanUniqueIds;
        }

        float score = repeatRate;
        if (scanUniqueIds > 30) score *= 0.1f;

        const char* verdict;
        if (scanMsgCount == 0) {
            verdict = "NO DATA";
        } else if (scanUniqueIds <= 20 && repeatRate > 10) {
            verdict = "LIKELY CORRECT";
        } else if (scanUniqueIds > 30) {
            verdict = "Noise";
        } else {
            verdict = "Uncertain";
        }

        json += "{\"baud\":\"" + String(baudToString(rates[r])) + "\"";
        json += ",\"msgs\":" + String(scanMsgCount);
        json += ",\"ids\":" + String(scanUniqueIds);
        json += ",\"repeat\":" + String(repeatRate, 1);
        json += ",\"verdict\":\"" + String(verdict) + "\"";

        // Include the actual IDs if it looks like real traffic
        if (scanUniqueIds > 0 && scanUniqueIds <= 20) {
            json += ",\"idList\":[";
            for (int i = 0; i < scanUniqueIds; i++) {
                if (i > 0) json += ",";
                json += "{\"id\":\"0x" + String(scanIds[i], HEX) + "\",\"n\":" + String(scanIdCounts[i]) + "}";
            }
            json += "]";
        }

        json += "}";

        if (score > bestScore) {
            bestScore = score;
            bestRate = r;
        }
    }
    json += "]";

    // Switch to the best rate found
    if (bestRate >= 0) {
        currentBaud = rates[bestRate];
    }
    initCAN(currentBaud);

    server.send(200, "application/json", json);
}

void handleClear() {
    messageCount = 0;
    errorCount = 0;
    uniqueIdCount = 0;
    logHead = 0;
    logCount = 0;
    startTime = millis();
    server.send(200, "text/plain", "OK");
}

void handleCSV() {
    String csv = "timestamp,id,extended,rtr,dlc,data\n";
    int start = (logCount < LOG_BUFFER_SIZE) ? 0 : logHead;

    for (int i = 0; i < logCount; i++) {
        int idx = (start + i) % LOG_BUFFER_SIZE;
        LogEntry* e = &logBuffer[idx];

        if (e->isMark) {
            csv += String(e->timestamp) + ",MARK,0,0,0,";
            csv += String(e->markText);
            csv += "\n";
        } else {
            csv += String(e->timestamp) + ",";
            csv += "0x" + String(e->id, HEX) + ",";
            csv += String(e->extended) + ",";
            csv += String(e->rtr) + ",";
            csv += String(e->dlc) + ",";
            for (int j = 0; j < e->dlc; j++) {
                if (j > 0) csv += " ";
                if (e->data[j] < 16) csv += "0";
                csv += String(e->data[j], HEX);
            }
            csv += "\n";
        }
    }

    server.sendHeader("Content-Disposition", "attachment; filename=ets_can_log.csv");
    server.send(200, "text/csv", csv);
}

// ============== MAIN ==============

void setup() {
    Serial.begin(115200);
    delay(2000);

    pinMode(CAN_INT_PIN, INPUT);

    Serial.println("\n\nETS CAN Sniffer - WiFi Version (MCP2515)");
    Serial.println("==========================================");

    WiFi.softAP(AP_SSID, AP_PASS);
    Serial.print("WiFi AP started: ");
    Serial.println(AP_SSID);
    Serial.print("IP: ");
    Serial.println(WiFi.softAPIP());

    server.on("/", handleRoot);
    server.on("/status", handleStatus);
    server.on("/ids", handleIds);
    server.on("/log", handleLog);
    server.on("/baud", handleBaud);
    server.on("/mark", handleMark);
    server.on("/scan", handleScan);
    server.on("/clear", handleClear);
    server.on("/csv", handleCSV);
    server.begin();
    Serial.println("Web server started on port 80");

    if (!initCAN(currentBaud)) {
        Serial.println("FATAL: MCP2515 init failed!");
        while(1) delay(1000);
    }
    Serial.printf("CAN initialised at %s (MCP2515, 8 MHz crystal)\n", baudToString(currentBaud));

    startTime = millis();
    Serial.println("Ready! Connect to WiFi and browse to http://192.168.4.1");
}

void loop() {
    server.handleClient();

    if (digitalRead(CAN_INT_PIN) == LOW) {
        unsigned long rxId;
        uint8_t dlc;
        uint8_t data[8];

        byte result = CAN.readMsgBuf(&rxId, &dlc, data);

        if (result == CAN_OK) {
            bool extended = (rxId & 0x80000000) != 0;
            bool rtr = (rxId & 0x40000000) != 0;
            uint32_t canId = rxId & 0x1FFFFFFF;

            messageCount++;
            findOrAddId(canId, data, dlc);
            addToLog(canId, extended, rtr, dlc, data);
        }
    }
}
