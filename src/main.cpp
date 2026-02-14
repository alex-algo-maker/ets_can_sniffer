/*
 * ETS CAN Bus Sniffer - Serial Version
 *
 * Passive CAN bus sniffer for reverse-engineering the Cummins MerCruiser
 * Diesel Electronic Throttle & Shift (ETS) system. Operates in listen-only
 * mode so the MCP2515 never transmits or acknowledges frames, making it
 * safe to connect to a live system.
 *
 * Output is CSV over serial, suitable for logging to a file and later
 * analysis in a spreadsheet or Python script.
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
 *
 * Make sure the 120 ohm termination jumper on the module is
 * REMOVED when tapping into an already-terminated bus.
 */

#include <Arduino.h>
#include <SPI.h>
#include <mcp_can.h>

// ============== CONFIGURATION ==============

#define CAN_CS_PIN 5
#define CAN_INT_PIN 4

MCP_CAN CAN(CAN_CS_PIN);

typedef enum {
    BAUD_125K,
    BAUD_250K,
    BAUD_500K,
    BAUD_1M
} can_baud_t;

can_baud_t currentBaud = BAUD_250K;

// ============== GLOBALS ==============

unsigned long messageCount = 0;
unsigned long errorCount = 0;
unsigned long startTime = 0;

#define MAX_UNIQUE_IDS 256
uint32_t seenIds[MAX_UNIQUE_IDS];
unsigned long idCounts[MAX_UNIQUE_IDS];
int uniqueIdCount = 0;

// Flag set when 'm' is pressed -- the next line of serial input
// will be captured as an annotation rather than treated as commands.
bool awaitingMark = false;

// Forward declarations
void clearCounts();

// ============== CAN SETUP ==============

const char* baudToString(can_baud_t baud) {
    switch(baud) {
        case BAUD_125K: return "125 kbps";
        case BAUD_250K: return "250 kbps";
        case BAUD_500K: return "500 kbps";
        case BAUD_1M:   return "1 Mbps";
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
    if (result != CAN_OK) {
        Serial.printf("Failed to initialise MCP2515: %d\n", result);
        return false;
    }

    CAN.setMode(MCP_LISTENONLY);
    Serial.printf("CAN initialised at %s (MCP2515, 8 MHz crystal)\n", baudToString(baud));
    return true;
}

// ============== MESSAGE TRACKING ==============

int findOrAddId(uint32_t id) {
    for (int i = 0; i < uniqueIdCount; i++) {
        if (seenIds[i] == id) {
            idCounts[i]++;
            return i;
        }
    }

    if (uniqueIdCount < MAX_UNIQUE_IDS) {
        seenIds[uniqueIdCount] = id;
        idCounts[uniqueIdCount] = 1;
        uniqueIdCount++;
        return uniqueIdCount - 1;
    }

    return -1;
}

// Format: TIMESTAMP_MS,CAN_ID,EXTENDED,RTR,DLC,DATA_BYTES
void printMessageHex(uint32_t id, bool extended, bool rtr, uint8_t dlc, uint8_t* data) {
    unsigned long timestamp = millis() - startTime;

    Serial.printf("%lu,", timestamp);

    if (extended) {
        Serial.printf("0x%08X,", id);
    } else {
        Serial.printf("0x%03X,", id);
    }

    Serial.printf("%d,%d,%d,",
        extended ? 1 : 0,
        rtr ? 1 : 0,
        dlc);

    for (int i = 0; i < dlc; i++) {
        Serial.printf("%02X", data[i]);
        if (i < dlc - 1) Serial.print(" ");
    }

    Serial.println();
}

void printStatus() {
    Serial.println("\n========== STATUS ==========");
    Serial.printf("Uptime: %lu ms\n", millis() - startTime);
    Serial.printf("Baud rate: %s\n", baudToString(currentBaud));
    Serial.printf("Messages received: %lu\n", messageCount);
    Serial.printf("Errors: %lu\n", errorCount);
    Serial.printf("Unique CAN IDs seen: %d\n", uniqueIdCount);

    if (uniqueIdCount > 0) {
        Serial.println("\nID Summary:");
        for (int i = 0; i < uniqueIdCount; i++) {
            Serial.printf("  0x%03X: %lu messages\n", seenIds[i], idCounts[i]);
        }
    }
    Serial.println("============================\n");
}

void printHelp() {
    Serial.println("\n========== COMMANDS ==========");
    Serial.println("1 - Set baud to 125 kbps");
    Serial.println("2 - Set baud to 250 kbps (default, most common)");
    Serial.println("3 - Set baud to 500 kbps");
    Serial.println("4 - Set baud to 1 Mbps");
    Serial.println("a - Auto-scan all baud rates");
    Serial.println("s - Print status summary");
    Serial.println("c - Clear message counts");
    Serial.println("m - Add annotation mark (type text, press enter)");
    Serial.println("h - Print this help");
    Serial.println("==============================\n");
}

// Tries each baud rate for a few seconds and reports which one looks
// like real CAN traffic vs decoded noise. Real traffic has a small
// number of IDs that repeat consistently. Noise produces many random IDs.
void autoScan() {
    Serial.println("\n========== AUTO-SCAN ==========");
    Serial.println("Testing each baud rate for 5 seconds...\n");

    can_baud_t rates[] = { BAUD_125K, BAUD_250K, BAUD_500K, BAUD_1M };
    int bestRate = -1;
    float bestScore = 0;

    for (int r = 0; r < 4; r++) {
        if (!initCAN(rates[r])) {
            Serial.printf("  %s: FAILED to init\n", baudToString(rates[r]));
            continue;
        }

        // Reset tracking
        int scanUniqueIds = 0;
        unsigned long scanMsgCount = 0;
        unsigned long scanErrCount = 0;
        uint32_t scanIds[64];
        unsigned long scanIdCounts[64];
        memset(scanIds, 0, sizeof(scanIds));
        memset(scanIdCounts, 0, sizeof(scanIdCounts));

        unsigned long scanStart = millis();
        while (millis() - scanStart < 5000) {
            if (digitalRead(CAN_INT_PIN) == LOW) {
                unsigned long rxId;
                uint8_t dlc;
                uint8_t data[8];

                if (CAN.readMsgBuf(&rxId, &dlc, data) == CAN_OK) {
                    uint32_t canId = rxId & 0x1FFFFFFF;
                    scanMsgCount++;

                    // Track unique IDs (up to 64 for the scan)
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
                } else {
                    scanErrCount++;
                }
            }
        }

        // Score this baud rate. Real CAN traffic has:
        //   - Few unique IDs (3-20 typically)
        //   - High repeat rate (each ID seen many times)
        //   - Low error count relative to message count
        // Noise has many unique IDs with low repeat counts.
        float repeatRate = 0;
        if (scanUniqueIds > 0 && scanMsgCount > 0) {
            repeatRate = (float)scanMsgCount / (float)scanUniqueIds;
        }
        float errRate = 0;
        if (scanMsgCount + scanErrCount > 0) {
            errRate = (float)scanErrCount / (float)(scanMsgCount + scanErrCount) * 100.0f;
        }

        // Higher repeat rate + fewer unique IDs = more likely real traffic
        float score = repeatRate;
        if (scanUniqueIds > 30) score *= 0.1f;  // Penalise many random IDs

        const char* verdict;
        if (scanMsgCount == 0) {
            verdict = "NO DATA";
        } else if (scanUniqueIds <= 20 && repeatRate > 10) {
            verdict = "<-- LIKELY CORRECT";
        } else if (scanUniqueIds > 30) {
            verdict = "noise (random IDs)";
        } else {
            verdict = "uncertain";
        }

        Serial.printf("  %s: %lu msgs, %d unique IDs, %.1f repeat rate, "
                       "%.0f%% errors  %s\n",
            baudToString(rates[r]), scanMsgCount, scanUniqueIds,
            repeatRate, errRate, verdict);

        // Print the IDs seen if it looks like real traffic
        if (scanUniqueIds > 0 && scanUniqueIds <= 20) {
            Serial.print("    IDs:");
            for (int i = 0; i < scanUniqueIds; i++) {
                Serial.printf(" 0x%03X(%lu)", scanIds[i], scanIdCounts[i]);
            }
            Serial.println();
        }

        if (score > bestScore) {
            bestScore = score;
            bestRate = r;
        }
    }

    Serial.println();
    if (bestRate >= 0) {
        Serial.printf("Best match: %s\n", baudToString(rates[bestRate]));
        // Switch to the best rate
        currentBaud = rates[bestRate];
        initCAN(currentBaud);
        clearCounts();
    } else {
        Serial.println("No valid traffic detected at any rate.");
        initCAN(currentBaud);
    }
    Serial.println("===============================\n");
}

void clearCounts() {
    messageCount = 0;
    errorCount = 0;
    uniqueIdCount = 0;
    memset(seenIds, 0, sizeof(seenIds));
    memset(idCounts, 0, sizeof(idCounts));
    startTime = millis();
    Serial.println("Counts cleared.");
}

// ============== MAIN ==============

void setup() {
    Serial.begin(115200);
    delay(2000);

    pinMode(CAN_INT_PIN, INPUT);

    Serial.println("\n\n");
    Serial.println("================================================");
    Serial.println("   ETS CAN Bus Sniffer - ESP32 + MCP2515");
    Serial.println("   For Cummins MerCruiser Diesel ETS System");
    Serial.println("================================================");
    Serial.printf("SPI CS Pin:  GPIO%d\n", CAN_CS_PIN);
    Serial.printf("INT Pin:     GPIO%d\n", CAN_INT_PIN);
    Serial.println("SPI Bus:     VSPI (MOSI=23, MISO=19, SCK=18)");
    Serial.println("Crystal:     8 MHz");
    Serial.println();

    printHelp();

    if (!initCAN(currentBaud)) {
        Serial.println("FATAL: Could not initialise MCP2515!");
        while(1) { delay(1000); }
    }

    startTime = millis();

    Serial.println("\nListening for CAN messages...");
    Serial.println("Format: TIMESTAMP_MS,ID,EXTENDED,RTR,DLC,DATA\n");
}

void loop() {
    // --- 1. Try to receive a CAN frame ---
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
            findOrAddId(canId);
            printMessageHex(canId, extended, rtr, dlc, data);
        } else {
            errorCount++;
            if (errorCount % 100 == 1) {
                Serial.printf("CAN read error: %d (total errors: %lu)\n", result, errorCount);
            }
        }
    }

    // --- 2. Check for serial commands ---
    if (Serial.available()) {
        if (awaitingMark) {
            // Read the full line as an annotation
            String markText = Serial.readStringUntil('\n');
            markText.trim();
            if (markText.length() > 0) {
                unsigned long timestamp = millis() - startTime;
                Serial.printf("%lu,MARK,0,0,0,%s\n", timestamp, markText.c_str());
            }
            awaitingMark = false;
        } else {
            char cmd = Serial.read();

            switch(cmd) {
                case '1':
                    currentBaud = BAUD_125K;
                    initCAN(currentBaud);
                    clearCounts();
                    break;
                case '2':
                    currentBaud = BAUD_250K;
                    initCAN(currentBaud);
                    clearCounts();
                    break;
                case '3':
                    currentBaud = BAUD_500K;
                    initCAN(currentBaud);
                    clearCounts();
                    break;
                case '4':
                    currentBaud = BAUD_1M;
                    initCAN(currentBaud);
                    clearCounts();
                    break;
                case 'a':
                case 'A':
                    autoScan();
                    break;
                case 's':
                case 'S':
                    printStatus();
                    break;
                case 'c':
                case 'C':
                    clearCounts();
                    break;
                case 'm':
                case 'M':
                    Serial.print("MARK> ");
                    awaitingMark = true;
                    break;
                case 'h':
                case 'H':
                case '?':
                    printHelp();
                    break;
            }
        }
    }

    // --- 3. Auto-print status every 30 seconds ---
    static unsigned long lastStatus = 0;
    if (messageCount > 0 && millis() - lastStatus > 30000) {
        printStatus();
        lastStatus = millis();
    }
}
