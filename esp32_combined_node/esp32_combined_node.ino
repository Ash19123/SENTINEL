// ESP32 combined node: SENTINEL anomaly detection + presence counting on one board.
//
//  1. SENTINEL: reads the DHT22, posts to the gateway (path /data) every 2 s, and shows the verdict of
//     the network IDS on the LEDs. "Generate anomaly" on the dashboard (or the button) makes this node
//     flood the gateway, which the IDS flags.
//  2. Presence: stays connected to Wi-Fi and listens passively to nearby Wi-Fi frames. For every device
//     it keeps only a HASH of the address, the signal strength and a frame count, and posts that table to
//     the gateway (path /presence) every 3 s. The gateway counts the devices on our network that are close.
//
//  LEDs
//   Green  = gateway reachable and traffic normal        Red 1 = IDS reports an ANOMALY (flashes)
//   Red 2  = DHT22 reading fails (check wiring)          Blue  = heartbeat: slow = nobody present,
//                                                                 fast = presence count above zero
//   Button (hold) = attack simulation (flood).
//
// Counts devices that transmit, not people: see presence_engine.py for the exact rules and limits.

#include <WiFi.h>
#include <HTTPClient.h>
#include <DHT.h>
#include "esp_wifi.h"

// ---- EDIT THESE ----
const char* WIFI_SSID = "YOUR_WIFI_NAME";
const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";
const char* GATEWAY_IP = "192.168.0.10";    // laptop IPv4 on the same 2.4 GHz network (run ipconfig)
const int   GATEWAY_PORT = 8000;
// --------------------

#define DHT_PIN     4
#define RED_LED_1   12
#define RED_LED_2   25
#define GREEN_LED   26
#define BLUE_LED    27
#define BUTTON_PIN  14

const unsigned long NORMAL_INTERVAL_MS = 2000;   // SENTINEL telemetry (the IDS baseline is learned at this rate)
const unsigned long FLOOD_INTERVAL_MS  = 100;
const unsigned long PRESENCE_INTERVAL_MS = 3000;
const unsigned long RETENTION_MS = 60000;        // a device is forgotten after this long without a frame
const unsigned long MAX_REMOTE_ATTACK_MS = 30000;  // safety cap per burst
const int MAX_DEVICES = 64;
const uint32_t SALT = 0x53454E54;                // "SENT"; addresses are hashed with this

DHT dht(DHT_PIN, DHT22);
unsigned long lastSend = 0, lastPresence = 0, lastBlue = 0, lastDht = 0, buttonSince = 0, remoteSince = 0;
bool blueState = false, anomaly = false, linkOk = false, sensorOk = false, remoteAttack = false;
bool presenceLink = false, present = false;
int reportedCount = 0;
float temperature = NAN, humidity = NAN;
uint32_t bootId;

// ---------------------------------------------------------------- presence sniffer
struct Entry {
  uint32_t h;
  int32_t rssiSum;
  uint16_t frames;
  uint32_t last;       // millis() of the last frame
  bool randomized;     // locally administered address bit
  bool assoc;          // seen sending data to OUR access point (on our network, not a neighbour's)
  bool used;
};
Entry table[MAX_DEVICES];
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
uint8_t ownMac[6], apMac[6];

uint32_t hashMac(const uint8_t* m) {
  uint32_t h = 2166136261u ^ SALT;
  for (int i = 0; i < 6; i++) { h ^= m[i]; h *= 16777619u; }
  return h;
}

// Called by the Wi-Fi driver for every frame on the channel (runs in the Wi-Fi task: keep it short).
void snifferCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  if (pkt->rx_ctrl.sig_len < 16) return;
  const uint8_t* p = pkt->payload;
  const uint8_t* tx = p + 10;                      // address 2 = transmitter
  if (tx[0] & 0x01) return;
  if (!memcmp(tx, ownMac, 6) || !memcmp(tx, apMac, 6)) return;
  uint32_t h = hashMac(tx);
  uint32_t now = millis();
  bool toAp = (p[0] & 0x0c) == 0x08 && (p[1] & 0x03) == 0x01 && !memcmp(p + 4, apMac, 6);  // data frame to our AP
  portENTER_CRITICAL_ISR(&mux);
  int slot = -1, oldest = 0;
  for (int i = 0; i < MAX_DEVICES; i++) {
    if (table[i].used && table[i].h == h) { slot = i; break; }
    if (!table[i].used) { if (slot < 0) slot = i; }
    else if (table[i].last < table[oldest].last || !table[oldest].used) oldest = i;
  }
  if (slot < 0) slot = oldest;
  Entry& e = table[slot];
  if (!e.used || e.h != h) { e = Entry{h, 0, 0, now, (tx[0] & 0x02) != 0, false, true}; }
  if (toAp) e.assoc = true;
  e.rssiSum += pkt->rx_ctrl.rssi;
  if (e.frames < 65535) e.frames++;
  e.last = now;
  portEXIT_CRITICAL_ISR(&mux);
}

void startSniffer() {
  WiFi.macAddress(ownMac);
  const uint8_t* b = WiFi.BSSID();
  if (b) memcpy(apMac, b, 6);
  wifi_promiscuous_filter_t f = {WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA};
  esp_wifi_set_promiscuous_filter(&f);
  esp_wifi_set_promiscuous_rx_cb(&snifferCb);
  esp_wifi_set_promiscuous(true);
}

void sendPresence() {
  if (WiFi.status() != WL_CONNECTED) { presenceLink = false; return; }
  uint32_t now = millis();
  String body = "{\"device\":\"esp32-presence\",\"boot\":" + String(bootId) +
                ",\"rssi\":" + String(WiFi.RSSI()) + ",\"devices\":[";
  bool first = true;
  portENTER_CRITICAL(&mux);
  for (int i = 0; i < MAX_DEVICES; i++) {
    Entry& e = table[i];
    if (!e.used) continue;
    if (now - e.last > RETENTION_MS) { e.used = false; continue; }
    if (!first) body += ",";
    first = false;
    char hex[9];
    snprintf(hex, sizeof(hex), "%08x", e.h);
    body += String("{\"h\":\"") + hex + "\",\"r\":" + String((int)(e.rssiSum / (int)e.frames)) +
            ",\"f\":" + String(e.frames) + ",\"t\":" + String((now - e.last) / 1000) +
            ",\"g\":" + String(e.randomized ? 1 : 0) + ",\"a\":" + String(e.assoc ? 1 : 0) + "}";
  }
  portEXIT_CRITICAL(&mux);
  body += "]}";

  HTTPClient http;
  http.setConnectTimeout(1000);
  http.setTimeout(1000);
  http.begin(String("http://") + GATEWAY_IP + ":" + GATEWAY_PORT + "/presence");
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(body);
  if (code == 200) {
    presenceLink = true;
    String reply = http.getString();
    int i = reply.indexOf("\"count\":");
    if (i >= 0) reportedCount = reply.substring(i + 8).toInt();
    present = reportedCount > 0;
  } else {
    presenceLink = false;
  }
  http.end();
}

// ---------------------------------------------------------------- SENTINEL telemetry
void connectWifi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("Connecting to WiFi");
  for (int i = 0; i < 40 && WiFi.status() != WL_CONNECTED; i++) {
    delay(500);
    Serial.print(".");
    digitalWrite(BLUE_LED, i % 2);
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("Connected, IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("WiFi failed, will retry.");
  }
}

void sendReading(bool flood) {
  if (WiFi.status() != WL_CONNECTED) {
    linkOk = false;
    WiFi.reconnect();
    return;
  }
  // Invalid DHT22 readings are sent as null so the dashboard never shows fake values.
  String body = "{\"device\":\"esp32-1\",\"temperature\":" +
                (sensorOk ? String(temperature, 1) : String("null")) +
                ",\"humidity\":" + (sensorOk ? String(humidity, 1) : String("null")) +
                ",\"rssi\":" + String(WiFi.RSSI()) +
                ",\"flood\":" + (flood ? "true" : "false") + "}";

  HTTPClient http;
  http.setConnectTimeout(1000);
  http.setTimeout(1000);
  http.begin(String("http://") + GATEWAY_IP + ":" + GATEWAY_PORT + "/data");
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(body);
  if (code == 200) {
    linkOk = true;
    String reply = http.getString();
    anomaly = reply.indexOf("\"anomaly\"") >= 0;
    remoteAttack = reply.indexOf("\"attack\":true") >= 0;
  } else {
    linkOk = false;
    Serial.printf("POST failed: %d\n", code);
  }
  http.end();
}

void setup() {
  Serial.begin(115200);
  pinMode(RED_LED_1, OUTPUT);
  pinMode(RED_LED_2, OUTPUT);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(BLUE_LED, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLDOWN);
  bootId = esp_random();
  dht.begin();
  connectWifi();
  startSniffer();
}

void loop() {
  unsigned long now = millis();

  // Flood only after the button has been held for 500 ms (ignores glitches).
  if (digitalRead(BUTTON_PIN) == HIGH) {
    if (buttonSince == 0) buttonSince = now;
  } else {
    buttonSince = 0;
  }
  bool buttonFlood = buttonSince != 0 && now - buttonSince >= 500;

  // Remote "Generate anomaly": flood while the gateway asks, but never longer than the cap.
  if (remoteAttack && remoteSince == 0) remoteSince = now;
  if (!remoteAttack) remoteSince = 0;
  bool remoteFlood = remoteAttack && now - remoteSince < MAX_REMOTE_ATTACK_MS;
  bool flood = buttonFlood || remoteFlood;

  // Blue heartbeat: slow while nobody is present, fast while the presence count is above zero.
  if (now - lastBlue >= (present ? 150UL : 500UL)) {
    lastBlue = now;
    blueState = !blueState;
    digitalWrite(BLUE_LED, blueState);
  }

  // DHT22 is sampled on its own 2 s timer, independent of the send rate.
  if (now - lastDht >= 2000 || lastDht == 0) {
    lastDht = now;
    float t = dht.readTemperature(), h = dht.readHumidity();
    sensorOk = !(isnan(t) || isnan(h));
    if (sensorOk) { temperature = t; humidity = h; }
  }

  if (now - lastSend >= (flood ? FLOOD_INTERVAL_MS : NORMAL_INTERVAL_MS)) {
    lastSend = now;
    sendReading(flood);
    Serial.printf("T=%.1f H=%.1f sensor=%s link=%s verdict=%s%s present=%d\n", temperature, humidity,
                  sensorOk ? "ok" : "ERR", linkOk ? "ok" : "ERR",
                  anomaly ? "ANOMALY" : "normal", flood ? " [FLOOD]" : "", reportedCount);
  }

  if (!flood && now - lastPresence >= PRESENCE_INTERVAL_MS) {
    lastPresence = now;
    sendPresence();
  }

  digitalWrite(RED_LED_1, anomaly ? ((now / 200) % 2) : LOW);
  digitalWrite(RED_LED_2, sensorOk ? LOW : HIGH);
  digitalWrite(GREEN_LED, (linkOk && !anomaly) ? HIGH : LOW);
}
