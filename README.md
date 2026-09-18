# RepoIntel-X

> GitHub Repository, IoT & Firmware Security Intelligence Platform

# RepoIntel-X is a Python-based open-source security intelligence tool designed to discover and analyze publicly available GitHub repositories related to 
# IoT, embedded systems, firmware, UAV/drone technologies, security research, and related technologies.

## Features

- Automatic GitHub repository discovery
- IoT and embedded security classification
- Firmware repository detection
- ESP32 / ESP8266 intelligence
- MQTT security discovery
- UAV / drone / MAVLink repository discovery
- FreeRTOS / Zephyr intelligence
- Repository metadata analysis
- File-tree analysis
- Security-file detection
- Dependency manifest discovery
- CVE reference detection
- Repository DNA fingerprinting
- Evidence collection
- SQLite intelligence database
- JSON reporting
- Local web dashboard
- Continuous monitoring mode
- GitHub API rate-limit diagnostics
- Single-file architecture

## Supported Intelligence Areas

### IoT

- ESP32
- ESP8266
- Arduino
- Raspberry Pi
- MQTT
- CoAP
- Zigbee
- LoRaWAN
- Modbus
- IoT gateways
- Sensors
- Embedded systems

### Firmware

- BIN
- HEX
- IMG
- ELF
- UF2
- ROM
- FW

### UAV / Drone

- UAV firmware
- Drone security
- MAVLink
- Flight-controller repositories
- Embedded aviation security research

### Security

- Vulnerability research
- CVE references
- Firmware security
- Penetration testing research
- Reverse engineering
- Security hardening

## Requirements

- Python 3.12+
- Internet connection
- GitHub account
- GitHub Personal Access Token recommended

No Node.js required.

No npm required.

No Docker required.

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/RepoIntel-X.git
cd RepoIntel-X


#Run :
 python3 RepoIntel-X.py --limit 20

 or 

  python3 RepoIntel-X.py 

  #in second terminal 
 python3 RepoIntel-X.py --web


 #output:

 [DISCOVER] iot firmware
[GITHUB] API remaining: 28
[DISCOVER] embedded security
[GITHUB] API remaining: 27
[DISCOVER] esp32 security
[GITHUB] API remaining: 26
[DISCOVER] esp8266 security
[GITHUB] API remaining: 25
[DISCOVER] mqtt security
[GITHUB] API remaining: 24
[DISCOVER] firmware security
[GITHUB] API remaining: 23
[DISCOVER] uav firmware
[GITHUB] API remaining: 22
[DISCOVER] drone security
[GITHUB] API remaining: 21
[DISCOVER] mavlink security
[GITHUB] API remaining: 20
[DISCOVER] freertos security
[GITHUB] API remaining: 19
[DISCOVER] zephyr security
[GITHUB] API remaining: 18
[DISCOVER] openwrt security
[GITHUB] API remaining: 17
[DISCOVER] industrial iot security
[GITHUB] API remaining: 16
[DISCOVER] unique repositories: 247
[ANALYZE] BruceDevices/firmware
[GITHUB] API remaining: 4925
[ANALYZE] attify/firmware-analysis-toolkit
[GITHUB] API remaining: 4924
[ANALYZE] ct-Open-Source/tuya-convert
[GITHUB] API remaining: 4923
[ANALYZE] fkie-cad/awesome-embedded-and-iot-security
[GITHUB] API remaining: 4922
[ANALYZE] Azure/iot-central-firmware
[GITHUB] API remaining: 4921
[ANALYZE] cesanta/mongoose-os
[GITHUB] API remaining: 4920




