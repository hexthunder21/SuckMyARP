# 💀 SUCK MY ARP

> A small toolkit for experimenting with ARP spoofing and its detection.

---

## 📌 About

This project is a collection of simple tools related to **ARP spoofing**:
- Performing ARP spoofing attacks
- Detecting ARP poisoning attempts

The project is actively evolving — more features and tools will be added over time.

---

## ⚙️ Tools

### 🔴 ARP-Spoofing.py

A basic ARP spoofing script.

#### Usage:
```bash
sudo python3 ARP-spoofing.py [target IP] [router IP]


⚠️ Root privileges are required to send raw packets.
```

🛡️ Detect-ARP-Spoofing.py

A simple ARP spoofing detector.

How it works:
Dumps your current ARP table into a file
Continuously scans it for suspicious changes (possible poisoning)
```bash Usage:
python3 Detect-ARP-Spoofing.py (or as sudo)
```
Planned improvements:

More reliable spoofing logic
Better detection heuristics
Logging & alerts
CLI arguments and configuration
Possibly GUI

⚠️ Disclaimer

This project is for educational purposes only.

Do NOT use these tools on networks you do not own or have permission to test.