# Simple Port Scanner & Service Banner Grabber

A multithreaded network scanning utility written in Python using native socket APIs to detect open common ports and capture running service banners.

## Features
- **Target Resolution:** Resolves target hostnames and domain names to active IP addresses.
- **Service Banner Grabbing:** Probes open connections to inspect software identification headers.
- **Multithreaded Scanning:** Utilizes Python's `ThreadPoolExecutor` for responsive socket probing without external network libraries.

## Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/Korrawit450/port-service-scanner.git](https://github.com/Korrawit450/port-service-scanner.git)