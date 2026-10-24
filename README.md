# Sinkhole - Native Windows 11 Network Ad & Tracker Sinkhole

**Sinkhole** is a lightweight, high-performance, self-hosted network ad and tracker sinkhole application built specifically for Windows 11. Functioning similarly to Pi-hole or AdGuard Home, it runs natively as a managed background **Windows Service** (`winsvc`), resolves network DNS queries on `0.0.0.0:53` (UDP and TCP), blocks ads and telemetry sub-millisecond in memory, and provides a modern embedded web administrative dashboard at `http://127.0.0.1:3002`.

---

## Key Features & Highlights

- **Native Windows Service Integration:** Runs seamlessly in the background on system boot via the Windows Service Control Manager (`winsvc`), requiring no open terminal window. Configured with automatic restart on recovery.
- **Dual UDP & TCP DNS Engine:** High-throughput DNS resolver listening on `0.0.0.0:53` and `[::]:53`, with automatic fallback to per-interface binding if local virtual adapters (such as Hyper-V or WSL) hold reserved ports.
- **Sub-Millisecond In-Memory Filtering:** Zero-allocation suffix-walking hash set matching capable of handling 500,000+ rules in under 1 microsecond per query.
- **Rich List Syntax Support:** Parses standard `hosts` files, AdBlock-syntax lists (e.g. `||tracker.com^`, `@@||whitelist.com^`), wildcard formats (`*.telemetry.microsoft.com`), and plain domain lists.
- **Secure Upstream Forwarding:** Forwards permitted queries over **DNS-over-HTTPS (DoH)**, **DNS-over-TLS (DoT)**, or standard UDP/TCP with parallel racing or failover strategies.
- **YouTube Video Ad Elimination:** Deep player API sanitization (`/youtubei/v1/player`) and scriptlet defusal that strips preroll and midroll video ads, home page mastheads, and sponsored search cards before the player initializes.
- **Universal HTTPS & Cosmetic Engine:** Built-in Root Certificate Authority (CA) and local proxy engine (`127.0.0.1:8080`) that decrypts, sanitizes, and injects cosmetic element-hiding CSS (`domain##selector`) across any browser.
- **Zero-Buffering Video Passthrough:** High-speed raw TCP tunneling for media chunks (`*.googlevideo.com/videoplayback`) ensuring 4K/60fps and 8K HDR playback without buffering or CPU overhead.
- **Loopback Isolation via Bootstrap Resolver:** Employs an independent bootstrap DNS client to resolve DoH upstream hostnames, avoiding resolution deadlocks when Windows points to `127.0.0.1`.
- **Pure-Go Embedded SQLite:** Embedded SQLite storage (pure Go, zero CGO requirement) with WAL mode for query logging, settings, blocklist metadata, and custom rules.
- **Embedded Web Dashboard:** Single-binary distribution with embedded HTML5/CSS3/JavaScript dashboard featuring real-time Server-Sent Events (SSE), 24h query charts, live query stream, blocklist manager, custom rule overrides, and network adapter controls.
- **Automated PowerShell Tooling:** Includes automated scripts for Windows Defender Firewall configuration, service installation, and 1-click network adapter DNS toggling.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |       Local Network Clients           |
                      |  (Phones, Laptops, Smart TVs, IoT)    |
                      +-------------------+-------------------+
                                          | DNS Port 53 (UDP/TCP)
                                          v
                      +---------------------------------------+
                      |          Sinkhole DNS Server          |
                      |               (Port 53)               |
                      +-------------------+-------------------+
                                          |
                +-------------------------+-------------------------+
                |                                                   |
      [Domain on Blocklist]                               [Permitted Domain]
                |                                                   |
                v                                                   v
      +--------------------+                              +--------------------+
      |  Sinkhole Response |                              | In-Memory TTL Cache|
      |  A    -> 0.0.0.0   |                              +---------+----------+
      |  AAAA -> ::        |                                        | (Cache Miss)
      |  (or NXDOMAIN)     |                                        v
      +--------------------+                              +--------------------+
                                                          |  Upstream Resolvers|
                                                          | Cloudflare / Quad9 |
                                                          | (DoH / DoT / UDP)  |
                                                          +--------------------+
```

### Component Structure

- [`src/config`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/src/config/config.go): Runtime configuration schema, defaults, upstream parser, and validation.
- [`src/server/filter`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/src/server/filter/engine.go): Domain normalization, AdBlock & hosts parser, atomic snapshot rule sets.
- [`src/server/cache`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/src/server/cache/cache.go): Concurrent LRU TTL cache with RFC 2308 negative caching.
- [`src/server/upstream`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/src/server/upstream/upstream.go): DoH (HTTP/2), DoT, UDP/TCP resolvers with bootstrap lookup.
- [`src/server/stats`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/src/server/stats/stats.go): Real-time metrics, rolling 24-hour histogram, and top domain/client rankings.
- [`src/server`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/src/server/dns.go): Core DNS engine, CNAME cloaking inspection, and non-blocking asynchronous query logger.
- [`src/store`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/src/store/store.go): Embedded SQLite database schema, settings, blocklist subscriptions, and query logs.
- [`src/system`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/src/system/dnsconfig.go): Windows adapter DNS inspector and PowerShell configuration bridge.
- [`src/service`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/src/service/service_windows.go): Windows Service Control Manager (`winsvc`) lifecycle handler.
- [`src/web`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/src/web/server.go): Embedded REST API and Server-Sent Events (SSE) live streaming hub.
- [`src/web/static`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/src/web/static/index.html): Modern dark-themed dashboard UI (no external CDN dependencies).
- [`cmd/sinkhole`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/cmd/sinkhole/main.go): Application CLI and entrypoint.
- [`scripts/`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/scripts): PowerShell automation for Firewall rules, service control, and adapter configuration.

---

## Local Compilation Instructions

The project uses standard Go (Go 1.22+ recommended). It contains zero CGO dependencies and compiles cleanly to a single standalone executable.

### 1. Build the Binary

From the repository root in PowerShell:

```powershell
# Build output into bin/sinkhole.exe
go build -o bin/sinkhole.exe ./cmd/sinkhole
```

### 2. Run All Tests

```powershell
go test -v ./...
```

---

## Running Sinkhole

Sinkhole can be run in **interactive console mode** (ideal for testing) or as a **Windows Service**.

### Option A: Interactive Console (Quick Test)

```powershell
.\bin\sinkhole.exe run
```

Output:
```
Starting Sinkhole v1.0.0 (Interactive Console Mode)...
Data directory: C:\ProgramData\Sinkhole
time=... level=INFO msg="blocklists compiled" unique_rules=457559 took=230ms
time=... level=INFO msg="DNS server listening" addresses="0.0.0.0:53, [::]:53"
time=... level=INFO msg="dashboard listening" url=http://127.0.0.1:3002
✓ DNS Server active on: [0.0.0.0:53 [::]:53] (UDP & TCP)
✓ Admin Dashboard:     http://127.0.0.1:3002
✓ Press Ctrl+C to shut down cleanly.
```

### Option B: Windows Background Service (Production)

To install and run Sinkhole as a native background Windows Service that automatically boots with Windows 11:

1. Open PowerShell as **Administrator**.
2. Run the helper script:
   ```powershell
   .\scripts\Install-Service.ps1
   ```
   Or use the binary directly:
   ```powershell
   .\bin\sinkhole.exe service install
   .\bin\sinkhole.exe service start
   ```

3. To check service status:
   ```powershell
   .\bin\sinkhole.exe service status
   # Output: Service 'SinkholeDNS': Running
   ```

4. To stop or remove the service:
   ```powershell
   .\scripts\Uninstall-Service.ps1
   # Or: .\bin\sinkhole.exe service stop
   #     .\bin\sinkhole.exe service uninstall
   ```

---

## Verification & Testing

Verify that DNS filtering and upstream resolution are functioning properly:

### 1. Test Blocked Ad Domain (Sinkhole)
Run `nslookup` against `127.0.0.1`:
```powershell
nslookup doubleclick.net 127.0.0.1
```
Expected output:
```
Server:  localhost
Address:  127.0.0.1

Name:    doubleclick.net
Addresses:  ::
	  0.0.0.0
```

### 2. Test Permitted Domain (Upstream Resolution via DoH)
```powershell
nslookup example.com 127.0.0.1
```
Expected output:
```
Server:  localhost
Address:  127.0.0.1

Name:    example.com
Addresses:  2606:4700:10::6814:179a
	  172.66.147.243
	  104.20.23.154
```

### 3. Test CLI Domain Inspector
```powershell
.\bin\sinkhole.exe check doubleclick.net
# Output:
# Domain: doubleclick.net
# Result: BLOCKED (Sinkholed) ❌
# Source: AdGuard DNS filter
# Rule:   doubleclick.net
```

### 4. Admin Web Dashboard
Open your browser to:
```
http://127.0.0.1:3002
```
- **Overview:** Real-time counters of queries today, blocked queries, block %, and 24h volume chart.
- **Live Query Log:** Streaming log of requests, status badges (Allowed, Blocked, Cached), and 1-click domain actions.
- **Blocklists:** Add URLs (e.g. OISD, StevenBlack, EasyList), enable/disable, and trigger manual updates.
- **Custom Rules:** Add immediate whitelist/blacklist overrides with wildcard subdomain support.
- **DNS Settings:** Switch between parallel racing and failover, configure DoH endpoints, and adjust cache size.

---

## Network Configuration & Setup Helper

### 1. Configure Windows Firewall (Port 53 & 3002)
To allow other devices on your home network to query this Windows host:
```powershell
# Run from an elevated (Administrator) PowerShell session:
.\scripts\Setup-Firewall.ps1
```
This automatically configures inbound rules for UDP Port 53, TCP Port 53, and TCP Port 3002.

### 2. Local Windows Adapter Setup (1-Click Local Testing)
To redirect your local Windows 11 machine to use the sinkhole:
```powershell
# Direct your adapter to 127.0.0.1 and ::1 (with automatic backup):
.\scripts\Set-LocalDNS.ps1

# Restore original DNS / DHCP settings whenever you want:
.\scripts\Restore-LocalDNS.ps1
```
*(You can also click the "Point to Sinkhole" button directly in the Web Dashboard under the "Adapters & Router" tab).*

---

## Home Router DHCP Configuration (Whole-Home Network Protection)

To protect all devices on your home network (iPhones, Android phones, smart TVs, laptops, tablets) without configuring each client individually:

```
[Internet] <---> [Home Router] <============== (DHCP distributes Sinkhole IP)
                       |
        +--------------+--------------+
        |              |              |
   [Smart TV]      [iPhone]     [Windows 11 PC]
                               (Runs Sinkhole)
                               LAN: 192.168.1.50
```

1. **Find this Windows PC's Local Static IP:**
   - Look at the bottom of the Web Dashboard (or run `ipconfig` in PowerShell).
   - Example LAN IP: `192.168.1.50`.
   - *Recommendation:* In your router's "Address Reservation" or "Static Leases" table, bind your Windows PC's MAC address to this IP so it never changes.

2. **Access Router Admin Portal:**
   - Open a browser and navigate to your router's gateway (typically `http://192.168.1.1` or `http://192.168.0.1`).
   - Log in with your router credentials.

3. **Update DHCP DNS Settings:**
   - Go to **LAN / Network / DHCP Server Settings**.
   - Find the **DNS Server** fields:
     - **Primary DNS:** Set to your Windows 11 PC's LAN IP (e.g., `192.168.1.50`).
     - **Secondary DNS:** Leave **blank** (or point it to the same Windows PC IP). *Do not enter an external DNS like 8.8.8.8, or devices may bypass the sinkhole*.
   - Save and apply router settings.

4. **Verify Connected Devices:**
   - Reconnect Wi-Fi on your phone or tablet (or run `ipconfig /renew`).
   - The device will now route all DNS queries through your Windows 11 Sinkhole, and its queries will appear live in the Sinkhole Dashboard!

---

## REST API Reference

All mutation endpoints require the `X-Sinkhole: 1` header to prevent CSRF:

| Endpoint | Method | Description |
|---|---|---|
| `/api/status` | `GET` | Server version, active rules count, protection state, host IPs |
| `/api/stats` | `GET` | Aggregated counters, top domains, top blocked, 24h histogram |
| `/api/events` | `GET` | Server-Sent Events (SSE) live query and counter stream |
| `/api/querylog` | `GET` | Filtered query log search (`?search=...&status=...&limit=50`) |
| `/api/querylog` | `DELETE` | Clears query log database |
| `/api/blocklists` | `GET` | List all blocklist subscriptions |
| `/api/blocklists` | `POST` | Add and download new blocklist URL |
| `/api/blocklists/:id` | `PATCH` | Enable or disable blocklist subscription |
| `/api/blocklists/:id` | `DELETE` | Remove blocklist subscription |
| `/api/blocklists/update`| `POST` | Trigger background update of all blocklists |
| `/api/rules` | `GET` | List custom user allowlist/denylist rules |
| `/api/rules` | `POST` | Add custom rule (`{"domain":"...", "action":"block/allow", "subdomains":true}`) |
| `/api/rules/:id` | `DELETE` | Delete custom rule |
| `/api/check` | `GET` | Check domain status against engine (`?domain=...`) |
| `/api/settings` | `GET` | Retrieve active DNS and upstream settings |
| `/api/settings` | `PUT` | Update configuration (hot-reloaded) |
| `/api/protection` | `POST` | Toggle global sinkhole protection on/off |
| `/api/cache/flush` | `POST` | Clear in-memory DNS cache |
| `/api/upstreams/test` | `POST` | Test latency and resolution of an upstream URL |
| `/api/system/adapters`| `GET` | Inspect Windows network adapters |
| `/api/system/adapters/:idx/sinkhole` | `POST` | Point network adapter to 127.0.0.1 |
| `/api/system/adapters/:idx/restore` | `POST` | Restore network adapter to original DNS / DHCP |

---

## License

MIT License. Designed and engineered for high-speed, native Windows 11 network ad and telemetry sinkholing.
