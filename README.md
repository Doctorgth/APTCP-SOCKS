# APTCP-SOCKS Tunnel

> **Note**: The original documentation in Russian is available in [README_ru.md](README_ru.md).

**APTCP-SOCKS Tunnel** is an asynchronous SOCKS5 proxy server and client operating over the session-based **APTCP** (`aioptcp`) transport protocol. It provides high fault tolerance and seamless connection continuity during short-term network disruptions, interface switching (Wi-Fi/LTE), or IP address changes.

The project supports full **SOCKS5 (RFC 1928)** functionality, including **TCP CONNECT** and **UDP ASSOCIATE** (for SOCKS5 clients such as Proxifier, Postern, etc.), as well as authentication under the **RFC 1929** standard via `.jsonl` files.

---

## Key Features & Architecture

* **Network Connection Resilience:** During temporary network outages, the logical SOCKS5 channel does not drop but buffers transmitted data. `aioptcp` automatically restores the underlying physical TCP channel in the background without any packet loss.
* **Full UDP Support:** Complete implementation of the SOCKS5 `UDP ASSOCIATE` command. It proxies UDP datagrams in both directions over a single resilient tunnel.
* **Two-tier Authentication:**
  1. Application $\rightarrow$ SOCKS5 Client (RFC 1929 Username/Password).
  2. SOCKS5 Client $\rightarrow$ APTCP Server (Tunnel Authentication).
* **JSONL User Configuration:** Easily manage user accounts using simple `{"username": "...", "password": "..."}` JSON lines.
* **TLS Encryption Support:** Optional traffic encryption between client and server with server certificate verification.

---

## Quick Server Deployment (Linux)

The easiest way to set up the APTCP server is to use the included `install.sh` script located in the root directory. This script automates repository cloning, configuration setup (port, users), and optional TLS certificate generation.

### Running the Installer

If you have uploaded the `install.sh` file from a Windows machine, you **must** clean it from Windows line endings and grant execution permissions before running:

1. **Fix line endings:**
   ```bash
   sed -i 's/\r//' install.sh
   ```
2. **Make it executable:**
   ```bash
   chmod +x install.sh
   ```
3. **Run the script:**
   ```bash
   ./install.sh
   ```

Alternatively, you can run the installer directly via a one-liner:
```bash
curl -O https://raw.githubusercontent.com/Doctorgth/APTCP-SOCKS/main/install.sh && sed -i 's/\r//' install.sh && chmod +x install.sh && ./install.sh
```

---

## Project Directory Tree

```text
.
├── common/                 # Common modules (config parsing, SOCKS5 parser, tunnel framing)
│   ├── config.py
│   ├── socks5.py
│   └── tunnel.py
├── client/                 # Local SOCKS5 proxy client
│   ├── aptcp_client.py
│   ├── socks_server.py
│   ├── config.json.example # Client configuration template
│   ├── users.jsonl
│   └── main.py
├── server/                 # Remote APTCP SOCKS5 server
│   ├── aptcp_server.py
│   ├── socks_handler.py
│   ├── config.json.example # Server configuration template
│   ├── users.jsonl.example # Server users template
│   └── main.py
├── tests/                  # Autotests (SOCKS5, Tunnel, Auth, E2E, and resilience tests)
├── Dockerfile              # Dockerfile for the server side
├── docker-compose.yml      # Docker Compose configuration for the server
├── requirements.txt
└── README.md
```

---

## Linux Server Deployment

The server side supports two deployment scenarios: automated deployment using Docker Compose and manual start.

### Option A: Deployment via Docker Compose (Recommended)

This is the easiest way to deploy the server. It does not require installing Python or dependencies on the host machine.

1. Copy the following files and directories to your remote Linux server:
   * `common/`
   * `server/`
   * `Dockerfile`
   * `docker-compose.yml`
   * `requirements.txt`
2. Create configuration files from the templates:
   ```bash
   cp server/config.json.example server/config.json
   cp server/users.jsonl.example server/users.jsonl
   ```
3. (Optional) Edit the authorization credentials in `server/users.jsonl` and network ports in `server/config.json`. The default port is `1080`.
4. Start the service in the background:
   ```bash
   docker compose up -d
   ```
5. Check logs to ensure everything is running correctly:
   ```bash
   docker compose logs -f
   ```

---

### Option B: Manual Host Start

1. Ensure Python 3.11+ is installed on your system.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Copy the configuration templates:
   ```bash
   cp server/config.json.example server/config.json
   cp server/users.jsonl.example server/users.jsonl
   ```
4. Set up authorization credentials in `server/users.jsonl`.
5. Run the server:
   ```bash
   python -m server.main server/config.json
   ```

---

## Authentication Explained (Two Password Levels)

The system uses a two-stage authentication mechanism. To avoid configuration confusion, please note the difference between local and tunnel authentication:

### 1. Local Authentication (Your App/Proxifier &rarr; Local Client)
* **What it does:** Controls whether local applications (like Proxifier) are allowed to connect to the locally running SOCKS5 proxy on port `1080`.
* **Configuration:** Managed in `client/config.json` via the `"auth_enabled"` flag and the user list in `client/users.jsonl`.
* **How it works:**
  * If `"auth_enabled": true`, you **must** enable authentication in your Proxifier settings and enter one of the credentials defined in `client/users.jsonl` (e.g., `proxifier` / `proxifier_password`).
  * If `"auth_enabled": false`, Proxifier will access the local SOCKS5 proxy **without a password** (select *«None»* / *«No Authentication»* in Proxifier). The tunnel to the remote server will still remain fully secure!

### 2. Tunnel Authentication (Local Client &rarr; Remote APTCP Server)
* **What it does:** Grants the local client permission to establish a secure transport tunnel with the remote server.
* **Configuration:** Configured in `client/config.json` (the `"aptcp_username"` and `"aptcp_password"` fields) and validated against `server/users.jsonl` on the server.
* **How it works:**
  * The local client **always** reads the username/password from its own `client/config.json` and submits them to the remote server on connection.
  * **You do not need to enter these credentials in Proxifier!** Proxifier is completely unaware of the tunnel transport auth; the client handles it under the hood automatically.

---

## Client Setup and Launch

The client runs on your local machine and provides a standard local SOCKS5 port for applications.

1. Copy the client configuration template:
   ```bash
   cp client/config.json.example client/config.json
   ```
2. Edit `client/config.json`, specifying:
   * `aptcp_server_host`: The IP address or domain name of your remote Linux server.
   * `aptcp_server_port`: The port where your APTCP server is listening (default is `1080`).
   * `aptcp_username` / `aptcp_password`: The credentials defined on the server side in `users.jsonl`.
3. Set up the local authentication database for your apps by copying and editing the user list template:
   ```bash
   cp client/users.jsonl.example client/users.jsonl
   ```
   *(Enter these credentials into your Proxifier/Postern settings if local auth is enabled).*
4. Start the client application:
   ```bash
   python -m client.main client/config.json
   ```

---

## TLS Configuration (Tunnel Encryption)

To protect transmitted traffic, it is recommended to enable TLS encryption between the SOCKS5 client and the APTCP server.

### 1. Self-Signed Certificate Generation
Generate a private key and a certificate on your Linux server:
```bash
openssl req -x509 -newkey rsa:2048 -keyout server/key.pem -out server/cert.pem -days 365 -nodes -subj "/CN=your_domain_or_ip"
```
*Ensure that both `key.pem` and `cert.pem` are saved inside the `server/` directory.*

### 2. Server Configuration
Enable TLS support in `server/config.json`:
```json
{
  "aptcp_host": "0.0.0.0",
  "aptcp_port": 1080,
  "auth_enabled": true,
  "users_file": "server/users.jsonl",
  "timeout": 30,
  "tls_enabled": true,
  "tls_cert": "server/cert.pem",
  "tls_key": "server/key.pem"
}
```
*If using Docker Compose, make sure to uncomment the certificate volumes in `docker-compose.yml` before starting.*

### 3. Client Configuration
1. Copy the public server certificate (`cert.pem`) from your server to your local machine, saving it as `client/server_cert.pem`.
2. Activate TLS in `client/config.json`:
   ```json
   {
     ...
     "aptcp_tls_enabled": true,
     "aptcp_tls_ca_cert": "client/server_cert.pem"
   }
   ```
   *Note:* If you are using a self-signed certificate and omit the `aptcp_tls_ca_cert` parameter, the client will connect in an insecure mode (disabling certificate and host validation), which is convenient for quick debugging but not recommended for production use.

---

## Running Tests

The test suite checks SOCKS5, UDP, authentication, and background session restoration resilience:

```bash
# Run all tests
pytest -v

# Run E2E tests (including physical link reconnection tests)
pytest tests/test_e2e.py -v
```

---

## License

Copyright 2026 APTCP-SOCKS Tunnel (https://github.com/Doctorgth)

Licensed under the Apache License, Version 2.0.