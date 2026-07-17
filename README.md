# besynx

<p align="center">
  <img src="assets/readme/hero.svg" alt="besynx banner" width="100%" />
</p>

`besynx` (Browser Extension Sync) is a **local-first, peer-to-peer browser sync daemon and extension** that securely syncs browser history and active cookies across your browsers and devices without any cloud dependencies. It acts like **Bitwarden for browser history**.

## Key Features
* **Zero Cloud Dependency**: Runs entirely locally on your network. Your history never leaves your devices.
* **Mutual Authentication**: Paired devices establish secure trust using **Ed25519** cryptographic identity keys and signatures.
* **History Event Queue**: The Manifest-V3 browser extension implements a queue-first storage model that guarantees no history events are lost even when the daemon is offline.
* **Cookie Sync**: Keeps your session active across multiple browsers (Firefox, Chrome, Brave, Zen) by synchronizing cookies bidirectionally with protection against feedback loops and domain mismatches.
* **Secured Local Connections**: Strictly validates WebSockets Origin headers and enforces random authorization tokens to prevent Cross-Site WebSocket Hijacking (CSWSH).

---

## Architecture

```mermaid
graph TD
    subgraph Browser A (e.g. Chrome)
        extA[WebExtension background.js]
        dbLocalA[chrome.storage.local Queue]
    end

    subgraph Browser B (e.g. Firefox)
        extB[WebExtension background.js]
        dbLocalB[chrome.storage.local Queue]
    end

    subgraph Local Machine
        daemon[besynx daemon - Rust]
        db[(SQLite db)]
    end

    subgraph Mobile / Remote Peer
        peerDaemon[besynx peer daemon]
    end

    %% Extensions connect to local daemon
    extA -- "Secure WebSocket (Token)" --> daemon
    extB -- "Secure WebSocket (Token)" --> daemon
    
    %% Local reads/writes
    daemon -- "Saves history & cookies" --> db
    extA -- "Queues visits offline" --> dbLocalA
    extB -- "Queues visits offline" --> dbLocalB
    
    %% P2P daemon sync
    daemon -- "Mutual Ed25519 Auth Sync" --> peerDaemon
```

---

## Installation & Setup

### 1. Run the Local Daemon
Ensure you have Rust installed. In your terminal, compile and run the daemon:
```bash
cargo run --manifest-path daemon/Cargo.toml
```
The daemon will:
1. Initialize the local database `besynx.db`.
2. Generate/load the local private key identity `besynx.key` (with locked `0o600` file permissions on Unix).
3. Generate a secure authentication token inside `besynx.token`.
4. Start listening on `127.0.0.1:9098`.

### 2. Load the Extension
1. Open the target browser's extension management page:
   * **Chromium (Brave, Chrome)**: Visit `chrome://extensions`, enable **Developer mode**, and click **Load unpacked**. Select the `extension/` folder in the project workspace.
   * **Firefox**: Visit `about:debugging#/runtime/this-firefox`, click **Load Temporary Add-on**, and choose `extension/manifest.json`.
2. Go to the extension's **Options** page.
3. Open `besynx.token` from the project directory, copy the token, paste it in the options settings field, and click **Save**.

---

## Developer Command Reference
All local development tasks can be run through `rtk` (Rust Token Killer) hooks:

```bash
# Manage Daemon
cargo build              # Build daemon target
cargo test               # Run workspace test suites

# Sync Checks
sqlite3 besynx.db "SELECT * FROM history LIMIT 10;"  # Check local synced history
sqlite3 besynx.db "SELECT * FROM cookies LIMIT 10;"  # Check local synced cookies
```

---

## License
Licensed under the [MIT License](LICENSE).
