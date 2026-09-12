# vSphere Supervisor Readiness Check + Installation

A web application that guides you through checking prerequisites and deploying **vSphere Supervisor** (formerly vSphere with Tanzu) in a **VMware Cloud Foundation 9.1** environment.

---

## Overview

The tool is a self-hosted Flask web app deployed on a VM inside your VCF environment. It connects directly to your vCenter and NSX Manager APIs to:

1. **Check if Supervisor is already installed** on a vCenter cluster
2. **Verify all NSX prerequisites** are in place for your chosen deployment mode
3. **Automatically fix missing prerequisites** via guided wizards
4. **Deploy Supervisor** once all requirements are met

It supports all three vSphere Supervisor deployment modes:

| Mode | Description |
|---|---|
| **NSX-VPC Distributed** ⭐ | Recommended. No Edge Node / Tier-0 / BGP.<br>*Note: L2 requirements on all ESX* |
| **NSX-VPC Centralized** | Requires Edge Cluster + Tier-0 + BGP.<br>*Note: No L2 requirements on all ESX* |
| **VDS / FLB** | No NSX required but limited network services.<br>*Note: L2 requirements on all ESX* |

In addition to the prerequisite checks, the tool offers three deeper validation tests prior to the Supervisor deployment:

| Check | Modes | What it verifies |
|:--|:--:|:--|
| **Check MTU** | VPC‑Dist.<br>VPC‑Cent. | Validates ESX tunnels support large MTU packets end-to-end |
| **Check Ext. Connectivity** | VPC‑Dist. | Validates each ESX has access to the Ext. Conn. VLAN, and scans the physical fabric to validate all IP addresses in the External IP Block are not already in use and so well available for Supervisor |
| **Check DNS Connectivity** | VPC‑Dist.<br>VPC‑Cent. | Verifies that the future Supervisor VM will have connectivity to the configured DNS servers |

Finally, the tool offers one deeper validation test post Supervisor and VKS deployment:

| Check | Modes | What it verifies |
|:--|:--:|:--|
| **Sup / VKS<br>Connectivity Test** | VPC‑Dist.<br>VPC‑Cent. | Validates the cross communication between Supervisor and VKS |

---

## Screenshots

The tool displays three side-by-side columns — one per deployment mode — each showing a live readiness check with pass/warn/fail status per step:

| NSX-VPC Distributed ⭐ | NSX-VPC Centralized | VDS / FLB |
|---|---|---|
| *Pros / Cons / Reqs* | *Pros / Cons / Reqs* | *Pros / Cons / Reqs* |
| ✅ vCenter Auth | ✅ vCenter Auth | ✅ vCenter Auth |
| ✅ Supervisor Capability | ✅ Supervisor Capability | ✅ Supervisor Capability |
| ✅ NSX Host Preparation | ✅ NSX Host Preparation | — (not required) |
| ✅ VNA Cluster | ⚠️ Edge Cluster \[Fix\] | — (not required) |
| ✅ Distributed Ext Conn | ❌ Centralized Ext Conn | — (not required) |
| ✅ Distributed TGW | ❌ Centralized TGW | — (not required) |
| ✅ External IP Block | ❌ External IP Block | — (not required) |
| ✅ VPC Profile | ❌ VPC Profile | — (not required) |
| **\[ Deploy Supervisor \]** | **\[ Deploy — disabled \]** | **\[ Deploy — n/a \]** |

---

## Quick Start

> **Broadcom employees:** A pre-built VM OVA with the application already installed is available on [Google Drive](https://drive.google.com/drive/folders/18pSjWNkDO_Xvin7IC3GqwO3maEQeEZNG).
>
> After deploying the OVA, the VM will obtain an IP via DHCP. To assign a static IP, log in as `root` (password: `VMware123!VMware123!`) and run the built-in `net-config` script — switch between DHCP and static. See [Network Configuration Script](docs/INSTALLATION.md#network-configuration-script) for details.
>
> Then open a browser and navigate to `http://<VM-IP>` to access the application.

### Prerequisites

- A Linux VM inside your VCF environment with:
  - Ubuntu 22.04+ or equivalent
  - Python 3.10+
  - Network access to vCenter and NSX Manager
- VCF 9.1 environment with:
  - SDDC Manager
  - Management + WLD vCenter
  - NSX Manager

### Install and run

```bash
# Clone the repo
git clone https://github.com/ddesmidt/Supervisor_Intall_Tool.git
cd Supervisor_Intall_Tool

# Install Python dependencies
apt-get install -y python3-flask python3-requests python3-paramiko

# Install PowerShell Core (required for the Check Ext. Conn. feature)
snap install powershell --classic

# Install VMware PowerCLI (inside PowerShell)
pwsh -Command "Install-Module -Name VMware.PowerCLI -Scope AllUsers -Force -AllowClobber"

# Copy app to standard location
cp -r app/ /opt/supervisor-check/

# Install and start the systemd service
cp app/supervisor-check.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now supervisor-check

# App is now running on port 80
```

> See [docs/INSTALLATION.md](docs/INSTALLATION.md) for the full deployment guide.

---

## Usage

1. Open `http://<VM-IP>/` in your browser
2. Enter your **vCenter IP/FQDN** + credentials, and **NSX IP/FQDN** + credentials
3. Click **"Check if Supervisor is Installed"** to see current state
4. If not installed, click **"Check Supervisor Requirements"** to see the 3-column readiness matrix
5. Use **"Fix"** buttons to remediate any failed steps
6. Once the column you want turns all-green, click **"Deploy Supervisor"**

> See [docs/USAGE.md](docs/USAGE.md) for a detailed walkthrough and [docs/CHECKS.md](docs/CHECKS.md) for an explanation of each requirement check.

---

## Architecture

```
Browser  ──────────────────────────────────────────────────  Flask app (port 80)
  │                                                               │
  │   Clarity Design System + Alpine.js UI                        │
  │                                                               │
  └──── GET /                          ◄── index_clarity.html     │
  └──── POST /api/check-installed      ◄── vCenter REST API       │
  └──── POST /api/check-requirements   ◄── vCenter + NSX APIs     │
  └──── POST /api/fix/*                ◄── NSX Policy API         │
  └──── POST /api/install-supervisor   ◄── vCenter REST API       │
  └──── POST /api/supervisor-status    ◄── vCenter REST API       │
```

**Backend** (`app/app.py`) — Python Flask:
- All vCenter and NSX API calls are made server-side (avoids CORS)
- Automatic SSO domain detection for vCenter authentication (see note below)
- NSX credentials are passed per-request (never stored)

**Frontend** (`app/templates/index_clarity.html`) — single-page app:
- [Clarity Design System](https://clarity.design) (Broadcom's official design language) for UI components
- Alpine.js for reactivity
- Font Awesome icons (CDN)
- No build step required

> The original Tailwind CSS version is preserved as `app/templates/index.html` for reference.

---

## Project Structure

```
Supervisor_Intall_Tool/
├── app/
│   ├── app.py                    # Flask backend — all API logic
│   ├── templates/
│   │   ├── index_clarity.html    # Default UI — Clarity Design System
│   │   └── index.html            # Original UI — Tailwind CSS (reference)
│   ├── requirements.txt          # Python dependencies
│   └── supervisor-check.service  # systemd unit file
├── vsphere-supervisor-deployment.md  # VCF 9.1 deployment reference
├── docs/
│   ├── INSTALLATION.md           # Full deployment guide
│   ├── USAGE.md                  # How to use the web interface
│   └── CHECKS.md                 # Requirement checks reference
└── README.md
```

---

## Credentials Required

| System | Credential used |
|---|---|
| vCenter (WLD) | `administrator@vsphere.local` or SSO user (auto-detected) |
| NSX Manager | `admin` |

Credentials are entered in the browser and sent to the Flask backend per-request. They are never stored on disk.

> **SSO domain auto-detection**: The app always tries the credentials as entered first. If vCenter responds with HTTP 401, the app reads the `WWW-Authenticate` header from that response — which contains the actual STS URL (e.g. `sts="https://vc/.../STSService/vsphere.local"`) — extracts the real SSO domain, and retries automatically. This means the app works with any SSO domain (`vsphere.local`, `wld.sso`, or any custom domain) without any manual configuration.

---

## License

Internal tool — VMware / Broadcom lab use.
