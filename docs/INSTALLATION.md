# Installation Guide

This guide walks through deploying the **vSphere Supervisor Readiness Check + Installation** tool on a Linux VM inside your VCF environment.

---

> **Broadcom employees:** A pre-built VM OVA with the application already installed is available on [Google Drive](https://drive.google.com/drive/folders/18pSjWNkDO_Xvin7IC3GqwO3maEQeEZNG).
>
> After deploying the OVA, the VM will obtain an IP via DHCP. To assign a static IP, log in as `root` (password: `VMware123!VMware123!`) and run the built-in `net-config` script — switch between DHCP and static. See [Network Configuration Script](#network-configuration-script) for details.
>
> Then open a browser and navigate to `http://<VM-IP>` to access the application.

---

## VM Requirements

| Resource | Minimum |
|---|---|
| OS | **Ubuntu 22.04 LTS** or **Ubuntu 24.04 LTS** (Ubuntu 16.04 / 18.04 are **not supported** — Python is too old) |
| Python | **3.10 or later** (Ubuntu 22.04 ships 3.10; Ubuntu 24.04 ships 3.12) |
| CPU | 1 vCPU |
| RAM | 2 GB |
| Disk | 5 GB |
| Network | Access to vCenter and NSX Manager APIs (port 443) |

> The VM should be placed in the **workload domain** so it can reach both the management vCenter (`vc-mgmt-a`) and the WLD vCenter (`vc-wld01-a`) as well as NSX Manager.

---

## Step 1 — Clone the Repository

```bash
apt-get update && apt-get install -y git
git clone https://github.com/ddesmidt/Supervisor_Install_Tool.git
cd Supervisor_Install_Tool
```

---

## Step 2 — Install Python Dependencies

```bash
apt-get install -y python3-flask python3-requests python3-paramiko
```

Alternatively, if PyPI is accessible:

```bash
pip3 install -r app/requirements.txt
```

**Python dependencies:**

| Package | Version | Purpose |
|---|---|---|
| `flask` | ≥ 3.0 | Web framework |
| `requests` | ≥ 2.31 | HTTP client for vCenter/NSX APIs |
| `urllib3` | ≥ 2.0 | TLS handling (self-signed cert support) |
| `paramiko` | ≥ 3.0 | SSH client used by the MTU Check feature |

---

## Step 3 — Install PowerShell Core + VMware PowerCLI

The **Check Ext. Conn.** feature uses PowerCLI to create temporary VMkernel adapters on ESX hosts and run connectivity tests. This requires PowerShell Core (`pwsh`) and the VMware PowerCLI module.

```bash
# Install PowerShell Core via snap
snap install powershell --classic

# Verify
pwsh --version
```

Then install the PowerCLI module inside PowerShell:

```bash
pwsh -Command "Install-Module -Name VMware.PowerCLI -Scope AllUsers -Force -AllowClobber"
```

This step takes a few minutes. Verify the install:

```bash
pwsh -Command "Get-Module -ListAvailable VMware.PowerCLI | Select Name, Version"
```

> **Note:** If the VM has no internet access, install PowerCLI offline by downloading the module on a connected machine and copying it to `/usr/local/share/powershell/Modules/`.

> **Note:** The Check Ext. Conn. button is only shown when R5-1 through R5-4 are all green. If you do not use this feature, PowerShell and PowerCLI are not required.

---

## Step 4 — Deploy the App

```bash
# Copy app files to the standard location
mkdir -p /opt/supervisor-check
cp -r app/* /opt/supervisor-check/

# Verify structure
ls /opt/supervisor-check/
# app.py  requirements.txt  supervisor-check.service  static/  templates/
```

> **All frontend assets are bundled — no internet access required.** The repository ships the full UI stack under `app/static/`:
>
> | File | Replaces |
> |---|---|
> | `static/clr-ui.min.css` | `unpkg.com/@clr/ui` (Clarity Design System) |
> | `static/alpine.min.js` | `cdn.jsdelivr.net/npm/alpinejs` (Alpine.js) |
> | `static/fa/` | `cdnjs.cloudflare.com/…/font-awesome` (Font Awesome 6) |
>
> All files are copied as part of `cp -r app/* /opt/supervisor-check/` — no extra step needed.

---

## Step 5 — Install the Network Configuration Script

The `net-config` helper script lets you switch the VM between DHCP and a static IP from the command line (no netplan knowledge required).

```bash
cp app/net-config /usr/local/bin/net-config
chmod +x /usr/local/bin/net-config
```

See [Network Configuration Script](#network-configuration-script) for usage details.

---

## Step 6 — Configure and Start the systemd Service

```bash
# Install the service unit
cp /opt/supervisor-check/supervisor-check.service /etc/systemd/system/

# Reload systemd and enable the service
systemctl daemon-reload
systemctl enable supervisor-check
systemctl start supervisor-check

# Verify it is running
systemctl status supervisor-check
```

Expected output:
```
● supervisor-check.service - vSphere Supervisor Readiness Check
     Loaded: loaded (/etc/systemd/system/supervisor-check.service; enabled)
     Active: active (running) since ...
```

The app listens on **port 80** by default and starts automatically on boot.

**To run on a different port**, add the `SUPERVISOR_CHECK_PORT` environment variable to the service file before installing it:

```ini
[Service]
...
Environment=SUPERVISOR_CHECK_PORT=8080
```

Or edit the installed unit directly:
```bash
systemctl edit supervisor-check   # adds an override drop-in
# add:  Environment=SUPERVISOR_CHECK_PORT=8080
systemctl daemon-reload && systemctl restart supervisor-check
```

Service logs are written to `/var/log/supervisor-check.log`.

---

## Step 7 — Verify

Open a browser and navigate to:

```
http://<VM-IP>/
```

Replace `/` with `:<PORT>/` if you configured a custom port (e.g. `http://10.1.1.238:8080/`).

You should see the **vSphere Supervisor Readiness Check + Installation** interface.

---

## Network Configuration Script

A utility script `net-config` is installed at `/usr/local/bin/net-config` on the VM. Run it as root to:

- View the current IP configuration (DHCP or Static)
- Switch to DHCP
- Set a static IP (prompts for IP, subnet prefix, gateway, DNS)

```bash
net-config
```

This uses `netplan` under the hood and applies changes immediately.

---

## Managing the Service

| Task | Command |
|---|---|
| Start | `systemctl start supervisor-check` |
| Stop | `systemctl stop supervisor-check` |
| Restart | `systemctl restart supervisor-check` |
| View logs | `journalctl -u supervisor-check -f` or `tail -f /var/log/supervisor-check.log` |
| Disable autostart | `systemctl disable supervisor-check` |

---

## Updating the App

After pulling new changes from the repo:

```bash
cd Supervisor_Install_Tool
git pull

cp app/app.py /opt/supervisor-check/app.py
cp app/templates/index_clarity.html /opt/supervisor-check/templates/index_clarity.html
cp -r app/static/ /opt/supervisor-check/static/

systemctl restart supervisor-check
```

> Flask caches Jinja2 templates in memory — always restart the service after updating `index.html`.

---

## Troubleshooting

**App not reachable on port 80**

Check if another process is listening on port 80:
```bash
ss -tlnp | grep :80
```

If Apache or nginx is running, stop it:
```bash
systemctl stop apache2 && systemctl disable apache2
systemctl stop nginx && systemctl disable nginx
systemctl restart supervisor-check
```

**"Connection refused" when checking vCenter/NSX**

The VM must be able to reach the target hosts on port 443:
```bash
curl -k https://<vcenter-fqdn>/api/session -v
```

**SSL certificate errors**

All vCenter and NSX API calls disable SSL verification by default (`urllib3.disable_warnings` + `verify=False`). This is intentional for lab environments with self-signed certificates.

**Service crashes on startup**

Check the logs:
```bash
journalctl -u supervisor-check --no-pager -n 50
```

Common causes: missing Python packages, wrong working directory, port 80 already in use.
