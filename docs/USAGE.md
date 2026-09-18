# Usage Guide

This guide explains how to use the **vSphere Supervisor Readiness Check + Installation** tool step by step.

---

## Interface Overview

The web interface uses the **[Clarity Design System](https://clarity.design)** (Broadcom's official design language) and has four main sections, accessed top to bottom:

1. **Connection Details** — enter vCenter and NSX credentials
2. **Check if Supervisor is Installed** — query the current state
3. **Check Supervisor Requirements** — 3-column readiness matrix with fix wizards
4. **Deploy Supervisor** — guided deployment wizard (available once requirements pass)
5. **VKS Deployment Validation** — post-deployment: VKS cluster listing, network topology, and connectivity testing (visible once Supervisor is running)

---

## Step 1 — Enter Connection Details

At the top of the page, fill in the two connection sections:

### vCenter

| Field | Example | Notes |
|---|---|---|
| vCenter IP / FQDN | `vc-wld01-a.site-a.vcf.lab` | Do not include `https://` |
| Username | `administrator@vsphere.local` | Pre-filled |
| Password | `VMware123!VMware123!` | |

> **VCF 9.1 note**: The WLD vCenter uses an internal SSO domain (`wld.sso`). The app auto-detects the correct authentication domain — just enter your usual credentials and it will find the right domain automatically.

### NSX

| Field | Example | Notes |
|---|---|---|
| NSX IP / FQDN | `nsx-wld01-a.site-a.vcf.lab` | Do not include `https://` |
| NSX Username | `admin` | Pre-filled |
| Password | `VMware123!VMware123!` | Eye icon toggles visibility |

---

## Step 2 — Check if Supervisor is Already Installed

Click **"Check if Supervisor is Installed"**.

**Possible results:**

- **Supervisor [name] is INSTALLED** (green banner) — one Supervisor is running on this vCenter. The cluster name, config status, k8s status, control plane VIP, and **network mode** (`NSX-VPC Distributed`, `NSX-VPC Centralized`, or `VDS / FLB`) are shown. The network mode is auto-detected by querying the NSX Transit Gateway attachment type via the NSX API.
- **N Supervisors INSTALLED** (green banner) — multiple Supervisors are running on this vCenter (e.g. in a multi-cluster or multi-zone setup). The count is shown; the VKS section will list clusters across all of them.
- **Supervisor is NOT installed** (blue banner) — Supervisor is not yet deployed.

> **Auto-run:** When NSX credentials are filled in, the requirements check runs automatically after a successful install check — so by the time the banner appears, the 3-column requirement matrix is already loading in the background.

---

## Step 3 — Check Supervisor Requirements

Click **"Check Supervisor Requirements"**.

The tool queries vCenter and NSX and displays a **3-column summary** (one card per deployment mode), then a **full-width step panel** for whichever mode you select.

### The three column cards

| Column | Mode | Status chip |
|---|---|---|
| 1 | **NSX-VPC Distributed** ⭐ (Recommended) | Ready / Warnings / Issues |
| 2 | **NSX-VPC Centralized** | Ready / Warnings / Issues |
| 3 | **VDS / FLB** | To Validate |

Each card shows:
- An architecture **thumbnail** for each mode — click it to open a draggable full-size diagram overlay
- **Pros / Cons / Requirements** text
- A **status chip** summarising the overall result: Ready / Warnings / Missing Reqs / To Validate — or a blue **"In Use"** chip if Supervisor is already installed in that mode
- A **"View Requirement Steps"** radio button in the footer — click it to expand the full-width steps panel for that mode
- A **Deploy** button (enabled only when all steps are green)

### The full-width steps panel

Clicking **"View Requirement Steps"** on a card shows all requirement steps for that mode in a full-width panel below the cards. Only one mode's steps are visible at a time. The panel header contains a **"Re-check Requirements"** button to refresh all checks at any time. Each step shows:
- A status icon: ✅ green / ⚠️ amber / ❌ red / ℹ️ info
- The step name and a one-line summary message
- Action buttons where applicable (Fix, Check MTU, Check Ext. Conn., Open in vCenter)
- An expandable detail section (click the row) with full check output

### Expanding a Step

Click any step row in the panel to expand it and see details — e.g. which VNA cluster was found, which IP blocks exist, what is missing.

### Fix Buttons

Steps that the tool can remediate show a **"Fix"** button. Clicking it opens a guided wizard that collects the necessary input and calls the NSX API to create the missing resource.

Steps the tool cannot automate (e.g. Edge Cluster + Tier-0 for Centralized mode) show an **info popup** with a link to the relevant VMware blog post.

### Open in vCenter Links

Most steps show a small **"Open in vCenter"** link button below the step title. Clicking it computes the exact vSphere Client deep link for the relevant page and opens it in a new browser tab — so you can jump directly to the right screen without navigating through the vCenter UI.

| Step | What opens |
|---|---|
| R2 — vSphere HA / DRS | Cluster > Configure > DRS (and a second link for HA) for each cluster |
| R3 — NSX Host Preparation | Cluster > Configure > Networking > Network Configuration for each cluster |
| R4 Distributed | NSX VNA Clusters page |
| R4 Centralized | NSX Edge Clusters page |
| R5-1 | External Connections page |
| R5-2 | Transit Gateway detail page (jumps to the specific TGW found by the check) |
| R5-3 | VPC > Configure > IP Blocks |
| R5-4 | VPC > Configure > Connectivity Profile — **or** "Open in NSX (VPC Conn. Prof.)" with a project-switch hint when the valid profile is in a non-default NSX project |

### Check MTU Button

R3 (NSX Host Preparation) shows a **"Check MTU"** button in the NSX columns. NSX overlay networking requires MTU ≥ 1700 on the physical fabric — use this to verify before deploying.

Clicking it opens a wizard that:
1. Shows all available ESX hosts (with health indicator); user selects the source host
2. Prompts for the **ESX root password**
3. **Temporarily enables SSH** on that host via vCenter SOAP (if not already enabled)
4. Runs large ICMP pings to each TEP tunnel peer to test the path
5. Shows per-tunnel **pass / fail** results; the button turns green or red
6. **Restores SSH** to its original state automatically

If any tunnel shows as failed, the physical switch ports or vDS uplinks MTU needs to be raised to at least 1700 bytes before proceeding.

### Check Ext. Conn. Button

Once **R5-1 through R5-4 are all green**, a **"Check Ext. Conn."** button appears on R5-1 in the Distributed steps panel. Use it to verify that the DVLAN VLAN ID is correctly configured end-to-end on every ESX host before deploying Supervisor.

Clicking it opens a wizard that:
1. Shows all ESX hosts; prompts for the root password (entering the first password copies it to all hosts)
2. Creates a **temporary DVPortGroup** on the VDS with the connection's VLAN ID
3. Adds a **temporary VMkernel NIC** to host 0 only; then scans all IPs in the External IP Block (see below) before adding the remaining hosts
4. Adds VMkernel NICs to all remaining hosts (using re-picked IPs if conflicts were found)
5. Pings the **VLAN gateway** from each VMkernel NIC
6. Shows a per-host **pass / fail** result; conflicts shown in a yellow box with two fix options:
   - **Fix Automatically** — adds the conflicting IPs to the IP Block's Excluded Ranges via the NSX API immediately
   - **Fix Manually** — opens vCenter → VPC → Configure → IP Blocks in a new tab
7. On a **clean pass** (all hosts OK, no conflicts), the result banner also shows how many IPs in the External IP Block are **available for Supervisor** and their ranges — so you can confirm the block has enough headroom before deploying
8. Removes all temporary VMkernel NICs and the temporary DVPortGroup automatically

The button turns green only when all hosts pass the gateway ping **and** no IP conflicts were detected.

### Fixing Prerequisites

The following steps have automated Fix wizards:

| Step | Mode | What the fix does |
|---|---|---|
| R2 — vSphere HA / DRS | All | Enables HA and sets DRS to Fully Automated on the cluster via vCenter SOAP |
| R4 — VNA Cluster | Distributed | Deploys a 2-node VNA cluster on the WLD vCenter cluster |
| R5-1 — Distributed External Connection | Distributed | Creates a Distributed VLAN Connection in NSX |
| R5-1 — Centralized External Connection | Centralized | Creates a Gateway Connection (Tier-0 + BGP required first) |
| R5-2 — Distributed Transit Gateway | Distributed | Attaches the Default TGW to a DVLAN connection, or creates a new Distributed TGW |
| R5-2 — Centralized Transit Gateway | Centralized | Attaches the Default TGW to a Gateway Connection, or creates a new Centralized TGW |
| R5-3 — External IP Block | Distributed + Centralized | Creates an NSX External IP Block |
| R5-4 — VPC Connectivity Profile | Distributed + Centralized | Creates or updates the VPC Connectivity Profile in the NSX Default Project |

#### VNA Cluster Deployment (R4 Distributed)

When you click **Fix** on R4 Distributed, a 3-step wizard opens:

1. **Node IPs** — Select the port group, enter the two management IPs (one per VNA node). The vSphere cluster and datastore are auto-selected.
2. **Network settings** — If the IPs are in the same subnet as the vCenter management network, no extra input is needed. Otherwise, enter the subnet prefix, gateway, and DNS.
3. **Confirm** — Review the settings and click **"Deploy VNA Cluster"**.

After clicking Deploy, the wizard shows live progress (polled every 30 seconds). Deployment typically takes 15–20 minutes.

#### Cascade Fix (R5-1 Distributed)

The R5-1 Distributed External Connection fix wizard includes an optional **"Also auto-fix R5-2, R5-3, R5-4"** checkbox. When enabled, after creating the DVLAN connection the tool automatically:
1. Attaches the Transit Gateway to the new connection (R5-2)
2. Creates an External IP Block using the connection's subnet (R5-3)
3. Configures the VPC Connectivity Profile (R5-4)

Each sub-step is shown with its own progress row. Steps that cannot complete (e.g. R5-4 is skipped if no VNA Cluster exists yet) are marked as skipped with a warning message.

#### VPC Connectivity Profile (R5-4 Distributed)

The R5-4 fix wizard auto-populates fields from data already discovered during the requirements check:

- **NSX Project** — defaults to "Default"; refreshes the profile list if changed
- **Distributed Transit Gateway** — auto-selected if only one exists
- **External IP Block** — auto-selected if it uniquely matches the TGW's DVLAN subnet
- **VNA Cluster** — auto-selected if only one exists
- **Private TGW IP Block** — auto-selected if only one PRIVATE block exists

---

## Step 4 — Deploy Supervisor

Once all steps in a column are green, click **"Deploy Supervisor"** in that column.

A 4-step wizard opens:

### Wizard Step 1 — vSphere Zone / Cluster

Select the vSphere Zone (or compute cluster) to enable Supervisor on.

- **vCenter 8.x / VCF 5.x and later**: a **Zone-based selector** is shown — choose the vSphere Zone that contains your target cluster. Zones are fetched from the vCenter Consumption Domains API.
- **Single cluster / no Zones configured**: a **cluster selector** is shown — choose the cluster directly. If only one cluster exists it is pre-selected.

### Wizard Step 2 — Network
| Field | Description |
|---|---|
| NSX Project | Auto-populated from the valid VPC Connectivity Profile found in Step 7 |
| VPC Connectivity Profile | Auto-populated; can be changed if multiple valid profiles exist |
| First Control Plane IP | Enter the first of 5 consecutive IPs (e.g. `10.1.1.85` reserves `.85`–`.89`) |
| Content Library | Select a vSphere Content Library for Supervisor VM images |

### Wizard Step 3 — Storage
Select the storage policy for Supervisor control plane VMs. The list is filtered to policies compatible with the selected cluster's datastore type (VVol, PMem, and ESA policies are excluded unless the cluster supports them).

### Wizard Step 4 — Config
| Field | Description |
|---|---|
| Supervisor Name | A name for the Supervisor (e.g. `supervisor-wld01-a`) |
| Management Network | The port group for the control plane management network — **auto-discovered** from the VNA node (Distributed) or Edge node (Centralized); shown with a green ✓ note when auto-filled |
| Gateway / DNS / NTP | Also auto-populated from the VNA or Edge node's management interface configuration |
| DNS Servers — Management | DNS servers for Supervisor VMs to resolve internal FQDNs (vCenter, NSX, ESX hosts) |
| DNS Servers — Workload | DNS servers for Supervisor Pods and VKS clusters to resolve external FQDNs (e.g. `github.com`) |

### Optional: Check DNS Connectivity

Once the port group, first IP, gateway, and both DNS fields are filled in, a **"Check DNS Connectivity"** button appears. It runs two independent test sets from a real ESX host using a temporary VMkernel adapter:

| Test set | VLAN | What is verified |
|---|---|---|
| **Management DNS** | Management port group VLAN | vmkping gateway · vmkping DNS server · nslookup vCenter FQDN |
| **Workload DNS** | Workload Ext. Conn. DVLAN | vmkping gateway · vmkping DNS server · nslookup `github.com` |

**How it works:**
1. Select an ESX host from the dropdown and enter its root password
2. The tool temporarily enables SSH on the host (if not already enabled)
3. **Management test** — creates a custom TCP/IP stack + temp VMkernel in the management VLAN, assigns the first control-plane IP, adds a default route, then runs vmkping + nslookup
4. **Workload test** — creates a temp VMkernel in the workload DVLAN using the first available External IP Block address, runs vmkping + nslookup for `github.com`
5. Both VMkernels are always removed in a `finally` block; SSH is restored to its original state

The button turns **green** when all 6 sub-tests pass (3 Management + 3 Workload), **red** if any fail. The modal info banner shows the exact VLANs and IPs that will be used before you run the test.

### Deployment Progress

After clicking **"Deploy"**, the wizard switches to a status view that polls every 30 seconds:

- **Config Status: CONFIGURING** — deployment in progress (K8s status hidden)
- **Config Status: RUNNING** — deployment complete; K8s status and Control Plane VIP are shown

---

## Step 5 — VKS Deployment Validation

Once the Supervisor is **RUNNING**, three post-deployment sections appear below the install status banner.

### VKS Clusters (Tanzu Kubernetes)

Once the Supervisor is **RUNNING**, a **VKS Clusters** section appears below the install status banner. It lists all Tanzu Kubernetes (VKS/TKG) clusters deployed under the Supervisor.

### Credentials

The Supervisor's Kubernetes API uses its own SSO domain (e.g. `administrator@wld.sso`), which may differ from the vCenter credentials. Enter the Supervisor username and password in the fields shown — they default to the vCenter credentials and can be changed if needed. A show/hide eye icon is available on the password field.

### Listing Clusters

Click **"List VKS Clusters"** to query the Supervisor. The tool:
1. Authenticates to vCenter to find the **Supervisor Control Plane VIP**
2. Logs into the Supervisor at `https://{vip}/wcp/login`
3. Queries the CAPI Kubernetes API (`/apis/cluster.x-k8s.io/v1beta1/clusters`) for all VKS clusters

A summary line shows the Supervisor VIP and the total number of clusters and namespaces found.

### Cluster Table

| Column | Description |
|---|---|
| Supervisor VIP | *(shown only when multiple Supervisors are running)* — the Control Plane VIP of the Supervisor this cluster belongs to |
| Cluster Name | CAPI cluster name and namespace |
| Phase | Kubernetes cluster lifecycle phase (e.g. Provisioned, Deleting) |
| Control Plane VIP | The VKS cluster's own Kubernetes API endpoint |
| K8s Version | Kubernetes version of the VKS cluster |
| Workers | Total worker node replica count |
| Topology | Per-cluster **"Topology"** button — opens the Network Topology modal showing the full NSX path for that cluster as an SVG diagram. The result is cached so re-opening is instant. |
| Connectivity | Per-cluster **"Test"** button — opens the Connectivity Test modal. The button is colour-coded: **grey** = not yet tested · 🔵 blue (spinning) = test in progress · 🟢 green = all tests passed · 🔴 red = at least one test failed. The colour persists until the next test run. |

---

### Network Topology

Clicking **"Topology"** on a VKS cluster row opens the **Network Topology** modal. It queries NSX directly and renders a live SVG diagram showing the complete network path from the physical upstream router down to the highlighted VKS cluster.

### What is drawn

The diagram shows nodes top-to-bottom:

| Layer | Node | Detail shown |
|---|---|---|
| Internet | Cloud shape | Upstream / public network |
| Physical router | Hexagon | All uplink VLANs and subnets / gateway IPs discovered from Tier-0 EXTERNAL interfaces or the DVLAN connection |
| External Connection | Pill label | **Distributed**: DVLAN name + VLAN ID + subnet  **Centralized**: Tier-0 name + "BGP" |
| Transit Gateway | Circle | TGW name — highlighted in blue if it is the Supervisor's TGW |
| Supervisor VIP | Circle | Supervisor Kubernetes control plane VIP + **NAT IP** (VPC Outbound NAT from kube-system VPC) |
| VKS Cluster | Circle | Control plane VIP + **NAT IP** (VPC Outbound NAT) — the selected cluster is highlighted in blue |

When two Centralized branches share the same Tier-0, the T0 node is drawn once at the center and both TGW arrows converge on it.

Arrows with arrowheads connect every layer in the path.

### NSX data source

The topology endpoint queries:
1. **All NSX projects** (`/orgs/default/projects`) — finds Transit Gateways in each project using composite keys (`proj_id:tgw_id`) to prevent cross-project collisions
2. **Legacy global path** (`/infra/transit-gateways`) — for older NSX versions
3. For each TGW, resolves attachments to determine **Distributed** (DVLAN connection) or **Centralized** (Gateway Connection → Tier-0 BGP) mode
4. Enumerates Tier-0 locale-service **EXTERNAL interfaces** to collect all uplink VLANs and subnets (deduped per VLAN)
5. **NAT IP resolution**: reads each VPC's NAT rules (`/vpcs/{id}/nat/DEFAULT/nat-rules → translated_network`) and assigns the best NAT IP to each TGW:
   - Centralized TGW → prefers `kube-system*` VPC (Supervisor's outbound NAT IP)
   - Distributed TGW → prefers `default-region*` VPC (VKS outbound NAT IP)
6. **VKS → TGW assignment**: each VKS cluster is placed on the correct TGW branch by matching the cluster's control-plane VIP against each TGW's NAT IP using a /20 subnet comparison

### Caching

The NSX response is cached in the page session. If you open the Topology modal first and then click "Test" on the same cluster, the topology diagram in the Connectivity Test panel appears instantly without a second NSX call. The connectivity test also pre-fetches topology automatically (if not cached) so it has NAT IPs available before running.

---

### Connectivity Test

Clicking **"Test"** on a VKS cluster row opens the **Connectivity Test** modal, which runs three groups of tests to verify network reachability between the Supervisor and the VKS cluster.

> Tests may take 20–30 seconds because the exec-based probes must find a suitable pod, open a WebSocket exec session, and run the TCP tool inside the container.

The modal has a **two-column layout**:
- **Left** — three groups of connectivity test results
- **Right** — Network Topology SVG (the same diagram as the Topology modal; loaded in parallel with the test; reuses the cached NSX response if Topology was opened first)

### Group 1 — TCP from App Server

Direct socket probe from **this server** (the VM running the app) to:
- Supervisor Control Plane VIP:6443
- VKS Cluster Control Plane VIP:6443

This confirms basic layer-3/4 reachability from the tool's own network position and does **not** require any Kubernetes exec permissions.

### Group 2 — Supervisor Node → VKS Control Plane VIP

TCP probe **exec'd inside a pod running on a Supervisor node**:
1. The tool searches all Supervisor namespaces for a Running pod with a network tool (`python3`, `nc`, `curl`, `wget`, or `bash`), preferring `hostNetwork=true` pods (antrea-agent, vsphere-csi-node …) so the source IP matches the actual node IP
2. It opens a raw WebSocket exec session (no `kubectl` required) and runs a TCP probe to the VKS control plane VIP:6443
3. The result shows which pod and node were used, and which tool ran the probe

> `kube-proxy` pods are explicitly avoided — their iptables DNAT rules can redirect outbound connections and produce false results.

### Group 3 — VKS Node → Supervisor Control Plane VIP

TCP probe **exec'd inside a pod running on a VKS worker node**:
1. The tool fetches the VKS cluster's kubeconfig from the `{cluster}-kubeconfig` secret in the Supervisor
2. It authenticates to the VKS cluster API using the extracted client certificate
3. It finds a suitable exec-capable pod in the VKS cluster and probes TCP to the Supervisor VIP:6443

This confirms that VKS worker nodes can reach the Supervisor API — necessary for the nodes to rejoin after a reboot.

### Result Table

Each row shows:

| Column | Description |
|---|---|
| Source | Pod name, namespace, node name, and whether hostNetwork is used |
| Destination | Target IP and port |
| Traffic in Physical Fabric | The **actual physical source → destination** after NAT — e.g. `10.1.7.141 (VPC Outbound NAT) → 10.1.12.1:6443`. NAT IPs are extracted from the topology data before the test runs. |
| Method | `tcp` (direct socket) or `exec` (probe inside pod) |
| Probe | Tool used (`python3`, `nc`, `curl`, `wget`) |
| Result | ✅ OK or ❌ FAIL |
| Detail | Output or error message |

---

## Tips

- **Hard refresh** (`Cmd+Shift+R` on Mac, `Ctrl+Shift+R` on Windows) if the UI looks stale after a change — Flask serves templates from disk but browsers cache aggressively.
- **Re-check Requirements** after each Fix to confirm the step turned green before moving to the next one.
- The **VDS/FLB** column Deploy button is always disabled — the tool does not automate VDS/FLB Supervisor deployment.
- Credentials are **not stored** — if you refresh the page you will need to re-enter them.
