# Requirement Checks Reference

This document explains each of the requirement steps checked by the tool, what the tool looks for, and what the Fix wizard does when a step fails.

---

## Overview

The tool runs the same set of checks against three deployment modes in parallel. Some steps are specific to a mode (NSX-related steps are skipped or differ for VDS/FLB). Each step can result in:

| Status | Meaning |
|---|---|
| ✅ Green | Requirement fully met |
| ⚠️ Amber (Warning) | Partially met or not yet configured — not a hard blocker in all cases |
| ❌ Red | Requirement not met — must be fixed before deploying |
| ℹ️ Info / To Validate | Informational — manual validation required (used for VDS/FLB) |

Step badges in the UI use an **R prefix** (R1, R2, R3, R5-1 …) to stand for "Requirement".

**Step order (NSX modes):**

| Step | Name | All modes |
|---|---|---|
| Auth | vCenter Authentication | ✅ |
| R1 | Supervisor Capability | ✅ |
| R2 | vSphere HA / DRS | ✅ |
| R3 | NSX Host Preparation | NSX only |
| R4 | VNA Cluster / Edge Cluster | NSX only |
| R5-1 | External Connection | NSX only |
| R5-2 | Transit Gateway | NSX only |
| R5-3 | External IP Block | NSX only |
| R5-4 | VPC Connectivity Profile | NSX only |

**VDS/FLB mode** shows Auth, R1, R2, and a single informational step:

| Step | Name |
|---|---|
| R3 | VLANs/Subnets for Supervisor and FLB |

When Supervisor is already installed, the column matching its deployment mode shows a blue **"In Use"** chip instead of the readiness chip.

---

## Auth — vCenter Authentication

**What it checks:** Can the tool authenticate to the vCenter API using the provided credentials?

**How it works:**
The tool sends a `POST /api/session` to vCenter. In VCF 9.1 environments, the WLD vCenter uses an internal SSO domain (e.g. `wld.sso`) rather than the federation domain (`vcf.lab`). The tool auto-detects the correct domain by reading the `WWW-Authenticate` header and trying a fallback sequence:
1. Try the username as entered
2. Extract the SSO domain from the `sts=` field in `WWW-Authenticate`
3. Try `<username-part>@<detected-domain>`
4. Try `administrator@<detected-domain>` as last resort

**Fix:** Not automated — verify credentials and NSX/vCenter connectivity.

---

## R1 — Supervisor Capability (vSphere)

**What it checks:** Is the vSphere cluster capable of running Supervisor?

**API:** `GET /api/vcenter/namespace-management/cluster-compatibility`

**What is required:** The cluster must appear in the compatibility list with `compatible: true`.

**Common failure reasons:**
- Cluster does not meet minimum hardware requirements
- vSphere license does not include Supervisor capability

**Fix:** Not automated — check vSphere licensing and hardware requirements.

---

## R2 — vSphere HA / DRS

**What it checks:** Is vSphere HA enabled and DRS set to **Fully Automated** on every cluster?

Both are required for Supervisor: HA ensures control-plane VMs are restarted on host failure; DRS Fully Automated is required for the initial placement and live migration of Supervisor VMs.

**How it works:**
The vCenter REST API can return stale values for HA/DRS state. The tool uses **vCenter SOAP** (`RetrieveProperties` on `ClusterComputeResource`) to get accurate live values for `dasConfig.enabled`, `drsConfig.enabled`, and `drsConfig.defaultVmBehavior`.

**Expanded detail (when green):**
```
· cluster-wld01-01a:
  - DRS ✓ (fullyAutomated)
  - HA ✓
```

**Expanded detail (when red):**
```
· cluster-wld01-01a:
  - HA disabled
  - DRS not Fully Automated (mode: manual)
```

**Fix wizard (automated):** Calls `ReconfigureComputeResource_Task` via vCenter SOAP to enable HA and set DRS to `fullyAutomated` on the affected cluster. Polls the task until completion (up to 60 seconds).

**Open in vCenter:** Two link buttons appear below the step title — **Open in vCenter (DRS)** and **Open in vCenter (HA)** — one per cluster. Each opens the corresponding Cluster > Configure > DRS (or HA) page directly in the vSphere Client.

---

## R3 — NSX Host Preparation

**What it checks:** Are the ESXi hosts in the cluster prepared for NSX (i.e. NSX agents installed and Transport Node configuration applied)?

**APIs used:**
- NSX Policy: `GET /policy/api/v1/infra/sites/default/enforcement-points/default/transport-node-collections` — lists Transport Node Collections (TNCs, one per vSphere cluster)
- NSX Policy: `GET /policy/api/v1/infra/sites/default/enforcement-points/default/host-transport-nodes` — lists prepared hosts
- NSX Policy: `GET /…/host-transport-nodes/{id}/state` — per-host deployment state
- NSX Manager: `GET /api/v1/fabric/compute-collections` — resolves TNC UUIDs to human-readable cluster names

**What is displayed when green:**
```
· esx-01: SUCCESS
· esx-02: SUCCESS
· esx-03: SUCCESS
· esx-04: SUCCESS
```

If any host has issues the step shows ⚠️ Amber with a summary such as `3/4 hosts healthy — 1 host(s) with issues`, and the expanded detail shows the state and failure message for the affected host(s).

**Fix:** Not automated — NSX host preparation is done via SDDC Manager or NSX Manager UI.

**Open in vCenter:** An **"Open in vCenter (NSX Host Prep)"** link button appears below the step title. It opens Cluster > Configure > Networking > **Network Configuration** directly in the vSphere Client (one tab per cluster).

**Check MTU button:**
A **"Check MTU"** button appears on R3 for NSX columns. Clicking it opens a wizard that:
1. Shows all available ESX hosts (with health indicator); user selects the source host
2. Prompts for the ESX root password
3. Temporarily enables SSH on that host via vCenter SOAP (if not already enabled)
4. Runs large ICMP pings (`ping -s 1672`) to each TEP tunnel peer to verify the physical fabric supports MTU ≥ 1700 (required for NSX overlay)
5. Displays per-tunnel pass/fail results; the button turns green (all pass) or red (any fail)
6. Restores SSH to its original state (disabled if it was disabled before)

> NSX overlay requires MTU ≥ 1700 on the physical network. If any tunnel ping fails, the physical switch ports or vDS uplinks need their MTU raised.

---

## R4 — VNA Cluster / Edge Cluster

This step differs significantly between modes.

### R4 — Distributed: VNA Cluster

**What it checks:** Is there at least one Virtual Network Appliance (VNA) cluster in NSX in a `SUCCESS` deployment state?

**API:** `GET /policy/api/v1/infra/sites/default/enforcement-points/default/virtual-network-appliance-clusters`

**Status mapping:**

| NSX state | Tool status |
|---|---|
| `SUCCESS` | ✅ Green |
| `IN_PROGRESS` / `PENDING` / `DEPLOYING` | ⚠️ Amber — "VNA Cluster deploying" |
| Not found | ❌ Red |

**Fix wizard (automated):**
1. Fetches available port groups from vCenter (distributed port groups only)
2. Auto-discovers the Overlay Transport Zone from the NSX TNC → TNP chain
3. You enter: port group, Node 1 IP, Node 2 IP
4. Tool calls `PUT /…/virtual-network-appliance-clusters/vna-cluster-{n}` then `PUT /…/virtual-network-appliances/vna-node-{1,2}` (auto-picks a free cluster ID, skipping any recently deleted ones)
5. Shows live deployment progress (polled every 30s)

**Open in vCenter:** An **"Open in vCenter (VNA Cluster)"** link button appears below the step title, opening the NSX VNA Clusters page directly in the vSphere Client.

### R4 — Centralized: Edge Cluster + Tier-0

**What it checks:** Are there Edge Clusters and Tier-0 gateways present in NSX (required for centralized routing)?

**Fix:** **Not automated** — Edge Cluster + Tier-0 + BGP deployment is complex. An info popup links to the [VMware blog post with recorded installation demo](https://blogs.vmware.com/cloud-foundation/2025/06/25/vpc-centralized-network-connectivity-with-guided-edge-deployment/).

**Open in vCenter:** An **"Open in vCenter (Edge Cluster)"** link button opens the NSX Edge Clusters page directly in the vSphere Client.

---

## R5-1 — Distributed / Centralized External Connection

This step differs between modes.

### R5-1 — Distributed: Distributed External Connection

**What it checks:** Is there at least one **Distributed VLAN Connection** in NSX?

**API:** `GET /policy/api/v1/infra/distributed-vlan-connections`

**Expanded detail shows:**
```
· dvlan-connection-1
  VLAN ID: 22
  Gateway: 10.1.7.129/25
```

**Fix wizard (automated):** Creates a new Distributed VLAN Connection — prompts for name, VLAN ID, and gateway CIDR.

**Cascade mode:** The R5-1 fix wizard offers an optional **"Also auto-fix R5-2, R5-3, R5-4"** checkbox. When enabled, after R5-1 succeeds the tool automatically runs R5-2 (TGW attachment), R5-3 (External IP Block), and R5-4 (VPC Profile) in sequence, showing per-step progress. Steps that cannot run due to missing data (e.g. no VNA Cluster yet) are skipped with a warning.

**Open in vCenter:** An **"Open in vCenter (Ext. Conn.)"** link button opens the External Connections page directly in the vSphere Client.

**Check Ext. Conn. button:**
Once R5-1 through R5-4 are all green, a **"Check Ext. Conn."** button appears on R5-1 in the Distributed steps panel. It verifies end-to-end VLAN reachability on every ESX host and validates that the External IP Block's exclusion list is complete.

The check runs in three phases:

**Phase 1 — Setup (host 0 only)**
- Prompts for the root password of each ESX host (entering the first password auto-fills all others)
- PowerCLI creates a temporary DVPortGroup on the VDS with the connection's VLAN ID
- A temporary VMkernel NIC is created on **host 0 only** (the other hosts' NICs are deferred until after the scan, so any responding IP is guaranteed to be a real server, not one of our own NICs)
- Temp IPs are auto-selected from the External IP Block subnet, skipping: the gateway, any already-excluded ranges, and three commonly-reserved addresses (`subnet+2`, `subnet+3`, `broadcast-1`, often used by HSRP/VRRP)

**Phase 2 — IP conflict scan (from host 0)**
- SSH to host 0, then scan **every IP in the External IP Block** (excluding: gateway, already-excluded ranges, host 0's own temp IP, and **IPs already allocated by NSX VPC** — NAT SNAT translated addresses and LoadBalancer VIPs, which are legitimately in use by existing Supervisor workloads and should not be flagged as conflicts) using `vmkping -c 1 -W 1`, in parallel batches of 200
- The scan script is uploaded via SFTP to avoid ESXi's inline command-length limit
- Any IP that responds and is NOT in the above exclusion set is flagged as a **conflict** — it is a foreign device in the VLAN that must be added to the "Excluded IP Ranges" of the IP Block so Supervisor does not assign it to workloads
- If conflicts are found, temp IPs for hosts 1–N are re-picked automatically to avoid the conflicting addresses; then PowerCLI adds VMkernel NICs to hosts 1–N using the (potentially re-picked) temp IPs

**Phase 3 — Gateway ping (all hosts)**
- SSH to each host, run `vmkping -I {vmk} -d -s 28 {gateway}`, check for 0% packet loss
- Reports a per-host pass/fail result

**Results**
- If conflicts were detected, a yellow warning box appears on host 0's row with two fix options:
  - **Fix Automatically** — calls `/api/fix/add-ip-block-exclusion` which merges the conflicting IPs with any existing exclusions, consolidates consecutive addresses into ranges, and writes them to the NSX native `excluded_ips` field via a single NSX `PUT` call. On success, click **"Run Again"** to re-run the check and confirm no conflicts remain.
  - **Fix Manually** — opens vCenter → Virtual Private Clouds → Configure → IP Blocks directly in a new tab
- On a **clean pass** (all hosts OK, no conflicts), the result banner also shows the number and ranges of IPs available for Supervisor in the External IP Block (block total minus gateway, explicit exclusions, and genuine conflicts — NSX VPC-allocated IPs are counted as still available since they belong to the pool)
- The button turns green only when all hosts pass the gateway ping **and** no conflicts were found; red otherwise
- All temporary VMkernel NICs and the DVPortGroup are removed automatically after the test

### R5-1 — Centralized: Centralized External Connection

**What it checks:** Is there at least one **Gateway Connection** (Tier-0 backed) in NSX?

**API:** `GET /policy/api/v1/infra/gateway-connections`

**Expanded detail shows:**
```
· cent-ext1
  Tier-0: T0
```

**Fix wizard (automated):** Creates a new Gateway Connection — prompts for name and Tier-0 selection (the dropdown shows each Tier-0 with its associated Edge Cluster for easy identification).

**Open in vCenter:** An **"Open in vCenter (Ext. Conn.)"** link button opens the External Connections page directly in the vSphere Client.

---

## R5-2 — Distributed / Centralized Transit Gateway

### R5-2 — Distributed: Distributed Transit Gateway

**What it checks:** Is there at least one Transit Gateway (TGW) that has an attachment pointing to a Distributed VLAN Connection?

**APIs:**
- `GET /policy/api/v1/orgs/default/projects` — lists all NSX projects
- `GET /…/projects/{id}/transit-gateways` — queries TGWs in **each** project (not just Default)
- `GET /…/transit-gateways/{id}/attachments`

**Expanded detail shows:**
```
· Default Transit Gateway
  Attached to: dvlan-connection-1
```

**Fix wizard — two cases:**

| Case | Condition | Action |
|---|---|---|
| Case 1 | Default TGW has no attachment | Attach Default TGW to a selected DVLAN connection |
| Case 2 | Default TGW has a Centralized attachment | Create a new `dist-tgw1` TGW and attach it to a selected DVLAN connection |

**Open in vCenter:** An **"Open in vCenter (Trans. GW)"** link button opens the Transit Gateway detail page directly in the vSphere Client, pre-navigating to the specific TGW found by the check.

### R5-2 — Centralized: Centralized Transit Gateway

**What it checks:** Is there at least one TGW with an attachment pointing to a Gateway Connection?

**Expanded detail shows:**
```
· cent-tgw1
  Attached to: cent-ext1
  Edge Cluster: EdgeCluster1
```

The Edge Cluster is read from `GET /…/transit-gateways/{id}/centralized-configs` (auto-populated by NSX when the attachment is created).

**Fix wizard — same Case 1/2 logic as Distributed**, but uses Gateway Connections instead.

**Open in vCenter:** An **"Open in vCenter (Trans. GW)"** link button opens the Transit Gateway detail page in the vSphere Client, pre-navigating to the specific TGW found by the check.

---

## R5-3 — External IP Block

**What it checks:** Is there at least one NSX IP Block with `visibility = EXTERNAL`?

**API:** `GET /policy/api/v1/infra/ip-blocks`

**Why `visibility = EXTERNAL` and not CIDR-based filtering?**
Earlier versions of this check rejected RFC-1918 ranges (private IPs), but in lab environments, VPC NAT means the IP block can be a private range that is "externally visible" to the VPC. NSX's own `visibility` field is the authoritative classification.

**Mode-specific filtering:**
- **Centralized**: additionally excludes blocks whose CIDR overlaps with any Distributed VLAN connection's gateway subnet (those belong to the Distributed mode)

**Expanded detail shows:**
```
· ext-ip-block-1
  CIDR: 10.1.7.128/25
  Excluded ranges: 10.1.7.130-10.1.7.131
· ext-ip-block-2
  CIDR: 10.1.9.128/25
```

Excluded ranges are read from the NSX native `excluded_ips` field (`[{start, end}]`). The tool fetches each block individually since the list endpoint omits this field.

**Fix wizard (automated):**
- Name is pre-filled (`dist-ext-ip-block-1` or `cent-ext-ip-block-1`)
- CIDR is pre-filled from the TGW's DVLAN connection gateway subnet (read-only); if multiple DVLAN connections exist, a dropdown lets you choose which one to cover
- Optional: enter comma-separated excluded IP ranges
- Creates `PUT /policy/api/v1/infra/ip-blocks/{name}` with `visibility: EXTERNAL` and exclusions written to the NSX native `excluded_ips` field (`[{start, end}]`)

**Open in vCenter:** An **"Open in vCenter (Ext. IP Block)"** link button opens VPC > Configure > **IP Blocks** directly in the vSphere Client.

---

## R5-4 — Distributed / Centralized VPC Connectivity Profile

**What it checks:** Does the NSX Default Project have a VPC Connectivity Profile that satisfies all of the following?

| Field | Requirement |
|---|---|
| `transit_gateway_path` | Points to a TGW with a Distributed (or Centralized) attachment |
| `external_ip_blocks` | At least one entry |
| `service_gateway.enable` | `true` |
| `service_gateway.edge_cluster_paths` | At least one VNA cluster path (Distributed) or Edge Cluster (Centralized) |
| `service_gateway.nat_config.enable_default_snat` | `true` |

**APIs:**
- `GET /policy/api/v1/orgs/default/projects` — lists all NSX projects
- `GET /…/projects/{id}/vpc-connectivity-profiles` — lists profiles per project
- `GET /…/transit-gateways/{id}/attachments` — validates TGW attachment type

The check scans **all projects** (not just Default) and shows all valid profiles.

**Expanded detail (when green):**
```
· vpc-dist-prof1  (Project: Default)
  TGW: Default Transit Gateway
  External IP Block: ext-ip-block-1
  VNA Cluster: vna-cluster-1
  N/S Services: enabled
  Outbound NAT: enabled
```

IP block names are resolved from the NSX display name (not the raw path segment).

**Fix wizard (automated):**

Fully reactive form:

| Field | Behavior |
|---|---|
| NSX Project | Dropdown of all NSX projects; defaults to "Default" |
| Distributed TGW | Dropdown refreshes per project; auto-selected if only one |
| VPC Profile name | Read-only; shows `Default VPC Connectivity Profile` for Default TGW, or `vpc-dist-prof1` for a custom TGW |
| External IP Block | Filtered to EXTERNAL blocks matching the TGW's subnet; auto-selected if only one |
| VNA Cluster | Dropdown; auto-selected if only one |
| Private TGW IP Block | Optional — dropdown of PRIVATE blocks |

**Profile creation/update logic:**
- If the profile does not exist → `PUT` (create)
- If the profile exists with the same TGW → `PATCH` (update fields only, no TGW change — NSX restriction)
- If the profile exists with a different TGW → creates a new profile with a different ID (NSX does not allow changing `transit_gateway_path` on an existing profile)

**Open in vCenter / Open in NSX:** An **"Open in vCenter (VPC Conn. Prof.)"** link button opens VPC > Configure > **Connectivity Profile** directly in the vSphere Client — shown when the profile is in the Default NSX project.

When the satisfying profile is in a **non-default NSX project**, the button changes to **"Open in NSX (VPC Conn. Prof.)"** and opens the NSX Manager UI directly at the VPC Connectivity Profiles page. A yellow hint badge also appears reminding you to switch to the correct project using the dropdown at the top-left of the NSX UI.

---

## VDS/FLB — R3 (VLANs/Subnets for Supervisor and FLB)

The VDS/FLB column shows Auth, R1, and R2 (same as the NSX modes), then a single informational step instead of the NSX-specific steps R3–R5-4.

**What it shows:** A reminder that deploying Supervisor with VDS requires the admin to pre-configure the correct VLANs and subnets for the Supervisor control plane and FLB networking. The tool does not automate or validate these for VDS/FLB mode.

**Status:** ℹ️ Info — the overall column chip shows **"To Validate"** (grey). This is not an error; it simply means the admin needs to verify these networking requirements manually before deploying.

**Fix:** Not automated — consult the VMware VCF 9.1 documentation for VDS/FLB Supervisor prerequisites.

---

## NSX API Reference

Key NSX Policy API paths used by this tool:

| Resource | API Path |
|---|---|
| Transport Node Collections | `/policy/api/v1/infra/sites/default/enforcement-points/default/transport-node-collections` |
| Host Transport Nodes | `/policy/api/v1/infra/sites/default/enforcement-points/default/host-transport-nodes` |
| VNA Clusters | `/policy/api/v1/infra/sites/default/enforcement-points/default/virtual-network-appliance-clusters` |
| Distributed VLAN Connections | `/policy/api/v1/infra/distributed-vlan-connections` |
| Gateway Connections | `/policy/api/v1/infra/gateway-connections` |
| Transit Gateways | `/policy/api/v1/orgs/default/projects/{id}/transit-gateways` (all projects) |
| TGW Attachments | `/policy/api/v1/orgs/default/projects/{id}/transit-gateways/{id}/attachments` |
| TGW Centralized Config | `/policy/api/v1/orgs/default/projects/default/transit-gateways/{id}/centralized-configs` |
| IP Blocks | `/policy/api/v1/infra/ip-blocks` |
| VPC Connectivity Profiles | `/policy/api/v1/orgs/default/projects/{id}/vpc-connectivity-profiles` |
| Overlay Transport Zones | `/policy/api/v1/infra/sites/default/enforcement-points/default/transport-zones` |
