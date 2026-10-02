import ipaddress
import re
import time
import traceback
import uuid
import yaml
from urllib.parse import urlparse

import requests
import urllib3
from flask import Flask, jsonify, render_template, request

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

SESS = requests.Session()
SESS.verify = False


# ── helpers ──────────────────────────────────────────────────────────────────

def _is_external_ip_block(cidr: str) -> bool:
    """True only if cidr is publicly routable (not private / link-local / reserved)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return not (net.is_private or net.is_link_local or net.is_reserved or net.is_loopback)
    except ValueError:
        return False


def _block_cidr(b: dict, nsx_url: str = "", user: str = "", pwd: str = "") -> str:
    """Extract CIDR from an NSX IP block object.

    NSX returns the subnet in 'cidr' (singular) OR 'cidrs' (array) — never reliably both.
    Fall back to subnets[].network, then to an individual GET if still empty.
    """
    cidr = (b.get("cidr") or "").strip()
    if not cidr:
        # NSX sometimes uses a 'cidrs' array instead of 'cidr'
        cidrs_list = b.get("cidrs") or []
        if cidrs_list:
            cidr = str(cidrs_list[0]).strip()
    if not cidr:
        # Some NSX versions embed CIDR inside a 'subnets' array
        for s in (b.get("subnets") or []):
            net = (s.get("network") or s.get("cidr") or "").strip()
            if net:
                cidr = net
                break
    if not cidr and nsx_url and b.get("path"):
        # Last resort: individual GET for the full block object
        try:
            full = nsx_get(nsx_url, user, pwd,
                           f"/policy/api/v1{b['path']}")
            if full:
                cidr = (full.get("cidr") or "").strip()
                if not cidr:
                    cidrs_list = full.get("cidrs") or []
                    if cidrs_list:
                        cidr = str(cidrs_list[0]).strip()
                if not cidr:
                    for s in (full.get("subnets") or []):
                        net = (s.get("network") or s.get("cidr") or "").strip()
                        if net:
                            cidr = net
                            break
        except Exception:
            pass
    return cidr


def normalize_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith("http"):
        url = "https://" + url
    # strip trailing path components like /ui
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def guess_nsx_url(vc_url: str) -> str | None:
    """Derive NSX URL from vCenter URL by swapping 'vc' prefix → 'nsx'."""
    p = urlparse(vc_url)
    host = p.hostname or ""
    if host.startswith("vc-"):
        return f"https://nsx-{host[3:]}"
    if host.startswith("vc"):
        return f"https://nsx{host[2:]}"
    return None


def _detect_sso_domain(www_auth_header: str) -> str | None:
    """Extract SSO domain from WWW-Authenticate STS URL.
    e.g. sts="https://host/sts/STSService/wld.sso" → "wld.sso"
    """
    m = re.search(r'sts="[^"]+/STSService/([^"]+)"', www_auth_header)
    return m.group(1) if m else None


def _vapi_zone_cluster_add(vc_url: str, session_token: str,
                            zone_name: str, cluster_moref: str) -> None:
    """Associate a vSphere cluster with a consumption zone via vapi JSON-RPC.

    Uses the vapi HTTP JSON-RPC 2.0 wire format (the same wire format the
    Python vapi-bindings use) sent to POST /api on the vCenter host.
    """
    opid = str(uuid.uuid4())
    body = {
        "jsonrpc": "2.0",
        "method": "invoke",
        "params": {
            "serviceId": "com.vmware.vcenter.consumption_domains.zones.cluster.associations",
            "operationId": "add",
            "input": {
                "STRUCTURE": {
                    "operation-input": {
                        "zone": zone_name,
                        "clusters": [cluster_moref]
                    }
                }
            },
            "ctx": {
                "appCtx": {"opId": opid},
                "securityCtx": {
                    "schemeId": "com.vmware.vapi.std.security.session_id",
                    "sessionId": session_token
                }
            }
        },
        "id": "0"
    }
    hdrs = {
        "Content-Type": "application/json",
        "vapi-service": "com.vmware.vcenter.consumption_domains.zones.cluster.associations",
        "vapi-operation": "add",
        "vapi-ctx-opid": opid,
    }
    r = SESS.post(f"{vc_url}/api", headers=hdrs, json=body, timeout=30)
    if not r.ok:
        raise ValueError(
            f"vapi zone-cluster add failed: HTTP {r.status_code}: {r.text[:300]}"
        )
    resp_data = r.json()
    if "error" in resp_data:
        raise ValueError(
            f"vapi zone-cluster add error: {resp_data['error']}"
        )
    # Check result.output for any failures
    try:
        struct = (resp_data.get("result", {})
                  .get("output", {})
                  .get("STRUCTURE", {}))
        status_key = "com.vmware.vcenter.consumption_domains.zones.cluster.associations.status"
        status = struct.get(status_key, {})
        if not status.get("success", True):
            failed = status.get("failed_clusters", [])
            raise ValueError(
                f"Zone-cluster association failed for {failed}"
            )
    except (AttributeError, TypeError):
        pass  # If response shape differs, the HTTP 200 is sufficient


def vc_auth(vc_url: str, username: str, password: str) -> tuple[str, str]:
    """Authenticate to vCenter REST API.

    Returns (token, effective_username).
    On 401, auto-detects the vCenter's local SSO domain from the
    WWW-Authenticate header and retries with administrator@<domain>.
    Uses fresh requests.post() calls to avoid session cookie interference.
    """
    url = f"{vc_url}/api/session"
    kw = dict(verify=False, headers={"Content-Type": "application/json"}, timeout=15)

    resp = requests.post(url, auth=(username, password), **kw)

    if resp.status_code == 401:
        www_auth = resp.headers.get("WWW-Authenticate", "")
        sso_domain = _detect_sso_domain(www_auth)
        if sso_domain:
            local = username.split("@")[0] if "@" in username else username
            candidates = [
                f"{local}@{sso_domain}",
                f"administrator@{sso_domain}",
            ]
            for candidate in candidates:
                if candidate == username:
                    continue
                r2 = requests.post(url, auth=(candidate, password), **kw)
                if r2.ok:
                    return r2.json(), candidate
        resp.raise_for_status()

    resp.raise_for_status()
    return resp.json(), username


def vc_get(vc_url: str, token: str, path: str, params: dict = None):
    resp = SESS.get(
        f"{vc_url}{path}",
        headers={"vmware-api-session-id": token},
        params=params,
        timeout=15,
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def _vc_soap_get_pg_cluster_map(vc_url: str, username: str, password: str) -> dict:
    """Return {pg_moref: [cluster_moref, ...]} via SOAP PropertyCollector.
    Strategy: PG → parent DVS (via config.distributedVirtualSwitch)
              DVS → connected hosts (via config.host)
              Cluster → member hosts (via host property)
    Combine these three to produce the accurate per-cluster PG list.
    Falls back to {} on any error (REST ?hosts= filter is unreliable in some vCenter versions)."""
    import re as _re
    _H = {'Content-Type': 'text/xml; charset=UTF-8', 'SOAPAction': 'urn:vim25/9.0'}
    _ss = requests.Session()
    _ss.verify = False

    def _soap(_xml):
        _r = _ss.post(f"{vc_url}/sdk", timeout=20, headers=_H, data=_xml)
        return _r.text if _r.ok else ""

    try:
        # ── Login ──────────────────────────────────────────────────────
        _soap(f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="urn:vim25">
<soapenv:Body><vim25:Login>
<vim25:_this type="SessionManager">SessionManager</vim25:_this>
<vim25:userName>{username}</vim25:userName>
<vim25:password>{password}</vim25:password>
</vim25:Login></soapenv:Body>
</soapenv:Envelope>""")

        _FOLDER_TRAVERSAL = """
  <vim25:objectSet>
    <vim25:obj type="Folder">group-d1</vim25:obj>
    <vim25:skip>true</vim25:skip>
    <vim25:selectSet xsi:type="vim25:TraversalSpec">
      <vim25:name>visitFolders</vim25:name>
      <vim25:type>Folder</vim25:type>
      <vim25:path>childEntity</vim25:path>
      <vim25:skip>false</vim25:skip>
      <vim25:selectSet><vim25:name>visitFolders</vim25:name></vim25:selectSet>
      <vim25:selectSet><vim25:name>visitDC_net</vim25:name></vim25:selectSet>
      <vim25:selectSet><vim25:name>visitDC_host</vim25:name></vim25:selectSet>
      <vim25:selectSet><vim25:name>visitCluster</vim25:name></vim25:selectSet>
    </vim25:selectSet>
    <vim25:selectSet xsi:type="vim25:TraversalSpec">
      <vim25:name>visitDC_net</vim25:name>
      <vim25:type>Datacenter</vim25:type>
      <vim25:path>networkFolder</vim25:path>
      <vim25:skip>false</vim25:skip>
      <vim25:selectSet><vim25:name>visitFolders</vim25:name></vim25:selectSet>
    </vim25:selectSet>
    <vim25:selectSet xsi:type="vim25:TraversalSpec">
      <vim25:name>visitDC_host</vim25:name>
      <vim25:type>Datacenter</vim25:type>
      <vim25:path>hostFolder</vim25:path>
      <vim25:skip>false</vim25:skip>
      <vim25:selectSet><vim25:name>visitFolders</vim25:name></vim25:selectSet>
    </vim25:selectSet>
    <vim25:selectSet xsi:type="vim25:TraversalSpec">
      <vim25:name>visitCluster</vim25:name>
      <vim25:type>ClusterComputeResource</vim25:type>
      <vim25:path>host</vim25:path>
      <vim25:skip>false</vim25:skip>
    </vim25:selectSet>
  </vim25:objectSet>"""

        # ── Query 1: DVS → connected hosts ────────────────────────────
        _rA = _soap(f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:vim25="urn:vim25">
<soapenv:Body>
<vim25:RetrievePropertiesEx>
<vim25:_this type="PropertyCollector">propertyCollector</vim25:_this>
<vim25:specSet>
  <vim25:propSet>
    <vim25:type>VmwareDistributedVirtualSwitch</vim25:type>
    <vim25:all>false</vim25:all>
    <vim25:pathSet>config.host</vim25:pathSet>
  </vim25:propSet>
  {_FOLDER_TRAVERSAL}
</vim25:specSet>
<vim25:options/>
</vim25:RetrievePropertiesEx>
</soapenv:Body></soapenv:Envelope>""")
        dvs_hosts: dict = {}  # dvs_moref → [host_morefs]
        for _blk in _re.findall(r'<objects>(.*?)</objects>', _rA, _re.DOTALL):
            _dm = _re.search(r'<obj type="VmwareDistributedVirtualSwitch">(dvs-\d+)</obj>', _blk)
            _hs = _re.findall(r'type="HostSystem"[^>]*>(host-\d+)<', _blk)
            if _dm and _hs:
                dvs_hosts[_dm.group(1)] = _hs

        # ── Query 2: Cluster → member hosts ───────────────────────────
        _rB = _soap(f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:vim25="urn:vim25">
<soapenv:Body>
<vim25:RetrievePropertiesEx>
<vim25:_this type="PropertyCollector">propertyCollector</vim25:_this>
<vim25:specSet>
  <vim25:propSet>
    <vim25:type>ClusterComputeResource</vim25:type>
    <vim25:all>false</vim25:all>
    <vim25:pathSet>host</vim25:pathSet>
  </vim25:propSet>
  {_FOLDER_TRAVERSAL}
</vim25:specSet>
<vim25:options/>
</vim25:RetrievePropertiesEx>
</soapenv:Body></soapenv:Envelope>""")
        cluster_hosts: dict = {}  # cluster_moref → [host_morefs]
        for _blk in _re.findall(r'<objects>(.*?)</objects>', _rB, _re.DOTALL):
            _cm = _re.search(r'<obj type="ClusterComputeResource">(domain-c\d+)</obj>', _blk)
            _hs = _re.findall(r'<ManagedObjectReference[^>]*type="HostSystem"[^>]*>(host-\d+)</ManagedObjectReference>', _blk)
            if not _hs:
                _hs = _re.findall(r'type="HostSystem"[^>]*>(host-\d+)<', _blk)
            if _cm and _hs:
                cluster_hosts[_cm.group(1)] = _hs

        # ── Query 3: DVPG → parent DVS ────────────────────────────────
        _rC = _soap(f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:vim25="urn:vim25">
<soapenv:Body>
<vim25:RetrievePropertiesEx>
<vim25:_this type="PropertyCollector">propertyCollector</vim25:_this>
<vim25:specSet>
  <vim25:propSet>
    <vim25:type>DistributedVirtualPortgroup</vim25:type>
    <vim25:all>false</vim25:all>
    <vim25:pathSet>config.distributedVirtualSwitch</vim25:pathSet>
  </vim25:propSet>
  {_FOLDER_TRAVERSAL}
</vim25:specSet>
<vim25:options/>
</vim25:RetrievePropertiesEx>
</soapenv:Body></soapenv:Envelope>""")
        pg_dvs: dict = {}  # pg_moref → dvs_moref
        for _blk in _re.findall(r'<objects>(.*?)</objects>', _rC, _re.DOTALL):
            _pg = _re.search(r'<obj type="DistributedVirtualPortgroup">(dvportgroup-\d+)</obj>', _blk)
            _dv = _re.search(r'<val[^>]*>(dvs-\d+)</val>', _blk)
            if not _dv:
                _dv = _re.search(r'type="[^"]*VirtualSwitch[^"]*">(dvs-\d+)<', _blk)
            if _pg and _dv:
                pg_dvs[_pg.group(1)] = _dv.group(1)

        # ── Combine ────────────────────────────────────────────────────
        # host → cluster
        _host_cluster: dict = {_h: _c for _c, _hs in cluster_hosts.items() for _h in _hs}
        # DVS → [cluster_morefs]
        _dvs_clusters: dict = {}
        for _dvs_id, _hs in dvs_hosts.items():
            for _h in _hs:
                _c = _host_cluster.get(_h)
                if _c:
                    _dvs_clusters.setdefault(_dvs_id, [])
                    if _c not in _dvs_clusters[_dvs_id]:
                        _dvs_clusters[_dvs_id].append(_c)
        # PG → [cluster_morefs]
        _result: dict = {}
        for _pg_id, _dvs_id in pg_dvs.items():
            _clusters = _dvs_clusters.get(_dvs_id, [])
            if _clusters:
                _result[_pg_id] = _clusters
        return _result
    except Exception:
        return {}


def _vc_soap_get_dvpg_vlans(vc_url: str, username: str, password: str) -> dict:
    """Use vSphere SOAP PropertyCollector to batch-fetch VLAN IDs for all DVPGs.
    Returns {portgroup_moref: vlan_id} dict, e.g. {'dvportgroup-24': 10}.
    Falls back to {} on any error (vCenter unreachable, wrong creds, etc.).
    Works on vCenter 9.x where the /api/vcenter/network/distributed-port-group/{id} REST
    endpoint returns 404."""
    import re as _re
    _H = {'Content-Type': 'text/xml; charset=UTF-8', 'SOAPAction': 'urn:vim25/9.0'}
    _ss = requests.Session()
    _ss.verify = False
    try:
        # SOAP Login (separate session — doesn't disturb the REST session)
        _lr = _ss.post(f"{vc_url}/sdk", timeout=15, headers=_H, data=
            f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="urn:vim25">
<soapenv:Body>
<vim25:Login>
<vim25:_this type="SessionManager">SessionManager</vim25:_this>
<vim25:userName>{username}</vim25:userName>
<vim25:password>{password}</vim25:password>
</vim25:Login>
</soapenv:Body>
</soapenv:Envelope>""")
        if not _lr.ok:
            return {}
        # Batch PropertyCollector: traverse Folder→Datacenter→NetworkFolder→DVPGs
        _pr = _ss.post(f"{vc_url}/sdk", timeout=20, headers=_H, data=
            """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:vim25="urn:vim25">
<soapenv:Body>
<vim25:RetrievePropertiesEx>
<vim25:_this type="PropertyCollector">propertyCollector</vim25:_this>
<vim25:specSet>
  <vim25:propSet>
    <vim25:type>DistributedVirtualPortgroup</vim25:type>
    <vim25:all>false</vim25:all>
    <vim25:pathSet>config</vim25:pathSet>
    <vim25:pathSet>name</vim25:pathSet>
  </vim25:propSet>
  <vim25:objectSet>
    <vim25:obj type="Folder">group-d1</vim25:obj>
    <vim25:skip>true</vim25:skip>
    <vim25:selectSet xsi:type="vim25:TraversalSpec">
      <vim25:name>visitFolders</vim25:name>
      <vim25:type>Folder</vim25:type>
      <vim25:path>childEntity</vim25:path>
      <vim25:skip>false</vim25:skip>
      <vim25:selectSet><vim25:name>visitFolders</vim25:name></vim25:selectSet>
      <vim25:selectSet><vim25:name>visitDC</vim25:name></vim25:selectSet>
    </vim25:selectSet>
    <vim25:selectSet xsi:type="vim25:TraversalSpec">
      <vim25:name>visitDC</vim25:name>
      <vim25:type>Datacenter</vim25:type>
      <vim25:path>networkFolder</vim25:path>
      <vim25:skip>false</vim25:skip>
      <vim25:selectSet><vim25:name>visitFolders</vim25:name></vim25:selectSet>
    </vim25:selectSet>
  </vim25:objectSet>
</vim25:specSet>
<vim25:options/>
</vim25:RetrievePropertiesEx>
</soapenv:Body>
</soapenv:Envelope>""")
        if not _pr.ok:
            return {}
        # Parse: each <objects> block has one dvportgroup moref + its config
        _result = {}
        for _block in _re.findall(r'<objects>(.*?)</objects>', _pr.text, _re.DOTALL):
            _m = _re.search(r'<obj type="DistributedVirtualPortgroup">(dvportgroup-\d+)</obj>', _block)
            _v = _re.search(r'<vlanId>(\d+)</vlanId>', _block)
            if _m and _v:
                _result[_m.group(1)] = int(_v.group(1))
        return _result
    except Exception:
        return {}



    resp = SESS.get(
        f"{vc_url}{path}",
        headers={"vmware-api-session-id": token},
        params=params,
        timeout=15,
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def nsx_get(nsx_url: str, user: str, pwd: str, path: str):
    resp = SESS.get(
        f"{nsx_url}{path}",
        auth=(user, pwd),
        headers={"Accept": "application/json"},
        timeout=15,
    )
    if resp.status_code in (404, 405):
        return None
    resp.raise_for_status()
    return resp.json()


# ── routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index_clarity.html")


@app.route("/api/debug-zones", methods=["POST"])
def debug_zones():
    """Probe multiple candidate vSphere Zones API paths and return raw results."""
    body     = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")

    candidates = [
        "/api/vcenter/consumption-domains/zones",
        "/api/vcenter/namespace-management/infrastructure/zones",
        "/api/vcenter/namespaces/infrastructure/zones",
        "/rest/vcenter/consumption-domains/zones",
    ]
    results = {}
    try:
        token, _ = vc_auth(vc_url, username, password)
        for path in candidates:
            try:
                resp = SESS.get(
                    f"{vc_url}{path}",
                    headers={"vmware-api-session-id": token,
                             "Accept": "application/json"},
                    verify=False, timeout=10,
                )
                results[path] = {
                    "status": resp.status_code,
                    "body":   resp.json() if resp.headers.get("content-type","").startswith("application/json") else resp.text[:300],
                }
            except Exception as e:
                results[path] = {"status": "error", "body": str(e)}
    except Exception as e:
        return jsonify({"auth_error": str(e), "results": {}})
    return jsonify({"results": results})


@app.route("/api/check-installed", methods=["POST"])
def check_installed():
    body = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    # Fall back to auto-discovery from vCenter if NSX URL not supplied (e.g. browser autofill race)
    nsx_url  = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user") or "admin"
    nsx_pass = body.get("nsx_pass") or password

    result = {"success": False, "installed": False, "clusters": [], "capability": {},
              "error": None, "auth_user": None}

    try:
        token, effective_user = vc_auth(vc_url, username, password)

        clusters = vc_get(vc_url, token, "/api/vcenter/namespace-management/clusters") or []
        capability = vc_get(vc_url, token, "/api/vcenter/namespace-management/capability") or {}

        # Build moref → human-readable name map from the standard cluster endpoint
        try:
            _all_clusters = vc_get(vc_url, token, "/api/vcenter/cluster") or []
            _name_map = {cl.get("cluster"): cl.get("name", "") for cl in _all_clusters}
        except Exception:
            _name_map = {}

        # Enrich each cluster with detail data (api_server_cluster_endpoint, etc.)
        # The list endpoint omits these fields; the individual GET includes them.
        enriched = []
        for c in clusters:
            cid = c.get("cluster")
            if cid:
                try:
                    detail = vc_get(vc_url, token,
                                    f"/api/vcenter/namespace-management/clusters/{cid}")
                    if detail:
                        c = {**c, **detail}
                except Exception:
                    pass
                # Attach human-readable cluster name (e.g. "supervisor-wld-a")
                if cid in _name_map and _name_map[cid]:
                    c["name"] = _name_map[cid]
            enriched.append(c)

        # Determine human-readable network mode for each cluster.
        # For NSX_VPC: vCenter cluster detail → VPC profile → NSX TGW → check attachment type.
        for c in enriched:
            np = c.get("network_provider", "")
            if np == "VSPHERE_NETWORK":
                c["network_mode"] = "VDS / FLB"
            elif np == "NSX_T":
                c["network_mode"] = "NSX-T (Legacy)"
            elif np == "NSX_VPC":
                c["network_mode"] = "NSX-VPC"  # default; refined below
                c["network_mode_warning"] = None

                def _detect_nsx_vpc_mode(nsx, user, pw, prof_path):
                    """Return 'NSX-VPC Distributed', 'NSX-VPC Centralized', or None."""
                    vcp      = nsx_get(nsx, user, pw, f"/policy/api/v1{prof_path}")
                    tgw_path = (vcp or {}).get("transit_gateway_path", "")
                    if not tgw_path:
                        return None
                    parts   = tgw_path.rstrip("/").split("/")
                    tgw_id  = parts[-1]
                    try:
                        tgw_proj = parts[parts.index("projects") + 1]
                    except (ValueError, IndexError):
                        tgw_proj = "default"
                    ta   = nsx_get(nsx, user, pw,
                                   f"/policy/api/v1/orgs/default/projects/{tgw_proj}"
                                   f"/transit-gateways/{tgw_id}/attachments")
                    atts = (ta or {}).get("results", [])
                    if any("/distributed-vlan-connections/" in (a.get("connection_path") or "") for a in atts):
                        return "NSX-VPC Distributed"
                    if any("/gateway-connections/" in (a.get("connection_path") or "") for a in atts):
                        return "NSX-VPC Centralized"
                    return None

                if nsx_url:
                    # Build the VPC profile path from vCenter cluster detail
                    vpc_net       = c.get("vpc_network") or {}
                    vpc_prof_path = vpc_net.get("vpc_connectivity_profile", "")
                    nsx_proj_path = vpc_net.get("nsx_project", "/orgs/default/projects/default")
                    parts_proj    = nsx_proj_path.rstrip("/").split("/")
                    nsx_proj_id   = (parts_proj[parts_proj.index("projects") + 1]
                                     if "projects" in parts_proj else "default")
                    if not vpc_prof_path:
                        vpc_prof_path = f"/orgs/default/projects/{nsx_proj_id}/vpc-connectivity-profiles/default"
                    if "/" not in vpc_prof_path:
                        vpc_prof_path = f"/orgs/default/projects/{nsx_proj_id}/vpc-connectivity-profiles/{vpc_prof_path}"

                    # First attempt with supplied NSX URL
                    detected = None
                    try:
                        detected = _detect_nsx_vpc_mode(nsx_url, nsx_user, nsx_pass, vpc_prof_path)
                    except Exception:
                        pass

                    # Second attempt: auto-discovered URL (handles truncated/wrong FQDNs)
                    if detected is None:
                        _fallback = guess_nsx_url(vc_url)
                        if _fallback and _fallback != nsx_url:
                            try:
                                detected = _detect_nsx_vpc_mode(_fallback, nsx_user, nsx_pass, vpc_prof_path)
                            except Exception:
                                pass

                    if detected:
                        c["network_mode"]         = detected
                        c["network_mode_warning"] = None
                    else:
                        c["network_mode_warning"] = (
                            "Cannot reach NSX to determine if Distributed or Centralized. "
                            "Check NSX FQDN / credentials."
                        )
            else:
                c["network_mode"] = np or "Unknown"
                c["network_mode_warning"] = None

        result.update(success=True, installed=bool(enriched), clusters=enriched,
                      capability=capability, auth_user=effective_user)

    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result["error"] = str(e)

    return jsonify(result)


@app.route("/api/check-requirements", methods=["POST"])
def check_requirements():
    body = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    nsx_url  = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user") or "admin"
    nsx_pass = body.get("nsx_pass") or password

    # ── Phase 1: collect all raw data (single API pass) ──────────────────────
    d: dict = {}

    try:
        d["token"], d["effective_user"] = vc_auth(vc_url, username, password)
        d["vc_auth_ok"] = True
    except Exception as e:
        d["vc_auth_ok"] = False
        d["vc_auth_error"] = str(e)

    if d.get("vc_auth_ok"):
        try:
            d["cap"] = vc_get(vc_url, d["token"],
                              "/api/vcenter/namespace-management/capability") or {}
        except Exception as e:
            d["cap"] = {}; d["cap_error"] = str(e)

        try:
            d["vc_clusters"] = vc_get(vc_url, d["token"], "/api/vcenter/cluster") or []
            # REST API ha_enabled/drs_enabled can be stale — overlay with accurate SOAP values
            _morefs = [c.get("cluster") for c in d["vc_clusters"] if c.get("cluster")]
            _soap_ha_drs = _soap_get_cluster_ha_drs(vc_url, username, password, _morefs)
            for _c in d["vc_clusters"]:
                _m = _c.get("cluster")
                if _m and _m in _soap_ha_drs:
                    _s = _soap_ha_drs[_m]
                    if _s.get("ha_enabled")  is not None: _c["ha_enabled"]   = _s["ha_enabled"]
                    if _s.get("drs_enabled") is not None: _c["drs_enabled"]  = _s["drs_enabled"]
                    _c["drs_behavior"] = _s.get("drs_behavior")
        except Exception as e:
            d["vc_clusters"] = []; d["clusters_error"] = str(e)

        # Build host_short/fqdn → cluster_name using vCenter (reliable; used for
        # R3 grouping and cluster-filter logic in the requirements checks).
        try:
            _vc_host_cluster: dict = {}
            for _c in d.get("vc_clusters", []):
                _moref = _c.get("cluster", "")
                _cname = _c.get("name", "")
                if not _moref or not _cname:
                    continue
                _raw = vc_get(vc_url, d["token"],
                              "/api/vcenter/host",
                              params={"clusters": _moref}) or []
                for _h in _raw:
                    _hname = _h.get("name", "")
                    if _hname:
                        _short = _hname.split(".")[0] if "." in _hname else _hname
                        _vc_host_cluster[_hname] = _cname
                        _vc_host_cluster[_short]  = _cname
            d["vc_host_cluster_map"] = _vc_host_cluster
        except Exception:
            d["vc_host_cluster_map"] = {}

    if nsx_url:
        try:
            tnc = nsx_get(nsx_url, nsx_user, nsx_pass,
                "/policy/api/v1/infra/sites/default/enforcement-points/default/transport-node-collections")
            d["tnc"] = (tnc or {}).get("results", [])
            htn = nsx_get(nsx_url, nsx_user, nsx_pass,
                "/policy/api/v1/infra/sites/default/enforcement-points/default/host-transport-nodes")
            d["htn"] = (htn or {}).get("results", [])
            # Fetch per-host /state to detect disconnected/failed hosts
            _htn_ep = ("/policy/api/v1/infra/sites/default/enforcement-points"
                       "/default/host-transport-nodes")
            htn_states: dict = {}
            for _h in d["htn"][:50]:
                _hid = _h.get("id", "")
                if _hid:
                    try:
                        _st = nsx_get(nsx_url, nsx_user, nsx_pass,
                                      f"{_htn_ep}/{_hid}/state")
                        htn_states[_hid] = _st or {}
                    except Exception:
                        pass
            d["htn_states"] = htn_states
        except Exception as e:
            d["tnc"] = []; d["htn"] = []; d["tep_error"] = str(e)

        # Resolve TNC UUID → cluster name via Manager API
        # compute_collection_id uses external_id format: "{cm_id}:{cluster_moref}"
        try:
            cc_resp  = nsx_get(nsx_url, nsx_user, nsx_pass, "/api/v1/fabric/compute-collections")
            cc_list  = (cc_resp or {}).get("results", [])
            # Key by external_id (matches TNC compute_collection_id exactly)
            cc_names = {c.get("external_id", c.get("id", "")): c.get("display_name", "")
                        for c in cc_list if c.get("origin_type") == "VC_Cluster"}

            tnc_v1_resp = nsx_get(nsx_url, nsx_user, nsx_pass, "/api/v1/transport-node-collections")
            tnc_v1_list = (tnc_v1_resp or {}).get("results", [])

            tnc_cluster_map: dict = {}
            cc_id_to_cluster: dict = {}   # compute_collection_id → cluster_name
            for t in tnc_v1_list:
                tid   = t.get("id", "")
                cc_id = t.get("compute_collection_id", "")
                cname = cc_names.get(cc_id, "")
                if cname:
                    tnc_cluster_map[tid]        = cname
                    cc_id_to_cluster[cc_id]     = cname

            d["tnc_cluster_map"] = tnc_cluster_map

            # Build host_short → cluster_name map by fetching compute-collection members
            host_cluster_map: dict = {}
            for _cc_id, _cname in cc_id_to_cluster.items():
                try:
                    _mbr = nsx_get(nsx_url, nsx_user, nsx_pass,
                                   f"/api/v1/fabric/compute-collections/{_cc_id}/member-status")
                    for _m in (_mbr or {}).get("member_status", []):
                        _fqdn  = _m.get("display_name", "")
                        _short = _fqdn.split(".")[0] if "." in _fqdn else _fqdn
                        if _short:
                            host_cluster_map[_short] = _cname
                except Exception:
                    pass
            d["host_cluster_map"] = host_cluster_map
        except Exception:
            d["tnc_cluster_map"] = {}

        try:
            vna = nsx_get(nsx_url, nsx_user, nsx_pass,
                "/policy/api/v1/infra/sites/default/enforcement-points/default/virtual-network-appliance-clusters")
            d["vna"] = (vna or {}).get("results", [])
            # Fetch deployment state for each VNA cluster
            d["vna_states"] = {}
            for v in d["vna"]:
                cid = v.get("id", "")
                if cid:
                    try:
                        st = nsx_get(nsx_url, nsx_user, nsx_pass,
                            f"/policy/api/v1/infra/sites/default/enforcement-points/default"
                            f"/virtual-network-appliance-clusters/{cid}/state")
                        d["vna_states"][cid] = (st or {}).get("consolidated_status", "UNKNOWN")
                    except Exception:
                        d["vna_states"][cid] = "UNKNOWN"
            ec = nsx_get(nsx_url, nsx_user, nsx_pass,
                "/policy/api/v1/infra/sites/default/enforcement-points/default/edge-clusters")
            d["ec"] = (ec or {}).get("results", [])
            # Fetch form_factor for every edge transport node that belongs to an EC
            _ec_ep = "/policy/api/v1/infra/sites/default/enforcement-points/default"
            _ec_etn_ids: set = set()
            for _ec_obj in d["ec"]:
                for _pen in (_ec_obj.get("policy_edge_nodes") or []):
                    _etn_path = _pen.get("edge_transport_node_path", "")
                    _etn_id = _etn_path.rstrip("/").split("/")[-1]
                    if _etn_id:
                        _ec_etn_ids.add(_etn_id)
            _ec_ff: dict = {}  # etn_id → {"name": ..., "form_factor": ...}
            if _ec_etn_ids:
                _etns_raw = nsx_get(nsx_url, nsx_user, nsx_pass,
                    f"{_ec_ep}/edge-transport-nodes")
                for _etn in (_etns_raw or {}).get("results", []):
                    _eid = _etn.get("id", "")
                    if _eid in _ec_etn_ids:
                        _ec_ff[_eid] = {
                            "name": _etn.get("display_name") or _etn.get("hostname") or _eid,
                            "form_factor": _etn.get("form_factor", "UNKNOWN"),
                        }
            d["ec_node_form_factors"] = _ec_ff
            t0 = nsx_get(nsx_url, nsx_user, nsx_pass, "/policy/api/v1/infra/tier-0s")
            d["t0"] = (t0 or {}).get("results", [])
        except Exception as e:
            d["vna"] = []; d["ec"] = []; d["t0"] = []
            d["ec_node_form_factors"] = {}; d["topo_error"] = str(e)

        try:
            dv = nsx_get(nsx_url, nsx_user, nsx_pass,
                         "/policy/api/v1/infra/distributed-vlan-connections")
            d["dvlan"] = (dv or {}).get("results", [])
            gw = nsx_get(nsx_url, nsx_user, nsx_pass,
                         "/policy/api/v1/infra/gateway-connections")
            d["gw_conn"] = (gw or {}).get("results", [])
        except Exception as e:
            d["dvlan"] = []; d["gw_conn"] = []; d["extconn_error"] = str(e)

        try:
            # Fetch TGWs + attachments from ALL projects (not just default).
            # Project-local TGWs have paths like
            # /orgs/default/projects/<proj>/transit-gateways/<id>
            # and VCPs reference them by full path, so we store _tgw_path for matching.
            _proj_ids_for_tgw = ["default"]
            try:
                _pr = nsx_get(nsx_url, nsx_user, nsx_pass,
                              "/policy/api/v1/orgs/default/projects")
                for _p in (_pr or {}).get("results", []):
                    _pid2 = _p.get("id", "")
                    if _pid2 and _pid2 not in _proj_ids_for_tgw:
                        _proj_ids_for_tgw.append(_pid2)
            except Exception:
                pass

            all_tgws_flat = []
            d["tgw_all_att"] = []
            for _proj_id in _proj_ids_for_tgw:
                try:
                    _tl = nsx_get(nsx_url, nsx_user, nsx_pass,
                                  f"/policy/api/v1/orgs/default/projects/{_proj_id}/transit-gateways")
                    for _tgw in (_tl or {}).get("results", []):
                        all_tgws_flat.append(_tgw)
                        _tid  = _tgw.get("id", "")
                        _tpath = _tgw.get("path", "")
                        _ta = nsx_get(nsx_url, nsx_user, nsx_pass,
                                      f"/policy/api/v1/orgs/default/projects/{_proj_id}"
                                      f"/transit-gateways/{_tid}/attachments")
                        for _a in (_ta or {}).get("results", []):
                            _a["_tgw_id"]   = _tid
                            _a["_tgw_path"] = _tpath
                            _a["_tgw_name"] = _tgw.get("display_name", _tid)
                            _a["_tgw_proj"] = _proj_id
                            d["tgw_all_att"].append(_a)
                except Exception:
                    pass

            d["tgw"] = next((t for t in all_tgws_flat
                             if t.get("id") == "default"
                             and "/projects/default/" in t.get("path", "")), None)
            # path → display_name map for all TGWs across all projects
            d["_tgw_names"] = {t.get("path", ""): t.get("display_name", t.get("id", "?"))
                               for t in all_tgws_flat}
            # Backward compat: tgw_att = Default project TGW attachments only
            d["tgw_att"] = [a for a in d["tgw_all_att"]
                            if a.get("_tgw_proj") == "default" and a.get("_tgw_id") == "default"]
        except Exception as e:
            d["tgw_all_att"] = []; d["tgw_att"] = []; d["tgw"] = None; d["tgw_error"] = str(e)

        try:
            bl = nsx_get(nsx_url, nsx_user, nsx_pass, "/policy/api/v1/infra/ip-blocks")
            all_blocks = (bl or {}).get("results", [])
            # Enrich each block with resolved CIDR (handles list-API omissions)
            for b in all_blocks:
                if not b.get("cidr"):
                    resolved = _block_cidr(b, nsx_url, nsx_user, nsx_pass)
                    if resolved:
                        b["cidr"] = resolved
            # Use NSX's own visibility field ("EXTERNAL") as the authoritative filter.
            # Fall back to CIDR-based heuristic only for blocks with no visibility set.
            def _block_is_external(b):
                vis = (b.get("visibility") or "").upper()
                if vis == "EXTERNAL":
                    return True
                if vis in ("PRIVATE", "PROJECT"):
                    return False
                # No visibility set — fall back to CIDR heuristic
                return _is_external_ip_block(b.get("cidr", ""))
            d["ext_blocks"] = [b for b in all_blocks if _block_is_external(b)]
            d["int_blocks"] = [b for b in all_blocks if not _block_is_external(b)]
            # NSX list endpoint omits excluded_ips — fetch each ext block individually
            for b in d["ext_blocks"]:
                if not b.get("excluded_ips"):
                    try:
                        full = nsx_get(nsx_url, nsx_user, nsx_pass,
                                       f"/policy/api/v1/infra/ip-blocks/{b['id']}")
                        if full:
                            b["excluded_ips"] = full.get("excluded_ips", [])
                    except Exception:
                        pass
        except Exception as e:
            d["ext_blocks"] = []; d["int_blocks"] = []; d["blocks_error"] = str(e)

        try:
            # Fetch VPC Connectivity Profiles from ALL projects
            _proj_resp = nsx_get(nsx_url, nsx_user, nsx_pass,
                "/policy/api/v1/orgs/default/projects")
            _all_projs = (_proj_resp or {}).get("results", [{"id": "default", "display_name": "default"}])
            all_vcps: list = []
            for _proj in _all_projs:
                _pid = _proj.get("id", "")
                _vr  = nsx_get(nsx_url, nsx_user, nsx_pass,
                    f"/policy/api/v1/orgs/default/projects/{_pid}/vpc-connectivity-profiles")
                for _vcp in (_vr or {}).get("results", []):
                    _vcp["_proj_id"]   = _pid
                    _vcp["_proj_name"] = _proj.get("display_name", _pid)
                    all_vcps.append(_vcp)
            d["all_vcps"] = all_vcps
            # Backward compat: keep d["vcp"] = default project default profile
            d["vcp"] = next((v for v in all_vcps
                             if v.get("_proj_id") == "default" and v.get("id") == "default"), None)
        except Exception as e:
            d["all_vcps"] = []; d["vcp"] = None; d["vcp_error"] = str(e)

    # ── Phase 2: build per-mode check lists ──────────────────────────────────

    # Optional cluster filter: list of morefs from the request body.
    # Empty list (default) = check all clusters.
    _cluster_filter = body.get("cluster_filter") or []
    _filter_set     = set(_cluster_filter)

    def _filtered_clusters():
        """Return vc_clusters filtered to the selection (or all if no filter)."""
        all_c = d.get("vc_clusters", [])
        if not _filter_set:
            return all_c
        return [c for c in all_c if c.get("cluster") in _filter_set]

    def build_checks(mode: str) -> list:
        checks: list = []

        def add(step, name, status, message, details="", can_fix=False, link=None, **extra):
            entry = {"step": step, "name": name, "status": status,
                     "message": message, "details": details,
                     "can_fix": can_fix, "link": link}
            entry.update(extra)
            checks.append(entry)

        # ── Auth (all modes) ────────────────────────────────────────────────
        if not d.get("vc_auth_ok"):
            add("Auth", "vCenter Authentication", "error", f"Failed: {d.get('vc_auth_error')}")
            return checks
        note = (f" (auto-detected: {d['effective_user']})"
                if d["effective_user"] != username else "")
        add("Auth", "vCenter Authentication", "ok",
            f"Authenticated to {vc_url}{note}", f"User: {d['effective_user']}")

        # ── Step 1: Supervisor capability (all modes) ────────────────────────
        if "cap_error" in d:
            add("1", "Supervisor Capability", "warning", f"Could not check: {d['cap_error']}")
        else:
            cap = d.get("cap", {})
            supported = cap.get("namespaces_supported", False)
            licensed  = cap.get("namespaces_licensed",  False)
            msg = "Supervisor supported" if supported else "Supervisor NOT supported on this vCenter"
            if supported and not licensed:
                msg += " (unlicensed — still OK in VCF 9.1)"
            add("1", "Supervisor Capability", "ok" if supported else "error", msg,
                f"namespaces_supported={supported}\nnamespaces_licensed={licensed}")

        # ── Step 2: HA/DRS (all modes) ───────────────────────────────────────
        if "clusters_error" in d:
            add("2", "vSphere HA / DRS", "warning", f"Could not check: {d['clusters_error']}")
        else:
            vc_clusters = _filtered_clusters()
            cluster_issues, cluster_ok, clusters_to_fix = [], [], []
            cluster_details = []
            for c in vc_clusters:
                name  = c.get("name", c.get("cluster", "?"))
                moref = c.get("cluster", "")
                bad   = []
                if not c.get("ha_enabled"):
                    bad.append("HA disabled")
                if not c.get("drs_enabled"):
                    bad.append("DRS disabled")
                elif c.get("drs_behavior") and c["drs_behavior"] != "fullyAutomated":
                    beh = c["drs_behavior"]
                    bad.append(f"DRS not Fully Automated (mode: {beh})")
                if bad:
                    cluster_issues.append(f"{name}: {', '.join(bad)}")
                    lines = [f"· {name}:"]
                    for b in bad:
                        lines.append(f"  - {b}")
                    cluster_details.append("\n".join(lines))
                    clusters_to_fix.append({"moref": moref, "name": name, "issues": bad})
                else:
                    beh = c.get("drs_behavior") or "fullyAutomated"
                    cluster_ok.append(name)
                    cluster_details.append(f"· {name}:\n  - DRS ✓ ({beh})\n  - HA ✓")
            if cluster_issues:
                add("2", "vSphere HA / DRS", "error",
                    f"{len(cluster_issues)} cluster(s) missing HA or DRS",
                    "\n".join(cluster_details)
                    + "\n\nBoth HA and DRS (Fully Automated) are required for Supervisor.",
                    can_fix=True, fix_clusters=clusters_to_fix)
            elif vc_clusters:
                add("2", "vSphere HA / DRS", "ok",
                    f"All {len(vc_clusters)} cluster(s) have HA and DRS enabled",
                    "\n".join(cluster_details))
            else:
                add("2", "vSphere HA / DRS", "warning", "No clusters found via vCenter API.")

        # ── Step 2: vCenter FQDN (all modes) ────────────────────────────────
        _vc_fqdn = urlparse(vc_url).hostname or ""
        if _vc_fqdn.lower().endswith(".local"):
            add("3", "vCenter FQDN", "error",
                f"vCenter FQDN ends with '.local' — not supported for Supervisor Deployment",
                f"Your vCenter FQDN is '{_vc_fqdn}' which is not supported for Supervisor Deployment.")
        else:
            add("3", "vCenter FQDN", "ok",
                _vc_fqdn,
                _vc_fqdn)

        # ── Steps 3-8: NSX checks ─────────────────────────────────────────────
        nsx_na = "Not required for this deployment mode."

        if mode == "vds_flb":
            add("4", "VLANs/Subnets for Supervisor and FLB", "info",
                "Validation to do by Admin",
                "Supervisor deployment with VDS requires subnets for Supervisor and FLB.")
        elif not nsx_url:
            ext_conn_name = ("Distributed External Connection" if mode == "distributed"
                             else "Centralized External Connection" if mode == "centralized"
                             else "External Connection")
            for sn, nm in [
                ("3", "NSX Host Preparation"), ("4", "NSX Networking"),
                ("6-1", ext_conn_name),           ("6-2", "TGW Attachment"),
                ("6-3", "External IP Block"),    ("6-4", "VPC Profile"),
            ]:
                add(sn, nm, "warning", "NSX URL not provided — enter it in the NSX section above.")
        else:
            # Step 2: TEPs (same for both NSX modes)
            if "tep_error" in d:
                add("4", "NSX Host Preparation", "warning", f"Could not check: {d['tep_error']}")
            elif d.get("tnc") or d.get("htn"):
                tncs             = d.get("tnc", [])
                htn_states       = d.get("htn_states", {})
                tnc_cluster_map  = d.get("tnc_cluster_map", {})
                # Prefer the vCenter-derived map (reliable); fall back to NSX map
                host_cluster_map = (d.get("vc_host_cluster_map") or
                                    d.get("host_cluster_map", {}))

                # Build moref → cluster_name lookup once
                _moref_to_name = {c.get("cluster",""): c.get("name","")
                                  for c in d.get("vc_clusters", [])}

                def _host_cname(h):
                    fn    = h.get("display_name", "")
                    short = fn.split(".")[0] if "." in fn else fn
                    return host_cluster_map.get(fn, "") or host_cluster_map.get(short, "")

                # Apply cluster filter to host list
                _all_htns = d.get("htn", [])
                if _filter_set:
                    _selected_cnames = {_moref_to_name[m] for m in _filter_set
                                        if m in _moref_to_name and _moref_to_name[m]}
                    if _selected_cnames:
                        htns = [h for h in _all_htns
                                if _host_cname(h) in _selected_cnames]
                    else:
                        htns = _all_htns   # map not built yet — show all
                else:
                    htns = _all_htns

                # Cluster names for subtitle — filtered to selected clusters when filter active
                cluster_names = []
                for t in tncs:
                    tid   = t.get("id", "")
                    cname = tnc_cluster_map.get(tid) or t.get("display_name") or tid
                    if _filter_set:
                        # Only include if this TNC's cluster is in the selected set
                        _moref_to_name = {c.get("cluster",""): c.get("name","")
                                          for c in d.get("vc_clusters", [])}
                        _sel_names = {_moref_to_name.get(m,"") for m in _filter_set}
                        if cname not in _sel_names:
                            continue
                    cluster_names.append(cname)
                if not cluster_names:
                    cluster_names = ["(unknown)"]

                # Build per-host status lines, grouped by cluster
                from collections import defaultdict as _ddict
                _grouped   = _ddict(list)   # cluster_name → [status_line, ...]
                fail_count = 0
                for h in htns:
                    hid   = h.get("id", "")
                    hname = h.get("display_name", hid)
                    short = hname.split(".")[0] if "." in hname else hname
                    cname = host_cluster_map.get(short, "")
                    st    = htn_states.get(hid, {})
                    if st:
                        dstate  = (st.get("node_deployment_state") or {}).get("state", "unknown")
                        overall = st.get("state", dstate)
                        if overall == "success":
                            _grouped[cname].append(f"  · {short}: SUCCESS")
                        else:
                            state_label = dstate.upper()
                            fail_msg    = (st.get("failure_message") or "").split(".")[0]
                            line = (f"  · {short}: {state_label} — {fail_msg}"
                                    if fail_msg else f"  · {short}: {state_label}")
                            _grouped[cname].append(line)
                            fail_count += 1
                    else:
                        _grouped[cname].append(f"  · {short}: SUCCESS")

                # Flatten into detail_lines with cluster headers
                detail_lines = []
                for _cname in sorted(_grouped.keys(), key=lambda x: (x == "", x.lower())):
                    if _cname:
                        detail_lines.append(f"── {_cname} ──")
                    else:
                        detail_lines.append("── (cluster unknown) ──")
                    detail_lines.extend(sorted(_grouped[_cname]))

                total = len(htns)
                if fail_count == 0:
                    step_status = "ok"
                    subtitle    = f"vCenter Clusters hosts prepared — {', '.join(cluster_names)}"
                else:
                    step_status = "warning"
                    ok_count    = total - fail_count
                    subtitle    = (f"{ok_count}/{total} hosts healthy in "
                                   f"{', '.join(cluster_names)} — "
                                   f"{fail_count} host(s) with issues")

                add("4", "NSX Host Preparation", step_status, subtitle,
                    "\n".join(detail_lines))
            else:
                add("4", "NSX Host Preparation", "error",
                    "No ESXi hosts prepared with NSX.",
                    "Without NSX host prep, Supervisor cannot use NSX-VPC networking.")

            # Step 3: networking topology (mode-specific)
            if mode == "distributed":
                if "topo_error" in d:
                    add("5", "VNA Cluster", "warning", f"Could not check: {d['topo_error']}")
                elif d.get("vna"):
                    vna_states = d.get("vna_states") or {}
                    detail_lines = []
                    all_ok = True
                    any_deploying = False
                    any_failed = False
                    any_ff_small = False
                    names = []
                    for vna in d["vna"]:
                        cid     = vna.get("id", "?")
                        cname   = vna.get("display_name", cid)
                        cstatus = vna_states.get(cid, "UNKNOWN")
                        cff     = vna.get("appliance_form_factor", "UNKNOWN")
                        names.append(cname)
                        detail_lines.append(f"· {cname}: {cstatus}  (form_factor: {cff})")
                        if cstatus != "SUCCESS":
                            all_ok = False
                        if cstatus in ("IN_PROGRESS", "PENDING", "DEPLOYING"):
                            any_deploying = True
                        if cstatus in ("FAILED", "ERROR", "PARTIAL_SUCCESS"):
                            any_failed = True
                        if cff.upper() == "SMALL":
                            any_ff_small = True
                    detail = "\n".join(detail_lines)
                    names_str = ", ".join(names)
                    if any_ff_small:
                        add("5", "VNA Cluster", "error",
                            f"VNA Cluster: SMALL form factor not supported (MEDIUM required)",
                            detail)
                    elif all_ok:
                        add("5", "VNA Cluster", "ok",
                            f"VNA Cluster found: {names_str}", detail)
                    elif any_failed:
                        add("5", "VNA Cluster", "error",
                            f"VNA Cluster deployment failed", detail, can_fix=True)
                    elif any_deploying:
                        add("5", "VNA Cluster", "warning",
                            f"VNA Cluster deploying: {names_str}", detail)
                    else:
                        add("5", "VNA Cluster", "warning",
                            f"VNA Cluster status unknown: {names_str}", detail)
                else:
                    add("5", "VNA Cluster", "error",
                        "No VNA Cluster found.",
                        "A VNA Cluster is required for Distributed NSX-VPC mode.\n"
                        "This tool will guide you through the installation.\n\n"
                        "VNA requirements:\n"
                        "  · 2 management IPs for the VNA nodes (on the mgmt VLAN)",
                        can_fix=True)
            else:  # centralized
                if "topo_error" in d:
                    add("5", "Edge Cluster + Tier-0", "warning", f"Could not check: {d['topo_error']}")
                elif d.get("ec") and d.get("t0"):
                    ec_node_ff = d.get("ec_node_form_factors") or {}
                    ec_lines = []
                    for _ec_obj in d["ec"]:
                        _ecn = _ec_obj.get("display_name", _ec_obj.get("id", "?"))
                        ec_lines.append(f"  - {_ecn}")
                        for _pen in (_ec_obj.get("policy_edge_nodes") or []):
                            _etn_path = _pen.get("edge_transport_node_path", "")
                            _etn_id = _etn_path.rstrip("/").split("/")[-1]
                            _pen_id = _pen.get("id", _etn_id)
                            _ff_info = ec_node_ff.get(_etn_id) or {}
                            _ff = _ff_info.get("form_factor", "UNKNOWN")
                            ec_lines.append(f"    · {_pen_id}: form_factor={_ff}")
                    t0_lines = "\n".join(f"  - {t.get('display_name','?')}" for t in d["t0"])
                    detail = "· Edge cluster(s):\n" + "\n".join(ec_lines) + "\n· Tier-0(s):\n" + t0_lines
                    _small_nodes = [
                        info.get("name", eid)
                        for eid, info in ec_node_ff.items()
                        if (info.get("form_factor") or "").upper() == "SMALL"
                    ]
                    if _small_nodes:
                        add("5", "Edge Cluster + Tier-0", "error",
                            f"Edge node(s) have SMALL form factor (MEDIUM required): {', '.join(_small_nodes)}",
                            detail)
                    else:
                        add("5", "Edge Cluster + Tier-0", "ok",
                            "Edge Cluster + Tier-0 found", detail)
                elif d.get("ec"):
                    add("5", "Edge Cluster + Tier-0", "error",
                        "Edge Cluster found but no Tier-0.",
                        f"Edge clusters: {[e.get('display_name','?') for e in d['ec']]}\n"
                        "A Tier-0 with BGP is required for Centralized NSX-VPC mode.",
                        can_fix=True)
                else:
                    add("5", "Edge Cluster + Tier-0", "error",
                        "No Edge Cluster found.",
                        "An Edge Cluster with Tier-0 + BGP is required for Centralized NSX-VPC.\n"
                        "This tool does not automate Edge Cluster + Tier-0 deployment.\n"
                        "A blog with a recorded installation demo is available.",
                        can_fix=True,
                        link={"text": "blog with recorded installation demo here",
                              "url": "https://blogs.vmware.com/cloud-foundation/2025/06/25/vpc-centralized-network-connectivity-with-guided-edge-deployment/"})

            # Step 4: external connection (mode-specific)
            if mode == "distributed":
                if "extconn_error" in d:
                    add("6-1", "Distributed External Connection", "warning", f"Could not check: {d['extconn_error']}")
                elif d.get("dvlan"):
                    names = [dc.get("display_name", dc.get("id", "?")) for dc in d["dvlan"]]
                    detail_lines = []
                    for dc in d["dvlan"]:
                        name = dc.get("display_name", dc.get("id", "?"))
                        vlan = dc.get("vlan_id", "?")
                        gws  = ", ".join(dc.get("gateway_addresses") or []) or "?"
                        detail_lines.append(f"· {name}\n  VLAN ID: {vlan}\n  Gateway: {gws}")
                    add("6-1", "Distributed External Connection", "ok",
                        f"{len(d['dvlan'])} Distributed External Connection(s): {', '.join(names)}",
                        "\n".join(detail_lines))
                else:
                    add("6-1", "Distributed External Connection", "error",
                        "No Distributed External Connection found.",
                        "The Distributed External Connection is the connection to the physical fabric.\n"
                        "In the Distributed option, that's a VLAN / physical gateway.\n"
                        "This tool will guide you through its creation.\n"
                        "Requires: 1 VLAN/subnet reachable from all ESXi hosts.",
                        can_fix=True)
            else:  # centralized
                if "extconn_error" in d:
                    add("6-1", "Centralized External Connection", "warning", f"Could not check: {d['extconn_error']}")
                elif d.get("gw_conn"):
                    detail_lines = []
                    for gc in d["gw_conn"]:
                        name  = gc.get("display_name", gc.get("id", "?"))
                        t0    = (gc.get("tier0_path") or "?").rstrip("/").split("/")[-1]
                        detail_lines.append(f"· {name}\n  Tier-0: {t0}")
                    names = [gc.get("display_name", gc.get("id","?")) for gc in d["gw_conn"]]
                    add("6-1", "Centralized External Connection", "ok",
                        f"{len(d['gw_conn'])} Centralized External Connection(s): {', '.join(names)}",
                        "\n".join(detail_lines))
                else:
                    add("6-1", "Centralized External Connection", "error",
                        "No Centralized External Connection found.",
                        "The Centralized External Connection is the connection to the physical fabric.\n"
                        "In the Centralized option, that's an NSX Tier-0.\n"
                        "This tool will guide you through its creation.",
                        can_fix=True)

            # Step 5: TGW attachment — mode-specific connection type check
            if "tgw_error" in d:
                add("6-2", "Distributed Transit Gateway" if mode == "distributed" else "TGW Attachment",
                    "warning", f"Could not check: {d['tgw_error']}")
            else:
                all_att_global = d.get("tgw_all_att", d.get("tgw_att", []))
                if mode == "distributed":
                    # Distributed: any TGW must have an attachment to /distributed-vlan-connections/
                    dist_att = [a for a in all_att_global
                                if "/distributed-vlan-connections/" in (a.get("connection_path") or "")]
                    # Check Default TGW for centralized (to decide fix Case 1 vs Case 2)
                    default_att = d.get("tgw_att", [])
                    centralized_att = [a for a in default_att
                                       if "/gateway-connections/" in (a.get("connection_path") or "")]
                    if dist_att:
                        # Group by TGW for display
                        tgw_groups: dict = {}
                        for a in dist_att:
                            tname = a.get("_tgw_name", a.get("_tgw_id", "Transit Gateway"))
                            tgw_groups.setdefault(tname, []).append(a.get("connection_path", "?"))
                        lines = []
                        first_tgw_name = next(iter(tgw_groups), "")
                        tgw_names_dist = list(tgw_groups.keys())
                        dist_subtitle = (f"1 Distributed Transit Gateway: {tgw_names_dist[0]}"
                                         if len(tgw_names_dist) == 1
                                         else f"{len(tgw_names_dist)} Distributed Transit Gateways")
                        for tname, cps in tgw_groups.items():
                            lines.append(f"· {tname}")
                            for cp in cps:
                                conn_name = cp.rstrip("/").split("/")[-1]
                                lines.append(f"  Attached to: {conn_name}")
                        add("6-2", "Distributed Transit Gateway", "ok",
                            dist_subtitle,
                            "\n".join(lines), tgw_name=first_tgw_name)
                    elif d.get("tgw"):
                        if centralized_att:
                            # Case 2: Default TGW is already Centralized → must create a new TGW
                            add("6-2", "Distributed Transit Gateway", "error",
                                "No Distributed Transit Gateway",
                                "The Default Transit Gateway is already configured as Centralized.\n"
                                "A new Distributed Transit Gateway must be created and attached\n"
                                "to a Distributed External Connection.\n"
                                "This tool will guide you through creating it.",
                                can_fix=True)
                        else:
                            # Case 1: Default TGW has no connection → attach it
                            add("6-2", "Distributed Transit Gateway", "error",
                                "No existing Distributed Transit Gateway.",
                                "This tool will guide you through attaching it to a Distributed External Connection.",
                                can_fix=True)
                    else:
                        add("6-2", "Distributed Transit Gateway", "error",
                            "Default Transit Gateway not found.",
                            "The Transit Gateway is required for NSX-VPC networking.\n"
                            "This tool will guide you through the configuration.",
                            can_fix=True)
                else:  # centralized
                    # Centralized: any TGW must have an attachment to /gateway-connections/
                    cent_att = [a for a in all_att_global
                                if "/gateway-connections/" in (a.get("connection_path") or "")]
                    if cent_att:
                        # Build edge-cluster path → name lookup
                        ec_names = {ec.get("path", ""): ec.get("display_name", ec.get("id", "?"))
                                    for ec in d.get("ec", [])}
                        # Group by TGW id for display; keep full attachment object
                        tgw_id_groups: dict = {}
                        for a in cent_att:
                            tid   = a.get("_tgw_id", "default")
                            tname = a.get("_tgw_name", tid)
                            tgw_id_groups.setdefault(tid, {"name": tname, "atts": []})["atts"].append(a)
                        tgw_names = [v["name"] for v in tgw_id_groups.values()]
                        subtitle = (f"1 Centralized Transit Gateway: {tgw_names[0]}"
                                    if len(tgw_names) == 1
                                    else f"{len(tgw_names)} Centralized Transit Gateways")
                        lines = []
                        for tid, info in tgw_id_groups.items():
                            lines.append(f"· {info['name']}")
                            for a in info["atts"]:
                                conn_name = (a.get("connection_path") or "?").rstrip("/").split("/")[-1]
                                lines.append(f"  Attached to: {conn_name}")
                            # Fetch CentralizedConfig to get the TGW Edge Cluster
                            try:
                                cc_resp = nsx_get(nsx_url, nsx_user, nsx_pass,
                                    f"/policy/api/v1/orgs/default/projects/default"
                                    f"/transit-gateways/{tid}/centralized-configs")
                                cc_list = (cc_resp or {}).get("results", [])
                                ec_paths = []
                                for cc in cc_list:
                                    ec_paths.extend(cc.get("edge_cluster_paths") or [])
                                for ecp in ec_paths:
                                    ec_name = ec_names.get(ecp, ecp.rstrip("/").split("/")[-1])
                                    lines.append(f"  Edge Cluster: {ec_name}")
                            except Exception:
                                pass
                        add("6-2", "Centralized Transit Gateway", "ok",
                            subtitle, "\n".join(lines), tgw_name=tgw_names[0] if tgw_names else "")
                    elif d.get("tgw"):
                        add("6-2", "Centralized Transit Gateway", "error",
                            "No existing Centralized Transit Gateway.",
                            "This tool will guide you through attaching it to a Centralized External Connection.",
                            can_fix=True)
                    else:
                        add("6-2", "Centralized Transit Gateway", "error",
                            "Default Transit Gateway not found.",
                            "The Transit Gateway is required for NSX-VPC networking.\n"
                            "This tool will guide you through the configuration.",
                            can_fix=True)

            # Step 6: external IP blocks — mode-specific validity check
            if "blocks_error" in d:
                add("6-3", "External IP Block", "warning", f"Could not check: {d['blocks_error']}")
            else:
                all_ext = d.get("ext_blocks", [])

                # Build the set of DVLAN gateway subnets once (used by both modes)
                dvlan_nets = []
                for dv in d.get("dvlan", []):
                    for gw in (dv.get("gateway_addresses") or []):
                        try:
                            dvlan_nets.append(ipaddress.ip_network(gw, strict=False))
                        except ValueError:
                            pass

                def _overlaps_dvlan(cidr):
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        return any(net.overlaps(dv) for dv in dvlan_nets)
                    except ValueError:
                        return False

                if mode == "distributed":
                    # Distributed: the block MUST overlap a DVLAN connection's gateway subnet.
                    # If there are no DVLAN connections there can be no valid block.
                    valid_blocks = [b for b in all_ext
                                    if dvlan_nets and _overlaps_dvlan(b.get("cidr", ""))]
                else:
                    # Centralized: the block must NOT overlap with a DVLAN gateway subnet
                    valid_blocks = [b for b in all_ext
                                    if not _overlaps_dvlan(b.get("cidr", ""))]

                if valid_blocks:
                    block_info = [f"{b.get('display_name','?')} ({b.get('cidr','?')})"
                                  for b in valid_blocks]
                    # Build details lines, including excluded ranges from description if present
                    detail_lines = []
                    for b in valid_blocks:
                        line = f"· {b.get('display_name', b.get('id','?'))}\n  CIDR: {b.get('cidr','?')}"
                        excl = _nsx_excl_to_str(b)
                        if excl:
                            line += f"\n  Excluded ranges: {excl}"
                        detail_lines.append(line)
                    add("6-3", "External IP Block", "ok",
                        f"{len(valid_blocks)} External IP block(s): {', '.join(block_info)}",
                        "\n".join(detail_lines))
                else:
                    if mode == "distributed":
                        if not dvlan_nets:
                            ext_detail = (
                                "No Distributed External Connection found (Step R5-1).\n"
                                "An External IP Block for Distributed mode requires a Distributed External Connection first —\n"
                                "its CIDR must match that connection's gateway subnet."
                            )
                        else:
                            rejected = [b for b in all_ext if not _overlaps_dvlan(b.get("cidr", ""))]
                            overlap_note = ""
                            if rejected:
                                names = [b.get("display_name", "?") for b in rejected]
                                overlap_note = (f"\nNote: {len(rejected)} block(s) found ({', '.join(names)})"
                                                " but their CIDR does not match any Distributed External Connection subnet.")
                            ext_detail = (
                                "An External IP Block is required for future Supervisor VIP and NAT allocation.\n"
                                "In the Distributed option, the CIDR must match the subnet from Step R5-1 "
                                "(Distributed External Connection)." + overlap_note + "\n"
                                "This tool will guide you through the creation of an External IP Block."
                            )
                    else:
                        overlap_note = ""
                        if all_ext:
                            names = [b.get("display_name", "?") for b in all_ext]
                            overlap_note = (f"\nNote: {len(all_ext)} external block(s) found ({', '.join(names)})"
                                            " but they overlap with the Distributed VLAN subnet — not usable for Centralized mode.")
                        ext_detail = (
                            "An External IP Block is required for future Supervisor VIP and NAT allocation.\n"
                            "In the Centralized option, that's a new subnet (not on the physical fabric)\n"
                            "which the physical fabric will learn from the T0-BGP." + overlap_note + "\n"
                            "This tool will guide you through the creation of an External IP Block."
                        )
                    add("6-3", "External IP Block", "error",
                        "No External IP Block found.",
                        ext_detail,
                        can_fix=True)

            # Step 7: VPC connectivity profile
            title_7 = ("Distributed VPC Connectivity Profile"
                       if mode == "distributed"
                       else "Centralized VPC Connectivity Profile")
            if "vcp_error" in d:
                add("6-4", title_7, "warning", f"Could not check: {d['vcp_error']}")
            else:
                all_vcps      = d.get("all_vcps", [v for v in [d.get("vcp")] if v])
                cluster_label = "VNA Cluster" if mode == "distributed" else "Edge Cluster"

                def _tgw_attachments(tgw_path):
                    """Return all attachments for a TGW identified by its full path."""
                    tgw_id = tgw_path.rstrip("/").split("/")[-1]
                    return [
                        a for a in d.get("tgw_all_att", [])
                        if (a.get("_tgw_path") == tgw_path   # exact full-path match
                            or a.get("_tgw_id") == tgw_id)   # fallback: ID-only match
                    ]

                def _vcp_is_valid_dist(vcp):
                    """Return True if a VCP satisfies the Distributed requirements."""
                    sg  = (vcp.get("service_gateway") or {})
                    nat = (sg.get("nat_config") or {})
                    tgw_path = vcp.get("transit_gateway_path", "")
                    if not tgw_path:
                        return False
                    has_dist = any(
                        "/distributed-vlan-connections/" in (a.get("connection_path") or "")
                        for a in _tgw_attachments(tgw_path)
                    )
                    return (has_dist and
                            bool(vcp.get("external_ip_blocks")) and
                            bool(vcp.get("private_tgw_ip_blocks")) and
                            bool(sg.get("edge_cluster_paths")) and
                            bool(sg.get("enable")) and
                            bool(nat.get("enable_default_snat")))

                def _vcp_is_valid_cent(vcp):
                    """Return True if a VCP satisfies the Centralized requirements.
                    The TGW must have a Gateway Connection (centralized) attachment.
                    """
                    sg  = (vcp.get("service_gateway") or {})
                    nat = (sg.get("nat_config") or {})
                    tgw_path = vcp.get("transit_gateway_path", "")
                    if not tgw_path:
                        return False
                    has_cent = any(
                        "/gateway-connections/" in (a.get("connection_path") or "")
                        for a in _tgw_attachments(tgw_path)
                    )
                    return (has_cent and
                            bool(vcp.get("external_ip_blocks")) and
                            bool(vcp.get("private_tgw_ip_blocks")) and
                            bool(sg.get("edge_cluster_paths")) and
                            bool(sg.get("enable")) and
                            bool(nat.get("enable_default_snat")))

                is_valid = _vcp_is_valid_dist if mode == "distributed" else _vcp_is_valid_cent
                valid_vcps = [v for v in all_vcps if is_valid(v)]

                if valid_vcps:
                    # Build path/id → display_name map for IP blocks so we show names, not IDs.
                    _bname_map: dict = {}
                    for _b in (d.get("ext_blocks", []) + d.get("int_blocks", [])):
                        _b_path = _b.get("path", "")
                        _b_dn   = _b.get("display_name") or _b.get("id", "")
                        if _b_path:
                            _bname_map[_b_path] = _b_dn
                        if _b.get("id"):
                            _bname_map[_b["id"]] = _b_dn

                    def _b_display(path: str) -> str:
                        if path in _bname_map:
                            return _bname_map[path]
                        seg = path.rstrip("/").split("/")[-1]
                        return _bname_map.get(seg, seg)

                    lines = []
                    for v in valid_vcps:
                        sg  = (v.get("service_gateway") or {})
                        nat = (sg.get("nat_config") or {})
                        proj  = v.get("_proj_name", v.get("_proj_id", "?"))
                        name  = v.get("display_name", v.get("id", "?"))
                        _tgw_p = v.get("transit_gateway_path", "")
                        tgw    = (d.get("_tgw_names", {}).get(_tgw_p)
                                  or _tgw_p.rstrip("/").split("/")[-1]
                                  or "?")
                        ext_b  = ", ".join(_b_display(b)
                                           for b in (v.get("external_ip_blocks") or []))
                        priv_b = ", ".join(_b_display(b)
                                           for b in (v.get("private_tgw_ip_blocks") or []))
                        clu    = ", ".join(p.rstrip("/").split("/")[-1]
                                           for p in (sg.get("edge_cluster_paths") or []))
                        lines.append(f"· {name}  (Project: {proj})")
                        lines.append(f"  TGW: {tgw}")
                        lines.append(f"  External IP Block: {ext_b}")
                        lines.append(f"  Private TGW IP Block: {priv_b}")
                        lines.append(f"  {cluster_label}: {clu}")
                        lines.append(f"  N/S Services: enabled")
                        lines.append(f"  Outbound NAT: enabled")
                    if len(valid_vcps) == 1:
                        _v0      = valid_vcps[0]
                        _vname   = _v0.get("display_name", _v0.get("id", "?"))
                        _vprojid = _v0.get("_proj_id", "default")
                        _vpname  = _v0.get("_proj_name", _vprojid)
                        subtitle = (f"1 valid VPC Connectivity Profile: {_vname} (Project: {_vpname})"
                                    if _vprojid != "default"
                                    else f"1 valid VPC Connectivity Profile: {_vname}")
                    else:
                        subtitle = f"{len(valid_vcps)} valid VPC Connectivity Profile(s)"
                    # Build structured deploy data (grouped by project) for the Deploy wizard
                    from collections import OrderedDict as _OD
                    _proj_map: dict = _OD()
                    for _v in valid_vcps:
                        _pid   = _v.get("_proj_id",   "default")
                        _pname = _v.get("_proj_name",  _pid)
                        _ppath = _v.get("path", "").rsplit("/vpc-connectivity-profiles/", 1)[0]
                        if not _ppath:
                            _ppath = f"/orgs/default/projects/{_pid}"
                        key = (_pid, _pname, _ppath)
                        if key not in _proj_map:
                            _proj_map[key] = []
                        _prof_path = _v.get("path", "")
                        _prof_name = _v.get("display_name", _v.get("id", ""))
                        _proj_map[key].append({"id": _v.get("id",""), "display_name": _prof_name, "path": _prof_path})
                    _deploy_projects = [
                        {"id": pid, "display_name": pname, "path": ppath,
                         "valid_vpc_profiles": profs}
                        for (pid, pname, ppath), profs in _proj_map.items()
                    ]
                    _first_nondefault = next(
                        (p for p in _deploy_projects if p["id"] != "default"), None)
                    _proj_hint = " | ".join(p["display_name"] for p in _deploy_projects)
                    add("6-4", title_7, "ok", subtitle, "\n".join(lines),
                        valid_vcps_for_deploy=_deploy_projects,
                        vcp_nsx_proj=(_first_nondefault["id"] if _first_nondefault else None),
                        vcp_proj_hint=_proj_hint)
                else:
                    tgw_bullet = ("  · Transit Gateway: Distributed"
                                  if mode == "distributed"
                                  else "  · Transit Gateway: Centralized")
                    req_lines = [tgw_bullet,
                                 "  · External IP Block",
                                 "  · Private - Transit Gateway IP Blocks",
                                 f"  · {cluster_label}",
                                 "  · N/S Services",
                                 "  · Outbound NAT"]
                    add("6-4", title_7, "error",
                        f"No valid {title_7} in any NSX Project",
                        "VPC Connectivity Profile requires the following settings:\n"
                        + "\n".join(req_lines)
                        + "\n\nThose are missing and this tool will guide you through this configuration.",
                        can_fix=True)

        return checks

    return jsonify({
        "modes": {
            "distributed": build_checks("distributed"),
            "centralized":  build_checks("centralized"),
            "vds_flb":      build_checks("vds_flb"),
        },
        "clusters": sorted(
            [{"cluster": c.get("cluster",""), "name": c.get("name", c.get("cluster",""))}
             for c in d.get("vc_clusters", [])],
            key=lambda c: c["name"].lower()
        ),
    })


@app.route("/api/discover-install-options", methods=["POST"])
def discover_install_options():
    """Auto-discover everything needed for the Supervisor install wizard."""
    body = request.get_json(force=True)
    vc_url = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    nsx_url = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user") or "admin"
    nsx_pass = body.get("nsx_pass") or password

    result = {
        "clusters": [],
        "storage_policies": [],
        "port_groups": [],
        "pg_clusters_map": {},   # pg_moref → [cluster_moref, ...] built via SOAP
        "vc_defaults": {
            "gateway": "", "prefix": 24, "dns_servers": [],
            "search_domains": [], "ntp_servers": [],
            "vc_pg_id": "",   # port group of the vCenter VM (empty if not found in this VC)
            "vc_pg_vlan_id": None,  # VLAN ID of the vCenter VM's port group
        },
        "node_defaults": {},
        "nsx_project_path": "/orgs/default/projects/default",
        "vpc_connectivity_profile_path": (
            "/orgs/default/projects/default/vpc-connectivity-profiles/default"
        ),
        "error": None,
    }

    try:
        token, _ = vc_auth(vc_url, username, password)

        # Batch-fetch all DVPG VLAN IDs via SOAP PropertyCollector (REST endpoint 404 on vCenter 9.x)
        _dvpg_vlans: dict = _vc_soap_get_dvpg_vlans(vc_url, username, password)

        _raw_clusters = vc_get(vc_url, token, "/api/vcenter/cluster") or []
        result["clusters"] = _raw_clusters

        # ── vSphere Zones ──────────────────────────────────────────────────
        # Use the official zone-associations API (vCenter 8.x / VCF 5.x).
        _cluster_map = {c.get("cluster"): c for c in _raw_clusters}  # moref → cluster obj

        def _parse_zones_list(raw):
            """Normalise raw zones API response to a plain list of dicts.
            Handles: plain list, {"value":[...]}, {"items":[...]}"""
            if isinstance(raw, list):
                return raw
            if isinstance(raw, dict):
                return raw.get("items", raw.get("value", [])) or []
            return []

        _zones_out = []

        try:
            # ── Step 1: get zone list ────────────────────────────────────────
            _zr  = vc_get(vc_url, token, "/api/vcenter/consumption-domains/zones")
            _zl  = _parse_zones_list(_zr)

            # ── Step 2: get zone-cluster associations ────────────────────────
            # Official API: GET /api/vcenter/consumption-domains/zone-associations/cluster
            # Returns: {"associations": [{"cluster": "domain-c9", "zone": "zone1",
            #                             "state": "ASSOCIATED"}, ...]}
            _zone_cluster_map = {}   # zone_id → [cluster_morefs]
            try:
                _ar = vc_get(vc_url, token,
                             "/api/vcenter/consumption-domains/zone-associations/cluster")
                _assocs = (_ar.get("associations", [])
                           if isinstance(_ar, dict) else _ar or [])
                for _a in _assocs:
                    if _a.get("state", "ASSOCIATED") == "ASSOCIATED":
                        _zid_a   = _a.get("zone", "")
                        _cmr_a   = _a.get("cluster", "")
                        if _zid_a and _cmr_a:
                            _zone_cluster_map.setdefault(_zid_a, []).append(_cmr_a)
            except Exception:
                pass   # endpoint may 404 on older builds — clusters will be empty

            # ── Step 3: build zone entries ───────────────────────────────────
            for _z in _zl:
                if not isinstance(_z, dict):
                    continue
                _zid   = _z.get("zone", "")
                _zname = _z.get("name", _zid)
                _zone_clusters = []
                for _cmr in _zone_cluster_map.get(_zid, []):
                    _cd = _cluster_map.get(_cmr, {})
                    _zone_clusters.append({
                        "cluster":     _cmr,
                        "name":        _cd.get("name", _cmr),
                        "ha_enabled":  _cd.get("ha_enabled"),
                        "drs_enabled": _cd.get("drs_enabled"),
                    })
                _zone_clusters.sort(key=lambda _c: _c.get("name", "").lower())
                _zones_out.append({"zone": _zid, "name": _zname, "clusters": _zone_clusters})

            result["zones"] = _zones_out

            # Clusters NOT assigned to any zone (shown separately so user can still
            # select them — vCenter will create a new zone automatically on deploy).
            _morefs_in_zones = {
                _c.get("cluster")
                for _z in _zones_out
                for _c in _z.get("clusters", [])
            }
            result["clusters_not_in_zone"] = sorted(
                [_rc for _rc in _raw_clusters
                 if _rc.get("cluster") not in _morefs_in_zones],
                key=lambda _rc: (_rc.get("name") or "").lower()
            )
        except Exception as _ze:
            result["zones"] = []
            result["zones_debug"] = str(_ze)

        result["storage_policies"] = (
            vc_get(vc_url, token, "/api/vcenter/storage/policies") or []
        )
        result["port_groups"] = (
            vc_get(vc_url, token, "/api/vcenter/network",
                   params={"types": "DISTRIBUTED_PORTGROUP"}) or []
        )

        # Enrich each distributed port group with its VLAN ID (from SOAP batch-fetch above)
        for _pg_obj in result["port_groups"]:
            _pgid = _pg_obj.get("network", "")
            if _pgid and _pgid in _dvpg_vlans:
                _pg_obj["vlan_id"] = _dvpg_vlans[_pgid]

        # Build pg_clusters_map via SOAP (REST ?hosts= filter is unreliable in some vCenter versions)
        result["pg_clusters_map"] = _vc_soap_get_pg_cluster_map(vc_url, username, password)

        # Get the vCenter appliance's own IP and gateway from /api/appliance/networking
        # (this works whether the user connected by FQDN or by IP).
        _vc_own_ip = ""
        try:
            _net = vc_get(vc_url, token, "/api/appliance/networking") or {}
            _ifaces_map = _net.get("interfaces", {}) if isinstance(_net, dict) else {}
            for _idata in _ifaces_map.values():
                _ipv4 = _idata.get("ipv4", {}) or {}
                _addr = _ipv4.get("address", "")
                _gw   = _ipv4.get("default_gateway", "")
                _pfx  = _ipv4.get("prefix", 24)
                if _addr:
                    _vc_own_ip = _addr
                if _gw and not result["vc_defaults"]["gateway"]:
                    result["vc_defaults"]["gateway"] = f"{_gw}/{_pfx}"
                    result["vc_defaults"]["prefix"]  = _pfx
                if _vc_own_ip:
                    break
        except Exception:
            pass

        # For gateway/prefix fallback via the older interfaces API
        if not result["vc_defaults"]["gateway"]:
            try:
                ifaces = vc_get(vc_url, token, "/api/appliance/networking/interfaces") or []
                for iface in (ifaces if isinstance(ifaces, list) else []):
                    ipv4 = iface.get("ipv4") or {}
                    gw = ipv4.get("default_gateway", "")
                    prefix = ipv4.get("prefix", 24)
                    if gw:
                        result["vc_defaults"]["gateway"] = f"{gw}/{prefix}"
                        result["vc_defaults"]["prefix"] = prefix
                        break
            except Exception:
                pass

        # Determine the vCenter short name for VM lookup:
        # - if the user typed a FQDN, extract the first label directly
        # - if the user typed an IP, _url_host is numeric → short name would be wrong,
        #   so we rely solely on the guest-IP match below
        _url_host = (urlparse(vc_url).hostname or "")
        _url_is_ip = all(p.isdigit() for p in _url_host.split(".") if p)
        _vc_short  = "" if _url_is_ip else _url_host.split(".")[0].lower()

        # Find vCenter VM's port group by:
        #   1. Name match  (FQDN input: match "vc-mgmt-a" from the URL)
        #   2. Guest IP match (IP input: find which VM's IP equals the vCenter IP we connected to)
        try:
            _all_vms = vc_get(vc_url, token, "/api/vcenter/vm") or []
            _vc_vm   = None

            # Strategy 1 — name match
            if _vc_short:
                _vc_vm = next((v for v in _all_vms
                               if (v.get("name") or "").lower() == _vc_short), None)

            # Strategy 2 — guest IP match (used when URL was an IP)
            if not _vc_vm and _vc_own_ip:
                for _v in _all_vms:
                    _vid = _v.get("vm", "")
                    if not _vid:
                        continue
                    _guest = vc_get(vc_url, token,
                                    f"/api/vcenter/vm/{_vid}/guest/networking/interfaces") or []
                    for _giface in (_guest if isinstance(_guest, list) else []):
                        for _gaddr in (_giface.get("ip", {}) or {}).get("ip_addresses", []):
                            if _gaddr.get("ip_address") == _vc_own_ip:
                                _vc_vm = _v
                                break
                        if _vc_vm:
                            break
                    if _vc_vm:
                        break

            if _vc_vm:
                _vm_id = _vc_vm.get("vm", "")
                _nics  = vc_get(vc_url, token,
                                f"/api/vcenter/vm/{_vm_id}/hardware/ethernet") or [] if _vm_id else []
                if _nics:
                    _nic0     = _nics[0].get("nic", "")
                    _nic_data = vc_get(vc_url, token,
                                      f"/api/vcenter/vm/{_vm_id}/hardware/ethernet/{_nic0}") if _nic0 else {}
                    _pg = ((_nic_data or {}).get("backing") or {}).get("network", "")
                    if _pg:
                        result["vc_defaults"]["vc_pg_id"]    = _pg
                        result["vc_defaults"]["vc_pg_vlan_id"] = _dvpg_vlans.get(_pg)
                # Also derive the short name from the found VM (for search domain)
                if _url_is_ip and not _vc_short:
                    _vc_short = (_vc_vm.get("name") or "").split(".")[0].lower()
        except Exception:
            pass

        try:
            dns = vc_get(vc_url, token, "/api/appliance/networking/dns/servers") or {}
            result["vc_defaults"]["dns_servers"] = dns.get("servers", [])
            # Search domain: always use the domain part of the vCenter FQDN the user entered.
            # e.g. "vc-mgmt-a.site-a.vcf.lab" → "site-a.vcf.lab"
            # If the user entered an IP, _url_is_ip is True → no domain available.
            _domain_src = ""
            if not _url_is_ip:
                _parts = _url_host.split(".")
                if len(_parts) >= 3:
                    _domain_src = ".".join(_parts[1:])
            if _domain_src:
                result["vc_defaults"]["search_domains"] = [_domain_src]
        except Exception:
            pass

        try:
            ntp = vc_get(vc_url, token, "/api/appliance/ntp") or []
            result["vc_defaults"]["ntp_servers"] = ntp if isinstance(ntp, list) else []
        except Exception:
            pass

        # NSX: discover valid distributed VPC profiles across all projects
        if nsx_url:
            try:
                # Build TGW attachment list for the default project
                _tgw_r = nsx_get(nsx_url, nsx_user, nsx_pass,
                    "/policy/api/v1/orgs/default/projects/default/transit-gateways")
                _tgw_att: list = []
                for _t in (_tgw_r or {}).get("results", []):
                    _tid = _t.get("id", "")
                    _ta  = nsx_get(nsx_url, nsx_user, nsx_pass,
                        f"/policy/api/v1/orgs/default/projects/default"
                        f"/transit-gateways/{_tid}/attachments")
                    for _a in (_ta or {}).get("results", []):
                        _a["_tgw_id"] = _tid
                        _tgw_att.append(_a)

                _projs = (nsx_get(nsx_url, nsx_user, nsx_pass,
                    "/policy/api/v1/orgs/default/projects") or {}).get("results",
                    [{"id": "default", "display_name": "default", "path": ""}])

                valid_nsx_projects: list = []
                for _proj in _projs:
                    _pid = _proj.get("id", "")
                    _vcp_r = nsx_get(nsx_url, nsx_user, nsx_pass,
                        f"/policy/api/v1/orgs/default/projects/{_pid}/vpc-connectivity-profiles")
                    valid_profiles: list = []
                    for _vcp in (_vcp_r or {}).get("results", []):
                        _sg  = (_vcp.get("service_gateway") or {})
                        _nat = (_sg.get("nat_config") or {})
                        _tp  = _vcp.get("transit_gateway_path", "")
                        if not _tp:
                            continue
                        _tgw_id = _tp.rstrip("/").split("/")[-1]
                        _has_dist = any(
                            _a.get("_tgw_id") == _tgw_id and
                            "/distributed-vlan-connections/" in (_a.get("connection_path") or "")
                            for _a in _tgw_att
                        )
                        if (_has_dist and _vcp.get("external_ip_blocks") and
                                _sg.get("edge_cluster_paths") and _sg.get("enable") and
                                _nat.get("enable_default_snat")):
                            valid_profiles.append({
                                "id":           _vcp.get("id", ""),
                                "display_name": _vcp.get("display_name", _vcp.get("id", "")),
                                "path":         _vcp.get("path", ""),
                            })
                    if valid_profiles:
                        _ppath = _proj.get("path") or f"/orgs/default/projects/{_pid}"
                        valid_nsx_projects.append({
                            "id":           _pid,
                            "display_name": _proj.get("display_name", _pid),
                            "path":         _ppath,
                            "valid_vpc_profiles": valid_profiles,
                        })

                result["valid_nsx_projects"] = valid_nsx_projects
                if valid_nsx_projects:
                    result["nsx_project_path"] = valid_nsx_projects[0]["path"]
                    if valid_nsx_projects[0]["valid_vpc_profiles"]:
                        result["vpc_connectivity_profile_path"] = \
                            valid_nsx_projects[0]["valid_vpc_profiles"][0]["path"]
            except Exception:
                result["valid_nsx_projects"] = []

        # ── Node defaults (port group, gateway, DNS, NTP from VNA/Edge ETN) ──
        try:
            _ep = ("/policy/api/v1/infra/sites/default"
                   "/enforcement-points/default")

            # Collect VNA ETN IDs from all VNA clusters
            _vna_etn_ids: set = set()
            _vna_clusters = nsx_get(nsx_url, nsx_user, nsx_pass,
                f"{_ep}/virtual-network-appliance-clusters")
            for _vc in (_vna_clusters or {}).get("results", []):
                for _m in _vc.get("members", []):
                    _etn_id = (_m.get("edge_transport_node_path") or "").rstrip("/").split("/")[-1]
                    if _etn_id:
                        _vna_etn_ids.add(_etn_id)

            # List all Policy ETNs
            _all_etns = (nsx_get(nsx_url, nsx_user, nsx_pass,
                f"{_ep}/edge-transport-nodes") or {}).get("results", [])

            # portgroup id → name map from already-fetched port_groups
            _pg_map = {pg.get("network", ""): pg.get("name", pg.get("network", ""))
                       for pg in result.get("port_groups", [])}

            def _etn_defaults(etn_id):
                """Fetch a Policy ETN and extract management network info."""
                _etn = nsx_get(nsx_url, nsx_user, nsx_pass,
                    f"{_ep}/edge-transport-nodes/{etn_id}")
                if not _etn:
                    return None
                _mi = _etn.get("management_interface", {})
                _pg_id = _mi.get("network_id", "")
                _specs = (_mi.get("ip_assignment_specs") or [{}])[0]
                _gw    = (_specs.get("default_gateway") or [""])[0]
                _snets = _specs.get("management_port_subnets") or [{}]
                _pfx   = (_snets[0] if _snets else {}).get("prefix_length", 24)
                _host  = _etn.get("hostname", "")
                _parts = _host.split(".")
                _domain = ".".join(_parts[1:]) if len(_parts) > 1 else ""
                # Try to get the VLAN ID for this port group from the SOAP batch dict
                _etn_vlan_id = _dvpg_vlans.get(_pg_id) if _pg_id else None
                return {
                    "pg_id":       _pg_id,
                    "pg_name":     _pg_map.get(_pg_id, _pg_id),
                    "gateway_cidr": f"{_gw}/{_pfx}" if _gw else "",
                    "search_domain": _domain,
                    "vlan_id":     _etn_vlan_id,
                }

            # Shared DNS/NTP from NSX manager
            _dns_r  = nsx_get(nsx_url, nsx_user, nsx_pass, "/api/v1/node/network/name-servers")
            _nsx_dns = (_dns_r.get("name_servers") if _dns_r else []) or []
            _ntp_r  = nsx_get(nsx_url, nsx_user, nsx_pass, "/api/v1/node/services/ntp")
            _nsx_ntp = ((_ntp_r.get("service_properties") or {}).get("servers")
                        if _ntp_r else []) or []

            _nd: dict = {}

            # Distributed: first VNA ETN
            _vna_etn = next((e for e in _all_etns if e.get("id") in _vna_etn_ids), None)
            if _vna_etn:
                _d = _etn_defaults(_vna_etn["id"])
                if _d:
                    _d["dns"] = _nsx_dns
                    _d["ntp"] = _nsx_ntp
                    _nd["distributed"] = _d

            # Centralized: first ETN NOT in any VNA cluster
            _cent_etn = next((e for e in _all_etns if e.get("id") not in _vna_etn_ids), None)
            if _cent_etn:
                _d = _etn_defaults(_cent_etn["id"])
                if _d:
                    _d["dns"] = _nsx_dns
                    _d["ntp"] = _nsx_ntp
                    _nd["centralized"] = _d

            result["node_defaults"] = _nd
        except Exception:
            result["node_defaults"] = {}

    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result["error"] = str(e)

    return jsonify(result)


@app.route("/api/storage-policies-for-cluster", methods=["POST"])
def storage_policies_for_cluster():
    """Return storage policies compatible with ALL selected clusters.

    1. Collect the ESX hosts of every selected cluster.
    2. Work out which datastores each host can access.
    3. Work out which policies are compatible with each datastore
       (REST filter.datastores if supported, otherwise PBM SOAP — the same
       source as the vSphere Client's "Storage Compatibility" tab).
    4. Keep a policy only if EVERY host has at least one compatible datastore.

    Notes on this vCenter family: REST filter.clusters / filter.datastores
    return HTTP 400 and filter.hosts is silently ignored, so each is probed at
    most once and abandoned on the first failure.
    """
    body           = request.get_json(force=True)
    vc_url         = normalize_url(body.get("vc_url", ""))
    username       = body.get("username", "")
    password       = body.get("password", "")
    cluster_moref  = body.get("cluster_moref", "")
    cluster_morefs = body.get("cluster_morefs") or ([cluster_moref] if cluster_moref else [])
    result         = {"policies": [], "error": None}
    try:
        token, _ = vc_auth(vc_url, username, password)
        all_policies = vc_get(vc_url, token, "/api/vcenter/storage/policies") or []

        if not cluster_morefs:
            result["policies"] = all_policies
            return jsonify(result)

        # ── Step 1: hosts of every selected cluster (one call per cluster) ──
        all_host_ids: list = []
        for c_id in cluster_morefs:
            for h in vc_get(vc_url, token, "/api/vcenter/host",
                            params={"clusters": c_id}) or []:
                hid = h.get("host", "")
                if hid and hid not in all_host_ids:
                    all_host_ids.append(hid)
        if not all_host_ids:
            result["policies"] = all_policies
            return jsonify(result)

        # ── Step 2: host → datastores, datastore summaries (type/capacity) ──
        ds_summary: dict = {}      # datastore_id → summary dict from the list API
        try:
            for d in vc_get(vc_url, token, "/api/vcenter/datastore") or []:
                if d.get("datastore"):
                    ds_summary[d["datastore"]] = d
        except Exception:
            pass

        host_ds_map: dict = {}     # host_id → set(datastore_id)
        all_ds_ids:  set  = set()

        # Preferred: REST filter.clusters (all-or-nothing; abandoned on 1st failure)
        _tmp_map: dict = {}
        _tmp_ds:  set  = set()
        try:
            for c_id in cluster_morefs:
                _lst = vc_get(vc_url, token, "/api/vcenter/datastore",
                              params={"filter.clusters": c_id}) or []
                _c_ds = {d.get("datastore") for d in _lst if d.get("datastore")} \
                    if isinstance(_lst, list) else set()
                if not _c_ds:
                    continue
                for d in _lst:
                    if d.get("datastore"):
                        ds_summary.setdefault(d["datastore"], d)
                for h in vc_get(vc_url, token, "/api/vcenter/host",
                                params={"clusters": c_id}) or []:
                    if h.get("host"):
                        _tmp_map.setdefault(h["host"], set()).update(_c_ds)
                _tmp_ds |= _c_ds
            host_ds_map, all_ds_ids = _tmp_map, _tmp_ds
        except Exception:
            pass                   # unsupported → SOAP below

        # Fallback: SOAP PropertyCollector (host → datastores, exact)
        if not all_ds_ids:
            _soap_map = _soap_get_host_datastores(vc_url, username, password, all_host_ids)
            if _soap_map:
                host_ds_map = {h: set(s) for h, s in _soap_map.items()}
                all_ds_ids  = set().union(*host_ds_map.values())

        if not all_ds_ids:
            result["policies"] = all_policies
            return jsonify(result)

        # Capacity / type for datastores missing from the list API (rare)
        for ds_id in all_ds_ids:
            if ds_id not in ds_summary:
                try:
                    _di = vc_get(vc_url, token, f"/api/vcenter/datastore/{ds_id}")
                    if isinstance(_di, dict):
                        ds_summary[ds_id] = _di
                except Exception:
                    pass

        def _cap(ds_id: str) -> tuple:
            d = ds_summary.get(ds_id, {})
            free = d.get("free_space", 0) or 0
            return (d.get("capacity", 0) or free), free

        # ── Step 3: datastore → compatible policy ids ───────────────────────
        ds_to_policy_ids: dict = {}
        for ds_id in sorted(all_ds_ids):
            try:
                pols = vc_get(vc_url, token, "/api/vcenter/storage/policies",
                              params={"filter.datastores": ds_id}) or []
            except Exception:
                break              # unsupported on this vCenter: don't hammer it
            ds_to_policy_ids[ds_id] = {p.get("policy", "") for p in pols if p.get("policy")}
        rest_filter_ok = any(ds_to_policy_ids.values())

        pbm_used = False
        if not rest_filter_ok:
            _all_pids = {p.get("policy", "") for p in all_policies if p.get("policy")}
            _pbm = _pbm_policy_ds_compat(vc_url, username, password,
                                         sorted(_all_pids), sorted(all_ds_ids))
            if _pbm is not None:
                pbm_used = True
                ds_to_policy_ids = {d: {pid for pid, dss in _pbm.items() if d in dss}
                                    for d in all_ds_ids}
            else:   # last resort: assume everything is compatible with everything
                ds_to_policy_ids = {d: set(_all_pids) for d in all_ds_ids}

        # ── Step 4: invert → policy → compatible datastores ─────────────────
        policy_compat_ds: dict = {}
        for ds_id, pol_ids in ds_to_policy_ids.items():
            for pid in pol_ids:
                policy_compat_ds.setdefault(pid, set()).add(ds_id)

        # ── Step 5: name-based filters ──────────────────────────────────────
        # Policies named after a cluster that is NOT selected are dropped.
        _other_cluster_names: set = set()
        _selected_cluster_names: set = set()
        try:
            for _c in vc_get(vc_url, token, "/api/vcenter/cluster") or []:
                _cname = (_c.get("name") or "").lower().strip()
                if not _cname:
                    continue
                (_selected_cluster_names if _c.get("cluster") in cluster_morefs
                 else _other_cluster_names).add(_cname)
        except Exception:
            pass

        # Capability heuristics (vvol / pmem / stretched / ESA in the policy
        # name) are ALWAYS applied: PBM reports e.g. "vSAN ESA ..." or
        # "... Stretched" policies as compatible with any vSAN datastore.
        has_vvol = has_pmem = is_stretched = is_esa = False
        have_real_compat = pbm_used or rest_filter_ok
        _types = {str(ds_summary.get(d, {}).get("type", "")).upper() for d in all_ds_ids}
        has_vvol = "VVOL" in _types
        has_pmem = bool(_types & {"PMEM", "PERSISTENTMEMORY"})
        _vsan_rest = True
        for c_id in cluster_morefs:
            if not _vsan_rest:
                break
            _got = False
            for _ep in (f"/api/vcenter/vsan/cluster/{c_id}/config",
                        f"/api/vcenter/vsan/config/{c_id}"):
                try:
                    _cfg = vc_get(vc_url, token, _ep)
                except Exception:
                    continue
                if isinstance(_cfg, dict):
                    _got = True
                    if _cfg.get("stretched_cluster") or _cfg.get("is_stretched"):
                        is_stretched = True
                    _st = str(_cfg.get("storage_type", "") or "").upper()
                    if "ESA" in _st or "EXPRESS" in _st:
                        is_esa = True
                    break
            if not _got:
                _vsan_rest = False     # endpoints absent (404): stop probing

        def _policy_applicable(p: dict) -> bool:
            n = p.get("name", "").lower()
            if any(_ocn and _ocn in n for _ocn in _other_cluster_names):
                return False
            if "vvol"      in n and not has_vvol:     return False
            if "pmem"      in n and not has_pmem:     return False
            if "stretched" in n and not is_stretched: return False
            if "esa"       in n and not is_esa and "stretched" not in n: return False
            # Without real compatibility data (PBM and REST both unavailable),
            # a policy named after one of several selected clusters is treated
            # as cluster-specific → drop it.  With real data the all_covered
            # check below is exact, so this rule must NOT apply.
            if (not have_real_compat and len(cluster_morefs) > 1 and
                    any(_scn and _scn in n for _scn in _selected_cluster_names)):
                return False
            return True

        # ── Step 6: keep policies where EVERY host has ≥1 compatible ds ─────
        valid_policies = []
        for p in all_policies:
            pid = p.get("policy", "")
            if not pid or not _policy_applicable(p):
                continue
            compat_ds = policy_compat_ds.get(pid, set())
            if not compat_ds:
                continue
            if all(host_ds_map.get(h_id, set()) & compat_ds for h_id in all_host_ids):
                p_out = dict(p)
                total_cap  = sum(_cap(d)[0] for d in compat_ds)
                total_free = sum(_cap(d)[1] for d in compat_ds)
                if total_cap > 0 or total_free > 0:
                    p_out["total_capacity"] = total_cap
                    p_out["free_space"]     = total_free
                valid_policies.append(p_out)

        result["policies"] = valid_policies

    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
        result["policies"] = []
    except Exception as e:
        result["error"] = str(e)
        result["policies"] = []
    return jsonify(result)


@app.route("/api/wcp-datacenter", methods=["POST"])
def wcp_datacenter():
    """Name of the vCenter datacenter that holds the given clusters.
    Needed for the vCenter-native Supervisor config export (vcenterDatacenter)."""
    body     = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    morefs   = {m for m in (body.get("cluster_morefs") or []) if m}
    try:
        token, _ = vc_auth(vc_url, username, password)
        dcs = vc_get(vc_url, token, "/api/vcenter/datacenter") or []
        name = ""
        if len(dcs) == 1:
            name = dcs[0].get("name", "")
        else:
            for dc in dcs:
                cl = []
                for _p in ({"datacenters": dc.get("datacenter")},
                           {"filter.datacenters": dc.get("datacenter")}):
                    try:
                        cl = vc_get(vc_url, token, "/api/vcenter/cluster", params=_p) or []
                        break
                    except Exception:
                        continue
                if any(c.get("cluster") in morefs for c in cl):
                    name = dc.get("name", "")
                    break
        return jsonify({"datacenter": name, "error": None})
    except Exception as e:
        return jsonify({"datacenter": "", "error": str(e)})


@app.route("/api/install-supervisor", methods=["POST"])
def install_supervisor():
    """Enable Supervisor using the NSX VPC (enable_on_zones) API."""
    body = request.get_json(force=True)
    vc_url = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    cfg = body.get("config", {})

    result = {"success": False, "supervisor_id": None, "error": None}

    def _list(val):
        if isinstance(val, list):
            return [str(v).strip() for v in val if str(v).strip()]
        return [v.strip() for v in str(val).split(",") if v.strip()]

    try:
        token, _ = vc_auth(vc_url, username, password)

        # Sanitise first_ip — if user typed "10.1.1.85-10.1.1.89" take only the first IP
        raw_first_ip = str(cfg.get("first_ip", "")).strip()
        if "-" in raw_first_ip:
            raw_first_ip = raw_first_ip.split("-")[0].strip()
        cfg["first_ip"] = raw_first_ip

        dns_mgmt     = _list(cfg.get("dns_servers", ""))
        dns_workload = _list(cfg.get("dns_servers_workload", "")) or dns_mgmt
        ntp          = _list(cfg.get("ntp_servers", ""))
        domains      = _list(cfg.get("search_domains", ""))

        # ── Zone resolution: create zones if clusters are not yet in a zone ──────
        # Case A: pre-existing zones explicitly selected (selected_zones list)
        _placement_mode = cfg.get("placement_mode", "multiple")
        if cfg.get("selected_zones") and len(cfg["selected_zones"]) > 0:
            _zones = cfg["selected_zones"]

        # Case B: clusters NOT yet in a zone → create zones + associate, then deploy
        elif not cfg.get("zone_id") and cfg.get("selected_clusters"):
            _sel_clusters = cfg["selected_clusters"]
            _zone_prefix  = (cfg.get("zone_prefix") or "tool-zone").strip() or "tool-zone"

            if _placement_mode == "multiple":
                # One zone per cluster (HA across zones)
                _zones = []
                for _i, _sc in enumerate(_sel_clusters, 1):
                    _cmoref    = _sc["cluster"] if isinstance(_sc, dict) else _sc
                    _zone_name = f"{_zone_prefix}{_i}"
                    # 1. Create zone
                    _zr = SESS.post(
                        f"{vc_url}/api/vcenter/consumption-domains/zones",
                        headers={"vmware-api-session-id": token,
                                 "Content-Type": "application/json"},
                        json={"zone": _zone_name},
                        verify=False, timeout=30,
                    )
                    if not _zr.ok:
                        raise ValueError(
                            f"Failed to create zone '{_zone_name}': "
                            f"HTTP {_zr.status_code}: {_zr.text[:300]}"
                        )
                    _zid = _zone_name   # zone name IS the zone identifier
                    # 2. Associate cluster → zone via vapi JSON-RPC
                    _vapi_zone_cluster_add(vc_url, token, _zone_name, _cmoref)
                    _zones.append(_zid)
            else:
                # single_specific / single_least: one shared zone, all clusters in it
                _zone_name = f"{_zone_prefix}1"
                _zr = SESS.post(
                    f"{vc_url}/api/vcenter/consumption-domains/zones",
                    headers={"vmware-api-session-id": token,
                             "Content-Type": "application/json"},
                    json={"zone": _zone_name},
                    verify=False, timeout=30,
                )
                if not _zr.ok:
                    raise ValueError(
                        f"Failed to create zone '{_zone_name}': "
                        f"HTTP {_zr.status_code}: {_zr.text[:300]}"
                    )
                _zid = _zone_name   # zone name IS the zone identifier
                # Associate each cluster → zone via vapi JSON-RPC
                for _sc in _sel_clusters:
                    _cmoref = _sc["cluster"] if isinstance(_sc, dict) else _sc
                    _vapi_zone_cluster_add(vc_url, token, _zone_name, _cmoref)
                _zones = [_zid]

        # Case C: single pre-existing zone_id
        elif cfg.get("zone_id"):
            _zones = [cfg["zone_id"]]

        # Case D: last-resort fallback (single-cluster legacy path)
        else:
            _zones = [cfg.get("cluster_moref", "")]

        # ── Management network backing ──────────────────────────────────────
        # Each selected cluster may have its OWN port group (e.g. one VDS per
        # cluster, all on the same VLAN).  A single NETWORK backing would have
        # to exist in every zone ("No portgroup backing given Network Segment
        # dvportgroup-N is available on any cluster in the zone ...").  The
        # API (8.0.3+) accepts a NETWORK_SEGMENT = list of port groups that are
        # part of the same layer-2 broadcast domain, one per cluster.
        _cpg_map = cfg.get("cluster_port_groups") or {}
        _sel_c = {(_c["cluster"] if isinstance(_c, dict) else _c)
                  for _c in (cfg.get("selected_clusters") or [])}
        if cfg.get("cluster_moref"):
            _sel_c.add(cfg["cluster_moref"])
        _pg_list: list = []
        for _pg in [cfg.get("port_group_id")] + [
                _v for _k, _v in _cpg_map.items() if not _sel_c or _k in _sel_c]:
            if _pg and _pg not in _pg_list:
                _pg_list.append(_pg)
        if len(_pg_list) > 1:
            _mgmt_backing = {"backing": "NETWORK_SEGMENT",
                             "network_segment": {"networks": _pg_list}}
        else:
            _mgmt_backing = {"backing": "NETWORK", "network": cfg["port_group_id"]}

        spec = {
            "name": cfg["name"],
            "zones": _zones,
            "control_plane": {
                "size": cfg.get("size", "SMALL"),
                "cpvmCount": 3 if cfg.get("ha_mode", True) else 1,
                "storage_policy": cfg.get("ctrl_plane_policy_uuid") or cfg["storage_policy_uuid"],
                "network": {
                    "backing": _mgmt_backing,
                    "services": {
                        "dns": {"servers": dns_mgmt, "search_domains": domains},
                        "ntp": {"servers": ntp},
                    },
                    "ip_management": {
                        "dhcp_enabled": False,
                        "gateway_address": cfg["gateway_cidr"],
                        "ip_assignments": [
                            {
                                "assignee": "NODE",
                                "ranges": [{"address": cfg["first_ip"], "count": 5}],
                            }
                        ],
                    },
                },
            },
            "workloads": {
                "network": {
                    "network_type": "NSX_VPC",
                    "nsx_vpc": {
                        "nsx_project": cfg.get(
                            "nsx_project_path", "/orgs/default/projects/default"
                        ),
                        "vpc_connectivity_profile": cfg.get(
                            "vpc_connectivity_profile_path",
                            "/orgs/default/projects/default/vpc-connectivity-profiles/default",
                        ),
                        "default_private_cidrs": [{"address": cfg.get("private_workload_cidr", "172.30.0.0/16").split("/")[0],
                                                    "prefix": int(cfg.get("private_workload_cidr", "172.30.0.0/16").split("/")[-1])}],
                    },
                    "services": {
                        "dns": {"servers": dns_workload, "search_domains": domains},
                        "ntp": {"servers": ntp},
                    },
                    "ip_management": {
                        "dhcp_enabled": False,
                        "ip_assignments": [
                            {
                                "assignee": "SERVICE",
                                "ranges": [{"address": cfg.get("service_cidr", "10.96.0.0/12").split("/")[0],
                                            "count": 2 ** (32 - int(cfg.get("service_cidr", "10.96.0.0/12").split("/")[-1]))}],
                            }
                        ],
                    },
                },
                "edge": {"provider": "NSX", "nsx": {"routing_mode": "NO_NAT"}},
                "storage": {
                    "ephemeral_storage_policy": cfg.get("ephemeral_policy_uuid") or cfg["storage_policy_uuid"],
                    "image_storage_policy":     cfg.get("image_cache_policy_uuid") or cfg["storage_policy_uuid"],
                },
            },
        }

        resp = SESS.post(
            f"{vc_url}/api/vcenter/namespace-management/supervisors?action=enable_on_zones",
            headers={
                "vmware-api-session-id": token,
                "Content-Type": "application/json",
            },
            json=spec,
            timeout=30,
        )

        if resp.ok:
            result.update(success=True, supervisor_id=resp.json())
        else:
            msgs = ""
            try:
                msgs = "; ".join(
                    m.get("default_message", "")
                    for m in (resp.json().get("messages") or [])
                )
            except Exception:
                pass
            result["error"] = f"HTTP {resp.status_code}: {msgs or resp.text[:500]}"

    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:500]}"
    except Exception as e:
        result["error"] = traceback.format_exc()

    return jsonify(result)


@app.route("/api/vks-clusters", methods=["POST"])
def vks_clusters():
    """List VKS (TKG) clusters deployed under the Supervisor via the supervisor K8s API."""
    body        = request.get_json(force=True)
    vc_url      = normalize_url(body.get("vc_url", ""))
    username    = body.get("username", "")
    password    = body.get("password", "")
    # Supervisor SSO credentials may differ from vCenter (e.g. administrator@wld.sso)
    sup_user    = body.get("sup_username") or username
    sup_pass    = body.get("sup_password") or password

    result = {"success": False, "supervisor_vip": None, "clusters": [],
              "namespaces": [], "error": None}
    try:
        # ── 1. Authenticate to vCenter ─────────────────────────────────────
        token, _ = vc_auth(vc_url, username, password)

        # ── 2. Collect ALL supervisor control-plane VIPs (one per cluster) ──
        sup_clusters = vc_get(vc_url, token,
                              "/api/vcenter/namespace-management/clusters") or []
        supervisor_vips = []
        for c in sup_clusters:
            cid = c.get("cluster")
            if not cid:
                continue
            detail = vc_get(vc_url, token,
                            f"/api/vcenter/namespace-management/clusters/{cid}") or {}
            ep = detail.get("api_server_cluster_endpoint", "")
            if ep and ep not in supervisor_vips:
                supervisor_vips.append(ep)

        if not supervisor_vips:
            raise RuntimeError(
                "Could not determine the Supervisor control-plane VIP. "
                "Make sure the Supervisor is fully installed (RUNNING).")

        # For backward-compat keep single-VIP fields; also expose full list
        result["supervisor_vip"]  = supervisor_vips[0]
        result["supervisor_vips"] = supervisor_vips

        # ── 3 + 4. For each VIP: login → list CAPI clusters ────────────────
        all_clusters   = []
        login_errors   = []
        for supervisor_vip in supervisor_vips:
            try:
                s = requests.Session()
                s.verify = False
                login_r = s.post(f"https://{supervisor_vip}/wcp/login",
                                 auth=(sup_user, sup_pass),
                                 timeout=15)
                if login_r.status_code not in (200, 204):
                    login_errors.append(
                        f"Supervisor {supervisor_vip}: login failed "
                        f"(HTTP {login_r.status_code}). "
                        f"Credentials used: {sup_user}. "
                        "The Supervisor may use a different SSO domain "
                        "(e.g. administrator@wld.sso).")
                    continue
                k8s_token = login_r.json().get("session_id", "")
                if not k8s_token:
                    login_errors.append(
                        f"Supervisor {supervisor_vip}: login succeeded "
                        "but returned no session_id.")
                    continue

                k8s_headers = {"Authorization": f"Bearer {k8s_token}",
                               "Accept": "application/json"}

                capi_r = s.get(f"https://{supervisor_vip}:6443"
                               f"/apis/cluster.x-k8s.io/v1beta1/clusters",
                               headers=k8s_headers, timeout=20)
                capi_r.raise_for_status()
                items = capi_r.json().get("items", [])

                for item in items:
                    meta   = item.get("metadata", {})
                    spec   = item.get("spec", {})
                    status = item.get("status", {})
                    cp_ep  = spec.get("controlPlaneEndpoint", {})
                    k8s_ver = (spec.get("topology", {}).get("version")
                               or spec.get("version")
                               or status.get("controlPlane", {}).get("version", ""))
                    workers = (spec.get("topology", {}).get("workers", {})
                                       .get("machineDeployments", []))
                    worker_count = sum(
                        (md.get("replicas") or 0) for md in workers
                    ) if workers else status.get("replicas", 0)
                    all_clusters.append({
                        "name":               meta.get("name", ""),
                        "namespace":          meta.get("namespace", ""),
                        "phase":              status.get("phase", "Unknown"),
                        "control_plane_vip":  cp_ep.get("host", ""),
                        "kubernetes_version": k8s_ver,
                        "cp_ready":           status.get("controlPlaneReady", False),
                        "infra_ready":        status.get("infrastructureReady", False),
                        "worker_replicas":    worker_count,
                        "created":            meta.get("creationTimestamp", ""),
                        "supervisor_vip":     supervisor_vip,   # which Supervisor
                    })
            except Exception as _vip_exc:
                login_errors.append(
                    f"Supervisor {supervisor_vip}: {_vip_exc}")

        result["clusters"] = all_clusters
        # Surface per-VIP errors only when nothing was fetched at all
        if login_errors and not all_clusters:
            raise RuntimeError(" | ".join(login_errors))

        # ── 5. Namespace list from vCenter for context ─────────────────────
        ns_list = vc_get(vc_url, token, "/api/vcenter/namespaces/instances") or []
        result["namespaces"] = [
            {"name": ns.get("namespace", ""),
             "config_status": ns.get("config_status", "")}
            for ns in ns_list
        ]

        result["success"] = True

    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result["error"] = str(e)

    return jsonify(result)


# ── Pure-Python Kubernetes WebSocket exec (no external deps) ──────────────────

def _k8s_ws_exec(host, port, token, namespace, pod_name, command,
                  timeout=12, ssl_ctx=None):
    """
    Execute *command* (list of strings) inside a Kubernetes pod via the
    WebSocket exec API.  Uses only Python stdlib (ssl + socket).
    Returns (stdout_str, stderr_str, error_str).
    """
    import ssl as _ssl
    import socket as _sock
    import struct as _struct
    import base64 as _b64
    import os as _os
    from urllib.parse import quote as _q

    cmd_qs = "&".join(f"command={_q(str(c), safe='')}" for c in command)
    path   = (f"/api/v1/namespaces/{namespace}/pods/{pod_name}/exec"
              f"?{cmd_qs}&stdout=1&stderr=1&stdin=0&tty=0")

    key = _b64.b64encode(_os.urandom(16)).decode()
    if token:
        auth_hdr = f"Authorization: Bearer {token}\r\n"
    else:
        auth_hdr = ""
    handshake = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Protocol: v4.channel.k8s.io\r\n"
        f"{auth_hdr}"
        f"\r\n"
    ).encode()

    if ssl_ctx is None:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
    else:
        ctx = ssl_ctx

    raw  = _sock.create_connection((host, int(port)), timeout=timeout)
    wsock = ctx.wrap_socket(raw, server_hostname=host)
    wsock.settimeout(timeout)

    try:
        wsock.sendall(handshake)

        # Read HTTP upgrade response
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = wsock.recv(4096)
            if not chunk:
                raise RuntimeError("Connection closed during WebSocket upgrade")
            buf += chunk
        status_line = buf.split(b"\r\n", 1)[0].decode(errors="replace")
        if "101" not in status_line:
            # Pull any body for better error context
            raise RuntimeError(f"K8s exec upgrade failed: {status_line}")

        stdout_b = b""
        stderr_b = b""
        error_b  = b""
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                # Read 2-byte frame header
                hdr = b""
                while len(hdr) < 2:
                    c = wsock.recv(2 - len(hdr))
                    if not c:
                        return (stdout_b.decode("utf-8", errors="replace"),
                                stderr_b.decode("utf-8", errors="replace"),
                                error_b.decode("utf-8", errors="replace"))
                    hdr += c

                opcode  = hdr[0] & 0x0F
                masked  = (hdr[1] & 0x80) != 0
                plen    = hdr[1] & 0x7F

                if plen == 126:
                    ext = b""
                    while len(ext) < 2:
                        ext += wsock.recv(2 - len(ext))
                    plen = _struct.unpack(">H", ext)[0]
                elif plen == 127:
                    ext = b""
                    while len(ext) < 8:
                        ext += wsock.recv(8 - len(ext))
                    plen = _struct.unpack(">Q", ext)[0]

                mask_key = b""
                if masked:
                    while len(mask_key) < 4:
                        mask_key += wsock.recv(4 - len(mask_key))

                payload = b""
                while len(payload) < plen:
                    chunk = wsock.recv(min(4096, plen - len(payload)))
                    if not chunk:
                        break
                    payload += chunk

                if masked:
                    payload = bytes(b ^ mask_key[i % 4]
                                    for i, b in enumerate(payload))

                if opcode == 8:   # close frame
                    break

                if not payload:
                    continue

                channel = payload[0]
                data    = payload[1:]

                if channel == 1:
                    stdout_b += data
                elif channel == 2:
                    stderr_b += data
                elif channel == 3:
                    error_b  += data
                    # status channel signals end of exec
                    if (b'"status":"Success"' in error_b
                            or b'"status":"Failure"' in error_b):
                        break

            except _ssl.SSLWantReadError:
                time.sleep(0.05)
            except (_sock.timeout, OSError):
                break

        return (stdout_b.decode("utf-8", errors="replace"),
                stderr_b.decode("utf-8", errors="replace"),
                error_b.decode("utf-8", errors="replace"))
    finally:
        try:
            wsock.close()
        except Exception:
            pass


def _k8s_find_exec_pod(api_base, headers, hint_namespaces=None,
                       host_network_only=True, ssl_ctx=None, req_cert=None):
    """
    Find a Running pod that responds to K8s exec AND has at least one
    network-testing tool (nc, python3, curl, wget, or bash).

    req_cert: tuple (cert_path, key_path) forwarded to requests.get for
              clusters that use client-certificate authentication.

    Returns (namespace, pod_name, tool_available) or (None, None, None).
    """
    h, p = (api_base.split(":", 1) if ":" in api_base else (api_base, "6443"))
    port = int(p)
    token = headers.get("Authorization", "").replace("Bearer ", "")

    _req_kw = dict(headers=headers, verify=False, timeout=10)
    if req_cert:
        _req_kw["cert"] = req_cert

    # Fetch all namespace names
    namespaces = hint_namespaces or []
    try:
        ns_r = requests.get(f"https://{h}:{port}/api/v1/namespaces", **_req_kw)
        if ns_r.ok:
            namespaces = [n["metadata"]["name"]
                          for n in ns_r.json().get("items", [])]
    except Exception:
        pass
    if not namespaces:
        namespaces = ["kube-system", "vmware-system-nsx", "vmware-system-csi"]

    # Preferred pod-name prefixes (DaemonSets / node agents are most likely to have tools)
    _PREFER = ["antrea-agent", "vsphere-csi-node",
               "node-exporter", "calico-node", "cilium", "flannel", "nsx-node-agent"]
    # Avoid known tool-less control-plane containers AND kube-proxy:
    # kube-proxy manages iptables DNAT/MASQUERADE rules; raw socket probes run
    # inside its container (hostNetwork) can be redirected by those very rules,
    # giving false TCP_FAIL results even when connectivity is fine.
    _AVOID  = ["antrea-controller", "coredns", "etcd-", "kube-apiserver",
               "kube-controller-manager", "kube-scheduler", "metrics-server",
               "kube-proxy"]

    # Quick-probe commands to confirm exec works + detect which tool is available
    # Each probe: (tool_name, command_list, success_test_fn(stdout, stderr, status))
    _PROBE_CMDS = [
        ("sh",      ["sh",   "-c", "echo _alive_"]),
        ("bash",    ["bash", "-c", "echo _alive_"]),
        # direct version checks — any output + Success status = tool present
        ("python3", ["python3", "--version"]),
        ("nc",      ["nc",      "--version"]),
        ("curl",    ["curl",    "--version"]),
        ("wget",    ["wget",    "--version"]),
    ]

    def _pod_score(pod):
        name = pod["metadata"]["name"].lower()
        hn   = pod.get("spec", {}).get("hostNetwork", False)
        if any(name.startswith(a) for a in _AVOID):
            return 99
        pref = any(name.startswith(pp) for pp in _PREFER)
        return (0 if pref else 1) * 10 + (0 if hn else 5)

    for ns in namespaces:
        try:
            pods_r = requests.get(
                f"https://{h}:{port}/api/v1/namespaces/{ns}/pods", **_req_kw)
            if not pods_r.ok:
                continue
            pods = pods_r.json().get("items", [])
        except Exception:
            continue

        pods = [pod for pod in pods
                if pod.get("status", {}).get("phase") == "Running"
                and (not host_network_only
                     or pod.get("spec", {}).get("hostNetwork", False))]
        pods.sort(key=_pod_score)

        for pod in pods:
            pod_name = pod["metadata"]["name"]
            for tool, cmd in _PROBE_CMDS:
                try:
                    stdout, stderr, status = _k8s_ws_exec(
                        h, port, token, ns, pod_name, cmd,
                        timeout=6, ssl_ctx=ssl_ctx
                    )
                    combined = stdout + stderr
                    ok = ("_alive_" in combined
                          or ('"status":"Success"' in status and tool not in ("sh", "bash"))
                          or (combined.strip() and "OCI" not in status
                              and "not found" not in combined.lower()))
                    if ok:
                        return ns, pod_name, tool
                except Exception:
                    pass

    return None, None, None


def _tcp_test_via_exec(api_base, headers, ns, pod_name, tool,
                       target_host, target_port, ssl_ctx=None):
    """
    Run a TCP connectivity test to target_host:target_port from inside
    the given pod.  Uses *tool* as first choice, then falls back.

    Returns {"ok": bool, "method_used": str, "output": str, "error": str|None}
    """
    import json as _json
    h, p = (api_base.split(":", 1) if ":" in api_base else (api_base, "6443"))
    port = int(p)
    token = headers.get("Authorization", "").replace("Bearer ", "")

    # Probe tiers:
    #   Tier-1 (reliable — trust both success AND failure): python3
    #   Tier-2 (somewhat reliable, but nc exit-code can be misleading): curl, wget
    #   Tier-3 (nc — known to give false negatives in some VMware containers):
    #           try all nc variants, but on failure keep going to Tier-2
    #   Tier-4 (shell-wrapped, needs sh/bash)
    #
    # Strategy: on Tier-3 failure don't stop — keep trying until a Tier-1/2 probe
    # confirms the result.  This avoids the false-negative seen when nc says FAIL
    # but curl confirms 403 (= TCP/TLS works).

    tier1 = [
        ("python3", ["python3", "-c",
                     f"import socket,sys; s=socket.socket(); s.settimeout(3); "
                     f"r=s.connect_ex(('{target_host}',{target_port})); sys.exit(r)"]),
    ]
    tier2 = [
        ("curl",  ["curl", "-sk", "--max-time", "3", "--connect-timeout", "3",
                   f"https://{target_host}:{target_port}/healthz"]),
        ("wget",  ["wget", "-qT3", "--no-check-certificate", "-O", "/dev/null",
                   f"https://{target_host}:{target_port}/healthz"]),
    ]
    tier3_nc = [
        ("nc",    ["nc", "-z", "-w", "3", target_host, str(target_port)]),
        ("nc-v2", ["nc", "-z", "-w3",     target_host, str(target_port)]),
        ("nc-v3", ["nc", "-zw3",           target_host, str(target_port)]),
        ("nc-v4", ["nc", "-z",             target_host, str(target_port)]),
    ]
    tier4 = [
        # sh+curl first — most reliable (HTTP 4xx = TCP OK; exit 7 = can't connect;
        # exit 127 = curl missing → print CURL_MISSING so we can skip)
        ("sh+curl",      ["sh", "-c",
            f"type curl >/dev/null 2>&1 || {{ echo CURL_MISSING; exit 0; }}; "
            f"curl -sk --max-time 5 https://{target_host}:{target_port}/healthz "
            f">/dev/null 2>&1; c=$?; "
            f"if [ $c -eq 7 ] || [ $c -eq 6 ]; then echo TCP_FAIL; else echo TCP_OK; fi"]),
        # bash /dev/tcp — lightweight, no external tools needed
        ("bash/dev/tcp", ["bash", "-c",
            f"timeout 3 bash -c 'echo >/dev/tcp/{target_host}/{target_port}' "
            f"2>/dev/null && echo TCP_OK || echo TCP_FAIL"]),
        # sh+python3 — reliable socket test, try after curl/bash
        ("sh+python3",   ["sh", "-c",
            f"type python3 >/dev/null 2>&1 || {{ echo PYTHON3_MISSING; exit 0; }}; "
            f"python3 -c \"import socket; s=socket.socket(); s.settimeout(5);"
            f"r=s.connect_ex(('{target_host}',{target_port}));"
            f"print('TCP_OK' if r==0 else 'TCP_FAIL')\""]),
        ("sh+nc",        ["sh", "-c",
            f"nc -z -w 3 {target_host} {target_port} 2>/dev/null "
            f"&& echo TCP_OK || echo TCP_FAIL"]),
    ]

    # Re-order Tier-1 to put the known-working tool first
    if tool in ("python3",):
        order = tier1 + tier2 + tier3_nc + tier4
    elif tool in ("curl", "wget"):
        order = tier2 + tier1 + tier3_nc + tier4
    else:
        # tool is nc, sh, bash — still try python3/curl first for reliability
        order = tier1 + tier2 + tier3_nc + tier4

    nc_failed = False   # track nc failure so we can continue to curl
    shell_fail_method = None
    shell_fail_output = ""

    for method, cmd in order:
        try:
            stdout, stderr, status = _k8s_ws_exec(
                h, port, token, ns, pod_name, cmd,
                timeout=12, ssl_ctx=ssl_ctx
            )
            combined = (stdout + stderr).strip()

            # ── Shell-wrapped: look for explicit marker ───────────────────
            if "CURL_MISSING" in combined or "PYTHON3_MISSING" in combined:
                continue   # tool not in this container — try next probe
            if "TCP_OK" in combined:
                return {"ok": True,
                        "method_used": method, "output": combined[:120], "error": None}
            if "TCP_FAIL" in combined:
                # Don't return immediately — continue to next probe to confirm.
                # A later TCP_OK from curl/bash overrides this.
                shell_fail_method = method
                shell_fail_output = combined[:120]
                continue

            # ── Direct binary: use K8s exit-code status ───────────────────
            if '"status":"Success"' in status:
                # curl/wget success even on HTTP 4xx/5xx means TCP+TLS OK
                note = combined[:60] if combined else "TCP connected"
                return {"ok": True, "method_used": method,
                        "output": note, "error": None}

            if '"status":"Failure"' in status:
                try:
                    msg = _json.loads(status).get("message", "")
                except Exception:
                    msg = status

                # Command not found (126/127) or OCI error → try next probe
                if any(x in msg for x in ("126", "127", "not found", "OCI")):
                    continue

                # curl/wget: SSL errors mean TCP actually worked
                if method == "curl" and "exit code 60" in msg:
                    return {"ok": True, "method_used": method,
                            "output": "SSL cert error (TCP connected)", "error": None}
                if method == "wget" and "exit code 5" in msg:
                    return {"ok": True, "method_used": method,
                            "output": "SSL cert error (TCP connected)", "error": None}

                # nc bad flags → try next nc variant
                if method.startswith("nc") and any(x in msg for x in
                        ["invalid option", "usage", "unknown flag", "unrecognized",
                         "illegal option", "bad option"]):
                    continue

                # nc exit-1: may be a false negative — record it but keep going
                # to let curl/wget confirm.  Only Tier-1 (python3) is trusted here.
                if method.startswith("nc"):
                    nc_failed = True
                    continue   # ← do NOT return yet; try curl/wget first

                # Tier-1 (python3) confirmed failure — trust it
                if method == "python3":
                    return {"ok": False, "method_used": method,
                            "output": combined[:120],
                            "error": f"{target_host}:{target_port} not reachable from this node (python3 errno≠0)"}

                # Tier-2/4 confirmed failure
                return {"ok": False, "method_used": method,
                        "output": combined[:120],
                        "error": f"{target_host}:{target_port} not reachable from this node"}

        except Exception:
            continue

    # All probes exhausted
    if nc_failed and not shell_fail_method:
        return {"ok": False, "method_used": "nc",
                "output": "",
                "error": f"{target_host}:{target_port} not reachable from this node (confirmed by multiple nc variants)"}

    if shell_fail_method:
        return {"ok": False, "method_used": shell_fail_method,
                "output": shell_fail_output,
                "error": f"{target_host}:{target_port} not reachable from this node (confirmed by multiple probes)"}

    return {"ok": False, "method_used": "none", "output": "",
            "error": "No working probe command found in this container"}


@app.route("/api/connectivity-test", methods=["POST"])
def connectivity_test():
    """
    Tests network reachability for VKS communication paths.

    Group 1 — TCP from this server (app VM): always fast, always runs.
    Group 2 — From Supervisor Nodes → VKS VIP:6443
               Execs a TCP probe in a hostNetwork pod on each Supervisor node.
    Group 3 — From VKS Nodes → Supervisor VIP:6443
               Fetches VKS kubeconfig, finds hostNetwork pod in VKS cluster,
               execs a TCP probe there.
    """
    import socket as _sock
    import ssl as _ssl_m
    import base64 as _b64
    import tempfile as _tmp
    import json as _json

    def tcp_probe(host, port, timeout=5):
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(timeout)
            t0 = time.time()
            s.connect((str(host), int(port)))
            lat = int((time.time() - t0) * 1000)
            s.close()
            return {"ok": True, "latency_ms": lat}
        except _sock.timeout:
            return {"ok": False, "error": "Timeout (5 s)"}
        except ConnectionRefusedError:
            return {"ok": False, "error": "Connection refused"}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    body     = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    sup_user = body.get("sup_username") or username
    sup_pass = body.get("sup_password") or password
    # Optional: test only this VKS cluster
    target_ns   = body.get("cluster_namespace", "")
    target_name = body.get("cluster_name", "")
    target_vip  = body.get("cluster_vip", "")
    # Caller may pass the exact Supervisor VIP for the cluster under test
    # (avoids always picking the first Supervisor when there are multiple)
    hint_supervisor_vip = (body.get("supervisor_vip") or "").strip()

    out = {"success": False, "supervisor_vip": None, "server_ip": None,
           "groups": [], "error": None}

    try:
        # ── App-server outgoing IP ────────────────────────────────────────
        try:
            _s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            _s.connect(("8.8.8.8", 80))
            out["server_ip"] = _s.getsockname()[0]
            _s.close()
        except Exception:
            out["server_ip"] = "this server"
        server_label = f"This server ({out['server_ip']})"

        # ── Resolve Supervisor VIP ────────────────────────────────────────
        # Prefer the VIP passed by the caller (one per cluster in multi-supervisor
        # environments).  Fall back to vCenter discovery for backwards compat.
        if hint_supervisor_vip:
            supervisor_vip = hint_supervisor_vip
        else:
            vc_token, _ = vc_auth(vc_url, username, password)
            supervisor_vip = None
            for c in (vc_get(vc_url, vc_token,
                             "/api/vcenter/namespace-management/clusters") or []):
                cid = c.get("cluster", "")
                if not cid:
                    continue
                d = vc_get(vc_url, vc_token,
                           f"/api/vcenter/namespace-management/clusters/{cid}") or {}
                ep = d.get("api_server_cluster_endpoint", "")
                if ep:
                    supervisor_vip = ep
                    break
            if not supervisor_vip:
                raise RuntimeError("Could not determine Supervisor Control Plane VIP.")
        out["supervisor_vip"] = supervisor_vip

        # ── Supervisor K8s login ──────────────────────────────────────────
        _sess = requests.Session()
        _sess.verify = False
        lr = _sess.post(f"https://{supervisor_vip}/wcp/login",
                        auth=(sup_user, sup_pass), timeout=15)
        if lr.status_code not in (200, 204):
            raise RuntimeError(
                f"Supervisor login failed (HTTP {lr.status_code}). "
                f"Credentials: {sup_user}.")
        k8s_token = lr.json().get("session_id", "")
        sup_hdr   = {"Authorization": f"Bearer {k8s_token}",
                     "Accept": "application/json"}
        sup_base  = f"{supervisor_vip}:6443"

        # ── All CAPI clusters (filter if specific one requested) ──────────
        capi_r = _sess.get(f"https://{sup_base}/apis/cluster.x-k8s.io/v1beta1/clusters",
                           headers=sup_hdr, timeout=20)
        all_capi = capi_r.json().get("items", []) if capi_r.ok else []
        if target_name:
            capi_items = [c for c in all_capi
                          if c["metadata"]["name"] == target_name]
        else:
            capi_items = all_capi

        # NAT IPs optionally passed from frontend (from topology data)
        sup_vpc_nat = body.get('sup_vpc_nat', '') or ''
        vks_vpc_nat = body.get('vks_vpc_nat', '') or ''

        # ─── Group 1: TCP from app server ────────────────────────────────
        grp1 = {
            "id": "tcp",
            "title": f"{server_label} → Supervisor and VKS Control Plane VIP:6443",
            "subtitle": "Direct socket probe — source is the app server, not the Supervisor/VKS nodes",
            "rows": [],
        }
        grp1["rows"].append({
            "source": server_label,
            "destination": f"Supervisor VIP {supervisor_vip}:6443",
            "physical_traffic": f"{out['server_ip']} → {supervisor_vip}:6443",
            "method": "tcp", **tcp_probe(supervisor_vip, 6443),
        })
        for c in capi_items:
            vip  = target_vip or c.get("spec", {}).get("controlPlaneEndpoint", {}).get("host", "")
            port = c.get("spec", {}).get("controlPlaneEndpoint", {}).get("port", 6443)
            if vip:
                grp1["rows"].append({
                    "source": server_label,
                    "destination": f"VKS '{c['metadata']['name']}' VIP {vip}:{port}",
                    "physical_traffic": f"{out['server_ip']} → {vip}:{port}",
                    "method": "tcp", **tcp_probe(vip, port),
                })
        out["groups"].append(grp1)

        # ─── Group 2: Supervisor Node → VKS VIP (exec) ───────────────────
        grp2 = {
            "id": "sup_to_vks",
            "title": "Supervisor Node → VKS Control Plane VIP:6443",
            "subtitle": "TCP probe exec'd inside a pod on a Supervisor node (hostNetwork=true means same source IP as the node)",
            "rows": [],
        }
        if capi_items:
            # Search ALL namespaces in Supervisor for a usable exec pod
            exec_ns, exec_pod, exec_tool = _k8s_find_exec_pod(
                sup_base, sup_hdr, host_network_only=True)
            if not exec_pod:
                exec_ns, exec_pod, exec_tool = _k8s_find_exec_pod(
                    sup_base, sup_hdr, host_network_only=False)

            for c in capi_items:
                cname = c["metadata"]["name"]
                vip   = target_vip or c.get("spec", {}).get("controlPlaneEndpoint", {}).get("host", "")
                port  = c.get("spec", {}).get("controlPlaneEndpoint", {}).get("port", 6443)

                if not exec_pod:
                    grp2["rows"].append({
                        "source": "Supervisor Node",
                        "destination": f"VKS '{cname}' VIP {vip}:{port}",
                        "physical_traffic": ((f"{sup_vpc_nat} (VPC Outbound NAT) → {vip}:{port}")
                                              if sup_vpc_nat else f"(NAT IP unknown) → {vip}:{port}"),
                        "method": "exec", "ok": False, "note": "",
                        "error": ("No exec-capable pod found in Supervisor cluster. "
                                  "The WCP session token may not have pods/exec RBAC "
                                  "on system namespaces, or all pods are distroless."),
                    })
                    continue

                res = _tcp_test_via_exec(sup_base, sup_hdr,
                                         exec_ns, exec_pod, exec_tool,
                                         vip, port)
                # Get pod detail — node name + hostNetwork flag
                pd = _sess.get(f"https://{sup_base}/api/v1/namespaces/{exec_ns}/pods/{exec_pod}",
                               headers=sup_hdr, verify=False, timeout=5)
                pod_spec  = pd.json().get("spec", {}) if pd.ok else {}
                is_hn     = pod_spec.get("hostNetwork", False)
                node_name = pod_spec.get("nodeName", "")
                node_tag  = f" node:{node_name}" if node_name else ""
                grp2["rows"].append({
                    "source": (f"Supervisor Node{node_tag} — pod {exec_pod} "
                               f"({exec_ns}{'  hostNetwork' if is_hn else '  podNetwork'})"),
                    "destination": f"VKS '{cname}' VIP {vip}:{port}",
                    "physical_traffic": ((f"{sup_vpc_nat} (VPC Outbound NAT) → {vip}:{port}")
                                         if sup_vpc_nat else f"(NAT IP unknown) → {vip}:{port}"),
                    "method": "exec",
                    "probe": res.get("method_used", ""),
                    "ok": res["ok"],
                    "note": res.get("output", ""),
                    "error": res.get("error"),
                })
        out["groups"].append(grp2)

        # ─── Group 3: VKS Node → Supervisor VIP (exec) ───────────────────
        grp3 = {
            "id": "vks_to_sup",
            "title": "VKS Node → Supervisor Control Plane VIP:6443",
            "subtitle": ("TCP probe exec'd inside a pod on a VKS worker node. "
                         "Note: VKS worker nodes do not normally need direct access to the "
                         "Supervisor Kubernetes API — this test checks general reachability "
                         "from the VKS pod network to the Supervisor VIP."),
            "rows": [],
        }
        for c in capi_items:
            ns    = c["metadata"]["namespace"]
            cname = c["metadata"]["name"]

            # Fetch VKS kubeconfig secret
            sec_r = _sess.get(
                f"https://{sup_base}/api/v1/namespaces/{ns}/secrets/{cname}-kubeconfig",
                headers=sup_hdr, verify=False, timeout=10)

            def _vks_err(msg):
                grp3["rows"].append({
                    "source": f"VKS '{cname}' Node",
                    "destination": f"Supervisor VIP {supervisor_vip}:6443",
                    "physical_traffic": ((f"{vks_vpc_nat} (VPC Outbound NAT) → {supervisor_vip}:6443")
                                          if vks_vpc_nat else f"(NAT IP unknown) → {supervisor_vip}:6443"),
                    "method": "exec", "ok": False, "note": "", "error": msg,
                })

            if not sec_r.ok:
                _vks_err(f"Could not fetch kubeconfig secret (HTTP {sec_r.status_code})")
                continue

            kc_b64 = sec_r.json().get("data", {}).get("value", "")
            if not kc_b64:
                _vks_err("kubeconfig secret is empty")
                continue

            try:
                kc = yaml.safe_load(
                    _b64.b64decode(kc_b64).decode("utf-8", errors="replace"))
            except Exception as ye:
                _vks_err(f"Failed to parse kubeconfig: {ye}")
                continue

            try:
                vks_url   = kc["clusters"][0]["cluster"]["server"]
                vks_host  = vks_url.split("//")[-1].split(":")[0]
                vks_port  = int(vks_url.split(":")[-1].rstrip("/"))
                user_e    = kc["users"][0]["user"]
                cert_b64  = user_e.get("client-certificate-data", "")
                key_b64   = user_e.get("client-key-data", "")
                bearer    = user_e.get("token", "")
            except Exception as pe:
                _vks_err(f"Could not extract VKS credentials: {pe}")
                continue

            # Build SSL context with client cert
            vks_ctx = _ssl_m.create_default_context()
            vks_ctx.check_hostname = False
            vks_ctx.verify_mode = _ssl_m.CERT_NONE
            _cert_f = _key_f = None
            if cert_b64 and key_b64:
                try:
                    with _tmp.NamedTemporaryFile(delete=False, suffix=".crt") as cf:
                        cf.write(_b64.b64decode(cert_b64))
                        _cert_f = cf.name
                    with _tmp.NamedTemporaryFile(delete=False, suffix=".key") as kf:
                        kf.write(_b64.b64decode(key_b64))
                        _key_f = kf.name
                    vks_ctx.load_cert_chain(_cert_f, _key_f)
                except Exception:
                    pass

            vks_base = f"{vks_host}:{vks_port}"
            vks_hdr  = ({"Authorization": f"Bearer {bearer}", "Accept": "application/json"}
                        if bearer else {"Accept": "application/json"})
            vks_req  = dict(verify=False, timeout=10)
            if _cert_f and _key_f:
                vks_req["cert"] = (_cert_f, _key_f)

            _vks_cert_tuple = (_cert_f, _key_f) if (_cert_f and _key_f) else None
            try:
                exec_ns2, exec_pod2, exec_tool2 = _k8s_find_exec_pod(
                    vks_base, vks_hdr, host_network_only=True,
                    ssl_ctx=vks_ctx, req_cert=_vks_cert_tuple)
                if not exec_pod2:
                    exec_ns2, exec_pod2, exec_tool2 = _k8s_find_exec_pod(
                        vks_base, vks_hdr, host_network_only=False,
                        ssl_ctx=vks_ctx, req_cert=_vks_cert_tuple)

                if not exec_pod2:
                    _vks_err("No exec-capable pod found in VKS cluster — "
                             "all pods may be distroless with no network tools.")
                else:
                    res2 = _tcp_test_via_exec(
                        vks_base, vks_hdr, exec_ns2, exec_pod2, exec_tool2,
                        supervisor_vip, 6443, ssl_ctx=vks_ctx)
                    pd2 = requests.get(
                        f"https://{vks_base}/api/v1/namespaces/{exec_ns2}/pods/{exec_pod2}",
                        headers=vks_hdr, verify=False, timeout=5,
                        **({} if not _vks_cert_tuple else {"cert": _vks_cert_tuple}))
                    pod_spec2  = pd2.json().get("spec", {}) if pd2.ok else {}
                    is_hn2     = pod_spec2.get("hostNetwork", False)
                    node_name2 = pod_spec2.get("nodeName", "")
                    node_tag2  = f" node:{node_name2}" if node_name2 else ""
                    grp3["rows"].append({
                        "source": (f"VKS '{cname}' Node{node_tag2} — pod {exec_pod2} "
                                   f"({exec_ns2}{'  hostNetwork' if is_hn2 else '  podNetwork'})"),
                        "destination": f"Supervisor VIP {supervisor_vip}:6443",
                        "physical_traffic": ((f"{vks_vpc_nat} (VPC Outbound NAT) → {supervisor_vip}:6443")
                                              if vks_vpc_nat else f"(NAT IP unknown) → {supervisor_vip}:6443"),
                        "method": "exec",
                        "probe": res2.get("method_used", ""),
                        "ok": res2["ok"],
                        "note": res2.get("output", ""),
                        "error": res2.get("error"),
                    })
            finally:
                for _f in (_cert_f, _key_f):
                    if _f:
                        try:
                            import os as _osc
                            _osc.unlink(_f)
                        except Exception:
                            pass

        out["groups"].append(grp3)
        out["success"] = True

    except requests.HTTPError as e:
        out["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        out["error"] = str(e)

    return jsonify(out)


@app.route("/api/supervisor-status", methods=["POST"])
def supervisor_status():
    """Poll Supervisor deployment status by cluster moref."""
    body = request.get_json(force=True)
    vc_url = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    cluster_id = body.get("cluster_id", "")

    result = {"success": False, "status": None, "error": None}
    try:
        token, _ = vc_auth(vc_url, username, password)
        status = vc_get(
            vc_url, token, f"/api/vcenter/namespace-management/clusters/{cluster_id}"
        )
        # Normalise messages to plain strings so the frontend never shows [object Object]
        if status and "messages" in status:
            def _msg_text(m):
                if isinstance(m, str):
                    return m
                return (m.get("default_message") or m.get("message") or
                        " ".join(str(a) for a in (m.get("args") or [])) or
                        str(m))
            status["messages"] = [_msg_text(m) for m in status["messages"] if m]
        result.update(success=True, status=status)
    except Exception as e:
        result["error"] = str(e)
    return jsonify(result)


@app.route("/api/fix/vna-status", methods=["POST"])
def fix_vna_status():
    """Poll the VNA cluster deployment state."""
    body     = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    nsx_url  = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user") or "admin"
    nsx_pass = body.get("nsx_pass") or body.get("password", "")
    cluster_id = body.get("cluster_id", "vna-cluster-1")

    result = {"success": False, "error": None,
              "consolidated_status": "UNKNOWN", "members": []}
    try:
        state = nsx_get(nsx_url, nsx_user, nsx_pass,
            f"/policy/api/v1/infra/sites/default/enforcement-points/default"
            f"/virtual-network-appliance-clusters/{cluster_id}/state")
        if state is None:
            result["error"] = "Cluster not found"
            return jsonify(result)
        result["success"]            = True
        result["consolidated_status"] = state.get("consolidated_status", "UNKNOWN")
        members = []
        for m in (state.get("members_state") or []):
            cfg   = m.get("configuration_state") or {}
            prog  = cfg.get("progress_state") or {}
            members.append({
                "name":     m.get("member_path", "").rstrip("/").split("/")[-1],
                "status":   cfg.get("state", "UNKNOWN"),
                "step":     prog.get("current_step_title", ""),
                "progress": prog.get("progress", 0),
            })
        result["members"] = members
    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result["error"] = str(e)
    return jsonify(result)



@app.route("/api/fix/vna-options", methods=["POST"])
def fix_vna_options():
    """Return all data needed to populate the VNA install wizard."""
    body     = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    username = body.get("username", "")
    password = body.get("password", "")
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    nsx_url  = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user") or "admin"
    nsx_pass = body.get("nsx_pass") or password

    result = {
        "success": False, "error": None,
        "port_groups": [], "clusters": [], "datastores": [],
        "vc_subnet": None, "vc_gateway": None, "vc_prefix": 24,
        "vc_dns": [], "vc_ntp": [],
        "domain": "", "compute_manager_id": None,
        # auto-discovered NSX fields
        "overlay_tz_path":  None,
        "vm_mgmt_dvpg":     None,
        "vm_cluster_moref": None,
        "vm_datastore_id":  None,
        # cascading-dropdown maps
        "pg_clusters_map":  {},   # pg_moref  → [cluster_moref, ...]
        "cluster_ds_map":   {},   # cluster_moref → [datastore_moref, ...]
    }
    try:
        token, _ = vc_auth(vc_url, username, password)

        result["port_groups"] = vc_get(
            vc_url, token, "/api/vcenter/network",
            params={"types": "DISTRIBUTED_PORTGROUP"}) or []
        result["clusters"] = vc_get(vc_url, token, "/api/vcenter/cluster") or []
        ds_raw = vc_get(vc_url, token, "/api/vcenter/datastore") or []
        result["datastores"] = sorted(ds_raw,
                                      key=lambda d: d.get("free_space", 0), reverse=True)

        # ── Cascading-dropdown maps ────────────────────────────────────────
        # NOTE: GET /api/vcenter/network?hosts= and ?clusters= filters are silently
        # ignored in some vCenter versions (all portgroups returned regardless).
        # Use SOAP PropertyCollector to accurately map PGs → clusters via the
        # DVS membership chain: DVPG → parent DVS → connected hosts → cluster.

        # 1. pg_clusters_map: portgroup moref → [cluster morefs] via SOAP
        result["pg_clusters_map"] = _vc_soap_get_pg_cluster_map(vc_url, username, password)

        # 2. cluster_ds_map still uses REST (datastore filter is reliable enough)
        # 3. cluster_ds_map: cluster moref → [datastore morefs] (use per-cluster hosts)
        try:
            _cdm: dict = {}
            for _c in result["clusters"]:
                _cm = _c.get("cluster", "")
                if not _cm:
                    continue
                _hs = vc_get(vc_url, token, "/api/vcenter/host",
                             params={"clusters": _cm}) or []
                if _hs:
                    _hid = _hs[0].get("host", "")
                    _dsl = vc_get(vc_url, token, "/api/vcenter/datastore",
                                  params={"hosts": _hid}) or []
                    _cdm[_cm] = [_d.get("datastore", "") for _d in _dsl
                                 if _d.get("datastore")]
            result["cluster_ds_map"] = _cdm
        except Exception:
            pass

        # cluster_ds_map is built above via per-host queries.

        _vc_own_ip = ""   # stored for VM-lookup fallback below
        try:
            ifaces = vc_get(vc_url, token, "/api/appliance/networking/interfaces") or []
            for iface in (ifaces if isinstance(ifaces, list) else []):
                ipv4 = (iface.get("ipv4") or {})
                vc_ip  = ipv4.get("address", "")
                prefix = ipv4.get("prefix", 24)
                gw     = ipv4.get("default_gateway", "")
                if vc_ip and gw:
                    _vc_own_ip = vc_ip
                    # Compute proper network address (e.g. 10.1.1.0/24, not 10.1.1.10/24)
                    try:
                        import ipaddress
                        net = ipaddress.IPv4Network(f"{vc_ip}/{prefix}", strict=False)
                        result["vc_subnet"] = str(net)          # "10.1.1.0/24"
                    except Exception:
                        result["vc_subnet"] = f"{vc_ip}/{prefix}"
                    result["vc_gateway"] = gw
                    result["vc_prefix"]  = prefix
                    break
        except Exception:
            pass

        # Find vCenter VM's management port group via name/IP match.
        # This is more reliable than the NSX TNC-tag approach which only
        # exists in VCF-automated environments.
        try:
            _p = urlparse(vc_url)
            _vc_host  = _p.hostname or ""
            _url_is_ip = all(p.isdigit() for p in _vc_host.split(".") if p)
            _vc_short  = "" if _url_is_ip else _vc_host.split(".")[0].lower()

            _all_vms = vc_get(vc_url, token, "/api/vcenter/vm") or []
            _vc_vm = None

            # Strategy 1 — exact short-name match
            if _vc_short:
                _vc_vm = next((v for v in _all_vms
                               if (v.get("name") or "").split(".")[0].lower() == _vc_short), None)

            # Strategy 2 — guest IP match (when URL was an IP address)
            if not _vc_vm and _vc_own_ip:
                for _v in _all_vms:
                    _vid = _v.get("vm", "")
                    if not _vid:
                        continue
                    _guest = vc_get(vc_url, token,
                                    f"/api/vcenter/vm/{_vid}/guest/networking/interfaces") or []
                    for _gi in (_guest if isinstance(_guest, list) else []):
                        for _ga in (_gi.get("ip", {}) or {}).get("ip_addresses", []):
                            if _ga.get("ip_address") == _vc_own_ip:
                                _vc_vm = _v
                                break
                        if _vc_vm:
                            break
                    if _vc_vm:
                        break

            if _vc_vm:
                _vm_id = _vc_vm.get("vm", "")

                # ── Port group from first NIC ──────────────────────────────
                _nics  = (vc_get(vc_url, token,
                                 f"/api/vcenter/vm/{_vm_id}/hardware/ethernet")
                          or []) if _vm_id else []
                if _nics:
                    _nic0     = _nics[0].get("nic", "")
                    _nic_data = (vc_get(vc_url, token,
                                       f"/api/vcenter/vm/{_vm_id}/hardware/ethernet/{_nic0}")
                                 if _nic0 else {})
                    _pg = ((_nic_data or {}).get("backing") or {}).get("network", "")
                    if _pg:
                        result["vm_mgmt_dvpg"] = _pg

                # ── Cluster: iterate clusters, find which one contains the vCenter VM ──
                if _vm_id:
                    for _c in result.get("clusters", []):
                        _cmoref = _c.get("cluster", "")
                        if not _cmoref:
                            continue
                        _vms_in_c = vc_get(vc_url, token, "/api/vcenter/vm",
                                           params={"clusters": _cmoref}) or []
                        if any(v.get("vm") == _vm_id for v in _vms_in_c):
                            result["vm_cluster_moref"] = _cmoref
                            break

                # ── Datastore: read from the VM's actual disk backing ─────────────
                # The VM's boot disk path includes the datastore name,
                # e.g. "[vsan-mgmt-01a] vc-mgmt-a/vc-mgmt-a.vmdk"
                if _vm_id:
                    try:
                        _disks = vc_get(vc_url, token,
                                        f"/api/vcenter/vm/{_vm_id}/hardware/disk") or []
                        if _disks:
                            _disk0_id = _disks[0].get("disk", "")
                            if _disk0_id:
                                _dd = vc_get(vc_url, token,
                                             f"/api/vcenter/vm/{_vm_id}/hardware/disk/{_disk0_id}") or {}
                                _vmdk = (_dd.get("backing") or {}).get("vmdk_file", "")
                                # Extract datastore name from "[ds-name] path/file.vmdk"
                                if _vmdk and "[" in _vmdk:
                                    _ds_name = _vmdk.split("[")[1].split("]")[0].strip()
                                    # Match by name in the datastores list
                                    for _ds in result.get("datastores", []):
                                        if _ds.get("name") == _ds_name:
                                            result["vm_datastore_id"] = _ds.get("datastore", "")
                                            break
                    except Exception:
                        pass
        except Exception:
            pass

        try:
            dns_resp = vc_get(vc_url, token, "/api/appliance/networking/dns/servers") or {}
            result["vc_dns"] = dns_resp.get("servers", [])
        except Exception:
            pass

        try:
            ntp = vc_get(vc_url, token, "/api/appliance/ntp") or []
            result["vc_ntp"] = ntp if isinstance(ntp, list) else []
        except Exception:
            pass

        try:
            p = urlparse(vc_url)
            parts = (p.hostname or "").split(".")
            if len(parts) >= 3:
                result["domain"] = ".".join(parts[1:])
        except Exception:
            pass

        if nsx_url:
            # Compute manager ID
            try:
                cms_resp = SESS.get(
                    f"{nsx_url}/api/v1/fabric/compute-managers",
                    auth=(nsx_user, nsx_pass),
                    headers={"Accept": "application/json"},
                    verify=False, timeout=15,
                )
                if cms_resp.ok:
                    vc_host = urlparse(vc_url).hostname or ""
                    for cm in cms_resp.json().get("results", []):
                        srv = cm.get("server", "")
                        if srv == vc_host or vc_host in srv or srv in vc_host:
                            result["compute_manager_id"] = cm["id"]
                            break
                    if not result["compute_manager_id"]:
                        for cm in cms_resp.json().get("results", []):
                            if cm.get("origin_type") == "vCenter":
                                result["compute_manager_id"] = cm["id"]
                                break
            except Exception:
                pass

            # Auto-discover overlay TZ path and vm-mgmt DVPG from TNC tags
            try:
                tnc_resp = nsx_get(nsx_url, nsx_user, nsx_pass,
                    "/policy/api/v1/infra/sites/default/enforcement-points/default"
                    "/transport-node-collections")
                tnc_results = (tnc_resp or {}).get("results", [])
                if tnc_results:
                    tnc0 = tnc_results[0]
                    # vm-mgmt DVPG from tag — only use if non-empty AND not already
                    # discovered via the vCenter VM NIC lookup (which is more reliable)
                    if not result["vm_mgmt_dvpg"]:
                        for tag in (tnc0.get("tags") or []):
                            if tag.get("scope") == "vcf-orchestration/vm-mgmt-dvpg-moid":
                                _tval = (tag.get("tag") or "").strip()
                                if _tval:
                                    result["vm_mgmt_dvpg"] = _tval
                                break
                    # overlay TZ path — from TNC → TNP (primary method per doc)
                    tnp_id = tnc0.get("transport_node_profile_id", "")
                    # profile_id may be a full path like "/infra/host-transport-node-profiles/xyz"
                    if "/" in tnp_id:
                        tnp_id = tnp_id.rstrip("/").split("/")[-1]
                    if tnp_id:
                        tnp = nsx_get(nsx_url, nsx_user, nsx_pass,
                            f"/policy/api/v1/infra/host-transport-node-profiles/{tnp_id}")
                        if tnp:
                            hs_list = (tnp.get("host_switch_spec") or {}).get("host_switches", [])
                            for hs in hs_list:
                                for tz_ep in hs.get("transport_zone_endpoints", []):
                                    tz_id = (tz_ep.get("transport_zone_id")
                                             or tz_ep.get("transport_zone_path", ""))
                                    if not tz_id:
                                        continue
                                    # Normalise bare IDs to full Policy path
                                    if not tz_id.startswith("/"):
                                        tz_id = (
                                            "/infra/sites/default/enforcement-points"
                                            f"/default/transport-zones/{tz_id}"
                                        )
                                    result["overlay_tz_path"] = tz_id
                                    break
                                if result["overlay_tz_path"]:
                                    break
            except Exception:
                pass

            # Fallback: list all transport zones and return them so the wizard
            # can show a dropdown if auto-discovery didn't find a single answer.
            try:
                tzs_resp = nsx_get(nsx_url, nsx_user, nsx_pass,
                    "/policy/api/v1/infra/sites/default/enforcement-points/default"
                    "/transport-zones")
                overlay_tzs = []
                for tz in (tzs_resp or {}).get("results", []):
                    tz_type = tz.get("tz_type", "")
                    if "OVERLAY" in tz_type.upper():
                        overlay_tzs.append({
                            "id":    tz.get("id", ""),
                            "name":  tz.get("display_name", tz.get("id", "")),
                            "path":  tz.get("path") or (
                                "/infra/sites/default/enforcement-points"
                                f"/default/transport-zones/{tz.get('id','')}"),
                        })
                result["overlay_tzs"] = overlay_tzs
                # If primary method failed, auto-pick:
                # prefer a non-standard TZ (anything except nsx-overlay-transportzone)
                if not result["overlay_tz_path"]:
                    preferred = [t for t in overlay_tzs
                                 if t["id"] != "nsx-overlay-transportzone"]
                    if preferred:
                        result["overlay_tz_path"] = preferred[0]["path"]
                    elif overlay_tzs:
                        result["overlay_tz_path"] = overlay_tzs[0]["path"]
            except Exception:
                pass

        result["success"] = True

    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result["error"] = str(e)
    return jsonify(result)


@app.route("/api/fix/create-vna", methods=["POST"])
def fix_create_vna():
    """Deploy a VNA cluster via the two-step NSX Policy API:
       1. PUT the cluster object (metadata only, no nodes).
       2. PUT each node separately under the cluster path.
    """
    body     = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    nsx_url  = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user") or "admin"
    nsx_pass = body.get("nsx_pass") or body.get("password", "")

    port_group_id      = body.get("port_group_id", "")
    cluster_moref      = body.get("cluster_moref", "")
    datastore_id       = body.get("datastore_id", "")
    compute_manager_id = body.get("compute_manager_id", "")
    overlay_tz_path    = body.get("overlay_tz_path", "")
    ip1       = body.get("ip1", "")
    ip2       = body.get("ip2", "")
    prefix    = int(body.get("prefix", 24))
    gateway   = body.get("gateway", "")
    dns_list  = body.get("dns", [])
    ntp_list  = body.get("ntp", [])
    domain    = body.get("domain", "local")
    form_factor = body.get("form_factor", "MEDIUM")
    ip_mode   = body.get("ip_mode", "static")

    result = {"success": False, "error": None}
    base  = ("/policy/api/v1/infra/sites/default/enforcement-points/default"
             "/virtual-network-appliance-clusters")
    ha_profile = ("/infra/sites/default/enforcement-points/default"
                  "/edge-cluster-high-availability-profiles"
                  "/019a9fc9-f1ab-76b9-b515-d73348fdf2fe")
    failure_domain = ("/infra/sites/default/enforcement-points/default"
                      "/failure-domains/4fc1e3b0-1cd4-4339-86c8-f76baddbaafb")
    nsx_headers = {"Content-Type": "application/json", "Accept": "application/json"}

    def nsx_put(path, payload):
        r = requests.put(f"{nsx_url}{path}", auth=(nsx_user, nsx_pass),
                         headers=nsx_headers, json=payload, verify=False, timeout=30)
        return r

    def nsx_get_raw(path):
        return requests.get(f"{nsx_url}{path}", auth=(nsx_user, nsx_pass),
                            headers=nsx_headers, verify=False, timeout=15)

    def extract_error(r):
        try:
            err  = r.json()
            msgs = "; ".join(
                m.get("default_message", "")
                for m in (err.get("error_messages") or [])
            )
            return f"HTTP {r.status_code}: {msgs or err.get('error_message') or r.text[:500]}"
        except Exception:
            return f"HTTP {r.status_code}: {r.text[:500]}"

    try:
        # Find a free cluster ID — skip any objects still marked for deletion
        cluster_id = "vna-cluster-1"
        for _suffix in range(1, 20):
            _cid  = f"vna-cluster-{_suffix}"
            _rc   = nsx_get_raw(f"{base}/{_cid}")
            if _rc.status_code == 404:
                cluster_id = _cid
                break
            if _rc.ok and _rc.json().get("marked_for_delete"):
                continue  # still being purged — try next suffix
            cluster_id = _cid  # exists and healthy, or unknown error; just use it
            break

        # ── Step 1: create the cluster object ────────────────────────────
        cluster_payload = {
            "resource_type":     "VirtualNetworkApplianceCluster",
            "id":                cluster_id,
            "display_name":      cluster_id,
            "appliance_form_factor": form_factor,
            "appliance_type":    "VirtualNetworkAppliance",
            "service_type":      "VPC_SERVICES",
            "advanced_configuration": {
                "overlay_transport_zone_path": overlay_tz_path,
                "high_availability_profile":  ha_profile,
            },
        }
        r1 = nsx_put(f"{base}/{cluster_id}", cluster_payload)
        if not r1.ok:
            if r1.status_code == 400 and "marked for deletion" in r1.text:
                result["error"] = (
                    f"NSX object '{cluster_id}' was recently deleted and is still "
                    f"being purged (up to 5 minutes). Please wait a few minutes "
                    f"and try again."
                )
            else:
                result["error"] = f"[Create cluster] {extract_error(r1)}"
            return jsonify(result)

        # ── Step 2: create each node ──────────────────────────────────────
        for i, ip in enumerate([ip1, ip2]):
            node_id = f"vna-node-{i + 1}"
            # Build ip_assignment_specs based on mode
            if ip_mode == "dhcp":
                ip_specs = [{"ip_assignment_type": "Dhcpv4"}]
            else:
                ip_specs = [{
                    "management_port_subnets": [
                        {"ip_addresses": [ip], "prefix_length": prefix}
                    ],
                    "default_gateway":    [gateway],
                    "ip_assignment_type": "StaticIpv4",
                }]
            node_payload = {
                "resource_type":     "VirtualNetworkAppliance",
                "id":                node_id,
                "display_name":      node_id,
                "hostname":          f"{node_id}.{domain}",
                "failure_domain_path": failure_domain,
                "vm_deployment_config": {
                    "compute_manager_id":          compute_manager_id,
                    "cluster_or_resource_pool_id": cluster_moref,
                    "datastore_id":                datastore_id,
                    "reservation_info": {
                        "memory_reservation": {"reservation_percentage": 100},
                        "cpu_reservation":    {"reservation_in_shares": "HIGH_PRIORITY"},
                    },
                },
                "management_interface": {
                    "ip_assignment_specs": ip_specs,
                    "network_id": port_group_id,
                },
                "credentials": {
                    "cli_username":   "admin",
                    "audit_username": "audit",
                },
            }
            r2 = nsx_put(f"{base}/{cluster_id}/virtual-network-appliances/{node_id}",
                         node_payload)
            if not r2.ok:
                result["error"] = f"[Create node {node_id}] {extract_error(r2)}"
                return jsonify(result)

        result["success"] = True
        result["cluster_id"] = cluster_id

    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:500]}"
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


# ── shared helpers for Fix endpoints ─────────────────────────────────────────

def _nsx_creds(body):
    vc_url      = normalize_url(body.get("vc_url", ""))
    nsx_url_raw = (body.get("nsx_url") or "").strip()
    nsx_url     = normalize_url(nsx_url_raw) if nsx_url_raw else guess_nsx_url(vc_url)
    nsx_user    = body.get("nsx_user") or "admin"
    nsx_pass    = body.get("nsx_pass") or body.get("password", "")
    return nsx_url, nsx_user, nsx_pass


def _nsx_error(r):
    try:
        err  = r.json()
        msgs = "; ".join(m.get("default_message", "")
                         for m in (err.get("error_messages") or []))
        return (f"HTTP {r.status_code}: "
                f"{msgs or err.get('error_message') or r.text[:500]}")
    except Exception:
        return f"HTTP {r.status_code}: {r.text[:500]}"


def _nsx_put(nsx_url, nsx_user, nsx_pass, path, payload):
    return requests.put(
        f"{nsx_url}{path}",
        auth=(nsx_user, nsx_pass),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json=payload, verify=False, timeout=30,
    )


def _nsx_excl_to_str(block):
    """Return excluded ranges as a comma-separated string.
    NSX stores these in the 'excluded_ips' field (list of {start, end}).
    Falls back to legacy 'Excluded ranges:' description convention.
    """
    ranges = block.get("excluded_ips") or block.get("excluded_ip_ranges") or []
    if ranges:
        parts = []
        for r in ranges:
            s, e = r.get("start", ""), r.get("end", "")
            parts.append(s if s == e else f"{s}-{e}")
        return ", ".join(parts)
    desc = block.get("description", "")
    if "Excluded ranges:" in desc:
        return desc.split("Excluded ranges:", 1)[1].strip()
    return ""


def _str_to_nsx_excl(excl_str):
    """Parse comma-separated exclusion string into NSX IpRange list [{start, end}, ...]."""
    result = []
    for tok in excl_str.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            parts = tok.split("-", 1)
            result.append({"start": parts[0].strip(), "end": parts[1].strip()})
        else:
            result.append({"start": tok, "end": tok})
    return result


def _consolidate_ip_ranges(items):
    """Sort, deduplicate, and merge consecutive IPs/ranges into compact IpRange list.

    Input: list of bare IP strings or 'start-end' strings.
    Output: [{start, end}, ...] with consecutive IPs merged.

    Examples:
      [11, 12, 13]        → [{11, 13}]
      [11, 12, 13, 21, 22]→ [{11, 13}, {21, 22}]
      [11, 21, 31]        → [{11, 11}, {21, 21}, {31, 31}]
    """
    import ipaddress as _ip
    addrs: set = set()
    for item in items:
        item = str(item).strip()
        if not item:
            continue
        if "-" in item:
            parts = item.split("-", 1)
            try:
                s = int(_ip.ip_address(parts[0].strip()))
                e = int(_ip.ip_address(parts[1].strip()))
                addrs.update(range(s, e + 1))
            except Exception:
                pass
        else:
            try:
                addrs.add(int(_ip.ip_address(item)))
            except Exception:
                pass
    if not addrs:
        return []
    sorted_addrs = sorted(addrs)
    ranges: list = []
    start = end = sorted_addrs[0]
    for addr in sorted_addrs[1:]:
        if addr == end + 1:
            end = addr
        else:
            ranges.append({"start": str(_ip.ip_address(start)),
                           "end":   str(_ip.ip_address(end))})
            start = end = addr
    ranges.append({"start": str(_ip.ip_address(start)),
                   "end":   str(_ip.ip_address(end))})
    return ranges


def _get_vpc_allocated_ips(nsx_url: str, user: str, pwd: str,
                           block_cidr: str) -> set:
    """Return the set of IPs (strings) from *block_cidr* that NSX VPC has
    already allocated for NAT SNAT rules or LoadBalancer VIPs.

    These IPs are legitimately in use by deployed Supervisors/VPCs and
    must NOT be flagged as VLAN conflicts during the Check-VLAN pre-scan.
    """
    try:
        block_net = ipaddress.ip_network(block_cidr, strict=False)
        allocated: set = set()

        projs = (nsx_get(nsx_url, user, pwd,
                         "/policy/api/v1/orgs/default/projects") or {}).get(
            "results", [{"id": "default"}])

        for proj in projs:
            pid = proj.get("id", "default")
            vpcs = (nsx_get(nsx_url, user, pwd,
                            f"/policy/api/v1/orgs/default/projects/{pid}/vpcs") or {}).get(
                "results", [])
            for vpc in vpcs:
                vid = vpc.get("id", "")
                if not vid:
                    continue

                # SNAT rules — translated_network holds the outbound NAT IP
                for section in ("USER", "GATEWAY"):
                    try:
                        nat = nsx_get(nsx_url, user, pwd,
                            f"/policy/api/v1/orgs/default/projects/{pid}"
                            f"/vpcs/{vid}/nat/{section}/nat-rules") or {}
                        for rule in nat.get("results", []):
                            trans = (rule.get("translated_network") or "").split("/")[0]
                            if trans:
                                try:
                                    if ipaddress.ip_address(trans) in block_net:
                                        allocated.add(trans)
                                except ValueError:
                                    pass
                    except Exception:
                        pass

                # LoadBalancer virtual server IPs
                try:
                    lbs = nsx_get(nsx_url, user, pwd,
                        f"/policy/api/v1/orgs/default/projects/{pid}"
                        f"/vpcs/{vid}/load-balancer-virtual-servers") or {}
                    for vs in lbs.get("results", []):
                        ip = vs.get("ip_address", "")
                        if ip:
                            try:
                                if ipaddress.ip_address(ip) in block_net:
                                    allocated.add(ip)
                            except ValueError:
                                pass
                except Exception:
                    pass

        return allocated
    except Exception:
        return set()


# ── Fix: fetch all NSX state needed for S4-S7 wizards ────────────────────────

@app.route("/api/fix/nsx-prereq-options", methods=["POST"])
def fix_nsx_prereq_options():
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)

    def _list(path):
        r = nsx_get(nsx_url, nsx_user, nsx_pass, path)
        return (r or {}).get("results", [])

    def _to_item(o):
        return {"id":   o.get("id", ""),
                "name": o.get("display_name", o.get("id", "")),
                "path": o.get("path", ""),
                "cidr": _block_cidr(o, nsx_url, nsx_user, nsx_pass)}

    result = {"success": False, "error": None}
    try:
        result["dvlan_connections"] = _list("/policy/api/v1/infra/distributed-vlan-connections")
        result["gw_connections"]    = _list("/policy/api/v1/infra/gateway-connections")
        result["tgw_attachments"]   = _list(
            "/policy/api/v1/orgs/default/projects/default/transit-gateways/default/attachments")
        all_global_raw              = _list("/policy/api/v1/infra/ip-blocks")
        result["ip_blocks"]         = [_to_item(b) for b in all_global_raw]

        # Centralized External IP Blocks:
        # - visibility == EXTERNAL
        # - CIDR does NOT overlap with any Distributed VLAN connection subnet
        import ipaddress as _ip
        dvlan_nets: list = []
        for dv in result["dvlan_connections"]:
            for gw in (dv.get("gateway_addresses") or []):
                try:
                    dvlan_nets.append(_ip.ip_network(
                        str(_ip.ip_interface(gw).network), strict=False))
                except Exception:
                    pass
        cent_ext: list = []
        for b in all_global_raw:
            if (b.get("visibility") or "").upper() != "EXTERNAL":
                continue
            raw_cidr = _block_cidr(b, nsx_url, nsx_user, nsx_pass)
            if not raw_cidr:
                continue
            try:
                block_net = _ip.ip_network(raw_cidr, strict=False)
            except Exception:
                continue
            if any(block_net.overlaps(dn) for dn in dvlan_nets):
                continue
            item = _to_item(b)
            cent_ext.append(item)
        result["cent_ext_ip_blocks"] = cent_ext
        # Private TGW blocks: global ones with visibility=PRIVATE  +  project-level blocks
        private_from_global  = [_to_item(b) for b in all_global_raw
                                 if (b.get("visibility") or "").upper() == "PRIVATE"]
        private_from_project = [_to_item(b) for b in _list(
                                    "/policy/api/v1/orgs/default/projects/default/infra/ip-blocks")]
        seen_paths: set = set()
        combined_private: list = []
        for p in private_from_global + private_from_project:
            key = p["path"] or p["id"]
            if key and key not in seen_paths:
                seen_paths.add(key)
                combined_private.append(p)
        result["private_ip_blocks"] = combined_private
        result["vna_clusters"]      = [_to_item(v)
                                        for v in _list(
                                            "/policy/api/v1/infra/sites/default/enforcement-points"
                                            "/default/virtual-network-appliance-clusters")]
        # Build edge-cluster path → T0 name mapping via T0 locale-services
        _ec_to_t0: dict = {}
        _t0_raw = _list("/policy/api/v1/infra/tier-0s")
        for _t0 in _t0_raw:
            _t0_id   = _t0.get("id", "")
            _t0_name = _t0.get("display_name", _t0_id)
            try:
                _ls = nsx_get(nsx_url, nsx_user, nsx_pass,
                              f"/policy/api/v1/infra/tier-0s/{_t0_id}/locale-services")
                for _s in (_ls or {}).get("results", []):
                    _ec_path = _s.get("edge_cluster_path", "")
                    if _ec_path:
                        _ec_to_t0[_ec_path] = _t0_name
            except Exception:
                pass
        _ec_items = []
        for _e in _list("/policy/api/v1/infra/sites/default/enforcement-points/default/edge-clusters"):
            _item = _to_item(_e)
            _item["t0_name"] = _ec_to_t0.get(_e.get("path", ""), "")
            _ec_items.append(_item)
        result["edge_clusters"] = _ec_items
        result["t0s"]           = [_to_item(t) for t in _t0_raw]
        result["vpc_profile"]       = nsx_get(nsx_url, nsx_user, nsx_pass,
                                              "/policy/api/v1/orgs/default/projects/default"
                                              "/vpc-connectivity-profiles/default")
        tgw_raw = nsx_get(nsx_url, nsx_user, nsx_pass,
                          "/policy/api/v1/orgs/default/projects/default/transit-gateways/default")
        result["tgw"] = _to_item(tgw_raw) if tgw_raw else {"id": "default", "name": "Default Transit Gateway", "path": ""}

        # Identify Centralized TGWs (any TGW with a gateway-connection attachment)
        all_tgws_raw = (_list("/policy/api/v1/orgs/default/projects/default/transit-gateways")
                        if True else [])
        cent_tgws: list = []
        for _t in all_tgws_raw:
            _tid = _t.get("id", "")
            _atts = (_list(f"/policy/api/v1/orgs/default/projects/default"
                           f"/transit-gateways/{_tid}/attachments"))
            has_cent = any("/gateway-connections/" in (a.get("connection_path") or "")
                           for a in _atts)
            if has_cent:
                cent_tgws.append({"id": _tid,
                                   "name": _t.get("display_name", _tid),
                                   "path": _t.get("path", "")})
        result["cent_tgws"] = cent_tgws
        result["success"] = True
    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result["error"] = str(e)
    return jsonify(result)


# ── Fix S4 Distributed: Create VLAN External Connection ──────────────────────

@app.route("/api/fix/create-vlan-connection", methods=["POST"])
def fix_create_vlan_connection():
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    name         = body.get("name", "dvlan-connection-1")
    vlan_id      = int(body.get("vlan_id") or 0)
    gateway_cidr = body.get("gateway_cidr", "")
    result = {"success": False, "error": None}
    try:
        payload = {"resource_type": "DistributedVlanConnection",
                   "id": name, "display_name": name,
                   "vlan_id": vlan_id,
                   "gateway_addresses": [gateway_cidr]}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/infra/distributed-vlan-connections/{name}", payload)
        if r.ok:
            result.update(success=True, path=r.json().get("path", f"/infra/distributed-vlan-connections/{name}"))
        else:
            result["error"] = _nsx_error(r)
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


# ── Fix S4 Centralized: Create Gateway Connection ────────────────────────────

@app.route("/api/fix/create-gateway-connection", methods=["POST"])
def fix_create_gateway_connection():
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    name    = body.get("name", "gw-connection-1")
    t0_path = body.get("t0_path", "")
    result = {"success": False, "error": None}
    try:
        payload = {"resource_type": "GatewayConnection",
                   "id": name, "display_name": name, "tier0_path": t0_path}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/infra/gateway-connections/{name}", payload)
        if r.ok:
            result.update(success=True, path=r.json().get("path", f"/infra/gateway-connections/{name}"))
        else:
            result["error"] = _nsx_error(r)
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


# ── Fix S5: Create TGW Attachment ─────────────────────────────────────────────

@app.route("/api/fix/create-tgw-attachment", methods=["POST"])
def fix_create_tgw_attachment():
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    connection_path = body.get("connection_path", "")
    att_id          = "tgw-attachment-1"
    result = {"success": False, "error": None}
    try:
        payload: dict = {"resource_type": "TransitGatewayAttachment",
                         "id": att_id, "display_name": att_id,
                         "connection_path": connection_path,
                         "urpf_mode": "STRICT"}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/orgs/default/projects/default"
                     f"/transit-gateways/default/attachments/{att_id}", payload)
        if r.ok:
            result["success"] = True
        else:
            result["error"] = _nsx_error(r)
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


# ── Fix S5 Distributed Case 2: Create new Distributed TGW + Attachment ───────

@app.route("/api/fix/create-dist-tgw", methods=["POST"])
def fix_create_dist_tgw():
    """Create a new Distributed Transit Gateway and attach it to a DVLAN connection."""
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    connection_path = body.get("connection_path", "")
    tgw_name        = (body.get("new_tgw_name") or "dist-tgw1").strip()
    att_id          = "tgw-attachment-1"
    result = {"success": False, "error": None}
    try:
        # Step 1: Create the new Transit Gateway
        tgw_payload = {"resource_type": "TransitGateway",
                       "id": tgw_name,
                       "display_name": tgw_name}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/orgs/default/projects/default"
                     f"/transit-gateways/{tgw_name}", tgw_payload)
        if not r.ok:
            result["error"] = f"[Create TGW] {_nsx_error(r)}"
            return jsonify(result)

        # Step 2: Attach the new TGW to the DVLAN connection
        att_payload = {"resource_type": "TransitGatewayAttachment",
                       "id": att_id, "display_name": att_id,
                       "connection_path": connection_path,
                       "urpf_mode": "STRICT"}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/orgs/default/projects/default"
                     f"/transit-gateways/{tgw_name}/attachments/{att_id}", att_payload)
        if r.ok:
            result["success"] = True
        else:
            result["error"] = f"[Create Attachment] {_nsx_error(r)}"
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)

@app.route("/api/fix/create-cent-tgw", methods=["POST"])
def fix_create_cent_tgw():
    """Create a new Centralized Transit Gateway and attach it to a Gateway Connection."""
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    connection_path = body.get("connection_path", "")
    tgw_name        = (body.get("new_tgw_name") or "cent-tgw1").strip()
    att_id          = "tgw-attachment-1"
    result = {"success": False, "error": None}
    try:
        # Step 1: Create the new Transit Gateway
        tgw_payload: dict = {"resource_type": "TransitGateway",
                             "id": tgw_name,
                             "display_name": tgw_name}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/orgs/default/projects/default"
                     f"/transit-gateways/{tgw_name}", tgw_payload)
        if not r.ok:
            result["error"] = f"[Create TGW] {_nsx_error(r)}"
            return jsonify(result)

        # Step 2: Attach the new TGW to the Gateway Connection
        # NSX auto-creates CentralizedConfig (edge cluster) from the T0 — no need to set it here.
        att_payload: dict = {"resource_type": "TransitGatewayAttachment",
                             "id": att_id, "display_name": att_id,
                             "connection_path": connection_path}
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/orgs/default/projects/default"
                     f"/transit-gateways/{tgw_name}/attachments/{att_id}", att_payload)
        if r.ok:
            result["success"] = True
        else:
            result["error"] = f"[Create Attachment] {_nsx_error(r)}"
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


@app.route("/api/fix/create-ip-block", methods=["POST"])
def fix_create_ip_block():
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    name             = body.get("name", "ext-ip-block-1")
    cidr             = body.get("cidr", "")
    excluded_ranges  = (body.get("excluded_ranges") or "").strip()
    result = {"success": False, "error": None}
    try:
        payload = {"id": name, "display_name": name, "cidr": cidr, "visibility": "EXTERNAL"}
        if excluded_ranges:
            payload["excluded_ips"] = _str_to_nsx_excl(excluded_ranges)
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1/infra/ip-blocks/{name}", payload)
        if r.ok:
            result.update(success=True, path=r.json().get("path", f"/infra/ip-blocks/{name}"))
        else:
            result["error"] = _nsx_error(r)
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


@app.route("/api/fix/add-ip-block-exclusion", methods=["POST"])
def fix_add_ip_block_exclusion():
    """Add IPs to the Excluded Ranges description of an existing External IP Block."""
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    ip_block_path = body.get("ip_block_path", "")
    ips_to_add    = body.get("ips", [])  # list of IP strings
    result = {"success": False, "error": None}
    if not ip_block_path or not ips_to_add:
        result["error"] = "ip_block_path and ips are required"
        return jsonify(result)
    try:
        # GET current block
        block = nsx_get(nsx_url, nsx_user, nsx_pass,
                        f"/policy/api/v1{ip_block_path}")
        if not block:
            result["error"] = "IP Block not found"
            return jsonify(result)
        # Collect all existing IPs/ranges from NSX field (+ description fallback)
        existing_ranges = block.get("excluded_ips") or block.get("excluded_ip_ranges") or []
        existing_items = []
        for r_ in existing_ranges:
            s, e = r_.get("start", ""), r_.get("end", "")
            existing_items.append(s if s == e else f"{s}-{e}")
        if not existing_items:
            desc = block.get("description", "")
            if "Excluded ranges:" in desc:
                existing_items = [x.strip() for x in
                                  desc.split("Excluded ranges:", 1)[1].split(",")
                                  if x.strip()]
        # Merge existing + new IPs then consolidate into compact consecutive ranges
        new_ranges = _consolidate_ip_ranges(existing_items + ips_to_add)
        new_excl_str = ", ".join(
            x["start"] if x["start"] == x["end"] else f"{x['start']}-{x['end']}"
            for x in new_ranges
        )
        # Build payload: keep all existing block fields, write to excluded_ips (NSX native field)
        payload = {**block, "excluded_ips": new_ranges}
        # Clean up old description-based convention if present
        if "Excluded ranges:" in (payload.get("description") or ""):
            prefix = payload["description"].split("Excluded ranges:", 1)[0].rstrip()
            payload["description"] = prefix if prefix else ""
        r = _nsx_put(nsx_url, nsx_user, nsx_pass,
                     f"/policy/api/v1{ip_block_path}", payload)
        if r.ok:
            result.update(success=True, new_excluded=new_excl_str)
        else:
            result["error"] = _nsx_error(r)
    except Exception:
        result["error"] = traceback.format_exc()
    return jsonify(result)


# ── Fix S7 options: VPC Profile wizard data (projects, dist TGWs, IP blocks) ──

@app.route("/api/fix/vpc-profile-options", methods=["POST"])
def fix_vpc_profile_options():
    """Return all data needed for the Step 7 Distributed Fix wizard."""
    import ipaddress as _ip
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    project_id = body.get("project_id", "default")

    def _lst(path):
        r = nsx_get(nsx_url, nsx_user, nsx_pass, path)
        return (r or {}).get("results", [])

    def _item(o):
        return {"id":           o.get("id", ""),
                "display_name": o.get("display_name", o.get("id", "")),
                "path":         o.get("path", "")}

    result = {"success": False}
    try:
        # ── NSX Projects ────────────────────────────────────────────────────
        projs_raw = _lst("/policy/api/v1/orgs/default/projects")
        result["projects"] = [_item(p) for p in projs_raw] or [
            {"id": "default", "display_name": "default", "path": ""}]

        # ── Distributed TGWs in the selected project ─────────────────────
        all_tgws = _lst(f"/policy/api/v1/orgs/default/projects/{project_id}/transit-gateways")
        dist_tgws = []
        for tgw in all_tgws:
            tid = tgw.get("id", "")
            att_resp = nsx_get(nsx_url, nsx_user, nsx_pass,
                f"/policy/api/v1/orgs/default/projects/{project_id}"
                f"/transit-gateways/{tid}/attachments")
            atts = (att_resp or {}).get("results", [])
            dist_atts = [a for a in atts
                         if "/distributed-vlan-connections/" in (a.get("connection_path") or "")]
            if not dist_atts:
                continue
            # Fetch the DVLAN connection details so we can compute subnet overlap
            dvlan_conns = []
            for a in dist_atts:
                cp = a.get("connection_path", "")
                conn = nsx_get(nsx_url, nsx_user, nsx_pass, f"/policy/api/v1{cp}") if cp else None
                if conn:
                    dvlan_conns.append(conn)
            dist_tgws.append({**_item(tgw), "dvlan_connections": dvlan_conns})
        result["dist_tgws"] = dist_tgws

        # ── Global EXTERNAL IP blocks ────────────────────────────────────
        all_global = _lst("/policy/api/v1/infra/ip-blocks")
        ext_blocks = []
        for b in all_global:
            if (b.get("visibility") or "").upper() == "EXTERNAL":
                cidr = _block_cidr(b, nsx_url, nsx_user, nsx_pass)
                ext_blocks.append({**_item(b), "cidr": cidr})
        result["ext_ip_blocks"] = ext_blocks

        # ── Compute matching ext blocks per dist TGW (subnet overlap) ────
        for tgw in dist_tgws:
            dvlan_nets = []
            for conn in tgw.get("dvlan_connections", []):
                for gw in (conn.get("gateway_addresses") or []):
                    try:
                        dvlan_nets.append(_ip.ip_interface(gw).network)
                    except Exception:
                        pass
            if dvlan_nets:
                matching = []
                for b in ext_blocks:
                    try:
                        bnet = _ip.ip_network(b["cidr"], strict=False)
                        if any(bnet.overlaps(dn) for dn in dvlan_nets):
                            matching.append(b["path"])
                    except Exception:
                        pass
                tgw["matching_ext_block_paths"] = matching if matching else [b["path"] for b in ext_blocks]
            else:
                tgw["matching_ext_block_paths"] = [b["path"] for b in ext_blocks]

        # ── VNA Clusters (global) ────────────────────────────────────────
        vna_raw = _lst("/policy/api/v1/infra/sites/default/enforcement-points"
                       "/default/virtual-network-appliance-clusters")
        result["vna_clusters"] = [_item(v) for v in vna_raw]

        # ── Private IP Blocks in the project (not used by any VPC) ───────
        private_global = [b for b in all_global
                          if (b.get("visibility") or "").upper() == "PRIVATE"]
        proj_blocks = _lst(f"/policy/api/v1/orgs/default/projects/{project_id}/infra/ip-blocks")
        vpcs = _lst(f"/policy/api/v1/orgs/default/projects/{project_id}/vpcs")
        vpc_block_paths: set = set()
        for vpc in vpcs:
            for bp in (vpc.get("private_ipv4_blocks") or vpc.get("ip_blocks") or []):
                vpc_block_paths.add(bp)
        seen: set = set()
        private_result = []
        for b in private_global + proj_blocks:
            key = b.get("path") or b.get("id")
            if key and key not in seen and b.get("path") not in vpc_block_paths:
                seen.add(key)
                cidr = _block_cidr(b, nsx_url, nsx_user, nsx_pass)
                private_result.append({**_item(b), "cidr": cidr})
        result["private_ip_blocks"] = private_result

        result["success"] = True
    except requests.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


# ── Fix S7: Configure VPC Connectivity Profile ────────────────────────────────

@app.route("/api/fix/configure-vpc-profile", methods=["POST"])
def fix_configure_vpc_profile():
    body = request.get_json(force=True)
    nsx_url, nsx_user, nsx_pass = _nsx_creds(body)
    project_id            = body.get("project_id", "default")
    mode                  = body.get("mode", "distributed")
    tgw_path              = (body.get("tgw_path") or
                             f"/orgs/default/projects/{project_id}/transit-gateways/default")
    ext_ip_block_path     = body.get("ext_ip_block_path", "")
    cluster_path          = body.get("cluster_path", "")
    private_ip_block_path = body.get("private_ip_block_path", "")
    # If the selected TGW is not the Default TGW, use a dedicated profile
    # to avoid the NSX restriction "transit_gateway_path change not supported".
    is_default_tgw = tgw_path.rstrip("/").split("/")[-1] == "default"
    if is_default_tgw:
        profile_id = "default"
    elif mode == "centralized":
        profile_id = "vpc-cent-prof1"
    else:
        profile_id = "vpc-dist-prof1"
    profile_api = (f"/policy/api/v1/orgs/default/projects/{project_id}"
                   f"/vpc-connectivity-profiles/{profile_id}")
    result = {"success": False, "error": None, "profile_id": profile_id}
    try:
        payload = {
            "external_ip_blocks": [ext_ip_block_path],
            "service_gateway": {
                "enable":             True,
                "edge_cluster_paths": [cluster_path],
                "nat_config": {
                    "enable_default_snat": True,
                    "auto_snat_ip_block":  ext_ip_block_path,
                },
            },
        }
        if private_ip_block_path:
            payload["private_tgw_ip_blocks"] = [private_ip_block_path]

        # If the profile already exists, PATCH (TGW path cannot be changed by NSX,
        # but must still be present in every request as it is a required field).
        # If new, PUT to create it with the desired TGW path.
        existing = nsx_get(nsx_url, nsx_user, nsx_pass, profile_api)
        if existing:
            # Carry the existing transit_gateway_path unchanged (NSX forbids changing it
            # but also rejects requests where the field is absent).
            payload["transit_gateway_path"] = (existing.get("transit_gateway_path") or tgw_path)
            r = requests.patch(
                f"{nsx_url}{profile_api}",
                auth=(nsx_user, nsx_pass),
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                json=payload, verify=False, timeout=30,
            )
        else:
            payload["transit_gateway_path"] = tgw_path
            r = _nsx_put(nsx_url, nsx_user, nsx_pass, profile_api, payload)

        if r.ok:
            result["success"] = True
        else:
            result["error"] = _nsx_error(r)
    except Exception as e:
        result["error"] = traceback.format_exc()
    return jsonify(result)


# ── vCenter SOAP helpers for SSH service management ──────────────────────────

def _soap_get_host_datastores(vc_url, vc_user, vc_pass, host_morefs):
    """Get {host_moref: set(datastore_morefs)} via SOAP PropertyCollector.

    Used as fallback when REST GET /api/vcenter/datastore?filter.hosts is not supported
    (returns HTTP 400 on some vCenter versions including vCenter 9.1).
    """
    import re as _re
    if not host_morefs:
        return {}
    result: dict = {}
    try:
        s, ep, hdr = _soap_session(vc_url, vc_user, vc_pass)
        obj_set = "".join(
            f"<objectSet><obj type=\"HostSystem\">{h}</obj></objectSet>"
            for h in host_morefs
        )
        r = s.post(ep, verify=False, timeout=30, headers=hdr, data=(
            '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
            '<Body><RetrieveProperties xmlns="urn:vim25">'
            '<_this type="PropertyCollector">propertyCollector</_this>'
            "<specSet>"
            "<propSet><type>HostSystem</type><all>false</all>"
            "<pathSet>datastore</pathSet>"
            "</propSet>"
            + obj_set
            + "</specSet>"
            "</RetrieveProperties></Body></Envelope>"
        ))
        if r.status_code != 200 or "Fault" in r.text:
            return result
        for block in _re.findall(r"<returnval>(.*?)</returnval>", r.text, _re.S):
            host_m = _re.search(r'<obj type="HostSystem">([^<]+)</obj>', block)
            # vCenter encodes datastore array as ManagedObjectReference elements
            ds_ids = _re.findall(r"<ManagedObjectReference[^>]*>([^<]+)</ManagedObjectReference>", block)
            if not ds_ids:
                # Alternate: <val ...>datastore-NNN</val> or naked text matching datastore-NNN
                ds_ids = _re.findall(r">(datastore-\d+)<", block)
            if host_m and ds_ids:
                result[host_m.group(1)] = set(ds_ids)
    except Exception:
        pass
    return result


_PBM_CACHE: dict = {}          # (vc, user, policies, datastores) → (timestamp, result)
_PBM_CACHE_TTL = 120           # seconds


def _pbm_policy_ds_compat(vc_url, vc_user, vc_pass, policy_ids, ds_ids):
    """Real storage-policy / datastore compatibility via the PBM SOAP API
    (same source the vSphere Client uses for the 'Storage Compatibility' tab).

    Needed because REST /api/vcenter/storage/policies?filter.datastores is
    unsupported on some vCenter versions (HTTP 400).

    Returns {policy_id: set(compatible datastore ids)}, or None if PBM is
    unusable (login failure, every call failed, ...).
    Auth notes (learned the hard way): PBM needs BOTH the vmware_soap_session
    cookie AND a <vcSessionCookie> SOAP header; the parameter is named
    'hubsToSearch' (not hubList) and PbmProfileId uses <uniqueId>.
    """
    import re as _re
    import time as _time
    from concurrent.futures import ThreadPoolExecutor
    if not policy_ids or not ds_ids:
        return None
    _ck = (vc_url, vc_user, tuple(policy_ids), tuple(ds_ids))
    _hit = _PBM_CACHE.get(_ck)
    if _hit and _time.time() - _hit[0] < _PBM_CACHE_TTL:
        return {k: set(v) for k, v in _hit[1].items()}
    try:
        s, _ep, _hdr = _soap_session(vc_url, vc_user, vc_pass)
        key = ""
        for c in s.cookies:
            if c.name == "vmware_soap_session":
                key = c.value.strip('"')
        if not key:
            return None
        pbm_ep  = f"{vc_url}/pbm/sdk"
        pbm_hdr = {"Content-Type": "text/xml; charset=UTF-8",
                   "SOAPAction": "urn:pbm/version2",
                   "Cookie": f'vmware_soap_session="{key}"'}
        hubs = "".join(
            f"<hubsToSearch><hubType>Datastore</hubType><hubId>{d}</hubId></hubsToSearch>"
            for d in ds_ids)
        def _check(pid):
            body = (
                '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                f'<soapenv:Header><vcSessionCookie xmlns="urn:vim25">{key}</vcSessionCookie></soapenv:Header>'
                "<soapenv:Body>"
                '<PbmCheckCompatibility xmlns="urn:pbm">'
                '<_this type="PbmPlacementSolver">placementSolver</_this>'
                + hubs +
                f"<profile><uniqueId>{pid}</uniqueId></profile>"
                "</PbmCheckCompatibility></soapenv:Body></soapenv:Envelope>")
            try:
                r = s.post(pbm_ep, verify=False, timeout=30, headers=pbm_hdr, data=body)
            except Exception:
                return pid, None
            if r.status_code != 200 or "Fault" in r.text[:600]:
                return pid, None
            compat: set = set()
            for blk in _re.findall(r"<returnval>(.*?)</returnval>", r.text, _re.S):
                m = _re.search(r"<hubId>([^<]+)</hubId>", blk)
                # incompatible hubs carry an <error ...> element (with attributes)
                if m and not _re.search(r"<error[\s>]", blk):
                    compat.add(m.group(1).strip())
            return pid, compat

        # Independent per-policy calls → run in parallel
        with ThreadPoolExecutor(max_workers=6) as ex:
            outcomes = list(ex.map(_check, policy_ids))
        result = {pid: c for pid, c in outcomes if c is not None}
        if not result:
            return None
        _PBM_CACHE[_ck] = (_time.time(), {k: set(v) for k, v in result.items()})
        return result
    except Exception:
        return None


def _soap_get_cluster_ha_drs(vc_url, vc_user, vc_pass, cluster_morefs):
    """
    Fetch accurate HA and DRS settings for vSphere clusters via SOAP.
    The REST API /api/vcenter/cluster returns stale ha_enabled / drs_enabled values;
    SOAP ClusterComputeResource.configuration is the authoritative source.

    Returns dict: {moref: {"ha_enabled": bool, "drs_enabled": bool, "drs_behavior": str}}
    where drs_behavior is "fullyAutomated" | "partiallyAutomated" | "manual" | None.
    """
    import re as _re
    if not cluster_morefs:
        return {}
    result = {}
    try:
        s, ep, hdr = _soap_session(vc_url, vc_user, vc_pass)
        for moref in cluster_morefs:
            r = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><RetrieveProperties xmlns="urn:vim25">'
                '<_this type="PropertyCollector">propertyCollector</_this>'
                '<specSet>'
                '<propSet><type>ClusterComputeResource</type><all>false</all>'
                '<pathSet>configuration</pathSet>'
                '</propSet>'
                f'<objectSet><obj type="ClusterComputeResource">{moref}</obj></objectSet>'
                '</specSet>'
                '</RetrieveProperties></Body></Envelope>'))
            if r.status_code != 200 or 'Fault' in r.text:
                continue
            t = r.text
            m_ha  = _re.search(r'<dasConfig>.*?<enabled>(.*?)</enabled>', t, _re.S)
            m_den = _re.search(r'<drsConfig>.*?<enabled>(.*?)</enabled>', t, _re.S)
            m_dbh = _re.search(r'<drsConfig>.*?<defaultVmBehavior>(.*?)</defaultVmBehavior>', t, _re.S)
            result[moref] = {
                "ha_enabled":   m_ha.group(1).strip().lower()  == 'true' if m_ha  else None,
                "drs_enabled":  m_den.group(1).strip().lower() == 'true' if m_den else None,
                "drs_behavior": m_dbh.group(1).strip()                   if m_dbh else None,
            }
    except Exception:
        pass
    return result


def _soap_session(vc_url, vc_user, vc_pass):
    """Open a vCenter SOAP session. Returns (requests.Session, endpoint, headers)."""
    ep  = f"{vc_url}/sdk"
    hdr = {"Content-Type": "text/xml; charset=UTF-8"}
    s   = requests.Session()
    r   = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><Login xmlns="urn:vim25">'
        '<_this type="SessionManager">SessionManager</_this>'
        f'<userName>{vc_user}</userName><password>{vc_pass}</password>'
        '</Login></Body></Envelope>'))
    if not r.ok or "Fault" in r.text:
        raise RuntimeError(f"SOAP login failed ({r.status_code})")
    return s, ep, hdr


def _soap_find_host(s, ep, hdr, fqdn):
    """Return HostSystem MoRef for the given FQDN, or None."""
    r = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><FindByDnsName xmlns="urn:vim25">'
        '<_this type="SearchIndex">SearchIndex</_this>'
        f'<dnsName>{fqdn}</dnsName><vmSearch>false</vmSearch>'
        '</FindByDnsName></Body></Envelope>'))
    import re as _re
    m = _re.search(r'type="HostSystem"[^>]*>([^<]+)<', r.text)
    return m.group(1).strip() if m else None


def _soap_get_service_system(s, ep, hdr, host_moref):
    """Return HostServiceSystem MoRef for a host.

    Uses RetrieveProperties (not Ex) with propSet — the Ex variant and the
    old propSpec element name both cause vCenter to return HTTP 500.
    """
    r = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><RetrieveProperties xmlns="urn:vim25">'
        '<_this type="PropertyCollector">propertyCollector</_this>'
        '<specSet>'
        '<propSet><type>HostSystem</type><all>false</all>'
        '<pathSet>configManager.serviceSystem</pathSet></propSet>'
        f'<objectSet><obj type="HostSystem">{host_moref}</obj></objectSet>'
        '</specSet>'
        '</RetrieveProperties></Body></Envelope>'))
    import re as _re
    m = _re.search(r'type="HostServiceSystem"[^>]*>([^<]+)<', r.text)
    return m.group(1).strip() if m else None


def _soap_get_ssh_state(s, ep, hdr, svc_moref):
    """Return True if SSH (TSM-SSH) is currently running on the host."""
    r = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        '<Body><RetrieveProperties xmlns="urn:vim25">'
        '<_this type="PropertyCollector">propertyCollector</_this>'
        '<specSet>'
        '<propSet><type>HostServiceSystem</type><all>false</all>'
        '<pathSet>serviceInfo</pathSet></propSet>'
        f'<objectSet><obj type="HostServiceSystem">{svc_moref}</obj></objectSet>'
        '</specSet>'
        '</RetrieveProperties></Body></Envelope>'))
    import re as _re
    m = _re.search(r'<key>TSM-SSH</key>.*?<running>(.*?)</running>', r.text, _re.S)
    return m.group(1).strip().lower() == 'true' if m else False


def _soap_set_ssh(s, ep, hdr, svc_moref, enable):
    """Start or stop SSH (TSM-SSH) on an ESX host. Returns ok (bool)."""
    action = "StartService" if enable else "StopService"
    r = s.post(ep, verify=False, timeout=30, headers=hdr, data=(
        '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
        f'<Body><{action} xmlns="urn:vim25">'
        f'<_this type="HostServiceSystem">{svc_moref}</_this>'
        f'<id>TSM-SSH</id>'
        f'</{action}></Body></Envelope>'))
    return "Fault" not in r.text


def _vc_manage_ssh(vc_url, vc_user, vc_pass, host_fqdn, enable):
    """
    Enable or disable SSH on an ESX host via vCenter SOAP.
    Returns (success, was_already_in_desired_state).
    """
    try:
        s, ep, hdr = _soap_session(vc_url, vc_user, vc_pass)
        moref = _soap_find_host(s, ep, hdr, host_fqdn)
        if not moref:
            return False, False
        svc = _soap_get_service_system(s, ep, hdr, moref)
        if not svc:
            return False, False
        # Check current state first to avoid unnecessary calls
        currently_running = _soap_get_ssh_state(s, ep, hdr, svc)
        if currently_running == enable:
            return True, True   # already in desired state
        ok = _soap_set_ssh(s, ep, hdr, svc, enable)
        # Logout (best-effort)
        try:
            s.post(ep, verify=False, timeout=10, headers=hdr, data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><Logout xmlns="urn:vim25">'
                '<_this type="SessionManager">SessionManager</_this>'
                '</Logout></Body></Envelope>'))
        except Exception:
            pass
        return ok, False
    except Exception:
        return False, False


def _collect_mtu_hosts(nsx_url, nsx_user, nsx_pass, cluster_filter=None,
                       vc_url=None, vc_user=None, vc_pass=None):
    """Return list of dicts {id, name, short, healthy} from NSX HTNs.

    cluster_filter: optional list of vCenter cluster morefs; when supplied only
                    hosts belonging to those clusters are returned.  vCenter
                    credentials are used to do the lookup (same approach as
                    dns_check_hosts), which is far more reliable than NSX
                    compute-collection introspection.
    """
    ep = "/policy/api/v1/infra/sites/default/enforcement-points/default"
    htn_resp = nsx_get(nsx_url, nsx_user, nsx_pass, f"{ep}/host-transport-nodes")
    htns     = (htn_resp or {}).get("results", [])

    # Build set of allowed host names from vCenter when a filter is requested
    allowed_names: set = set()   # both FQDN and short names
    if cluster_filter and vc_url and vc_user and vc_pass:
        try:
            _tok, _ = vc_auth(vc_url, vc_user, vc_pass)
            for moref in cluster_filter:
                raw = vc_get(vc_url, _tok,
                             "/api/vcenter/host",
                             params={"clusters": moref}) or []
                for h in raw:
                    hname = h.get("name", "")
                    if hname:
                        allowed_names.add(hname)
                        allowed_names.add(hname.split(".")[0] if "." in hname else hname)
        except Exception:
            pass  # if vCenter lookup fails fall through to returning all hosts

    hosts = []
    for h in htns:
        hid   = h.get("id", "")
        name  = h.get("display_name", hid)
        short = name.split(".")[0] if "." in name else name

        # Apply cluster filter — only skip when we successfully built the allow-list
        if allowed_names and name not in allowed_names and short not in allowed_names:
            continue

        healthy  = False
        has_vmks = False
        try:
            st = nsx_get(nsx_url, nsx_user, nsx_pass,
                         f"{ep}/host-transport-nodes/{hid}/state")
            if (st or {}).get("state") == "success":
                healthy = True
            for hs in (st or {}).get("host_switch_states", []):
                for ep2 in hs.get("endpoints", []):
                    if ep2.get("ip") and "overlay" in ep2.get("net_stack_instance_key","").lower():
                        has_vmks = True
        except Exception:
            pass
        hosts.append({
            "id":      hid,
            "name":    name,
            "short":   short,
            "healthy": healthy,
            "has_vmks": has_vmks,
        })
    return hosts


@app.route("/api/fix-ha-drs", methods=["POST"])
def fix_ha_drs():
    """Enable HA and DRS (Fully Automated) on a vSphere cluster via SOAP."""
    import re as _re, time as _time
    body          = request.get_json(force=True)
    vc_url        = normalize_url(body.get("vc_url", ""))
    vc_user       = body.get("username", "")
    vc_pass       = body.get("password", "")
    cluster_moref = (body.get("cluster_moref") or "").strip()

    result = {"success": False, "error": None}
    if not cluster_moref:
        result["error"] = "No cluster moref provided."
        return jsonify(result)

    try:
        s, ep, hdr = _soap_session(vc_url, vc_user, vc_pass)

        # ReconfigureComputeResource_Task — enable HA + DRS Fully Automated
        r = s.post(ep, verify=False, timeout=30, headers=hdr, data=(
            '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/" '
            '          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<Body><ReconfigureComputeResource_Task xmlns="urn:vim25">'
            f'<_this type="ClusterComputeResource">{cluster_moref}</_this>'
            '<spec xsi:type="ClusterConfigSpecEx">'
            '<dasConfig><enabled>true</enabled></dasConfig>'
            '<drsConfig>'
            '<enabled>true</enabled>'
            '<defaultVmBehavior>fullyAutomated</defaultVmBehavior>'
            '</drsConfig>'
            '</spec>'
            '<modify>true</modify>'
            '</ReconfigureComputeResource_Task></Body></Envelope>'))

        if r.status_code != 200 or 'Fault' in r.text:
            m = _re.search(r'<faultstring>(.*?)</faultstring>', r.text, _re.S)
            result["error"] = (m.group(1).strip() if m else
                               f"HTTP {r.status_code}: {r.text[:200]}")
            return jsonify(result)

        m = _re.search(r'type="Task"[^>]*>([^<]+)<', r.text)
        if not m:
            result["error"] = "Could not parse task ID from vCenter response."
            return jsonify(result)
        task_moref = m.group(1).strip()

        # Poll task (up to 60 s)
        for _ in range(30):
            _time.sleep(2)
            rp = s.post(ep, verify=False, timeout=15, headers=hdr, data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><RetrieveProperties xmlns="urn:vim25">'
                '<_this type="PropertyCollector">propertyCollector</_this>'
                '<specSet>'
                '<propSet><type>Task</type><all>false</all>'
                '<pathSet>info.state</pathSet>'
                '<pathSet>info.error</pathSet></propSet>'
                f'<objectSet><obj type="Task">{task_moref}</obj></objectSet>'
                '</specSet>'
                '</RetrieveProperties></Body></Envelope>'))
            m_st = _re.search(
                r'<name>info\.state</name>\s*<val[^>]*>([^<]+)</val>', rp.text, _re.S)
            state = m_st.group(1).strip() if m_st else "running"
            if state == "success":
                result["success"] = True
                return jsonify(result)
            if state == "error":
                m_err = _re.search(
                    r'<localizedMessage>(.*?)</localizedMessage>', rp.text, _re.S)
                result["error"] = m_err.group(1).strip() if m_err else "Task failed."
                return jsonify(result)

        result["error"] = "Task timed out after 60 s."
        return jsonify(result)

    except Exception as e:
        result["error"] = str(e)
        return jsonify(result)


@app.route("/api/mtu-hosts", methods=["POST"])
def mtu_hosts():
    """Return the list of ESX hosts available for MTU testing."""
    body     = request.get_json(force=True)
    nsx_raw  = (body.get("nsx_url") or "").strip()
    vc_url   = normalize_url(body.get("vc_url", ""))
    nsx_url  = normalize_url(nsx_raw) if nsx_raw else guess_nsx_url(vc_url)
    nsx_user       = body.get("nsx_user") or "admin"
    nsx_pass       = body.get("nsx_pass") or body.get("password") or ""
    cluster_filter = body.get("cluster_filter") or []
    vc_user        = body.get("username") or body.get("vc_user") or ""
    vc_pass        = body.get("password") or body.get("vc_pass") or ""
    try:
        hosts = _collect_mtu_hosts(nsx_url, nsx_user, nsx_pass,
                                   cluster_filter=cluster_filter or None,
                                   vc_url=vc_url or None,
                                   vc_user=vc_user or None,
                                   vc_pass=vc_pass or None)
        return jsonify({"hosts": hosts})
    except Exception as e:
        return jsonify({"hosts": [], "error": str(e)})


@app.route("/api/check-mtu", methods=["POST"])
def check_mtu():
    """SSH into one ESX host per cluster and vmkping every TEP at the given MTU."""
    import re as _re
    try:
        import paramiko as _paramiko
    except ImportError:
        return jsonify({"error": "paramiko not installed on server (apt install python3-paramiko)",
                        "tests": [], "summary": ""})

    import socket as _socket
    body        = request.get_json(force=True)
    vc_url      = normalize_url(body.get("vc_url", ""))
    vc_user     = body.get("username", "")
    vc_pass     = body.get("password", "")
    nsx_raw     = (body.get("nsx_url") or "").strip()
    nsx_url     = normalize_url(nsx_raw) if nsx_raw else guess_nsx_url(vc_url)
    nsx_user    = body.get("nsx_user") or "admin"
    nsx_pass    = body.get("nsx_pass") or vc_pass
    esx_pass    = body.get("esx_pass") or ""
    mtu_size    = int(body.get("mtu_size") or 1600)
    source_host = (body.get("source_host") or "").strip()   # optional: specific host name/id

    # Determine this VM's IP so we can mention it in error messages
    try:
        vm_ip = _socket.gethostbyname(_socket.gethostname())
    except Exception:
        vm_ip = "this VM"

    result = {"tests": [], "summary": "", "error": None}
    ep = "/policy/api/v1/infra/sites/default/enforcement-points/default"

    try:
        # ── collect HTNs ──────────────────────────────────────────────────────
        htn_resp = nsx_get(nsx_url, nsx_user, nsx_pass, f"{ep}/host-transport-nodes")
        htns     = (htn_resp or {}).get("results", [])
        if not htns:
            result["error"] = "No Host Transport Nodes found via NSX API."
            return jsonify(result)

        # ── per-host: TEP vmk interfaces + overall health ─────────────────────
        class _H:
            def __init__(self, hid, name):
                self.id      = hid
                self.name    = name
                self.short   = name.split(".")[0] if "." in name else name
                self.vmks    = []   # [{"vmk": str, "ip": str}]
                self.healthy = False

        all_hosts: list = []
        all_teps:  list = []   # [{"ip": str, "host": str}]  ← all TEP IPs (ESX + Edge)

        for h in htns:
            hid  = h.get("id", "")
            obj  = _H(hid, h.get("display_name", hid))
            try:
                st = nsx_get(nsx_url, nsx_user, nsx_pass,
                             f"{ep}/host-transport-nodes/{hid}/state")
                if (st or {}).get("state") == "success":
                    obj.healthy = True
                for hs in (st or {}).get("host_switch_states", []):
                    for ep2 in hs.get("endpoints", []):
                        ip    = ep2.get("ip", "")
                        vmk   = ep2.get("device_name", "")
                        stack = ep2.get("net_stack_instance_key", "")
                        if ip and vmk and "overlay" in stack.lower():
                            obj.vmks.append({"vmk": vmk, "ip": ip})
                            all_teps.append({"ip": ip, "host": obj.short})
            except Exception:
                pass
            all_hosts.append(obj)

        # ── add Edge node TEPs as targets ─────────────────────────────────────
        try:
            edge_resp = nsx_get(nsx_url, nsx_user, nsx_pass, f"{ep}/edge-transport-nodes")
            for e in (edge_resp or {}).get("results", []):
                eid  = e.get("id", "")
                ename = e.get("display_name", eid).split(".")[0]
                est   = nsx_get(nsx_url, nsx_user, nsx_pass,
                                f"{ep}/edge-transport-nodes/{eid}/state")
                for hs in (est or {}).get("host_switch_states", []):
                    for ep3 in hs.get("endpoints", []):
                        ip = ep3.get("ip", "")
                        if ip:
                            all_teps.append({"ip": ip, "host": ename})
        except Exception:
            pass

        if not all_teps:
            result["error"] = "No TEP IPs found. Check NSX credentials."
            return jsonify(result)

        # ── pick source host ──────────────────────────────────────────────────
        if source_host:
            # Use the host explicitly chosen by the user
            sources = [h for h in all_hosts
                       if h.name == source_host or h.short == source_host or h.id == source_host]
            if not sources:
                result["error"] = f"Host '{source_host}' not found in NSX Transport Nodes."
                return jsonify(result)
        else:
            healthy = [h for h in all_hosts if h.healthy and h.vmks]
            if not healthy:
                healthy = [h for h in all_hosts if h.vmks]
            sources = healthy[:1] if healthy else []

        if not sources:
            result["error"] = "No ESX host with NSX-overlay VMkernel interfaces found."
            return jsonify(result)

        # ── run vmkping from each source host ─────────────────────────────────
        tests      = []
        fail_count = 0
        import time as _time

        for src in sources:
            # ── 1. Enable SSH via vCenter SOAP (if vCenter creds provided) ────
            ssh_we_enabled = False
            ssh_note       = ""
            if vc_url and vc_user and vc_pass:
                ok, already = _vc_manage_ssh(vc_url, vc_user, vc_pass,
                                             src.name, enable=True)
                if ok and not already:
                    ssh_we_enabled = True
                    _time.sleep(3)   # initial wait for sshd to start
                elif already:
                    ssh_note = "SSH was already enabled"
                else:
                    ssh_note = "Could not enable SSH via vCenter — trying anyway"

            # ── 2. SSH + vmkping ───────────────────────────────────────────────
            ssh = _paramiko.SSHClient()
            ssh.set_missing_host_key_policy(_paramiko.AutoAddPolicy())

            # Retry loop: sshd can take up to ~10s to start after being enabled
            _max_attempts = 6   # × 2s = 12s max wait
            _last_err     = None
            for _attempt in range(_max_attempts):
                try:
                    ssh.connect(src.name, username="root", password=esx_pass,
                                timeout=10, banner_timeout=15,
                                allow_agent=False, look_for_keys=False)
                    _last_err = None
                    break   # connected successfully
                except _paramiko.AuthenticationException:
                    result["error"] = (f"SSH authentication failed for {src.name} — "
                                       f"check ESX root password.")
                    return jsonify(result)
                except Exception as _e:
                    _last_err = _e
                    _es = str(_e).lower()
                    # "Unable to connect" / "Errno None" → sshd not ready yet → retry
                    if ("unable to connect" in _es or "errno none" in _es
                            or "connection refused" in _es):
                        if _attempt < _max_attempts - 1:
                            _time.sleep(2)
                            continue
                    break   # other error — don't retry

            if _last_err:
                _es = str(_last_err).lower()
                if ("unable to connect" in _es or "errno none" in _es
                        or "connection refused" in _es or "timed out" in _es):
                    result["error"] = (
                        f"Cannot reach {src.short} via SSH from this VM ({vm_ip}). "
                        f"Port 22 may be blocked by a firewall between "
                        f"{vm_ip} and {src.name}.")
                else:
                    result["error"] = f"SSH to {src.name} failed: {_last_err}"
                return jsonify(result)

            for vmk_info in src.vmks:
                vmk    = vmk_info["vmk"]
                src_ip = vmk_info["ip"]
                for tgt in all_teps:
                    tgt_ip   = tgt["ip"]
                    tgt_host = tgt["host"]
                    if tgt_ip == src_ip:
                        continue
                    cmd = (f"vmkping -I {vmk} -S vxlan -d -s {mtu_size} "
                           f"-c 2 {tgt_ip} 2>&1")
                    try:
                        _, stdout, _ = ssh.exec_command(cmd, timeout=12)
                        out = stdout.read().decode("utf-8", errors="replace")
                        ok  = (", 0% packet loss" in out or
                               ", 0.0% packet loss" in out)
                        lat = ""
                        for line in out.splitlines():
                            m = _re.search(r"time=(\S+)", line)
                            if m:
                                lat = m.group(1) + " ms"
                                break
                    except Exception as ex:
                        out = str(ex)
                        ok  = False
                        lat = ""
                    tests.append({
                        "from_host": src.short,
                        "from_vmk":  vmk,
                        "from_ip":   src_ip,
                        "to_host":   tgt_host,
                        "to_ip":     tgt_ip,
                        "success":   ok,
                        "latency":   lat,
                    })
                    if not ok:
                        fail_count += 1
            ssh.close()

            # ── 3. Disable SSH if we enabled it ───────────────────────────────
            if ssh_we_enabled and vc_url and vc_user and vc_pass:
                _vc_manage_ssh(vc_url, vc_user, vc_pass, src.name, enable=False)

        result["tests"] = tests
        if not tests:
            result["error"] = "No tests ran — nothing to ping."
        elif fail_count == 0:
            result["summary"] = f"All {len(tests)} MTU {mtu_size} tests PASSED"
        else:
            result["summary"] = f"{fail_count} of {len(tests)} MTU tests FAILED"

    except Exception:
        result["error"] = traceback.format_exc()

    return jsonify(result)


# ── Check VLAN helpers ──────────────────────────────────────────────────────

def _pick_temp_ips(cidr, gateway_cidr, excluded_str, count):
    """Pick up to `count` host IPs from cidr, excluding gateway and excluded ranges."""
    import ipaddress as _ip
    try:
        net = _ip.ip_network(cidr, strict=False)
    except Exception:
        return []
    gw_ip = None
    if gateway_cidr:
        try:
            gw_ip = _ip.ip_address(gateway_cidr.split("/")[0])
        except Exception:
            pass
    excluded: set = set()
    for tok in (excluded_str or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            try:
                a, b = tok.split("-", 1)
                for i in range(int(_ip.ip_address(a.strip())),
                               int(_ip.ip_address(b.strip())) + 1):
                    excluded.add(_ip.ip_address(i))
            except Exception:
                pass
        else:
            try:
                excluded.add(_ip.ip_address(tok))
            except Exception:
                pass
    result: list = []
    for ip in net.hosts():
        if ip == gw_ip or ip in excluded:
            continue
        result.append(str(ip))
        if len(result) >= count:
            break
    return result


def _pcli_setup_vlan_test(vc_url, vc_user, vc_pass, vds_name, pg_name, vlan_id, host_ips,
                          pg_already_exists=False):
    """
    PowerCLI: creates DVPortGroup (unless pg_already_exists) + one vmk per host.
    host_ips: list of (fqdn, ip_str, mask_str) tuples.
    Returns (vmk_map, pg_created, error_str)
      vmk_map: {fqdn: vmk_name}
    """
    import subprocess, tempfile, os, textwrap, re
    vc_host = vc_url.replace("https://", "").replace("http://", "").rstrip("/")

    per_host_lines = []
    for fqdn, ip, mask in host_ips:
        per_host_lines.append(textwrap.dedent(f"""            try {{
                $vmhost = Get-VMHost -Name '{fqdn}'
                Get-VMHostNetworkAdapter -VMHost $vmhost -PortGroup $pg -ErrorAction SilentlyContinue | Remove-VMHostNetworkAdapter -Confirm:$false
                $vmk = New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $vds -PortGroup $pg -IP '{ip}' -SubnetMask '{mask}' -Confirm:$false
                Write-Host "VMK:{fqdn}:$($vmk.Name)"
            }} catch {{
                Write-Host "VMK_ERR:{fqdn}:$($_.Exception.Message)"
            }}"""))

    if pg_already_exists:
        pg_block = f"$pg = Get-VDPortgroup -Name '{pg_name}'"
    else:
        # Before creating the PG, clean up any leftover from a previous run:
        # remove vmknics on every host that still use the old PG, then delete it.
        pg_block = textwrap.dedent(f"""\
            $old_pg = Get-VDPortgroup -Name '{pg_name}' -ErrorAction SilentlyContinue
            if ($old_pg) {{
                foreach ($vmh in (Get-VMHost -ErrorAction SilentlyContinue)) {{
                    try {{
                        Get-VMHostNetworkAdapter -VMHost $vmh -PortGroup $old_pg -ErrorAction SilentlyContinue |
                            Remove-VMHostNetworkAdapter -Confirm:$false
                    }} catch {{}}
                }}
                Start-Sleep -Seconds 2
                $old_pg | Remove-VDPortgroup -Confirm:$false
            }}
            $pg = New-VDPortgroup -VDSwitch $vds -Name '{pg_name}' -VlanId {vlan_id} -NumPorts 16
            Write-Host "PG:CREATED:{pg_name}"
            Start-Sleep -Seconds 3""")

    script = textwrap.dedent(f"""\
        $env:DOTNET_SYSTEM_GLOBALIZATION_INVARIANT = "1"
        $ErrorActionPreference = 'SilentlyContinue'
        Set-PowerCLIConfiguration -Scope Session -ParticipateInCEIP $false -Confirm:$false | Out-Null
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
        $ErrorActionPreference = 'Stop'
        Connect-VIServer -Server '{vc_host}' -User '{vc_user}' -Password '{vc_pass}' -Force | Out-Null
        $vds = Get-VDSwitch -Name '{vds_name}'
        {pg_block}
        {chr(10).join(per_host_lines)}
        Disconnect-VIServer -Confirm:$false | Out-Null
        Write-Host "PCLI_SETUP_DONE"
    """)
    with tempfile.NamedTemporaryFile(suffix=".ps1", mode="w", delete=False, prefix="vcf_setup_") as f:
        f.write(script); script_path = f.name
    try:
        env = os.environ.copy()
        env["DOTNET_SYSTEM_GLOBALIZATION_INVARIANT"] = "1"   # fixes CoreServiceFactory on Ubuntu 24.04
        env.setdefault("HOME", "/root")                      # ensure pwsh can write its config
        r = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", script_path],
                           capture_output=True, text=True, timeout=150, env=env)
        out = r.stdout + r.stderr
        # Strip ANSI escape codes so error messages are readable
        out = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', out)
        if "PCLI_SETUP_DONE" not in out:
            return {}, False, f"PowerCLI setup failed (no DONE marker):\n{out[:2000]}"
        pg_created = "PG:CREATED:" in out
        vmk_map = {}
        for line in out.splitlines():
            if line.startswith("VMK:"):
                parts = line.split(":", 2)
                if len(parts) == 3:
                    vmk_map[parts[1]] = parts[2].strip()
        return vmk_map, pg_created, ""
    except FileNotFoundError:
        return {}, False, "PowerShell (pwsh) not found — install via: snap install powershell --classic"
    except subprocess.TimeoutExpired:
        return {}, False, "PowerCLI timed out during setup (>150s)"
    finally:
        try: os.unlink(script_path)
        except Exception: pass


def _pcli_cleanup_vlan_test(vc_url, vc_user, vc_pass, pg_name, host_fqdns):
    """PowerCLI: removes vmks on all hosts + DVPortGroup (best-effort)."""
    import subprocess, tempfile, os, textwrap
    vc_host = vc_url.replace("https://", "").replace("http://", "").rstrip("/")
    host_array = ", ".join(f"\'{h}\'" for h in host_fqdns)
    script = textwrap.dedent(f"""\
        $env:DOTNET_SYSTEM_GLOBALIZATION_INVARIANT = "1"
        $ErrorActionPreference = 'SilentlyContinue'
        Set-PowerCLIConfiguration -Scope Session -ParticipateInCEIP $false -Confirm:$false | Out-Null
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
        Connect-VIServer -Server '{vc_host}' -User '{vc_user}' -Password '{vc_pass}' -Force | Out-Null
        $pg = Get-VDPortgroup -Name '{pg_name}' -ErrorAction SilentlyContinue
        if ($pg) {{
            foreach ($fqdn in @({host_array})) {{
                try {{
                    $vmhost = Get-VMHost -Name $fqdn
                    Get-VMHostNetworkAdapter -VMHost $vmhost -PortGroup $pg -ErrorAction SilentlyContinue | Remove-VMHostNetworkAdapter -Confirm:$false
                }} catch {{}}
            }}
            $pg | Remove-VDPortgroup -Confirm:$false
        }}
        Disconnect-VIServer -Confirm:$false | Out-Null
    """)
    with tempfile.NamedTemporaryFile(suffix=".ps1", mode="w", delete=False, prefix="vcf_cleanup_") as f:
        f.write(script); script_path = f.name
    try:
        _env2 = os.environ.copy()
        _env2["DOTNET_SYSTEM_GLOBALIZATION_INVARIANT"] = "1"
        _env2.setdefault("HOME", "/root")
        subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", script_path],
                       capture_output=True, text=True, timeout=90, env=_env2)
    except Exception:
        pass
    finally:
        try: os.unlink(script_path)
        except Exception: pass


# ──────────────────────────────────────────────────────────────────────────────
# DNS Connectivity Check  (Deploy Wizard — Step 2 Network)
# ──────────────────────────────────────────────────────────────────────────────

def _pcli_vmk_on_stack(vc_url, vc_user, vc_pass, host_name, pg_name, stack_name,
                        create_pg=False, vds_name=None, vlan_id=None, ip_to_exclude=None):
    """
    PowerCLI: create a VMkernel on a custom TCP/IP stack that was previously
    created on the host via 'esxcli network ip netstack add'.
    No IP is assigned here — caller sets IP via esxcli afterward.

    create_pg=False  Use existing portgroup by name (pg_name).
    create_pg=True   Create a new DVPortGroup on vds_name with vlan_id.

    Returns (vmk_name, vlan_id_int, error_str).
    """
    import subprocess, tempfile, textwrap, re as _re, os
    vc_host = vc_url.replace("https://","").replace("http://","").rstrip("/")

    # Build portgroup block
    if create_pg:
        pg_block = textwrap.dedent(f"""\
            $vds = Get-VDSwitch -Name '{vds_name}' -ErrorAction SilentlyContinue
            if (-not $vds) {{ Write-Host 'ERROR:VDS_NOT_FOUND:{vds_name}'; exit }}
            $old = Get-VDPortgroup -Name '{pg_name}' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($old) {{
                Get-VMHostNetworkAdapter -PortGroup $old -ErrorAction SilentlyContinue |
                    Remove-VMHostNetworkAdapter -Confirm:$false -ErrorAction SilentlyContinue
                Remove-VDPortgroup -VDPortgroup $old -Confirm:$false -ErrorAction SilentlyContinue
            }}
            $pg = New-VDPortgroup -VDSwitch $vds -Name '{pg_name}' -VLanId {vlan_id} -ErrorAction SilentlyContinue
            if (-not $pg) {{ Write-Host 'ERROR:PG_CREATE_FAILED'; exit }}
        """)
    else:
        pg_block = textwrap.dedent(f"""\
            $pg  = Get-VDPortgroup -Name '{pg_name}' -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $pg) {{ Write-Host 'ERROR:PG_NOT_FOUND:{pg_name}'; exit }}
            $vds = $pg.VDSwitch
        """)

    excl_block = ""
    if ip_to_exclude:
        excl_block = textwrap.dedent(f"""\
            $stale = Get-VMHostNetworkAdapter -VMHost $vmhost -ErrorAction SilentlyContinue |
                         Where-Object {{ $_.IP -eq '{ip_to_exclude}' }}
            if ($stale) {{
                Write-Host "PRE_CLEAN:$($stale.Name)"
                Remove-VMHostNetworkAdapter -NetworkAdapter $stale -Confirm:$false -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }}
        """)

    script = textwrap.dedent(f"""\
        $env:DOTNET_SYSTEM_GLOBALIZATION_INVARIANT = "1"
        $ErrorActionPreference = 'SilentlyContinue'
        Set-PowerCLIConfiguration -Scope Session -ParticipateInCEIP $false -Confirm:$false | Out-Null
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
        Connect-VIServer -Server '{vc_host}' -User '{vc_user}' -Password '{vc_pass}' -Force | Out-Null
        $vmhost = Get-VMHost -Name '{host_name}' -ErrorAction SilentlyContinue
        if (-not $vmhost) {{ Write-Host 'ERROR:VMHOST_NOT_FOUND'; exit }}
        {excl_block}
        {pg_block}
        # Get VLAN ID from portgroup
        $vlanCfg = $pg.VlanConfiguration
        $vlanId  = if ($vlanCfg -ne $null -and $vlanCfg.VlanId -ne $null) {{ $vlanCfg.VlanId }} else {{ 0 }}
        Write-Host "VLAN_ID:$vlanId"
        # Find the custom stack (must already exist — created via esxcli before this call)
        $stack = Get-VMHostNetworkStack -VMHost $vmhost -ErrorAction SilentlyContinue |
                     Where-Object {{ $_.Name -eq '{stack_name}' }}
        if (-not $stack) {{ Write-Host 'ERROR:STACK_NOT_FOUND:{stack_name}'; exit }}
        # Create vmk on the custom stack — NO -IP, caller sets IP via esxcli
        $vmk = New-VMHostNetworkAdapter -VMHost $vmhost `
                   -PortGroup $pg -VirtualSwitch $vds `
                   -NetworkStack $stack `
                   -ErrorAction SilentlyContinue
        if (-not $vmk) {{ Write-Host 'ERROR:VMK_CREATE_FAILED'; exit }}
        Write-Host "VMK_NAME:$($vmk.Name)"
        Write-Host "STACK_VMK_DONE"
        Disconnect-VIServer -Confirm:$false | Out-Null
    """)
    with tempfile.NamedTemporaryFile(suffix=".ps1", mode="w", delete=False, prefix="vmk_stack_") as f:
        f.write(script); script_path = f.name
    try:
        env = __import__("os").environ.copy()
        env["DOTNET_SYSTEM_GLOBALIZATION_INVARIANT"] = "1"
        env.setdefault("HOME", "/root")
        r = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", script_path],
                           capture_output=True, text=True, timeout=120, env=env)
        out = _re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', r.stdout + r.stderr)
        if "STACK_VMK_DONE" not in out:
            return None, None, f"PowerCLI vmk-on-stack failed:\n{out[:1500]}"
        vmk_name = vlan_id_out = None
        for line in out.splitlines():
            if line.startswith("VMK_NAME:"): vmk_name = line.split(":",1)[1].strip()
            if line.startswith("VLAN_ID:"):
                try: vlan_id_out = int(line.split(":",1)[1].strip())
                except: vlan_id_out = 0
            if line.startswith("ERROR:"):
                return None, None, line[6:]
        return vmk_name, (vlan_id_out or 0), ""
    except subprocess.TimeoutExpired:
        return None, None, "PowerCLI timed out (>120s)"
    finally:
        try: __import__("os").unlink(script_path)
        except: pass


def _pcli_dns_vmk_remove(vc_url, vc_user, vc_pass, host_fqdn, vmk_name, ip=""):
    """PowerCLI: remove the temp vmk created for the DNS check.
    Looks up by name (Where-Object pipe) AND by IP as fallback — both reliable."""
    if not vmk_name and not ip:
        return
    import subprocess, tempfile, textwrap, os
    vc_host = vc_url.replace("https://","").replace("http://","").rstrip("/")
    script = textwrap.dedent(f"""\
        $env:DOTNET_SYSTEM_GLOBALIZATION_INVARIANT = "1"
        $ErrorActionPreference = 'SilentlyContinue'
        Set-PowerCLIConfiguration -Scope Session -ParticipateInCEIP $false -Confirm:$false | Out-Null
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
        Connect-VIServer -Server '{vc_host}' -User '{vc_user}' -Password '{vc_pass}' -Force | Out-Null
        $vmhost = Get-VMHost -Name '{host_fqdn}'
        $allVmks = Get-VMHostNetworkAdapter -VMHost $vmhost
        # Strategy 1: remove by name (pipe through Where-Object, reliable for vmkernel)
        if ('{vmk_name}') {{
            $byName = $allVmks | Where-Object {{ $_.Name -eq '{vmk_name}' }}
            if ($byName) {{
                Remove-VMHostNetworkAdapter -NetworkAdapter $byName -Confirm:$false
                Write-Host "REMOVED_BY_NAME:{vmk_name}"
            }}
        }}
        # Strategy 2: remove by IP (belt-and-suspenders for stale adapters)
        if ('{ip}') {{
            $allVmks2 = Get-VMHostNetworkAdapter -VMHost $vmhost
            $byIp = $allVmks2 | Where-Object {{ $_.IP -eq '{ip}' }}
            if ($byIp) {{
                Remove-VMHostNetworkAdapter -NetworkAdapter $byIp -Confirm:$false
                Write-Host "REMOVED_BY_IP:{ip}"
            }}
        }}
        Disconnect-VIServer -Confirm:$false | Out-Null
        Write-Host "CLEANUP_DONE"
    """)
    with tempfile.NamedTemporaryFile(suffix=".ps1", mode="w", delete=False, prefix="dns_clean_") as f:
        f.write(script); script_path = f.name
    try:
        env = os.environ.copy()
        env["DOTNET_SYSTEM_GLOBALIZATION_INVARIANT"] = "1"
        env.setdefault("HOME", "/root")
        subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", script_path],
                       capture_output=True, text=True, timeout=90, env=env)
    except Exception:
        pass
    finally:
        try: os.unlink(script_path)
        except Exception: pass


def _pcli_get_pg_vlan(vc_url, vc_user, vc_pass, pg_name, pg_moref=None):
    """Return the integer VLAN ID of a DVPortGroup.
    NOTE: $pg.VLanId is unreliable (often empty).
    The correct path is ExtensionData.Config.DefaultPortConfig.Vlan.VlanId.
    Uses Get-VDPortgroup -Name (confirmed working); moref is kept for future use."""
    import subprocess, tempfile, os, textwrap
    vc_host = vc_url.replace("https://","").replace("http://","").rstrip("/")
    # Always use -Name lookup: confirmed to return correct ExtensionData VLAN
    lookup = pg_name or pg_moref or ""
    if not lookup:
        return None
    # Use -Name if we have it (more human-readable in logs); if only moref, try -Id
    if pg_name:
        pg_selector = f"-Name '{pg_name}'"
    else:
        pg_selector = f"-Id '{pg_moref}'"
    script = textwrap.dedent(f"""\
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
        Connect-VIServer -Server '{vc_host}' -User '{vc_user}' -Password '{vc_pass}' | Out-Null
        $pg = Get-VDPortgroup {pg_selector} -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($pg) {{
            $pg.ExtensionData.Config.DefaultPortConfig.Vlan.VlanId
        }}
        Disconnect-VIServer -Confirm:$false | Out-Null
    """)
    with tempfile.NamedTemporaryFile(suffix=".ps1", delete=False, mode="w") as f:
        f.write(script); fname = f.name
    try:
        r = subprocess.run(["pwsh", "-NonInteractive", "-NoProfile", "-File", fname],
                           capture_output=True, text=True, timeout=45)
        for line in reversed(r.stdout.strip().splitlines()):
            line = line.strip()
            if line.lstrip("-").isdigit():
                return int(line)
        return None
    except Exception:
        return None
    finally:
        try: os.unlink(fname)
        except: pass


@app.route("/api/dns-check-hosts", methods=["POST"])
def dns_check_hosts():
    """Return ESX hosts in a given cluster for the DNS check host selector.
    Also returns preview data: management PG VLAN, workload DVLAN VLAN + first available IP.
    """
    body       = request.get_json(force=True)
    vc_url     = normalize_url(body.get("vc_url", ""))
    vc_user    = body.get("vc_user", "") or body.get("username", "")
    vc_pass    = body.get("vc_pass", "") or body.get("password", "")
    zone_id    = (body.get("zone_id") or "").strip()
    pg_name    = (body.get("port_group_name") or "").strip()
    pg_moref   = (body.get("port_group_id")   or "").strip()   # e.g. "dvportgroup-24"
    nsx_raw    = (body.get("nsx_url") or "").strip()
    nsx_url    = normalize_url(nsx_raw) if nsx_raw else guess_nsx_url(vc_url)
    nsx_user   = body.get("nsx_user", "")
    nsx_pass   = body.get("nsx_pass", "")
    try:
        token, _ = vc_auth(vc_url, vc_user, vc_pass)

        # ── Resolve cluster IDs for the zone (always fresh from vCenter) ─────
        # Priority: (1) use zone_id → fetch live zone-associations
        #           (2) fall back to cluster_morefs list from frontend
        #           (3) fall back to single cluster_moref
        # Multi-zone deployments select SEVERAL zones (zone_ids): every cluster of
        # every selected zone must be offered, not just the first zone's.
        zone_ids = [z for z in (body.get("zone_ids") or []) if z]
        if zone_id and zone_id not in zone_ids:
            zone_ids.insert(0, zone_id)
        cluster_ids = []
        if zone_ids:
            try:
                _ar = vc_get(vc_url, token,
                             "/api/vcenter/consumption-domains/zone-associations/cluster")
                _assocs = (_ar.get("associations", [])
                           if isinstance(_ar, dict) else _ar or [])
                for _zid in zone_ids:
                    for _a in _assocs:
                        if (_a.get("zone") == _zid and
                                _a.get("state", "ASSOCIATED") == "ASSOCIATED"):
                            cluster_ids.append(_a.get("cluster", ""))
            except Exception:
                pass
        # Also honour the cluster list sent by the frontend (union, de-duplicated)
        cluster_ids += [c for c in (body.get("cluster_morefs") or []) if c]
        if not cluster_ids:
            single = (body.get("cluster_moref") or "").strip()
            if single:
                cluster_ids = [single]
        cluster_ids = list(dict.fromkeys(c for c in cluster_ids if c))

        # Cluster names, so the host selector can show where each host lives
        _cl_names = {}
        try:
            _cl_names = {c.get("cluster"): c.get("name", "")
                         for c in (vc_get(vc_url, token, "/api/vcenter/cluster") or [])}
        except Exception:
            pass

        # Collect hosts from ALL selected clusters (dedup by name)
        seen_names = set()
        hosts = []
        for cluster_id in cluster_ids:
            raw = vc_get(vc_url, token, "/api/vcenter/host",
                         params={"clusters": cluster_id}) or []
            for h in raw:
                hname = h.get("name", "")
                if hname and hname not in seen_names:
                    seen_names.add(hname)
                    hosts.append({"name": hname, "short": hname.split(".")[0],
                                  "cluster": cluster_id,
                                  "cluster_name": _cl_names.get(cluster_id, "")})

        # ── Preview: management portgroup VLAN ──────────────────────────────
        mgt_vlan = None
        if pg_moref or pg_name:
            try: mgt_vlan = _pcli_get_pg_vlan(vc_url, vc_user, vc_pass, pg_name, pg_moref)
            except Exception: pass

        # ── Preview: workload DVLAN VLAN + first available temp IP ──────────
        wld_vlan = None; wld_preview_ip = None; wld_gateway = None
        if nsx_url and nsx_user and nsx_pass:
            try:
                import ipaddress as _ip
                _dvlans = (nsx_get(nsx_url, nsx_user, nsx_pass,
                    "/policy/api/v1/infra/distributed-vlan-connections") or {}).get("results", [])
                if _dvlans:
                    _dv = _dvlans[0]
                    wld_vlan = _dv.get("vlan_id")
                    _gws = _dv.get("gateway_addresses") or []
                    if _gws:
                        _gw_cidr  = _gws[0]
                        wld_gateway = _gw_cidr.split("/")[0]
                        _wld_net  = _ip.ip_interface(_gw_cidr).network
                        _blks = (nsx_get(nsx_url, nsx_user, nsx_pass,
                            "/policy/api/v1/infra/ip-blocks") or {}).get("results", [])
                        for _b in _blks:
                            if (_b.get("visibility") or "").upper() != "EXTERNAL":
                                continue
                            _cidr = _block_cidr(_b, nsx_url, nsx_user, nsx_pass)
                            try:
                                if _cidr and _ip.ip_network(_cidr, strict=False).overlaps(_wld_net):
                                    _fb  = nsx_get(nsx_url, nsx_user, nsx_pass,
                                        f"/policy/api/v1/infra/ip-blocks/{_b.get('id','')}") or _b
                                    _ips = _pick_temp_ips(_cidr, _gw_cidr, _nsx_excl_to_str(_fb), 1)
                                    if _ips: wld_preview_ip = _ips[0]
                                    break
                            except Exception: pass
            except Exception: pass

        return jsonify({"hosts": hosts,
                        "mgt_vlan": mgt_vlan,
                        "wld_vlan": wld_vlan,
                        "wld_preview_ip": wld_preview_ip,
                        "wld_gateway": wld_gateway,
                        "_debug_zone_id": zone_id,
                        "_debug_cluster_ids": cluster_ids})
    except Exception as e:
        return jsonify({"hosts": [], "error": str(e)})


@app.route("/api/check-dns-connectivity", methods=["POST"])
def check_dns_connectivity():
    """
    Deploy-wizard Step 2: verify management-VLAN connectivity for a single ESX host.
    1. Enable SSH on selected host.
    2. Create temp vmk on the selected management Port Group with the first Control-Plane IP.
       (Pre-cleans any stale vmk with that IP before creating.)
    3. vmkping gateway, vmkping DNS server, nslookup domain.
    4. Always removes the temp vmk and restores SSH state in the finally block.
    """
    body       = request.get_json(force=True)
    vc_url     = normalize_url(body.get("vc_url", ""))
    vc_user    = body.get("vc_user", "")
    vc_pass    = body.get("vc_pass", "")
    cluster_id    = body.get("cluster_moref", "")
    selected_host = (body.get("selected_host") or "").strip()
    pg_name       = body.get("port_group_name") or body.get("port_group_id", "")
    first_ip_raw  = body.get("first_ip", "")
    gateway_cidr  = body.get("gateway_cidr", "")
    ip_mode       = body.get("ip_mode", "static")
    dns_raw       = body.get("dns_servers", "")
    search_dom    = (body.get("search_domain") or "").strip()
    esx_pass      = body.get("esx_pass", "")

    first_ip = re.split(r'[-/\s]', first_ip_raw.strip())[0].strip()
    if not first_ip and ip_mode != "dhcp":
        return jsonify({"success": False, "error": "No Control-Plane IP provided"})
    try:    prefix = int(gateway_cidr.split("/")[-1])
    except: prefix = 24
    gw_ip    = gateway_cidr.split("/")[0].strip()
    dns_list = [s.strip() for s in re.split(r'[,\s]+', dns_raw) if s.strip()]
    if not dns_list and ip_mode != "dhcp":
        return jsonify({"success": False, "error": "No DNS server specified"})
    dns_ip = dns_list[0] if dns_list else ""

    ntp_raw  = body.get("ntp_servers", "")
    ntp_list = [s.strip() for s in re.split(r'[,\s]+', ntp_raw) if s.strip()]
    ntp_ip   = ntp_list[0] if ntp_list else ""

    def _ntp_check(run_fn, stack_name, ntp_server, timeout=12):
        """Check NTP server reachability via ICMP from the custom TCP/IP stack.

        Uses vmkping -S <stack> so the ping is routed through the dedicated
        VLAN stack (same interface/routing as the gateway ping), not the
        default management vmk.

        Note: ESXi tools cannot send a real NTP protocol request from a custom
        stack — nc and Python sockets always use the default management stack.
        ICMP reachability from the correct VLAN is the best we can do here.

        Returns ('pass'|'fail', raw_ping_output)
        """
        p_out, p_err = run_fn(
            f"vmkping -S {stack_name} -c 3 -W 2 {ntp_server} 2>&1", timeout=12)
        ping_ok = ", 0% packet loss" in p_out or "bytes from" in p_out
        return ("pass" if ping_ok else "fail"), (p_out + p_err).strip()

    result = {
        "success": False, "error": "",
        "host": "", "vmk": "", "vlan_id": None, "ip_used": first_ip,
        "ip_mode": ip_mode,
        "gw_ping": None, "dns_ping": None, "dns_resolve": None,
        "mgt_ntp_check": None, "mgt_ntp_server": ntp_ip, "mgt_ntp_detail": "",
        "gw_ping_output": "", "dns_ping_output": "", "dns_resolve_output": "",
        "dns_domain": "",
        "ip_free_checks": [],
        "vc_ping_check": None, "vc_ping_host": "", "vc_ping_output": "",
        "nsx_ping_check": None, "nsx_ping_host": "", "nsx_ping_output": "",
        # DHCP mode extra
        "dhcp_ip_received": None, "dhcp_ip": "",
        # Workload network test results
        "wld_vmk": "", "wld_vlan_id": None, "wld_ip_used": "", "wld_gateway": "",
        "wld_gw_ping": None, "wld_dns_ping": None, "wld_dns_resolve": None,
        "wld_ntp_check": None, "wld_ntp_server": ntp_ip, "wld_ntp_detail": "",
        "wld_gw_ping_output": "", "wld_dns_ping_output": "", "wld_dns_resolve_output": "",
        "wld_dns_domain": "", "wld_error": "",
    }
    vmk_name = None; host_name = ""; ssh_was_on = None
    vmk_removed_via_ssh = False   # always defined — referenced in outer finally

    try:
        import time as _time, paramiko as _para
    except ImportError as e:
        result["error"] = f"Missing dependency: {e}"
        return jsonify(result)

    try:
        token, _ = vc_auth(vc_url, vc_user, vc_pass)

        hosts = vc_get(vc_url, token, "/api/vcenter/host",
                       params={"clusters": cluster_id}) or []
        if not hosts:
            result["error"] = "No ESX hosts found in the selected cluster"
            return jsonify(result)
        host_name = selected_host if selected_host else hosts[0].get("name", "")
        result["host"] = host_name

        ok_ssh, ssh_was_on = _vc_manage_ssh(vc_url, vc_user, vc_pass, host_name, True)
        if not ok_ssh:
            result["error"] = f"Could not enable SSH on {host_name} via vCenter"
            return jsonify(result)
        if not ssh_was_on:
            _time.sleep(5)

        # ── Management DNS test — custom TCP/IP stack approach ────────────────
        # Flow (mirrors the user-validated manual sequence):
        #  1. SSH conn-1: remove stale stack (if any) + create fresh custom stack
        #     (ESXi may drop this SSH session when the netstack changes — that's OK)
        #  2. PowerCLI: New-VMHostNetworkAdapter -NetworkStack $MyStack (no -IP)
        #  3. SSH conn-2 (fresh): set IP + add default route on stack + run tests
        #     (vmkping -S <stack> reaches cross-subnet DNS via the default route)
        #  4. SSH conn-2 finally: remove vmk + stack; PowerCLI outer finally removes
        #     the portgroup only if needed.
        # ──────────────────────────────────────────────────────────────────────
        import ipaddress as _ipa
        mgt_stack = "vcf-dns-mgt-chk"
        mask      = str(_ipa.IPv4Network(f"0.0.0.0/{prefix}").netmask)

        # Step 1 — SSH conn-1: create the custom stack
        _ssh1 = _para.SSHClient()
        _ssh1.set_missing_host_key_policy(_para.AutoAddPolicy())
        for _att in range(6):
            try:
                _ssh1.connect(host_name, username="root", password=esx_pass, timeout=10)
                break
            except _para.AuthenticationException:
                raise RuntimeError(
                    f"ESX root password incorrect for {host_name}. "
                    "Please enter the correct password and run again.")
            except Exception:
                if _att < 5: _time.sleep(2)
                else: raise RuntimeError(
                    f"Cannot reach {host_name} via SSH. "
                    "Check that port 22 is reachable from this VM.")
        try:
            _ssh1.exec_command(
                f"esxcli network ip netstack remove -N {mgt_stack} 2>/dev/null",
                timeout=10)[1].read()
            _time.sleep(1)
            _ssh1.exec_command(
                f"esxcli network ip netstack add -N {mgt_stack} 2>/dev/null",
                timeout=15)[1].read()
        finally:
            try: _ssh1.close()
            except: pass
        _time.sleep(5)   # wait for ESXi to settle after netstack add

        # Step 2 — PowerCLI: create vmk on the custom stack (no IP assigned yet)
        vmk_name, vlan_id, pcli_err = _pcli_vmk_on_stack(
            vc_url, vc_user, vc_pass, host_name, pg_name, mgt_stack,
            create_pg=False, ip_to_exclude=first_ip)
        if pcli_err:
            result["error"] = f"PowerCLI vmk-on-stack failed: {pcli_err}"
            return jsonify(result)
        result["vmk"]     = vmk_name or ""
        result["vlan_id"] = vlan_id
        _time.sleep(2)

        # Step 3 — SSH conn-2: set IP + route + tests
        ssh_client = _para.SSHClient()
        ssh_client.set_missing_host_key_policy(_para.AutoAddPolicy())
        try:
            for attempt in range(6):
                try:
                    ssh_client.connect(host_name, username="root",
                                       password=esx_pass, timeout=10)
                    break
                except _para.AuthenticationException:
                    raise RuntimeError(
                        f"ESX root password incorrect for {host_name}. "
                        "Please enter the correct password and run again.")
                except Exception:
                    if attempt < 5: _time.sleep(2)
                    else: raise RuntimeError(
                        f"Cannot reach {host_name} via SSH. "
                        "Check that port 22 is reachable from this VM.")

            def _run(cmd, timeout=30):
                _, so, se = ssh_client.exec_command(cmd, timeout=timeout)
                return so.read().decode("utf-8","replace"), se.read().decode("utf-8","replace")

            if ip_mode == "dhcp":
                # ── DHCP mode: skip management test ────────────────────────
                # Supervisor IPs come from DHCP; can't pre-test management
                # connectivity without a known IP.  Skip all management checks
                # and proceed directly to the workload test.
                result["gw_ping"]        = "skip"
                result["dns_ping"]       = "skip"
                result["dns_resolve"]    = "skip"
                result["mgt_ntp_check"]  = "skip"
                result["ip_free_checks"] = []
                result["vc_ping_check"]  = "skip"
                result["nsx_ping_check"] = "skip"
                result["dhcp_skipped"]   = True
                result["success"]        = True

            else:
                # ── STATIC IP mode ────────────────────────────────────────
                # Configure IP and default route on the custom stack
                _run(f"esxcli network ip interface ipv4 set"
                     f" -i {vmk_name} -I {first_ip} -N {mask} -t static 2>/dev/null",
                     timeout=10)
                _run(f"esxcli network ip route ipv4 add"
                     f" --gateway={gw_ip} --network=default -N {mgt_stack} 2>/dev/null",
                     timeout=10)
                _time.sleep(1)

                # 1. Gateway ping — uses the stack's routing (same subnet → direct)
                gw_out, gw_err = _run(
                    f"vmkping -S {mgt_stack} -c 3 -W 2 {gw_ip}", timeout=30)
                gw_pass = ", 0% packet loss" in gw_out or "bytes from" in gw_out
                result["gw_ping"]        = "pass" if gw_pass else "fail"
                result["gw_ping_output"] = (gw_out + gw_err).strip()

            # 1b → 6: static-mode only tests (DHCP already ran its own branch above)
            if ip_mode != "dhcp":
                # 1b. NTP check
                if ntp_ip:
                    result["mgt_ntp_check"], result["mgt_ntp_detail"] = \
                        _ntp_check(_run, mgt_stack, ntp_ip)
                else:
                    result["mgt_ntp_check"] = "skip"
                    result["mgt_ntp_detail"] = ""

                # 2. DNS server ping
                dn_out, dn_err = _run(
                    f"vmkping -S {mgt_stack} -c 3 -W 2 {dns_ip}", timeout=30)
                dn_pass = ", 0% packet loss" in dn_out or "bytes from" in dn_out
                result["dns_ping"]        = "pass" if dn_pass else "fail"
                result["dns_ping_output"] = (dn_out + dn_err).strip()

                # 3. DNS resolution — vCenter FQDN
                def _nslookup(query):
                    _o, _e = _run(f"nslookup {query} {dns_ip} 2>&1", timeout=15)
                    if not _o.strip():
                        _o, _e = _run(f"busybox nslookup {query} {dns_ip} 2>&1", timeout=15)
                    return (_o + _e).strip()

                def _parse_ptr(output):
                    import re as _r2
                    for _ln in output.splitlines():
                        _m = _r2.search(r'name\s*=\s*(\S+)', _ln, _r2.IGNORECASE)
                        if _m:
                            return _m.group(1).rstrip('.')
                    for _ln in output.splitlines():
                        if not _ln.strip().lower().startswith("address"):
                            continue
                        _parts = _ln.split(":", 1)
                        if len(_parts) < 2:
                            continue
                        _val = _parts[1].strip().rstrip('.')
                        if '#' in _val:
                            continue
                        if ('.' in _val and
                                not _val.replace('.','').replace('-','').replace('_','').isdigit()):
                            return _val
                    return ""

                def _fwd_passed(output):
                    return ("Name:" in output and
                            "can't find"  not in output and
                            "NXDOMAIN"    not in output and
                            "REFUSED"     not in output and
                            "timed out"   not in output.lower())

                _vc_host_raw = (urlparse(vc_url).hostname or "").strip()
                _vc_is_ip    = bool(_vc_host_raw) and all(
                    p.isdigit() for p in _vc_host_raw.split(".") if p)

                if _vc_is_ip:
                    rev_out  = _nslookup(_vc_host_raw)
                    _vc_fqdn = _parse_ptr(rev_out)
                    if _vc_fqdn:
                        fwd_out    = _nslookup(_vc_fqdn)
                        ns_pass    = _fwd_passed(fwd_out)
                        ns_combined = (
                            f"Reverse lookup ({_vc_host_raw} → PTR):\n{rev_out}"
                            f"\n\nForward lookup ({_vc_fqdn}):\n{fwd_out}"
                        )
                        result["dns_domain"] = _vc_fqdn
                    else:
                        ns_pass     = False
                        ns_combined = (
                            f"Reverse lookup ({_vc_host_raw} → PTR):\n{rev_out}"
                            f"\n\n(No PTR record — cannot perform forward lookup)"
                        )
                        result["dns_domain"] = f"{_vc_host_raw} (PTR)"
                else:
                    fwd_out    = _nslookup(_vc_host_raw)
                    ns_pass    = _fwd_passed(fwd_out)
                    ns_combined = fwd_out
                    result["dns_domain"] = _vc_host_raw

                result["dns_resolve"]        = "pass" if ns_pass else "fail"
                result["dns_resolve_output"] = ns_combined[:800]

                # 4. Ping Supervisor IPs+1..+4 via DEFAULT stack
                import ipaddress as _ipa3
                _base_int = int(_ipa3.ip_address(first_ip))
                _ip_free_checks = []
                for _i in range(1, 5):
                    try:
                        _other_ip = str(_ipa3.ip_address(_base_int + _i))
                        _p_out2, _p_err2 = _run(
                            f"vmkping -c 2 -W 1 {_other_ip} 2>&1", timeout=8)
                        _in_use = ", 0% packet loss" in _p_out2 or "bytes from" in _p_out2
                        _ip_free_checks.append({
                            "ip": _other_ip, "free": not _in_use,
                            "output": (_p_out2 + _p_err2).strip()})
                    except Exception:
                        pass
                result["ip_free_checks"] = _ip_free_checks

                # 5. vCenter ping
                _vc_host_ping = (urlparse(vc_url).hostname or "").strip()
                if _vc_host_ping:
                    _vc_p_out, _vc_p_err = _run(
                        f"vmkping -c 3 -W 2 {_vc_host_ping} 2>&1", timeout=15)
                    _vc_ping_ok = ", 0% packet loss" in _vc_p_out or "bytes from" in _vc_p_out
                    result["vc_ping_check"]  = "pass" if _vc_ping_ok else "fail"
                    result["vc_ping_host"]   = _vc_host_ping
                    result["vc_ping_output"] = (_vc_p_out + _vc_p_err).strip()
                else:
                    result["vc_ping_check"] = "skip"
                    result["vc_ping_host"]  = ""

                # 6. NSX ping
                _nsx_raw2  = (body.get("nsx_url") or "").strip()
                _nsx_url2  = normalize_url(_nsx_raw2) if _nsx_raw2 else guess_nsx_url(vc_url)
                _nsx_host2 = (urlparse(_nsx_url2).hostname or "").strip()
                if _nsx_host2:
                    _nsx_p_out, _nsx_p_err = _run(
                        f"vmkping -c 3 -W 2 {_nsx_host2} 2>&1", timeout=15)
                    _nsx_ping_ok = ", 0% packet loss" in _nsx_p_out or "bytes from" in _nsx_p_out
                    result["nsx_ping_check"]  = "pass" if _nsx_ping_ok else "fail"
                    result["nsx_ping_host"]   = _nsx_host2
                    result["nsx_ping_output"] = (_nsx_p_out + _nsx_p_err).strip()
                else:
                    result["nsx_ping_check"] = "skip"
                    result["nsx_ping_host"]  = ""

                result["success"] = True
                # end of ip_mode != "dhcp" block — DHCP mode sets success within its own branch

        finally:
            # Primary cleanup: remove vmk then custom stack via esxcli.
            # Runs whether tests passed, failed, or raised — SSH conn-2 is still open.
            if vmk_name:
                try:
                    _run(f"esxcli network ip interface remove -i {vmk_name}", timeout=15)
                    vmk_removed_via_ssh = True
                except Exception: pass
            try:
                _run(f"esxcli network ip netstack remove -N {mgt_stack}", timeout=15)
            except Exception: pass
            try: ssh_client.close()
            except Exception: pass

        # ══════════════════════════════════════════════════════════════════════
        # WORKLOAD DNS TEST
        # Uses a DEDICATED TCP/IP stack so routing goes through the workload
        # gateway (not the management gateway), correctly simulating what
        # Supervisor pods will do.
        #
        # Flow:
        #  1. NSX  → DVLAN info + temp IP from External IP Block
        #  2. PowerCLI → create DVPortGroup only (returns portgroup moref key)
        #  3. SSH/esxcli → create custom netstack + attach vmk + set IP + route
        #  4. SSH → vmkping gateway, vmkping DNS, nslookup <wld_test_host>
        #  5. SSH/esxcli → remove vmk + custom stack
        #  6. PowerCLI → remove portgroup
        # ══════════════════════════════════════════════════════════════════════
        import ipaddress as _ip2
        _nsx_raw      = (body.get("nsx_url") or "").strip()
        _nsx_url      = normalize_url(_nsx_raw) if _nsx_raw else guess_nsx_url(vc_url)
        _nsx_user     = body.get("nsx_user", "") or vc_user
        _nsx_pass     = body.get("nsx_pass", "") or vc_pass
        _dns_wld_raw  = body.get("dns_servers_workload", "") or dns_raw
        _dns_wld      = [s.strip() for s in re.split(r'[,\s]+', _dns_wld_raw) if s.strip()] or dns_list
        _wld_test_host = (body.get("dns_workload_test_host") or "github.com").strip() or "github.com"

        wld_pg_name  = None; wld_vmk_name = None; wld_temp_ip = ""
        wld_stack    = "vcf-dns-wld-chk"

        try:
            # ── 1. DVLAN connection details ──────────────────────────────────
            _dvlans = (nsx_get(_nsx_url, _nsx_user, _nsx_pass,
                "/policy/api/v1/infra/distributed-vlan-connections") or {}).get("results", [])
            if not _dvlans:
                result["wld_error"] = (
                    "No Distributed External Connection found — "
                    "run 'Check Distributed External Connection' first.")
            else:
                _dvlan       = _dvlans[0]
                _wld_vlan    = _dvlan.get("vlan_id", 0)
                _wld_gw_list = _dvlan.get("gateway_addresses") or []
                if not _wld_gw_list:
                    result["wld_error"] = "DVLAN has no gateway address — check NSX config."
                else:
                    _wld_gw_cidr = _wld_gw_list[0]
                    _wld_gw_ip   = _wld_gw_cidr.split("/")[0]
                    _wld_prefix  = int(_wld_gw_cidr.split("/")[1])
                    _wld_mask    = str(_ip2.IPv4Network(f"0.0.0.0/{_wld_prefix}").netmask)
                    _wld_net     = _ip2.ip_interface(_wld_gw_cidr).network

                    # ── 2. NSX VDS name for the selected host ────────────────
                    _htns = (nsx_get(_nsx_url, _nsx_user, _nsx_pass,
                        "/policy/api/v1/infra/sites/default/enforcement-points"
                        "/default/host-transport-nodes") or {}).get("results", [])
                    # Build per-host map; use the selected host's own VDS so the
                    # temp portgroup is created on the correct cluster's VDS.
                    _host_vds_map_wld: dict = {}
                    for _h in _htns:
                        _hfqdn = ((_h.get("node_deployment_info") or {}).get("fqdn")
                                  or _h.get("display_name", ""))
                        for _hs in (_h.get("host_switch_spec") or {}).get("host_switches") or []:
                            _vn = _hs.get("host_switch_name", "")
                            if _vn and _hfqdn:
                                _host_vds_map_wld[_hfqdn] = _vn
                                break
                    # Prefer the selected host's VDS; fall back to any known VDS
                    _nsx_vds = (_host_vds_map_wld.get(host_name)
                                or next(iter(_host_vds_map_wld.values()), ""))
                    if not _nsx_vds:
                        result["wld_error"] = "Could not determine NSX VDS name."
                    else:
                        # ── 3. External IP Block ──────────────────────────────
                        _all_blocks = (nsx_get(_nsx_url, _nsx_user, _nsx_pass,
                            "/policy/api/v1/infra/ip-blocks") or {}).get("results", [])
                        _blk_cidr = None; _blk_excl = None
                        for _b in _all_blocks:
                            if (_b.get("visibility") or "").upper() != "EXTERNAL":
                                continue
                            _cidr2 = _block_cidr(_b, _nsx_url, _nsx_user, _nsx_pass)
                            try:
                                if _cidr2 and _ip2.ip_network(_cidr2, strict=False).overlaps(_wld_net):
                                    _blk_cidr = _cidr2
                                    _full_b   = nsx_get(_nsx_url, _nsx_user, _nsx_pass,
                                        f"/policy/api/v1/infra/ip-blocks/{_b.get('id','')}") or _b
                                    _blk_excl = _nsx_excl_to_str(_full_b)
                                    break
                            except Exception: pass
                        if not _blk_cidr:
                            result["wld_error"] = "No External IP Block found overlapping the DVLAN subnet."
                        else:
                            _wld_ips = _pick_temp_ips(_blk_cidr, _wld_gw_cidr, _blk_excl, 1)
                            if not _wld_ips:
                                result["wld_error"] = "No available IP in External IP Block."
                            else:
                                wld_temp_ip  = _wld_ips[0]
                                wld_pg_name  = f"vcf-dns-wld-check-{_wld_vlan}"
                                result["wld_vlan_id"] = _wld_vlan
                                result["wld_ip_used"] = wld_temp_ip
                                result["wld_gateway"] = _wld_gw_ip

                                # ── 4. SSH conn-w1: create custom workload stack ─
                                wld_stack = "vcf-dns-wld-chk"
                                _wld_ssh1 = _para.SSHClient()
                                _wld_ssh1.set_missing_host_key_policy(_para.AutoAddPolicy())
                                try:
                                    _wld_ssh1.connect(host_name, username="root",
                                                      password=esx_pass, timeout=10)
                                    _wld_ssh1.exec_command(
                                        f"esxcli network ip netstack remove"
                                        f" -N {wld_stack} 2>/dev/null",
                                        timeout=10)[1].read()
                                    _time.sleep(1)
                                    _wld_ssh1.exec_command(
                                        f"esxcli network ip netstack add"
                                        f" -N {wld_stack} 2>/dev/null",
                                        timeout=15)[1].read()
                                finally:
                                    try: _wld_ssh1.close()
                                    except: pass
                                _time.sleep(5)

                                # ── 5. PowerCLI: create portgroup + vmk on stack ─
                                wld_vmk_name, _, _pg_err = _pcli_vmk_on_stack(
                                    vc_url, vc_user, vc_pass, host_name,
                                    wld_pg_name, wld_stack,
                                    create_pg=True, vds_name=_nsx_vds,
                                    vlan_id=_wld_vlan,
                                    ip_to_exclude=wld_temp_ip)
                                if _pg_err:
                                    result["wld_error"] = f"PowerCLI vmk-on-stack failed: {_pg_err}"
                                else:
                                    result["wld_vmk"] = wld_vmk_name
                                    _time.sleep(2)

                                    # ── 6. SSH conn-w2: IP + route + tests ───────
                                    _wld_ssh = _para.SSHClient()
                                    _wld_ssh.set_missing_host_key_policy(_para.AutoAddPolicy())
                                    try:
                                        for _att in range(4):
                                            try:
                                                _wld_ssh.connect(host_name, username="root",
                                                                 password=esx_pass, timeout=10)
                                                break
                                            except _para.AuthenticationException:
                                                raise RuntimeError(
                                                    f"ESX root password incorrect for {host_name}.")
                                            except Exception:
                                                if _att < 3: _time.sleep(2)
                                                else: raise RuntimeError(
                                                    f"Cannot SSH to {host_name}.")

                                        def _wrun(cmd, timeout=30):
                                            _, _so, _se = _wld_ssh.exec_command(cmd, timeout=timeout)
                                            return (_so.read().decode("utf-8","replace"),
                                                    _se.read().decode("utf-8","replace"))

                                        # Set IP on vmk + add default route on stack
                                        _wrun(f"esxcli network ip interface ipv4 set"
                                              f" -i {wld_vmk_name} -I {wld_temp_ip}"
                                              f" -N {_wld_mask} -t static 2>/dev/null",
                                              timeout=10)
                                        _wrun(f"esxcli network ip route ipv4 add"
                                              f" --gateway={_wld_gw_ip} --network=default"
                                              f" -N {wld_stack} 2>/dev/null",
                                              timeout=10)
                                        _time.sleep(1)

                                        # ── 7. Tests using -S <stack> ─────────────
                                        _dns_wld_ip = _dns_wld[0] if _dns_wld else dns_ip

                                        # a. Ping workload gateway
                                        _wgw_o, _wgw_e = _wrun(
                                            f"vmkping -S {wld_stack} -c 3 -W 2 {_wld_gw_ip}",
                                            timeout=30)
                                        _wgw_pass = (", 0% packet loss" in _wgw_o or
                                                     "bytes from" in _wgw_o)
                                        result["wld_gw_ping"]        = "pass" if _wgw_pass else "fail"
                                        result["wld_gw_ping_output"] = (_wgw_o + _wgw_e).strip()

                                        # a2. NTP check — vmkping via stack + nc UDP/123
                                        if ntp_ip:
                                            result["wld_ntp_check"], result["wld_ntp_detail"] = \
                                                _ntp_check(_wrun, wld_stack, ntp_ip)
                                        else:
                                            result["wld_ntp_check"] = "skip"
                                            result["wld_ntp_detail"] = ""

                                        # b. Ping workload DNS server
                                        #    Default route on stack routes via workload GW
                                        _wdn_o, _wdn_e = _wrun(
                                            f"vmkping -S {wld_stack} -c 3 -W 2 {_dns_wld_ip}",
                                            timeout=30)
                                        _wdn_pass = (", 0% packet loss" in _wdn_o or
                                                     "bytes from" in _wdn_o)
                                        result["wld_dns_ping"]        = "pass" if _wdn_pass else "fail"
                                        result["wld_dns_ping_output"] = (_wdn_o + _wdn_e).strip()

                                        # c. DNS resolution: user-configurable test host (default github.com)
                                        _wns_o, _wns_e = _wrun(
                                            f"nslookup {_wld_test_host} {_dns_wld_ip} 2>&1", timeout=15)
                                        if not _wns_o.strip():
                                            _wns_o, _wns_e = _wrun(
                                                f"busybox nslookup {_wld_test_host} {_dns_wld_ip} 2>&1",
                                                timeout=15)
                                        _wns_combined = (_wns_o + _wns_e).strip()
                                        _wns_pass = (
                                            "Name:"      in _wns_o and
                                            "can't find" not in _wns_o and
                                            "NXDOMAIN"   not in _wns_o and
                                            "REFUSED"    not in _wns_o and
                                            "timed out"  not in _wns_o.lower())
                                        result["wld_dns_resolve"]        = "pass" if _wns_pass else "fail"
                                        result["wld_dns_resolve_output"] = _wns_combined[:600]
                                        result["wld_dns_domain"]         = _wld_test_host

                                    finally:
                                        # Cleanup: remove vmk + custom stack via esxcli
                                        if wld_vmk_name:
                                            try:
                                                _wld_ssh.exec_command(
                                                    f"esxcli network ip interface remove"
                                                    f" -i {wld_vmk_name}", timeout=15)[1].read()
                                            except Exception: pass
                                        try:
                                            _wld_ssh.exec_command(
                                                f"esxcli network ip netstack remove"
                                                f" -N {wld_stack}", timeout=15)[1].read()
                                        except Exception: pass
                                        try: _wld_ssh.close()
                                        except Exception: pass

        except Exception as _wld_exc:
            if not result.get("wld_error"):
                result["wld_error"] = str(_wld_exc)
        finally:
            # Always remove the temp workload portgroup via PowerCLI
            if wld_pg_name and host_name:
                try: _pcli_cleanup_vlan_test(vc_url, vc_user, vc_pass, wld_pg_name, [host_name])
                except Exception: pass

    except RuntimeError as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    finally:
        # Fallback cleanup via PowerCLI (runs only if SSH removal didn't happen,
        # e.g. SSH was unreachable or the test aborted before cleanup ran).
        if vmk_name and host_name and not vmk_removed_via_ssh:
            try: _pcli_dns_vmk_remove(vc_url, vc_user, vc_pass, host_name, vmk_name, first_ip)
            except Exception: pass
        if host_name and ssh_was_on is False:
            try: _vc_manage_ssh(vc_url, vc_user, vc_pass, host_name, False)
            except Exception: pass

    return jsonify(result)


@app.route("/api/check-vlan", methods=["POST"])
def check_vlan():
    """
    VLAN connectivity check for NSX-VPC Distributed mode.
    1. PowerCLI creates temp DVPortGroup + one vmk per host via New-VMHostNetworkAdapter.
    2. SSH to each host: vmkping the DVLAN gateway.
    3. PowerCLI removes all vmks + portgroup.
    """
    body     = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url",  ""))
    vc_user  = body.get("username", "")
    vc_pass  = body.get("password", "")
    nsx_raw  = (body.get("nsx_url") or "").strip()
    nsx_url  = normalize_url(nsx_raw) if nsx_raw else guess_nsx_url(vc_url)
    nsx_user = body.get("nsx_user", "")
    nsx_pass = body.get("nsx_pass", "")
    esx_pass       = body.get("esx_pass", "")
    host_passwords = body.get("host_passwords") or {}

    result: dict = {"success": False, "tests": [], "summary": "", "error": None}
    pg_name        = None
    _extra_pg_names: list = []   # PG names created on non-host-0 VDS (for teardown)
    host_pg_map:   dict  = {}    # fqdn → pg_name used for that host
    hosts   = []

    try:
        import ipaddress as _ip, time as _time, paramiko as _para

        # ── 1. DVLAN connection details ──────────────────────────────────────
        dvlan_id_req = (body.get("dvlan_id") or "").strip()
        dvlans = (nsx_get(nsx_url, nsx_user, nsx_pass,
            "/policy/api/v1/infra/distributed-vlan-connections") or {}).get("results", [])
        if not dvlans:
            result["error"] = "No Distributed External Connection found — complete R5-1 first."
            return jsonify(result)
        dvlan = next((d for d in dvlans if d.get("id") == dvlan_id_req), dvlans[0])
        vlan_id    = dvlan.get("vlan_id", 0)
        gw_addrs   = dvlan.get("gateway_addresses") or []
        if not gw_addrs:
            result["error"] = "DVLAN connection has no gateway address configured."
            return jsonify(result)
        gateway_cidr = gw_addrs[0]
        gateway_ip   = gateway_cidr.split("/")[0]
        prefix_len   = int(gateway_cidr.split("/")[1])
        dvlan_net    = _ip.ip_interface(gateway_cidr).network
        mask_str     = str(_ip.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)

        # ── 2. External IP Block overlapping the DVLAN subnet ──────────────
        all_blocks = (nsx_get(nsx_url, nsx_user, nsx_pass,
            "/policy/api/v1/infra/ip-blocks") or {}).get("results", [])
        block_cidr = excl_str = None
        ip_block_id = ip_block_name = ip_block_path = ""
        for b in all_blocks:
            if (b.get("visibility") or "").upper() != "EXTERNAL":
                continue
            cidr = _block_cidr(b, nsx_url, nsx_user, nsx_pass)
            try:
                if cidr and _ip.ip_network(cidr, strict=False).overlaps(dvlan_net):
                    block_cidr = cidr
                    ip_block_id   = b.get("id", "")
                    ip_block_name = b.get("display_name", ip_block_id)
                    ip_block_path = b.get("path", f"/infra/ip-blocks/{ip_block_id}")
                    # List endpoint omits excluded_ip_ranges — fetch individual block
                    full_block = nsx_get(nsx_url, nsx_user, nsx_pass,
                                         f"/policy/api/v1/infra/ip-blocks/{ip_block_id}") or b
                    excl_str = _nsx_excl_to_str(full_block)
                    break
            except Exception:
                pass
        if not block_cidr:
            result["error"] = "No External IP Block matching the DVLAN subnet — complete R5-3 first."
            return jsonify(result)

        # ── 3. Prepared ESX hosts + NSX VDS name ───────────────────────────
        htns = (nsx_get(nsx_url, nsx_user, nsx_pass,
            "/policy/api/v1/infra/sites/default/enforcement-points"
            "/default/host-transport-nodes") or {}).get("results", [])
        nsx_vds_name = ""
        host_vds_map: dict = {}   # fqdn → NSX VDS name on that host
        for h in htns:
            fqdn = (h.get("node_deployment_info") or {}).get("fqdn") or h.get("display_name", "")
            if not fqdn: continue
            hosts.append(fqdn)
            for hs in (h.get("host_switch_spec") or {}).get("host_switches") or []:
                _vn = hs.get("host_switch_name", "")
                if _vn:
                    host_vds_map[fqdn] = _vn
                    if not nsx_vds_name:
                        nsx_vds_name = _vn   # fallback / error-check below
                    break
        if not hosts:
            result["error"] = "No prepared ESX hosts found — complete S3 (NSX Host Preparation) first."
            return jsonify(result)
        if not nsx_vds_name:
            result["error"] = "Could not determine NSX VDS name from host transport nodes."
            return jsonify(result)

        # ── 4. Compute reserved IPs + allocate temp IPs ─────────────────────
        # Reserved = subnet_network+2, subnet_network+3, broadcast-1.
        # These are often used by physical infrastructure (HSRP/VRRP etc.) and
        # should not be assigned as temp IPs.  If they fall inside the External
        # IP Block we will also probe them to detect stale allocations.
        _seen_r: set = set()
        reserved_in_subnet: list = []
        for _r in [dvlan_net.network_address + 2,
                   dvlan_net.network_address + 3,
                   dvlan_net.broadcast_address - 1]:
            if str(_r) not in _seen_r:
                _seen_r.add(str(_r)); reserved_in_subnet.append(_r)

        # Parse the existing exclusion string into a set for quick lookup
        _gw_addr = _ip.ip_address(gateway_ip)
        _excl_set: set = set()
        for tok in (excl_str or "").split(","):
            tok = tok.strip()
            if not tok: continue
            if "-" in tok:
                try:
                    a, b = tok.split("-", 1)
                    for i in range(int(_ip.ip_address(a.strip())),
                                   int(_ip.ip_address(b.strip())) + 1):
                        _excl_set.add(_ip.ip_address(i))
                except Exception: pass
            else:
                try: _excl_set.add(_ip.ip_address(tok))
                except Exception: pass

        # Build combined exclusion for _pick_temp_ips (explicit + reserved)
        _res_str = ",".join(str(r) for r in reserved_in_subnet)
        _combined_excl = f"{excl_str},{_res_str}" if excl_str else _res_str

        temp_ips = _pick_temp_ips(block_cidr, gateway_cidr, _combined_excl, len(hosts))
        if not temp_ips:
            result["error"] = "No available IPs in External IP Block for temp vmk."
            return jsonify(result)
        hosts = hosts[:len(temp_ips)]

        # ── 5a. Phase 1: PG + vmknic for host-0 only ──────────────────────
        # We create only host-0's vmknic first so the IP scan runs before
        # the other hosts' temp IPs exist on the VLAN — any response is a
        # real server, not our own vmknic.
        pg_name = f"vcf-vlan-check-{vlan_id}"
        vmk_map, _pg_created, setup_err = _pcli_setup_vlan_test(
            vc_url, vc_user, vc_pass, nsx_vds_name, pg_name, vlan_id,
            [(hosts[0], temp_ips[0], mask_str)])
        if setup_err:
            result["error"] = f"PowerCLI setup failed: {setup_err}"
            return jsonify(result)
        host_pg_map[hosts[0]] = pg_name

        # ── 5b. Pre-scan from host-0 ───────────────────────────────────────
        # Scan ALL IPs in block (excl. gateway, excl_ranges, host-0's own IP).
        # No other vmknics exist yet → every RESPOND is a real server.
        _block_net_obj = _ip.ip_network(block_cidr, strict=False)

        # Collect IPs already allocated by NSX VPC (NAT SNAT + LB VIPs).
        # These are legitimately in use — skip them during the pre-scan to
        # avoid false "conflict" warnings.
        _nsx_alloc_ips: set = set()
        try:
            _raw_alloc = _get_vpc_allocated_ips(nsx_url, nsx_user, nsx_pass, block_cidr)
            _nsx_alloc_ips = {_ip.ip_address(a) for a in _raw_alloc}
        except Exception:
            pass

        _scan_excl_pre = _excl_set | {_gw_addr, _ip.ip_address(temp_ips[0])} | _nsx_alloc_ips
        _prescan_ips = [
            str(_ip.ip_address(h))
            for h in range(int(_block_net_obj.network_address) + 1,
                           int(_block_net_obj.broadcast_address))
            if _ip.ip_address(h) not in _scan_excl_pre
        ]
        _prescan_conflict: str | None    = None
        _prescan_steps:    list          = []
        _prescan_ssh_was_on: bool | None = None  # tracks host-0 SSH state for cleanup
        _conflict_ips:     list          = []
        _vmk0 = vmk_map.get(hosts[0])

        if _prescan_ips and _vmk0:
            _alloc_note = (f", {len(_nsx_alloc_ips)} NSX VPC-allocated IPs skipped"
                           if _nsx_alloc_ips else "")
            _prescan_steps.append(
                f"Scanning {len(_prescan_ips)} IPs in {block_cidr} for conflicts{_alloc_note}…")
            _pssh = None
            try:
                _pok, _pstate = _vc_manage_ssh(vc_url, vc_user, vc_pass, hosts[0], True)
                _prescan_ssh_was_on = _pstate  # True = already on; False = we enabled it
                if _pok:
                    if not _pstate:
                        _time.sleep(5)
                    _pw0 = host_passwords.get(hosts[0]) or esx_pass
                    _pssh = _para.SSHClient()
                    _pssh.set_missing_host_key_policy(_para.AutoAddPolicy())
                    for _att in range(6):
                        try:
                            _pssh.connect(hosts[0], username="root",
                                          password=_pw0, timeout=10)
                            break
                        except Exception as _es:
                            _es_s = str(_es).lower()
                            if any(k in _es_s for k in (
                                    "authentication", "bad authentication",
                                    "keyboard", "publickey")):
                                raise RuntimeError(
                                    f"ESX root password incorrect for {hosts[0]}.") from _es
                            if _att < 5: _time.sleep(2)
                            else: raise
                    _time.sleep(2)

                    def _prun(cmd, timeout=60):
                        _, so, se = _pssh.exec_command(cmd, timeout=timeout)
                        return so.read().decode("utf-8", "replace"), \
                               se.read().decode("utf-8", "replace")

                    BATCH = 200
                    _sl: list = [f"vmk='{_vmk0}'"]
                    for _bi in range(0, len(_prescan_ips), BATCH):
                        _b = _prescan_ips[_bi:_bi + BATCH]
                        for _sip in _b:
                            _k = _sip.replace(".", "_")
                            _sl.append(f"vmkping -c 1 -W 1 -I $vmk {_sip}"
                                       f" > /tmp/_vp_{_k} 2>&1 &")
                        _sl.append("wait")
                        for _sip in _b:
                            _k = _sip.replace(".", "_")
                            _sl.append(f"grep -q 'bytes from {_sip}'"
                                       f" /tmp/_vp_{_k} 2>/dev/null"
                                       f" && echo RESPOND:{_sip}")
                            _sl.append(f"rm -f /tmp/_vp_{_k} 2>/dev/null")
                    _sl.append("echo SCAN_DONE")
                    _sto = max(30, (len(_prescan_ips) // BATCH + 1) * 2 + 10)
                    # ESXi busybox sh has an ~8 KB inline-command limit.
                    # Upload the script via SFTP and execute it as a file.
                    _scan_remote = "/tmp/_vcf_scan.sh"
                    try:
                        _sftp = _pssh.open_sftp()
                        with _sftp.open(_scan_remote, "w") as _sf:
                            _sf.write("\n".join(_sl))
                        _sftp.close()
                    except Exception as _sftp_e:
                        raise RuntimeError(
                            f"SFTP upload of scan script failed: {_sftp_e}"
                        ) from _sftp_e
                    _sout, _ = _prun(
                        f"sh {_scan_remote}; rm -f {_scan_remote}", timeout=_sto)

                    _conflict_ips: list = [
                        ln.split("RESPOND:", 1)[1].strip()
                        for ln in _sout.splitlines()
                        if ln.startswith("RESPOND:")
                    ]
                    _prescan_steps.append(
                        f"Scan complete — {len(_conflict_ips)} IP(s) responded")

                    if _conflict_ips:
                        # Re-pick temp IPs for hosts 1-N, avoiding conflicts
                        if len(hosts) > 1:
                            _excl_c = ((excl_str or "") +
                                       ("," if excl_str else "") +
                                       ",".join(_conflict_ips) + "," + temp_ips[0])
                            _new_rest = list(_pick_temp_ips(
                                block_cidr, gateway_cidr, _excl_c, len(hosts) - 1))
                            if len(_new_rest) == len(hosts) - 1:
                                temp_ips = [temp_ips[0]] + _new_rest
                                _prescan_steps.append(
                                    "Reassigned temp IPs for remaining hosts "
                                    "to avoid conflicts")
                        _prescan_conflict = (
                            f"IP conflict in VLAN {vlan_id}: "
                            f"{', '.join(_conflict_ips)} responded to ping "
                            f"but are not in the Excluded Ranges of the "
                            f"External IP Block.\n"
                            f"These addresses are in use in the VLAN "
                            f"(by the router or a physical server).\n"
                            f"Add them to the 'Excluded IP Ranges' of the "
                            f"IP Block to prevent Supervisor from assigning"
                            f" them to workloads.")
                        _prescan_steps.append(_prescan_conflict)
                else:
                    _prescan_steps.append(
                        f"Could not enable SSH on {hosts[0]} — conflict scan skipped")
            except Exception as _ep:
                _prescan_steps.append(f"Pre-scan error (conflict scan skipped): {_ep}")
            finally:
                if _pssh:
                    try: _pssh.close()
                    except Exception: pass
                # Keep SSH enabled — the main gateway-ping loop needs it for host-0

        # ── 5c. Phase 2: vmknics for hosts 1-N ────────────────────────────
        # Group remaining hosts by their NSX VDS so each cluster's hosts get
        # a vmk created on the correct VDS (each cluster has its own VDS).
        # IMPORTANT: use a unique PG name per VDS group. The cleanup block
        # inside _pcli_setup_vlan_test (pg_already_exists=False) searches for
        # the PG by name globally across ALL VDS switches. If two groups shared
        # the same name, the second group would delete the first group's PG —
        # stripping vmks from the already-prepared hosts before they get tested.
        if len(hosts) > 1:
            _vds_groups: dict = {}   # vds_name → [(fqdn, ip, mask), ...]
            _host0_vds = host_vds_map.get(hosts[0], nsx_vds_name)
            for _i in range(1, len(hosts)):
                _vn = host_vds_map.get(hosts[_i], nsx_vds_name)
                _vds_groups.setdefault(_vn, []).append(
                    (hosts[_i], temp_ips[_i], mask_str))

            _vds_idx = 0
            # Pre-compute per-group params (sequential — order matters for naming)
            _vds_group_args = []
            for _vn, _h_list in _vds_groups.items():
                if _vn == _host0_vds:
                    _this_pg   = pg_name
                    _pg_exists = True
                else:
                    _vds_idx  += 1
                    _this_pg   = f"{pg_name}-{_vds_idx}"
                    _pg_exists = False
                    _extra_pg_names.append(_this_pg)
                for _fqdn, _, _ in _h_list:
                    host_pg_map[_fqdn] = _this_pg
                _vds_group_args.append((_vn, _this_pg, _pg_exists, _h_list))

            # Run all VDS groups in parallel — each creates vmks on its own VDS
            import concurrent.futures as _cf2
            def _setup_group(args):
                _vn2, _tpg, _pge, _hl = args
                return _pcli_setup_vlan_test(
                    vc_url, vc_user, vc_pass, _vn2, _tpg, vlan_id,
                    _hl, pg_already_exists=_pge)

            with _cf2.ThreadPoolExecutor(max_workers=len(_vds_group_args)) as _p2:
                for _vmk2, _, _err2 in _p2.map(_setup_group, _vds_group_args):
                    if not _err2:
                        vmk_map.update(_vmk2)

        # ── 6. Per-host: SSH → gateway ping (parallel) ────────────────────
        import concurrent.futures as _cf3

        def _run_host_test(_idx, _fqdn, _tip, _vmk_dev):
            """SSH + vmkping for one host. Fully self-contained, thread-safe."""
            _test: dict = {
                "host": _fqdn, "vlan_id": vlan_id,
                "temp_ip": _tip, "gateway": gateway_ip,
                "vmk": _vmk_dev, "result": "error", "output": "", "error": None,
                "conflict": _prescan_conflict if _idx == 0 else None
            }
            _steps = (list(_prescan_steps) if _idx == 0 else []) + [
                f"✓ VDS='{host_vds_map.get(_fqdn, nsx_vds_name)}'"
                f", PG='{host_pg_map.get(_fqdn, pg_name)}' (VLAN {vlan_id})",
                f"✓ Temp IP={_tip}/{prefix_len}, Gateway={gateway_ip}"
            ]
            _ssh_state  = None
            _ssh_client = None

            try:
                if not _vmk_dev:
                    _test["error"] = (f"PowerCLI failed to create vmk on {_fqdn}. "
                                      f"Check PowerCLI setup output for VMK_ERR lines.")
                    _test["output"] = "\n".join(_steps)
                    return _test

                _steps.append(
                    f"✓ vmk created via PowerCLI: {_vmk_dev} with IP {_tip}/{prefix_len}")

                if _idx == 0 and _prescan_ssh_was_on is not None:
                    _ssh_state = _prescan_ssh_was_on
                    _steps.append("✓ SSH enabled (from pre-scan phase)")
                else:
                    _ok_ssh, _ssh_state = _vc_manage_ssh(
                        vc_url, vc_user, vc_pass, _fqdn, True)
                    if not _ok_ssh:
                        _test["error"] = f"Could not enable SSH on {_fqdn} via vCenter"
                        _test["output"] = "\n".join(_steps)
                        return _test
                    if not _ssh_state:
                        _time.sleep(5)
                    _steps.append("✓ SSH enabled")

                _host_pwd  = host_passwords.get(_fqdn) or esx_pass
                _ssh_client = _para.SSHClient()
                _ssh_client.set_missing_host_key_policy(_para.AutoAddPolicy())
                for _att in range(6):
                    try:
                        _ssh_client.connect(
                            _fqdn, username="root", password=_host_pwd, timeout=10)
                        break
                    except Exception as _es:
                        _es_str = str(_es).lower()
                        if any(k in _es_str for k in (
                                "authentication", "bad authentication",
                                "keyboard", "publickey")):
                            raise RuntimeError(
                                f"ESX root password incorrect for {_fqdn}.\n"
                                "Please enter the correct root password and run again."
                            ) from _es
                        if _att < 5: _time.sleep(2)
                        else: raise RuntimeError(
                            f"Cannot reach {_fqdn} via SSH.\n"
                            "Check that port 22 is reachable from this VM.") from _es
                _steps.append("✓ SSH connected")

                def _hrun(cmd, timeout=30):
                    _, _so, _se = _ssh_client.exec_command(cmd, timeout=timeout)
                    return (_so.read().decode("utf-8", "replace"),
                            _se.read().decode("utf-8", "replace"))

                _time.sleep(2)   # let vmk IP stack initialise

                _pout, _perr = _hrun(
                    f"vmkping -I {_vmk_dev} -d -s 28 {gateway_ip}", timeout=30)
                _pcomb = (_pout + _perr).strip()
                _steps.append(f"vmkping {gateway_ip} (gateway):\n{_pcomb}"
                               if _pcomb else "vmkping: no output")
                _gw_ok = ", 0% packet loss" in _pout or "bytes from" in _pout
                _test["result"] = "pass" if _gw_ok else "fail"
                _test["output"] = "\n".join(_steps)

            except Exception as _exc:
                _test["error"] = (str(_exc) if isinstance(_exc, RuntimeError)
                                  else f"{_exc}\n{traceback.format_exc()}")
                _test["output"] = "\n".join(_steps)
            finally:
                if _ssh_client:
                    if _vmk_dev:
                        try:
                            _, _so2, _ = _ssh_client.exec_command(
                                f"esxcli network ip interface remove -i {_vmk_dev}",
                                timeout=15)
                            _so2.read()
                        except Exception:
                            pass
                    try: _ssh_client.close()
                    except Exception: pass
                if _ssh_state is False:
                    try: _vc_manage_ssh(vc_url, vc_user, vc_pass, _fqdn, False)
                    except Exception: pass

            return _test

        _h_results = [None] * len(hosts)
        with _cf3.ThreadPoolExecutor(max_workers=min(len(hosts), 12)) as _pool3:
            _futs = {
                _pool3.submit(_run_host_test, i, hosts[i], temp_ips[i],
                              vmk_map.get(hosts[i])): i
                for i in range(len(hosts))
            }
            for _fut in _cf3.as_completed(_futs):
                _i = _futs[_fut]
                try:
                    _h_results[_i] = _fut.result()
                except Exception as _fe:
                    _h_results[_i] = {
                        "host": hosts[_i], "vlan_id": vlan_id,
                        "temp_ip": temp_ips[_i], "gateway": gateway_ip,
                        "vmk": vmk_map.get(hosts[_i]),
                        "result": "error", "output": "",
                        "error": str(_fe), "conflict": None
                    }
        result["tests"] = [r for r in _h_results if r is not None]

        passed    = sum(1 for t in result["tests"] if t["result"] == "pass")
        total     = len(result["tests"])
        conflicts = [t["conflict"] for t in result["tests"] if t.get("conflict")]
        gw_ok     = total > 0 and passed == total
        result["success"] = gw_ok and not conflicts
        # IP block info + conflict IPs for the auto-fix button
        result["ip_block_id"]   = ip_block_id
        result["ip_block_name"] = ip_block_name
        result["ip_block_path"] = ip_block_path
        result["conflict_ips"]  = list(_conflict_ips)

        # ── Compute available IP ranges for Supervisor ──────────────────────
        # "Available for Supervisor" = all block IPs minus:
        #   · gateway
        #   · explicit NSX excluded_ips (admin-configured)
        #   · genuine IP conflicts detected during pre-scan (real other devices)
        # NOT excluded: reserved_in_subnet (those are test-only reservations, NSX
        # can and does allocate subnet+3 etc. to workloads) and _nsx_alloc_ips
        # (those are already Supervisor's own allocations — still part of its pool).
        try:
            _blk_net = ipaddress.ip_network(block_cidr, strict=False)
            _all_excl = (
                _excl_set
                | {_gw_addr}
                | {ipaddress.ip_address(c) for c in _conflict_ips}
            )
            _avail: list = []   # list of (start_int, end_int) consecutive ranges
            _run_start = _run_end = None
            for _h in range(int(_blk_net.network_address) + 1,
                            int(_blk_net.broadcast_address)):
                _haddr = ipaddress.ip_address(_h)
                if _haddr in _all_excl:
                    if _run_start is not None:
                        _avail.append((_run_start, _run_end))
                        _run_start = _run_end = None
                else:
                    if _run_start is None:
                        _run_start = _run_end = _h
                    else:
                        _run_end = _h
            if _run_start is not None:
                _avail.append((_run_start, _run_end))

            def _fmt_range(s, e):
                return (str(ipaddress.ip_address(s))
                        if s == e
                        else f"{ipaddress.ip_address(s)}-{ipaddress.ip_address(e)}")

            result["available_ranges"] = [_fmt_range(s, e) for s, e in _avail]
            result["available_count"]  = sum(e - s + 1 for s, e in _avail)
        except Exception:
            result["available_ranges"] = []
            result["available_count"]  = 0

        if gw_ok and not conflicts:
            result["summary"] = f"{passed}/{total} host(s) passed VLAN {vlan_id} connectivity test"
        elif gw_ok and conflicts:
            result["summary"] = (f"{passed}/{total} host(s) passed gateway ping — "
                                 f"but IP conflicts detected in VLAN {vlan_id}")
        else:
            result["summary"] = f"{passed}/{total} host(s) passed VLAN {vlan_id} connectivity test"

    except Exception:
        result["error"] = traceback.format_exc()
    finally:
        if pg_name and hosts:
            try: _pcli_cleanup_vlan_test(vc_url, vc_user, vc_pass, pg_name, hosts)
            except Exception: pass
        for _epg in _extra_pg_names:
            try: _pcli_cleanup_vlan_test(vc_url, vc_user, vc_pass, _epg, hosts)
            except Exception: pass

    return jsonify(result)


@app.route("/api/vc-cluster-page-url", methods=["POST"])
def vc_cluster_page_url():
    """
    Return vSphere-Client deep links to any standard cluster Configure sub-page.
    The caller passes a `page` string that is appended after /configure/, e.g.:
      page="drs"  →  .../configure/drs
      page="ha"   →  .../configure/ha
    """
    body    = request.get_json(force=True)
    vc_url  = normalize_url(body.get("vc_url", ""))
    vc_user = body.get("username", "")
    vc_pass = body.get("password", "")
    page    = body.get("page", "drs").strip("/")

    vc_host      = vc_url.replace("https://", "").replace("http://", "").rstrip("/")
    fallback_url = f"https://{vc_host}/ui/"

    try:
        # vCenter instance UUID (PropertyCollector, auth needed)
        soap_s, soap_ep, soap_hdr = _soap_session(vc_url, vc_user, vc_pass)
        r_uuid = soap_s.post(soap_ep, verify=False, timeout=10, headers=soap_hdr,
            data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><RetrieveProperties xmlns="urn:vim25">'
                '<_this type="PropertyCollector">propertyCollector</_this>'
                '<specSet>'
                '<propSet><type>ServiceInstance</type><all>false</all>'
                '<pathSet>content.about.instanceUuid</pathSet></propSet>'
                '<objectSet><obj type="ServiceInstance">ServiceInstance</obj></objectSet>'
                '</specSet>'
                '</RetrieveProperties></Body></Envelope>'))
        m = re.search(r'<val[^>]*>([^<]+)</val>', r_uuid.text)
        instance_uuid = m.group(1).strip() if m else ""

        # Cluster list via REST
        rest_s = requests.Session(); rest_s.verify = False
        r = rest_s.post(f"{vc_url}/api/session",
                        auth=(vc_user, vc_pass), verify=False, timeout=10)
        if r.status_code != 201:
            return jsonify({"urls": [], "fallback": fallback_url})

        hdrs = {"vmware-api-session-id": r.json()}
        r2   = rest_s.get(f"{vc_url}/api/vcenter/cluster",
                          headers=hdrs, verify=False, timeout=10)
        clusters = r2.json() if r2.status_code == 200 else []

        urls = []
        for c in clusters:
            cid   = c.get("cluster", "")
            cname = c.get("name", cid)
            mor   = f"urn:vmomi:ClusterComputeResource:{cid}"
            if instance_uuid:
                mor = f"{mor}:{instance_uuid}"
            url = f"https://{vc_host}/ui/app/cluster;nav=h/{mor}/configure/{page}"
            urls.append({"name": cname, "url": url})

        return jsonify({"urls": urls, "fallback": fallback_url})
    except Exception as ex:
        return jsonify({"urls": [], "error": str(ex), "fallback": fallback_url})


@app.route("/api/vc-tgw-url", methods=["POST"])
def vc_tgw_url():
    """
    Return a vSphere-Client deep link for a specific Transit Gateway.

    URL pattern from HAR:
      https://{vc}/ui/app/tgw;nav=n/
        urn:vmomi:TransitGateway:{tgw-mor-id}:{instance-uuid}/
        summary/plugin/com.vmware.nsx.management.nsxt.vpc/{ext_uid}

    tgw_name (optional): display name to match; defaults to first TGW found.
    """
    body     = request.get_json(force=True)
    vc_url   = normalize_url(body.get("vc_url", ""))
    vc_user  = body.get("username", "")
    vc_pass  = body.get("password", "")
    tgw_name = body.get("tgw_name", "")   # optional hint

    vc_host      = vc_url.replace("https://", "").replace("http://", "").rstrip("/")
    fallback_url = f"https://{vc_host}/ui/"

    try:
        soap_s, soap_ep, soap_hdr = _soap_session(vc_url, vc_user, vc_pass)

        # Instance UUID
        r_uuid = soap_s.post(soap_ep, verify=False, timeout=10, headers=soap_hdr,
            data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><RetrieveProperties xmlns="urn:vim25">'
                '<_this type="PropertyCollector">propertyCollector</_this>'
                '<specSet>'
                '<propSet><type>ServiceInstance</type><all>false</all>'
                '<pathSet>content.about.instanceUuid</pathSet></propSet>'
                '<objectSet><obj type="ServiceInstance">ServiceInstance</obj></objectSet>'
                '</specSet>'
                '</RetrieveProperties></Body></Envelope>'))
        m_uuid = re.search(r'<val[^>]*>([^<]+)</val>', r_uuid.text)
        instance_uuid = m_uuid.group(1).strip() if m_uuid else ""

        # VPC plugin version
        r_ext = soap_s.post(soap_ep, verify=False, timeout=10, headers=soap_hdr,
            data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><FindExtension xmlns="urn:vim25">'
                '<_this type="ExtensionManager">ExtensionManager</_this>'
                '<extensionKey>com.vmware.nsx.management.nsxt.vpc</extensionKey>'
                '</FindExtension></Body></Envelope>'))
        mv = re.search(r'<version>([^<]+)</version>', r_ext.text)
        plugin_version = mv.group(1).strip() if mv else ""

        ext_uid = (f"VC~com.vmware.nsx.management.nsxt.vpc~{plugin_version}~navigable~plugin.tgw.summary"
                   if plugin_version else
                   "VC~com.vmware.nsx.management.nsxt.vpc~navigable~plugin.tgw.summary")

        # Enumerate TransitGateway managed objects via SOAP ContainerView
        # Need SOAPAction vim25/9.1 so vCenter uses the current API version;
        # without it the default old version doesn't know the TransitGateway type.
        soap_hdr_v9 = dict(soap_hdr, **{"SOAPAction": "vim25/9.1"})

        r_sc = soap_s.post(soap_ep, verify=False, timeout=10, headers=soap_hdr_v9,
            data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><RetrieveServiceContent xmlns="urn:vim25">'
                '<_this type="ServiceInstance">ServiceInstance</_this>'
                '</RetrieveServiceContent></Body></Envelope>'))
        m_rf = re.search(r'<rootFolder[^>]*>([^<]+)</rootFolder>', r_sc.text)
        root_folder = m_rf.group(1).strip() if m_rf else "group-d1"

        r_cv = soap_s.post(soap_ep, verify=False, timeout=10, headers=soap_hdr_v9,
            data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><CreateContainerView xmlns="urn:vim25">'
                '<_this type="ViewManager">ViewManager</_this>'
                f'<container type="Folder">{root_folder}</container>'
                '<type>TransitGateway</type>'
                '<recursive>true</recursive>'
                '</CreateContainerView></Body></Envelope>'))
        m_cv = re.search(r'<returnval[^>]*type="ContainerView"[^>]*>([^<]+)</returnval>', r_cv.text)
        if not m_cv:
            return jsonify({"url": fallback_url, "error": "no TGW container view"})
        cv_mor = m_cv.group(1).strip()

        r_props = soap_s.post(soap_ep, verify=False, timeout=15, headers=soap_hdr_v9,
            data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><RetrieveProperties xmlns="urn:vim25">'
                '<_this type="PropertyCollector">propertyCollector</_this>'
                '<specSet>'
                '<propSet><type>TransitGateway</type><all>false</all>'
                '<pathSet>name</pathSet></propSet>'
                f'<objectSet><obj type="ContainerView">{cv_mor}</obj>'
                '<selectSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="TraversalSpec">'
                '<type>ContainerView</type><path>view</path></selectSet>'
                '</objectSet></specSet>'
                '</RetrieveProperties></Body></Envelope>'))

        # Parse TGW MOR → name pairs
        tgws: list[tuple[str,str]] = []
        for block in re.finditer(
                r'<returnval>(<obj type="TransitGateway">[^<]+</obj>.*?)</returnval>',
                r_props.text, re.DOTALL):
            chunk = block.group(1)
            m_obj  = re.search(r'<obj type="TransitGateway">([^<]+)</obj>', chunk)
            m_name = re.search(r'<val[^>]*>([^<]+)</val>', chunk)
            if m_obj:
                mor_id = m_obj.group(1).strip()
                name   = m_name.group(1).strip() if m_name else mor_id
                tgws.append((mor_id, name))

        if not tgws:
            return jsonify({"url": fallback_url, "error": "no TransitGateway objects found"})

        # Prefer matching by name, otherwise use the first (default) TGW
        chosen_mor, chosen_name = tgws[0]
        if tgw_name:
            for (mid, nm) in tgws:
                if nm.lower() == tgw_name.lower():
                    chosen_mor, chosen_name = mid, nm
                    break

        # Extract the bare ID from the MOR string (may be "tgw-32" or full MOR)
        tgw_id = chosen_mor.split(":")[-1] if ":" in chosen_mor else chosen_mor

        mor      = f"urn:vmomi:TransitGateway:{tgw_id}"
        if instance_uuid:
            mor = f"{mor}:{instance_uuid}"

        url = (f"https://{vc_host}/ui/app/tgw;nav=n/{mor}"
               f"/summary/plugin/com.vmware.nsx.management.nsxt.vpc/{ext_uid}")
        return jsonify({"url": url, "tgw_name": chosen_name})

    except Exception as ex:
        return jsonify({"url": fallback_url, "error": str(ex)})


@app.route("/api/vc-vcenter-folder-plugin-url", methods=["POST"])
def vc_vcenter_folder_plugin_url():
    """
    Return a vSphere-Client deep link to a networking plugin page that is
    scoped to the vCenter root folder (e.g. VNA Clusters, Edge Clusters).

    URL pattern from HAR:
      https://{vc}/ui/app/folder;nav=n/
        urn:vmomi:Folder:{rootFolder}:{instance-uuid}/
        configure/plugin/com.vmware.nsx.management.nsxt.networking/
        VC~com.vmware.nsx.management.nsxt.networking~{version}~navigable~{nav_key}

    The rootFolder is read from SOAP RetrieveServiceContent (no extra call needed).
    """
    body    = request.get_json(force=True)
    vc_url  = normalize_url(body.get("vc_url", ""))
    vc_user = body.get("username", "")
    vc_pass = body.get("password", "")
    nav_key = body.get("nav_key", "plugin.network.connectivity.vna.clusters")
    # plugin: "networking" → com.vmware.nsx.management.nsxt.networking
    #         "vpc"        → com.vmware.nsx.management.nsxt.vpc
    plugin_short = body.get("plugin", "networking")
    plugin_id    = f"com.vmware.nsx.management.nsxt.{plugin_short}"
    # url_type: "folder"    → /ui/app/folder;nav=n/{mor}/configure/plugin/{id}/{ext_uid}
    #           "extension" → /ui/extension/{ext_uid}
    url_type = body.get("url_type", "folder")

    vc_host      = vc_url.replace("https://", "").replace("http://", "").rstrip("/")
    fallback_url = f"https://{vc_host}/ui/"

    try:
        soap_s, soap_ep, soap_hdr = _soap_session(vc_url, vc_user, vc_pass)

        # Plugin version (FindExtension for whichever plugin was requested)
        r_ext = soap_s.post(soap_ep, verify=False, timeout=10, headers=soap_hdr,
            data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><FindExtension xmlns="urn:vim25">'
                '<_this type="ExtensionManager">ExtensionManager</_this>'
                f'<extensionKey>{plugin_id}</extensionKey>'
                '</FindExtension></Body></Envelope>'))
        mv = re.search(r'<version>([^<]+)</version>', r_ext.text)
        plugin_version = mv.group(1).strip() if mv else ""

        if plugin_version:
            ext_uid = f"VC~{plugin_id}~{plugin_version}~navigable~{nav_key}"
        else:
            ext_uid = f"VC~{plugin_id}~navigable~{nav_key}"

        # Folder-scoped format for all plugin pages
        r_sc = soap_s.post(soap_ep, verify=False, timeout=10, headers=soap_hdr,
            data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><RetrieveServiceContent xmlns="urn:vim25">'
                '<_this type="ServiceInstance">ServiceInstance</_this>'
                '</RetrieveServiceContent></Body></Envelope>'))
        m_rf = re.search(r'<rootFolder[^>]*>([^<]+)</rootFolder>', r_sc.text)
        root_folder = m_rf.group(1).strip() if m_rf else "group-d1"

        r_uuid = soap_s.post(soap_ep, verify=False, timeout=10, headers=soap_hdr,
            data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><RetrieveProperties xmlns="urn:vim25">'
                '<_this type="PropertyCollector">propertyCollector</_this>'
                '<specSet>'
                '<propSet><type>ServiceInstance</type><all>false</all>'
                '<pathSet>content.about.instanceUuid</pathSet></propSet>'
                '<objectSet><obj type="ServiceInstance">ServiceInstance</obj></objectSet>'
                '</specSet>'
                '</RetrieveProperties></Body></Envelope>'))
        m_uuid = re.search(r'<val[^>]*>([^<]+)</val>', r_uuid.text)
        instance_uuid = m_uuid.group(1).strip() if m_uuid else ""

        mor = f"urn:vmomi:Folder:{root_folder}"
        if instance_uuid:
            mor = f"{mor}:{instance_uuid}"

        url = (f"https://{vc_host}/ui/app/folder;nav=n/{mor}"
               f"/configure/plugin/{plugin_id}/{ext_uid}")

        return jsonify({"url": url, "fallback": fallback_url})
    except Exception as ex:
        return jsonify({"url": fallback_url, "error": str(ex)})


@app.route("/api/vc-network-config-url", methods=["POST"])
def vc_network_config_url():
    """
    Return vSphere-Client deep links to the NSX Network Configuration page
    (Cluster > Configure > Networking > Network Configuration) for every
    cluster in the given vCenter.

    URL pattern discovered from HAR:
      https://{vc}/ui/app/cluster;nav=h/
        urn:vmomi:ClusterComputeResource:{cluster-id}:{instance-uuid}/
        configure/plugin/com.vmware.nsx.management.nsxt.networking/
        VC~com.vmware.nsx.management.nsxt.networking~{version}
          ~navigable~plugin.network.connectivity.overlay.network.configuration
    """
    body    = request.get_json(force=True)
    vc_url  = normalize_url(body.get("vc_url", ""))
    vc_user = body.get("username", "")
    vc_pass = body.get("password", "")

    vc_host      = vc_url.replace("https://", "").replace("http://", "").rstrip("/")
    fallback_url = f"https://{vc_host}/ui/"

    try:
        # ── 1. SOAP: instance UUID + networking plugin version ────────────
        soap_s, soap_ep, soap_hdr = _soap_session(vc_url, vc_user, vc_pass)

        r_uuid = soap_s.post(soap_ep, verify=False, timeout=10, headers=soap_hdr,
            data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><RetrieveProperties xmlns="urn:vim25">'
                '<_this type="PropertyCollector">propertyCollector</_this>'
                '<specSet>'
                '<propSet><type>ServiceInstance</type><all>false</all>'
                '<pathSet>content.about.instanceUuid</pathSet></propSet>'
                '<objectSet><obj type="ServiceInstance">ServiceInstance</obj></objectSet>'
                '</specSet>'
                '</RetrieveProperties></Body></Envelope>'))
        m = re.search(r'<val[^>]*>([^<]+)</val>', r_uuid.text)
        instance_uuid = m.group(1).strip() if m else ""

        r_ext = soap_s.post(soap_ep, verify=False, timeout=10, headers=soap_hdr,
            data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><FindExtension xmlns="urn:vim25">'
                '<_this type="ExtensionManager">ExtensionManager</_this>'
                '<extensionKey>com.vmware.nsx.management.nsxt.networking</extensionKey>'
                '</FindExtension></Body></Envelope>'))
        mv = re.search(r'<version>([^<]+)</version>', r_ext.text)
        plugin_version = mv.group(1).strip() if mv else ""

        # Extension UID (tildes kept as-is — the browser URL uses them verbatim)
        if plugin_version:
            ext_uid = (f"VC~com.vmware.nsx.management.nsxt.networking"
                       f"~{plugin_version}~navigable"
                       f"~plugin.network.connectivity.overlay.network.configuration")
        else:
            ext_uid = ("VC~com.vmware.nsx.management.nsxt.networking"
                       "~navigable~plugin.network.connectivity.overlay.network.configuration")

        # ── 2. REST: list clusters ────────────────────────────────────────
        rest_s = requests.Session(); rest_s.verify = False
        r = rest_s.post(f"{vc_url}/api/session",
                        auth=(vc_user, vc_pass), verify=False, timeout=10)
        if r.status_code != 201:
            return jsonify({"urls": [], "fallback": fallback_url})

        hdrs = {"vmware-api-session-id": r.json()}
        r2   = rest_s.get(f"{vc_url}/api/vcenter/cluster",
                          headers=hdrs, verify=False, timeout=10)
        clusters = r2.json() if r2.status_code == 200 else []

        urls = []
        for c in clusters:
            cid   = c.get("cluster", "")   # e.g. "domain-c9"
            cname = c.get("name", cid)
            mor   = f"urn:vmomi:ClusterComputeResource:{cid}"
            if instance_uuid:
                mor = f"{mor}:{instance_uuid}"
            url = (f"https://{vc_host}/ui/app/cluster;nav=h/{mor}"
                   f"/configure/plugin/com.vmware.nsx.management.nsxt.networking/{ext_uid}")
            urls.append({"name": cname, "url": url})

        return jsonify({"urls": urls, "fallback": fallback_url})
    except Exception as ex:
        return jsonify({"urls": [], "error": str(ex), "fallback": fallback_url})


@app.route("/api/vc-vpc-ipblocks-url", methods=["POST"])
def vc_vpc_ipblocks_url():
    """
    Resolve the vCenter deep-link URL for VPC > Configure > IP Blocks.

    The vSphere Client deep-link format requires:
      urn:vmomi:Folder:{folder-id}:{vcenter-instance-uuid}

    The folder-id comes from the vCenter REST API folder list.
    The instance UUID comes from the SOAP RetrieveServiceContent (no auth needed).
    Falls back to the vCenter UI root if resolution fails.
    """
    body    = request.get_json(force=True)
    vc_url  = normalize_url(body.get("vc_url", ""))
    vc_user = body.get("username", "")
    vc_pass = body.get("password", "")
    nav_key = body.get("nav_key", "plugin.vpc.ip.blocks")

    vc_host      = vc_url.replace("https://", "").replace("http://", "").rstrip("/")
    fallback_url = f"https://{vc_host}/ui/"

    try:
        # ── 1. Authenticate via SOAP ────────────────────────────────────────
        # RetrieveServiceContent in vCenter 9.x no longer includes instanceUuid
        # in the <about> block; use the PropertyCollector instead.
        soap_s, soap_ep, soap_hdr = _soap_session(vc_url, vc_user, vc_pass)

        # vCenter instance UUID (needed for the full MOR in the deep link URL)
        r_uuid = soap_s.post(soap_ep, verify=False, timeout=10, headers=soap_hdr,
            data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><RetrieveProperties xmlns="urn:vim25">'
                '<_this type="PropertyCollector">propertyCollector</_this>'
                '<specSet>'
                '<propSet><type>ServiceInstance</type><all>false</all>'
                '<pathSet>content.about.instanceUuid</pathSet></propSet>'
                '<objectSet><obj type="ServiceInstance">ServiceInstance</obj></objectSet>'
                '</specSet>'
                '</RetrieveProperties></Body></Envelope>'))
        m = re.search(r'<val[^>]*>([^<]+)</val>', r_uuid.text)
        instance_uuid = m.group(1).strip() if m else ""

        # NSX VPC plugin version (needed to build the versioned extension UID
        # that the vSphere Client embeds in the deep link URL)
        r_ext = soap_s.post(soap_ep, verify=False, timeout=10, headers=soap_hdr,
            data=(
                '<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">'
                '<Body><FindExtension xmlns="urn:vim25">'
                '<_this type="ExtensionManager">ExtensionManager</_this>'
                '<extensionKey>com.vmware.nsx.management.nsxt.vpc</extensionKey>'
                '</FindExtension></Body></Envelope>'))
        mv = re.search(r'<version>([^<]+)</version>', r_ext.text)
        plugin_version = mv.group(1).strip() if mv else ""

        # ── 2. Find the 'Virtual Private Clouds' folder via REST API ────────
        rest_s = requests.Session(); rest_s.verify = False
        r = rest_s.post(f"{vc_url}/api/session",
                        auth=(vc_user, vc_pass), verify=False, timeout=10)
        if r.status_code != 201:
            return jsonify({"url": fallback_url})

        token = r.json()
        hdrs  = {"vmware-api-session-id": token}

        r2 = rest_s.get(f"{vc_url}/api/vcenter/folder",
                        headers=hdrs, verify=False, timeout=10)
        folders = r2.json() if r2.status_code == 200 else []

        vpc_folder_id = None
        for f in folders:
            name = (f.get("name") or "").lower()
            if "virtual private" in name or "nsx-project" in name:
                vpc_folder_id = f.get("folder", "")
                break

        if vpc_folder_id:
            # Full MOR: urn:vmomi:Folder:{id}:{instance-uuid}
            mor = f"urn:vmomi:Folder:{vpc_folder_id}"
            if instance_uuid:
                mor = f"{mor}:{instance_uuid}"

            # The vSphere Client deep link for a plugin section uses the
            # extension UID with tildes as separators (NOT dashes):
            #   VC~com.vmware.nsx.management.nsxt.vpc~{ver}~navigable~plugin.vpc.ip.blocks
            if plugin_version:
                ext_uid = (f"VC~com.vmware.nsx.management.nsxt.vpc"
                           f"~{plugin_version}~navigable~{nav_key}")
            else:
                ext_uid = f"VC~com.vmware.nsx.management.nsxt.vpc~navigable~{nav_key}"

            url = (f"https://{vc_host}/ui/app/nsx-project;nav=n/{mor}"
                   f"/configure/plugin/com.vmware.nsx.management.nsxt.vpc/{ext_uid}")
            return jsonify({"url": url})
    except Exception:
        pass

    return jsonify({"url": fallback_url})


# ─────────────────────────────────────────────────────────────────────────────
#  Live Topology endpoint
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/topology', methods=['POST'])
def build_topology():
    """Return NSX network topology — searches global + per-project TGW scope."""
    try:
        data     = request.json or {}
        nsx_url  = (data.get('nsx_url') or '').strip().rstrip('/')
        nsx_user = data.get('nsx_user') or ''
        nsx_pass = data.get('nsx_pass') or ''
        nsx_auth = (nsx_user, nsx_pass)
        base     = f"https://{nsx_url}/policy/api/v1"
        s        = requests.Session()
        s.verify = False
        import ipaddress as _ipa

        # ── Helper: resolve TGW attachments → (type, ext_conn) ──────────
        def _resolve_tgw(tgw_prefix):
            att_r = s.get(f"{tgw_prefix}/attachments", auth=nsx_auth, timeout=10)
            atts  = att_r.json().get('results', []) if att_r.ok else []
            ttype = None; ext_conn = None
            for att in atts:
                cp = att.get('connection_path', '') or ''   # ← correct field name

                # ── Distributed: connection_path contains /distributed-vlan-connections/
                if '/distributed-vlan-connections/' in cp:
                    ttype = 'D'
                    dvid  = cp.rstrip('/').split('/')[-1]
                    dv_r  = s.get(f"{base}/infra/distributed-vlan-connections/{dvid}",
                                  auth=nsx_auth, timeout=10)
                    if dv_r.ok:
                        d      = dv_r.json()
                        subnet = (d.get('gateway_addresses') or [''])[0]
                        try:
                            net = _ipa.ip_interface(subnet).network
                            gw  = str(list(net.hosts())[0])
                        except Exception:
                            gw = subnet.split('/')[0]
                        ext_conn = dict(type='dvlan', name=d.get('display_name', dvid),
                                        vlan=str(d.get('vlan_id', '')),
                                        subnet=subnet, gateway_ip=gw)

                # ── Centralized: connection_path contains /gateway-connections/
                elif '/gateway-connections/' in cp:
                    ttype = 'C'
                    gc_r  = s.get(f"https://{nsx_url}/policy/api/v1{cp}",
                                  auth=nsx_auth, timeout=10)
                    t0_name = ''
                    if gc_r.ok:
                        t0_path = gc_r.json().get('tier0_path', '') or ''
                        t0_id   = t0_path.rstrip('/').split('/')[-1] if t0_path else ''
                        t0_r    = s.get(f"{base}/infra/tier-0s/{t0_id}",
                                        auth=nsx_auth, timeout=10)
                        t0_name = t0_r.json().get('display_name', t0_id) if t0_r.ok else t0_id
                        # Enumerate ALL locale-services and collect ALL unique VLAN/GW pairs
                        ls_r  = s.get(f"{base}/infra/tier-0s/{t0_id}/locale-services",
                                      auth=nsx_auth, timeout=10)
                        lsvcs = ls_r.json().get('results', []) if ls_r.ok else [{'id': 'default'}]
                        seen_vlans = {}   # vlan_key → {vlan, subnet, gateway_ip}
                        for ls in lsvcs:
                            ls_id = ls.get('id', 'default')
                            if_r  = s.get(
                                f"{base}/infra/tier-0s/{t0_id}/locale-services/{ls_id}/interfaces",
                                auth=nsx_auth, timeout=10)
                            if not if_r.ok:
                                continue
                            for ifc in if_r.json().get('results', []):
                                if ifc.get('type') != 'EXTERNAL':
                                    continue
                                # ── IP / subnet ─────────────────────────────────
                                ifc_subnet = ''
                                subs = ifc.get('subnets', [])
                                if subs:
                                    _ip  = subs[0].get('ip_addresses', [''])[0]
                                    _pfx = subs[0].get('prefix_len', '')
                                    ifc_subnet = f"{_ip}/{_pfx}" if _ip and _pfx else ''
                                # ── VLAN: direct field → connected segment ──────
                                ifc_vlan = str(ifc.get('vlan', '') or '')
                                if not ifc_vlan:
                                    seg_path = ifc.get('segment_path', '') or ''
                                    if seg_path:
                                        seg_id = seg_path.rstrip('/').split('/')[-1]
                                        sg_r = s.get(f"{base}/infra/segments/{seg_id}",
                                                     auth=nsx_auth, timeout=10)
                                        if sg_r.ok:
                                            vids = sg_r.json().get('vlan_ids', [])
                                            ifc_vlan = str(vids[0]) if vids else ''
                                # ── First host in subnet = physical router IP ────
                                ifc_gw = ''
                                try:
                                    net    = _ipa.ip_interface(ifc_subnet).network
                                    ifc_gw = str(list(net.hosts())[0])
                                except Exception:
                                    ifc_gw = ifc_subnet.split('/')[0]
                                # Deduplicate by VLAN (or by subnet if no VLAN tag)
                                dedup_key = ifc_vlan or ifc_subnet
                                if dedup_key and dedup_key not in seen_vlans:
                                    seen_vlans[dedup_key] = {
                                        'vlan': ifc_vlan,
                                        'subnet': ifc_subnet,
                                        'gateway_ip': ifc_gw,
                                    }
                        vlans_list = list(seen_vlans.values())
                        # Legacy single-value fallback (first entry)
                        vlan   = vlans_list[0]['vlan']        if vlans_list else ''
                        subnet = vlans_list[0]['subnet']      if vlans_list else ''
                        gw     = vlans_list[0]['gateway_ip']  if vlans_list else ''
                    else:
                        vlans_list = []
                        vlan = subnet = gw = ''
                    ext_conn = dict(type='t0', name=t0_name,
                                    vlan=vlan, subnet=subnet, gateway_ip=gw,
                                    vlans=vlans_list)
            return ttype, ext_conn

        # key = "{scope}:{tid}" to avoid collisions when two projects share TGW id 'default'
        tgw_info         = {}   # "{proj_id}:{tid}" or "global:{tid}" → {id,name,type,ext_conn,nat_ip,ckey,proj_id}
        vpc_tgw_map      = {}   # vpc_display_name.lower() → {tgw_id, name, nat_ip}
        vip_to_tgw_ckey  = {}   # VIP IP string → tgw_ckey  (built from NSX LB virtual-servers)
        all_vpc_debug    = []   # debug list across all projects

        # ── 1. Project-scoped TGWs ────────────────────────────────────────
        org_r    = s.get(f"{base}/orgs/default/projects", auth=nsx_auth, timeout=10)
        projects = org_r.json().get('results', []) if org_r.ok else []

        for proj in projects:
            proj_id   = proj['id']
            proj_base = f"{base}/orgs/default/projects/{proj_id}"

            # TGWs in this project
            pt_r = s.get(f"{proj_base}/transit-gateways", auth=nsx_auth, timeout=10)
            for tgw in (pt_r.json().get('results', []) if pt_r.ok else []):
                tid  = tgw['id']
                ckey = f"{proj_id}:{tid}"
                if ckey not in tgw_info:
                    ttype, ext_conn = _resolve_tgw(
                        f"{proj_base}/transit-gateways/{tid}")
                    tgw_info[ckey] = dict(id=tid, name=tgw.get('display_name', tid),
                                          type=ttype, ext_conn=ext_conn, nat_ip='',
                                          ckey=ckey, proj_id=proj_id)

            # VPCs → resolve NAT IP (directly, no connectivity-profile lookup needed)
            # 'vpc_connectivity_profile' / 'vpc_service_profile' are empty in this NSX build.
            # Strategy: collect all VPC NAT IPs, then assign to each project TGW by priority:
            #   C-TGW → prefer 'kube-system*' VPC (Supervisor), else first with a NAT IP
            #   D-TGW → prefer 'default-region*' VPC (VKS),      else first with a NAT IP
            vpcs_r = s.get(f"{proj_base}/vpcs", auth=nsx_auth, timeout=10)
            vpc_list = vpcs_r.json().get('results', []) if vpcs_r.ok else []

            # Collect composite keys for TGWs that belong to this project
            proj_tgw_ckeys = [k for k in tgw_info if k.startswith(f"{proj_id}:")]

            vpc_debug_list = [{'proj': proj_id, 'vpcs_status': vpcs_r.status_code,
                               'vpcs_count': len(vpc_list),
                               'proj_tgw_ckeys': proj_tgw_ckeys}]

            # Pass 1 – collect (vpc_name, vpc_id, nat_ip) for every VPC
            vpc_nats = []  # [(vpc_name, vpc_id, nat_ip)]
            for vpc in vpc_list:
                vpc_name = vpc.get('display_name', vpc['id'])
                vpc_id   = vpc['id']
                nat_ip   = ''
                nat_r    = s.get(f"{proj_base}/vpcs/{vpc_id}/nat/DEFAULT/nat-rules",
                                 auth=nsx_auth, timeout=10)
                vdbg = {'vpc': vpc_name, 'id': vpc_id, 'nat_status': nat_r.status_code}
                if nat_r.ok:
                    rules = nat_r.json().get('results', [])
                    vdbg['nat_rules_count'] = len(rules)
                    for rule in rules:
                        translated = rule.get('translated_network', '') or ''
                        if translated:
                            nat_ip = str(translated).split('/')[0]
                            break
                vdbg['nat_ip'] = nat_ip

                # NOTE: LB virtual-server endpoints return 404 in this NSX build.
                # VKS→TGW assignment is done in the frontend via /20 subnet matching
                # between the cluster VIP and the TGW's nat_ip.

                vpc_nats.append((vpc_name, vpc_id, nat_ip))
                vpc_debug_list.append(vdbg)

            # Pass 2 – assign best NAT IP to each TGW in this project
            tgw_id_fallback = tgw_info[proj_tgw_ckeys[0]]['id'] if proj_tgw_ckeys else ''
            for ckey in proj_tgw_ckeys:
                ttype = tgw_info[ckey].get('type', '')
                # Priority order for choosing which VPC's NAT IP to show
                if ttype == 'C':
                    # Supervisor VPC first, then any
                    ordered = sorted(vpc_nats,
                        key=lambda v: 0 if 'kube-system' in v[0].lower() else 1)
                else:
                    # VKS / default-region VPC first, then any
                    ordered = sorted(vpc_nats,
                        key=lambda v: 0 if 'default-region' in v[0].lower() else 1)
                for vn, vid, ni in ordered:
                    if ni:
                        tgw_info[ckey]['nat_ip'] = ni
                        break  # first matching wins

            # Populate vpc_tgw_map for VPC name display (best-effort)
            for vn, vid, ni in vpc_nats:
                if tgw_id_fallback:
                    vpc_tgw_map[vn.lower()] = {
                        'tgw_id': tgw_id_fallback, 'name': vn, 'nat_ip': ni}

            all_vpc_debug.extend(vpc_debug_list)

        # ── 2. Legacy global path (some NSX versions) ─────────────────────
        gl_r = s.get(f"{base}/infra/transit-gateways", auth=nsx_auth, timeout=10)
        for tgw in (gl_r.json().get('results', []) if gl_r.ok else []):
            tid  = tgw['id']
            ckey = f"global:{tid}"
            if ckey not in tgw_info:
                ttype, ext_conn = _resolve_tgw(f"{base}/infra/transit-gateways/{tid}")
                tgw_info[ckey] = dict(id=tid, name=tgw.get('display_name', tid),
                                      type=ttype, ext_conn=ext_conn, nat_ip='',
                                      ckey=ckey, proj_id='global')

        tgw_list = sorted(tgw_info.values(),
                          key=lambda t: 0 if t.get('type') == 'D' else 1)
        return jsonify({'success': True, 'tgws': tgw_list,
                        'vpc_tgw_map': vpc_tgw_map,
                        'vip_to_tgw_ckey': vip_to_tgw_ckey,
                        '_debug': {
                            'global_tgw_status': gl_r.status_code if gl_r.ok else f"FAIL-{gl_r.status_code}",
                            'global_tgw_count':  len([t for t in tgw_info.values()]),
                            'projects_status':   org_r.status_code if org_r.ok else f"FAIL-{org_r.status_code}",
                            'projects_found':    [p['id'] for p in projects],
                            'tgw_ids':           list(tgw_info.keys()),
                                'tgw_types':         {k: v.get('type','?') for k,v in tgw_info.items()},
                        }})

    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e),
                        'tb': traceback.format_exc()})




# ── VPC Public Subnets ─────────────────────────────────────────────────────────

@app.route("/api/nsx-vpc-public-subnets", methods=["POST"])
def nsx_vpc_public_subnets():
    body     = request.get_json(force=True)
    nsx_url  = normalize_url(body.get("nsx_url", ""))
    nsx_user = body.get("nsx_user", "admin")
    nsx_pass = body.get("nsx_pass", "")
    subnets  = []
    try:
        # Use search/aggregate with context:"projects:ALL" — finds subnets across every project
        # in one call (same API the NSX UI uses).
        search_body = {
            "primary": {"resource_type": "VpcSubnet", "filters": []},
            "related": [
                {
                    "resource_type": "Vpc",
                    "join_condition": "path:parent_path",
                    "alias": "Vpc",
                    "included_fields": "id,path,display_name",
                }
            ],
            "context": "projects:ALL",
        }
        cursor = 0
        page_size = 200
        while True:
            resp = SESS.post(
                f"{nsx_url}/policy/api/v1/search/aggregate?page_size={page_size}&cursor={cursor}",
                json=search_body,
                auth=(nsx_user, nsx_pass),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                timeout=20,
                verify=False,
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
            for result in results:
                primary = result.get("primary", {})
                if (primary.get("access_mode") or "").lower() != "public":
                    continue
                path = primary.get("path", "")
                # path: /orgs/default/projects/{proj}/vpcs/{vpc}/subnets/{sub}
                parts = path.split("/")
                proj_id  = parts[4] if len(parts) > 4 else "default"
                vpc_alias = next(
                    (r for r in result.get("related", []) if r.get("alias") == "Vpc"), {}
                )
                vpc_results = vpc_alias.get("results") or [{}]
                vpc_name = vpc_results[0].get("display_name", "") if vpc_results else ""
                subnets.append({
                    "path":         path,
                    "id":           primary.get("id", ""),
                    "display_name": primary.get("display_name", primary.get("id", "")),
                    "project":      proj_id,
                    "vpc":          vpc_name,
                    "ip_addresses": primary.get("ip_addresses", []),
                })
            # Paginate if needed
            total = data.get("result_count", 0)
            cursor += len(results)
            if cursor >= total or not results:
                break

        return jsonify({"success": True, "subnets": subnets})
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "subnets": []})


@app.route("/api/check-vpc-subnet-dhcp", methods=["POST"])
def check_vpc_subnet_dhcp():
    """Check whether a VPC Public subnet has DHCP Server or Relay enabled.
    Accepts subnet_path (NSX Policy path like /orgs/default/projects/P/vpcs/V/subnets/S).
    """
    body        = request.get_json(force=True)
    nsx_url     = normalize_url(body.get("nsx_url", ""))
    nsx_user    = body.get("nsx_user", "admin")
    nsx_pass    = body.get("nsx_pass", "")
    subnet_path = (body.get("subnet_path") or "").strip()
    if not subnet_path:
        return jsonify({"dhcp_enabled": False, "error": "No subnet path provided"})
    try:
        # The NSX Policy path is like /orgs/default/projects/P/vpcs/V/subnets/S
        # Build the full REST URL: /policy/api/v1<path>
        api_path = f"/policy/api/v1{subnet_path}"
        resp = SESS.get(
            f"{nsx_url}{api_path}",
            auth=(nsx_user, nsx_pass),
            headers={"Accept": "application/json"},
            timeout=15,
            verify=False,
        )
        if resp.status_code == 404:
            return jsonify({"dhcp_enabled": False, "error": "Subnet not found"})
        resp.raise_for_status()
        data = resp.json()
        # Check dhcp_config - mode can be "SERVER", "RELAY", or "NONE"/absent
        dhcp_cfg  = data.get("dhcp_config") or {}
        dhcp_mode = (dhcp_cfg.get("mode") or dhcp_cfg.get("resource_type") or "").upper()
        # Also check subnet_dhcp_config (alternate field name in some NSX versions)
        if not dhcp_mode:
            sub_dhcp = data.get("subnet_dhcp_config") or {}
            dhcp_mode = (sub_dhcp.get("mode") or "").upper()
        # Also check top-level dhcp_server_config
        if not dhcp_mode and data.get("dhcp_server_config"):
            dhcp_mode = "SERVER"
        enabled = dhcp_mode in ("SERVER", "RELAY", "DHCP_SERVER", "DHCP_RELAY")
        return jsonify({"dhcp_enabled": enabled, "dhcp_mode": dhcp_mode or "NONE", "error": None})
    except Exception as e:
        return jsonify({"dhcp_enabled": None, "error": str(e)})


if __name__ == "__main__":
    import os as _os
    _port = int(_os.environ.get("SUPERVISOR_CHECK_PORT", "80"))
    app.run(host="0.0.0.0", port=_port, debug=False)
