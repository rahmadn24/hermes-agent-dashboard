#!/usr/bin/env python3
"""Ops Board — operational board + agent/room chat + host status.

Single file, stdlib only. Session-cookie login.
No configuration is required: paths, divisions, models, services, units and
host address are detected from the machine the process runs on.
An optional JSON config ($OPS_CONFIG, else ./config.json) only overrides
detected values; the credential file is the only mandatory input.
Run: python3 ops_board.py --port 8899
"""
import concurrent.futures, hashlib, hmac, html, json, os, re, secrets, shutil, socket, sqlite3, subprocess, sys, tempfile, threading, time
import urllib.error, urllib.parse, urllib.request
from pathlib import Path
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

_DEFAULTS = {
    "app_name": "", "app_short": "OPS", "owner_label": "Owner", "owner_id": "owner",
    "listen_host": "127.0.0.1", "listen_port": 8899,
    "hq_dir": "",
    "tasks_file": "shared/tasks.json", "activity_log": "reports/activity-stream.log",
    "secret_file": ".ops-board.secret", "rooms_dir": "shared/rooms",
    "roster_file": "shared/roster.json", "brand_dir": "brand",
    "files_roots": {"workspace": "workspace", "reports": "reports",
                    "docs": "docs", "scripts": "scripts"},
    "hermes_bin": "", "hermes_home": "",
    "divisions": [], "room_base": [], "agent_models": [],
    "services": [], "units_system": [], "units_user": [], "host_ip": "",
    "session_cookie": "ops_session", "session_ttl": 604800,
    "demo": False, "login_attempts": 10, "login_window": 300,
    "request_limit": 120, "request_window": 60, "max_body": 1048576,
}

def _env(name):
    """Env var as stripped text, '' when unset."""
    return (os.environ.get(name) or "").strip()

def _detect_hq(start):
    """Walk up from `start` for a folder holding shared/ and reports/ or NOTES.md."""
    start = os.path.abspath(start)
    cur = start
    while True:
        if os.path.isdir(os.path.join(cur, "shared")) and (
                os.path.isdir(os.path.join(cur, "reports"))
                or os.path.isfile(os.path.join(cur, "NOTES.md"))):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return start
        cur = parent

def _detect_hermes_home():
    """$HERMES_HOME, else ~/.hermes."""
    for cand in (_env("HERMES_HOME"), os.path.expanduser("~/.hermes")):
        if cand and os.path.isdir(cand):
            return cand
    return os.path.expanduser("~/.hermes")

def _detect_hermes_bin():
    """which hermes, ~/.local/bin/hermes, ~/.hermes/bin/hermes; '' disables chat."""
    found = shutil.which("hermes")
    if found:
        return found
    for cand in (os.path.expanduser("~/.local/bin/hermes"),
                 os.path.expanduser("~/.hermes/bin/hermes")):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return ""

def _profile_rows(home):
    """[(slug, path)] for <home>/profiles/* holding config.yaml, sorted by slug."""
    rows = []
    try:
        for p in sorted(Path(home, "profiles").iterdir()):
            if p.is_dir() and (p / "config.yaml").is_file():
                rows.append((p.name, str(p)))
    except OSError:
        pass
    return rows

def _detect_divisions(home):
    """One division per profile folder; 'ops' when there is none."""
    rows = _profile_rows(home)
    if not rows:
        return [{"slug": "ops", "label": "Ops"}]
    return [{"slug": s, "label": s[:1].upper() + s[1:]} for s, _ in rows]

def _read_model(path):
    """`model.default` (block form) else `model: <scalar>`; '' when unreadable."""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    for i, line in enumerate(lines):
        if line.rstrip() != "model:":
            continue
        for nxt in lines[i + 1:]:
            if nxt.strip() and nxt[:1] not in (" ", "\t"):
                break
            m = re.match(r"^\s+(?:default|model):\s*(\S.*)$", nxt)
            if m:
                return m.group(1).split(" #", 1)[0].strip().strip("\"'")
        break
    for line in lines:
        m = re.match(r"^model:\s*(\S.*)$", line)
        if m:
            return m.group(1).split(" #", 1)[0].strip().strip("\"'")
    return ""

def _detect_agent_models(home):
    """Distinct model values across profiles, 'default' when nothing reads."""
    out = []
    for _slug, path in _profile_rows(home):
        model = _read_model(os.path.join(path, "config.yaml")) or "default"
        if model not in out:
            out.append(model)
    return out or ["default"]

def _local_addr(host):
    """True for the addresses the board is allowed to list as local listens."""
    if host in ("0.0.0.0", "127.0.0.1", "*", ""):
        return True
    if host.startswith("127."):
        return True
    octets = host.split(".")
    if len(octets) == 4 and octets[0] == "172":
        try:
            return 16 <= int(octets[1]) <= 31
        except ValueError:
            return False
    return False

def _detect_services():
    """[label, host, target] from `ss -ltnp`, plus containers when docker answers."""
    rows, seen = [], set()
    try:
        out = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=6).stdout
    except Exception:
        out = ""
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "LISTEN":
            continue
        local = parts[3]
        if local.startswith("["):  # IPv6 listen: skip, the v4 socket is listed too
            continue
        host, _, port = local.rpartition(":")
        host = host.split("%", 1)[0]
        if not port.isdigit() or not _local_addr(host):
            continue
        name = ""
        m = re.search(r'users:\(\("([^"]+)"', line)
        if m:
            name = m.group(1).split(" ", 1)[0]
        key = (name or "-", port)
        if key in seen:
            continue
        seen.add(key)
        rows.append([name or "-", "", local])
    try:
        p = subprocess.run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"],
                           capture_output=True, text=True, timeout=8)
        if p.returncode == 0:
            for line in p.stdout.splitlines():
                name, _, ports = line.partition("\t")
                if not name.strip() or name in seen:
                    continue
                seen.add(name)
                rows.append([name.strip(), "", (ports.strip() or "docker")[:60]])
    except Exception:
        pass
    return rows

def _detect_units(home_ignored=None):
    """(system units, user units) currently running; [] when systemctl is unavailable."""
    def run(extra):
        try:
            p = subprocess.run(["systemctl"] + extra + ["list-units", "--type=service",
                                                       "--state=running", "--no-legend", "--plain"],
                               capture_output=True, text=True, timeout=8)
        except Exception:
            return []
        if p.returncode != 0:
            return []
        return [l.split()[0] for l in p.stdout.splitlines() if l.strip()]
    return run([]), run(["--user"])

def _detect_host_ip():
    """First non-loopback IPv4 of this host, '' when none is found."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 9))  # routed lookup only, nothing is sent
            ip = s.getsockname()[0]
        finally:
            s.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    try:
        cands = subprocess.run(["hostname", "-I"], capture_output=True, text=True,
                               timeout=4).stdout.split()
    except Exception:
        cands = []
    for ip in cands:
        if "." in ip and not ip.startswith("127."):
            return ip
    return ""

def _detect_app_name():
    """$OPS_BOARD_NAME, else '<hostname> Ops', else 'Ops Board'."""
    name = _env("OPS_BOARD_NAME")
    if name:
        return name
    short = ""
    try:
        short = subprocess.run(["hostname", "-s"], capture_output=True, text=True,
                               timeout=4).stdout.strip()
    except Exception:
        short = ""
    if not short:
        try:
            short = socket.gethostname().split(".", 1)[0]
        except Exception:
            short = ""
    return f"{short} Ops" if short else "Ops Board"

def _load_cfg():
    """(merged cfg, keys the file set explicitly). Missing/garbage file = no overrides."""
    path = os.environ.get("OPS_CONFIG") or os.path.join(_SCRIPT_DIR, "config.json")
    raw = {}
    if os.path.isfile(path):
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            sys.exit(f"config {path}: {exc}")
        if not isinstance(raw, dict):
            sys.exit(f"config {path}: top level must be a JSON object")
    cfg = dict(_DEFAULTS)
    cfg.update({k: v for k, v in raw.items() if v is not None})
    return cfg, set(raw)

CFG, _EXPLICIT = _load_cfg()

def _conf(key):
    """Explicit non-empty config value; None means detection decides."""
    val = CFG.get(key)
    return val if key in _EXPLICIT and val not in (None, "", [], {}) else None

def _conf_or(key, detect):
    """Explicit config value wins even when empty; otherwise detection."""
    return CFG[key] if key in _EXPLICIT and CFG[key] is not None else detect()

HQ = os.path.abspath(os.path.expanduser(str(_conf("hq_dir") or _detect_hq(_SCRIPT_DIR))))

def _p(val):
    """Config path: absolute as-is, relative resolved against hq_dir."""
    v = os.path.expanduser(str(val or ""))
    return v if os.path.isabs(v) else os.path.normpath(os.path.join(HQ, v))

TASKS = _p(CFG["tasks_file"])
ACTIVITY = _p(CFG["activity_log"])
SECRET = _p(CFG["secret_file"])
ROOMS_DIR = _p(CFG["rooms_dir"])
BRAND_DIR = _p(CFG["brand_dir"])
BRAND_FILES = {"logo-mark-256.png", "logo-mark-64.png", "logo-full.png", "logo-full-dark.png"}

def _ensure_secret(path):
    """Create the secret with a random credential, mode 0600. True when it was created."""
    if os.path.exists(path):
        return False
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(f"admin:{secrets.token_hex(32)}\n")
    return True

if _ensure_secret(SECRET):
    print(f"secret dibuat: {SECRET} (user admin, password acak di dalam berkas)", flush=True)

HERMES = str(_conf("hermes_bin") or _detect_hermes_bin())
CHAT_ENABLED = bool(HERMES)
AGENT_HOME = Path(os.path.expanduser(str(_conf("hermes_home") or _detect_hermes_home())))
AGENT_BACKUP = Path(HQ) / "backups" / "agent-settings"
ROSTER_FILE = _p(CFG["roster_file"])
ROSTER_TTL = 30
_AVATAR_COLORS = ("#4f8cff", "#22d3ee", "#a78bfa", "#f59e0b", "#22c55e", "#f472b6", "#60a5fa", "#facc15")

DIVISIONS = tuple((str(d.get("slug") or ""), str(d.get("label") or d.get("slug") or ""))
                  for d in _conf_or("divisions", lambda: _detect_divisions(AGENT_HOME))
                  if isinstance(d, dict) and d.get("slug"))
DIV_SLUGS = tuple(s for s, _ in DIVISIONS)

ROOM_BASE = tuple((str(r[0]), str(r[1])) for r in _conf_or(
    "room_base", lambda: [["all-hands", "All Hands"]] + [[s, l] for s, l in DIVISIONS])
                  if isinstance(r, (list, tuple)) and len(r) >= 2)
SERVICES = tuple((str(s[0]), str(s[1] or ""), str(s[2]))
                 for s in _conf_or("services", _detect_services)
                 if isinstance(s, (list, tuple)) and len(s) >= 3)
_UNITS_SYSTEM, _UNITS_USER = _detect_units()
SYS_UNITS = tuple(str(u) for u in _conf_or("units_system", lambda: _UNITS_SYSTEM))
USER_UNITS = tuple(str(u) for u in _conf_or("units_user", lambda: _UNITS_USER))
HOST_IP = str(_conf("host_ip") or _detect_host_ip())
MODELS = [str(m) for m in _conf_or("agent_models",
                                   lambda: _detect_agent_models(AGENT_HOME))] or ["default"]
APP = str(_conf("app_name") or _detect_app_name())
APPSHORT = str(CFG["app_short"] or "OPS")
OWNER_LABEL = str(CFG["owner_label"] or _env("OWNER_LABEL") or "Owner")
OWNER_ID = str(CFG["owner_id"] or _env("OWNER_ID") or "owner")
DEMO = bool(CFG["demo"])
COOKIE = str(CFG["session_cookie"] or "ops_session")
SESSION_TTL = int(CFG["session_ttl"] or 604800)
FILES_ROOTS = {str(k): _p(v) for k, v in (CFG["files_roots"] or {}).items()}
DEFAULT_THREAD = f"room:{ROOM_BASE[0][0]}" if ROOM_BASE else "room:"
_REQ = threading.local()

def _req_domain():
    """Host header of the request being served ('' outside a request)."""
    return str(getattr(_REQ, "domain", "") or "")

_STATE_SNAP = os.path.join(tempfile.gettempdir(), "ops_board_state.json")

_ROSTER = {"at": 0.0, "data": None}
_ROSTER_LOCK = threading.Lock()
_LOCKS = {}
_LOCKS_LOCK = threading.Lock()

def div_label(slug):
    """Label for a division slug from config; unknown slug returned as-is."""
    low = str(slug or "").lower()
    for s, l in DIVISIONS:
        if s.lower() == low:
            return l
    return str(slug or "")

def _tpl(text, **extra):
    """Fill __PLACEHOLDER__ slots. Text slots escaped, JSON slots stay JSON."""
    rep = {
        "__STYLE__": STYLE,
        "__APPSHORT__": html.escape(APPSHORT),
        "__APP__": html.escape(APP),
        "__FOOT__": html.escape(f"{_req_domain()} · {APP}" if _req_domain() else APP),
        "__OWNER__": json.dumps(OWNER_LABEL),
        "__OWNERID__": json.dumps(OWNER_ID),
        "__HQ__": json.dumps(HQ),
        "__DEFTHREAD__": json.dumps(DEFAULT_THREAD),
        "__DIVS__": json.dumps([{"slug": s, "label": l} for s, l in DIVISIONS]),
        "__DIVLABELS__": json.dumps({s: l for s, l in DIVISIONS}),
    }
    rep.update(extra)
    for k, v in rep.items():
        text = text.replace(k, v)
    return text

def _profile_dir(slug):
    """Folder akar satu profile; 'default' = ~/.hermes."""
    if slug == "default":
        return AGENT_HOME
    return AGENT_HOME / "profiles" / slug

def _yaml_block_value(text, key):
    """Nilai skalar YAML tingkat atas. Nilai boleh lanjut di baris ber-indentasi
    (gabung dengan spasi), buang tanda kutip pembungkus. Baris kosong dilewati,
    baris tanpa indentasi mengakhiri nilai."""
    lines = text.splitlines()
    for i, l in enumerate(lines):
        if not l.startswith(key + ":"):
            continue
        vals = [l[len(key) + 1:].strip()]
        for nxt in lines[i + 1:]:
            if not nxt.strip():
                continue
            if nxt[:1] in (" ", "\t"):
                vals.append(nxt.strip())
                continue
            break
        v = " ".join(x for x in vals if x).strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        return v.strip()
    return ""

def _slug_title(slug):
    """software-engineer -> 'Software Engineer'."""
    return " ".join(w[:1].upper() + w[1:] for w in slug.replace("-", " ").split())

def _display_name(slug):
    """Heading pertama SOUL.md: '# Software Engineer — Company Name' -> 'Software Engineer'
    (potong juga pada '–', ' - ', '|'). Tanpa heading / file tidak ada -> _slug_title(slug)."""
    try:
        text = (_profile_dir(slug) / "SOUL.md").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return _slug_title(slug)
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("# "):
            t = s.lstrip("#").strip()
            for sep in ("—", "–", " - ", "|"):
                t = t.split(sep, 1)[0].strip()
            if t:
                return t
            break
    return _slug_title(slug)

def _initials(name, slug):
    """2 huruf besar dari nama tampilan; >=2 kata -> huruf awal dua kata, 1 kata -> 2 huruf awal."""
    words = [w for w in (name or "").split() if w]
    if len(words) >= 2:
        return (words[0][:1] + words[1][:1]).upper()
    if words:
        return words[0][:2].upper()
    return (slug or "?")[:2].upper()

def _color_for(slug):
    """Warna avatar deterministik dari slug (index = sum(ord) % len(_AVATAR_COLORS))."""
    return _AVATAR_COLORS[sum(ord(c) for c in slug) % len(_AVATAR_COLORS)]

def _roster_override():
    """Baca shared/roster.json (read-only, opsional). Return (dict agents by profile, list rooms).
    File tidak ada / JSON rusak / bentuk salah -> ({}, []). Jangan pernah melempar error."""
    try:
        data = json.loads(Path(ROSTER_FILE).read_text(encoding="utf-8"))
    except Exception:
        return {}, []
    if not isinstance(data, dict):
        return {}, []
    agents_by = {}
    for a in data.get("agents") or []:
        if isinstance(a, dict) and isinstance(a.get("profile"), str) and a["profile"]:
            agents_by[a["profile"]] = a
    rooms_list = [r for r in (data.get("rooms") or [])
                  if isinstance(r, dict) and isinstance(r.get("id"), str) and r["id"]]
    return agents_by, rooms_list

def _discover():
    """Pindai filesystem, return {"agents": [...], "rooms": {...}}."""
    ov_agents, ov_rooms = _roster_override()
    slugs = []
    try:
        for p in sorted((AGENT_HOME / "profiles").iterdir()):
            if p.is_dir() and (p / "config.yaml").is_file():
                slugs.append(p.name)
    except OSError:
        pass
    if (AGENT_HOME / "config.yaml").is_file():
        slugs.insert(0, "default")
    if not slugs and ov_agents:
        slugs = sorted(ov_agents)
    out = []
    for slug in slugs:
        pdir = _profile_dir(slug)
        o = ov_agents.get(slug) or {}
        try:
            ptext = (pdir / "profile.yaml").read_text(encoding="utf-8", errors="replace")
        except OSError:
            ptext = ""
        desc = _yaml_block_value(ptext, "description") if ptext else ""
        label = o.get("label")
        if isinstance(label, str) and label.strip():
            name = label.strip()
        else:
            name = OWNER_LABEL if slug == "default" else _display_name(slug)
        division = o.get("division")
        if not (isinstance(division, str) and division):
            division = next((d for d in DIV_SLUGS if slug.startswith(d)),
                            DIV_SLUGS[0] if DIV_SLUGS else "HQ")
        order = o.get("order")
        if not isinstance(order, int) or isinstance(order, bool):
            order = 999
        role = o.get("role")
        if not (isinstance(role, str) and role):
            role = desc or (f"{OWNER_LABEL} · read-only" if slug == "default" else division)
        model, provider = _config_model(str(pdir / "config.yaml"))
        out.append({"bot": slug, "id": slug, "label": name, "name": name,
                    "initials": _initials(name, slug), "color": _color_for(slug),
                    "description": desc, "division": division, "order": order,
                    "role": role, "model": model, "provider": provider,
                    "chat": slug != "default", "read_only": slug == "default"})
    out.sort(key=lambda a: (a["order"], a["bot"]))
    ids = [a["bot"] for a in out]
    room_ov = {r["id"]: r for r in ov_rooms}
    rooms_out = {}
    for rid, rname in ROOM_BASE:
        o = room_ov.get(rid) or {}
        members = o.get("members")
        if isinstance(members, list):
            members = [m for m in members if isinstance(m, str) and m in ids]
        elif ROOM_BASE and rid == ROOM_BASE[0][0]:
            members = list(ids)
        else:
            div = rid if rid in DIV_SLUGS else (rid.split("-", 1)[1] if "-" in rid else rid)
            hqslug = DIV_SLUGS[0] if DIV_SLUGS else "hq"
            members = [a["bot"] for a in out if a["bot"] != "default" and
                       (a["division"].lower() == div or a["division"].lower() == hqslug)]
        name = o.get("name")
        if not (isinstance(name, str) and name):
            name = rname
        rooms_out[rid] = {"name": name, "members": members, "rounds": 1}
    return {"agents": out, "rooms": rooms_out}

def _roster_state():
    """_discover() dengan cache 30 detik di bawah _ROSTER_LOCK."""
    now = time.time()
    with _ROSTER_LOCK:
        if _ROSTER["data"] is None or now - _ROSTER["at"] > ROSTER_TTL:
            _ROSTER["data"] = _discover()
            _ROSTER["at"] = now
        return _ROSTER["data"]

def agents():
    """List dict agen terurut."""
    return _roster_state()["agents"]

def agent_ids():
    """List slug agen, termasuk 'default'."""
    return [a["bot"] for a in agents()]

def profile_ids():
    """agent_ids() tanpa 'default'."""
    return [b for b in agent_ids() if b != "default"]

def agent_cfg(bot):
    """dict satu agen atau None."""
    return next((a for a in agents() if a["bot"] == bot), None)

def rooms():
    """dict room id -> {"name", "members", "rounds"}."""
    return _roster_state()["rooms"]

def room_cfg(rid):
    """rooms().get(rid)."""
    return rooms().get(rid)

def _bot_lock(bot):
    """threading.Lock per bot, dibuat lazy di bawah _LOCKS_LOCK."""
    with _LOCKS_LOCK:
        lock = _LOCKS.get(bot)
        if lock is None:
            lock = _LOCKS[bot] = threading.Lock()
        return lock

BOT_RE = re.compile(r"^[a-z0-9-]{2,32}$")
SKILL_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
SKILL_MAX_BYTES = 20000
SKILL_DESC_MAX = 200
CRON_FIELD_RE = re.compile(r"^[0-9*/,\-]+$")
ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
FILE_TEXT_MAX = 512 * 1024
FILE_LIST_MAX = 500
_FILE_BLOCK_SUFFIX = (".secret", ".env", ".pem", ".key", ".db", ".sqlite", ".log")

def _bad_name(rel):
    """Daftar hitam nama path — tanpa membaca isi file."""
    for part in (rel or "").replace("\\", "/").split("/"):
        low = part.lower()
        if not low:
            continue
        if low in (".git", "id_rsa", "id_ed25519", ".ssh") or low.startswith(".ops-board"):
            return True
        if low == os.path.basename(SECRET).lower():
            return True
        if low.endswith(_FILE_BLOCK_SUFFIX):
            return True
        if "token=" in low or "api_key=" in low:
            return True
    return False

def _file_path(root, rel):
    """(abs_path, err_code, err_msg) — root whitelist + anti traversal + daftar hitam."""
    if root not in FILES_ROOTS:
        return None, 400, "root tidak dikenal"
    rel = rel or ""
    if "\x00" in rel or rel.startswith("/") or rel.startswith("\\"):
        return None, 400, "path tidak valid"
    if any(p == ".." for p in rel.replace("\\", "/").split("/")):
        return None, 403, "path tidak valid"
    base = os.path.realpath(FILES_ROOTS[root])
    target = os.path.realpath(os.path.join(base, rel))
    if target != base and not target.startswith(base + os.sep):
        return None, 403, "di luar root"
    if target != os.path.realpath(ACTIVITY) and _bad_name(rel):
        return None, 403, "path sensitif"
    if not os.path.exists(target):
        return None, 404, "tidak ditemukan"
    return target, 0, ""

def _crumbs(root, rel):
    out = [{"label": root, "path": ""}]
    acc = []
    for seg in [s for s in (rel or "").replace("\\", "/").split("/") if s]:
        acc.append(seg)
        out.append({"label": seg, "path": "/".join(acc)})
    return out

def file_entries(root, rel):
    base, code, msg = _file_path(root, rel)
    if not base:
        return None, code, msg
    if not os.path.isdir(base):
        return None, 400, "bukan direktori"
    real_root = os.path.realpath(FILES_ROOTS[root])
    entries = []
    try:
        names = os.listdir(base)
    except OSError:
        names = []
    for name in names:
        if _bad_name(name):
            continue
        full = os.path.join(base, name)
        real = os.path.realpath(full)
        if real != real_root and not real.startswith(real_root + os.sep):
            continue
        try:
            st = os.stat(full)
        except OSError:
            continue
        isdir = os.path.isdir(full)
        entries.append({
            "name": name,
            "type": "dir" if isdir else "file",
            "size": 0 if isdir else int(st.st_size),
            "mtime": int(st.st_mtime),
            "ext": "" if isdir else os.path.splitext(name)[1].lstrip(".").lower(),
        })
    entries.sort(key=lambda e: (e["type"] != "dir", e["name"].lower()))
    return {"root": root, "path": rel or "", "breadcrumb": _crumbs(root, rel),
            "entries": entries[:FILE_LIST_MAX]}, 0, ""

def file_read(root, rel):
    path, code, msg = _file_path(root, rel)
    if not path:
        return None, code, msg
    if os.path.isdir(path):
        return None, 400, "bukan file"
    try:
        st = os.stat(path)
    except OSError:
        return None, 404, "tidak ditemukan"
    size = int(st.st_size)
    out = {"name": os.path.basename(path), "root": root, "path": rel or "",
           "size": size, "mtime": int(st.st_mtime), "lines": 0, "binary": False,
           "content": None, "truncated": False}
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
    except OSError:
        return None, 404, "tidak ditemukan"
    if b"\x00" in head:
        out["binary"] = True
        return out, 0, ""
    if size > FILE_TEXT_MAX:
        out["truncated"] = True
        out["lines"] = None
        return out, 0, ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None, 404, "tidak ditemukan"
    out["content"] = text
    out["lines"] = 0 if not text else text.count("\n") + (0 if text.endswith("\n") else 1)
    return out, 0, ""

# ---------- data ----------

def load_tasks():
    try:
        return json.load(open(TASKS))["tasks"]
    except Exception as exc:
        return [{"id": "ERR", "title": f"tasks.json tidak terbaca: {exc}", "status": "blocked",
                 "agen": "-", "prioritas": "-"}]

def load_activity(limit=200):
    try:
        return list(reversed(open(ACTIVITY, errors="replace").read().splitlines()[-limit:]))
    except OSError:
        return []

def room_log(room_id, limit=40):
    path = os.path.join(ROOMS_DIR, f"{room_id}.jsonl")
    if not os.path.exists(path):
        return []
    rows = []
    for line in open(path, errors="replace").read().splitlines()[-limit:]:
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    return rows

def room_members(room_id):
    """Anggota room = owner + member terkonfigurasi + siapa pun yang benar-benar menulis di JSONL.
    Owner selalu ditampilkan terpisah dengan label dari config."""
    seen = [OWNER_ID] + [m for m in rooms().get(room_id, {}).get("members", []) if m != "default"]
    for row in room_log(room_id):
        who = str(row.get("who") or "").strip()
        if who and who != "default" and who not in seen:
            seen.append(who)
    out = []
    for who in seen:
        label = OWNER_LABEL if who == OWNER_ID else who
        if label not in out:
            out.append(label)
    return out

def chat(profile, text):
    if DEMO:
        return f"(demo) {profile} menerima: {text[:200]}"
    if not CHAT_ENABLED:
        return "hermes tidak ditemukan di mesin ini; fitur chat dimatikan"
    if profile not in profile_ids():
        return "profile tidak dikenal"
    cwd = f"{HQ}/shared" if profile == "hq-orchestrator" else f"{HQ}/workspace"
    try:
        p = subprocess.run([HERMES, "-p", profile, "chat", "-q", text, "--oneshot"],
                           capture_output=True, text=True, timeout=420, cwd=cwd)
    except subprocess.TimeoutExpired:
        return "[timeout 420s — turn masih jalan atau model lambat]"
    out = ANSI.sub("", (p.stdout or "") + (p.stderr or "")).strip()
    if "BALAS:" in out:
        out = out.rsplit("BALAS:", 1)[1].strip()
    keep = [l for l in out.splitlines()
            if not re.match(r"^(Resume this session|hermes --resume|Session:|Duration:|Messages:|💻|⚙|─+$|☤|∴|Query:)", l.strip())]
    return "\n".join(keep).strip()[:6000] or "(kosong)"

def room_turn(room_id, text):
    cfg = room_cfg(room_id)
    if not cfg:
        return {"error": "room tidak dikenal"}
    os.makedirs(ROOMS_DIR, exist_ok=True)
    path = os.path.join(ROOMS_DIR, f"{room_id}.jsonl")
    def stamp():
        return time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with open(path, "a") as fh:
        fh.write(json.dumps({"ts": stamp(), "who": OWNER_ID, "text": text}, ensure_ascii=False) + "\n")
    for _ in range(int(cfg.get("rounds", 1))):
        for profile in cfg["members"]:
            hist = "\n".join(f"{r['who']}: {r['text'][:800]}" for r in room_log(room_id, 20))
            prompt = (f"Room {cfg['name']} ({room_id}). Transkrip:\n{hist}\n\n"
                      f"Perintah {OWNER_LABEL}: {text}\n\n"
                      "Jawab sebagai peranmu, maksimal 5 baris, tanpa basa-basi. "
                      "Kalau bukan bidangmu, bilang singkat siapa yang harus ambil. "
                      "Tulis balasan setelah label 'BALAS:' dan jangan ulangi instruksi ini.")
            with open(path, "a") as fh:
                fh.write(json.dumps({"ts": stamp(), "who": profile, "text": chat(profile, prompt)},
                                    ensure_ascii=False) + "\n")
    return {"ok": True, "log": room_log(room_id)}

_vps_cache = {"at": 0.0, "data": None}

_STATE = {"at": 0.0, "data": None}
_STATE_LOCK = threading.Lock()
_STATE_READY = threading.Event()
_STATE_TTL = 900

def _sh(cmd, timeout=8):
    if DEMO:
        return ""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""

def _human(sec):
    sec = int(max(0, sec))
    d, h, m = sec // 86400, (sec % 86400) // 3600, (sec % 3600) // 60
    if d:
        return f"{d}d {h}h"
    return f"{h}h {m}m" if h else f"{m}m"

def _probe(url, timeout=2):
    if DEMO:
        return {"code": 0, "ms": 0}
    t0 = time.time()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"user-agent": "ops-board"}),
                                    timeout=timeout) as r:
            code = r.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    except Exception:
        code = 0
    return {"code": code, "ms": int((time.time() - t0) * 1000)}

def _svc_probe(svc):
    """Probe a service tuple; detected services have no host, so nothing to probe."""
    return _probe("https://" + svc[1], 2) if svc[1] else {"code": 0, "ms": 0}

_CPU_LAST = {"tot": None, "idle": None, "ts": 0.0, "pct": None}


def _cpu_pct():
    """Persen CPU dari delta /proc/stat sejak sampel sebelumnya."""
    def snap():
        try:
            v = [int(x) for x in open("/proc/stat").readline().split()[1:]]
        except Exception:
            return None
        return sum(v), v[3] + v[4]

    st = _CPU_LAST
    cur = snap()
    if cur is None:
        return 0.0
    if st["tot"] is None or st["pct"] is None:
        time.sleep(0.2)
        nxt = snap()
        if nxt is None:
            return 0.0
        dt, di = nxt[0] - cur[0], nxt[1] - cur[1]
        if dt > 0:
            st["pct"] = round(100.0 * (dt - di) / dt, 1)
        cur = nxt
    elif time.time() - st["ts"] >= 1.0:
        dt, di = cur[0] - st["tot"], cur[1] - st["idle"]
        if dt > 0:
            st["pct"] = round(100.0 * (dt - di) / dt, 1)
    st["tot"], st["idle"], st["ts"] = cur[0], cur[1], time.time()
    return st["pct"] if st["pct"] is not None else 0.0

def _unit_rows():
    rows = []
    boot = float(open("/proc/uptime").read().split()[0])
    for scope, names in (("system", SYS_UNITS), ("user", USER_UNITS)):
        base = ["systemctl"] + (["--user"] if scope == "user" else [])
        for name in names:
            out = _sh(base + ["show", "-p", "ActiveState", "-p", "ActiveEnterTimestampMonotonic",
                              "-p", "MemoryCurrent", name], timeout=5)
            f = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
            state = f.get("ActiveState") or "unknown"
            up = "—"
            try:
                mono = int(f.get("ActiveEnterTimestampMonotonic") or 0) / 1e6
                if mono > 0 and boot > mono:
                    up = _human(boot - mono)
            except (TypeError, ValueError):
                pass
            mem = None
            try:
                mc = int(f.get("MemoryCurrent") or 0)
                mem = round(mc / 2 ** 20, 1) if mc > 0 else None
            except (TypeError, ValueError):
                pass
            rows.append({"name": name, "scope": scope, "state": state, "uptime": up, "mem_mb": mem})
    return rows

def _containers():
    fmt = "{{.Names}}\t{{.Image}}\t{{.ID}}\t{{.Status}}\t{{.Ports}}"
    ps = _sh(["sudo", "-n", "docker", "ps", "--format", fmt], timeout=10)
    if not ps.strip():
        ps = _sh(["docker", "ps", "--format", fmt], timeout=10)
    sfmt = "{{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}"
    st = _sh(["sudo", "-n", "docker", "stats", "--no-stream", "--format", sfmt], timeout=12)
    if not st.strip():
        st = _sh(["docker", "stats", "--no-stream", "--format", sfmt], timeout=12)
    stats = {}
    for line in st.splitlines():
        p = line.split("\t")
        if len(p) >= 3:
            stats[p[0]] = (p[1].strip(), p[2].strip())
    out = []
    for line in ps.splitlines():
        p = line.split("\t")
        if not p or not p[0].strip():
            continue
        mem_use, mem_raw = stats.get(p[0], ("", ""))
        try:
            pct = float(mem_raw.rstrip("%"))
        except ValueError:
            pct = None
        status = p[3].strip() if len(p) > 3 else ""
        health = "healthy" if "(healthy)" in status else ("unhealthy" if "(unhealthy)" in status else "")
        out.append({"name": p[0], "image": p[1] if len(p) > 1 else "",
                    "cid": (p[2] if len(p) > 2 else "")[:7],
                    "status": status.replace(" (healthy)", "").replace(" (unhealthy)", ""),
                    "health": health, "ports": (p[4].strip() if len(p) > 4 else "") or "—",
                    "mem_used": mem_use or "—", "mem_pct": pct})
    return out

def _vlogs(limit=15):
    rows = []
    try:
        lines = open(ACTIVITY, errors="replace").read().splitlines()[-limit:]
    except OSError:
        return rows
    for line in lines:
        parts = line.split(" | ")
        head = parts[0].strip()
        bits = head.split(None, 1)
        stamp = bits[0] if bits else ""
        who = bits[1].strip() if len(bits) > 1 else ""
        tm = stamp[11:19] if len(stamp) > 10 else stamp[:8]
        tag = (who or "log").upper()[:18]
        body = " | ".join(parts[1:-1]).strip() if len(parts) > 2 else (parts[1].strip() if len(parts) > 1 else line)
        rows.append({"time": tm, "tag": tag, "text": re.sub(r"\s+", " ", body)[:600]})
    return rows

def vps_status():
    if _vps_cache["data"] and time.time() - _vps_cache["at"] < 20:
        return _vps_cache["data"]
    mi = {}
    for line in open("/proc/meminfo"):
        if ":" in line:
            k, v = line.split(":", 1)
            mi[k] = int(v.split()[0]) if v.split() else 0
    total, avail = mi.get("MemTotal", 0), mi.get("MemAvailable", mi.get("MemFree", 0))
    cache = mi.get("Cached", 0) + mi.get("SReclaimable", 0)
    swap_t, swap_f = mi.get("SwapTotal", 0), mi.get("SwapFree", 0)
    st = os.statvfs("/")
    dtot = st.f_blocks * st.f_frsize
    dfree = st.f_bavail * st.f_frsize
    dused = dtot - dfree
    inodes = st.f_files or 0
    inode_used = inodes - st.f_ffree
    up = float(open("/proc/uptime").read().split()[0])
    ld = open("/proc/loadavg").read().split()
    procs = ld[3].split("/")[-1] if len(ld) > 3 else "—"
    ts_name = "—"
    try:
        tj = json.loads(_sh(["tailscale", "status", "--json"], 4) or "{}")
        ts_name = ((tj.get("Self") or {}).get("HostName")) or "—"
    except Exception:
        ts_name = "—"
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        res = list(ex.map(_svc_probe, SERVICES))
    endpoints = [{"label": d[0], "host": d[1], "url": ("https://" + d[1]) if d[1] else "",
                  "code": r["code"], "ms": r["ms"], "target": d[2]}
                 for d, r in zip(SERVICES, res)]
    data = {
        "host": HOST_IP or (_sh(["hostname", "-I"], 3).split() or ["—"])[0],
        "host_local": (_sh(["hostname", "-I"], 3).split() or ["—"])[0],
        "hostname": _sh(["hostname"], 3).strip() or "—",
        "tailscale_name": ts_name,
        "arch": _sh(["uname", "-m"], 3).strip() or "—",
        "virt": (_sh(["systemd-detect-virt"], 3).strip() or "—").upper(),
        "kernel": _sh(["uname", "-r"], 3).strip() or "—",
        "vcpus": os.cpu_count() or 0, "cpu": _cpu_pct(), "load": ld[:3],
        "mem": {"total_mb": total // 1024, "used_mb": (total - avail) // 1024,
                "avail_mb": avail // 1024, "cached_mb": cache // 1024,
                "free_mb": mi.get("MemFree", 0) // 1024,
                "pct": round(100 * (total - avail) / total, 1) if total else 0,
                "swap_total_mb": swap_t // 1024, "swap_used_mb": (swap_t - swap_f) // 1024,
                "swap_pct": round(100 * (swap_t - swap_f) / swap_t, 1) if swap_t else 0},
        "disk": {"total_gb": round(dtot / 2 ** 30, 1), "used_gb": round(dused / 2 ** 30, 1),
                 "free_gb": round(dfree / 2 ** 30, 1),
                 "pct": round(100 * dused / dtot, 1) if dtot else 0,
                 "inode_pct": round(100 * inode_used / inodes, 1) if inodes else 0, "mount": "/"},
        "uptime_s": int(up), "uptime_h": round(up / 3600, 1), "uptime_human": _human(up),
        "boot_at": int(time.time() - up), "processes": procs,
        "sessions": len([l for l in _sh(["who"], 3).splitlines() if l.strip()]),
        "units": _unit_rows(), "containers": _containers(), "endpoints": endpoints,
        "logs": _vlogs(), "refreshed_at": int(time.time()),
    }
    _vps_cache.update(at=time.time(), data=data)
    return data

def build_state():
    """Payload /api/state — satu-satunya definisi bentuk JSON-nya."""
    return {"tasks": load_tasks(), "activity": load_activity(), "vps": vps_status(),
            "group_logs": {rid: room_log(rid) for rid in rooms()},
            "room_defs": {rid: {"name": c["name"], "members": room_members(rid)}
                          for rid, c in rooms().items()}}

def _state_dump(data):
    try:
        os.makedirs(os.path.dirname(_STATE_SNAP), exist_ok=True)
        tmp = _STATE_SNAP + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, _STATE_SNAP)
    except OSError:
        pass

def _state_restore():
    try:
        if time.time() - os.path.getmtime(_STATE_SNAP) > _STATE_TTL:
            return None
        with open(_STATE_SNAP, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) and "vps" in data else None
    except (OSError, ValueError):
        return None

def state_refresh():
    with _STATE_LOCK:
        data = build_state()
        _STATE.update(at=time.time(), data=data)
        _STATE_READY.set()
        _state_dump(data)
        return data

def state_get(timeout=2.0):
    if _STATE["data"] is not None:
        if time.time() - _STATE["at"] < _STATE_TTL:
            return _STATE["data"]
    else:
        _STATE_READY.wait(timeout)
        if _STATE["data"] is not None:
            return _STATE["data"]
    return state_refresh()

def _state_warm():
    snap = _state_restore()
    if snap is not None and _STATE["data"] is None:
        _STATE.update(at=time.time(), data=snap)
        _STATE_READY.set()
    while True:
        try:
            state_refresh()
        except Exception:
            pass
        time.sleep(60)

# ---------- agent settings ----------

def agent_root(bot):
    if bot not in agent_ids():
        return None
    root = AGENT_HOME if bot == "default" else AGENT_HOME / "profiles" / bot
    try:
        root = root.resolve()
    except OSError:
        return None
    return root if root.is_dir() else None

def agent_path(bot, *parts):
    root = agent_root(bot)
    if root is None:
        return None
    p = root.joinpath(*parts)
    if p.is_symlink():
        return None
    try:
        rp = p.resolve(strict=False)
    except OSError:
        return None
    if rp != root and root not in rp.parents:
        return None
    return rp

def _config_path(bot):
    return agent_path(bot, "config.yaml")

def _profile_yaml_path(bot):
    return agent_path(bot, "profile.yaml")

def _soul_path(bot):
    return agent_path(bot, "SOUL.md")

def _jobs_path(bot):
    return agent_path(bot, "cron", "jobs.json")

def _dir_kb(path, limit=20000):
    total = n = 0
    try:
        for root, _dirs, files in os.walk(str(path)):
            for f in files:
                if n >= limit:
                    return round(total / 1024, 1)
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
                n += 1
    except OSError:
        pass
    return round(total / 1024, 1)

def agent_stats(bot, entries=None):
    root = agent_root(bot)
    sessions = messages = last = 0
    db = bot_db(bot)
    if db and os.path.isfile(db):
        try:
            con = _ro(db)
            try:
                sessions = con.execute("select count(*) from sessions").fetchone()[0] or 0
                messages = con.execute(
                    "select count(*) from messages where role in ('user','assistant')").fetchone()[0] or 0
                a = con.execute(
                    "select max(coalesce(last_activity_at,started_at,0)) from sessions").fetchone()[0] or 0
                b = con.execute("select max(timestamp) from messages").fetchone()[0] or 0
                last = max(a, b)
            finally:
                con.close()
        except Exception:
            sessions = messages = last = 0
    memory_kb = _dir_kb(root / "memories") if root else 0
    if entries is None:
        try:
            entries = skill_entries(bot)
        except OSError:
            entries = []
    skills = len(entries)
    return {"sessions": sessions, "messages": messages, "last_activity": last,
            "memory_kb": memory_kb, "skills": skills,
            "folder_kb": _dir_kb(root) if root else 0}

def _skills_dir(bot):
    root = agent_root(bot)
    if root is None:
        return None
    d = root / "skills"
    if d.is_symlink():
        return None
    try:
        rd = d.resolve(strict=False)
    except OSError:
        return None
    if rd != root and root not in rd.parents:
        return None
    return rd

def _skill_meta(text):
    name = description = ""
    body = text
    lines = text.splitlines(keepends=True)
    if lines and lines[0].strip() == "---":
        end = None
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                end = i
                break
        if end is not None:
            for line in lines[1:end]:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                    v = v[1:-1]
                if k == "name":
                    name = v
                elif k == "description":
                    description = v
            body = "".join(lines[end + 1:])
    return name, description, body

def skill_entries(bot):
    d = _skills_dir(bot)
    out = []
    if d is None or not d.is_dir():
        return out
    try:
        children = sorted(d.iterdir())
    except OSError:
        return out
    for child in children:
        try:
            name = child.name
            if not child.is_dir():
                continue
            if child.is_symlink():
                continue
            if not SKILL_RE.fullmatch(name):
                continue
            rd = child.resolve(strict=False)
            if rd != d and d not in rd.parents:
                continue
            f = child / "SKILL.md"
            if not f.is_file() or f.is_symlink():
                continue
            with f.open(encoding="utf-8", errors="replace") as fh:
                text = fh.read(65536)
            meta_name, meta_desc, body = _skill_meta(text)
            if not meta_name:
                meta_name = name
            if not meta_desc:
                desc = ""
                for line in body.splitlines():
                    if line.strip():
                        desc = line.strip()
                        break
                meta_desc = desc[:160]
            st = f.stat()
            out.append({
                "name": meta_name,
                "description": " ".join(meta_desc.split()),
                "size": st.st_size,
                "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
            })
        except OSError:
            continue
    out.sort(key=lambda e: e["name"])
    return out

def _clean_yaml_value(v):
    v = v.split(" #", 1)[0].strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v.strip()

def _config_model(path):
    if not path:
        return "", ""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "", ""
    start = None
    for i, l in enumerate(lines):
        if l.rstrip() == "model:":
            start = i
            break
    if start is None:
        return "", ""
    model = provider = ""
    for l in lines[start + 1:]:
        if re.match(r"^[A-Za-z_]", l):
            break
        m = re.match(r"^\s+default:\s*(.+)$", l) or re.match(r"^\s+model:\s*(.+)$", l)
        if m and not model:
            model = _clean_yaml_value(m.group(1))
        m = re.match(r"^\s+provider:\s*(.+)$", l)
        if m and not provider:
            provider = _clean_yaml_value(m.group(1))
    return model, provider

def agent_description(bot, fallback):
    p = _profile_yaml_path(bot)
    if p and p.is_file():
        try:
            v = _yaml_block_value(p.read_text(encoding="utf-8", errors="replace"), "description")
            if v:
                return v
        except OSError:
            pass
    return fallback

def _routine_schedule(j):
    s = j.get("schedule")
    if isinstance(s, dict):
        return s.get("expr") or s.get("display") or ""
    if isinstance(s, str):
        return s
    return j.get("schedule_display") or ""

_ROUTINE_EXTRA = ("deliver", "next_run_at", "last_run_at", "last_status", "timezone")

def _routine_item(j):
    item = {"id": j.get("id"), "name": j.get("name") or "(tanpa nama)",
            "schedule": _routine_schedule(j),
            "enabled": bool(j.get("enabled", True))}
    if "prompt" in j:
        item["prompt"] = j.get("prompt") or ""
    for k in _ROUTINE_EXTRA:
        if j.get(k):
            item[k] = j[k]
    steps = j.get("steps") or j.get("langkah")
    if steps:
        item["steps"] = steps
    return item

def agent_state(last, now=None):
    src = "stats.last_activity (state.db)"
    now = time.time() if now is None else now
    try:
        last = float(last or 0)
    except (TypeError, ValueError):
        last = 0
    if not last:
        return {"text": "Idle", "cls": "", "minutes": None, "source": src}
    minutes = max(0, int((now - last) // 60))
    if minutes <= 10:
        return {"text": "Aktif", "cls": "on", "minutes": minutes, "source": src}
    if minutes <= 1440:
        return {"text": "Aktif hari ini", "cls": "today", "minutes": minutes, "source": src}
    return {"text": "Idle", "cls": "", "minutes": minutes, "source": src}

def _routines(bot):
    p = _jobs_path(bot)
    out = []
    if not p or not p.is_file():
        return out
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, list):
        return out
    for j in jobs:
        if not isinstance(j, dict) or not j.get("id"):
            continue
        out.append(_routine_item(j))
    return out

def agent_info(bot):
    rows = skill_entries(bot)
    b = agent_cfg(bot)
    cfg = _config_path(bot)
    model, provider = _config_model(cfg)
    soul = ""
    sp = _soul_path(bot)
    if sp and sp.is_file():
        try:
            soul = sp.read_text(encoding="utf-8", errors="replace")[:20000]
        except OSError:
            soul = ""
    members = set()
    for c in rooms().values():
        if bot in c["members"]:
            members.update(c["members"])
    members.discard(bot)
    stats = agent_stats(bot, rows)
    routines = _routines(bot)
    return {"name": b["name"] if b else bot, "bot": bot,
            "initials": b["initials"] if b else "", "color": b["color"] if b else "#8a94a6",
            "description": agent_description(bot, b["role"] if b else ""),
            "model": model, "provider": provider,
            "config_path": ("config.yaml" if bot == "default" else f"profiles/{bot}/config.yaml"),
            "soul": soul, "members": sorted(members), "stats": stats,
            "state": agent_state(stats.get("last_activity")),
            "skills": rows,
            "routines": routines, "routine_count": len(routines), "models": MODELS,
            "read_only": bot == "default"}

def roster():
    out = []
    for a in agents():
        stats = agent_stats(a["bot"])
        out.append({
            "bot": a["bot"], "name": a["name"], "role": a["role"],
            "initials": a["initials"], "color": a["color"],
            "state": agent_state(stats.get("last_activity")),
            "description": agent_description(a["bot"], a["description"] or a["role"]),
            "skills": len(skill_entries(a["bot"])),
            "routines": len(_routines(a["bot"])),
            "read_only": a["bot"] == "default",
            "division": a["division"], "order": a["order"],
            "model": a["model"], "provider": a["provider"],
        })
    return out

def _atomic_write(path, text):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix="." + path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text); fh.flush(); os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

def _agent_backup(bot, files):
    ts = time.strftime("%Y%m%d-%H%M%S")
    dest = AGENT_BACKUP / f"{bot}-{ts}"
    dest.mkdir(parents=True, exist_ok=True)
    for f in files:
        if f and Path(f).is_file():
            shutil.copy2(f, dest / Path(f).name)
    return dest

def _agent_audit(bot, changed):
    line = "%s | agent-settings | %s | changed: %s\n" % (
        time.strftime("%H:%M:%S"), bot, ", ".join(changed))
    try:
        Path(ACTIVITY).parent.mkdir(parents=True, exist_ok=True)
        with open(ACTIVITY, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass

def _set_config_model(text, model):
    lines = text.splitlines(keepends=True)
    start = next((i for i, l in enumerate(lines) if l.rstrip("\r\n") == "model:"), None)
    if start is None:
        if text and not text.endswith("\n"):
            text += "\n"
        return text + "model:\n  default: %s\n" % model
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if re.match(r"^[A-Za-z_]", lines[i]):
            end = i
            break
    for i in range(start + 1, end):
        if re.match(r"^\s+default:\s*(.+)$", lines[i]):
            indent = re.match(r"^(\s+)", lines[i]).group(1)
            lines[i] = "%sdefault: %s\n" % (indent, model)
            return "".join(lines)
    lines.insert(start + 1, "  default: %s\n" % model)
    return "".join(lines)

def agent_update(bot, body):
    if bot not in agent_ids() or not BOT_RE.fullmatch(bot):
        return 404, {"error": "bot tidak dikenal"}
    if bot == "default":
        return 403, {"error": "read-only"}
    if not isinstance(body, dict):
        return 400, {"error": "body harus objek"}
    if "model" in body:
        if not isinstance(body["model"], str) or body["model"] not in MODELS:
            return 400, {"error": "model di luar whitelist"}
    if "description" in body:
        d = body["description"]
        if not isinstance(d, str) or len(d) > 200:
            return 400, {"error": "description tidak valid"}
    if "soul" in body:
        s = body["soul"]
        if not isinstance(s, str) or len(s) > 20000:
            return 400, {"error": "soul tidak valid"}
    routines_in = None
    if "routines" in body:
        rl = body["routines"]
        if not isinstance(rl, list) or len(rl) > 20:
            return 400, {"error": "routines tidak valid"}
        for r in rl:
            if not isinstance(r, dict):
                return 400, {"error": "routines tidak valid"}
            rid = r.get("id")
            if not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", rid):
                return 400, {"error": "routines tidak valid"}
            if not isinstance(r.get("enabled"), bool):
                return 400, {"error": "routines tidak valid"}
            if not cron_valid(r.get("schedule")):
                return 400, {"error": "routines tidak valid"}
            if "prompt" in r and (not isinstance(r["prompt"], str) or len(r["prompt"]) > 4000):
                return 400, {"error": "routines tidak valid"}
        routines_in = rl

    cfg = _config_path(bot)
    prof = _profile_yaml_path(bot)
    soul_p = _soul_path(bot)
    targets = []
    if "model" in body:
        targets.append(cfg)
    if "description" in body:
        targets.append(prof)
    if "soul" in body:
        targets.append(soul_p)
    dest = _agent_backup(bot, targets)

    changed = []
    if "model" in body:
        try:
            text = cfg.read_text(encoding="utf-8")
        except OSError:
            return 400, {"error": "config tidak bisa dibaca"}
        new = _set_config_model(text, body["model"])
        if new != text:
            _atomic_write(cfg, new)
            changed.append("model")
    if "description" in body:
        val = " ".join(body["description"].splitlines()).strip()
        try:
            text = prof.read_text(encoding="utf-8") if prof.is_file() else ""
        except OSError:
            text = ""
        new, n = re.subn(r"^description:.*$", "description: " + val, text, count=1, flags=re.M)
        if not n:
            new = "description: %s\n" % val + text
        if new != text:
            prof.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(prof, new)
            changed.append("description")
    if "soul" in body:
        try:
            old = soul_p.read_text(encoding="utf-8") if soul_p.is_file() else ""
        except OSError:
            old = ""
        if body["soul"] != old:
            soul_p.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(soul_p, body["soul"])
            changed.append("soul")

    for r in routines_in or []:
        upd = {"enabled": r["enabled"], "schedule": r["schedule"]}
        if "prompt" in r:
            upd["prompt"] = r["prompt"]
        code, payload = routine_update(bot, r["id"], upd)
        if code >= 400:
            return code, payload
        if code == 200 and "routines" not in changed:
            changed.append("routines")

    _agent_audit(bot, changed)
    return 200, {"ok": True, "changed": changed,
                 "backup": f"backups/agent-settings/{dest.name}"}

def _yaml_quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

def skill_create(bot, body):
    if bot not in agent_ids() or not BOT_RE.fullmatch(bot):
        return 404, {"error": "bot tidak dikenal"}
    if bot == "default":
        return 403, {"error": "read-only"}
    if not isinstance(body, dict):
        return 400, {"error": "body harus objek"}
    name = body.get("name")
    if not isinstance(name, str) or not SKILL_RE.fullmatch(name) or name in {".", ".."}:
        return 400, {"error": "nama skill tidak valid"}
    desc = body.get("description")
    if (not isinstance(desc, str) or not (1 <= len(desc.strip()) <= SKILL_DESC_MAX)
            or "\n" in desc or "\r" in desc):
        return 400, {"error": "deskripsi 1-200 karakter, satu baris"}
    text = body.get("body")
    if (not isinstance(text, str) or not text.strip()
            or len(text) > SKILL_MAX_BYTES):
        return 400, {"error": "isi SKILL.md 1-20000 karakter"}

    root = agent_root(bot)
    if root is None:
        return 500, {"error": "folder skills tidak aman"}
    d = root / "skills"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        return 500, {"error": "folder skills tidak aman"}
    skills = _skills_dir(bot)
    if skills is None:
        return 500, {"error": "folder skills tidak aman"}

    child = skills / name
    try:
        target = child.resolve(strict=False)
    except OSError:
        return 500, {"error": "folder skills tidak aman"}
    if target.parent != skills:
        return 400, {"error": "nama skill tidak valid"}
    if child.exists() or child.is_symlink():
        return 409, {"error": "skill sudah ada"}

    content = "---\nname: %s\ndescription: %s\n---\n\n%s\n" % (
        name, _yaml_quote(desc), text.rstrip())
    try:
        child.mkdir(parents=True, exist_ok=False)
        path = child / "SKILL.md"
        _atomic_write(path, content)
        os.chmod(path, 0o644)
    except OSError:
        return 500, {"error": "gagal menulis skill"}

    line = "%s | agent-settings | %s | skill+ %s\n" % (time.strftime("%H:%M:%S"), bot, name)
    try:
        Path(ACTIVITY).parent.mkdir(parents=True, exist_ok=True)
        with open(ACTIVITY, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass

    return 201, {"ok": True, "name": name, "path": "skills/%s/SKILL.md" % name}

def cron_valid(expr):
    if not isinstance(expr, str):
        return False
    parts = expr.split()
    if len(parts) != 5:
        return False
    for p in parts:
        if not CRON_FIELD_RE.match(p):
            return False
    for p, (lo, hi) in zip(parts, ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))):
        for seg in p.split(","):
            base = seg.split("/")[0]
            if base == "*":
                continue
            if "-" in base:
                a, b = base.split("-", 1)
                if not (a.isdigit() and b.isdigit()):
                    return False
                a, b = int(a), int(b)
                if not (lo <= a <= b <= hi):
                    return False
            elif base.isdigit():
                if not (lo <= int(base) <= hi):
                    return False
            else:
                return False
    return True

def routine_update(bot, job_id, body):
    if bot not in agent_ids() or not BOT_RE.fullmatch(bot):
        return 404, {"error": "bot tidak dikenal"}
    if bot == "default":
        return 403, {"error": "read-only"}
    if not isinstance(body, dict):
        return 400, {"error": "body harus objek"}
    jp = _jobs_path(bot)
    if not jp or not jp.is_file():
        return 404, {"error": "job tidak dikenal"}
    try:
        data = json.loads(jp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 400, {"error": "jobs.json rusak"}
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, list):
        return 400, {"error": "jobs bukan list"}
    job = next((j for j in jobs if isinstance(j, dict) and j.get("id") == job_id), None)
    if job is None:
        return 404, {"error": "job tidak dikenal"}
    if "enabled" in body and not isinstance(body["enabled"], bool):
        return 400, {"error": "enabled harus bool"}
    if "schedule" in body:
        if not isinstance(body["schedule"], str) or not cron_valid(body["schedule"]):
            return 400, {"error": "jadwal tidak valid"}
    if "prompt" in body:
        if not isinstance(body["prompt"], str) or len(body["prompt"]) > 2000:
            return 400, {"error": "prompt tidak valid"}

    ts = time.strftime("%Y%m%d-%H%M%S")
    dest = AGENT_BACKUP / f"{bot}-{ts}"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(jp, dest / f"jobs-{job_id}.json")

    changed = []
    if "enabled" in body and job.get("enabled", True) != body["enabled"]:
        job["enabled"] = body["enabled"]
        changed.append("enabled")
    if "schedule" in body:
        sched = job.get("schedule")
        if _routine_schedule(job) != body["schedule"]:
            if isinstance(sched, dict):
                sched["expr"] = body["schedule"]
            else:
                job["schedule"] = body["schedule"]
            changed.append("schedule")
    if "prompt" in body and job.get("prompt") != body["prompt"]:
        job["prompt"] = body["prompt"]
        changed.append("prompt")
    if changed:
        _atomic_write(jp, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    _agent_audit(bot, changed)
    return 200, {"ok": True, "routine": _routine_item(job)}

# ---------- bots ----------

def bot_db(bot):
    if bot not in agent_ids():
        return None
    return str(_profile_dir(bot) / "state.db")

def _ro(db):
    return sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=3)

def _msg_ok(p=""):
    """Filter SQL: hanya pesan user/assistant nyata — bukan role system, bukan injeksi [IMPORTANT."""
    p = (p + ".") if p else ""
    return (f"{p}role in ('user','assistant') and {p}content is not null and trim({p}content)<>'' "
            f"and ltrim({p}content) not like '[IMPORTANT%'")

def _bot_session(con):
    """(id, title, ts) sesi 'Bot Chat' terbaru; kalau belum ada, sesi terakhir yang punya pesan nyata."""
    row = con.execute("select id,title,coalesce(last_activity_at,started_at,0) from sessions "
                      "where title='Bot Chat' order by coalesce(last_activity_at,0) desc limit 1").fetchone()
    if row:
        return row
    return con.execute(
        "select s.id,s.title,coalesce(s.last_activity_at,s.started_at,0) from sessions s "
        "where exists (select 1 from messages m where m.session_id=s.id and " + _msg_ok("m") + ") "
        "order by coalesce(s.last_activity_at,0) desc, s.started_at desc limit 1").fetchone()

def bot_last_message(bot):
    db = bot_db(bot)
    if not db:
        return "", 0.0
    try:
        con = _ro(db)
        row = con.execute(
            "select content,timestamp from messages where " + _msg_ok() +
            " order by timestamp desc limit 1").fetchone()
        con.close()
    except Exception:
        return "", 0.0
    if not row:
        return "", 0.0
    return row[0] or "", float(row[1] or 0)

def bot_active(bot, ts):
    return bool(ts) and time.time() - float(ts) <= 90

def bot_routines(bot):
    if bot not in agent_ids():
        return []
    path = _profile_dir(bot) / "cron" / "jobs.json"
    try:
        jobs = json.load(open(path)).get("jobs") or []
    except Exception:
        return []
    out = []
    for j in jobs:
        if not isinstance(j, dict):
            continue
        item = {"name": j.get("name") or "(tanpa nama)"}
        sched = j.get("schedule_display")
        if not sched and isinstance(j.get("schedule"), dict):
            sched = j["schedule"].get("display") or j["schedule"].get("expr") or j["schedule"].get("kind")
        if not sched and isinstance(j.get("schedule"), str):
            sched = j["schedule"]
        if sched:
            item["schedule"] = sched
        if j.get("next_run_at"):
            item["next_run"] = j["next_run_at"]
        if "enabled" in j:
            item["enabled"] = bool(j["enabled"])
        out.append(item)
    return out

def _clip(text, limit=90):
    s = " ".join((text or "").split()).rstrip("… ")
    if len(s) <= limit:
        return s
    cut = s[:limit].rsplit(" ", 1)[0].rstrip(" ,.;:—-")
    return (cut or s[:limit].strip()) + "…"

def bots_overview():
    out = []
    for a in agents():
        text, ts = bot_last_message(a["bot"])
        out.append({"bot": a["bot"], "name": a["name"], "role": a["role"], "color": a["color"],
                    "initials": a["initials"], "chat": a["chat"],
                    "last_message": _clip(text),
                    "last_message_full": _clip(text, 2000),
                    "last_ts": ts, "active": bot_active(a["bot"], ts),
                    "routines": bot_routines(a["bot"])})
    return out

def bot_messages(bot, limit=50):
    db = bot_db(bot)
    if not db:
        return [], ""
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 50
    try:
        con = _ro(db)
        sess = _bot_session(con)
        if not sess:
            con.close()
            return [], ""
        sid, title, sts = sess
        rows = con.execute(
            "select role,content,timestamp from messages where session_id=? and " + _msg_ok() +
            " order by timestamp desc limit ?", (sid, limit)).fetchall()
        con.close()
    except Exception:
        return [], ""
    label = title or (time.strftime("%d %b %H:%M", time.localtime(sts)) if sts else sid[:12])
    return [{"role": r, "content": c, "timestamp": float(t or 0)}
            for r, c, t in reversed(rows)], label

def _bot_last_ts(bot):
    db = bot_db(bot)
    if not db:
        return 0.0
    try:
        con = _ro(db)
        sess = _bot_session(con)
        if not sess:
            con.close()
            return 0.0
        row = con.execute("select max(timestamp) from messages where session_id=? and " + _msg_ok(),
                          (sess[0],)).fetchone()
        con.close()
    except Exception:
        return 0.0
    return float(row[0] or 0) if row else 0.0

def _bot_last_assistant(bot, after=0.0):
    for m in reversed(bot_messages(bot, 200)[0]):
        if m["role"] == "assistant" and m["timestamp"] > after:
            return m["content"]
    return ""

def _clean_out(raw):
    out = ANSI.sub("", raw or "").strip()
    keep = [l for l in out.splitlines()
            if not re.match(r"^(Resume this session|hermes --resume|Session:|Duration:|Messages:|💻|⚙|─+$|☤|∴|Query:)", l.strip())]
    return "\n".join(keep).strip()

def bot_send(bot, text):
    cfg = agent_cfg(bot)
    if not cfg:
        return {"reply": "", "ok": False, "error": "bot tidak dikenal"}
    if not cfg["chat"]:
        return {"reply": "", "ok": False, "error": f"bot {OWNER_LABEL} tidak menerima chat"}
    if not CHAT_ENABLED:
        return {"reply": "", "ok": False, "error": "hermes tidak ditemukan di mesin ini; fitur chat dimatikan"}
    lock = _bot_lock(bot)
    if not lock.acquire(blocking=False):
        return {"reply": "", "ok": False, "busy": True, "error": "bot sedang memproses pesan lain"}
    tmp = None
    try:
        tmp = tempfile.mkdtemp()
        qf = os.path.join(tmp, "query.txt")
        with open(qf, "w") as fh:
            fh.write(text)
        baseline = _bot_last_ts(bot)
        try:
            p = subprocess.run(
                [HERMES, "-p", bot, "chat", "--continue", "Bot Chat", "--create-if-missing",
                 "--query-file", qf, "--oneshot"],
                capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            return {"reply": "", "ok": False, "error": "timeout 180s — bot masih memproses"}
        except Exception as exc:
            return {"reply": "", "ok": False, "error": str(exc)}
        reply = _bot_last_assistant(bot, baseline)
        if reply:
            return {"reply": reply, "ok": True, "error": None}
        err = _clean_out((p.stdout or "") + (p.stderr or ""))[:2000]
        return {"reply": "", "ok": False, "error": err or f"hermes exit {p.returncode}"}
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        lock.release()

# ---------- auth ----------

_PBKDF2_ROUNDS = 200_000
_SESSION_SALT = b"ops-board-session"
_LOGIN_SALT = b"ops-board-login"
LOGIN_ATTEMPTS = int(CFG["login_attempts"] or 10)
LOGIN_WINDOW = int(CFG["login_window"] or 300)
REQ_LIMIT = int(CFG["request_limit"] or 120)
REQ_WINDOW = int(CFG["request_window"] or 60)
MAX_BODY = int(CFG["max_body"] or 1048576)

def creds():
    """First line of the secret file, `user:password`. '' when the file is missing."""
    try:
        with open(SECRET, encoding="utf-8", errors="replace") as fh:
            return (fh.readline() or "").strip()
    except OSError:
        return ""

def _pbkdf2(text, salt):
    return hashlib.pbkdf2_hmac("sha256", str(text).encode(), salt, _PBKDF2_ROUNDS, 32)

_KEY_CACHE = {}
_KEY_LOCK = threading.Lock()

def _key():
    """Cookie/CSRF key, derived once from the stored password."""
    secret = creds()
    with _KEY_LOCK:
        cached = _KEY_CACHE.get(secret)
        if cached is None:
            _KEY_CACHE.clear()
            cached = _KEY_CACHE[secret] = _pbkdf2(secret.partition(":")[2] or secret, _SESSION_SALT)
        return cached

def check_creds(user, password):
    """PBKDF2 hash compare with compare_digest; both sides always computed."""
    stored = creds()
    s_user, _, s_pw = stored.partition(":")
    if not s_user:
        s_user, s_pw = stored, ""
    user_ok = hmac.compare_digest(_pbkdf2(user, _LOGIN_SALT), _pbkdf2(s_user, _LOGIN_SALT))
    pass_ok = hmac.compare_digest(_pbkdf2(password, _LOGIN_SALT), _pbkdf2(s_pw, _LOGIN_SALT))
    return bool(stored) and user_ok and pass_ok

def issue_session():
    exp = int(time.time()) + SESSION_TTL
    sig = hmac.new(_key(), str(exp).encode(), hashlib.sha256).hexdigest()[:40]
    return f"{exp}.{sig}"

def valid_session(value):
    try:
        exp_s, sig = value.split(".", 1)
        exp = int(exp_s)
    except Exception:
        return False
    if exp < time.time():
        return False
    return hmac.compare_digest(sig, hmac.new(_key(), exp_s.encode(), hashlib.sha256).hexdigest()[:40])

def session_value(headers):
    """Value of the session cookie, '' when absent."""
    c = SimpleCookie()
    try:
        c.load(headers.get("Cookie") or "")
    except Exception:
        return ""
    m = c.get(COOKIE)
    return m.value if m else ""

def cookie_ok(headers):
    value = session_value(headers)
    return bool(value) and valid_session(value)

def cookie_header(value, max_age):
    """Set-Cookie value; Secure only when the request arrived over HTTPS."""
    tail = "; Secure" if getattr(_REQ, "https", False) else ""
    return f"{COOKIE}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax{tail}"

def csrf_token(value):
    return hmac.new(_key(), b"csrf:" + str(value).encode(), hashlib.sha256).hexdigest()[:40]

def csrf_ok(headers, value):
    given = (headers.get("X-CSRF") or "").strip()
    return bool(given) and bool(value) and hmac.compare_digest(given, csrf_token(value))

_HITS = {}
_HITS_LOCK = threading.Lock()

def rate_ok(ip, bucket, limit, window):
    """Sliding-window counter per IP+bucket. False means 429."""
    now = time.time()
    with _HITS_LOCK:
        if len(_HITS) > 4096:
            _HITS.clear()
        row = _HITS.setdefault(ip, {})
        hits = [t for t in row.get(bucket, []) if now - t < window]
        allowed = len(hits) < limit
        if allowed:
            hits.append(now)
        row[bucket] = hits
    return allowed

# ---------- ui ----------

STYLE = r"""
:root{--bg:#111317;--surf:#15171c;--ctr:#1a1c22;--ctr2:#1e2024;--high:#20232a;--hi2:#282c35;
--bd:#22252c;--bd2:#262930;--voc:#2b3038;--tx:#e2e2e8;--tx2:#9aa7b4;--dim:#5b6270;
--pri:#8ed5ff;--pri2:#38bdf8;--teal:#44e2cd;--amber:#fcd34d;--err:#ff8e85;--ok:#44e2cd;
--rad:12px;--rad2:16px;
--sans:"Inter",ui-sans-serif,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--disp:"Plus Jakarta Sans",ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif;
--mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
html{scrollbar-color:var(--bd2) transparent;scrollbar-width:thin}
body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.55 var(--sans);
-webkit-font-smoothing:antialiased;overscroll-behavior:none}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--hi2);border-radius:999px}
::-webkit-scrollbar-thumb:hover{background:#3e484f}
a{color:var(--pri);text-decoration:none}
a:hover{text-decoration:underline}
h1,h2,h3{font-family:var(--disp)}
[hidden]{display:none!important}
.msi{font-family:"Material Symbols Outlined";font-weight:400;font-style:normal;font-size:18px;
line-height:1;letter-spacing:normal;text-transform:none;display:inline-block;white-space:nowrap;
word-wrap:normal;direction:ltr;font-variation-settings:"FILL" 0,"wght" 400,"GRAD" 0,"opsz" 24;
-webkit-font-feature-settings:"liga";font-feature-settings:"liga";-webkit-font-smoothing:antialiased}

/* ---------- shell ---------- */
.app{display:flex;min-height:100vh}
.rail{position:fixed;left:0;top:0;bottom:0;width:230px;z-index:30;background:var(--bg);
border-right:1px solid var(--bd);display:flex;flex-direction:column;justify-content:space-between}
.content{flex:1 1 auto;min-width:0;margin-left:230px;display:flex;flex-direction:column}

/* brand */
.rbrand{height:64px;padding:0 13px;display:flex;align-items:center;gap:9px;
border-bottom:1px solid rgba(34,37,44,.7)}
.rlogo{height:30px;width:auto;max-width:100%;flex:0 0 auto;object-fit:contain;image-rendering:auto}
.rbrand .rname{display:flex;flex-direction:column;min-width:0}
.rbrand b{font:600 14px/1.1 var(--disp);letter-spacing:-.01em;white-space:nowrap}
.rbrand span{font-size:11px;color:var(--tx2);letter-spacing:.02em;margin-top:3px;white-space:nowrap}
.rlivepill{margin-left:auto;display:inline-flex;align-items:center;gap:5px;padding:2px 6px;
border-radius:999px;background:rgba(68,226,205,.1);border:1px solid rgba(68,226,205,.2);
font:500 10px var(--mono);letter-spacing:.08em;color:var(--teal)}

/* fleet status block */
.rstat{margin:10px 10px 0;padding:10px 11px;border-radius:10px;background:#14161b;
border:1px solid rgba(34,37,44,.9);display:flex;flex-direction:column;gap:6px}
.rstat .row{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;font-size:11px;
color:var(--tx2);letter-spacing:.01em}
.rstat .row b{font:500 10.5px var(--mono);color:var(--tx);letter-spacing:.02em;text-align:right;
flex:1 0 100%;margin-top:1px}
.rstat .row b.teal{color:var(--teal)}
.rstat .bar{height:3px;border-radius:999px;background:#22252c;overflow:hidden;margin-top:2px}
.rstat .bar i{display:block;height:100%;background:var(--pri2);border-radius:999px}

/* nav */
.nav{display:flex;flex-direction:column;gap:4px;padding:16px 10px}
.navitem{display:flex;align-items:center;gap:9px;width:100%;padding:8px 9px;border:1px solid transparent;
border-left:2px solid transparent;border-radius:9px;background:transparent;color:var(--tx2);
font:500 13px var(--sans);text-align:left;cursor:pointer;transition:.15s;letter-spacing:.01em}
.navitem .msi{font-size:18px;opacity:.75;flex:0 0 18px}
.navitem:hover{background:#181a20;color:var(--tx)}
.navitem:hover .msi{opacity:1}
.navitem.on{background:#1e2027;border-color:rgba(142,213,255,.2);border-left-color:var(--pri);
color:var(--pri);font-weight:500}
.navitem.on .msi{opacity:1}
.nlabel{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nbadge{font:500 10px var(--mono);background:#22252c;color:var(--tx2);border-radius:999px;padding:1px 7px}
.navitem.on .nbadge{background:rgba(142,213,255,.14);color:var(--pri)}

/* rail footer */
.railfoot{padding:10px;border-top:1px solid rgba(34,37,44,.7);display:flex;flex-direction:column;gap:9px;margin-top:auto}
.rlived{display:flex;align-items:center;gap:7px;padding:7px 10px;border-radius:9px;
background:#181a20;border:1px solid var(--bd);font-size:11px;color:var(--tx2);
overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.rdot{width:6px;height:6px;border-radius:50%;background:var(--teal);flex:0 0 6px;
animation:pulse 2.4s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(68,226,205,.45)}70%{box-shadow:0 0 0 5px rgba(68,226,205,0)}
100%{box-shadow:0 0 0 0 rgba(68,226,205,0)}}
.railfoot .out{display:flex;align-items:center;justify-content:center;gap:7px;width:100%;
padding:7px;border-radius:9px;border:1px solid var(--bd2);background:transparent;color:var(--tx2);
font:500 12px var(--sans);cursor:pointer;transition:.15s}
.railfoot .out:hover{color:var(--err);border-color:rgba(255,142,133,.4)}

/* ---------- topbar ---------- */
header{position:fixed;top:0;left:230px;right:0;height:64px;z-index:20;
display:flex;align-items:center;justify-content:space-between;gap:16px;padding:0 30px;
background:rgba(17,19,23,.86);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
border-bottom:1px solid rgba(34,37,44,.7)}
.search{display:flex;align-items:center;gap:10px;width:100%;max-width:480px;padding:6px 14px;
border-radius:999px;background:#181a20;border:1px solid var(--bd2);color:var(--tx2);
transition:.15s}
.search:focus-within{border-color:rgba(142,213,255,.45)}
.search .msi{font-size:16px;opacity:.8}
.search input{background:transparent;border:0;outline:none;width:100%;color:var(--tx);
font:13px var(--sans);padding:0}
.search input::placeholder{color:#9aa7b4}
.search kbd{font:500 10px var(--mono);background:#22252c;color:var(--tx2);padding:2px 6px;
border-radius:5px;flex:0 0 auto}
.tright{display:flex;align-items:center;gap:12px;padding-right:6px}
.tbadges{display:flex;align-items:center;gap:10px;padding:6px 12px;border-radius:999px;
background:#181a20;border:1px solid var(--bd2);font:11px var(--mono);color:var(--tx2)}
.tbadges .sep{width:1px;height:11px;background:var(--voc)}
.tbadges b{font-weight:500;letter-spacing:.02em}
.tbadges b.pri{color:var(--pri)}
.tbadges b.teal{color:var(--teal)}
.iconbtn{width:32px;height:32px;border-radius:50%;background:#181a20;border:1px solid var(--bd2);
color:var(--tx2);display:grid;place-items:center;cursor:pointer;transition:.15s}
.iconbtn:hover{color:var(--tx);border-color:var(--voc)}
.iconbtn .msi{font-size:17px}
.tright .iconbtn{position:relative;overflow:visible}
.bellbadge{position:absolute;top:-4px;right:-5px;min-width:16px;height:16px;padding:0 4px;border-radius:999px;
 background:var(--err);color:#14161b;font:600 9.5px/16px var(--mono);text-align:center;letter-spacing:0}

/* ---------- main ---------- */
main{margin-left:0;padding:84px 30px 40px;min-height:100vh}
.wrap{display:flex;flex-direction:column;gap:20px;max-width:none}

/* KPI */
.kpi{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px}
.kcard{padding:14px 16px;border-radius:14px;background:#16181d;border:1px solid var(--bd);
display:flex;flex-direction:column;gap:10px;transition:border-color .15s}
.kcard:hover{border-color:#2f343d}
.kcard .ktop{display:flex;align-items:center;justify-content:space-between;gap:8px}
.kcard .klab{font:500 11px var(--sans);letter-spacing:.08em;text-transform:uppercase;color:var(--tx2)}
.kcard .kdot{width:8px;height:8px;border-radius:50%;background:rgba(142,213,255,.7);flex:0 0 8px}
.kcard .kdot.teal{background:rgba(68,226,205,.8)}
.kcard .kdot.amber{background:rgba(252,211,77,.8)}
.kcard .kdot.gray{background:rgba(155,166,178,.6)}
.kcard .kval{display:flex;align-items:baseline;gap:7px}
.kcard .kval b{font:600 24px/1.1 var(--disp);letter-spacing:-.02em;color:var(--tx)}
.kcard .kval span{font-size:11px;color:var(--tx2)}
.kcard .kbar{height:4px;border-radius:999px;background:#22252c;overflow:hidden}
.kcard .kbar i{display:block;height:100%;border-radius:999px;background:rgba(142,213,255,.8)}
.kcard .kbar i.teal{background:rgba(68,226,205,.75)}
.kcard .kbar i.amber{background:rgba(252,211,77,.65)}
.kcard .kbar i.gray{background:rgba(155,166,178,.5)}
.kcard .msi{font-size:15px;color:rgba(142,213,255,.7)}

/* breadcrumb toolbar */
.crumb{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px}
.crumb .cleft{display:flex;align-items:center;gap:12px;min-width:0}
.crumb .cpath{display:flex;align-items:center;gap:8px;font:500 13px var(--sans)}
.crumb .cpath span{color:var(--tx)}
.crumb .cpath i{font-style:normal;color:var(--tx2)}
.crumb .cpath em{font-style:normal;color:var(--tx2)}
.chip{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;
font:500 11px var(--sans);background:#172522;border:1px solid rgba(68,226,205,.2);color:var(--teal)}
.chip.gray{background:#20232a;border-color:var(--voc);color:var(--tx2)}
.chip .rdot{width:5px;height:5px;flex:0 0 5px}
.cright{display:flex;align-items:center;gap:8px}
.btn{display:inline-flex;align-items:center;gap:7px;padding:7px 12px;border-radius:9px;
background:#181a20;border:1px solid var(--bd2);color:var(--tx);font:500 12px var(--sans);
cursor:pointer;transition:.15s}
.btn:hover{border-color:var(--voc);background:#1c1f26}
.btn .msi{font-size:15px;color:var(--tx2)}
.btn.primary{background:var(--pri2);border-color:var(--pri2);color:#04222e;font-weight:600;
padding:7px 14px;border-radius:9px}
.btn.primary:hover{background:#5cc9f9;box-shadow:0 0 18px -4px rgba(56,189,248,.35)}
.btn.primary .msi{color:#04222e}

/* ---------- panels ---------- */
.panel{min-width:0}
/* agent settings */
#p-agent{display:block;max-width:none}
.aghead{display:flex;align-items:center;gap:14px;padding:14px 16px;background:var(--surf);
 border:1px solid var(--bd);border-radius:var(--rad2);flex-wrap:wrap}
.agava{width:46px;height:46px;flex:0 0 46px;border-radius:14px;display:grid;place-items:center;
 font:600 15px var(--disp);letter-spacing:.02em;background:#1b1f27;border:1px solid var(--bd2);color:var(--pri)}
.agmeta{min-width:0;flex:1 1 260px;display:flex;flex-direction:column;gap:5px}
.agline{display:flex;align-items:center;gap:9px;min-width:0}
.agline b{font:600 16px var(--disp);color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.agstate{font:500 10px var(--mono);text-transform:uppercase;letter-spacing:.06em;padding:3px 8px;border-radius:999px;
 background:#20232a;border:1px solid var(--bd2);color:var(--tx2);white-space:nowrap}
.agstate.on{color:var(--teal);border-color:rgba(68,226,205,.35);background:rgba(68,226,205,.10)}
.agstate.today{color:#fcd34d;border-color:rgba(252,211,77,.35);background:rgba(252,211,77,.10)}
.agdesc{width:100%;background:#14161b;border:1px solid var(--bd2);border-radius:9px;color:var(--tx);
 font:13px var(--sans);padding:7px 10px;outline:none}
.agdesc:focus{border-color:var(--voc, #2b3038);box-shadow:0 0 0 3px rgba(142,213,255,.08)}
.agdesc:disabled{color:var(--tx2);background:#12141a}
.agacts{display:flex;gap:8px;margin-left:auto;flex-wrap:wrap}
.aggrid{display:grid;grid-template-columns:minmax(280px,1.05fr) minmax(300px,1.1fr) minmax(250px,.9fr);gap:14px;align-items:stretch}
.agcard{background:var(--surf);border:1px solid var(--bd);border-radius:var(--rad2);padding:14px 16px 16px;
 display:flex;flex-direction:column;gap:10px;min-width:0}
.aggrid>.agcard{height:100%}
.agcard-h{display:flex;align-items:center;justify-content:space-between;gap:8px;padding-bottom:9px;
 border-bottom:1px solid var(--bd)}
.agcard-h h3{margin:0;font:600 13px var(--disp);color:var(--tx);letter-spacing:.01em}
.agtag{font:500 9.5px var(--mono);letter-spacing:.07em;text-transform:uppercase;color:var(--tx2);
 background:#20232a;border:1px solid var(--bd2);border-radius:999px;padding:2px 7px;white-space:nowrap}
.aglab{font:500 10px var(--mono);letter-spacing:.09em;text-transform:uppercase;color:var(--tx2);margin-bottom:-4px}
.agsel{width:100%;background:#14161b;border:1px solid var(--bd2);border-radius:9px;color:var(--tx);
 font:12.5px var(--mono);padding:8px 10px;outline:none}
.agsel:focus{border-color:var(--voc, #2b3038)}
.agkv{display:flex;align-items:baseline;gap:10px;justify-content:space-between;font-size:12px}
.agkv>span{color:var(--tx2);font:500 10px var(--mono);letter-spacing:.07em;text-transform:uppercase}
.agkv>b{color:var(--tx);font-weight:500;text-align:right;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.agmono{font:12px var(--mono)!important;color:var(--tx2)!important;direction:rtl;text-align:left!important}
.agsoul{width:100%;height:320px;resize:vertical;background:#12141a;border:1px solid var(--bd2);border-radius:10px;
 color:var(--tx);font:12px/1.6 var(--mono);padding:10px 11px;outline:none;white-space:pre-wrap;word-break:break-word;overflow:auto;tab-size:2}
.agsoul:focus{border-color:var(--voc, #2b3038)}
.agsoul:disabled{color:var(--tx2)}
.agcount{font:500 10px var(--mono);color:var(--dim);letter-spacing:.04em;margin-top:auto;padding-bottom:2px}
.agcron{display:flex;flex-direction:column;gap:10px}
.agjob{border:1px solid var(--bd2);border-radius:11px;padding:10px 11px;background:#14161b;
 display:flex;flex-direction:column;gap:8px}
.agjob-h{display:flex;align-items:center;gap:8px;justify-content:space-between}
.agjob-h b{font:600 12.5px var(--sans);color:var(--tx);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.agjob-st{font:500 9.5px var(--mono);letter-spacing:.06em;text-transform:uppercase;padding:2px 7px;border-radius:999px;
 background:#20232a;border:1px solid var(--bd2);color:var(--tx2);white-space:nowrap}
.agjob-st.off{color:#ff8e85;border-color:rgba(255,142,133,.35);background:rgba(255,142,133,.10)}
.agjob-row{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.agjob-row input[type=text]{flex:1 1 120px;min-width:0;background:#0f1116;border:1px solid var(--bd2);border-radius:8px;
 color:var(--tx);font:12px var(--mono);padding:6px 8px;outline:none}
.agjob-row input[type=text]:focus{border-color:var(--voc, #2b3038)}
.agsw{display:inline-flex;align-items:center;gap:7px;font:11px var(--sans);color:var(--tx2);white-space:nowrap;cursor:pointer}
.agsw input{position:absolute;width:1px;height:1px;margin:0;opacity:0}
.agsw-track{position:relative;flex:0 0 28px;width:28px;height:16px;border-radius:999px;
 background:#2a2f38;border:1px solid var(--bd2);transition:.15s}
.agsw-track::after{content:"";position:absolute;top:2px;left:2px;width:10px;height:10px;border-radius:50%;
 background:#8a94a6;transition:.15s}
.agsw input:checked+.agsw-track{background:rgba(68,226,205,.25);border-color:rgba(68,226,205,.45)}
.agsw input:checked+.agsw-track::after{left:14px;background:var(--teal)}
.agsw input:focus-visible+.agsw-track{box-shadow:0 0 0 3px rgba(142,213,255,.18)}
.agsw input:disabled+.agsw-track{opacity:.5}
.agsw-txt{min-width:52px}
.agjob-meta{display:flex;flex-direction:column;gap:3px;font:11px var(--mono);color:var(--tx2)}
.agjob-meta div{display:flex;gap:7px;min-width:0}
.agjob-meta i{font-style:normal;color:var(--dim);flex:0 0 auto}
.agjob-meta span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.agjob textarea{width:100%;height:110px;resize:vertical;background:#0f1116;border:1px solid var(--bd2);border-radius:8px;
 color:var(--tx);font:11.5px/1.5 var(--mono);padding:7px 8px;outline:none}
.agjob textarea:focus{border-color:var(--voc, #2b3038)}
.agjob-f{display:flex;align-items:center;gap:8px;justify-content:space-between;flex-wrap:wrap}
.agjob-msg{font:11px var(--mono);color:var(--tx2);min-height:14px}
.agjob-msg.ok{color:var(--teal)}.agjob-msg.err{color:var(--err)}
.agstats{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
.agstat{background:#14161b;border:1px solid var(--bd2);border-radius:10px;padding:9px 10px;min-width:0}
.agstat span{display:block;font:500 9.5px var(--mono);letter-spacing:.07em;text-transform:uppercase;color:var(--tx2)}
.agstat b{display:block;font:600 15px var(--disp);color:var(--tx);margin-top:2px;white-space:nowrap;
 overflow:hidden;text-overflow:ellipsis}
.agstat.wide{grid-column:1/-1}
.aglinks{display:flex;gap:8px;flex-wrap:wrap;margin-top:2px}
.agbanner{display:flex;align-items:center;gap:8px;font:11.5px var(--sans);color:var(--tx2);
 background:#151a1a;border:1px solid rgba(68,226,205,.18);border-radius:10px;padding:8px 12px}
.agbanner .msi{font-size:15px;color:var(--teal)}
.agfoot{position:sticky;bottom:0;z-index:5;display:flex;align-items:center;justify-content:space-between;gap:10px;
 padding:11px 14px;background:rgba(21,23,28,.94);backdrop-filter:blur(8px);
 border:1px solid var(--bd);border-radius:12px;flex-wrap:wrap}
.agfoot .btn.primary[disabled],.agacts .btn.primary[disabled]{opacity:.45;cursor:not-allowed}
#p-agent[data-ro="1"] .agfoot .btn.primary,#p-agent[data-ro="1"] .agacts .btn.primary{display:none}
/* agent page: roster + detail */
.agpage{display:grid;grid-template-columns:280px minmax(0,1fr);gap:14px;align-items:start}
.agroster{background:var(--surf);border:1px solid var(--bd);border-radius:var(--rad2);padding:12px;
 display:flex;flex-direction:column;gap:10px;position:sticky;top:0}
.agroster-h{display:flex;align-items:center;justify-content:space-between;gap:8px;
 font:600 12px var(--disp);color:var(--tx)}
.agroster-h b{font:500 10.5px var(--mono);color:var(--tx2);background:#20232a;border:1px solid var(--bd2);
 border-radius:999px;padding:1px 8px}
.agroster-list{display:flex;flex-direction:column;gap:8px;max-height:calc(100vh - 220px);overflow:auto}
.agrcard{display:flex;align-items:flex-start;gap:9px;padding:10px 11px;border-radius:11px;
 border:1px solid var(--bd2);background:#14161b;cursor:pointer;transition:border-color .15s,background .15s}
.agrcard:hover{border-color:var(--voc)}
.agrcard.on{border-color:rgba(142,213,255,.45);background:rgba(142,213,255,.06)}
.agrcard:focus-visible{outline:2px solid var(--pri);outline-offset:2px}
.agrav{width:34px;height:34px;flex:0 0 34px;border-radius:10px;display:grid;place-items:center;
 font:600 12px var(--mono);background:#1b1f27;border:1px solid var(--bd2);color:var(--pri)}
.agrbody{min-width:0;flex:1 1 auto;display:flex;flex-direction:column;gap:2px}
.agrtop{display:flex;align-items:center;gap:6px;justify-content:space-between;min-width:0}
.agrtop b{flex:1 1 auto;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.agrtop .agstate{flex:0 0 auto}
.agrcard b{font:600 13px var(--sans);color:var(--tx);min-width:0;overflow:hidden;overflow-wrap:anywhere;white-space:nowrap;text-overflow:ellipsis;line-height:1.25;font-size:12.5px}
.agrcard .agstate{font-size:8.5px;padding:1px 6px;letter-spacing:.05em}
.agrcard .agrole{font-size:11px;color:var(--tx2);min-width:0;overflow-wrap:anywhere;white-space:normal}
.agrcard .agrfoot{display:flex;align-items:center;flex-wrap:nowrap;gap:6px;font:10px var(--mono);color:var(--dim);letter-spacing:.02em;min-width:0;white-space:nowrap;overflow:hidden}
.agrcard .agrfoot .agtag{font-size:8.5px;padding:1px 5px;margin-left:auto;flex:0 0 auto}
.agrcard .agrfoot .agrfoot-txt{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.agdetail{display:flex;flex-direction:column;gap:14px;min-width:0}
.agskbar{display:flex;align-items:center;gap:8px;flex-wrap:nowrap}
.agskbar .msi{font-size:16px;color:var(--tx2);flex:0 0 auto}
.agskbar input{flex:1 1 0;min-width:0;background:#14161b;border:1px solid var(--bd2);border-radius:9px;
 color:var(--tx);font:13px var(--sans);padding:7px 10px;outline:none}
.agskbar input:focus{border-color:var(--voc, #2b3038);box-shadow:0 0 0 3px rgba(142,213,255,.08)}
.agskbar .btn{flex:0 0 auto}
.agskills{display:flex;flex-direction:column;gap:6px;max-height:280px;overflow:auto}
.agskill{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:2px 8px;
 align-items:center;padding:6px 7px;border-radius:7px}
.agskill:hover{background:#14161b}
.agskill .agname{grid-column:1;grid-row:1;font:500 12px var(--mono);color:var(--tx);
 min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.agskill .agsdesc{grid-column:1/-1;grid-row:2;font-size:11.5px;color:var(--tx2);
 white-space:normal;overflow-wrap:anywhere;line-height:1.35;
 display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.agskill .agkvsz{grid-column:2;grid-row:1;justify-self:end}
.agkvsz{font:500 9.5px var(--mono);color:var(--tx2);background:#1b1f27;border:1px solid var(--bd2);
 border-radius:999px;padding:1px 6px;flex:0 0 auto}
.agsub-h{margin-top:4px}
.smcard{max-width:640px;width:100%}
.smtext{width:100%;background:#14161b;border:1px solid var(--bd2);border-radius:9px;color:var(--tx);
 font:13px var(--sans);padding:8px 11px;outline:none;margin-bottom:8px}
.smtext:focus{border-color:var(--voc, #2b3038);box-shadow:0 0 0 3px rgba(142,213,255,.08)}
.smbody{width:100%;height:220px;resize:vertical;background:#12141a;border:1px solid var(--bd2);
 border-radius:10px;color:var(--tx);font:12px/1.6 var(--mono);padding:10px 11px;outline:none;
 white-space:pre;overflow:auto;tab-size:2}
.smbody:focus{border-color:var(--voc, #2b3038)}
.smmeta{display:flex;align-items:center;justify-content:space-between;gap:8px;
 font:500 10.5px var(--mono);color:var(--dim);margin-top:7px}
.smmeta code{font:500 10.5px var(--mono);color:var(--tx2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.smmsg{font:11px var(--mono);color:var(--tx2);min-height:14px;margin-top:6px}
.smmsg.err{color:var(--err)}
@media(max-width:1100px){.agpage{grid-template-columns:minmax(0,1fr)}.agroster{position:static}
 .agroster-list{flex-direction:row;overflow-x:auto;max-height:none} .agrcard{min-width:200px}}
.agroster,.agdetail,.agdetail>*,.agcard,.aggrid>*{min-width:0}
.agsoul,.agdesc,.agsel{box-sizing:border-box;max-width:100%}
.bchathead .aggear{margin-left:6px;width:28px;height:28px;flex:0 0 28px}
.bchathead .aggear .msi{font-size:16px}
@media(max-width:1100px){.aggrid{grid-template-columns:minmax(0,1fr)}}
@media(max-width:640px){
 .aghead{padding:12px}.aggrid{gap:10px}.agcard{padding:12px}.agpage{gap:10px}
 .agsoul{height:240px}.agfoot{position:static}
 #p-agent{overflow-x:hidden}.agkv>b{white-space:normal;overflow-wrap:anywhere;text-align:right}.agmono{direction:ltr}
}
.panel>h2{margin:0 0 14px;font:600 11px var(--sans);letter-spacing:.08em;text-transform:uppercase;
color:var(--tx2);display:flex;align-items:center;gap:8px}
.panel>h2::before{content:"";width:2px;height:12px;border-radius:2px;background:var(--teal)}
.ph{display:flex;align-items:center;justify-content:space-between;gap:10px;
padding:12px 16px;background:#17191f;border:1px solid var(--bd);border-bottom:0;
border-radius:var(--rad2) var(--rad2) 0 0}
.ph .pl{display:flex;align-items:center;gap:10px;min-width:0}
.ph .picon{width:24px;height:24px;border-radius:7px;background:#20232a;color:var(--pri);
display:grid;place-items:center;flex:0 0 24px}
.ph .picon .msi{font-size:15px}
.ph h2{margin:0;padding:0;font:600 14px var(--disp);letter-spacing:0;text-transform:none;
color:var(--tx);display:block}
.ph h2::before{content:none}
.ph .pright{display:flex;align-items:center;gap:12px}
.ph .meta{font:11px var(--mono);color:var(--tx2);display:flex;align-items:center;gap:8px}
.ph .meta u{text-decoration:none;color:var(--tx2)}
/* ---------- kanban ---------- */
.boardstack{display:flex;flex-direction:column;gap:14px;margin-top:14px;min-width:0}
.cols{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px;align-items:stretch;
height:min(58vh,560px);min-height:320px}
.col{display:flex;flex-direction:column;gap:10px;min-height:0;height:100%;padding:12px;
background:rgba(21,23,28,.7);border:1px solid var(--bd);border-radius:var(--rad2);overflow-y:auto}
.col:has(.collist){overflow:hidden}
.collist{display:flex;flex-direction:column;gap:10px;flex:1 1 auto;min-height:0;overflow-y:auto;
scrollbar-gutter:stable;padding-right:4px;overscroll-behavior:contain}
.col h3,.colhead{position:sticky;top:0;z-index:2;margin:0;padding:2px 2px 8px;display:flex;
align-items:center;justify-content:space-between;gap:8px;background:rgba(21,23,28,.96);
font:600 13px var(--disp);letter-spacing:0;text-transform:none;color:var(--tx)}
.colhead .chl{display:flex;align-items:center;gap:8px;min-width:0}
.colhead .cnt{font:500 11px var(--mono);padding:1px 8px;border-radius:999px;background:#20232a;
color:var(--tx2);letter-spacing:0}
.colhead .cnt.hot{background:rgba(68,226,205,.1);border:1px solid rgba(68,226,205,.2);color:var(--teal)}
.colhead .cnt.warn{background:rgba(252,211,77,.1);border:1px solid rgba(252,211,77,.2);color:var(--amber)}
.colhead .dots{background:transparent;border:0;color:#9aa7b4;cursor:pointer;
padding:2px;line-height:1;border-radius:5px}
.colhead .dots:hover{color:var(--tx);background:#1e2025}
.colhead .dots .msi{font-size:16px}
.col h3 i{font:500 10.5px var(--mono);background:var(--high);border-radius:999px;padding:1px 8px;
color:var(--tx2);letter-spacing:0}
.col .none{color:var(--tx2);font-size:11px;font-style:italic;padding:2px 2px 6px}

/* card */
.card{display:flex;flex-direction:column;gap:9px;padding:13px;border-radius:var(--rad);
background:var(--ctr);border:1px solid var(--bd2);cursor:pointer;text-align:left;width:100%;
font-family:inherit;color:inherit;transition:border-color .15s,background .15s;flex:0 0 auto}
.card:hover{border-color:#383e4a}
.card:focus-visible{outline:2px solid var(--pri);outline-offset:2px}
.card.active{border-color:#2d3340;box-shadow:0 1px 2px rgba(0,0,0,.35)}
.card.done{background:#17191f;border-color:#20232a;opacity:.85}
.card.done:hover{opacity:1}
.ctop{display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:11px}
.ctop .cid{display:flex;align-items:center;gap:6px;font-family:var(--mono);color:var(--tx2)}
.ctop .cid .rdot{width:5px;height:5px;flex:0 0 5px}
.card.active .cid{color:var(--pri)}
.card b{display:none}
.ctitle{display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden;
font:500 13px/1.4 var(--sans);color:var(--tx);margin:0}
.cdesc{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;
font:400 12px/1.5 var(--sans);color:rgba(155,166,178,.85);margin:0}
.csub{padding:9px 10px;border-radius:9px;background:#14161b;border:1px solid var(--bd);
display:flex;flex-direction:column;gap:5px;font-size:11px}
.csub .csubh{display:flex;align-items:center;justify-content:space-between;gap:8px;
color:var(--tx2)}
.csub .csubh span{font-family:var(--mono);font-size:10.5px}
.csub .csubh b{font:500 10.5px var(--mono);color:var(--teal)}
.csub .csubtx{font:10.5px/1.45 var(--mono);color:rgba(142,213,255,.9);background:#1b1e25;
border-radius:6px;padding:4px 7px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cbar{height:4px;border-radius:999px;background:#22252c;overflow:hidden}
.cbar i{display:block;height:100%;border-radius:999px;background:rgba(142,213,255,.8)}
.cfoot{display:flex;align-items:center;justify-content:space-between;gap:8px;padding-top:9px;
border-top:1px solid rgba(38,41,48,.6);font-size:11px;color:var(--tx2);min-width:0}
.cfoot .cwho{display:flex;align-items:center;gap:6px;min-width:0}
.cfoot .cwho span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cav{width:20px;height:20px;border-radius:50%;flex:0 0 20px;display:grid;place-items:center;
font:500 9.5px var(--sans);font-style:normal;background:rgba(142,213,255,.1);
border:1px solid rgba(142,213,255,.2);color:var(--pri)}
.cav.ch{background:rgba(155,166,178,.12);border-color:rgba(155,166,178,.25);color:var(--tx2)}
.cav.pl{background:rgba(68,226,205,.12);border-color:rgba(68,226,205,.22);color:var(--teal)}
.cav.al{background:rgba(252,211,77,.12);border-color:rgba(252,211,77,.22);color:var(--amber)}
.cav.dl{background:rgba(196,181,253,.12);border-color:rgba(196,181,253,.22);color:#ddd6fe}
.cav.ho{background:rgba(142,213,255,.1);border-color:rgba(142,213,255,.2);color:var(--pri)}
.cwhen,.cage{margin-left:auto;color:var(--tx2);white-space:nowrap;font:500 10.5px var(--mono)}

/* pills */
.tag{display:inline-flex;align-items:center;gap:4px;font:500 10px var(--sans);letter-spacing:.02em;
padding:1.5px 7px;border-radius:6px;background:#20232a;color:var(--tx2);border:1px solid var(--voc);
white-space:nowrap}
.p0{background:#2b1719;color:#fda4af;border-color:rgba(244,63,94,.2)}
.p1{background:#2b2216;color:var(--amber);border-color:rgba(245,158,11,.2)}
.p2{background:rgba(56,189,248,.12);color:#a5e0ff;border-color:rgba(56,189,248,.22)}
.p3{background:#20232a;color:var(--tx2);border-color:var(--voc)}
.st{display:inline-flex;align-items:center;gap:4px;font:500 10.5px var(--sans);padding:1.5px 8px;
border-radius:999px;background:var(--high);color:var(--tx2);letter-spacing:.02em}
.st.s-queued{background:rgba(155,166,178,.14);color:#c7ced8}
.st.s-in_progress{background:rgba(68,226,205,.14);color:#7ff0e2}
.st.s-blocked{background:rgba(220,38,38,.18);color:#ffb4ab}
.st.s-review{background:rgba(252,211,77,.14);color:var(--amber)}
.st.s-done{background:rgba(74,222,128,.14);color:#86efac}

/* ---------- activity table ---------- */
.actwrap{background:#15171c;border:1px solid var(--bd);border-radius:var(--rad2);overflow:hidden;
display:flex;flex-direction:column;min-width:0}
.actbar{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:9px 16px;
background:#17191f;border-bottom:1px solid var(--bd);cursor:pointer;user-select:none}
.actbar-l{display:flex;align-items:center;gap:9px;min-width:0}
.actbar .picon{width:24px;height:24px;flex:0 0 24px;border-radius:7px;display:grid;place-items:center;
background:#20232a;color:var(--pri)}
.actbar .picon .msi{font-size:15px}
.actbar h2{margin:0;font:600 13.5px var(--disp);color:var(--tx);letter-spacing:-.01em;white-space:nowrap}
.actbadge{font:500 10.5px var(--mono);padding:1px 8px;border-radius:999px;background:#20232a;
color:var(--tx2);white-space:nowrap}
.actbar-r{display:flex;align-items:center;gap:10px;flex:0 0 auto}
.actbar .alive{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:999px;
background:rgba(68,226,205,.1);border:1px solid rgba(68,226,205,.2);
font:500 10px var(--mono);letter-spacing:.06em;color:var(--teal);white-space:nowrap}
.actbar .alive .rdot{width:5px;height:5px;flex:0 0 5px}
.metaline{font:11px var(--mono);color:var(--tx2);white-space:nowrap}
.actbar .tgl{width:26px;height:26px;flex:0 0 26px;border-radius:7px;border:1px solid var(--bd2);
background:#20232a;color:var(--tx);display:grid;place-items:center;cursor:pointer;transition:.15s}
.actbar .tgl:hover{background:#282c35}
.actbar .tgl .msi{font-size:16px;transition:transform .18s}
.actwrap.folded .tgl .msi{transform:rotate(180deg)}
.actwrap.folded .acthead,.actwrap.folded .actrows{display:none}
.acthead{display:grid;grid-template-columns:96px 150px 190px minmax(0,1fr) 92px;gap:12px;
padding:8px 16px;background:#17191f;border-bottom:1px solid var(--bd);
font:600 10px var(--sans);letter-spacing:.08em;text-transform:uppercase;color:var(--tx2)}
.actrows{height:min(30vh,300px);overflow-y:auto;overscroll-behavior:contain}
.actrow{display:grid;grid-template-columns:96px 150px 190px minmax(0,1fr) 92px;gap:12px;
align-items:baseline;padding:5px 16px;border-bottom:1px solid rgba(34,37,44,.7);
font:11.5px/1.4 var(--mono);color:var(--tx2)}
.actrow:hover{background:#181a20}
.actrow:last-child{border-bottom:0}
.actrow .atime{color:var(--tx2);white-space:nowrap}
.actrow .aagent{color:var(--tx);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.actrow .aact{color:var(--teal);text-transform:uppercase;letter-spacing:.02em;overflow:hidden;
text-overflow:ellipsis;white-space:nowrap;font-size:10.5px}
.actrow .atext{color:rgba(226,226,232,.85);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
font-family:var(--sans);font-size:12px}
.actrow .amet{text-align:right;color:var(--tx2);font-size:10.5px;white-space:nowrap}
.actrow .amet.ok{color:var(--teal)}
.actrow .amet.warn{color:var(--amber)}
.empty{color:var(--tx2);font-size:12px;padding:12px 16px}
.line{font:11.5px/1.6 var(--mono);color:var(--tx2)}

/* ---------- chat3 ---------- */
.chat3{display:grid;grid-template-columns:minmax(280px,320px) minmax(0,1fr) 320px;gap:14px;
 height:clamp(520px,calc(100dvh - 173px),900px)}
.chleft,.chtele{display:flex;flex-direction:column;gap:12px;min-width:0;padding:10px;
 background:#15171c;border:1px solid var(--bd);border-radius:var(--rad2);overflow-y:auto;
 overscroll-behavior:contain}
.chleft{padding:0;overflow:hidden}
.chscroll{display:flex;flex-direction:column;gap:4px;flex:1 1 auto;min-height:0;
 overflow-y:auto;overflow-x:hidden;overscroll-behavior:contain;padding:8px;
 scrollbar-width:thin;scrollbar-color:var(--bd2) transparent}
.chscroll::-webkit-scrollbar{width:6px}
.chscroll::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:999px}
.chscroll::-webkit-scrollbar-track{background:transparent}
.chmid{display:flex;flex-direction:column;min-width:0;overflow:hidden;background:#0f1116;
 border:1px solid var(--bd);border-radius:var(--rad2)}
.chsec{position:sticky;top:-8px;z-index:2;display:flex;align-items:center;justify-content:space-between;
 padding:5px 4px 6px;background:#15171c;font:600 10px var(--sans);letter-spacing:.08em;
 text-transform:uppercase;color:var(--tx2)}
.chsec b{padding:0 7px;border-radius:999px;background:#20232a;color:var(--tx2);
 font:500 10px var(--mono);letter-spacing:0}
.chlist{display:flex;flex-direction:column;gap:4px}
.convo{position:relative;display:flex;align-items:flex-start;gap:9px;padding:7px 8px;
 border:1px solid transparent;border-left:2px solid transparent;border-radius:9px;
 cursor:pointer;transition:.14s;flex:0 0 auto}
.convo:hover{background:#1a1d23}
.convo.on{background:#1a1c20;border-color:rgba(142,213,255,.14);border-left:2px solid var(--pri)}
.botav{position:relative;display:grid;place-items:center;width:30px;height:30px;flex:0 0 30px;
 border-radius:50%;background:#282a2e;color:var(--pri);font:600 11px var(--sans)}
.botlive{position:absolute;right:-1px;bottom:-1px;width:8px;height:8px;border-radius:50%;
 background:#3b434e;box-shadow:0 0 0 2px #15171c}
.botlive.on{background:var(--teal)}
.botmeta{display:flex;flex-direction:column;gap:2px;min-width:0;flex:1 1 auto}
.botmeta b{display:flex;align-items:center;justify-content:space-between;gap:6px;min-width:0;
 min-height:18px;color:var(--tx);font:500 12.5px var(--sans)}
.botmeta b span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.botmeta s{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;
 white-space:normal;word-break:break-word;text-decoration:none;color:var(--tx2);font:400 10.5px var(--sans)}
.convotime{flex:0 0 auto;color:#9aa7b4;font:500 9.5px var(--mono);white-space:nowrap}
.hmeta{display:flex;align-items:center;gap:7px;min-width:0;overflow:hidden}
.hbadge{flex:0 0 auto;padding:1px 7px;border-radius:999px;font:600 9px var(--mono);
 letter-spacing:.06em;text-transform:uppercase;font-style:normal}
.hbadge.room{background:rgba(252,211,77,.12);border:1px solid rgba(252,211,77,.24);color:var(--amber)}
.hbadge.bot{background:rgba(142,213,255,.12);border:1px solid rgba(142,213,255,.24);color:var(--pri)}
.bchathead{display:flex;align-items:center;gap:9px;padding:12px 16px;flex:0 0 auto;min-width:0;
 border-bottom:1px solid rgba(34,37,44,.7);font:500 13px var(--sans);white-space:nowrap}
.bchathead>span{min-width:0;overflow:hidden;text-overflow:ellipsis;flex:0 1 auto}
.bchathead b{font-weight:600;color:var(--tx)}
.bchathead small{margin-left:auto;min-width:0;overflow:hidden;text-overflow:ellipsis;
 color:var(--tx2);font:400 11px var(--sans);text-align:right;flex:0 1 auto}
.chatstream{display:flex;flex-direction:column;gap:14px;flex:1 1 auto;min-height:0;
 padding:16px 18px 12px;overflow-y:auto;overscroll-behavior:contain}
.chatstream>*:first-child{margin-top:auto}
.chatstream>*{flex:0 0 auto}
.chatstream{scroll-padding-top:16px}
.chatturn{display:flex;flex-direction:column;gap:5px;max-width:min(760px,94%)}
.chatturn.me{align-self:flex-end;align-items:flex-end}
.chatturn.me .cmeta{flex-direction:row-reverse}
.cmeta{display:flex;align-items:center;gap:7px;padding:0 3px;font:11px var(--sans);color:var(--tx2)}
.cmeta b{color:var(--tx);font-weight:500}
.cmeta time{color:#9aa7b4;font:10px var(--mono)}
.cmeta .cav{width:22px;height:22px;flex:0 0 22px;font-size:8.5px}
.bub{min-width:0;padding:10px 13px;background:#161a1f;border:1px solid rgba(38,41,48,.85);
 border-radius:12px;border-top-left-radius:4px;color:var(--tx);font:12.5px/1.6 var(--sans);
 white-space:pre-wrap;word-break:break-word}
.chatturn.me .bub{background:#1b2430;border-color:rgba(142,213,255,.18);border-radius:12px;
 border-top-right-radius:4px}
.chchips{display:flex;flex-wrap:wrap;gap:6px;padding:0 0 4px;flex:1 0 100%;order:-1}
.chchips:empty{display:none}
.chchip{padding:2px 9px;border:1px solid var(--bd2);border-radius:999px;background:#15171c;
 color:var(--tx2);font:500 10.5px var(--mono);cursor:pointer;transition:.14s}
.chchip:hover{color:var(--pri);border-color:rgba(142,213,255,.4)}
.composer{display:flex;flex-wrap:wrap;gap:9px;align-items:flex-end;flex:0 0 auto;margin:0 12px 12px;padding:9px;
 border:1px solid var(--bd2);border-radius:12px;background:#15171c;transition:border-color .15s}
.composer:focus-within{border-color:rgba(142,213,255,.4)}
.composer textarea{flex:1 1 auto;min-width:0;min-height:26px;max-height:120px;padding:4px 6px;
 background:transparent;border:0;outline:none;color:var(--tx);font:13px/1.5 var(--sans);resize:none}
.composer textarea::placeholder{color:#9aa7b4}
.send{display:grid;place-items:center;width:36px;height:36px;flex:0 0 auto;border-radius:50%;
 border:1px solid var(--pri2);background:var(--pri2);color:#04222e;cursor:pointer;transition:.15s}
.send:hover:not(:disabled){box-shadow:0 0 18px -4px rgba(56,189,248,.45)}
.send:disabled{opacity:.35;cursor:not-allowed;box-shadow:none}
.send .msi{font-size:18px}
.thinking{padding:0 18px 8px;color:var(--teal);font:11.5px var(--sans);animation:blink 1.1s infinite}
@keyframes blink{0%,100%{opacity:.35}50%{opacity:1}}
.teleh{display:flex;align-items:center;justify-content:space-between;color:var(--tx);
 font:600 12px var(--sans)}
.telelive{padding:1px 7px;border:1px solid rgba(68,226,205,.3);border-radius:999px;
 background:rgba(68,226,205,.08);color:var(--teal);font:500 9px var(--mono);font-style:normal;
 letter-spacing:.08em;text-transform:uppercase}
.telegrid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.tele-stat{display:flex;flex-direction:column;gap:1px;min-width:0;padding:8px 9px;
 background:#181a20;border:1px solid var(--bd);border-radius:9px}
.tele-stat .telab{color:var(--tx2);font:500 9px var(--mono);letter-spacing:.06em;text-transform:uppercase}
.tele-stat b{color:var(--pri);font:600 18px var(--sans);letter-spacing:-.01em}
.tele-stat s{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-decoration:none;
 color:var(--tx2);font:400 9.5px var(--sans)}
.tblock{display:flex;flex-direction:column}
.tfile{display:flex;align-items:baseline;gap:7px;min-width:0;padding:5px 2px;
 border-bottom:1px solid rgba(34,37,44,.6)}
.tfile:last-child{border-bottom:0}
.tfile .tfn{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
 color:var(--tx2);font:500 11px var(--mono)}
.tfile .tfs{flex:0 0 auto;color:#9aa7b4;font:10px var(--mono);white-space:nowrap}
.tmeta{margin:0;padding:0 2px;color:var(--tx2);font:11px var(--sans)}
.rt{margin-bottom:5px;padding:6px 9px;background:#181a20;border:1px solid var(--bd);border-radius:8px}
.rt b{display:block;color:var(--tx);font:500 11.5px var(--sans)}
.rt span{color:var(--tx2);font:10px var(--mono)}
@media(max-width:1180px){.chat3{grid-template-columns:minmax(240px,280px) minmax(0,1fr)}
 .chtele{display:none}}
@media(max-width:760px){.chat3{grid-template-columns:1fr;grid-template-rows:auto minmax(0,1fr);height:calc(100dvh - 210px);min-height:480px}
 .chleft{max-height:34vh;min-height:0}.chmid{height:auto;min-height:0;overflow:hidden}}
textarea,input{font-family:inherit}

/* ---------- files ---------- */
#p-files{display:grid;grid-template-columns:minmax(260px,330px) minmax(0,1fr);gap:14px;
height:calc(100vh - 340px);min-height:420px}
.fleft{display:flex;flex-direction:column;min-height:0;gap:10px;background:#15171c;
border:1px solid var(--bd);border-radius:var(--rad2);padding:12px}
.froots{display:flex;flex-wrap:wrap;gap:5px}
.froots .tab{padding:4px 10px;font:500 11px var(--sans);border:1px solid var(--bd2);
background:#181a20;color:var(--tx2);border-radius:999px;cursor:pointer;transition:.15s}
.froots .tab:hover{color:var(--tx);border-color:var(--voc)}
.froots .tab.on{background:#1e2027;border-color:rgba(142,213,255,.25);color:var(--pri)}
.fsearch{display:flex;align-items:center;gap:8px;background:#181a20;border:1px solid var(--bd2);
border-radius:9px;padding:6px 10px}
.fsearch .msi{font-size:15px;color:#9aa7b4}
.fsearch input{background:transparent;border:0;outline:none;width:100%;color:var(--tx);
font:12px var(--mono)}
.fsearch input::placeholder{color:#9aa7b4}
.fcrumbs{display:flex;flex-wrap:wrap;align-items:center;gap:3px;font:11px var(--mono);min-width:0}
.fcrumbs button{background:transparent;border:0;color:var(--tx2);cursor:pointer;font-family:inherit;
font-size:11px;padding:1px 3px;border-radius:4px}
.fcrumbs button:hover{color:var(--tx);background:#1e2025}
.fcrumbs b{color:var(--pri);background:rgba(142,213,255,.1);border:1px solid rgba(142,213,255,.2);
border-radius:4px;padding:0 5px;font-weight:500}
.fcrumbs .fsep{color:var(--voc)}
.flist{flex:1 1 auto;min-height:0;overflow-y:auto;border-top:1px solid rgba(34,37,44,.7);
padding-top:6px}
.frow{display:flex;align-items:center;gap:8px;padding:5px 8px;border-radius:7px;cursor:default;
font:12px var(--mono);color:var(--tx2)}
.frow.dir{cursor:pointer}
.frow:hover{background:#1e2025;color:var(--tx)}
.frow.on{background:#1e2027;color:var(--pri);box-shadow:inset 2px 0 0 var(--pri)}
.frow .msi{font-size:14px;flex:0 0 14px;color:#9aa7b4}
.frow.dir .msi{color:#a3abff}
.frow.on .msi{color:var(--pri)}
.frow .fname{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.frow .fsize,.frow .fwhen{font:10px var(--mono);color:#9aa7b4;flex:0 0 auto}
.ffoot{font:10.5px var(--mono);color:#9aa7b4;flex:0 0 auto;
border-top:1px solid rgba(34,37,44,.7);padding-top:8px;display:flex;justify-content:space-between}
.fright{display:flex;flex-direction:column;min-width:0;min-height:0;background:#15171c;
border:1px solid var(--bd);border-radius:var(--rad2);overflow:hidden}
.fright .fbar{display:flex;align-items:center;gap:8px;padding:9px 14px;background:#17191f;
border-bottom:1px solid var(--bd);flex-wrap:wrap;flex:0 0 auto}
.fbar .fname{font:500 12.5px var(--mono);color:var(--tx);overflow:hidden;text-overflow:ellipsis;
white-space:nowrap;min-width:0}
.fbar .fspacer{flex:1 1 auto}
.fbar .mbtn{font:500 11px var(--sans);padding:4px 11px;border-radius:999px;border:1px solid var(--bd2);
background:#181a20;color:var(--tx2);cursor:pointer;text-decoration:none}
.fbar .mbtn:hover{color:var(--tx);border-color:var(--pri)}
.fhead{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.fbody{flex:1 1 auto;min-height:0;overflow:auto;background:#0c0e12}
.fempty{color:var(--tx2);font-size:12px;padding:16px}
.fbody>.fempty,.flist>.fempty{display:grid;place-items:center;min-height:180px;text-align:center}
.fcode{margin:0;font:12px/1.7 var(--mono);padding:14px 0;tab-size:2}
.lnrow{display:flex;gap:14px;align-items:flex-start;padding:0 14px}
.lnrow:hover{background:#12141a}
.ln{flex:0 0 4ch;color:#9aa7b4;user-select:none;text-align:right}
.lntx{flex:1;min-width:0;white-space:pre-wrap;overflow-wrap:anywhere;color:#c9d1d9}
.fstbar{flex:0 0 auto;display:flex;flex-wrap:wrap;align-items:center;gap:14px;padding:7px 14px;
background:#17191f;border-top:1px solid var(--bd);font:10.5px var(--mono);color:var(--tx2)}
.fstbar b{color:var(--tx);font-weight:500}
.fstbar .teal{color:var(--teal)}

/* ---------- vps ---------- */
.mono{font-family:var(--mono)}.cy{color:var(--teal)}
.vwrap{display:flex;flex-direction:column;gap:14px}
.vhead{display:flex;align-items:center;gap:14px;background:#15171c;border:1px solid var(--bd);
border-radius:var(--rad2);padding:12px 14px}
.vdot{width:8px;height:8px;border-radius:50%;background:var(--dim);flex:0 0 8px}
.vdot.on{background:var(--teal);box-shadow:0 0 0 3px rgba(68,226,205,.14)}
.vwho{display:flex;flex-direction:column;gap:2px;min-width:0}
.vwho b{font:600 14px var(--disp);letter-spacing:-.01em;color:var(--tx)}
.vwho span{font:500 11px var(--mono);color:var(--tx2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vspeclist{display:grid;grid-template-columns:repeat(4,auto);gap:18px;margin-left:auto}
.vspeclist span{display:flex;flex-direction:column;gap:2px;min-width:0}
.vspeclist i{font:500 10.5px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:#8b98a5;font-style:normal}
.vspeclist b{font:500 12px var(--mono);color:var(--tx);white-space:nowrap}
.vbtn{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--bd2);background:#181a20;
color:var(--tx2);border-radius:999px;padding:6px 13px;font:500 12px var(--sans);cursor:pointer;white-space:nowrap}
.vbtn:hover{color:var(--tx);border-color:var(--pri)}
.vbtn .msi{font-size:15px}
.vgrid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;grid-auto-rows:1fr;align-items:stretch}
.vgrid>.vcard2{height:100%}
.vcard2{background:#15171c;border:1px solid var(--bd);border-radius:var(--rad2);padding:12px 14px;
display:flex;flex-direction:column;gap:7px;min-width:0}
.vcardt{display:flex;align-items:center;justify-content:space-between;gap:8px}
.vlab{font:600 10.5px var(--sans);letter-spacing:.08em;text-transform:uppercase;color:#8b98a5}
.vchip{font:500 10px var(--mono);color:var(--tx2);border:1px solid var(--bd2);border-radius:999px;
padding:1px 7px;background:#17191f;white-space:nowrap}
.vbig{font:600 27px/1.1 var(--disp);letter-spacing:-.02em;color:var(--tx);white-space:nowrap}
.vbig small{font:500 12px var(--mono);color:var(--tx2);letter-spacing:0;margin-left:5px;white-space:nowrap}
.vspark{width:100%;flex:1 1 auto;height:auto;min-height:32px;max-height:56px;display:block}
.vsegbar{display:flex;height:6px;border-radius:999px;overflow:hidden;background:#20232a;gap:1px}
.vsegbar i{display:block;height:100%}
.vmused{background:linear-gradient(90deg,#38bdf8,#44e2cd)}
.vmcache{background:#3f5d8f}
.vmfree{background:#39414b}
.vbar{height:5px;border-radius:999px;background:#20232a;overflow:hidden}
.vbar i{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,#38bdf8,#44e2cd)}
.vbar.dim i{background:#39414b}
.vfoot{display:flex;justify-content:space-between;gap:8px;font:500 10.5px var(--mono);color:var(--tx2);
border-top:1px solid rgba(34,37,44,.7);padding-top:7px;margin-top:auto}
.vsplit{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(0,1fr);gap:14px;align-items:stretch}
.vleft{display:flex;flex-direction:column;gap:14px;min-width:0}
.vright{display:flex;flex-direction:column;gap:14px;min-width:0}
.vcardh{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}
.vcardh h3{margin:0;font:600 10.5px var(--sans);letter-spacing:.08em;text-transform:uppercase;color:#8b98a5}
.vcardh .vsub{display:block;margin-top:3px;font:500 10.5px var(--mono);color:var(--tx2)}
.vpill{font:500 10px var(--mono);letter-spacing:.04em;color:var(--tx2);border:1px solid var(--bd2);
border-radius:999px;padding:1px 8px;background:#17191f;white-space:nowrap}
.vpill.ok{color:var(--teal);border-color:rgba(68,226,205,.3);background:rgba(68,226,205,.08)}
.vtable{display:flex;flex-direction:column}
.vrow{display:grid;grid-template-columns:minmax(0,1.5fr) 76px 72px 78px;gap:8px;align-items:center;
padding:6px 2px;border-top:1px solid rgba(34,37,44,.55);font:500 11.5px var(--mono);color:var(--tx2)}
.vrow.vth{border-top:0;padding-top:0;padding-bottom:4px;font:500 10.5px var(--mono);letter-spacing:.08em;
text-transform:uppercase;color:#8b98a5}
.vunit{display:flex;align-items:center;gap:6px;min-width:0;color:var(--tx)}
.vunit b{font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.vscope{font:500 9px var(--mono);color:var(--tx2);border:1px solid var(--bd2);border-radius:4px;
padding:0 4px;font-style:normal;flex:0 0 auto}
.vstate{display:inline-flex;align-items:center;gap:5px;font:500 10.5px var(--mono)}
.vstate i{width:6px;height:6px;border-radius:50%;background:var(--dim)}
.vstate.on{color:var(--teal)}.vstate.on i{background:var(--teal)}
.vstate.off{color:var(--err)}.vstate.off i{background:var(--err)}
.vempty{color:var(--tx2);font-size:12px;padding:10px 2px}
.vclist{display:flex;flex-direction:column;gap:8px;max-height:600px;overflow-y:auto;
 scrollbar-width:thin;scrollbar-color:var(--bd2) transparent}
.vclist::-webkit-scrollbar{width:6px}
.vclist::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:999px}
.vclist::-webkit-scrollbar-track{background:transparent}
.vclistfoot{font:500 10px var(--mono);color:#9aa7b4;padding-top:2px;display:flex;justify-content:space-between;gap:8px}
.vctr{background:#17191f;border:1px solid var(--bd);border-radius:10px;padding:8px 10px;
display:flex;flex-direction:column;gap:6px}
.vctrtop{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.vctrtop b{font:500 12px var(--mono);color:var(--tx);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}
.vcid{font:500 10px var(--mono);color:var(--tx2);font-style:normal}
.vhealth{font:500 9.5px var(--mono);text-transform:uppercase;letter-spacing:.06em;border:1px solid var(--bd2);
border-radius:999px;padding:0 6px;color:var(--tx2)}
.vhealth.ok{color:var(--teal);border-color:rgba(68,226,205,.3);background:rgba(68,226,205,.08)}
.vctrmeta{display:flex;align-items:center;justify-content:space-between;gap:10px;
font:500 10.5px var(--mono);color:var(--tx2)}
.vctrmeta .vbar{flex:1 1 auto}
.veplist{display:flex;flex-direction:column}
.veplist .vrow{grid-template-columns:minmax(0,1fr) 70px 70px}
.vep b{font:500 11.5px var(--mono);color:var(--tx);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.vms{font:500 10.5px var(--mono);color:var(--tx2);white-space:nowrap}
.vcode{font:600 10px var(--mono);border-radius:6px;padding:1px 7px;border:1px solid var(--bd2);color:var(--tx2)}
.vcode.ok{color:#0b1a16;background:var(--teal);border-color:var(--teal)}
.vcode.bad{color:#2a0b09;background:var(--err);border-color:var(--err)}
.vlogcard{flex:1 1 auto;min-height:0}
.vlogwrap{display:flex;flex-direction:column;gap:10px;min-height:0;max-height:520px;overflow-y:auto;padding-right:4px;scrollbar-width:thin;scrollbar-color:var(--bd2) transparent}
.vlogwrap::-webkit-scrollbar{width:6px}.vlogwrap::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:999px}.vlogwrap::-webkit-scrollbar-track{background:transparent}
.vlog{display:flex;align-items:baseline;gap:7px;padding:3px 0;border-bottom:1px solid rgba(34,37,44,.7)}
.vlog:last-child{border-bottom:0}
.vtime{flex:0 0 auto;font:500 10.5px var(--mono);color:var(--tx2)}
.vtag{flex:0 0 auto;min-width:48px;font:600 9.5px var(--mono);letter-spacing:.04em;
text-transform:uppercase;color:var(--tx2)}
.vtag.ok{color:var(--teal)}
.vtag.warn{color:var(--amber)}
.vtag.err{color:var(--err)}
.vtext{min-width:0;white-space:pre-wrap;overflow-wrap:anywhere;font:400 11.5px/1.45 var(--sans);color:var(--tx)}
.vmbars{display:flex;flex-direction:column;gap:6px}
.vmbar{display:grid;grid-template-columns:38px minmax(0,1fr) auto;align-items:center;gap:8px;
font:500 10.5px var(--mono);color:var(--tx2)}
.vmbar .vbar{height:4px}
.vmbar b{font-weight:500;color:var(--tx)}
@media(max-width:1100px){.vgrid{grid-template-columns:repeat(2,minmax(0,1fr))}.vsplit{grid-template-columns:1fr}}
@media(max-width:640px){.vgrid,.vspeclist{grid-template-columns:1fr}.vhead{flex-wrap:wrap}
.vtable{overflow-x:auto}.vrow{font-size:11px}}
.sub{font:600 10px var(--sans);letter-spacing:.08em;text-transform:uppercase;color:var(--tx2);
margin:0 0 8px}

.vheadr{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-left:auto}
.vtagbadge{font:500 9.5px var(--mono);letter-spacing:.1em;color:var(--teal);
 border:1px solid rgba(68,226,205,.28);background:rgba(68,226,205,.08);border-radius:999px;padding:2px 8px}
.vstamp{font:500 10.5px var(--mono);color:var(--tx2)}
.vbtn.small{padding:2px 8px;font-size:10.5px}
.vbtn.small .msi{font-size:14px}

.vcname{font:500 10px var(--mono);font-style:normal;color:var(--tx2);margin-left:6px}
.vtgt{display:block;grid-column:1/-1;font:500 10px var(--mono);color:var(--tx2);
 overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.vrow.vep{grid-template-columns:minmax(0,1fr) 54px 62px;row-gap:2px}


/* ---------- login ---------- */
.login-wrap{min-height:100dvh;display:grid;place-items:center;padding:24px;background:var(--bg)}
.login{width:100%;max-width:390px;background:#15171c;border:1px solid var(--bd2);
border-radius:16px;padding:28px}
.login .logo{width:42px;height:42px;border-radius:12px;font:600 14px var(--disp);margin-bottom:18px;
background:linear-gradient(140deg,#38bdf8,#2ee6c9);color:#06171f;display:grid;place-items:center}
.login .brandmark{display:block;width:210px;max-width:100%;height:auto;margin:0 auto 16px}
.login h1{font:600 18px var(--disp);margin:0 0 5px}
.login p{margin:0 0 20px;color:var(--tx2);font-size:12.5px}
.login label{display:block;font:600 10px var(--sans);letter-spacing:.08em;text-transform:uppercase;
color:var(--tx2);margin:14px 0 6px}
.login input{width:100%;background:#181a20;border:1px solid var(--bd2);color:var(--tx);
border-radius:9px;padding:10px 12px;font:13px var(--sans);outline:none}
.login input:focus{border-color:rgba(142,213,255,.45)}
.login .err{background:rgba(220,38,38,.12);border:1px solid rgba(255,142,133,.35);color:#ffc9c2;
border-radius:9px;padding:8px 11px;font-size:12px;margin-bottom:10px}
.login button{width:100%;margin-top:20px;padding:11px;border-radius:9px;border:1px solid var(--pri2);
background:var(--pri2);color:#04222e;font:600 13px var(--sans);cursor:pointer}
.login button:hover{box-shadow:0 0 20px -6px rgba(56,189,248,.5)}
.login small{display:block;margin-top:18px;color:var(--tx2);font:10.5px var(--mono);text-align:center}

/* ---------- modal ---------- */
body.modal-open{overflow:hidden}
.modal{position:fixed;inset:0;z-index:40;display:flex;align-items:center;justify-content:center;
padding:20px}
.modal[hidden]{display:none}
.modal-bd{position:absolute;inset:0;background:rgba(6,7,9,.72);backdrop-filter:blur(8px);
-webkit-backdrop-filter:blur(8px)}
.mcard{position:relative;z-index:1;width:100%;max-width:720px;max-height:85vh;display:flex;
flex-direction:column;background:#15171c;border:1px solid var(--bd2);border-radius:16px;overflow:hidden;
box-shadow:0 24px 64px -32px rgba(0,0,0,.9)}
.mcard:focus{outline:none}
.mhead{display:flex;align-items:center;gap:9px;padding:14px 18px;border-bottom:1px solid var(--bd);
background:#17191f}
.mhead .mid{font:500 11.5px var(--mono);color:var(--pri);letter-spacing:.04em}
.mclose{margin-left:auto;background:transparent;border:1px solid var(--bd2);color:var(--tx2);
border-radius:999px;width:27px;height:27px;line-height:1;font-size:16px;cursor:pointer;
display:grid;place-items:center;font-family:inherit}
.mclose:hover{color:var(--tx);border-color:var(--pri)}
.mbody{padding:18px;overflow-y:auto;overscroll-behavior:contain;flex:1 1 auto}
.mbody h3{margin:0 0 14px;font:600 17px/1.4 var(--disp);color:var(--tx)}
.mnote{border-radius:10px;padding:11px 13px;font-size:12.5px;line-height:1.6;white-space:pre-wrap;
margin-bottom:11px;background:#181a20;border:1px solid var(--bd);color:var(--tx2)}
.mnote.blocker{background:rgba(220,38,38,.1);border-color:rgba(255,142,133,.3);color:#ffc9c2}
.mnote em{display:block;font-style:normal;font:600 10px var(--sans);letter-spacing:.08em;
text-transform:uppercase;color:var(--tx2);margin-bottom:6px}
.mnote.blocker em{color:var(--err)}
.mmeta{display:grid;grid-template-columns:1fr 1fr;gap:14px 20px;margin:0 0 14px}
.mmeta>div{min-width:0}
.mmeta dt{font:600 10px var(--sans);letter-spacing:.08em;text-transform:uppercase;color:var(--tx2);
margin-bottom:3px}
.mmeta dd{margin:0;font-size:12.5px;color:var(--tx);overflow-wrap:anywhere}
.mmeta dd.mono{font:11.5px var(--mono);color:var(--tx2)}
.mout{border-top:1px solid var(--bd);padding-top:13px}
.mout .mlab{font:600 10px var(--sans);letter-spacing:.08em;text-transform:uppercase;color:var(--tx2);
display:block;margin-bottom:7px}
.opath{display:flex;align-items:center;gap:8px}
.opath code{flex:1 1 auto;min-width:0;background:#0c0e12;border:1px solid var(--bd);
border-radius:8px;padding:8px 11px;font:11.5px var(--mono);color:var(--tx2);overflow-x:auto;
white-space:nowrap}
.mbtn{background:transparent;border:1px solid var(--bd2);color:var(--tx2);border-radius:999px;
padding:6px 14px;font:500 12px var(--sans);cursor:pointer;white-space:nowrap;transition:.15s}
.mbtn:hover{color:var(--tx);border-color:var(--pri)}
.mbtn.primary{background:var(--pri2);border-color:var(--pri2);color:#04222e;font-weight:600}
.mbtn.primary:hover{box-shadow:0 0 18px -4px rgba(56,189,248,.4)}
.mfoot{display:flex;gap:8px;justify-content:flex-end;padding:12px 18px;border-top:1px solid var(--bd);
background:#17191f}
.ghost{border:1px solid var(--bd2);background:transparent;color:var(--tx2);border-radius:999px;
padding:5px 13px;font:500 12px var(--sans);cursor:pointer;transition:.15s}
.ghost:hover{color:var(--tx);border-color:var(--pri)}

/* ---------- responsive ---------- */
@media(max-width:1500px){.acthead,.actrow{grid-template-columns:84px 130px 165px minmax(0,1fr) 80px}}
@media(max-width:1380px){.cols{grid-template-columns:repeat(3,minmax(0,1fr));height:auto}
.col{height:auto;max-height:none}.kpi{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media(max-width:1100px){.rail{width:64px}.rbrand{padding:0;justify-content:center}
.rbrand .rname,.rlivepill,.nlabel,.nbadge,.rstat,.rlived span{display:none}
.nav{padding:12px 8px}.navitem{justify-content:center;padding:10px 0;border-radius:9px}
.rstat{display:none}.railfoot{padding:10px 8px}.railfoot .out{padding:8px 0}
.railfoot .out span.otx{display:none}
header{left:64px;padding:0 18px}main{margin-left:0;padding:84px 18px 32px}
.content{margin-left:64px}
.vtables{grid-template-columns:1fr}.vgrid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:900px){.cols{grid-template-columns:repeat(2,minmax(0,1fr))}
.kpi{grid-template-columns:repeat(2,minmax(0,1fr))}
.bots{grid-template-columns:1fr;height:auto}
.botchat{height:min(70vh,600px)}
#p-files{grid-template-columns:1fr;height:auto}
.fbody{min-height:320px}.fleft{max-height:420px}
.tbadges{display:none}}
@media(max-width:680px){
.app{flex-direction:column}
.rail{position:sticky;top:0;width:100%;flex-direction:row;align-items:center;height:52px;
border-right:0;border-bottom:1px solid var(--bd);padding:0 8px;gap:4px;overflow-x:auto;z-index:31}
 .rbrand{height:52px;padding:0 6px}.rlogo{height:24px;width:auto}
.nav{flex-direction:row;padding:0;gap:2px;flex:1 1 auto;overflow-x:auto}
.navitem{width:auto;padding:8px;border-left:0;border-bottom:2px solid transparent;border-radius:0}
.navitem.on{border-left:0;border-bottom-color:var(--pri);background:transparent}
.railfoot{display:none}
header{position:sticky;top:52px;left:0;height:auto;padding:10px 12px;flex-wrap:wrap;gap:8px;
border-bottom:1px solid var(--bd)}
.search{max-width:none}
main{margin-left:0;padding:14px 12px 28px}
.content{margin-left:0}
.wrap{gap:14px}
.cols{grid-template-columns:1fr;height:auto;min-height:0}
.actrows{height:min(34vh,300px)}
.actbar .alive,.metaline{display:none}
.col{height:auto;max-height:none}
.col .collist{max-height:none;overflow:visible}
.kpi{grid-template-columns:repeat(2,minmax(0,1fr))}
.crumb{flex-direction:column;align-items:flex-start}
.cright{width:100%;flex-wrap:wrap}
.acthead{display:none}
.actrow{grid-template-columns:74px minmax(0,1fr);gap:6px;font-size:11px}
.actrow .aact{grid-column:2;color:var(--teal)}
.actrow .atext{grid-column:1/-1;white-space:normal}
.actrow .amet{grid-column:2;text-align:left}
.vgrid{grid-template-columns:1fr}
.mmeta{grid-template-columns:1fr}
.mcard{max-height:92vh}
.login{padding:22px}
}


"""

LOGIN = r"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Masuk · __APP__</title>
<link rel="icon" type="image/png" href="/brand/logo-mark-64.png">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap">
<style>__STYLE__</style></head><body><div class="login-wrap"><form class="login" method="post" action="/login">
<img class="brandmark" src="/brand/logo-full-dark.png" alt="__APP__" width="210" height="210" decoding="async">
<p>Papan operasional · akses terbatas</p>
__ERR__
<label for="u">User</label><input id="u" name="user" autocomplete="username" required autofocus>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Masuk</button>
<small>__FOOT__</small></form></div></body></html>"""

PAGE = r"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__APP__</title>
<link rel="icon" type="image/png" href="/brand/logo-mark-64.png">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap">
<style>__STYLE__</style></head><body>
<div class="app">
<aside class="rail" id="rail">
 <div class="rbrand">
  <img class="rlogo" src="/brand/logo-mark-256.png" alt="__APP__" width="62" height="30" decoding="async">
  <div class="rname"><b>__APP__</b><span>__APPSHORT__</span></div>
  <span class="rlivepill"><span class="rdot"></span>LIVE</span>
 </div>
 <div class="rstat">
  <div class="row"><span>Fleet</span><b id="fleet-bots">– agen</b></div>
  <div class="bar"><i id="fleet-bar" style="width:100%"></i></div>
  <div class="row"><span>Task aktif</span><b id="fleet-tasks">–</b></div>
  <div class="row"><span>Quorum</span><b class="teal" id="fleet-quorum">–</b></div>
 </div>
 <nav class="nav">
  <button class="navitem on" type="button" data-panel="vps" title="Status VPS"><span class="msi" aria-hidden="true">dns</span><span class="nlabel">Status VPS</span><span class="nbadge" id="nb-vps">–</span></button>
  <button class="navitem" type="button" data-panel="board" title="Papan Tugas"><span class="msi" aria-hidden="true">view_kanban</span><span class="nlabel">Papan Tugas</span><span class="nbadge" id="nb-board">0</span></button>
  <button class="navitem" type="button" data-panel="agent" title="Agen"><span class="msi" aria-hidden="true">smart_toy</span><span class="nlabel">Agen</span><span class="nbadge" id="nb-agent">–</span></button>
  <button class="navitem" type="button" data-panel="bot" title="Chat"><span class="msi" aria-hidden="true">forum</span><span class="nlabel">Chat</span><span class="nbadge" id="nb-bot">–</span></button>
  <button class="navitem" type="button" data-panel="files" title="File"><span class="msi" aria-hidden="true">folder_data</span><span class="nlabel">File</span><span class="nbadge" id="nb-files">–</span></button>
 </nav>
 <div class="railfoot">
  <div class="rlived"><span class="rdot"></span><span id="ts">memuat…</span></div>
  <button class="out" type="button" onclick="location.href='/logout'"><span class="msi" aria-hidden="true">power_settings_new</span><span class="otx">Keluar</span></button>
 </div>
</aside>
<div class="content">
<header>
 <div class="search">
  <span class="msi" aria-hidden="true">search</span>
  <input id="q" type="text" placeholder="Cari task, agen, atau ID…" autocomplete="off" aria-label="Cari task">
  <kbd>Ctrl + K</kbd>
 </div>
 <div class="tright">
  <div class="tbadges">
   <span title="waktu muat /api/state terakhir">latensi <b class="teal" id="lat-ms">–</b></span><span class="sep"></span>
   <span>agen <b class="pri" id="bots-on">–</b></span><span class="sep"></span>
   <span><b id="clock-wib">--.--.--</b> WIB</span>
  </div>
  <button class="iconbtn" type="button" id="bell" title="Muat ulang data"><span class="msi" aria-hidden="true">notifications</span><span class="bellbadge" id="bell-badge" hidden>0</span></button>
 </div>
</header>
<main>
<div class="wrap">
 <section class="kpi" id="kpi" aria-label="Ringkasan antrean">
  <div class="kcard"><div class="ktop"><span class="klab">Antri</span><span class="kdot gray"></span></div>
   <div class="kval"><b id="k-antri">0</b><span>task menunggu</span></div>
   <div class="kbar"><i class="gray" id="k-antri-bar" style="width:0%"></i></div></div>
  <div class="kcard"><div class="ktop"><span class="klab">Dikerjakan</span><span class="kdot teal"></span></div>
   <div class="kval"><b id="k-kerja">0</b><span>slot aktif</span></div>
   <div class="kbar"><i class="teal" id="k-kerja-bar" style="width:0%"></i></div></div>
  <div class="kcard"><div class="ktop"><span class="klab">Terhenti</span><span class="kdot amber"></span></div>
   <div class="kval"><b id="k-terhenti">0</b><span>butuh keputusan</span></div>
   <div class="kbar"><i class="amber" id="k-terhenti-bar" style="width:0%"></i></div></div>
  <div class="kcard"><div class="ktop"><span class="klab">Verifikasi</span><span class="kdot amber"></span></div>
   <div class="kval"><b id="k-verif">0</b><span>menunggu review</span></div>
   <div class="kbar"><i class="amber" id="k-verif-bar" style="width:0%"></i></div></div>
  <div class="kcard"><div class="ktop"><span class="klab">Selesai</span><span class="kdot"></span></div>
   <div class="kval"><b id="k-selesai">0</b><span>task tuntas</span></div>
   <div class="kbar"><i id="k-selesai-bar" style="width:0%"></i></div></div>
 </section>

  <section class="panel" id="p-bots" hidden>
   <div class="ph"><div class="pl"><span class="picon"><span class="msi" aria-hidden="true">forum</span></span><h2 id="panelTitle">Percakapan</h2></div></div>
   <div class="chat3">
    <aside class="chleft">
     <div class="chscroll" id="chscroll">
      <div class="chsec"><span>Ruang</span><b id="roomcnt">0</b></div>
      <div class="chlist" id="roomlist"></div>
      <div class="chsec"><span>Agen</span><b id="agentcnt">0</b></div>
      <div class="chlist" id="botlist"></div>
     </div>
    </aside>
    <section class="chmid">
     <div class="bchathead" id="chathead">memuat…</div>
     <div class="chatstream" id="chatlog"><div class="empty">Belum ada percakapan</div></div>
     <div class="composer"><div class="chchips" id="chchips"></div><textarea id="cmsg" rows="1" placeholder="Tulis pesan…"></textarea><button class="send" id="csend" aria-label="Kirim"><span class="msi" aria-hidden="true">arrow_upward</span></button></div>
     <div class="thinking" id="cthink" hidden>berpikir…</div>
    </section>
    <aside class="chtele" id="chtele"></aside>
   </div>
  </section>

 <section class="panel" id="p-tasks" hidden>
  <div class="crumb">
   <div class="cleft">
    <div class="cpath"><span>Papan Tugas</span><i>/</i><em>semua divisi</em></div>
    <span class="chip"><span class="rdot"></span>Otonom: aktif</span>
   </div>
   <div class="cright">
    <button class="btn" type="button" id="fdiv-btn"><span class="msi" aria-hidden="true">tune</span><span id="fdiv-label">Semua divisi</span></button>
    <button class="btn primary" type="button" id="refresh"><span class="msi" aria-hidden="true">refresh</span>Muat ulang</button>
   </div>
  </div>
  <div class="boardstack">
   <div class="cols" id="board"></div>
   <div class="actwrap" id="actwrap">
    <div class="actbar" id="log-toggle">
     <div class="actbar-l">
      <span class="picon"><span class="msi" aria-hidden="true">terminal</span></span>
      <h2>Aktivitas &amp; Log</h2>
      <span class="actbadge" id="act-count">0 entri</span>
     </div>
     <div class="actbar-r">
      <span class="alive"><span class="rdot"></span>STREAMING</span>
      <span class="metaline" id="act-lat">–</span>
      <button class="tgl" type="button" id="log-toggle-btn" aria-expanded="true" aria-label="Lipat log"><span class="msi" aria-hidden="true">expand_less</span></button>
     </div>
    </div>
    <div class="acthead"><span>Waktu</span><span>Agen</span><span>Aksi</span><span>Detail</span><span style="text-align:right">Metrik</span></div>
    <div class="actrows" id="log"></div>
   </div>
  </div>
 </section>


 <section class="panel" id="p-vps">
  <div id="vps" class="empty">memuat…</div>
 </section>

 <section class="panel" id="p-agent" hidden>
  <div class="agpage">
   <aside class="agroster">
    <div class="agroster-h"><span>Agen</span><b id="ag-roster-count">0</b></div>
    <div class="agroster-list" id="ag-roster"></div>
   </aside>
   <div class="agdetail">
    <div class="aghead">
     <span class="agava" id="ag-av">—</span>
     <div class="agmeta">
      <div class="agline"><b id="ag-name">—</b><span class="agstate" id="ag-state">Idle</span>
       <span class="agtag" id="ag-rotag" hidden>read-only</span></div>
      <input id="ag-desc" class="agdesc" type="text" maxlength="200"
        placeholder="Deskripsi peran" aria-label="Deskripsi peran" autocomplete="off">
     </div>
     <div class="agacts">
      <button class="btn" id="ag-chat" type="button"><span class="msi" aria-hidden="true">chat</span>Buka chat</button>
      <button class="btn" id="ag-reset" type="button"><span class="msi" aria-hidden="true">refresh</span>Muat ulang</button>
     </div>
    </div>
    <div class="aggrid">
     <section class="agcard">
      <div class="agcard-h"><h3>Model &amp; Identitas</h3><span class="agtag" id="ag-idtag">—</span></div>
      <label class="aglab" for="ag-model">Model</label>
      <select id="ag-model" class="agsel"></select>
      <div class="agkv"><span>Provider</span><b id="ag-provider">—</b></div>
      <div class="agkv"><span>Config</span><b class="agmono" id="ag-config">—</b></div>
      <label class="aglab" for="ag-soul">SOUL.md</label>
      <textarea id="ag-soul" class="agsoul" spellcheck="false" aria-label="Isi SOUL.md"></textarea>
      <div class="agcount" id="ag-soulcount">0 baris · 0 karakter</div>
     </section>
     <section class="agcard agcard-skills">
      <div class="agcard-h"><h3>Skill</h3><span class="agtag" id="ag-skillcnt">0</span></div>
      <div class="agskbar">
       <span class="msi" aria-hidden="true">search</span>
       <input id="ag-skillfind" type="text" placeholder="Cari skill…" autocomplete="off" aria-label="Cari skill">
       <button class="btn" id="ag-addskill" type="button"><span class="msi" aria-hidden="true">add</span>Tambah skill</button>
      </div>
      <div class="agskills" id="ag-skilllist"><div class="empty">memuat…</div></div>
      <div class="agcard-h agsub-h"><h3>Rutin (cron)</h3><span class="agtag" id="ag-croncnt">0</span></div>
      <div id="ag-cron" class="agcron"><div class="empty">memuat…</div></div>
     </section>
     <section class="agcard">
      <div class="agcard-h"><h3>Status</h3><span class="agtag">live</span></div>
      <div class="agstats" id="ag-stats"><div class="empty">memuat…</div></div>
      <div class="aglinks">
       <button class="btn" id="ag-files" type="button"><span class="msi" aria-hidden="true">folder_data</span>Lihat file output</button>
      </div>
     </section>
    </div>
    <div class="agbanner" id="ag-banner"><span class="msi" aria-hidden="true">info</span>Perubahan langsung berlaku untuk bot ini — dicatat di activity-stream.log</div>
    <div class="agfoot">
     <button class="btn" id="ag-cancel" type="button">Batalkan perubahan</button>
     <button class="btn primary" id="ag-save2" type="button" disabled>Simpan perubahan</button>
    </div>
   </div>
  </div>
 </section>

 <section class="panel" id="p-files" hidden>
  <div class="fleft">
   <div class="froots" id="froots">
    <button class="tab on" type="button" data-root="workspace">workspace</button>
    <button class="tab" type="button" data-root="reports">reports</button>
    <button class="tab" type="button" data-root="docs">docs</button>
    <button class="tab" type="button" data-root="scripts">scripts</button>
   </div>
   <div class="fsearch"><span class="msi" aria-hidden="true">filter_alt</span><input id="ffilter" type="text" placeholder="Filter nama file…" autocomplete="off"></div>
   <div class="fcrumbs" id="fcrumbs"></div>
   <div class="flist" id="flist"><div class="fempty">memuat…</div></div>
   <div class="ffoot"><span id="fcount">0 entri</span><span>read-only</span></div>
  </div>
  <div class="fright" id="fright">
   <div class="fbody" id="fbody"><div class="fempty">Pilih file di kolom kiri untuk melihat pratinjau</div></div>
   <div class="fstbar" id="fstbar"></div>
  </div>
 </section>
</div>
</main>
</div>
</div>
<div class="modal" id="modal" hidden aria-hidden="true">
 <div class="modal-bd" data-close></div>
 <div class="mcard" id="mcard" role="dialog" aria-modal="true" aria-labelledby="m-title" tabindex="-1">
  <div class="mhead">
   <span class="mid" id="m-id"></span>
   <span class="st" id="m-status"></span>
   <span class="tag" id="m-prio"></span>
   <button class="mclose" id="m-x" type="button" aria-label="Tutup detail task">&times;</button>
  </div>
  <div class="mbody" id="m-body">
   <h3 id="m-title"></h3>
   <div class="mnote blocker" id="m-blocker" hidden><em>Blocker</em><span id="m-blocker-tx"></span></div>
   <div class="mnote" id="m-catatan" hidden><em>Catatan</em><span id="m-catatan-tx"></span></div>
   <dl class="mmeta" id="m-meta"></dl>
   <div class="mout" id="m-out" hidden>
    <span class="mlab">Output</span>
    <div class="opath"><code id="m-path"></code><button class="mbtn" id="m-copy" type="button">Salin</button></div>
   </div>
  </div>
  <div class="mfoot">
   <button class="mbtn" id="m-close" type="button">Tutup</button>
   <button class="mbtn primary" id="m-chat" type="button">Buka chat agen</button>
  </div>
  </div>
 </div>
<div class="modal" id="skillmodal" hidden aria-hidden="true">
 <div class="modal-bd" data-sclose></div>
 <div class="mcard smcard" role="dialog" aria-modal="true" aria-labelledby="sm-title" tabindex="-1">
  <div class="mhead"><span class="mid" id="sm-bot">—</span><button class="mclose" id="sm-x" type="button" aria-label="Tutup">&times;</button></div>
  <div class="mbody">
   <h3 id="sm-title">Tambah skill</h3>
   <label class="aglab" for="sm-name">Nama (slug)</label>
   <input id="sm-name" class="smtext" type="text" maxlength="64" placeholder="mis. riset-pasar" autocomplete="off">
   <label class="aglab" for="sm-desc">Deskripsi</label>
   <input id="sm-desc" class="smtext" type="text" maxlength="200" placeholder="Satu baris, maks 200 karakter" autocomplete="off">
   <label class="aglab" for="sm-body">Isi SKILL.md</label>
   <textarea id="sm-body" class="smbody" spellcheck="false" maxlength="20000" placeholder="# Nama skill&#10;&#10;Kapan dipakai…"></textarea>
   <div class="smmeta"><code id="sm-path">skills/&lt;slug&gt;/SKILL.md</code><span id="sm-count">0 / 20000</span></div>
   <div class="smmsg" id="sm-msg"></div>
  </div>
  <div class="mfoot">
   <button class="mbtn" id="sm-cancel" type="button">Batal</button>
   <button class="mbtn primary" id="sm-save" type="button" disabled>Simpan skill</button>
  </div>
 </div>
</div>
<script>const CSRF=__CSRF__;const _f=window.fetch.bind(window);window.fetch=(u,o)=>{o=o||{};o.headers=Object.assign({"x-csrf":CSRF},o.headers||{});return _f(u,o)};
const OWNER=__OWNER__,OWNERID=__OWNERID__,HQDIR=__HQ__;
const el=id=>document.getElementById(id);
const roomDefs=__ROOMS__;
let lastState=null;
let divFilter="", query="", latMs=null;
const DIVS=["semua"].concat(Object.keys(__DIVLABELS__));
const DIVLABEL=Object.assign({semua:"Semua divisi"},__DIVLABELS__);
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function mk(tag,cls,txt){const n=document.createElement(tag);if(cls)n.className=cls;if(txt!=null)n.textContent=txt;return n;}
function clipWords(s,n){s=String(s||"").replace(/\s+/g," ").trim();if(s.length<=n)return s;
 const w=s.split(" ");let out="";
 for(const x of w){if((out?out.length+1:0)+x.length>n)break;out=out?out+" "+x:x;}
 return (out||s.slice(0,n-1)).replace(/[ ,.;:—\-]+$/,"")+"…";}
function short(p){const w=String(p||"-").split("-").filter(Boolean);
 if(w.length>1)return (w[0][0]+w[1][0]).toUpperCase();return String(p||"-").slice(0,2).toUpperCase();}
function avClass(p){p=String(p||"");if(p===OWNERID)return"ch";if(p.indexOf("product")===0)return"pl";
 if(p.indexOf("agency")===0)return"al";if(p.indexOf("dropship")===0)return"dl";if(p.indexOf("hq")===0)return"ho";return"";}
function prioCls(v){v=String(v||"").toUpperCase();return v==="P0"?"p0":v==="P1"?"p1":v==="P2"?"p2":v==="P3"?"p3":"";}
function toBottom(n){if(n)n.scrollTop=n.scrollHeight;}
function lockBottom(n){if(!n)return;n.__stick=true;toBottom(n);
 requestAnimationFrame(()=>toBottom(n));
 requestAnimationFrame(()=>requestAnimationFrame(()=>toBottom(n)));
 if(document.fonts&&document.fonts.ready)document.fonts.ready.then(()=>toBottom(n));
 if(!n.__pin){n.__pin=function(){if(n.__stick!==false)toBottom(n);};
  n.addEventListener('scroll',function(){n.__stick=n.scrollTop+n.clientHeight>=n.scrollHeight-24;},{passive:true});
  if(window.ResizeObserver){new ResizeObserver(n.__pin).observe(n);}
  else if(window.addEventListener){window.addEventListener('resize',n.__pin);}}}
function relIso(iso){if(!iso)return"";const s=String(iso).replace(/([+-]\d{2})(\d{2})$/,"$1:$2");
 const t=new Date(s).getTime();if(isNaN(t))return"";const d=Math.max(0,Math.floor((Date.now()-t)/1000));
 if(d<60)return"baru saja";const m=Math.floor(d/60);if(m<60)return m+" mnt";const h=Math.floor(m/60);
 if(h<24)return h+" jam";const g=Math.floor(h/24);return g<30?g+" hari":Math.floor(g/30)+" bln";}
function fmtWIB(iso){if(!iso)return"";const s=String(iso).replace(/([+-]\d{2})(\d{2})$/,"$1:$2");
 const d=new Date(s);if(isNaN(d.getTime()))return String(iso);
 const p=new Intl.DateTimeFormat("id-ID",{timeZone:"Asia/Jakarta",day:"2-digit",month:"short",
  year:"numeric",hour:"2-digit",minute:"2-digit",hour12:false}).formatToParts(d);
 const g=k=>{const x=p.find(v=>v.type===k);return x?x.value:"";};
 return g("day")+" "+g("month")+" "+g("year")+" "+g("hour")+":"+g("minute");}
function wibHM(iso){const s=String(iso||"").replace(/([+-]\d{2})(\d{2})$/,"$1:$2");
 const d=new Date(s);if(isNaN(d.getTime()))return String(iso||"").slice(11,16);
 return d.toLocaleTimeString("id-ID",{timeZone:"Asia/Jakarta",hour:"2-digit",minute:"2-digit"});}
function wibEpoch(t){const d=new Date((Number(t)||0)*1000);if(!t||isNaN(d.getTime()))return"";
 return d.toLocaleTimeString("id-ID",{timeZone:"Asia/Jakarta",hour:"2-digit",minute:"2-digit"})+" WIB";}
function humanSize(n){n=Number(n)||0;if(n<1024)return n+" B";const u=["KB","MB","GB","TB"];let i=-1;
 do{n/=1024;i++;}while(n>=1024&&i<u.length-1);return (n<10?n.toFixed(1):Math.round(n))+" "+u[i];}
function relEpoch(t){if(!t)return"";const s=Math.max(0,Math.floor(Date.now()/1000-Number(t)));
 if(s<60)return"baru";const m=Math.floor(s/60);if(m<60)return m+"m";const h=Math.floor(m/60);
 if(h<24)return h+"j";const d=Math.floor(h/24);return d<30?d+"h":Math.floor(d/30)+"bl";
}

/* ---------- topbar clock ---------- */
function tickClock(){const d=new Date();const t=d.toLocaleTimeString("id-ID",{timeZone:"Asia/Jakarta",
 hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:false}).replace(/:/g,".");
 const c=el("clock-wib");if(c)c.textContent=t;
 if(lastState&&lastState.tasks)renderLive(lastState.tasks);}
setInterval(tickClock,1000);tickClock();

/* ---------- KPI + rail ---------- */
function countBy(tasks){const c={queued:0,in_progress:0,blocked:0,review:0,done:0,cancelled:0};
 tasks.forEach(t=>{if(c[t.status]!==undefined)c[t.status]++;else c.queued++;});return c;}
function fillBar(id,pct,cls){const n=el(id);if(!n)return;n.style.width=Math.max(2,Math.min(100,pct))+"%";
 n.className=cls||"";}
function renderKpi(tasks,activity){
 const c=countBy(tasks),tot=Math.max(1,tasks.length);
 const mx=Math.max(1,c.queued,c.in_progress,c.blocked,c.review,c.done);
 const pc=n=>Math.max(2,n/mx*100);
 const blocks=[[c.queued,pc(c.queued)],[c.in_progress,pc(c.in_progress)],
  [c.review,pc(c.review)],[c.done,pc(c.done)]];
 const set=(id,v)=> {const n=el(id);if(n)n.textContent=v;};
 set("k-antri",c.queued);set("k-kerja",c.in_progress);set("k-terhenti",c.blocked);set("k-verif",c.review);set("k-selesai",c.done);
 fillBar("k-antri-bar",blocks[0][1],"gray");fillBar("k-kerja-bar",blocks[1][1],"teal");
 fillBar("k-terhenti-bar",pc(c.blocked),"amber");
 fillBar("k-verif-bar",blocks[2][1],"amber");fillBar("k-selesai-bar",blocks[3][1],"");
 const open=tasks.filter(t=>t.status!=="done"&&t.status!=="cancelled").length;
 const nb=(id,v)=>{const n=el(id);if(n)n.textContent=v;};
 nb("nb-board",open);
 const bb=el("bell-badge");if(bb){bb.hidden=!open;bb.textContent=String(open);bb.title=open+" tugas aktif";}
 nb("fleet-tasks",String(open));
 const totalB=(typeof bots!=="undefined"&&bots?bots.length:0);
 const nowS=Date.now()/1000;
 const online=(typeof bots!=="undefined"&&bots?bots.filter(b=>b.active).length:0);
 const today=(typeof bots!=="undefined"&&bots?bots.filter(b=>Number(b.last_ts)>0&&nowS-Number(b.last_ts)<=86400).length:0);
 const qtip=online+" aktif ≤90 detik · "+today+" aktif 24 jam terakhir";
 nb("fleet-bots",totalB+" agen");
 nb("fleet-quorum",online>0?online+"/"+totalB+" online":totalB+" agen · "+today+" aktif hari ini");
 nb("bots-on",online>0?online+"/"+totalB:today+"/"+totalB+" hari ini");
 ["fleet-quorum","bots-on"].forEach(id=>{const n=el(id);if(n)n.title=qtip;});
 fillBar("fleet-bar",100,"");
 nb("nb-bot",totalB);
 nb("nb-agent",totalB);
}
let clockTick=0;
function renderLive(tasks){
 const open=tasks.filter(t=>t.status!=="done"&&t.status!=="cancelled").length;
 const t=el("ts");
 if(t)t.textContent="live · "+open+" tugas aktif · "+new Date().toLocaleTimeString("id-ID",
  {timeZone:"Asia/Jakarta",hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:false}).replace(/:/g,".")+" WIB";
 const l=el("act-lat");if(l)l.textContent=latMs==null?"–":"latency "+latMs+"ms";
}

/* ---------- board ---------- */
const COLORDER=["queued","in_progress","blocked","review","done"];
const COLLABEL={queued:"Antri",in_progress:"Dikerjakan",blocked:"Terhenti",review:"Verifikasi",done:"Selesai"};
const STATUS_ID={queued:"ANTRI",in_progress:"DIKERJAKAN",blocked:"TERHENTI",review:"VERIFIKASI",done:"SELESAI",cancelled:"DIBATALKAN"};
function taskNote(t){
 const id=t.id;const acts=(lastState&&lastState.activity)||[];
 for(const l of acts){if(String(l).indexOf(id)<0)continue;
  const parts=String(l).split("|");const body=parts.slice(2).join("|").trim();
  if(body)return body;}
 return clipWords(t.catatan||t.note||"",110);}
function cardHtml(t){
 const p=String(t.prioritas||t.priority||"").toUpperCase();
 const who=t.agen||t.owner||"-";
 const done=t.status==="done";
 const active=t.status==="in_progress";
 let sub="";
 if(active){
  const note=taskNote(t);
  sub='<div class="csub"><div class="csubh"><span>'+esc(who)+'</span><b>aktif</b></div>'
   +'<div class="csubtx">'+esc(note||"menjalankan task")+'</div></div>';
 }
 const age=relIso(t.updated_at||t.created_at);
 return '<div class="card'+(done?" done":"")+(active?" active":"")+'" role="button" tabindex="0" data-task="'+esc(t.id)+'" aria-haspopup="dialog">'
  +'<div class="ctop"><span class="cid">'+(active?'<span class="rdot"></span>':'')+esc(t.id)+'</span>'
  +(p?'<span class="tag '+prioCls(p)+'">'+esc(p)+'</span>':'')+'</div>'
  +'<p class="ctitle">'+esc(t.title||"(tanpa judul)")+'</p>'
  +((t.catatan||t.note)?'<p class="cdesc">'+esc(clipWords(t.catatan||t.note,120))+'</p>':'')
  +sub
  +'<div class="cfoot"><span class="cwho"><i class="cav '+avClass(who)+'">'+esc(short(who))+'</i>'
  +'<span>'+esc(who)+'</span></span><span class="cage">'+esc(age)+'</span></div>'
  +'</div>';}
function board(tasks){
 const q=(query||"").toLowerCase();
 const rows=(tasks||[]).filter(t=>{
  if(divFilter&&divFilter!=="semua"&&String(t.divisi||"")!==divFilter)return false;
  if(!q)return true;
  return (String(t.id)+" "+String(t.title||"")+" "+String(t.agen||"")).toLowerCase().indexOf(q)>=0;});
 const cols={queued:[],in_progress:[],blocked:[],review:[],done:[]};
 rows.forEach(t=>{(cols[t.status]||cols.queued).push(t);});
 el("board").innerHTML=COLORDER.map(k=>{
  const n=cols[k].length;
  const cntCls=k==="in_progress"?"cnt hot":k==="review"?"cnt warn":"cnt";
  return '<div class="col"><div class="colhead"><div class="chl"><span>'+COLLABEL[k]+'</span>'
   +'<span class="'+cntCls+'">'+n+'</span></div>'
   +'<button class="dots" type="button" tabindex="-1" aria-hidden="true"><span class="msi">more_horiz</span></button></div>'
   +'<div class="collist">'+(n?cols[k].map(cardHtml).join(""):'<div class="none">kosong</div>')+'</div></div>';
 }).join("");
}

/* ---------- activity ---------- */
function parseAct(l){
 const m=/^(\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d)?(?:[+-]\d\d:?\d\d)?)\s+(.*)$/.exec(String(l));
 if(!m)return{time:"--:--:--",who:"–",act:"LOG",txt:String(l),met:""};
 const d=new Date(m[1].replace(/([+-]\d\d)(\d\d)$/,"$1:$2"));
 const time=isNaN(d.getTime())?"--:--:--":d.toLocaleTimeString("en-GB",{timeZone:"Asia/Jakarta",hour12:false});
 const rest=m[2];
 const bar=rest.indexOf("|");
 const head=(bar>=0?rest.slice(0,bar):rest).trim();
 const tail=(bar>=0?rest.slice(bar+1):"").trim();
 const sp=head.indexOf(" ");
 const who=sp>0?head.slice(0,sp):head;
 let body=(sp>0?head.slice(sp+1):"").trim();
 let met="";
 if(tail){const bits=tail.split("|").map(s=>s.trim()).filter(Boolean);
  const last=bits.length?bits[bits.length-1]:"";
  if(last&&last.length<=12&&!/\s/.test(last)){met=last;if(bits.length>1)body+=" "+bits.slice(0,-1).join(" ");}
  else if(bits.length){body+=" "+bits.join(" ");}}
 let act="",txt=body;
 const c=body.indexOf(":");
 if(c>0&&c<=48){act=body.slice(0,c).trim();txt=body.slice(c+1).trim();}
 if(!act){act="aktivitas";}
 return{time,who,act:act.toUpperCase().slice(0,32),txt,met:met.slice(0,14)};
}
function renderActivity(activity){
 const box=el("log");box.replaceChildren();
 const rows=activity||[];
 const total=rows.length,shown=rows.slice(0,200);
 const cnt=document.getElementById("act-count");
 if(cnt)cnt.textContent=(total>200?"200 dari "+total:" "+total).trim()+" entri";
 if(!rows.length){box.appendChild(mk("div","empty","belum ada aktivitas"));return;}
 shown.forEach(l=>{const a=parseAct(l);
  const row=mk("div","actrow");row.title=String(l);
  row.appendChild(mk("span","atime",a.time));
  row.appendChild(mk("span","aagent",a.who));
  row.appendChild(mk("span","aact",a.act));
  row.appendChild(mk("span","atext",a.txt||"("+a.act.toLowerCase()+")"));
  const m=mk("span","amet"+(/^ok$/i.test(a.met)?" ok":/fail|error|blok/i.test(a.met)?" warn":""),a.met||"–");
  row.appendChild(m);box.appendChild(row);});
 box.scrollTop=0;
}

/* ---------- VPS ---------- */
let vpsCpuHist=[];
function num(x,d){const n=Number(x);if(x==null||x===""||isNaN(n))return"—";return n.toFixed(d==null?1:d);}
function vspark(hist){
 const v=hist&&hist.length?hist.slice(-60):[0];
 const n=v.length,max=Math.max(20,...v.map(x=>Number(x)||0));
 const pts=n<2?"0,32 120,32":v.map((x,i)=>((i/(n-1))*120).toFixed(1)+","+(32-(Math.min(100,Number(x)||0)/max)*30).toFixed(1)).join(" ");
 return'<svg class="vspark" viewBox="0 0 120 34" preserveAspectRatio="none" aria-hidden="true">'
  +'<defs><linearGradient id="vsparkg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#44e2cd" stop-opacity=".28"/><stop offset="1" stop-color="#44e2cd" stop-opacity="0"/></linearGradient></defs>'
  +(n<2?"":'<polygon points="'+pts+' 120,34 0,34" fill="url(#vsparkg)"/>')
  +'<polyline points="'+pts+'" fill="none" stroke="#44e2cd" stroke-width="1.6" vector-effect="non-scaling-stroke" stroke-linejoin="round" stroke-linecap="round"/></svg>';}
function vsegbar(m){
 const t=Math.max(1,Number(m.total_mb)||0);
 const used=Math.max(0,(Number(m.used_mb)||0)-(Number(m.cached_mb)||0));
 const w=x=>Math.max(0,Math.min(100,100*(Number(x)||0)/t)).toFixed(1);
 return'<div class="vsegbar"><i class="vmused" style="width:'+w(used)+'%"></i><i class="vmcache" style="width:'+w(m.cached_mb)+'%"></i><i class="vmfree" style="width:'+w(m.free_mb)+'%"></i></div>';}
function vcard(label,chip,value,body,foot){
 return'<article class="vcard2"><div class="vcardt"><span class="vlab">'+esc(label)+'</span>'
  +(chip?'<span class="vchip">'+chip+'</span>':'')+'</div>'
  +'<div class="vbig">'+value+'</div>'+(body||'')
  +(foot?'<div class="vfoot">'+foot+'</div>':'')+'</article>';}
function renderVps(v){v=v||{};
 const mem=v.mem||{},disk=v.disk||{},units=v.units||[],cont=v.containers||[],eps=v.endpoints||[],logs=(v.logs||[]).slice(-15);
 const cpu=Number(v.cpu)||0;vpsCpuHist.push(cpu);vpsCpuHist=vpsCpuHist.slice(-60);
 const proc=v.processes==null?"—":String(v.processes);
 const ld=(v.load||[]).slice(0,3).map(x=>esc(String(x))).join(" ")||"—";
 const boot=v.boot_at?new Date((Number(v.boot_at)+7*3600)*1000):null;
 const bmon=["Jan","Feb","Mar","Apr","Mei","Jun","Jul","Agu","Sep","Okt","Nov","Des"];
 const bootTxt=boot?boot.toISOString().slice(8,10)+" "+bmon[boot.getUTCMonth()]:"—";
 const bootFull=boot?bootTxt+" "+boot.toISOString().slice(11,16):"—";
 const sesN=Number(v.sessions)||0,tskN=Number(String(proc).split("/").pop())||0;
 const sesPct=Math.max(3,Math.min(100,sesN*10)),tskPct=Math.max(3,Math.min(100,tskN/512*100));
 const stamp=v.refreshed_at?new Date((Number(v.refreshed_at)+7*3600)*1000).toISOString().slice(11,19):"—";
 let h='<div class="vwrap"><div class="vhead"><span class="vdot on"></span>'
  +'<div class="vwho"><b>'+esc(v.hostname||v.host||"—")+'</b><span>'+esc(v.host||v.host_local||"—")+' · '+esc((v.arch||"—")+" / "+(v.virt||"—"))+'</span></div>'
  +'<div class="vspeclist">'
  +'<span><i>Kernel</i><b>'+esc(v.kernel||"—")+'</b></span>'
  +'<span><i>Uptime</i><b>'+esc(v.uptime_human||"—")+'</b></span>'
  +'<span><i>Proses</i><b>'+esc(proc)+'</b></span>'
  +'<span><i>Sesi</i><b>'+num(v.sessions,0)+'</b></span></div>'
  +'<div class="vheadr"><span class="vtagbadge">TAILSCALE</span>'
  +'<span class="vstamp">Diperbarui '+stamp+' WIB</span>'
  +'<button class="vbtn" type="button" id="vps-reload"><span class="msi" aria-hidden="true">refresh</span>Muat ulang</button></div></div>';

 h+='<div class="vgrid">'
  +vcard("CPU",esc((v.vcpus||"—")+" vCPU"),num(cpu,1)+' <small>%</small>',vspark(vpsCpuHist),
   '<span>Load: '+ld+'</span><span title="sampel CPU: polling klien, maks 60 titik" style="white-space:nowrap">'+vpsCpuHist.length+'/60</span>')
  +vcard("RAM",esc(num(mem.pct,1)+"%"),num((Number(mem.used_mb)||0)/1024,1)+' <small>/ '+num((Number(mem.total_mb)||0)/1024,1)+' GB</small>',vsegbar(mem),
   '<span>Cache '+num(mem.cached_mb,0)+' MB</span><span>Swap '+num(mem.swap_used_mb,0)+'/'+num(mem.swap_total_mb,0)+' MB</span>')
  +vcard("Disk",esc(num(disk.pct,1)+"%"),num(disk.used_gb,0)+' <small>/ '+num(disk.total_gb,0)+' GB</small>',
   '<div class="vbar"><i style="width:'+Math.max(1,Math.min(100,Number(disk.pct)||0))+'%"></i></div>',
   '<span>Sisa '+num(disk.free_gb,1)+' GB</span><span>Inode '+num(disk.inode_pct,1)+'%</span>')
  +vcard("Uptime","",esc(v.uptime_human||"—"),
   '<div class="vmbars"><div class="vmbar"><span>Sesi</span><div class="vbar"><i style="width:'+sesPct.toFixed(1)+'%"></i></div><b>'+num(v.sessions,0)+'</b></div>'
   +'<div class="vmbar"><span>Task</span><div class="vbar"><i style="width:'+tskPct.toFixed(1)+'%"></i></div><b>'+esc(proc)+'</b></div></div>',
   '<span>Boot '+esc(bootFull)+'</span>')
  +'</div>';

 const activeN=units.filter(u=>u.state==="active").length;
 h+='<div class="vsplit"><div class="vleft">'
  +'<div class="vcard2"><div class="vcardh"><div><h3>Systemd Unit</h3><span class="vsub">proses inti &amp; supervisor</span></div>'
  +'<span class="vpill'+(units.length&&activeN===units.length?" ok":"")+'">'+activeN+'/'+units.length+' active</span></div>'
  +'<div class="vtable"><div class="vrow vth"><span>UNIT</span><span>STATUS</span><span>UPTIME</span><span>RESOURCE</span></div>'
  +(units.length?units.map(u=>'<div class="vrow"><span class="vunit"><b title="'+esc(u.name||"—")+'">'+esc(u.name||"—")+'</b><i class="vscope">'+(u.scope==="user"?"user":"sys")+'</i></span>'
   +'<span class="vstate '+(u.state==="active"?"on":"off")+'"><i></i>'+esc(u.state||"—")+'</span>'
   +'<span>'+esc(u.uptime||"—")+'</span>'
   +'<span>'+esc(u.mem_mb==null?"—":num(u.mem_mb,1)+" MB")+'</span></div>').join(""):'<div class="vempty">tidak ada unit</div>')
  +'</div></div>'
  +'<div class="vcard2"><div class="vcardh"><div><h3>Container Docker</h3><span class="vsub">runtime container aktif</span></div>'
  +'<span class="vpill">'+cont.length+' container</span></div>'
  +'<div class="vclist">'+(cont.length?cont.map(c=>'<div class="vctr"><div class="vctrtop"><b>'+esc(c.image||c.name||"—")+'</b><i class="vcname">'+esc(c.name||"")+'</i>'
   +'<i class="vcid">cid:'+esc(String(c.cid||"—").slice(0,7))+'</i>'
   +'<span class="vhealth'+(c.health==="healthy"?" ok":"")+'">'+esc(c.health||"")+'</span></div>'
   +'<div class="vctrmeta"><span>Ports: '+esc(c.ports||"—")+'</span>'
   +'<div class="vbar"><i style="width:'+Math.max(0,Math.min(100,Number(c.mem_pct)||0))+'%"></i></div>'
   +'<span>'+esc(c.mem_used||"—")+' ('+num(c.mem_pct,1)+'%)</span></div></div>').join(""):'<div class="vempty">tidak ada container</div>')
   +'</div><div class="vclistfoot"><span>'+cont.length+' container aktif</span><span>gulir bila melebihi kartu</span></div></div></div>';

 h+='<div class="vright">'
  +'<div class="vcard2"><div class="vcardh"><div><h3>Domain & Endpoint</h3><span class="vsub">probe HTTP langsung dari VPS</span></div></div>'
  +'<div class="veplist"><div class="vrow vth"><span>HOST</span><span>STATUS</span><span>LATENSI</span><span>TARGET</span></div>'
  +(eps.length?eps.map(e=>{const c=Number(e.code)||0,okc=c>=200&&c<400;
    return '<div class="vrow vep"><b>'+esc(e.host||e.label||"—")+'</b>'
     +'<span class="vcode '+(okc?"ok":"bad")+'">'+(c?c:"down")+'</span>'
     +'<span class="vms">'+num(e.ms,0)+' ms</span>'
     +'<span class="vtgt mono">→ '+esc(e.target||"—")+'</span></div>';}).join(""):'<div class="vempty">tidak ada endpoint</div>')
  +'</div></div>'
  +'<div class="vcard2 vlogcard"><div class="vcardh"><div><h3>Log Aktivitas</h3><span class="vsub">'+logs.length+' baris terakhir</span></div>'
  +'<button class="vbtn small" type="button" id="vps-logreload"><span class="msi" aria-hidden="true">refresh</span>Muat ulang</button></div>'
  +'<div class="vlogwrap">'+(logs.length?logs.map(l=>{const tg=String(l.tag||"log").toUpperCase();
    const k=/ERROR/.test(tg)?"err":/WARN/.test(tg)?"warn":/(INFO|OK)/.test(tg)?"ok":"";
    return '<div class="vlog"><span class="vtime">'+esc(l.time||"—")+'</span>'
     +'<span class="vtag '+k+'">'+esc(l.tag||"log")+'</span>'
     +'<span class="vtext" title="'+esc(l.text||"—")+'">'+esc(l.text||"—")+'</span></div>';}).join(""):'<div class="vempty">tidak ada log</div>')
  +'</div></div></div></div></div>';

 const box=el("vps");if(box){box.className="";box.innerHTML=h;}
 const nb=el("nb-vps");
 if(nb){const bad=units.filter(u=>u.state!=="active").length+eps.filter(e=>!(Number(e.code)>=200&&Number(e.code)<400)).length;
  nb.textContent=bad?bad+"!":"ok";}
 const rl=el("vps-reload");if(rl)rl.onclick=()=>load();
 const ll=el("vps-logreload");if(ll)ll.onclick=()=>load();
}

/* ---------- state load ---------- */
async function load(){
 const t0=performance.now();
 try{
  const r=await fetch("/api/state",{cache:"no-store"});
  latMs=Math.round(performance.now()-t0);
  if(r.status===401){location.href="/login";return;}
  const d=await r.json();lastState=d;
  const lb=el("lat-ms");if(lb)lb.textContent=latMs+" ms";
  renderKpi(d.tasks||[],d.activity||[]);
  board(d.tasks||[]);
  renderActivity(d.activity||[]);
  renderVps(d.vps);
  renderLive(d.tasks||[]);
  deepLink();
  if(typeof renderList==="function")renderList();
  if(thread&&typeof loadThread==="function"&&tkind()==="room")loadThread();
  if(typeof renderTele==="function")renderTele();
  if(typeof bots!=="undefined"&&bots.length)renderKpi(d.tasks||[],d.activity||[]);
 }catch(e){const t=el("ts");if(t)t.textContent="terputus — coba lagi";}
}

/* ---------- percakapan: satu daftar (ruang + agen) ---------- */
let bots=[], curBot=null, curMsgs=[], roomMsgs=[], thread="";
const ROOM_IDS=Object.keys(roomDefs);
let BOT_IDS=[];
let lastSessionLabel="—";
function savedThread(){try{const v=localStorage.getItem("hq.thread")||"";
 const m=/^(room|bot):(.+)$/.exec(v);
 if(m&&(m[1]==="room"?ROOM_IDS.includes(m[2]):(BOT_IDS.length?BOT_IDS.includes(m[2]):true)))return v;}catch(e){}
 return __DEFTHREAD__;}
function tkind(){return thread.indexOf("bot:")===0?"bot":"room";}
function tid(){return thread.slice(thread.indexOf(":")+1);}
function rel(ts){if(!ts)return"";const n=Number(ts);return isFinite(n)&&n>0?relEpoch(n):"";}
function botFind(id){return bots.find(b=>b.bot===id)||null;}
function whoLabel(w){return w===OWNERID?OWNER:(w||"");}
function rtag(id){const p=String(id).split("-");return (p[0]==="hq"?p[0]:p[1]||p[0]).slice(0,2).toUpperCase();}
function renderRoutines(){
 const box=el("botroutines");if(!box)return;box.replaceChildren();
 const b=botFind(tid());
 if(!b||!(b.routines||[]).length){box.className="empty";box.textContent="Belum ada rutin";return;}
 box.className="";
 b.routines.forEach(r=>{
  const d=mk("div","rt");d.appendChild(mk("b",null,r.name||"(tanpa nama)"));
  const bits=[];if(r.schedule)bits.push(r.schedule);
  if(r.next_run)bits.push("berikut "+fmtWIB(r.next_run));
  if(r.enabled!==undefined)bits.push(r.enabled?"aktif":"nonaktif");
  d.appendChild(mk("span",null,bits.join(" · ")));box.appendChild(d);});
}
function convoRow(o){
 const it=mk("div","convo"+(o.on?" on":""));
 it.dataset.thread=o.key;it.setAttribute("role","button");it.tabIndex=0;
 const av=mk("div","botav",o.av);
 if(o.color)av.style.color=o.color;
 av.appendChild(mk("span","botlive"+(o.live?" on":"")));
 it.appendChild(av);
 const meta=mk("div","botmeta");
 const top=mk("b");top.appendChild(mk("span",null,o.name));
 top.appendChild(mk("time","convotime",o.time||""));meta.appendChild(top);
 const s=mk("s",null,o.sub);s.title=o.title||o.sub;meta.appendChild(s);
 it.appendChild(meta);
 it.onclick=()=>openThread(o.key);
 it.onkeydown=e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();openThread(o.key);}};
 return it;
}
function renderList(){
 const rl=el("roomlist"),bl=el("botlist");if(!rl||!bl)return;
 const logs=(lastState&&lastState.group_logs)||{};
 rl.replaceChildren();bl.replaceChildren();
 ROOM_IDS.forEach(id=>{
  const def=roomDefs[id]||{name:id,members:[]},rows=logs[id]||[],last=rows[rows.length-1]||null;
  rl.appendChild(convoRow({key:"room:"+id,av:rtag(id),name:def.name||id,
   sub:(def.members||[]).length+" anggota · "+rows.length+" pesan",
   time:last?relIso(last.ts):"",
   live:!!(last&&relIso(last.ts)&&/^(baru saja|\d+ mnt)$/.test(relIso(last.ts))),
   on:thread==="room:"+id}));});
 bots.forEach(b=>{
  const full=b.last_message_full||b.last_message||"";
  bl.appendChild(convoRow({key:"bot:"+b.bot,av:b.initials||short(b.bot),color:b.color||"#8ed5ff",
   name:b.name||b.bot,title:full,
   sub:(b.role||"agen")+(full?" · "+clipWords(full,48):" · belum ada pesan"),
   time:rel(b.last_ts),live:!!b.active,on:thread==="bot:"+b.bot}));});
 const rc=el("roomcnt"),ac=el("agentcnt");
 if(rc)rc.textContent=String(ROOM_IDS.length);
 if(ac)ac.textContent=String(bots.length);
}
function renderHead(){
 const h=el("chathead");if(!h)return;h.replaceChildren();
 const isRoom=tkind()==="room",id=tid();
 const wrap=mk("span","hmeta");
 if(isRoom){
  const def=roomDefs[id]||{name:id,members:[]};
  const av=mk("i","cav ho",rtag(id));h.appendChild(av);
  wrap.appendChild(mk("em","hbadge room","Ruang"));
  wrap.appendChild(mk("b",null,"# "+(def.name||id)));
  h.appendChild(wrap);
  h.appendChild(mk("small",null,(def.members||[]).length+" anggota · "+(roomMsgs||[]).length+" pesan"));
 }else{
  const b=botFind(id)||{name:id};
  const av=mk("i","cav "+avClass(id),b.initials||short(id));
  av.style.color=b.color||"#8ed5ff";h.appendChild(av);
  wrap.appendChild(mk("em","hbadge bot","Agen"));
  wrap.appendChild(mk("b",null,b.name||id));
  h.appendChild(wrap);
  h.appendChild(mk("small",null,b.role||"agen"));
  const gear=mk("button","iconbtn aggear");
  gear.type="button";gear.title="Pengaturan agen";gear.setAttribute("aria-label","Pengaturan agen");
  gear.appendChild(mk("span","msi","settings"));gear.onclick=()=>setPanel("agent",{bot:id});
  h.appendChild(gear);
 }
}
function renderChips(){
 const ch=el("chchips");if(!ch)return;ch.replaceChildren();
 if(tkind()!=="room")return;
 bots.filter(b=>b.chat).forEach(b=>{
  const c=mk("span","chchip","@"+b.bot);c.setAttribute("role","button");c.tabIndex=0;
  c.onclick=()=>{const t=el("cmsg");if(!t)return;
   t.value=(t.value.replace(/\s+$/,"")?t.value.replace(/\s+$/,"")+" ":"")+"@"+b.bot+" ";
   t.focus();syncSend();};
  ch.appendChild(c);});
}
function syncSend(){
 const t=el("cmsg"),s=el("csend");if(!t||!s)return;
 s.disabled=!t.value.trim()||(tkind()==="bot"&&!(curBot&&curBot.chat));
}
function setComposer(){
 const t=el("cmsg");if(!t)return;
 const isRoom=tkind()==="room";
 const dis=!isRoom&&!(curBot&&curBot.chat);
 t.disabled=dis;
 t.placeholder=dis?"chat nonaktif":(isRoom?"Tulis pesan ke ruang…":"Tulis pesan ke agen…");
 syncSend();
}
async function loadThread(){
 const box=el("chatlog");if(!box)return;
 box.replaceChildren();lastSessionLabel="—";
 if(!thread)return;
 if(tkind()==="room"){
  const id=tid();
  let rows=((lastState||{}).group_logs||{})[id]||[];
  try{
   const r=await fetch("/api/room?room="+encodeURIComponent(id),{cache:"no-store"});
   if(r.status===401){location.href="/login";return;}
   if(r.ok){const d=await r.json();if(d.log)rows=d.log;}
   roomMsgs=rows;
  }catch(e){}
  lastSessionLabel="#"+((roomDefs[id]||{}).name||id);
  if(!rows.length){box.appendChild(mk("div","empty","belum ada pesan di ruangan ini — tulis perintah, anggota menjawab bergiliran"));}
  else{
   rows.forEach(x=>{
    const me=String(x.who||"")===OWNERID;
    const turn=mk("div","chatturn"+(me?" me":""));
    const meta=mk("div","cmeta");
    if(!me){const av=mk("i","cav "+avClass(x.who),short(x.who));meta.appendChild(av);}
    meta.appendChild(mk("b",null,whoLabel(x.who)));
    const tEl=mk("time",null,wibHM(x.ts)+" WIB");tEl.dateTime=String(x.ts||"");
    tEl.title=fmtWIB(String(x.ts||""))+" WIB";meta.appendChild(tEl);
    turn.appendChild(meta);
    turn.appendChild(mk("div","bub",x.text||""));
    box.appendChild(turn);});
   lockBottom(box);
  }
  renderHead();renderTele();return;
 }
 const b=botFind(tid());
 if(!b){box.appendChild(mk("div","empty","Belum ada percakapan"));renderHead();renderTele();return;}
 curBot=b;
 try{
  const r=await fetch("/api/bots/"+encodeURIComponent(b.bot)+"/messages?limit=50",{cache:"no-store"});
  if(r.status===401){location.href="/login";return;}
  const d=await r.json();const msgs=d.messages||[];curMsgs=msgs;lastSessionLabel=d.session||"—";
  if(!msgs.length){box.appendChild(mk("div","empty","Belum ada percakapan"));}
  else{
   msgs.forEach(m=>{
    const user=m.role==="user";
    const turn=mk("div","chatturn"+(user?" me":""));
    const meta=mk("div","cmeta");
    if(!user){const av=mk("i","cav "+avClass(b.bot),b.initials||short(b.bot));
     av.style.color=b.color||"#8ed5ff";meta.appendChild(av);}
    meta.appendChild(mk("b",null,user?OWNER:(b.name||b.bot)));
    const tm=wibEpoch(m.timestamp);
    if(tm){const tEl=mk("time",null,tm);tEl.dateTime=new Date((Number(m.timestamp)||0)*1000).toISOString();
     tEl.title=fmtWIB(new Date((Number(m.timestamp)||0)*1000).toISOString());meta.appendChild(tEl);}
    turn.appendChild(meta);
    turn.appendChild(mk("div","bub",m.content||""));
    box.appendChild(turn);});
   lockBottom(box);
  }
 }catch(e){box.appendChild(mk("div","empty","gagal memuat: "+e.message));}
 renderHead();renderTele();
}
async function openThread(t){
 thread=t;
 curBot=tkind()==="bot"?botFind(tid()):null;
 try{localStorage.setItem("hq.thread",t);}catch(e){}
 renderList();renderChips();setComposer();renderHead();
 await loadThread();
 renderTele();
}
async function loadBots(){
 try{
  const r=await fetch("/api/bots",{cache:"no-store"});
  if(r.status===401){location.href="/login";return;}
  const d=await r.json();bots=d.bots||[];
  BOT_IDS=bots.map(b=>b.bot);
  curBot=tkind()==="bot"?botFind(tid()):null;
  renderList();setComposer();
  if(lastState)renderKpi(lastState.tasks||[],lastState.activity||[]);
 }catch(e){}
}
function threadCount(){return tkind()==="room"?roomMsgs.length:curMsgs.length;}
function teleStat(lab,val,sub){
 return'<div class="tele-stat"><span class="telab">'+lab+'</span><b>'+val+'</b>'+(sub?'<s>'+sub+'</s>':'')+'</div>';}
function threadOutputs(){
 const tasks=(lastState&&lastState.tasks)||[];
 const want=tkind()==="bot"?tid():null;
  const seen=new Set();
  return tasks.filter(t=>t.output_path&&(!want||t.agen===want))
   .sort((a,b)=>String(b.updated_at||"").localeCompare(String(a.updated_at||"")))
   .filter(t=>{if(seen.has(t.output_path))return false;seen.add(t.output_path);return true;})
   .slice(0,3);
}
function renderTele(){
 const box=el("chtele");if(!box)return;
 const isRoom=tkind()==="room",id=tid();
 const b=isRoom?null:botFind(id);
 const def=isRoom?(roomDefs[id]||{name:id,members:[]}):null;
 let h='<div class="teleh"><span>Telemetri</span><i class="telelive">Live</i></div>';
 h+='<div class="telegrid">'
  +teleStat("Pesan",String(threadCount()),"transkrip aktif")
  +(isRoom?teleStat("Anggota",String((def.members||[]).length),"di ruangan ini")
          :teleStat("Sesi",esc(lastSessionLabel||"—")))
  +'</div>';
 h+='<p class="tmeta">'+(isRoom?('Anggota: '+esc((def.members||[]).join(" · ")))
   :('Peran: '+esc(b?b.role:"—")))+'</p>';
 if(!isRoom&&((botFind(tid())||{}).routines||[]).length>0)h+='<div class="tblock"><p class="sub">Rutin agen</p><div id="botroutines"></div></div>';
 h+='<div class="tblock"><p class="sub">Output terakhir</p><div id="t-outputs"></div></div>';
 box.innerHTML=h;
 if(!isRoom)renderRoutines();
 renderOutputs();
}
function renderOutputs(){
 const box=el("t-outputs");if(!box)return;box.replaceChildren();
 const files=threadOutputs();
 if(!files.length){box.appendChild(mk("div","tmeta","—"));return;}
 files.forEach(f=>{
  const row=mk("div","tfile");
  row.appendChild(mk("span","tfn",String(f.output_path).replace(HQDIR+"/","")));
  row.appendChild(mk("span","tfs",relIso(f.updated_at)||""));
  row.title=f.output_path;box.appendChild(row);});
}
el("csend").onclick=async()=>{
 const box=el("chatlog"),ta=el("cmsg"),th=el("cthink");
 if(!thread)return;
 const text=ta.value.trim();if(!text)return;
 const isRoom=tkind()==="room",id=tid();
 ta.disabled=true;el("csend").disabled=true;th.hidden=false;
 th.textContent=isRoom?"ruang memproses… (1–2 menit)":"berpikir…";
 try{
  if(isRoom){
   const r=await fetch("/api/room",{method:"POST",headers:{"content-type":"application/json"},
    body:JSON.stringify({room:id,text:text})});
   const d=await r.json();ta.value="";
   if(!lastState)lastState={};
   if(!lastState.group_logs)lastState.group_logs={};
   if(d.log)lastState.group_logs[id]=d.log;
   await loadThread();renderList();
  }else{
   const r=await fetch("/api/bots/"+encodeURIComponent(id)+"/chat",{method:"POST",
    headers:{"content-type":"application/json"},body:JSON.stringify({text:text})});
   const d=await r.json();ta.value="";
   if(!d.ok&&d.error&&box)box.appendChild(mk("div","empty","error: "+d.error));
   await loadThread();await loadBots();
  }
 }catch(e){if(box)box.appendChild(mk("div","empty","error: "+e.message));}
 th.hidden=true;ta.disabled=false;syncSend();ta.focus();
};

/* ---------- modal ---------- */
let curTask=null,lastFocusId=null;
function taskById(id){return (((lastState||{}).tasks)||[]).find(t=>t.id===id)||null;}
function fillMeta(t){
 const rows=[["Agen",t.agen,""],["Divisi",t.divisi,""],["Room asal",t.room_asal,"mono"],
  ["Input dari",t.input_dari_agen,""],["Dibuat",fmtWIB(t.created_at),"mono"],
  ["Diperbarui",fmtWIB(t.updated_at),"mono"]];
 const box=el("m-meta");box.replaceChildren();
 rows.filter(r=>r[1]).forEach(([k,v,c])=>{
  const w=document.createElement("div");
  const dt=document.createElement("dt");dt.textContent=k;
  const dd=document.createElement("dd");if(c)dd.className=c;dd.textContent=v;
  w.appendChild(dt);w.appendChild(dd);box.appendChild(w);});
}
function openTask(id){
 const t=taskById(id);if(!t)return;
 curTask=t;lastFocusId=t.id;
 el("m-id").textContent=t.id;
 const st=el("m-status");st.textContent=STATUS_ID[t.status]||t.status||"-";
 st.className="st s-"+(t.status||"queued");
 const pv=String(t.prioritas||t.priority||"").toUpperCase();
 const pr=el("m-prio");pr.textContent=pv||"-";pr.className="tag "+(prioCls(pv)||"");
 el("m-title").textContent=t.title||"(tanpa judul)";
 const bl=el("m-blocker"),bt=t.blocker||"";
 bl.hidden=!bt;el("m-blocker-tx").textContent=bt;
 const ct=el("m-catatan"),cx=t.catatan||t.note||"";
 ct.hidden=!cx;el("m-catatan-tx").textContent=cx;
 fillMeta(t);
 const out=t.output_path?String(t.output_path):"";
 el("m-out").hidden=!out;el("m-path").textContent=out;
 el("m-copy").textContent="Salin";
 el("m-chat").hidden=!botFind(t.agen);
 const m=el("modal");m.hidden=false;m.setAttribute("aria-hidden","false");
 document.body.classList.add("modal-open");
 el("m-body").scrollTop=0;
 el("mcard").focus();
 if(location.hash!=="#task="+encodeURIComponent(t.id))history.replaceState(null,"","#task="+encodeURIComponent(t.id));
}
function closeTask(){
 const m=el("modal");if(!m||m.hidden)return;
 m.hidden=true;m.setAttribute("aria-hidden","true");
 document.body.classList.remove("modal-open");
 if(location.hash.indexOf("#task=")===0)history.replaceState(null,"","#panel=board");
 curTask=null;
 const back=lastFocusId?document.querySelector("[data-task='"+lastFocusId+"']"):null;
 if(back){try{back.focus();}catch(e){}}
}
function fallbackCopy(txt,done){const ta=document.createElement("textarea");
 ta.value=txt;ta.setAttribute("readonly","");ta.style.position="fixed";ta.style.top="-1000px";
 document.body.appendChild(ta);ta.select();
 try{document.execCommand("copy");}catch(e){}
 document.body.removeChild(ta);done();}
function copyOut(){const txt=el("m-path").textContent||"";if(!txt)return;
 const done=()=>{const b=el("m-copy");b.textContent="Tersalin";setTimeout(()=>{if(b)b.textContent="Salin";},1500);};
 if(navigator.clipboard&&navigator.clipboard.writeText)
  navigator.clipboard.writeText(txt).then(done,()=>fallbackCopy(txt,done));
 else fallbackCopy(txt,done);}
el("board").addEventListener("click",e=>{const c=e.target.closest("[data-task]");if(c)openTask(c.dataset.task);});
el("board").addEventListener("keydown",e=>{const c=e.target.closest("[data-task]");
 if(c&&(e.key==="Enter"||e.key===" ")){e.preventDefault();openTask(c.dataset.task);}});
el("modal").addEventListener("click",e=>{if(e.target.closest("[data-close]"))closeTask();});
el("m-x").onclick=closeTask;
el("m-close").onclick=closeTask;
el("m-copy").onclick=copyOut;
el("m-chat").onclick=()=>{const t=curTask;if(!t)return;const b=botFind(t.agen);
 closeTask();if(!b)return;setPanel("bot");openThread("bot:"+b.bot);};
document.addEventListener("keydown",e=>{if(e.key==="Escape")closeTask();});
(function(){const bar=el("log-toggle"),wrap=el("actwrap"),btn=el("log-toggle-btn");
 if(!bar||!wrap)return;
 const flip=()=>{const f=wrap.classList.toggle("folded");
  if(btn)btn.setAttribute("aria-expanded",f?"false":"true");};
 bar.addEventListener("click",flip);
})();
function deepLink(){const m=(location.hash||"").match(/^#task=(.+)$/);
 if(m){const id=decodeURIComponent(m[1]);if(el("modal").hidden)openTask(id);}}

/* ---------- panels / routing ---------- */
const PANELS={vps:"Status VPS",board:"Papan Tugas",agent:"Agen",bot:"Chat",files:"File"};
const PSEC={vps:"p-vps",board:"p-tasks",agent:"p-agent",bot:"p-bots",files:"p-files"};
let curPanel="vps",curRoot="workspace",curDir="",curFile=null,filesLoaded=false,fileFilter="";
let fileCache={root:"workspace",path:"",entries:[],breadcrumb:[]};
function panelHash(name){let h="#panel="+name;
 if(name==="files"){h+="&root="+encodeURIComponent(curRoot);if(curDir)h+="&path="+encodeURIComponent(curDir);}
 if(name==="agent"){h+="&bot="+encodeURIComponent(agentBot||anyAgent());}
 return h;}
function setPanel(name,opts){
 opts=opts||{};
 if(name==="agent"&&opts.bot)agentBot=opts.bot;
 if(name==="activity"){name="board";try{history.replaceState(null,"",panelHash("board"));}catch(e){}}
 if(!PANELS[name])name="vps";curPanel=name;
 document.querySelectorAll("main .panel").forEach(s=>{s.hidden=s.id!==PSEC[name];});
 document.querySelectorAll(".navitem").forEach(b=>b.classList.toggle("on",b.dataset.panel===name));
 document.querySelectorAll("#kpi").forEach(s=>{s.hidden=name!=="board";});
 if(!opts.silent){try{localStorage.setItem("hq.panel",name);}catch(e){}
  const h=panelHash(name);if(location.hash!==h)history.pushState(null,"",h);}
   if(name==="bot"){requestAnimationFrame(()=>{const s=el("chatlog");lockBottom(s);});}
   if(name==="agent"){requestAnimationFrame(()=>{
    const b=opts.bot||agentBot||(tkind()==="bot"?tid():"")||anyAgent();
    if(!rosterLoaded){rosterLoaded=true;loadRoster();}
    loadAgent(b);markRoster(b);});}
   if(name==="files"){
   if(opts.root)curRoot=opts.root;
  if(!filesLoaded){filesLoaded=true;loadFiles(opts.path!==undefined?opts.path:curDir,curRoot);}
  else if(opts.path!==undefined||opts.root){loadFiles(opts.path!==undefined?opts.path:curDir,curRoot);}
 }
}
function parseHash(){
 const h=location.hash||"";
 if(h.indexOf("#task=")===0)return{task:decodeURIComponent(h.slice(6))};
 if(h.indexOf("#panel=")===0){
  const parts=h.slice(7).split("&"),out={};
  parts.forEach((p,i)=>{if(i===0){out.panel=decodeURIComponent(p);return;}
   const kv=p.split("=");out[kv[0]]=decodeURIComponent(kv.slice(1).join("=")||"");});
  if(out.panel==="activity"){out.panel="board";try{history.replaceState(null,"","#panel=board");}catch(e){}}
  return out;}
 return {};}
function route(){
 const r=parseHash();
 if(r.task){if(curPanel!=="board")setPanel("board",{silent:true});
  if(el("modal").hidden)openTask(r.task);return;}
 if(r.panel){setPanel(r.panel,{silent:true,root:r.root,path:r.path,bot:r.bot});return;}
 let saved="vps";try{saved=localStorage.getItem("hq.panel")||"vps";}catch(e){}
 setPanel(saved,{silent:true});}

/* ---------- agent settings ---------- */
let agentBot=null,agentData=null,agentDirty=false,agentSkills=[],rosterLoaded=false;
let AGENT_RO=[];
function anyAgent(){return AGENT_RO[0]||"";}
function markRoster(bot){
 document.querySelectorAll("#ag-roster .agrcard").forEach(c=>{
  c.classList.toggle("on",!!bot&&c.dataset.bot===bot);});}
async function loadRoster(silent){
 const box=el("ag-roster");if(!box)return;
 try{
  const r=await fetch("/api/agents",{cache:"no-store"});
  if(r.status===401){location.href="/login";return;}
  const d=await r.json();const list=(d&&d.agents)||[];
  AGENT_RO=list.map(a=>a.bot);
  const c=el("ag-roster-count");if(c)c.textContent=String(list.length);
  const frag=document.createDocumentFragment();
  list.forEach(a=>{
   const card=mk("div","agrcard"+(a.bot===agentBot?" on":""));
   card.dataset.bot=a.bot;card.tabIndex=0;card.setAttribute("role","button");
   const av=mk("div","agrav",a.initials||(a.name||"?").slice(0,2).toUpperCase());
   av.style.color=a.color||"#8ed5ff";card.appendChild(av);
   const body=mk("div","agrbody");
   const top=mk("div","agrtop");top.appendChild(mk("b",null,a.name||a.bot));
   const st0=a.state||{};top.appendChild(mk("span","agstate"+(st0.cls?" "+st0.cls:""),st0.text||"Idle"));
   body.appendChild(top);
   body.appendChild(mk("span","agrole",a.role||""));
   const foot=mk("div","agrfoot");
   foot.appendChild(mk("span","agrfoot-txt",(a.skills||0)+" skill · "+(a.routines||0)+" rutin"));
   if(a.read_only)foot.appendChild(mk("span","agtag","read-only"));
   body.appendChild(foot);card.appendChild(body);
   card.addEventListener("click",()=>selectAgent(a.bot));
   card.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();selectAgent(a.bot);}});
   frag.appendChild(card);});
  box.replaceChildren(frag);
 }catch(e){if(!silent&&box)box.replaceChildren(mk("div","empty",e.message));}
}
function selectAgent(bot){
 if(!bot)return;
 if(curPanel!=="agent"||agentBot!==bot){setPanel("agent",{bot});return;}
 loadAgent(bot);markRoster(bot);
}
function renderSkillList(q){
 const box=el("ag-skilllist");if(!box)return;box.replaceChildren();
 const s=(q||"").trim().toLowerCase();
 const rows=agentSkills.filter(x=>!s||(((x.name||"")+" "+(x.description||"")).toLowerCase().indexOf(s)>=0));
 if(!rows.length){box.appendChild(mk("div","empty",s?"tidak ada yang cocok":"Belum ada skill"));return;}
 rows.forEach(x=>{
   const row=mk("div","agskill");
   row.title=x.description||"";
  row.appendChild(mk("span","agname",x.name||"—"));
  const de=mk("span","agsdesc",x.description||"");
  de.title=x.description||"";
  row.appendChild(de);
  row.appendChild(mk("span","agkvsz",agFmtKb((Number(x.size)||0)/1024)));
  box.appendChild(row);});
}
function agSetDirty(on){agentDirty=!!on;
 ["ag-save2"].forEach(id=>{const b=el(id);if(b)b.disabled=!agentDirty||!agentData||agentData.read_only;});}
function agCountSoul(){const t=el("ag-soul"),c=el("ag-soulcount");if(!t||!c)return;
 const v=t.value;const lines=v?v.split("\n").length:0;
 c.textContent=lines+" baris · "+v.length+" karakter";}
function agStat(lab,val,wide){const d=mk("div","agstat"+(wide?" wide":""));d.appendChild(mk("span",null,lab));
 d.appendChild(mk("b",null,val));return d;}
function agFmtKb(kb){const n=Number(kb||0);return n>=1024?(n/1024).toFixed(1)+" MB":n.toFixed(1)+" KB";}
function agModelSelect(d){
 const sel=el("ag-model");if(!sel)return;sel.replaceChildren();
 const list=(d.models||[]).slice();
 if(d.model&&list.indexOf(d.model)<0)list.unshift(d.model);
 list.forEach(m=>{const o=document.createElement("option");o.value=m;
  o.textContent=m+(d.model===m&&(d.models||[]).indexOf(m)<0?" (sekarang)":"");sel.appendChild(o);});
 sel.value=d.model||list[0]||"";
}
function agJobState(box,on){
 const cb=box.querySelector(".agjob-en"),st=box.querySelector(".agjob-st"),txt=box.querySelector(".agsw-txt");
 if(cb)cb.checked=!!on;
 if(txt)txt.textContent=on?"Aktif":"Nonaktif";
 if(st){st.textContent="NONAKTIF";st.className="agjob-st off";st.hidden=!!on;}
}
function agRoutineBox(j){
 const box=mk("div","agjob");box.dataset.id=j.id;
 const hd=mk("div","agjob-h");hd.appendChild(mk("b",null,j.name||"(tanpa nama)"));
 const st=mk("span","agjob-st off","NONAKTIF");hd.appendChild(st);box.appendChild(hd);
 const row=mk("div","agjob-row");
 const lab=mk("label","agsw");
 const cb=document.createElement("input");cb.type="checkbox";cb.className="agjob-en";cb.setAttribute("role","switch");
 lab.appendChild(cb);lab.appendChild(mk("span","agsw-track"));lab.appendChild(mk("span","agsw-txt"));row.appendChild(lab);
 const sch=document.createElement("input");sch.type="text";sch.className="agjob-sch";sch.value=j.schedule||"";sch.placeholder="m h dom mon dow";
 sch.setAttribute("aria-label","Jadwal cron");row.appendChild(sch);
 const btn=mk("button","btn","Simpan rutin");btn.type="button";btn.className="btn agjob-save";row.appendChild(btn);
 box.appendChild(row);
 const meta=mk("div","agjob-meta");
 const mrow=(k,v)=>{const d=mk("div");d.appendChild(mk("i",null,k));d.appendChild(mk("span",null,v));meta.appendChild(d);};
 if(j.deliver)mrow("deliver:",String(j.deliver));
 if(j.next_run_at)mrow("berikut:",fmtWIB(j.next_run_at)+" WIB");
 if(j.last_run_at){const s=fmtWIB(j.last_run_at)+" WIB"+(j.last_status?" · "+j.last_status:"");
  mrow("terakhir:",s);}
 else if(j.last_status)mrow("terakhir:","· "+j.last_status);
 if(j.timezone)mrow("timezone:",String(j.timezone));
 if(meta.childNodes.length)box.appendChild(meta);
  if(Object.prototype.hasOwnProperty.call(j,"prompt")){
   const plab=mk("label","aglab","Prompt rutin");box.appendChild(plab);
   const ta=document.createElement("textarea");ta.className="agjob-prompt";ta.maxLength=2000;
  ta.value=j.prompt||"";ta.setAttribute("aria-label","Prompt rutin");box.appendChild(ta);}
 if(j.steps){
  const st2=document.createElement("textarea");st2.className="agjob-steps";st2.maxLength=4000;
  st2.value=String(j.steps);st2.setAttribute("aria-label","Langkah rutin");st2.readOnly=true;box.appendChild(st2);}
 const msg=mk("div","agjob-msg");box.appendChild(msg);
 const ro=!agentData||agentData.read_only;
 [cb,sch,btn].forEach(x=>{x.disabled=ro;});
 box.querySelectorAll("textarea").forEach(x=>{x.disabled=ro;});
 agJobState(box,!!j.enabled);
 btn.onclick=()=>agSaveRoutine(j.id,box);
 cb.onchange=()=>agJobState(box,cb.checked);
 cb.addEventListener("change",()=>agSetDirty(true));
 sch.addEventListener("input",()=>agSetDirty(true));
 box.querySelectorAll("textarea").forEach(t=>t.addEventListener("input",()=>agSetDirty(true)));
 return box;
}
function renderAgent(d){
 agentData=d;agentBot=d.bot||agentBot;
 const ro=!!d.read_only;
 const p=el("p-agent");if(p)p.dataset.ro=ro?"1":"0";
 const rt=el("ag-rotag");if(rt)rt.hidden=!ro;
 const av=el("ag-av");if(av){av.textContent=d.initials||(d.name||"?").slice(0,2).toUpperCase();av.style.color=d.color||"#8ed5ff";}
 const nm=el("ag-name");if(nm)nm.textContent=d.name||d.bot;
 const s=el("ag-state");
 if(s){const d0=d.state||{};s.textContent=d0.text||"Idle";s.className="agstate"+(d0.cls?" "+d0.cls:"");
  s.title=d0.minutes==null?"Dihitung dari stats.last_activity (state.db): belum ada aktivitas tercatat"
   :"Dihitung dari stats.last_activity (state.db): "+d0.minutes+" menit lalu";}
 const ds=el("ag-desc");if(ds){ds.value=d.description||"";ds.disabled=ro;}
 agModelSelect(d);
 const pv=el("ag-provider");if(pv)pv.textContent=d.provider||"—";
 const cf=el("ag-config");if(cf)cf.textContent=d.config_path||"—";
 const idt=el("ag-idtag");if(idt)idt.textContent=ro?"read-only":(d.bot||"");
 const soul=el("ag-soul");
 if(soul){soul.value=d.soul||"";soul.disabled=ro;soul.placeholder="(belum ada SOUL.md)";}
 agCountSoul();
 const sel=el("ag-model");if(sel)sel.disabled=ro;
 const cr=el("ag-cron");const cnt=el("ag-croncnt");
 if(cr){cr.replaceChildren();const rs=d.routines||[];
  if(cnt)cnt.textContent=String(rs.length);
  if(!rs.length){const e=mk("div","empty","Belum ada rutin");cr.appendChild(e);}
  else rs.forEach(j=>cr.appendChild(agRoutineBox(j)));}
 agentSkills=(d.skills||[]).slice();
 const sc=el("ag-skillcnt");if(sc)sc.textContent=String(agentSkills.length);
 const sf=el("ag-skillfind");if(sf)sf.value="";
 renderSkillList("");
 const as=el("ag-addskill");if(as)as.disabled=ro;
 const sb=el("ag-stats");
 if(sb){sb.replaceChildren();const st=d.stats||{};
  sb.appendChild(agStat("Sesi",String(st.sessions||0)));
  sb.appendChild(agStat("Pesan",String(st.messages||0)));
  sb.appendChild(agStat("Aktivitas terakhir",st.last_activity?fmtWIB(new Date(Number(st.last_activity)*1000).toISOString())+" WIB":"—",true));
  sb.appendChild(agStat("Memori",agFmtKb(st.memory_kb)));
  sb.appendChild(agStat("Skill",String(st.skills||0)));
  sb.appendChild(agStat("Folder profile",agFmtKb(st.folder_kb),true));}
 const bn=el("ag-banner");
 if(bn&&ro)bn.lastChild.textContent="Bot "+OWNER+" bersifat read-only — pengaturan tidak dapat diubah dari panel ini.";
 agSetDirty(false);
 markRoster(agentBot);
 loadRoster(true);
}
async function loadAgent(bot){
 if(!AGENT_RO.length)await loadRoster(true);
 if(!bot||AGENT_RO.indexOf(bot)<0)bot=anyAgent();
 if(!bot)return;
 agentBot=bot;agentData=null;agSetDirty(false);
 const sb=el("ag-stats");if(sb)sb.innerHTML='<div class="empty">memuat…</div>';
 const cr=el("ag-cron");if(cr)cr.innerHTML='<div class="empty">memuat…</div>';
 const sl=el("ag-skilllist");if(sl)sl.innerHTML='<div class="empty">memuat…</div>';
 try{
  const r=await fetch("/api/agent/"+encodeURIComponent(bot),{cache:"no-store"});
  if(r.status===401){location.href="/login";return;}
  const d=await r.json();
  if(!r.ok){if(cr)cr.innerHTML='<div class="empty">'+(d.error||"gagal memuat")+'</div>';return;}
  renderAgent(d);
 }catch(e){if(cr)cr.innerHTML='<div class="empty">'+e.message+'</div>';}
}
async function agSave(){
 if(!agentData||agentData.read_only)return;
 const body={},base=agentData,changed=[];
 const ds=el("ag-desc"),sel=el("ag-model"),soul=el("ag-soul");
 if(ds&&(ds.value||"")!==(base.description||"")){body.description=ds.value;changed.push("description");}
 if(sel&&sel.value!==(base.model||"")){body.model=sel.value;changed.push("model");}
 if(soul&&(soul.value||"")!==(base.soul||"")){body.soul=soul.value;changed.push("soul");}
 const rout=[];
 document.querySelectorAll("#ag-cron .agjob").forEach(box=>{
  const id=box.dataset.id;
  const snap=(base.routines||[]).filter(x=>String(x.id)===String(id))[0];
  if(!snap)return;
  const cb=box.querySelector(".agjob-en"),sch=box.querySelector(".agjob-sch"),ta=box.querySelector(".agjob-prompt");
  const rec={id:snap.id,enabled:!!(cb&&cb.checked),schedule:((sch&&sch.value)||"").trim(),
   prompt:ta?ta.value:(snap.prompt||"")};
  const diff=rec.enabled!==!!snap.enabled||rec.schedule!==(snap.schedule||"")||
   rec.prompt!==(snap.prompt||"");
  if(diff){rout.push(rec);changed.push("routine:"+String(snap.id));}
 });
 if(rout.length)body.routines=rout;
 if(!changed.length){agSetDirty(false);return;}
 ["ag-save2"].forEach(id=>{const b=el(id);if(b)b.disabled=true;});
 try{
  const r=await fetch("/api/agent/"+encodeURIComponent(agentBot),{method:"POST",
   headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const d=await r.json().catch(()=>({}));
  if(!r.ok){alert(d.error||("gagal menyimpan ("+r.status+")"));agSetDirty(true);return;}
  await loadAgent(agentBot);
 }catch(e){alert("gagal menyimpan: "+e.message);agSetDirty(true);}
}
async function agSaveRoutine(id,box){
 if(!agentData||agentData.read_only)return;
 const cb=box.querySelector(".agjob-en"),sch=box.querySelector(".agjob-sch"),ta=box.querySelector(".agjob-prompt");
 const msg=box.querySelector(".agjob-msg");const btn=box.querySelector(".agjob-save");
 const body={enabled:!!cb.checked,schedule:(sch.value||"").trim()};
 if(ta)body.prompt=ta.value||"";
 if(btn)btn.disabled=true;
 try{
  const r=await fetch("/api/agent/"+encodeURIComponent(agentBot)+"/routine/"+encodeURIComponent(id),
   {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const d=await r.json().catch(()=>({}));
  if(!r.ok){if(msg){msg.className="agjob-msg err";msg.textContent=d.error||("gagal ("+r.status+")");}return;}
  if(msg){msg.className="agjob-msg ok";msg.textContent="Tersimpan · "+wibEpoch(Date.now()/1000);}
   if(agentData&&agentData.routines){agentData.routines=agentData.routines.map(x=>x.id===id?d.routine:x);}
   if(d.routine)agJobState(box,!!d.routine.enabled);
  }catch(e){if(msg){msg.className="agjob-msg err";msg.textContent=e.message;}}
 finally{if(btn)btn.disabled=false;}
}
["ag-desc","ag-model","ag-soul"].forEach(id=>{const n=el(id);if(!n)return;
 const ev=n.tagName==="SELECT"?"change":"input";
 n.addEventListener(ev,()=>{agCountSoul();agSetDirty(true);});});
let smBot=null;
function smSync(){
 const nm=el("sm-name"),ds=el("sm-desc"),bd=el("sm-body");
 const name=nm?nm.value.trim():"",desc=ds?ds.value.trim():"",body=bd?bd.value.trim():"";
 const path=el("sm-path");if(path)path.textContent="skills/"+(name||"<slug>")+"/SKILL.md";
 const cnt=el("sm-count");if(cnt)cnt.textContent=(bd?bd.value.length:0)+" / 20000";
 const ok=/^[a-z0-9][a-z0-9_-]{1,63}$/.test(name)&&desc.length>=1&&desc.length<=200&&body.length>0;
 const sv=el("sm-save");if(sv)sv.disabled=!ok;
}
function smOpen(){
 const m=el("skillmodal");if(!m)return;
 smBot=agentBot||anyAgent();
 if(!smBot)return;
 const b=el("sm-bot");if(b)b.textContent=smBot;
 ["sm-name","sm-desc","sm-body"].forEach(id=>{const n=el(id);if(n)n.value="";});
 const msg=el("sm-msg");if(msg){msg.className="smmsg";msg.textContent="";}
 smSync();
 m.hidden=false;m.setAttribute("aria-hidden","false");
 document.body.classList.add("modal-open");
 setTimeout(()=>{const n=el("sm-name");if(n)n.focus();},30);
}
function smClose(){
 const m=el("skillmodal");if(!m)return;
 m.hidden=true;m.setAttribute("aria-hidden","true");
 const k=el("modal");if(!k||k.hidden)document.body.classList.remove("modal-open");
}
async function smSave(){
 if(!smBot)return;
 const nm=el("sm-name"),ds=el("sm-desc"),bd=el("sm-body"),msg=el("sm-msg"),sv=el("sm-save");
 const payload={name:(nm?nm.value:"").trim(),description:(ds?ds.value:"").trim(),body:bd?bd.value:""};
 if(sv)sv.disabled=true;
 try{
  const r=await fetch("/api/agent/"+encodeURIComponent(smBot)+"/skill",{method:"POST",
   headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  const d=await r.json().catch(()=>({}));
  if(!r.ok){if(msg){msg.className="smmsg err";msg.textContent=d.error||("gagal ("+r.status+")");}
   smSync();return;}
  smClose();loadAgent(smBot);
 }catch(e){if(msg){msg.className="smmsg err";msg.textContent=e.message;}smSync();}
}
(function(){
 ["ag-save2"].forEach(id=>{const b=el(id);if(b)b.onclick=agSave;});
 const rs=el("ag-reset");if(rs)rs.onclick=()=>{if(agentBot)loadAgent(agentBot);};
 const cn=el("ag-cancel");if(cn)cn.onclick=()=>{agSetDirty(false);if(agentBot)loadAgent(agentBot);};
  const ch=el("ag-chat");if(ch)ch.onclick=()=>{const b=agentBot||anyAgent();if(!b)return;
  if(b==="default"){setPanel("bot");return;}setPanel("bot");openThread("bot:"+b);};
 const fl=el("ag-files");if(fl)fl.onclick=()=>setPanel("files");
 const sf=el("ag-skillfind");if(sf)sf.addEventListener("input",()=>renderSkillList(sf.value));
 const as=el("ag-addskill");if(as)as.onclick=smOpen;
 ["sm-name","sm-desc","sm-body"].forEach(id=>{const n=el(id);if(!n)return;
  n.addEventListener("input",()=>{smSync();
   const msg=el("sm-msg");if(msg&&msg.classList.contains("err")){msg.className="smmsg";msg.textContent="";}});});
 const sv=el("sm-save");if(sv)sv.onclick=smSave;
 const sx=el("sm-x");if(sx)sx.onclick=smClose;
 const sc=el("sm-cancel");if(sc)sc.onclick=smClose;
 const smm=el("skillmodal");
 if(smm){smm.addEventListener("click",e=>{if(e.target.closest("[data-sclose]"))smClose();});}
 document.addEventListener("keydown",e=>{const m=el("skillmodal");
  if(e.key==="Escape"&&m&&!m.hidden)smClose();});
})();

/* ---------- files ---------- */
function ficon(dir,name){
 if(dir)return "folder_open";
 const n=String(name||"").toLowerCase();const e=n.split(".").pop();
 if(["py","js","ts","html","css","sh","rs","go"].indexOf(e)>=0)return "code";
 if(["md","txt"].indexOf(e)>=0)return "article";
 if(["json","yaml","yml","toml","ini","conf"].indexOf(e)>=0)return "data_object";
 if(e==="log")return "receipt_long";
 if(["png","jpg","jpeg","svg","gif","webp"].indexOf(e)>=0)return "image";
 if(["zip","gz","tar"].indexOf(e)>=0)return "folder_zip";
 return "draft";}
function joinRel(a,b){return a?a.replace(/\/+$/,"")+"/"+b:b;}
async function loadFiles(path,root){
 curRoot=root||curRoot||"workspace";
 curDir=typeof path==="string"?path:(curDir||"");
 try{
  const r=await fetch("/api/files?root="+encodeURIComponent(curRoot)+"&path="+encodeURIComponent(curDir),{cache:"no-store"});
  if(r.status===401){location.href="/login";return;}
  const d=await r.json();
  if(!r.ok){renderFilesError(d.error||"gagal memuat");return;}
  fileCache=d;curDir=d.path||"";renderFiles();
 }catch(e){renderFilesError(e.message);}
}
function renderFilesError(msg){
 const list=el("flist");list.replaceChildren();list.appendChild(mk("div","fempty",msg));
 el("fcount").textContent="0 entri";
}
function renderFiles(){
 document.querySelectorAll("#froots .tab").forEach(b=>b.classList.toggle("on",b.dataset.root===curRoot));
 const cb=el("fcrumbs");cb.replaceChildren();
 const crumbs=fileCache.breadcrumb||[];
 if(!crumbs.length){cb.appendChild(mk("b",null,curRoot));}
 crumbs.forEach((c,i)=>{
  if(i)cb.appendChild(mk("span","fsep","/"));
  if(i===crumbs.length-1&&crumbs.length>1)cb.appendChild(mk("b",null,c.label));
  else{const b=mk("button",null,c.label);b.type="button";b.onclick=()=>openDir(c.path);cb.appendChild(b);}
 });
 const list=el("flist");list.replaceChildren();
 const q=(fileFilter||"").toLowerCase();
 const rows=(fileCache.entries||[]).filter(e=>!q||e.name.toLowerCase().indexOf(q)>=0);
 if(!rows.length)list.appendChild(mk("div","fempty",q?"tidak ada yang cocok":"folder kosong"));
 rows.forEach(e=>{
  const dir=e.type==="dir";
  const row=mk("div","frow"+(dir?" dir":"")+((!dir&&curFile===e.name)?" on":""));
  const ic=mk("span","msi",ficon(dir,e.name));ic.setAttribute("aria-hidden","true");
  row.appendChild(ic);
  row.appendChild(mk("span","fname",e.name));
  row.appendChild(mk("span","fsize",dir?"":humanSize(e.size)));
  row.appendChild(mk("span","fwhen",relEpoch(e.mtime)));
  row.title=e.name;
  row.onclick=()=>{if(dir)openDir(joinRel(curDir,e.name));else openFile(e.name);};
  list.appendChild(row);});
 el("fcount").textContent=rows.length+" entri";
}
function openDir(path){
 curDir=path||"";curFile=null;
 if(curPanel==="files")history.replaceState(null,"",panelHash("files"));
 clearPreview();loadFiles(curDir,curRoot);
}
async function openFile(name){
 curFile=name;renderFiles();
 const rel=joinRel(curDir,name),body=el("fbody");
 body.innerHTML='<div class="fempty">memuat…</div>';
 try{
  const r=await fetch("/api/file?root="+encodeURIComponent(curRoot)+"&path="+encodeURIComponent(rel),{cache:"no-store"});
  if(r.status===401){location.href="/login";return;}
  const d=await r.json();
  if(!r.ok){body.replaceChildren();body.appendChild(mk("div","fempty",d.error||"gagal memuat"));el("fstbar").textContent="";return;}
  renderFilePreview(d,rel);
 }catch(e){body.replaceChildren();body.appendChild(mk("div","fempty",e.message));}
}
function renderFilePreview(d,rel){
 const body=el("fbody");
 body.replaceChildren();
 const dl="/api/file?root="+encodeURIComponent(curRoot)+"&path="+encodeURIComponent(rel)+"&download=1";
 const bar=mk("div","fbar");
 const ic=mk("span","msi",ficon(false,d.name));ic.setAttribute("aria-hidden","true");
 bar.appendChild(ic);
 bar.appendChild(mk("span","fname",d.name));
 bar.appendChild(mk("span","fspacer"));
 const a=mk("a","mbtn","Unduh");a.href=dl;bar.appendChild(a);
 const cp=mk("button","mbtn","Salin path");cp.type="button";bar.appendChild(cp);
 const code=mk("pre","fcode");
 if(d.binary)code.appendChild(mk("div","fempty","Pratinjau tidak tersedia untuk file biner"));
 else if(d.truncated)code.appendChild(mk("div","fempty","File lebih dari 512 KB — pratinjau dimatikan."));
 else{
  const lines=String(d.content||"").replace(/\n$/,"").split("\n");
  const LIM=3000,n=Math.min(lines.length,LIM);
  for(let i=0;i<n;i++){
   const row=mk("div","lnrow");
   row.appendChild(mk("span","ln",i+1));
   row.appendChild(mk("span","lntx",lines[i]));
   code.appendChild(row);}
  if(lines.length>LIM){const row=mk("div","lnrow");
   row.appendChild(mk("span","ln",""));
   row.appendChild(mk("span","lntx","… ("+(lines.length-LIM)+" baris lagi — unduh untuk melihat semuanya)"));
   code.appendChild(row);}
 }
 body.appendChild(bar);body.appendChild(code);
 const st=el("fstbar");st.replaceChildren();
 const add=(k,v,cls)=>{st.appendChild(mk("span",null,k+": "));const b=mk("b",cls||"",v);st.appendChild(b);};
 add("ENCODING",d.binary?"BINARY":"UTF-8");
 add("BARIS",d.lines==null?"—":String(d.lines));
 add("SIZE",humanSize(d.size));
 add("DIUBAH",relEpoch(d.mtime));
 cp.onclick=()=>copyPath(HQDIR+"/"+curRoot+"/"+rel,cp);
}
function copyPath(txt,btn){
 const done=()=>{if(btn){btn.textContent="Tersalin";setTimeout(()=>{btn.textContent="Salin path";},1500);}};
 if(navigator.clipboard&&navigator.clipboard.writeText)
  navigator.clipboard.writeText(txt).then(done,()=>fallbackCopy(txt,done));
 else fallbackCopy(txt,done);}
function clearPreview(){
 el("fbody").innerHTML='<div class="fempty">Pilih file di kolom kiri untuk melihat pratinjau</div>';
 el("fstbar").textContent="";}

/* ---------- toolbar wiring ---------- */
document.querySelectorAll(".navitem").forEach(b=>b.onclick=()=>setPanel(b.dataset.panel));
document.querySelectorAll("#froots .tab").forEach(b=>b.onclick=()=>{curRoot=b.dataset.root;openDir("");});
el("ffilter").oninput=e=>{fileFilter=e.target.value.trim();renderFiles();};
el("refresh").onclick=()=>load();
el("bell").onclick=()=>load();
el("fdiv-btn").onclick=()=>{
 divFilter=DIVS[(DIVS.indexOf(divFilter)+1)%DIVS.length];
 el("fdiv-label").textContent=DIVLABEL[divFilter]||"Semua divisi";
 if(lastState)board(lastState.tasks||[]);};
el("q").addEventListener("input",e=>{query=e.target.value.trim();
 if(lastState)board(lastState.tasks||[]);});
document.addEventListener("keydown",e=>{
 if((e.metaKey||e.ctrlKey)&&String(e.key).toLowerCase()==="k"){e.preventDefault();
  if(curPanel!=="board")setPanel("board");el("q").focus();el("q").select();}
});
el("cmsg").addEventListener("input",()=>{const t=el("cmsg");t.style.height="auto";
 t.style.height=Math.min(110,t.scrollHeight)+"px";syncSend();});
window.addEventListener("hashchange",route);
route();
load();setInterval(load,15000);
setInterval(tickClock,1000);
loadBots().then(()=>openThread(savedThread()));
setInterval(loadBots,15000);
setInterval(()=>{
 if(curPanel!=="bot"||!thread)return;
 const s=el("chatlog");if(!s)return;
 const near=s.scrollTop+s.clientHeight>=s.scrollHeight-40;
 loadThread().then(()=>{const v=el("chatlog");if(near&&v)toBottom(v);});
},15000);
</script></body></html>"""

def page_login(err=""):
    return _tpl(LOGIN, __ERR__=f'<div class="err">{html.escape(err)}</div>' if err else "")

def page_index():
    return _tpl(PAGE, __ROOMS__=json.dumps({rid: {"name": c["name"], "members": room_members(rid),
                                                  "rounds": c.get("rounds", 1)}
                                             for rid, c in rooms().items()}),
                __CSRF__=json.dumps(csrf_token(getattr(_REQ, "session", ""))))

# ---------- http ----------

class H(BaseHTTPRequestHandler):
    server_version = "ops-board"

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=(), cache=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(data)))
        if not any(str(k).lower() == "cache-control" for k, _ in extra):
            self.send_header("cache-control", cache if cache is not None else "no-store")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("x-frame-options", "DENY")
        self.send_header("referrer-policy", "no-referrer")
        self.send_header("content-security-policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                         "font-src 'self' https://fonts.gstatic.com; "
                         "img-src 'self' data:; "
                         "connect-src 'self'")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _redirect(self, to, cookie=None):
        extra = [("location", to)]
        if cookie:
            extra.append(("set-cookie", cookie))
        self._send(302, b"", "text/plain", extra, cache="no-store")

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (time.strftime("%H:%M:%S"), fmt % a))

    def do_GET(self):
        self._req()
        try:
            self._get()
        except Exception as exc:
            self._fail(exc)

    def do_POST(self):
        self._req()
        try:
            self._post()
        except Exception as exc:
            self._fail(exc)

    def _req(self):
        """Remember Host, scheme and session for this request thread."""
        _REQ.domain = (self.headers.get("Host") or "").strip()
        _REQ.https = ((self.headers.get("X-Forwarded-Proto") or "").split(",")[0]
                      .strip().lower() == "https")
        _REQ.session = session_value(self.headers)

    def _fail(self, exc):
        """Never leak a traceback to the client."""
        sys.stderr.write(f"ops-board: {type(exc).__name__}: {exc}\n")
        try:
            self._send(500, json.dumps({"error": "kesalahan internal"}))
        except Exception:
            pass

    def do_HEAD(self):
        """Same status and headers as GET, body suppressed by _send."""
        self.do_GET()

    def _get(self):
        path = self.path.split("?")[0]
        if not rate_ok(self.client_address[0], "req", REQ_LIMIT, REQ_WINDOW):
            return self._send(429, json.dumps({"error": "terlalu banyak permintaan"}))
        if "%2e" in self.path.lower():
            return self._send(403, json.dumps({"error": "path tidak valid"}))
        if path == "/login":
            return self._send(200, page_login(), "text/html; charset=utf-8")
        if path == "/logout":
            return self._redirect("/login", cookie_header("", 0))
        if path.startswith("/brand/"):
            name = path[len("/brand/"):]
            if name not in BRAND_FILES:
                return self._send(404, "not found", "text/plain; charset=utf-8")
            try:
                with open(os.path.join(BRAND_DIR, name), "rb") as fh:
                    blob = fh.read()
            except OSError:
                return self._send(404, "not found", "text/plain; charset=utf-8")
            return self._send(200, blob, "image/png", cache="public, max-age=86400")
        if not cookie_ok(self.headers):
            if path.startswith("/api/"):
                return self._send(401, json.dumps({"error": "belum login"}))
            return self._redirect("/login")
        if path == "/api/agents":
            return self._send(200, json.dumps({"agents": roster()}))
        if path.startswith("/api/agent/"):
            bot = path[len("/api/agent/"):].strip("/")
            if not BOT_RE.fullmatch(bot) or bot not in agent_ids():
                return self._send(404, json.dumps({"error": "bot tidak dikenal"}))
            return self._send(200, json.dumps(agent_info(bot)))
        if path == "/api/tasks":
            return self._send(200, json.dumps({"tasks": load_tasks()}))
        if path == "/api/state":
            return self._send(200, json.dumps(state_get()))
        if path == "/api/bots":
            return self._send(200, json.dumps({"bots": bots_overview()}))
        if path == "/api/room":
            q = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            rid = (q.get("room") or [""])[0] or next(iter(rooms()))
            if rid not in rooms():
                return self._send(404, json.dumps({"error": "room tidak dikenal"}))
            room_rows = []
            for r, c in rooms().items():
                rows = room_log(r)
                room_rows.append({"id": r, "name": c["name"], "members": room_members(r),
                                  "count": len(rows),
                                  "last": (rows[-1].get("text") or "")[:120] if rows else ""})
            return self._send(200, json.dumps({"room": rid, "rooms": room_rows, "log": room_log(rid)}))
        if path == "/api/files":
            q = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            root = (q.get("root") or ["workspace"])[0] or "workspace"
            rel = (q.get("path") or [""])[0]
            data, code, msg = file_entries(root, rel)
            if data is None:
                return self._send(code, json.dumps({"error": msg}))
            return self._send(200, json.dumps(data))
        if path == "/api/file":
            q = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            root = (q.get("root") or ["workspace"])[0] or "workspace"
            rel = (q.get("path") or [""])[0]
            if (q.get("download") or ["0"])[0].lower() in ("1", "true", "yes"):
                fpath, code, msg = _file_path(root, rel)
                if not fpath:
                    return self._send(code, json.dumps({"error": msg}))
                if os.path.isdir(fpath):
                    return self._send(400, json.dumps({"error": "bukan file"}))
                try:
                    with open(fpath, "rb") as fh:
                        blob = fh.read()
                except OSError:
                    return self._send(404, json.dumps({"error": "tidak ditemukan"}))
                fname = os.path.basename(fpath).replace('"', "")
                return self._send(200, blob, "application/octet-stream",
                                  [("content-disposition", f'attachment; filename="{fname}"')])
            data, code, msg = file_read(root, rel)
            if data is None:
                return self._send(code, json.dumps({"error": msg}))
            return self._send(200, json.dumps(data))
        if path.startswith("/api/bots/"):
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[3] == "messages":
                bot = parts[2]
                if bot not in agent_ids():
                    return self._send(404, json.dumps({"error": "bot tidak dikenal"}))
                q = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
                try:
                    limit = int((q.get("limit") or ["50"])[0])
                except (TypeError, ValueError):
                    limit = 50
                limit = max(1, min(limit, 200))
                msgs, sess = bot_messages(bot, limit)
                return self._send(200, json.dumps({"bot": bot, "session": sess, "messages": msgs}))
            return self._send(404, json.dumps({"error": "not found"}))
        if path in ("/", "/index.html"):
            return self._send(200, page_index(), "text/html; charset=utf-8")
        self._send(404, "not found", "text/plain; charset=utf-8")

    def _agent_post(self, path, raw):
        ctype = (self.headers.get("content-type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return self._send(415, json.dumps({"error": "butuh application/json"}))
        origin = self.headers.get("Origin")
        if origin:
            try:
                netloc = urllib.parse.urlsplit(origin).netloc
            except ValueError:
                netloc = ""
            if netloc.lower() != (self.headers.get("Host") or "").lower():
                return self._send(403, json.dumps({"error": "origin tidak diizinkan"}))
        parts = path.strip("/").split("/")
        job_id = None
        kind = "self"
        if len(parts) == 3 and parts[:2] == ["api", "agent"]:
            bot = parts[2]
        elif len(parts) == 4 and parts[:2] == ["api", "agent"] and parts[3] == "skill":
            bot = parts[2]
            kind = "skill"
        elif len(parts) == 5 and parts[:2] == ["api", "agent"] and parts[3] == "routine":
            bot, job_id = parts[2], parts[4]
            kind = "routine"
        else:
            return self._send(404, json.dumps({"error": "not found"}))
        if not BOT_RE.fullmatch(bot) or bot not in agent_ids():
            return self._send(404, json.dumps({"error": "bot tidak dikenal"}))
        if job_id is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", job_id):
            return self._send(404, json.dumps({"error": "job tidak dikenal"}))
        try:
            body = json.loads(raw or b"{}")
        except Exception:
            return self._send(400, json.dumps({"error": "body rusak"}))
        if not isinstance(body, dict):
            return self._send(400, json.dumps({"error": "body harus objek"}))
        if kind == "skill":
            code, payload = skill_create(bot, body)
        elif kind == "routine":
            code, payload = routine_update(bot, job_id, body)
        else:
            code, payload = agent_update(bot, body)
        return self._send(code, json.dumps(payload))

    def _post(self):

        path = self.path.split("?")[0]
        ip = self.client_address[0]
        if path != "/login" and not rate_ok(ip, "req", REQ_LIMIT, REQ_WINDOW):
            return self._send(429, json.dumps({"error": "terlalu banyak permintaan"}))
        try:
            n = int(self.headers.get("content-length", 0))
        except (TypeError, ValueError):
            return self._send(400, json.dumps({"error": "body rusak"}))
        if n > MAX_BODY:
            return self._send(413, json.dumps({"error": "body terlalu besar"}))
        try:
            raw = self.rfile.read(n) if n else b""
        except Exception:
            return self._send(400, json.dumps({"error": "body rusak"}))

        if path == "/login":
            if not rate_ok(ip, "login", LOGIN_ATTEMPTS, LOGIN_WINDOW):
                return self._send(429, page_login("Terlalu banyak percobaan. Coba lagi nanti."),
                                  "text/html; charset=utf-8")
            form = {}
            for part in raw.decode("utf-8", "replace").split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    form[k] = urllib.request.unquote(v.replace("+", " ")).strip()
            if check_creds(form.get("user", ""), form.get("password", "")):
                return self._redirect("/", cookie_header(issue_session(), SESSION_TTL))
            time.sleep(0.4)
            return self._send(401, page_login("User atau password salah."),
                              "text/html; charset=utf-8")

        if not cookie_ok(self.headers):
            return self._send(401, json.dumps({"error": "belum login"}))
        if not csrf_ok(self.headers, _REQ.session):
            return self._send(403, json.dumps({"error": "csrf token tidak valid"}))
        if path.startswith("/api/agent/"):
            return self._agent_post(path, raw)
        if path.startswith("/api/bots/"):
            parts = path.strip("/").split("/")
            if len(parts) != 4 or parts[3] != "chat":
                return self._send(404, json.dumps({"error": "not found"}))
            bot = parts[2]
            if bot not in agent_ids():
                return self._send(404, json.dumps({"error": "bot tidak dikenal"}))
            try:
                body = json.loads(raw or b"{}")
            except Exception as exc:
                return self._send(400, json.dumps({"error": f"body: {exc}"}))
            text = (body.get("text") or "").strip()
            if not text:
                return self._send(400, json.dumps({"error": "text kosong"}))
            if not (agent_cfg(bot) or {}).get("chat"):
                return self._send(400, json.dumps({"error": f"bot {OWNER_LABEL} tidak menerima chat"}))
            res = bot_send(bot, text)
            return self._send(200 if res.get("ok") else 409, json.dumps(res))
        if path != "/api/room":
            return self._send(404, json.dumps({"error": "not found"}))
        try:
            body = json.loads(raw or b"{}")
        except Exception as exc:
            return self._send(400, json.dumps({"error": f"body: {exc}"}))
        text = (body.get("text") or "").strip()
        if not text:
            return self._send(400, json.dumps({"error": "text kosong"}))
        if path == "/api/room":
            return self._send(200, json.dumps(room_turn(body.get("room") or "", text)))


def _selftest():
    try:
        expected = sum(1 for p in (AGENT_HOME / "profiles").iterdir()
                       if p.is_dir() and (p / "config.yaml").is_file()) + 1
    except OSError:
        expected = 1
    ags = agents()
    assert len(ags) == expected, f"agen {len(ags)} != {expected}"
    ids = agent_ids()
    assert len(set(ids)) == len(ids), "slug duplikat"
    for b in ids:
        assert BOT_RE.fullmatch(b), f"slug tidak valid: {b}"
    for a in ags:
        assert a["name"], f"nama kosong: {a['bot']}"
        assert 1 <= len(a["initials"]) <= 2, f"inisial aneh: {a['bot']}"
        assert a["color"].startswith("#"), f"warna aneh: {a['bot']}"
    rms = rooms()
    assert len(rms) == len(ROOM_BASE), f"room {len(rms)} != {len(ROOM_BASE)}"
    for rid, _ in ROOM_BASE:
        assert rid in rms, f"room hilang: {rid}"
    assert ROOM_BASE, "room_base kosong di config"
    assert all(isinstance(s, str) and s for s, _ in DIVISIONS) or not DIVISIONS
    idset = set(ids)
    for rid, c in rms.items():
        for m in c["members"]:
            assert m in idset, f"member {m} tidak ada di {rid}"
    assert os.path.isdir(HQ), f"hq tidak ada: {HQ}"
    assert DIVISIONS, "divisi kosong"
    assert ROOM_BASE, "room kosong"
    assert MODELS, "model kosong"
    assert all(len(s) == 3 for s in SERVICES), "bentuk services bukan [label, host, target]"
    print(f"selftest OK: {len(ags)} agen, {len(rms)} room, {len(SERVICES)} service, "
          f"{len(SYS_UNITS) + len(USER_UNITS)} unit, hq={HQ}")

if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
        sys.exit(0)
    argv = [a for a in sys.argv[1:]]
    port = int(CFG["listen_port"])
    if "--port" in argv and argv.index("--port") + 1 < len(argv):
        port = int(argv[argv.index("--port") + 1])
    elif argv and argv[0].isdigit():
        port = int(argv[0])
    print(f"{APP} di {CFG['listen_host']}:{port}", flush=True)
    print(f"deteksi: hq={HQ} divisi={len(DIVISIONS)} service={len(SERVICES)} "
          f"unit={len(SYS_UNITS) + len(USER_UNITS)} hermes={HERMES or '-'}", flush=True)
    threading.Thread(target=_state_warm, name="state-warm", daemon=True).start()
    ThreadingHTTPServer((str(CFG["listen_host"]), port), H).serve_forever()
