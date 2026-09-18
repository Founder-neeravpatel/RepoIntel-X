#!/usr/bin/env python3
"""
RepoIntel-X — Single-file GitHub Repository & IoT Security Intelligence Platform
Version 1.1

One file. No project directory required.

Features:
- Automatic public GitHub repository discovery
- IoT / firmware / security classification
- Repository metadata and file-tree analysis
- Dependency manifest discovery and parsing
- Public CVE/advisory reference correlation
- Repository DNA fingerprint
- SQLite persistent database
- Evidence records
- JSON reports
- Continuous monitoring mode
- Simple local web dashboard (stdlib HTTP server)
- No Node.js / npm / Docker required

Usage:
  python3 RepoIntel-X.py
  python3 RepoIntel-X.py --query "iot firmware" --limit 20
  python3 RepoIntel-X.py --web
  python3 RepoIntel-X.py --monitor

Optional:
  Set GITHUB_TOKEN environment variable for authenticated GitHub API access. Use --rate-limit to inspect remaining quota.
"""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

APP = "RepoIntel-X"
VERSION = "1.1"
DB = os.getenv("REPOINTEL_DB", "repointel_x.db")
TOKEN = os.getenv("GITHUB_TOKEN", "")
DELAY = float(os.getenv("REPOINTEL_DELAY", "1.0"))
DEFAULT_LIMIT = int(os.getenv("REPOINTEL_LIMIT", "20"))

DISCOVERY_QUERIES = [
    "iot firmware",
    "embedded security",
    "esp32 security",
    "esp8266 security",
    "mqtt security",
    "firmware security",
    "uav firmware",
    "drone security",
    "mavlink security",
    "freertos security",
    "zephyr security",
    "openwrt security",
    "industrial iot security",
]

IOT_TOKENS = {
    "iot", "embedded", "esp32", "esp8266", "arduino", "raspberry pi",
    "mqtt", "coap", "zigbee", "lorawan", "modbus", "firmware",
    "freertos", "zephyr", "openwrt", "mavlink", "uav", "drone",
    "home automation", "gateway", "sensor", "rtos",
}
SECURITY_TOKENS = {
    "security", "cybersecurity", "vulnerability", "cve", "firmware",
    "pentest", "reverse engineering", "exploit", "infosec",
    "security research", "hardening",
}
FIRMWARE_EXT = {".bin", ".hex", ".img", ".elf", ".uf2", ".rom", ".fw"}
SECURITY_FILES = {
    "security.md", "security.txt", "codeowners",
    ".github/dependabot.yml", ".github/dependabot.yaml",
    "sbom.json", "sbom.xml",
}
MANIFESTS = {
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "poetry.lock": "python",
    "package.json": "javascript",
    "package-lock.json": "javascript",
    "go.mod": "go",
    "go.sum": "go",
    "cargo.toml": "rust",
    "cargo.lock": "rust",
    "pom.xml": "java",
    "build.gradle": "java",
    "gemfile": "ruby",
    "composer.json": "php",
    "platformio.ini": "embedded",
    "west.yml": "zephyr",
    "CMakeLists.txt": "cmake",
    "Makefile": "make",
}

def now():
    return datetime.now(timezone.utc).isoformat()

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.executescript("""
    CREATE TABLE IF NOT EXISTS repositories (
      id INTEGER PRIMARY KEY,
      full_name TEXT UNIQUE NOT NULL,
      html_url TEXT,
      description TEXT,
      stars INTEGER,
      forks INTEGER,
      language TEXT,
      default_branch TEXT,
      topics TEXT,
      first_seen TEXT,
      last_seen TEXT,
      iot_score INTEGER,
      security_score INTEGER,
      firmware_score INTEGER,
      dna TEXT
    );
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY,
      repo_id INTEGER,
      path TEXT,
      sha TEXT,
      size INTEGER,
      type TEXT,
      UNIQUE(repo_id,path)
    );
    CREATE TABLE IF NOT EXISTS dependencies (
      id INTEGER PRIMARY KEY,
      repo_id INTEGER,
      ecosystem TEXT,
      manifest TEXT,
      package TEXT,
      version TEXT,
      UNIQUE(repo_id,ecosystem,manifest,package,version)
    );
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id INTEGER PRIMARY KEY,
      repo_id INTEGER,
      cve TEXT,
      source TEXT,
      evidence TEXT,
      UNIQUE(repo_id,cve,source)
    );
    CREATE TABLE IF NOT EXISTS evidence (
      id INTEGER PRIMARY KEY,
      repo_id INTEGER,
      kind TEXT,
      source TEXT,
      detail TEXT,
      collected_at TEXT
    );
    """)
    return c

def api(path, params=None):
    """GitHub API request with explicit rate-limit diagnostics.

    GitHub allows only a small number of unauthenticated REST requests per hour.
    When a 403/429 rate-limit response is received, this function reports the
    remaining quota and reset time instead of producing an opaque traceback.
    """
    url = "https://api.github.com" + path
    if params:
        url += "?" + urllib.parse.urlencode(params)

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"{APP}/{VERSION}",
        "X-GitHub-Api-Version": "2026-03-10",
    }
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"

    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode("utf-8")
            data = json.loads(raw)
            remaining = r.headers.get("X-RateLimit-Remaining")
            reset = r.headers.get("X-RateLimit-Reset")
            if remaining is not None:
                print(f"[GITHUB] API remaining: {remaining}")
        time.sleep(DELAY)
        return data

    except urllib.error.HTTPError as e:
        remaining = e.headers.get("X-RateLimit-Remaining")
        reset = e.headers.get("X-RateLimit-Reset")
        retry_after = e.headers.get("Retry-After")

        try:
            body = e.read().decode("utf-8", errors="replace")
            payload = json.loads(body)
            message = payload.get("message", str(e))
        except Exception:
            message = str(e)

        if e.code in (403, 429):
            if remaining == "0" and reset:
                try:
                    reset_dt = datetime.datetime.fromtimestamp(
                        int(reset), tz=datetime.timezone.utc
                    )
                    now = datetime.datetime.now(datetime.timezone.utc)
                    wait_seconds = max(0, int((reset_dt - now).total_seconds()))
                    reset_text = reset_dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
                except Exception:
                    wait_seconds = 0
                    reset_text = "unknown"
                raise RuntimeError(
                    "\n"
                    "[GITHUB RATE LIMIT] GitHub rejected the request.\n"
                    f"  Endpoint: {path}\n"
                    f"  Message: {message}\n"
                    f"  Remaining: {remaining}\n"
                    f"  Reset: {reset_text}\n"
                    f"  Approx. wait: {wait_seconds}s\n\n"
                    "Fix: authenticate RepoIntel-X with a GitHub token.\n"
                    "Example:\n"
                    "  export GITHUB_TOKEN='YOUR_TOKEN'\n"
                    "  python3 RepoIntel-X.py --limit 5\n"
                )
            if retry_after:
                raise RuntimeError(
                    f"[GITHUB RATE LIMIT] Retry after {retry_after}s. Message: {message}"
                )

        raise RuntimeError(f"GitHub HTTP {e.code}: {message}")

    except urllib.error.URLError as e:
        raise RuntimeError(f"GitHub network error: {e.reason}")

    except Exception as e:
        raise RuntimeError(f"GitHub request failed: {e}")

def show_rate_limit():
    data = api("/rate_limit")
    resources = data.get("resources", {})
    print("\n=== GitHub API Rate Limit ===")
    for name in ("core", "search", "code_search"):
        item = resources.get(name, {})
        if item:
            reset = item.get("reset")
            if reset:
                try:
                    reset_text = datetime.datetime.fromtimestamp(
                        int(reset), tz=datetime.timezone.utc
                    ).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
                except Exception:
                    reset_text = str(reset)
            else:
                reset_text = "unknown"
            print(
                f"{name:12} limit={item.get('limit')} "
                f"used={item.get('used')} "
                f"remaining={item.get('remaining')} "
                f"reset={reset_text}"
            )
    print()

def search_repositories(query, limit):
    data = api("/search/repositories", {"q": query, "per_page": min(limit, 100), "page": 1})
    return data.get("items", [])

def get_repo(full_name):
    return api("/repos/" + full_name)

def get_tree(full_name, branch):
    return api(f"/repos/{full_name}/git/trees/{urllib.parse.quote(branch, safe='')}", {"recursive": "1"})

def get_raw(full_name, branch, path):
    url = f"https://raw.githubusercontent.com/{full_name}/{urllib.parse.quote(branch, safe='')}/{urllib.parse.quote(path)}"
    req = urllib.request.Request(url, headers={"User-Agent": f"{APP}/{VERSION}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return ""

def tokens_found(text, tokens):
    text = (text or "").lower()
    return sorted(t for t in tokens if t in text)

def score(repo, paths):
    text = " ".join([
        repo.get("name", ""),
        repo.get("description") or "",
        " ".join(repo.get("topics") or []),
    ]).lower()
    iot = tokens_found(text, IOT_TOKENS)
    sec = tokens_found(text, SECURITY_TOKENS)
    fw = [p for p in paths if os.path.splitext(p.lower())[1] in FIRMWARE_EXT]
    return min(100, len(iot) * 12), min(100, len(sec) * 12), min(100, len(fw) * 25), iot, sec, fw

def dna(repo, paths, deps, signals):
    payload = {
        "languages": [repo.get("language")] if repo.get("language") else [],
        "topics": sorted(repo.get("topics") or []),
        "extensions": sorted(set(os.path.splitext(p.lower())[1] for p in paths if "." in os.path.basename(p))),
        "manifests": sorted(set(d["manifest"] for d in deps)),
        "ecosystems": sorted(set(d["ecosystem"] for d in deps)),
        "signals": sorted(signals),
        "file_count": len(paths),
    }
    raw = json.dumps(payload, sort_keys=True)
    payload["fingerprint"] = hashlib.sha256(raw.encode()).hexdigest()[:24]
    return payload

def parse_dependencies(repo, tree_items):
    found = []
    names = {x.get("path", "").lower(): x.get("path") for x in tree_items}
    for lower, ecosystem in MANIFESTS.items():
        if lower in names:
            manifest = names[lower]
            content = get_raw(repo["full_name"], repo.get("default_branch", "main"), manifest)
            # Safe metadata extraction: package names/versions only.
            if ecosystem == "python":
                for line in content.splitlines():
                    m = re.match(r"\s*([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|>|<)\s*([A-Za-z0-9.*+_-]+)", line)
                    if m:
                        found.append({"ecosystem": ecosystem, "manifest": manifest, "package": m.group(1), "version": m.group(2)})
            elif ecosystem == "javascript":
                try:
                    obj = json.loads(content)
                    for section in ("dependencies", "devDependencies", "optionalDependencies"):
                        for pkg, ver in (obj.get(section) or {}).items():
                            found.append({"ecosystem": ecosystem, "manifest": manifest, "package": pkg, "version": str(ver)})
                except Exception:
                    pass
            elif ecosystem == "go":
                for line in content.splitlines():
                    m = re.match(r"\s*([A-Za-z0-9_.\-/]+)\s+v([0-9][^\s]+)", line)
                    if m:
                        found.append({"ecosystem": ecosystem, "manifest": manifest, "package": m.group(1), "version": "v"+m.group(2)})
            elif ecosystem == "rust":
                for line in content.splitlines():
                    m = re.match(r"\s*([A-Za-z0-9_-]+)\s*=\s*['\"]?([0-9][^'\"\s]+)", line)
                    if m:
                        found.append({"ecosystem": ecosystem, "manifest": manifest, "package": m.group(1), "version": m.group(2)})
    return found[:2000]

def cve_extract(repo, tree_items):
    results = []
    # Correlate explicit CVE references found in repository metadata/files.
    candidate_text = " ".join([
        repo.get("name", ""),
        repo.get("description") or "",
        " ".join(repo.get("topics") or []),
    ])
    for item in tree_items[:3000]:
        candidate_text += " " + item.get("path", "")
    for cve in sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", candidate_text, re.I))):
        results.append((cve.upper(), "github-metadata/tree", "Explicit CVE reference"))
    return results

def analyze(repo):
    c = db()
    ridata = c.execute("SELECT id FROM repositories WHERE full_name=?", (repo["full_name"],)).fetchone()
    if ridata:
        rid = ridata["id"]
    else:
        cur = c.execute(
            """INSERT INTO repositories
            (full_name,html_url,description,stars,forks,language,default_branch,topics,first_seen,last_seen)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (repo["full_name"], repo.get("html_url"), repo.get("description"),
             repo.get("stargazers_count"), repo.get("forks_count"), repo.get("language"),
             repo.get("default_branch"), json.dumps(repo.get("topics") or []), now(), now())
        )
        rid = cur.lastrowid

    tree = get_tree(repo["full_name"], repo.get("default_branch", "main"))
    items = tree.get("tree", [])
    paths = [x.get("path", "") for x in items if x.get("type") == "blob"]

    iot, sec, fw, iot_sig, sec_sig, fw_files = score(repo, paths)
    deps = parse_dependencies(repo, items)
    signals = iot_sig + sec_sig
    if fw_files:
        signals.append("firmware-artifacts")
    security_files = [p for p in paths if p.lower() in SECURITY_FILES]
    if security_files:
        signals.append("security-files")

    d = dna(repo, paths, deps, signals)

    c.execute("""UPDATE repositories SET last_seen=?,iot_score=?,security_score=?,firmware_score=?,dna=?
                 WHERE id=?""", (now(), iot, sec, fw, json.dumps(d), rid))

    for x in items:
        p = x.get("path", "")
        c.execute("""INSERT OR IGNORE INTO files(repo_id,path,sha,size,type)
                     VALUES(?,?,?,?,?)""", (rid,p,x.get("sha"),x.get("size"),x.get("type")))

    for dep in deps:
        c.execute("""INSERT OR IGNORE INTO dependencies(repo_id,ecosystem,manifest,package,version)
                     VALUES(?,?,?,?,?)""", (rid,dep["ecosystem"],dep["manifest"],dep["package"],dep["version"]))

    for cve, source, evidence in cve_extract(repo, items):
        c.execute("""INSERT OR IGNORE INTO vulnerabilities(repo_id,cve,source,evidence)
                     VALUES(?,?,?,?)""", (rid,cve,source,evidence))

    evidence = [
        ("repository", repo.get("html_url",""), repo["full_name"]),
        ("classification", "RepoIntel-X", json.dumps({"iot":iot,"security":sec,"firmware":fw})),
        ("repository-dna", "RepoIntel-X", d["fingerprint"]),
    ]
    for kind, source, detail in evidence:
        c.execute("""INSERT INTO evidence(repo_id,kind,source,detail,collected_at)
                     VALUES(?,?,?,?,?)""", (rid,kind,source,detail,now()))
    c.commit()
    c.close()

    return {
        "repository": repo["full_name"],
        "url": repo.get("html_url"),
        "iot_score": iot,
        "security_score": sec,
        "firmware_score": fw,
        "iot_signals": iot_sig,
        "security_signals": sec_sig,
        "firmware_files": fw_files[:50],
        "security_files": security_files,
        "dependencies": deps[:100],
        "cves": [{"cve": a, "source": b, "evidence": d} for a,b,d in cve_extract(repo,items)],
        "repository_dna": d,
    }

def discover(queries, limit):
    seen = {}
    for q in queries:
        print(f"[DISCOVER] {q}")
        for r in search_repositories(q, limit):
            seen[r["full_name"]] = r
    print(f"[DISCOVER] unique repositories: {len(seen)}")
    return list(seen.values())

def run(queries, limit, report_path):
    results = []
    for repo in discover(queries, limit):
        try:
            print(f"[ANALYZE] {repo['full_name']}")
            results.append(analyze(repo))
        except Exception as e:
            print(f"[SKIP] {repo['full_name']}: {e}")
    report = {
        "tool": APP,
        "version": VERSION,
        "generated_at": now(),
        "results": results,
    }
    if report_path:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[REPORT] {report_path}")
    return report

def dashboard():
    c = db()
    stats = {}
    stats["repositories"] = c.execute("SELECT COUNT(*) n FROM repositories").fetchone()["n"]
    stats["iot"] = c.execute("SELECT COUNT(*) n FROM repositories WHERE iot_score >= 24").fetchone()["n"]
    stats["firmware"] = c.execute("SELECT COUNT(*) n FROM repositories WHERE firmware_score > 0").fetchone()["n"]
    stats["security"] = c.execute("SELECT COUNT(*) n FROM repositories WHERE security_score >= 24").fetchone()["n"]
    rows = c.execute("""SELECT full_name,html_url,iot_score,security_score,firmware_score,stars,last_seen
                        FROM repositories ORDER BY (iot_score+security_score+firmware_score) DESC LIMIT 100""").fetchall()
    c.close()
    return stats, [dict(x) for x in rows]

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/repos"):
            stats, rows = dashboard()
            body = json.dumps({"stats":stats,"repositories":rows}, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        stats, rows = dashboard()
        trs = "".join(
            f"<tr><td>{r['full_name']}</td><td>{r['iot_score']}</td>"
            f"<td>{r['security_score']}</td><td>{r['firmware_score']}</td>"
            f"<td>{r['stars']}</td></tr>" for r in rows
        )
        html = f"""<!doctype html><html><head><meta charset=utf-8>
        <title>RepoIntel-X</title><style>
        body{{font-family:Arial;background:#10141b;color:#eee;margin:30px}}
        .grid{{display:flex;gap:15px;flex-wrap:wrap}} .card{{background:#1a2230;padding:20px;border-radius:10px;min-width:150px}}
        table{{width:100%;border-collapse:collapse;margin-top:25px}}td,th{{padding:10px;border-bottom:1px solid #333;text-align:left}}
        </style></head><body><h1>RepoIntel-X</h1><p>GitHub Repository & IoT Security Intelligence</p>
        <div class=grid><div class=card>Repositories<br><b>{stats['repositories']}</b></div>
        <div class=card>IoT<br><b>{stats['iot']}</b></div>
        <div class=card>Firmware<br><b>{stats['firmware']}</b></div>
        <div class=card>Security<br><b>{stats['security']}</b></div></div>
        <table><tr><th>Repository</th><th>IoT</th><th>Security</th><th>Firmware</th><th>Stars</th></tr>{trs}</table>
        </body></html>""".encode()
        self.send_response(200)
        self.send_header("Content-Type","text/html;charset=utf-8")
        self.send_header("Content-Length",str(len(html)))
        self.end_headers()
        self.wfile.write(html)

def main():
    p = argparse.ArgumentParser(description=f"{APP} {VERSION} — single-file intelligence platform")
    p.add_argument("--query", action="append", help="GitHub repository query; repeatable")
    p.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    p.add_argument("--report", default="repointel_report.json")
    p.add_argument("--web", action="store_true", help="Start local dashboard")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--monitor", action="store_true", help="Continuously rediscover and analyze")
    p.add_argument("--interval", type=int, default=3600)
    p.add_argument("--token", help="GitHub token; safer alternative is GITHUB_TOKEN environment variable")
    p.add_argument("--rate-limit", action="store_true", help="Show GitHub API quota and exit")
    args = p.parse_args()

    global TOKEN
    if args.token:
        TOKEN = args.token

    db().close()

    if args.rate_limit:
        show_rate_limit()
        return

    if args.web:
        print(f"[WEB] http://127.0.0.1:{args.port}")
        HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()

    queries = args.query or DISCOVERY_QUERIES
    if args.monitor:
        while True:
            try:
                run(queries, args.limit, args.report)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print("[ERROR]", e)
            print(f"[MONITOR] sleeping {args.interval}s")
            time.sleep(args.interval)
    else:
        run(queries, args.limit, args.report)

if __name__ == "__main__":
    main()
