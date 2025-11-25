#!/usr/bin/env python3
"""
Garni Ibrahim 3SI3 Projet Annuel
PrOchoWatch.py

Intitulé du sujet:
Script Python qui détecte le lancement de processus non autorisés ou inconnus et génère une alerte en conséquence.

Fonctionnalités :
  - Process monitoring : heuristiques (exécutable supprimé, chemins temporaires, noms blacklistés)
  - FIM (File Integrity Monitoring) : baseline + détection d'ajouts/suppressions/modifications
  - Log monitoring : tail de fichiers + règles regex (sévérité, anti‑flood)
  - Alerting : console et fichier JSONL
  - Mode service (asynchrone) ou "one‑shot" (--once)

Utilisation :
  # Initialiser/mettre à jour la baseline FIM
  sudo python3 PrOchoWatch.py --init-baseline

  # Lancer en continu (config par défaut)
  sudo python3 PrOchoWatch.py

  # Lancer en continu avec un fichier de config
  sudo python3 PrOchoWatch.py --config /tmp/PrOchoWatch.json

  # Exécuter un passage unique (utile en CI/tests)
  sudo python3 PrOchoWatch.py --once

Exemple d'unité systemd ( /etc/systemd/system/PrOchoWatch.service ) :
  [Unit]
  Description=PrOchoWatch
  After=network.target

  [Service]
  ExecStart=/usr/bin/python3 /opt/PrOchoWatch/PrOchoWatch.py --config /etc/PrOchoWatch.json
  Restart=always
  User=root
  Group=root
  AmbientCapabilities=CAP_DAC_READ_SEARCH

  [Install]
  WantedBy=multi-user.target
"""

from __future__ import annotations
import argparse
import asyncio
import dataclasses
import fnmatch
import hashlib
import json
import logging
import os
import re
import stat
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

APP_NAME = "PrOchoWatch"
DEFAULT_DATA_DIR = Path.home() / "/var/log/LogPrOchoWatch"

# ------------------------ CONFIG PAR DÉFAUT ------------------------ #
DEFAULT_CONFIG = {
    "data_dir": str(DEFAULT_DATA_DIR),
    "alerting": {
        "alerts_jsonl": "alerts.jsonl",
        "app_log": "PrOchoWatch.log",
        "print_to_console": True
    },
    "fim": {
        "paths": ["/etc", "/usr/bin", "/usr/sbin", "/tmp"],
        "exclude_globs": ["*.log", "*.tmp", "*.cache*", "*.swp", "*.journal"],
        "max_file_size_mb": 20,
        "hash_large_files": False,
        "interval_sec": 300,
        "auto_update_baseline": True
    },
        "logmon": {
        "files": ["/var/log/auth.log"],
        "interval_sec": 2,
        "rules": [
            {"id": "SSH_FAIL", "pattern": r"Failed password for", "severity": "high", "throttle_sec": 30},
            {"id": "SUDO_DENIED", "pattern": r"sudo: .* user NOT in sudoers", "severity": "medium", "throttle_sec": 60},
            {"id": "ROOT_LOGIN", "pattern": r"Accepted .* for root ", "severity": "high", "throttle_sec": 60},
            {"id": "SUDO_FAIL", "pattern": r"sudo: .*incorrect password", "severity": "high", "throttle_sec": 60},
            {"id": "SUDO_ENUM", "pattern": r"sudo: .*COMMAND=.*sudo -l", "severity": "medium", "throttle_sec": 120},

            # --- Détections GTFOBins via sudo (élévation) ---
            # vim/vi/nvim -> shell via :! / -c '!sh'
            {"id": "SUDO_GTFO_VIM_SHELL",
             "pattern": r"sudo: .* COMMAND=.*\b(vim|vi|nvim)\b.*(-c|--cmd).*[!:\s]?(sh|bash|zsh|/bin/sh)",
             "severity": "high", "throttle_sec": 60},

            # tar -> --checkpoint-action=exec=/bin/sh
            {"id": "SUDO_GTFO_TAR_EXEC",
             "pattern": r"sudo: .* COMMAND=.*\btar\b.*--checkpoint-action=exec(=|:)\s*/?bin/(sh|bash|zsh)\b","severity": "high", "throttle_sec": 60},

            # find -> -exec /bin/sh
            {"id": "SUDO_GTFO_FIND_EXEC",
             "pattern": r"sudo: .* COMMAND=.*\bfind\b.*-exec\s*/?bin/(sh|bash|zsh)\b", "severity": "high", "throttle_sec": 60},

            # awk -> system('/bin/sh') ou équiv.
            {"id": "SUDO_GTFO_AWK_SYSTEM", "pattern": r"sudo: .* COMMAND=.*\bawk\b.*(system\s*\(|/bin/(sh|bash|zsh))", "severity": "high", "throttle_sec": 60},

            # perl -e 'exec "/bin/sh"' / system …
            {"id": "SUDO_GTFO_PERL_EXEC",
             "pattern": r"sudo: .* COMMAND=.*\bperl\b.*-e.*\b(exec|system)\b.*(/?bin/(sh|bash|zsh))", "severity": "high", "throttle_sec": 60},

            # python / python3 -c 'import os; os.system(...)' / subprocess / pty
            {"id": "SUDO_GTFO_PYTHON_OS_SYSTEM",
             "pattern": r"sudo: .* COMMAND=.*\bpython(3)?\b.*-c.*(os\.system\(|subprocess\.|pty\.spawn\()", "severity": "high", "throttle_sec": 60},

            # less -> ‘!’ (shell escape)
            {"id": "SUDO_GTFO_LESS_BANG", "pattern": r"sudo: .* COMMAND=.*\bless\b.*!.*", "severity": "medium", "throttle_sec": 120},

            # générique
            {"id": "SUDO_DIRECT_SHELL", "pattern": r"sudo: .* COMMAND=.*\b(/?bin/)?(sh|bash|zsh)\b(\s|$)", "severity": "high", "throttle_sec": 120}
        ]
    },
    "procmon": {
        "interval_sec": 5,
        "suspicious_path_prefixes": ["/tmp", "/dev/shm", "/var/tmp"],
        "blacklist_names": ["xmrig", "kinsing", "kworkerds", "minerd", "nc", "socat"],
        "proc_alert_throttle_sec": 120,
        "expected_system_procs": {
            "sshd": ["/usr/sbin/sshd", "/usr/lib/openssh/sbin/sshd"],
            "cron": ["/usr/sbin/cron", "/usr/sbin/crond", "/usr/bin/crond"],
            "rsyslogd": ["/usr/sbin/rsyslogd"],
            "systemd": ["/lib/systemd/systemd", "/usr/lib/systemd/systemd"]
        },
        "suspicious_name_regexes": [
            r"^kworkerz",
            r"^cron+d$",
            r"^syslogd$",
            r"^sshd:$", 
            r"^[a-z]{1,2}$",
            r"^bashd$|^zshd$|^pty\d*$"
        ],
        "kernel_like_names": ["kthreadd", "kswapd0", "ksoftirqd", "kworker"]
        ,
        "active_response": {"kill_on_blacklist": False}
    }
}

# ------------------------ OUTILS GÉNÉRAUX ------------------------ #

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_data_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open('rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# ------------------------ ALERTING ------------------------ #
@dataclasses.dataclass
class Alert:
    timestamp: str
    severity: str
    category: str
    rule_id: str
    message: str
    context: dict

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), ensure_ascii=False)


class AlertSink:
    def __init__(self, data_dir: Path, cfg: dict):
        self.data_dir = data_dir
        self.alerts_path = data_dir / cfg.get("alerts_jsonl", "alerts.jsonl")
        self.webhook_url = cfg.get("webhook_url")
        self.print_to_console = bool(cfg.get("print_to_console", True))

    def emit(self, alert: Alert) -> None:
        # 1) JSONL
        try:
            self.alerts_path.parent.mkdir(parents=True, exist_ok=True)
            with self.alerts_path.open('a', encoding='utf-8') as f:
                f.write(alert.to_json() + "\n")
        except Exception as e:
            logging.exception("Échec écriture alerts.jsonl: %s", e)

        # 2) Console
        if self.print_to_console:
            print(f"[{alert.severity.upper()}] {alert.category}/{alert.rule_id}: {alert.message}")


# ------------------------ FIM (File Integrity Monitoring) ------------------------ #
FIM_BASELINE_FILE = "fim_baseline.json"

@dataclasses.dataclass
class FileMeta:
    path: str
    inode: int
    size: int
    mtime: float
    mode: int
    uid: int
    gid: int
    sha256: Optional[str]

    @staticmethod
    def from_path(p: Path, want_hash: bool) -> Optional['FileMeta']:
        try:
            st = p.lstat()
            if not stat.S_ISREG(st.st_mode):
                return None
            digest = sha256_file(p) if want_hash else None
            return FileMeta(
                path=str(p), inode=st.st_ino, size=st.st_size, mtime=st.st_mtime,
                mode=st.st_mode, uid=st.st_uid, gid=st.st_gid, sha256=digest
            )
        except Exception:
            return None


def fim_build_snapshot(paths: List[str], exclude_globs: List[str], max_mb: int, hash_large: bool) -> Dict[str, FileMeta]:
    out: Dict[str, FileMeta] = {}
    max_bytes = max_mb * 1024 * 1024
    for root in paths:
        root_path = Path(root)
        if not root_path.exists():
            continue
        for p in root_path.rglob('*'):
            try:
                if not p.is_file():
                    continue
                rel = str(p)
                if any(fnmatch.fnmatch(rel, pat) for pat in exclude_globs):
                    continue
                st = p.lstat()
                want_hash = (st.st_size <= max_bytes) or hash_large
                meta = FileMeta.from_path(p, want_hash)
                if meta:
                    out[rel] = meta
            except Exception:
                continue
    return out


def fim_load_baseline(data_dir: Path) -> Dict[str, dict]:
    path = data_dir / FIM_BASELINE_FILE
    if not path.exists():
        return {}
    try:
        with path.open('r', encoding='utf-8') as f:
            raw = json.load(f)
            return {k: v for k, v in raw.items()}
    except Exception:
        logging.exception("Impossible de charger la baseline FIM")
        return {}


def fim_save_baseline(data_dir: Path, snap: Dict[str, FileMeta]) -> None:
    path = data_dir / FIM_BASELINE_FILE
    serial = {k: dataclasses.asdict(v) for k, v in snap.items()}
    with path.open('w', encoding='utf-8') as f:
        json.dump(serial, f, ensure_ascii=False, indent=2)


def fim_compare_and_alert(old: Dict[str, dict], new: Dict[str, FileMeta], sink: AlertSink) -> Tuple[int, int, int]:
    added = set(new.keys()) - set(old.keys())
    removed = set(old.keys()) - set(new.keys())
    common = set(new.keys()) & set(old.keys())

    mod_count = 0

    for p in added:
        sink.emit(Alert(utcnow_iso(), "medium", "FIM", "FILE_ADDED", f"Fichier ajouté: {p}", dataclasses.asdict(new[p])))
    for p in removed:
        sink.emit(Alert(utcnow_iso(), "high", "FIM", "FILE_REMOVED", f"Fichier supprimé: {p}", old[p]))

    for p in common:
        oldm = old[p]
        newm = dataclasses.asdict(new[p])
        deltas = {}
        for k in ("size", "mtime", "mode", "uid", "gid", "sha256"):
            if oldm.get(k) != newm.get(k):
                deltas[k] = {"old": oldm.get(k), "new": newm.get(k)}
        if deltas:
            mod_count += 1
            sink.emit(Alert(utcnow_iso(), "high", "FIM", "FILE_MODIFIED", f"Modification détectée: {p}", {"diff": deltas, "new": newm}))

    return (len(added), len(removed), mod_count)


async def fim_task(cfg: dict, data_dir: Path, sink: AlertSink, update_baseline: bool = False, once: bool = False):
    paths = cfg.get("paths", [])
    exclude_globs = cfg.get("exclude_globs", [])
    max_mb = int(cfg.get("max_file_size_mb", 20))
    hash_large = bool(cfg.get("hash_large_files", False))
    interval = int(cfg.get("interval_sec", 30))
    auto_update = bool(cfg.get("auto_update_baseline", False)) or update_baseline

    while True:
        logging.info("FIM: scan…")
        snap = fim_build_snapshot(paths, exclude_globs, max_mb, hash_large)
        base = fim_load_baseline(data_dir)
        if not base:
            logging.warning("Aucune baseline FIM présente. Exécutez --init-baseline pour en créer une.")
        counts = fim_compare_and_alert(base, snap, sink)
        logging.info("FIM: +%d / -%d / mod:%d", *counts)
        if auto_update:
            fim_save_baseline(data_dir, snap)
            logging.info("Baseline FIM mise à jour (%d fichiers).", len(snap))
        if once:
            return
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            return

# ------------------------ LOG MONITOR ------------------------ #
class LogTail:
    def __init__(self, path: Path):
        self.path = path
        self.fd = None
        self.inode = None
        self.pos = 0

    def _open(self):
        self.close()
        self.fd = self.path.open('r', errors='ignore')
        st = self.path.stat()
        self.inode = st.st_ino
        self.pos = self.fd.seek(0, os.SEEK_END)

    def close(self):
        if self.fd:
            try:
                self.fd.close()
            except Exception:
                pass
            self.fd = None

    def poll_lines(self) -> Iterable[str]:
        if not self.fd:
            if self.path.exists():
                self._open()
            else:
                return []
        try:
            st = self.path.stat()
            if st.st_ino != self.inode:
                self._open()
        except FileNotFoundError:
            self.close()
            return []
        except Exception:
            return []

        lines = []
        while True:
            line = self.fd.readline()
            if not line:
                break
            lines.append(line.rstrip("\n"))
        self.pos = self.fd.tell()
        return lines


@dataclasses.dataclass
class LogRule:
    id: str
    pattern: str
    severity: str
    throttle_sec: int = 0

    def __post_init__(self):
        self._regex = re.compile(self.pattern)

    def match(self, line: str) -> bool:
        return bool(self._regex.search(line))


async def logmon_task(cfg: dict, sink: AlertSink, once: bool = False):
    files = [Path(p) for p in cfg.get("files", [])]
    rules = [LogRule(**r) for r in cfg.get("rules", [])]
    interval = int(cfg.get("interval_sec", 2))
    tails = {p: LogTail(p) for p in files}
    last_alert: Dict[Tuple[str, str], float] = defaultdict(float)

    def should_emit(f: str, r: LogRule) -> bool:
        key = (f, r.id)
        now = time.time()
        if now - last_alert[key] >= r.throttle_sec:
            last_alert[key] = now
            return True
        return False

    while True:
        for p, tail in tails.items():
            for line in tail.poll_lines():
                for r in rules:
                    if r.match(line) and should_emit(str(p), r):
                        sink.emit(Alert(utcnow_iso(), r.severity, "LOG", r.id, f"{p}: {line}", {"file": str(p)}))
        if once:
            return
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            return

# ------------------------ PROCESS MONITOR ------------------------ #

def read_first_line(path: Path) -> Optional[str]:
    try:
        with path.open('r') as f:
            return f.readline().strip()
    except Exception:
        return None


def proc_iter_pids() -> Iterable[int]:
    for name in os.listdir('/proc'):
        if name.isdigit():
            yield int(name)


def proc_info(pid: int) -> Optional[dict]:
    base = Path('/proc') / str(pid)
    if not base.exists():
        return None
    try:
        exe_path = base / 'exe'
        exe = str(exe_path.readlink()) if exe_path.exists() else None
    except Exception:
        exe = None

    cmdline = None
    try:
        with (base / 'cmdline').open('rb') as f:
            raw = f.read()
            if raw:
                cmdline = raw.replace(b'\x00', b' ').strip().decode('utf-8', errors='replace')
    except Exception:
        pass

    comm = read_first_line(base / 'comm')

    statline = read_first_line(base / 'stat')
    ppid = None
    if statline:
        parts = statline.split()
        if len(parts) > 3:
            try:
                ppid = int(parts[3])
            except Exception:
                ppid = None

    cwd = None
    try:
        cwd = str((base / 'cwd').readlink())
    except Exception:
        pass

    return {
        'pid': pid,
        'ppid': ppid,
        'comm': comm,
        'cmdline': cmdline,
        'exe': exe,
        'cwd': cwd,
    }

def _normalize_exe_path(path) -> str:
    if not path:
        return ""
    s = str(path)
    if s.endswith(" (deleted)"):
        s = s[:-10]
    try:
        return os.path.realpath(s) if s.startswith("/") else s
    except Exception:
        return s


def is_deleted_exe_path(path) -> bool:
    return bool(path) and str(path).endswith(" (deleted)")


def is_suspicious_exe_path(path, prefixes: Iterable[str]) -> bool:
    s = _normalize_exe_path(path)
    if not s:
        return False
    pref_strs = [str(p) for p in prefixes]
    if any(s.startswith(pref) for pref in pref_strs):
        return True
    # emplacements éphémères souvent utilisés
    if s.startswith(("memfd:", "/dev/fd/", "pipe:", "anon_inode:")):
        return True
    return False

def regex_any_match(patterns: Iterable[str], text: str) -> Optional[str]:
    for pat in patterns:
        try:
            if re.search(pat, text or ""):
                return pat
        except re.error:
            continue
    return None

def path_under_any(prefixes: Iterable[str], path: Optional[str]) -> bool:
    if not path:
        return False
    try:
        rp = os.path.realpath(str(path).replace(" (deleted)", ""))
    except Exception:
        rp = str(path)
    return any(rp.startswith(pref) for pref in prefixes)


async def procmon_task(cfg: dict, sink: AlertSink, once: bool = False):
    interval = int(cfg.get("interval_sec", 60))
    sus_prefixes = list(cfg.get("suspicious_path_prefixes", []))
    blacklist = set(cfg.get("blacklist_names", []))
    active = cfg.get("active_response", {})
    kill_on_blacklist = bool(active.get("kill_on_blacklist", False))

    expected = cfg.get("expected_system_procs", {})  # name -> [allowed_paths]
    sus_name_pats = cfg.get("suspicious_name_regexes", [])
    kernel_like = cfg.get("kernel_like_names", [])
    throttle = int(cfg.get("proc_alert_throttle_sec", 120))

    # anti-spam de règles proc (clé -> timestamp)
    last_proc_alert: Dict[Tuple[str, str], float] = defaultdict(float)

    def should_emit_proc(rule_id: str, key: str) -> bool:
        now = time.time()
        k = (rule_id, key)
        if now - last_proc_alert[k] >= throttle:
            last_proc_alert[k] = now
            return True
        return False

    while True:
        # index du scan courant
        present_by_name: Dict[str, List[dict]] = defaultdict(list)

        for pid in proc_iter_pids():
            info = proc_info(pid)
            if not info:
                continue
            comm = (info.get('comm') or '').strip()
            exe = info.get('exe')  # peut finir par " (deleted)"
            norm_exe = _normalize_exe_path(exe)

            # Index pour vérifs post-scan
            if comm:
                present_by_name[comm].append(info)

            # 1) binaire supprimé
            if is_deleted_exe_path(exe):
                if should_emit_proc("DELETED_EXE", norm_exe or str(pid)):
                    sink.emit(Alert(utcnow_iso(), "high", "PROC", "DELETED_EXE",
                                    f"PID {pid} exécute un binaire supprimé: {exe}", info))

            # 2) exécutable dans répertoires temporaires / éphémères
            if is_suspicious_exe_path(exe, sus_prefixes):
                if should_emit_proc("TMP_EXE", norm_exe or str(pid)):
                    sink.emit(Alert(utcnow_iso(), "high", "PROC", "TMP_EXE",
                                    f"PID {pid} exécutable dans répertoire temporaire/éphémère: {exe}", info))

            # 3) blacklist par nom exact (xmrig, kinsing, minerd…)
            if comm in blacklist:
                if should_emit_proc("BLACKLISTED_NAME", comm):
                    sink.emit(Alert(utcnow_iso(), "high", "PROC", "BLACKLISTED_NAME",
                                    f"PID {pid} nom blacklisté: {comm}", info))
                if kill_on_blacklist:
                    try:
                        os.kill(pid, 9)
                        sink.emit(Alert(utcnow_iso(), "critical", "PROC", "KILLED", f"Processus {pid} tué (blacklist: {comm})", {"pid": pid, "comm": comm}))
                    except Exception as e:
                        logging.warning("Échec kill PID %s: %s", pid, e)

            # 4) noms suspects (regex)
            pat = regex_any_match(sus_name_pats, comm)
            if pat and should_emit_proc("SUS_NAME_PATTERN", f"{comm}:{pat}"):
                sink.emit(Alert(utcnow_iso(), "medium", "PROC", "SUS_NAME_PATTERN", f"Nom de processus suspect '{comm}' (pattern: {pat})", info))

            # 5) faux threads noyau (userland avec exécutable réel)
            #    Les vrais threads noyau apparaissent souvent entre crochets et/ou sans exe.
            if any(comm == k or comm.startswith(k) for k in kernel_like):
                # s'il y a un exécutable réel mappé, c'est louche
                if norm_exe and norm_exe.startswith("/"):
                    if should_emit_proc("FAKE_KERNEL_THREAD", f"{comm}:{norm_exe}"):
                        sink.emit(Alert(utcnow_iso(), "high", "PROC", "FAKE_KERNEL_THREAD", f"'{comm}' semble un thread noyau usurpé (exe: {norm_exe})", info))

            # 6) chemins anormaux pour services système connus
            if comm in expected:
                allowed = expected[comm]
                if not path_under_any(allowed, norm_exe):
                    if should_emit_proc("SYSTEM_PROC_PATH_MISMATCH", f"{comm}:{norm_exe}"):
                        sink.emit(Alert(utcnow_iso(), "high", "PROC", "SYSTEM_PROC_PATH_MISMATCH", f"{comm} exécute un binaire hors chemins autorisés: {norm_exe}", {
                                            "expected_prefixes": allowed, **(info or {}) }))

        # 7) processus critiques manquants
        for name, allowed in expected.items():
            if not present_by_name.get(name):
                if should_emit_proc("CRITICAL_MISSING", name):
                    sink.emit(Alert(utcnow_iso(), "high", "PROC", "CRITICAL_MISSING", f"Processus critique absent: {name}", {"expected_prefixes": allowed}))

        if once:
            return
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            return


# ------------------------ APPLICATION ------------------------ #

def setup_logging(data_dir: Path, app_log_name: str, debug: bool = False) -> None:
    ensure_data_dir(data_dir)
    log_path = data_dir / app_log_name
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s %(message)s',
        handlers=[
            logging.FileHandler(log_path, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )


def load_config(path: Optional[Path]) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if path and path.exists():
        try:
            with path.open('r', encoding='utf-8') as f:
                user = json.load(f)
            for k, v in user.items():
                if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
        except Exception as e:
            print(f"Erreur de lecture config {path}: {e}")
    return cfg


async def run_all(cfg: dict, once: bool = False, update_baseline: bool = False):
    data_dir = Path(cfg.get("data_dir", str(DEFAULT_DATA_DIR)))
    ensure_data_dir(data_dir)
    alert_cfg = cfg.get("alerting", {})
    sink = AlertSink(data_dir, alert_cfg)

    app_log = alert_cfg.get("app_log", "PrOchoWatch.log")
    setup_logging(data_dir, app_log_name=app_log, debug=False)

    tasks = []
    if cfg.get("fim"):
        tasks.append(asyncio.create_task(fim_task(cfg["fim"], data_dir, sink, update_baseline=update_baseline, once=once)))
    if cfg.get("logmon"):
        tasks.append(asyncio.create_task(logmon_task(cfg["logmon"], sink, once=once)))
    if cfg.get("procmon"):
        tasks.append(asyncio.create_task(procmon_task(cfg["procmon"], sink, once=once)))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=False) # À changer en True pour la démo pour vérifier toutes les fonctionnalités


def init_baseline(cfg: dict):
    fim_cfg = cfg.get("fim")
    if not fim_cfg:
        print("Aucune section 'fim' dans la configuration.")
        sys.exit(2)
    data_dir = Path(cfg.get("data_dir", str(DEFAULT_DATA_DIR)))
    ensure_data_dir(data_dir)

    paths = fim_cfg.get("paths", [])
    exclude_globs = fim_cfg.get("exclude_globs", [])
    max_mb = int(fim_cfg.get("max_file_size_mb", 20))
    hash_large = bool(fim_cfg.get("hash_large_files", False))

    print("Construction de la baseline FIM…")
    snap = fim_build_snapshot(paths, exclude_globs, max_mb, hash_large)
    fim_save_baseline(data_dir, snap)
    print(f"Baseline créée: {len(snap)} fichiers indexés → {(Path(cfg['data_dir'])/FIM_BASELINE_FILE)}")


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="PrOchoWatch — mini HIDS en Python")
    p.add_argument("--config", type=Path, help="Chemin du fichier JSON de configuration")
    p.add_argument("--once", action="store_true", help="Exécuter un scan unique et sortir")
    p.add_argument("--init-baseline", action="store_true", help="Initialiser (ou réécrire) la baseline FIM et quitter")
    p.add_argument("--update-baseline", action="store_true", help="Mettre à jour la baseline après scan FIM")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:

    print(r"""   


   ________  ________  ________  ________  ___  ___  ________  ___       __   ________  _________  ________  ___  ___    
  |\   __  \|\   __  \|\   __  \|\   ____\|\  \|\  \|\   __  \|\  \     |\  \|\   __  \|\___   ___\\   ____\|\  \|\  \    
  \ \  \|\  \ \  \|\  \ \  \|\  \ \  \___|\ \  \\\  \ \  \|\  \ \  \    \ \  \ \  \|\  \|___ \  \_\ \  \___|\ \  \\\  \   
   \ \   ____\ \   _  _\ \  \\\  \ \  \    \ \   __  \ \  \\\  \ \  \  __\ \  \ \   __  \   \ \  \ \ \  \    \ \   __  \  
    \ \  \___|\ \  \\  \\ \  \\\  \ \  \____\ \  \ \  \ \  \\\  \ \  \|\__\_\  \ \  \ \  \   \ \  \ \ \  \____\ \  \ \  \ 
     \ \__\    \ \__\\ _\\ \_______\ \_______\ \__\ \__\ \_______\ \____________\ \__\ \__\   \ \__\ \ \_______\ \__\ \__\
      \|__|     \|__|\|__|\|_______|\|_______|\|__|\|__|\|_______|\|____________|\|__|\|__|    \|__|  \|_______|\|__|\|__|

                                                                                               by ocho8sze

          """)


    args = parse_args(argv)
    cfg = load_config(args.config)

    if args.init_baseline:
        init_baseline(cfg)
        return 0

    try:
        asyncio.run(run_all(cfg, once=args.once, update_baseline=args.update_baseline))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
