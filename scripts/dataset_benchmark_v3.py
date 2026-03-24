#!/usr/bin/env python3
"""
dataset_benchmark_v3.py
========================
Benchmark avanzato per dataset JSONL — supporta tutti i formati della pipeline:

  FORMAT A — file_candidates (meta)
    { "repo_id", "file_score", "code_signal_count", "file_tier", "language", ... }

  FORMAT B — training examples (instruction/output)
    { "instruction", "output", "metadata": { "tier", "file_score", ... } }

  FORMAT C — messages+meta (legacy)
    { "messages": [...], "meta": { ... } }

Novità rispetto a v2:
  - Analyzer dedicato per ogni formato (niente più "formato non supportato")
  - ETA su caricamento streaming per file grandi
  - Rilevamento automatico formato su primo record
  - Distribuzione lunghezze con istogramma ASCII
  - --quick per test rapidi su N record
  - --output per salvare report JSON

Uso:
    python3 dataset_benchmark_v3.py --input file_candidates_v2.jsonl
    python3 dataset_benchmark_v3.py --input output_final_h200/train_examples.jsonl
    python3 dataset_benchmark_v3.py --input train_gold.jsonl --quick 10000
"""

import argparse
import json
import re
import hashlib
import time
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Any, Optional

# ─── Colori ANSI ─────────────────────────────────────────────────────────────
C = {
    "RED":    "\033[91m", "GREEN": "\033[92m", "YELLOW": "\033[93m",
    "BLUE":   "\033[94m", "CYAN":  "\033[96m", "BOLD":   "\033[1m",
    "RESET":  "\033[0m",
}

def cp(text: str, color: str = "") -> None:
    print(f"{C.get(color,'')}{text}{C['RESET']}")

def fmt(n) -> str:
    if isinstance(n, float): return f"{n:,.1f}"
    return f"{n:,}"

def bar(pct: float, width: int = 28) -> str:
    filled = int(pct / 100 * width)
    return "█" * filled + "░" * (width - filled)

def fmt_eta(sec: float) -> str:
    if sec <= 0 or sec != sec: return "--:--"
    h, rem = divmod(int(sec), 3600)
    m, s   = divmod(rem, 60)
    return f"{h}h {m:02d}m {s:02d}s" if h else f"{m}m {s:02d}s"

def pct_str(n: int, total: int) -> str:
    return f"{n/total*100:5.1f}%" if total else " 0.0%"

# ─── Statistiche descrittive ─────────────────────────────────────────────────

def describe(values: List[float]) -> Dict:
    if not values:
        return {}
    s = sorted(values)
    n = len(s)
    return {
        "count": n,
        "min":   s[0],
        "p25":   s[n // 4],
        "p50":   s[n // 2],
        "p75":   s[int(n * 0.75)],
        "p95":   s[int(n * 0.95)],
        "max":   s[-1],
        "avg":   sum(s) / n,
    }

def print_describe(label: str, d: Dict) -> None:
    if not d: return
    print(f"  {label}:")
    print(f"    avg {fmt(d['avg'])}  |  "
          f"p50 {fmt(d['p50'])}  p95 {fmt(d['p95'])}  "
          f"max {fmt(d['max'])}  min {fmt(d['min'])}")

def length_histogram(lengths: List[int], buckets=8) -> None:
    if not lengths: return
    lo, hi = min(lengths), max(lengths)
    if lo == hi:
        print(f"  Tutti {fmt(lo)} chars")
        return
    step   = (hi - lo) / buckets
    counts = [0] * buckets
    for v in lengths:
        idx = min(int((v - lo) / step), buckets - 1)
        counts[idx] += 1
    mx = max(counts)
    print("  Distribuzione lunghezze:")
    for i, c in enumerate(counts):
        lo_b = int(lo + i * step)
        hi_b = int(lo + (i + 1) * step)
        b = "█" * int(c / mx * 30) if mx else ""
        print(f"    {lo_b:>7,}–{hi_b:<7,}  {b}  {c:,}")

# ─── Caricamento streaming con ETA ───────────────────────────────────────────

def load_jsonl_stream(path: Path, max_records: int = 0) -> List[Dict]:
    """Carica con ETA basato su byte letti."""
    file_size = path.stat().st_size
    records   = []
    errors    = 0
    t_start   = time.time()
    bytes_read = 0

    with path.open("rb") as fb:
        raw_size = fb.read()
    total_lines = raw_size.count(b"\n")

    with path.open(encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            bytes_read += len(line.encode("utf-8", errors="replace"))
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                errors += 1
                continue

            if max_records and len(records) >= max_records:
                print(f"\r  [quick mode] Caricati {len(records):,} record          ")
                break

            # ETA ogni 20k righe
            if (i + 1) % 20_000 == 0:
                elapsed = time.time() - t_start
                speed   = bytes_read / elapsed if elapsed > 0 else 1
                remain  = (file_size - bytes_read) / speed
                pct     = bytes_read / file_size * 100
                print(
                    f"\r  [{pct:5.1f}%] {len(records):,} record  "
                    f"{speed/1e6:.1f} MB/s  ETA: {fmt_eta(remain)}   ",
                    end="", flush=True
                )

    print(f"\r  Caricati {len(records):,} record  ({errors} errori JSON)          ")
    return records

# ─── Rilevamento formato ──────────────────────────────────────────────────────

def detect_format(r: Dict) -> str:
    if "messages" in r:
        return "messages"
    if "output" in r and ("instruction" in r or "metadata" in r):
        return "training"
    if "file_score" in r or "code_signal_count" in r or "file_tier" in r:
        return "candidates"
    if "text" in r and len(r) <= 3:   # formato text-only: {"text": "..."}
        return "text"
    if "assistant" in r and ("user" in r or "human" in r or "instruction" in r):
        return "flat_chat"
    return "unknown"

# ─── ANALYZER: FORMAT A — file_candidates ────────────────────────────────────

def analyze_candidates(records: List[Dict]) -> Dict:
    n = len(records)
    lengths, scores, signal_counts = [], [], []
    langs     = Counter()
    tiers     = Counter()
    clusters  = Counter()
    repos     = Counter()
    orgs      = Counter()
    seen_sha  = set()
    dupes     = 0

    for r in records:
        lang    = r.get("language", "unknown")
        tier    = r.get("file_tier", r.get("tier", "?"))
        score   = r.get("file_score", 0)
        signals = r.get("code_signal_count", 0)
        cluster = r.get("cluster", "unknown")
        repo    = r.get("repo_id", "unknown")
        org     = repo.split("/")[0] if "/" in repo else repo.split("__")[0]
        sha     = r.get("sha1", "")
        lines   = r.get("line_count", 0)
        size    = r.get("bytes_size", 0)

        langs[lang]       += 1
        tiers[tier]       += 1
        clusters[cluster] += 1
        repos[repo]       += 1
        orgs[org]         += 1
        signal_counts.append(signals)
        if score:  scores.append(score)
        if lines:  lengths.append(lines)

        if sha:
            if sha in seen_sha: dupes += 1
            else: seen_sha.add(sha)

    return {
        "format":   "candidates",
        "total":    n,
        "langs":    langs,
        "tiers":    tiers,
        "clusters": clusters,
        "repos":    repos,
        "orgs":     orgs,
        "signal_counts": Counter(signal_counts),
        "scores":   describe(scores),
        "lengths":  describe(lengths),
        "raw_lengths": lengths,
        "dupes":    dupes,
    }

# ─── ANALYZER: FORMAT B — training examples ──────────────────────────────────

def analyze_training(records: List[Dict]) -> Dict:
    n = len(records)
    char_lens, scores, signal_counts = [], [], []
    langs    = Counter()
    tiers    = Counter()
    repos    = Counter()
    orgs     = Counter()
    clusters = Counter()
    malformed = 0
    seen_exact = set()
    seen_near  = set()
    dupes_exact = 0
    dupes_near  = 0

    for r in records:
        content = r.get("output", "")
        if not content:
            malformed += 1
            continue

        meta    = r.get("metadata", r.get("meta", {}))
        lang    = meta.get("language", "unknown")
        tier    = meta.get("tier", meta.get("file_tier", "?"))
        score   = meta.get("file_score", 0)
        signals = meta.get("code_signal_count", 0)
        repo    = meta.get("repo_id", meta.get("repo", "unknown"))
        org     = repo.split("/")[0] if "/" in repo else repo.split("__")[0]
        cluster = meta.get("cluster", "unknown")

        langs[lang]    += 1
        tiers[tier]    += 1
        repos[repo]    += 1
        orgs[org]      += 1
        clusters[cluster] += 1
        char_lens.append(len(content))
        signal_counts.append(signals)
        if score: scores.append(float(score))

        # Dedup
        h = hashlib.sha256(content.encode("utf-8", errors="replace")).digest()[:8]
        if h in seen_exact:
            dupes_exact += 1
        else:
            seen_exact.add(h)
            norm = re.sub(r'\s+', ' ', content.lower())
            hn   = hashlib.md5((norm[:512] + norm[-512:]).encode()).digest()[:8]
            if hn in seen_near:
                dupes_near += 1
            else:
                seen_near.add(hn)

    return {
        "format":       "training",
        "total":        n,
        "malformed":    malformed,
        "langs":        langs,
        "tiers":        tiers,
        "repos":        repos,
        "orgs":         orgs,
        "clusters":     clusters,
        "signal_counts": Counter(signal_counts),
        "scores":       describe(scores),
        "lengths":      describe(char_lens),
        "raw_lengths":  char_lens,
        "dupes_exact":  dupes_exact,
        "dupes_near":   dupes_near,
    }

# ─── ANALYZER: FORMAT C — messages+meta (legacy) ─────────────────────────────

def analyze_messages(records: List[Dict]) -> Dict:
    n = len(records)
    char_lens, scores, signal_counts = [], [], []
    langs  = Counter()
    tiers  = Counter()
    repos  = Counter()
    orgs   = Counter()
    malformed = 0
    seen   = set()
    dupes  = 0

    for r in records:
        messages = r.get("messages", [])
        meta     = r.get("meta", {})
        code     = ""
        for msg in messages:
            if msg.get("role") == "assistant":
                code = msg.get("content", "")
                break
        if not code.strip():
            malformed += 1
            continue

        lang    = meta.get("language", "unknown")
        tier    = meta.get("file_tier", "?")
        score   = meta.get("file_score", 0)
        signals = meta.get("code_signal_count", 0)
        repo    = meta.get("repo", "unknown")
        org     = repo.split("/")[0] if "/" in repo else "?"

        langs[lang]  += 1
        tiers[tier]  += 1
        repos[repo]  += 1
        orgs[org]    += 1
        char_lens.append(len(code))
        signal_counts.append(signals)
        if score: scores.append(float(score))

        h = hashlib.sha256(code.encode("utf-8", errors="replace")).digest()[:8]
        if h in seen: dupes += 1
        else: seen.add(h)

    return {
        "format":       "messages",
        "total":        n,
        "malformed":    malformed,
        "langs":        langs,
        "tiers":        tiers,
        "repos":        repos,
        "orgs":         orgs,
        "signal_counts": Counter(signal_counts),
        "scores":       describe(scores),
        "lengths":      describe(char_lens),
        "raw_lengths":  char_lens,
        "dupes_exact":  dupes,
    }

# ─── STAMPA REPORT ───────────────────────────────────────────────────────────

def print_report(s: Dict, filename: str) -> None:
    n      = s["total"]
    valid  = n - s.get("malformed", 0)
    fmt_   = s["format"].upper()

    cp(f"\n{'═'*72}", "CYAN")
    cp(f"  📊 DATASET BENCHMARK v3  —  {filename}  [{fmt_}]", "BOLD")
    cp(f"  Totale record : {fmt(n)}", "GREEN")
    if s.get("malformed"):
        cp(f"  Malformati    : {fmt(s['malformed'])}  ({pct_str(s['malformed'], n)})", "YELLOW")
    cp(f"{'─'*72}", "CYAN")

    # Lunghezze
    ld = s.get("lengths", {})
    label = "Lunghezza (righe)" if s["format"] == "candidates" else "Lunghezza contenuto (chars)"
    print_describe(label, ld)
    if s["format"] == "text" and s.get("line_counts"):
        print_describe("Righe per esempio", s["line_counts"])
    if s["format"] == "flat_chat":
        print_describe("Lunghezza domanda utente (chars)", s.get("user_lengths", {}))
        if s.get("has_system"):
            print(f"  Record con system prompt : {fmt(s['has_system'])}  ({pct_str(s['has_system'], n)})")
    if s.get("raw_lengths"):
        length_histogram(s["raw_lengths"])

    # Linguaggi
    if s.get("langs"):
        print(f"\n  {'LINGUAGGIO':<16} {'N':>8}   {'%':>6}  BAR")
        for lang, cnt in s["langs"].most_common(12):
            p = cnt / valid * 100
            print(f"  {lang:<16} {fmt(cnt):>8}   {p:5.1f}%  {bar(p)}")

    # Tier
    if s.get("tiers"):
        print(f"\n  {'TIER':<10} {'N':>8}   {'%':>6}")
        for tier, cnt in sorted(s["tiers"].items()):
            print(f"  {tier:<10} {fmt(cnt):>8}   {pct_str(cnt, valid)}")

    # Segnali offensivi
    if s.get("signal_counts"):
        print(f"\n  Distribuzione segnali offensivi:")
        for sig in sorted(s["signal_counts"]):
            cnt = s["signal_counts"][sig]
            p   = cnt / valid * 100
            print(f"    {sig:>2} segnali → {fmt(cnt):>8}   {p:5.1f}%  {bar(p, 20)}")

    # Score
    print_describe("File score", s.get("scores", {}))

    # Duplicati
    if "dupes_exact" in s or "dupes" in s:
        de = s.get("dupes_exact", s.get("dupes", 0))
        dn = s.get("dupes_near", 0)
        print(f"\n  Duplicati esatti stimati : {fmt(de)}  ({pct_str(de, valid)})")
        if dn:
            print(f"  Duplicati simili stimati : {fmt(dn)}  ({pct_str(dn, valid)})")

    # Cluster (solo candidates/training)
    if s.get("clusters") and len(s["clusters"]) > 1:
        print(f"\n  Top cluster offensivi:")
        for cl, cnt in s["clusters"].most_common(8):
            if cl not in ("unknown", ""):
                print(f"    {cl:<35} {fmt(cnt):>7}")

    # Org / Repo
    if s.get("orgs"):
        print(f"\n  Top 10 organizzazioni:")
        for org, cnt in s["orgs"].most_common(10):
            print(f"    {org:<35} {fmt(cnt):>7}")

    if s.get("repos"):
        print(f"\n  Top 10 repository:")
        for repo, cnt in s["repos"].most_common(10):
            print(f"    {repo:<45} {fmt(cnt):>6}")

    cp(f"{'═'*72}\n", "CYAN")


# ─── ANALYZER: FORMAT D — text-only {"text": "..."} ──────────────────────────

def analyze_text(records: List[Dict]) -> Dict:
    """
    Formato usato per il training v4 (dataset_text_field='text').
    Ogni record: {"text": "<contenuto>"} — senza metadati strutturati.
    Analisi: lunghezze, dedup, rilevamento linguaggio da estensione/pattern,
    segnali offensivi rilevati nel testo.
    """
    import re as _re

    CYBER_PATTERNS = [
        r"CVE-\d{4}-\d+", r"shellcode", r"payload", r"exploit",
        r"amsi.bypass", r"etw.patch", r"mimikatz", r"syscall",
        r"ntdll", r"backdoor", r"reverse.shell", r"privilege.escal",
        r"inject", r"beacon", r"cobalt.strike", r"metasploit",
        r"buffer.overflow", r"rootkit", r"byovd", r"unhook",
    ]

    LANG_PATTERNS = {
        "powershell": [r"Invoke-", r"Get-\w+", r"\$PSVersion", r"Write-Host",
                       r"param\s*\(", r"\.ps1", r"#requires"],
        "python":     [r"import\s+\w+", r"def\s+\w+\(", r"if __name__",
                       r"\.py[\s\"]", r"print\("],
        "c/cpp":      [r"#include\s*<", r"int\s+main\s*\(", r"void\s+\w+\s*\(",
                       r"printf\(", r"malloc\(", r"sizeof\("],
        "csharp":     [r"using\s+System", r"namespace\s+\w+", r"public\s+class",
                       r"\.cs[\s\"]", r"Console\.Write"],
        "go":         [r"package\s+main", r"func\s+\w+\(", r"import\s+\"",
                       r"fmt\.Print", r"\.go[\s\"]"],
        "rust":       [r"fn\s+main\(\)", r"use\s+std::", r"let\s+mut\s+",
                       r"impl\s+\w+", r"\.rs[\s\"]"],
    }

    n = len(records)
    char_lens   = []
    line_counts = []
    langs       = Counter()
    cyber_hits  = Counter()   # quanti pattern cyber per record
    seen_exact  = set()
    seen_near   = set()
    dupes_exact = 0
    dupes_near  = 0
    malformed   = 0

    for r in records:
        text = r.get("text", "")
        if not text or not text.strip():
            malformed += 1
            continue

        char_lens.append(len(text))
        line_counts.append(len(text.splitlines()))

        # Rilevamento linguaggio dal contenuto
        detected = "unknown"
        for lang, patterns in LANG_PATTERNS.items():
            if any(_re.search(p, text, _re.IGNORECASE) for p in patterns):
                detected = lang
                break
        langs[detected] += 1

        # Segnali offensivi
        hits = sum(1 for p in CYBER_PATTERNS
                   if _re.search(p, text, _re.IGNORECASE))
        cyber_hits[hits] += 1

        # Dedup
        h = hashlib.sha256(text.encode("utf-8", errors="replace")).digest()[:8]
        if h in seen_exact:
            dupes_exact += 1
        else:
            seen_exact.add(h)
            norm = _re.sub(r'\s+', ' ', text.lower())
            hn   = hashlib.md5((norm[:512] + norm[-512:]).encode()).digest()[:8]
            if hn in seen_near:
                dupes_near += 1
            else:
                seen_near.add(hn)

    return {
        "format":       "text",
        "total":        n,
        "malformed":    malformed,
        "langs":        langs,
        "tiers":        Counter(),        # non disponibile in formato text
        "signal_counts": cyber_hits,
        "scores":       {},
        "lengths":      describe(char_lens),
        "raw_lengths":  char_lens,
        "line_counts":  describe(line_counts),
        "dupes_exact":  dupes_exact,
        "dupes_near":   dupes_near,
    }


# ─── ANALYZER: FORMAT E — flat chat {system, user, assistant} ────────────────

def analyze_flat_chat(records: List[Dict]) -> Dict:
    """Formato flat: ogni record ha campi diretti system/user/assistant (o human)."""
    CYBER_PATTERNS = [
        r"CVE-\d{4}-\d+", r"shellcode", r"payload", r"exploit",
        r"amsi.bypass", r"mimikatz", r"syscall", r"ntdll", r"backdoor",
        r"reverse.shell", r"privilege.escal", r"inject", r"beacon",
        r"rootkit", r"byovd", r"unhook", r"lsass", r"kerberoast",
    ]

    n = len(records)
    char_lens_ans   = []
    char_lens_user  = []
    cyber_hits      = Counter()
    has_system      = 0
    malformed       = 0
    seen_exact      = set()
    seen_near       = set()
    dupes_exact     = 0
    dupes_near      = 0

    for r in records:
        answer = r.get("assistant", r.get("output", ""))
        user   = r.get("user", r.get("human", r.get("instruction", "")))
        system = r.get("system", "")

        if not answer or not answer.strip():
            malformed += 1
            continue

        if system:
            has_system += 1

        char_lens_ans.append(len(answer))
        if user:
            char_lens_user.append(len(user))

        hits = sum(1 for p in CYBER_PATTERNS
                   if re.search(p, answer, re.IGNORECASE))
        cyber_hits[hits] += 1

        h = hashlib.sha256(answer.encode("utf-8", errors="replace")).digest()[:8]
        if h in seen_exact:
            dupes_exact += 1
        else:
            seen_exact.add(h)
            norm = re.sub(r'\s+', ' ', answer.lower())
            hn   = hashlib.md5((norm[:512] + norm[-512:]).encode()).digest()[:8]
            if hn in seen_near:
                dupes_near += 1
            else:
                seen_near.add(hn)

    return {
        "format":        "flat_chat",
        "total":         n,
        "malformed":     malformed,
        "has_system":    has_system,
        "langs":         Counter(),
        "tiers":         Counter(),
        "signal_counts": cyber_hits,
        "scores":        {},
        "lengths":       describe(char_lens_ans),
        "raw_lengths":   char_lens_ans,
        "user_lengths":  describe(char_lens_user),
        "dupes_exact":   dupes_exact,
        "dupes_near":    dupes_near,
    }

# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Dataset Benchmark v3 — supporta tutti i formati pipeline",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input",   required=True, help="File JSONL da analizzare")
    parser.add_argument("--quick",   type=int, default=0,
                        help="Analizza solo i primi N record (0=tutti)")
    parser.add_argument("--output",  default=None,
                        help="Salva statistiche in JSON")
    args = parser.parse_args()

    path = Path(args.input)
    if not path.is_file():
        cp(f"[ERRORE] File non trovato: {path}", "RED")
        sys.exit(1)

    size_mb = path.stat().st_size / 1e6
    cp(f"\n[*] {path.name}  ({size_mb:.1f} MB)", "CYAN")
    if args.quick:
        cp(f"[*] Quick mode: primi {args.quick:,} record", "YELLOW")

    t0      = time.time()
    records = load_jsonl_stream(path, args.quick)
    cp(f"[*] Caricamento: {time.time()-t0:.1f}s", "GREEN")

    if not records:
        cp("[ERRORE] Nessun record valido trovato", "RED")
        sys.exit(1)

    fmt_type = detect_format(records[0])
    cp(f"[*] Formato rilevato: {fmt_type.upper()}", "BLUE")

    if fmt_type == "candidates":
        stats = analyze_candidates(records)
    elif fmt_type == "training":
        stats = analyze_training(records)
    elif fmt_type == "messages":
        stats = analyze_messages(records)
    elif fmt_type == "text":
        stats = analyze_text(records)
    elif fmt_type == "flat_chat":
        stats = analyze_flat_chat(records)
    else:
        cp(f"[AVVISO] Formato sconosciuto — prime chiavi: {list(records[0].keys())[:6]}", "YELLOW")
        sys.exit(1)

    print_report(stats, path.name)

    if args.output:
        out = Path(args.output)
        # Rimuovi campi non serializzabili
        safe = {k: v for k, v in stats.items()
                if k != "raw_lengths" and not isinstance(v, Counter)}
        with out.open("w", encoding="utf-8") as f:
            json.dump(safe, f, indent=2, ensure_ascii=False, default=str)
        cp(f"[OK] Statistiche salvate: {out}", "GREEN")


if __name__ == "__main__":
    main()