#!/usr/bin/env python3
"""
H200 Dataset Gold Filter — v5.20.0 PROFESSIONAL
=================================================
Fix rispetto alla v5.20.0:
  - Penalità rimossa: il tier originale viene usato direttamente come score
    (il proxy signal_count basato su CYBER_GOLD_KEYWORDS era troppo aggressivo
     e scartava tutti gli esempi Tier B/C non-cyber)
  - Aggiunto --penalty-mode {none|soft|full} per controllo esplicito
  - Noise filter: "dotnet-runtime" → "dotnet" per catturare dotnet__runtime
  - max-chars default alzato a 150.000
  - Report: aggiunta colonna "Tier originale → accettati/scartati"

  Formato rilevato (da diagnostica):
    {
      "instruction": "...",
      "input": "",
      "output": "<codice>",
      "metadata": {
        "original_path": "/home/.../extracted_code/REPO/file.py",
        "language": "py",
        "tier": "A+"
      }
    }

  Mapping campi:
    content      ← output  (+ instruction come prefisso opzionale)
    language     ← metadata.language
    tier_str     ← metadata.tier  →  score numerico (A+=10, A=8, B+=7, B=6 …)
    repo         ← estratto da original_path  (segmento dopo "extracted_code/")
    org          ← prima parte del repo (prima di "__" o "/")
    file_score   ← derivato da tier_str
    cyber_gold   ← cyber_scanner(content)  (come in v5.15)

Utilizzo tipico:
    python3 h200_gold_filter_v516.py \\
        --input output_final_h200/train_examples.jsonl \\
        --max-per-repo 200 \\
        --max-per-org 1000 \\
        --max-per-language 5000 \\
        --min-quality 4 \\
        --dedup-threshold 0.85

Dipendenze opzionali:
    pip install tqdm datasketch
"""

import argparse
import json
import re
import hashlib
import time
import sys
from pathlib import Path, PurePosixPath
from collections import Counter, defaultdict
from typing import Optional

# ── Dipendenze opzionali ─────────────────────────────────────────────────────
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

try:
    from datasketch import MinHash, MinHashLSH
    MINHASH_AVAILABLE = True
except ImportError:
    MINHASH_AVAILABLE = False

# ─── CONFIGURAZIONI GLOBALI ──────────────────────────────────────────────────
GENERICITY_PENALTY_MAX = 3
SIGNAL_BONUS_THRESHOLD = 3

# Mapping tier stringa → score numerico
# Copre varianti comuni: "A+", "A", "B+", "B", "C", "S", ecc.
TIER_SCORE_MAP = {
    "s":  10, "s+": 10,
    "a+": 9,  "a":  8,
    "b+": 7,  "b":  6,
    "c+": 5,  "c":  4,
    "d+": 3,  "d":  2,
    "f":  1,
}

# Cyber Gold: forza Tier S indipendentemente dallo score
CYBER_GOLD_KEYWORDS = [
    r"CVE-\d{4}-\d+",       r"exploit",           r"payload",
    r"shellcode",            r"buffer\s*overflow", r"privilege\s*escalation",
    r"rce",                  r"backdoor",          r"metasploit",
    r"beacon",               r"obfuscation",       r"antivirus\s*bypass",
    r"amsi\s*bypass",        r"mimikatz",          r"reverse\s*shell",
    r"injection",            r"sqlmap",            r"nmap\s*script",
    r"syscall",              r"ntdll",             r"hellsgate",
    r"halosgate",            r"tartarus",          r"syswhispers",
    r"direct\s*syscall",     r"etw\s*bypass",      r"unhook",
]

# Linguaggi ammessi — usato solo se --filter-languages è attivo
ALLOWED_LANGUAGES = frozenset({
    "c", "c_cpp", "cpp", "h", "csharp", "cs", "python", "py",
    "go", "rust", "rs", "powershell", "ps1", "java"
})

# Segmenti di path generici da scartare.
# NOTA: "build","dist","examples","obj" rimossi perché in corpus cybersec
# contengono spesso PoC, shellcode, C2 framework code — dati preziosi.
_GENERIC_PATH_SEGMENTS = frozenset({
    "node_modules", "vendor", "third_party",
})
# Segmenti aggiuntivi attivabili con --strict-path-filter
_STRICT_PATH_SEGMENTS = frozenset({
    "node_modules", "vendor", "third_party",
    "docs", "examples", "build", "dist", "obj",
})
# Keyword repo generici: match come PREFISSO del nome repo (prima di "__" o "-")
# Questo evita di filtrare tool offensivi come "dotnet-inject", "dotnet-spy" ecc.
_GENERIC_REPO_PREFIXES = frozenset({
    "llvm", "clang", "chromium", "pytorch", "tensorflow",
})
# Match esatto sul nome repo completo (per repo misti non-offensivi noti)
_GENERIC_REPO_EXACT = frozenset({
    "dotnet__runtime", "dotnet-runtime",
})

# ─── UTILITY ─────────────────────────────────────────────────────────────────

def get_tier(final_score: float, is_cyber_gold: bool) -> str:
    if is_cyber_gold or final_score >= 8: return "Tier S (Gold)"
    if final_score >= 6:                  return "Tier A (Silver)"
    if final_score >= 4:                  return "Tier B (Bronze)"
    return "Tier C (Common)"


def cyber_scanner(text: str) -> bool:
    for pattern in CYBER_GOLD_KEYWORDS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def tier_str_to_score(tier: str) -> float:
    """
    Converte la stringa tier del corpus in uno score numerico.
    Es: "A+" → 9,  "B" → 6,  "S" → 10
    Fallback a 5 se non riconosciuta.
    """
    return float(TIER_SCORE_MAP.get(tier.strip().lower(), 5))


def extract_repo_from_path(original_path: str) -> str:
    """
    Estrae il nome del repository dal campo original_path.
    Esempio:
      /home/andrea/.../extracted_code/JoasASantos__SysWhispers4/core/models.py
      → "JoasASantos__SysWhispers4"

    Cerca il segmento subito dopo "extracted_code" nel path.
    Fallback: usa il secondo livello del path.
    """
    try:
        parts = PurePosixPath(original_path).parts
        for i, part in enumerate(parts):
            if part == "extracted_code" and i + 1 < len(parts):
                return parts[i + 1]
        # Fallback: terzo segmento non-root (es. /home/user/REPO/...)
        non_root = [p for p in parts if p not in ("/", "home", "root")]
        return non_root[1] if len(non_root) > 1 else "unknown"
    except Exception:
        return "unknown"


def extract_org_from_repo(repo: str) -> str:
    """
    Estrae l'organizzazione dal nome repo.
    Supporta separatori "__" (GitHub clone) e "/" (formato owner/repo).
    Es: "JoasASantos__SysWhispers4" → "JoasASantos"
        "microsoft/terminal"        → "microsoft"
    """
    if "__" in repo:
        return repo.split("__")[0]
    if "/" in repo:
        return repo.split("/")[0]
    return repo


def is_generic_noise(path: str, repo: str, strict_path: bool = False) -> bool:
    repo_lower = repo.lower()
    # Controlla match esatto del repo (es. dotnet__runtime)
    if repo_lower in _GENERIC_REPO_EXACT:
        return True
    # Controlla se il PREFISSO dell'org è una keyword generica
    org = repo_lower.split("__")[0].split("-")[0].split("/")[0]
    if org in _GENERIC_REPO_PREFIXES:
        return True
    # Filtro path: usa set ridotto (default) o esteso (--strict-path-filter)
    try:
        parts = {p.lower() for p in PurePosixPath(path).parts}
    except Exception:
        parts = set()
    seg_set = _STRICT_PATH_SEGMENTS if strict_path else _GENERIC_PATH_SEGMENTS
    return bool(parts & seg_set)


def safe_pct(num: int, den: int) -> float:
    return (num / den * 100) if den > 0 else 0.0


def count_lines(filepath: Path) -> int:
    count = 0
    with open(filepath, "rb") as f:
        for _ in f:
            count += 1
    return count


# ─── DEDUP ───────────────────────────────────────────────────────────────────

def normalize_for_dedup(text: str) -> str:
    text = re.sub(r'//.*|/\*.*?\*/|#.*', '', text)
    text = re.sub(r'\s+', ' ', text).strip().lower()
    if len(text) > 1024:
        text = text[:512] + text[-512:]
    return text


def exact_hash(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).digest()[:16]


def make_minhash(text: str, num_perm: int) -> "MinHash":
    m = MinHash(num_perm=num_perm)
    norm = normalize_for_dedup(text)  # già troncato a 1024 char
    for i in range(max(1, len(norm) - 2)):
        m.update(norm[i:i+3].encode("utf-8"))
    return m

# NOTA: normalize_for_dedup tronca già a 1024 char (512 inizio + 512 fine),
# quindi make_minhash opera sempre su testo breve → velocità costante
# indipendentemente dalla dimensione del file originale.


# ─── ESTRAZIONE CONTENUTO (formato reale del corpus) ─────────────────────────

def extract_content(ex: dict, include_instruction: bool) -> str:
    """
    Estrae il contenuto dall'esempio nel formato reale:
      { "instruction": "...", "input": "", "output": "<codice>" }

    Se include_instruction=True antepone l'istruzione al codice
    (utile per training instruction-following).
    """
    output = ex.get("output", "")
    if not output:
        # Fallback a formati alternativi
        if isinstance(ex.get("messages"), list) and ex["messages"]:
            output = ex["messages"][0].get("content", "")
        if not output:
            output = ex.get("text", ex.get("content", ""))

    if include_instruction:
        instruction = ex.get("instruction", "").strip()
        if instruction and output:
            return f"### Instruction\n{instruction}\n\n### Code\n{output}"

    return output


# ─── CORE ENGINE ─────────────────────────────────────────────────────────────

def process_jsonl(input_path: Path, out_train: str, out_eval: str, args) -> None:
    stats = {
        "total":      0,
        "kept":       0,
        "start_time": time.time(),
        "rejected":   defaultdict(int),
        "langs":      defaultdict(int),
        "repos":      defaultdict(int),
        "orgs":       defaultdict(int),
        "tiers":      Counter(),
        "tier_src":   Counter(),   # distribuzione tier originali del corpus
    }

    seen_exact: set[bytes] = set()
    lsh: Optional["MinHashLSH"] = None
    lsh_map: dict = {}

    if MINHASH_AVAILABLE:
        lsh = MinHashLSH(threshold=args.dedup_threshold, num_perm=args.num_perm)
        print(f"[*] MinHash LSH attivo (threshold={args.dedup_threshold}, perm={args.num_perm})")
    else:
        print("[!] datasketch non trovato → dedup fuzzy disabilitata.")
        print("    Installa con: pip install datasketch")

    if args.total_rows:
        total_rows = args.total_rows
        print(f"[*] Righe totali (da argomento): {total_rows:,}")
    else:
        print("[*] Conteggio righe (usa --total-rows per saltare)…")
        total_rows = count_lines(input_path)
        print(f"[*] Righe totali rilevate:       {total_rows:,}")

    print(f"[*] Avvio v5.20.0 PROFESSIONAL su {input_path}\n")

    def line_gen(p: Path):
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                yield line

    iterator = (
        tqdm(line_gen(input_path), total=total_rows, unit="lines")
        if TQDM_AVAILABLE else line_gen(input_path)
    )

    f_train = open(out_train, "w", encoding="utf-8")
    f_eval  = open(out_eval,  "w", encoding="utf-8")

    try:
        for raw_line in iterator:
            stats["total"] += 1
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            try:
                ex = json.loads(raw_line)

                # ── 1. Estrazione contenuto ──────────────────────────────
                content = extract_content(ex, args.include_instruction)
                if not content:
                    stats["rejected"]["empty_content"] += 1
                    continue

                # ── 2. Filtri dimensionali ────────────────────────────────
                if len(content) < args.min_chars:
                    stats["rejected"]["too_short"] += 1
                    continue
                if args.max_chars > 0 and len(content) > args.max_chars:
                    stats["rejected"]["too_long"] += 1
                    continue
                if len(content.splitlines()) < 4:
                    stats["rejected"]["too_few_lines"] += 1
                    continue

                # ── 3. Metadati dal formato reale ─────────────────────────
                meta     = ex.get("metadata", ex.get("meta", {}))
                path     = meta.get("original_path", "")
                lang     = meta.get("language", "unknown").lower().strip()
                tier_str = meta.get("tier", "c").strip()

                stats["tier_src"][tier_str] += 1

                # Repo estratto dal meta (v4 converter) o dal path (v3 converter)
                repo = meta.get("repo_id", "") or extract_repo_from_path(path)
                org  = extract_org_from_repo(repo)

                # ── 4. Filtro linguaggio (opzionale) ─────────────────────
                if args.filter_languages and lang not in ALLOWED_LANGUAGES:
                    stats["rejected"]["lang_not_allowed"] += 1
                    continue

                # ── 5. Filtro rumore generico ─────────────────────────────
                if is_generic_noise(path, repo, strict_path=args.strict_path_filter):
                    stats["rejected"]["noise_filter"] += 1
                    continue

                # ── 6. Score e Cyber Scan ─────────────────────────────────
                is_gold    = cyber_scanner(content)

                # Usa file_score dal metadata (v4 converter) oppure
                # converte il tier stringa (v3 converter — fallback)
                raw_score = meta.get("file_score")
                if isinstance(raw_score, (int, float)) and raw_score > 0:
                    base_score = float(raw_score)
                    # Normalizza: file_score può arrivare a 40+, mappiamo a 0-10
                    base_score = min(10.0, base_score / 4.0)
                else:
                    base_score = tier_str_to_score(tier_str)

                # Penalità configurabile via --penalty-mode:
                #   none → final_score = base_score  (default, consigliato)
                #   soft → penalità fissa -1.0
                #   full → penalità basata su code_signal_count reale
                if args.penalty_mode == "none":
                    final_score = base_score
                elif args.penalty_mode == "soft":
                    final_score = max(0.0, base_score - 1.0)
                else:  # full
                    # Usa signal_count reale se disponibile (v4), altrove proxy
                    signal_count = meta.get("code_signal_count")
                    if not isinstance(signal_count, int):
                        signal_count = sum(
                            1 for p in CYBER_GOLD_KEYWORDS
                            if re.search(p, content, re.IGNORECASE)
                        )
                    penalty = (
                        GENERICITY_PENALTY_MAX
                        if signal_count < SIGNAL_BONUS_THRESHOLD
                        else GENERICITY_PENALTY_MAX / 2
                    )
                    final_score = max(0.0, base_score - penalty)

                # ── 7. Filtro qualità ─────────────────────────────────────
                if not is_gold and args.min_quality > 0 and final_score < args.min_quality:
                    stats["rejected"]["low_quality"] += 1
                    continue

                # ── 8. Dedup Exact ────────────────────────────────────────
                h_exact = exact_hash(content)
                if h_exact in seen_exact:
                    stats["rejected"]["exact_dup"] += 1
                    continue
                seen_exact.add(h_exact)

                # ── 9. Dedup Fuzzy (MinHash LSH) ─────────────────────────
                if lsh is not None:
                    mh      = make_minhash(content, args.num_perm)
                    similar = lsh.query(mh)

                    if similar:
                        best_key   = max(similar, key=lambda k: lsh_map[k][1])
                        best_score = lsh_map[best_key][1]
                        if base_score > best_score:
                            lsh.remove(best_key)
                            del lsh_map[best_key]
                            new_key = h_exact.hex()
                            lsh.insert(new_key, mh)
                            lsh_map[new_key] = (mh, base_score, h_exact)
                            # Prosegui: questo è migliore del precedente
                        else:
                            stats["rejected"]["fuzzy_dup"] += 1
                            continue
                    else:
                        new_key = h_exact.hex()
                        lsh.insert(new_key, mh)
                        lsh_map[new_key] = (mh, base_score, h_exact)

                # ── 10. Limiti per repo / org / lingua ────────────────────
                if args.max_per_repo and stats["repos"][repo] >= args.max_per_repo:
                    stats["rejected"]["repo_limit"] += 1
                    continue
                if args.max_per_org and stats["orgs"][org] >= args.max_per_org:
                    stats["rejected"]["org_limit"] += 1
                    continue
                if args.max_per_language and stats["langs"][lang] >= args.max_per_language:
                    stats["rejected"]["lang_limit"] += 1
                    continue

                # ── SALVATAGGIO ───────────────────────────────────────────
                stats["kept"] += 1
                stats["langs"][lang] += 1
                stats["repos"][repo] += 1
                stats["orgs"][org]   += 1
                stats["tiers"][get_tier(final_score, is_gold)] += 1

                # Split deterministico (5% eval)
                target = f_eval if (int.from_bytes(h_exact, "big") % 20 == 0) else f_train
                target.write(json.dumps(ex, ensure_ascii=False) + "\n")

            except Exception as e:
                stats["rejected"][f"err_{type(e).__name__}"] += 1

    finally:
        f_train.close()
        f_eval.close()

        duration = time.time() - stats["start_time"]
        kept  = stats["kept"]
        total = stats["total"]

        print("\n" + "═" * 75)
        print("📊 REPORT FINALE H200 GOLD DATASET v5.20.0")
        print("═" * 75)
        print(f"Esempi Analizzati:  {total:,}")
        print(f"Esempi Accettati:   {kept:,}  (Retention: {safe_pct(kept, total):.2f}%)")
        print(f"Tempo Totale:       {duration / 60:.2f} min")
        print(f"Velocità:           {(total / duration):,.0f} esempi/sec")

        print("\n🏆 CLASSIFICAZIONE QUALITÀ (TIERS):")
        for t in ["Tier S (Gold)", "Tier A (Silver)", "Tier B (Bronze)", "Tier C (Common)"]:
            c = stats["tiers"][t]
            print(f"  {t:<20}: {c:>10,}  ({safe_pct(c, kept):>5.1f}%)")

        print("\n📋 TIER ORIGINALI DEL CORPUS (Top 10):")
        for t, c in stats["tier_src"].most_common(10):
            print(f"  {t:<10}: {c:>10,}  ({safe_pct(c, total):>5.1f}% del totale)")

        print("\n🛑 ANALISI SCARTI (Top 8):")
        for k, v in sorted(stats["rejected"].items(), key=lambda x: -x[1])[:8]:
            print(f"  {k:<22}: {v:,}")

        print("\n💻 LINGUAGGI TOP 8:")
        for lang_n, cnt in sorted(stats["langs"].items(), key=lambda x: -x[1])[:8]:
            print(f"  {lang_n:<18}: {cnt:,}")

        print("\n🏢 ORGANIZZAZIONI TOP 10:")
        for org_n, cnt in sorted(stats["orgs"].items(), key=lambda x: -x[1])[:10]:
            print(f"  {org_n:<35}: {cnt:,}")

        print("\n📁 REPOSITORY TOP 10:")
        for repo_n, cnt in sorted(stats["repos"].items(), key=lambda x: -x[1])[:10]:
            print(f"  {repo_n:<40}: {cnt:,}")

        print("═" * 75)


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="H200 Dataset Gold Filter v5.20.0",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # I/O
    parser.add_argument("--input",              required=True)
    parser.add_argument("--out-train",          default="train_gold.jsonl")
    parser.add_argument("--out-eval",           default="eval_gold.jsonl")
    parser.add_argument("--total-rows",         type=int,   default=None)

    # Contenuto
    parser.add_argument("--include-instruction", action="store_true",
                        help="Antepone 'instruction' al codice nel campo content")

    # Filtri dimensionali
    parser.add_argument("--min-chars",          type=int,   default=150)
    parser.add_argument("--max-chars",          type=int,   default=0,
                        help="Max caratteri per esempio (0=disabilitato)")

    # Filtri qualità
    parser.add_argument("--min-quality",        type=int,   default=0,
                        help="Score minimo finale (0=disabilitato)")

    # Limiti dataset
    parser.add_argument("--max-per-repo",       type=int,   default=200)
    parser.add_argument("--max-per-org",        type=int,   default=1000)
    parser.add_argument("--max-per-language",   type=int,   default=10000)

    # Dedup fuzzy
    parser.add_argument("--dedup-threshold",    type=float, default=0.85)
    parser.add_argument("--num-perm",           type=int,   default=128)

    # Filtro lingua
    parser.add_argument("--penalty-mode",       default="none",
                        choices=["none", "soft", "full"],
                        help="none=tier diretto (default) | soft=-1 | full=-3 (v5.16)")
    parser.add_argument("--strict-path-filter",  action="store_true",
                        help="Filtra anche build/dist/docs/examples/obj nei path")
    parser.add_argument("--filter-languages",   action="store_true",
                        help=f"Filtra solo: {sorted(ALLOWED_LANGUAGES)}")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"[ERRORE] File non trovato: {input_path}")
        sys.exit(1)

    process_jsonl(input_path, args.out_train, args.out_eval, args)


if __name__ == "__main__":
    main()
