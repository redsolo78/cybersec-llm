#!/usr/bin/env python3
"""
dataset_merger_v2.py
====================
Unisce N dataset JSONL di formati diversi selezionando sempre il meglio.

Formati supportati in INPUT (rilevati automaticamente):
  - TEXT      : {"text": "..."}
  - TRAINING  : {"instruction":..., "output":..., "metadata":{...}}
  - MESSAGES  : {"messages":[...], "meta":{...}}
  - CANDIDATES: {"file_score":..., "code_signal_count":..., ...}

Formati OUTPUT disponibili:
  - auto      : usa il formato più ricco trovato nei file di input (default)
  - text      : {"text": "..."}  ← compatibile con tutti i trainer
  - training  : {"instruction", "output", "metadata"}  ← massimo metadata
  - messages  : {"messages":[...], "meta":{...}}  ← formato chat

Novità rispetto a v1 (v2.1 fix aggiuntivi):
  - is_valid_repo: repo come 'src','tests','include' → 'unknown'
  - Language normalization applicata su TUTTI i formati
  - Parser ChatML corretto (estrae solo blocco assistant)

Novità rispetto a v1 originali:
  - --out-format auto (default): rileva il formato migliore dai tuoi file
  - --scan-dir: scansiona una cartella e trova tutti i jsonl automaticamente
  - Formato preservato: se tutti i file sono TRAINING, output è TRAINING senza perdere niente
  - Report per file sorgente con breakdown formato
  - ETA su ogni fase (caricamento, dedup, filtri)

Utilizzo tipico:
    # Merge esplicito di file specifici
    python3 dataset_merger_v2.py \\
        --inputs file1.jsonl file2.jsonl file3.jsonl \\
        --output merged_gold.jsonl

    # Scansiona tutta una cartella
    python3 dataset_merger_v2.py \\
        --scan-dir ~/cybersec-llm/script_v1.1 \\
        --output merged_gold.jsonl \\
        --max-per-language 3000

    # Forza output in formato specifico
    python3 dataset_merger_v2.py \\
        --inputs *.jsonl \\
        --out-format text \\
        --output merged_text.jsonl
"""

import argparse
import hashlib
import json
import re
import time
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional

# ─── ETA ─────────────────────────────────────────────────────────────────────

def fmt_eta(sec: float) -> str:
    if sec <= 0 or sec != sec: return "--:--"
    h, r = divmod(int(sec), 3600)
    m, s = divmod(r, 60)
    return f"{h}h {m:02d}m {s:02d}s" if h else f"{m}m {s:02d}s"

def print_progress(processed: int, total: int, kept: int,
                   start: float, label: str = "") -> None:
    el    = time.time() - start
    speed = processed / el if el > 0 else 0
    pct   = processed / total * 100 if total else 0
    eta   = (total - processed) / speed if speed > 0 else 0
    print(
        f"\r  [{processed:>8,}/{total:,}] {pct:5.1f}% | "
        f"{speed:>7,.0f}/s | ETA: {fmt_eta(eta):>9} | "
        f"kept: {kept:,}  {label}        ",
        end="", flush=True
    )

# ─── RILEVAMENTO FORMATO ──────────────────────────────────────────────────────

FORMAT_PRIORITY = {"training": 4, "messages": 3, "chatml": 3,
                   "candidates": 2, "raw_candidates": 2, "content": 1, "code": 1,
                   "text": 1, "unknown": 0}

def detect_format(r: Dict) -> str:
    # RAW_CANDIDATES prima di tutto: hanno 'raw' dict + 'text_blob' (metadata, NO codice)
    if "raw" in r and isinstance(r.get("raw"), dict) and "text_blob" in r:
        return "raw_candidates"
    if "raw" in r and ("repo_path" in r or "file_tier" in r):
        return "raw_candidates"
    # ChatML
    if "text" in r:
        text = r.get("text", "")
        if "<|im_start|>" in text and "<|im_end|>" in text:
            return "chatml"
        return "text"
    if "messages" in r:                                              return "messages"
    if "output" in r and ("instruction" in r or "metadata" in r):   return "training"
    if "output" in r and "input" in r:                               return "training"
    if "file_score" in r or "code_signal_count" in r:               return "candidates"
    if "content" in r and isinstance(r["content"], str):             return "content"
    if "code" in r and isinstance(r["code"], str):                   return "code"
    return "unknown"

def best_format(formats: List[str]) -> str:
    """Ritorna il formato con priorità più alta trovato nell'insieme."""
    return max(set(formats), key=lambda f: FORMAT_PRIORITY.get(f, 0))

# ─── PARSER CHATML ────────────────────────────────────────────────────────────

def parse_chatml(text: str) -> Dict:
    """
    Parsa una stringa ChatML nel formato:
      <|im_start|>system\n...<|im_end|>
      <|im_start|>user\n...<|im_end|>
      <|im_start|>assistant\n...<|im_end|>

    Ritorna dict con: system, user, assistant
    """
    result = {"system": "", "user": "", "assistant": ""}
    # Splitta su <|im_start|> e processa ogni blocco
    blocks = text.split("<|im_start|>")
    for block in blocks:
        if not block.strip():
            continue
        # Rimuovi il tag di chiusura
        block = block.split("<|im_end|>")[0]
        # Prima riga = ruolo, resto = contenuto
        lines = block.split("\n", 1)
        if len(lines) < 2:
            continue
        role    = lines[0].strip().lower()
        content = lines[1].strip()
        if role in result:
            result[role] = content
    return result

# ─── RILEVAMENTO LINGUAGGIO ───────────────────────────────────────────────────

_LANG_PATTERNS = {
    "powershell": [r"Invoke-\w+", r"\$PSVersion", r"Write-Host",
                   r"param\s*\(", r"Get-\w+", r"\.ps1"],
    "python":     [r"^import\s+\w+", r"^from\s+\w+\s+import",
                   r"def\s+\w+\s*\(", r"if\s+__name__\s*=="],
    "go":         [r"^package\s+\w+", r"^func\s+\w+\(", r"^import\s+\"",
                   r"fmt\.Print"],
    "csharp":     [r"using\s+System", r"namespace\s+\w+",
                   r"public\s+class\s+\w+", r"Console\.Write"],
    "rust":       [r"^fn\s+\w+\(", r"use\s+std::", r"let\s+mut\s+",
                   r"impl\s+\w+"],
    "c/cpp":      [r"#include\s*<", r"int\s+main\s*\(", r"void\s+\w+\s*\(",
                   r"printf\s*\(", r"malloc\s*\("],
}

def infer_language(text: str) -> str:
    for lang, patterns in _LANG_PATTERNS.items():
        if any(re.search(p, text, re.MULTILINE | re.IGNORECASE) for p in patterns):
            return lang
    return "unknown"

# Normalizzazione nomi lingua — mappa tutti i sinonimi al nome canonico
_LANG_NORMALIZE = {
    # Python
    "py": "python", "python": "python", "python3": "python",
    # C/C++
    "c": "c/cpp", "c_cpp": "c/cpp", "cpp": "c/cpp", "cc": "c/cpp",
    "h": "c/cpp", "hpp": "c/cpp", "cxx": "c/cpp", "c++": "c/cpp",
    # C#
    "cs": "csharp", "csharp": "csharp", "c#": "csharp",
    # Rust
    "rs": "rust", "rust": "rust",
    # Go
    "go": "go", "golang": "go",
    # PowerShell
    "ps1": "powershell", "powershell": "powershell",
    "psm1": "powershell", "psd1": "powershell",
    # Java
    "java": "java",
    # Unknown
    "unknown": "unknown", "": "unknown",
}

def normalize_lang(lang: str) -> str:
    """Normalizza il nome del linguaggio al suo nome canonico."""
    if not lang:
        return "unknown"
    return _LANG_NORMALIZE.get(lang.lower().strip(), lang.lower().strip())


def infer_dominant_language(text: str) -> str:
    """
    Per contenuti con codice misto (bash + python + powershell nello stesso record),
    individua la lingua del blocco codice più lungo.
    Fallback su infer_language() se non ci sono blocchi espliciti.
    """
    import re as _re
    # Cerca blocchi ```lingua\n...```
    blocks = _re.findall(r"```(\w*)\n(.*?)```", text, _re.DOTALL)
    if not blocks:
        return infer_language(text)

    # Mappa delle estensioni/nomi nei backtick al nome canonico
    _backtick_map = {
        "python": "python", "py": "python",
        "powershell": "powershell", "ps1": "powershell",
        "csharp": "csharp", "cs": "csharp",
        "go": "go", "golang": "go",
        "rust": "rust", "rs": "rust",
        "c": "c/cpp", "cpp": "c/cpp", "c++": "c/cpp",
        "bash": "bash", "sh": "bash",
    }

    # Trova il blocco più lungo e usa la sua lingua
    longest_lang = "unknown"
    longest_len  = 0
    for lang_hint, block_content in blocks:
        if len(block_content) > longest_len:
            longest_len  = len(block_content)
            mapped       = _backtick_map.get(lang_hint.lower().strip(), "")
            longest_lang = mapped if mapped else infer_language(block_content)

    return normalize_lang(longest_lang) if longest_lang != "bash" else "unknown"

# ─── VALIDAZIONE E PULIZIA REPO ─────────────────────────────────────────────────

_GENERIC_DIRS = frozenset({
    "src", "tests", "test", "include", "source", "build", "dist",
    "bin", "lib", "obj", "server", "client", "core", "util", "utils",
    "system", "wireless", "c_language", "unknown", "common", "main",
    "app", "internal", "pkg", "cmd", "api", "web", "docs", "scripts",
})

def is_valid_repo(repo: str) -> bool:
    """Verifica che il repo sia un nome GitHub valido (owner/repo o owner__repo)."""
    if not repo or repo.lower() in ("unknown", "", "none"):
        return False
    has_sep = "/" in repo or "__" in repo
    first_seg = repo.split("/")[0].split("__")[0].lower()
    return has_sep and first_seg not in _GENERIC_DIRS

def clean_repo(repo: str) -> str:
    """Ritorna il repo se valido, altrimenti 'unknown'."""
    return repo if is_valid_repo(repo) else "unknown"

# ─── TIER DA SEGNALI (fallback per record senza tier) ────────────────────────

def tier_from_signals(signal_count: int) -> str:
    """
    Assegna un tier basato sui segnali cyber rilevati nel contenuto.
    Usato come fallback quando il record non ha un tier assegnato ('?').
    Coerente con la logica di extract_to_candidates.py:
      signal_count >= 4 → A+
      signal_count >= 2 → A
      signal_count >= 1 → B
      signal_count == 0 → C
    """
    if signal_count >= 4: return "A+"
    if signal_count >= 2: return "A"
    if signal_count >= 1: return "B"
    return "C"


def resolve_tier(tier: str, signal_count: int) -> str:
    """
    Se il tier è '?' o mancante, lo calcola dai segnali.
    Se è già valorizzato (A, B, C, A+, gold, ecc.), lo normalizza e lo mantiene.
    """
    # Mappa tier stringa generici al sistema A/B/C
    tier_map = {
        "gold": "A+", "silver": "A", "bronze": "B",
        "s": "A+", "s+": "A+",
        "a+": "A+", "a": "A",
        "b+": "A",  "b": "B",
        "c+": "B",  "c": "C",
        "d": "C",   "f": "C",
    }
    if not tier or tier.strip() in ("?", "", "none", "None", "N/A", "unknown"):
        return tier_from_signals(signal_count)
    normalized = tier_map.get(tier.strip().lower())
    return normalized if normalized else tier.strip()


# ─── CYBER SIGNAL SCAN ───────────────────────────────────────────────────────

_CYBER_PATTERNS = [
    r"CVE-\d{4}-\d+",    r"shellcode",      r"payload",      r"exploit",
    r"amsi.bypass",       r"etw.patch",      r"mimikatz",     r"syscall",
    r"ntdll",             r"backdoor",       r"reverse.shell",r"privilege.escal",
    r"inject",            r"beacon",         r"cobalt.strike",r"metasploit",
    r"buffer.overflow",   r"rootkit",        r"byovd",        r"unhook",
    r"hellsgate",         r"halosgate",      r"syswhispers",  r"obfuscat",
    r"lsass",             r"kerberoast",     r"dcsync",       r"token.steal",
    r"process.hollow",    r"reflective.dll", r"dll.inject",   r"apc.inject",
]

def count_signals(text: str) -> int:
    return sum(1 for p in _CYBER_PATTERNS if re.search(p, text, re.IGNORECASE))

# ─── ESTRAZIONE CONTENUTO (normalizzazione interna) ───────────────────────────

def extract_record(r: Dict, source_file: str) -> Optional[Dict]:
    """
    Normalizza qualsiasi formato in struttura interna comune.
    Preserva l'originale per ricostruire l'output nel formato giusto.
    """
    fmt = detect_format(r)

    if fmt == "chatml":
        text    = r.get("text", "")
        parsed  = parse_chatml(text)
        content = parsed["assistant"].strip()
        if not content: return None
        instruction = parsed["user"].strip()
        lang = r.get("language", infer_language(content))  # usa campo language se presente
        # Usa rank_score/quality_score come file_score se disponibili
        score = float(r.get("rank_score", r.get("quality_score", 0)) or 0)
        repo  = clean_repo(r.get("repo", "unknown") or "unknown")
        return {
            "content":     content,
            "instruction": instruction,
            "system":      parsed["system"],
            "lang":        normalize_lang(lang),
            "tier":        r.get("domain_bucket", "?"),
            "score":       score,
            "signals":     0,  # calcolato dopo in load_and_merge
            "repo":        repo,
            "fmt":         fmt, "source": source_file, "original": r,
        }

    if fmt == "text":
        content = r.get("text", "").strip()
        if not content: return None
        lang = infer_language(content)
        return {
            "content": content, "lang": normalize_lang(lang),
            "tier": "?", "score": 0.0, "signals": 0,
            "repo": "unknown", "fmt": fmt,
            "source": source_file, "original": r,
        }

    elif fmt == "training":
        content = r.get("output", "").strip()
        if not content: return None
        meta    = r.get("metadata", r.get("meta", {}))
        lang    = meta.get("language", "unknown")
        return {
            "content": content,
            "lang":    normalize_lang(lang if lang not in ("", None) else infer_language(content)),
            "tier":    meta.get("tier", meta.get("file_tier", "?")),
            "score":   float(meta.get("file_score", 0) or 0),
            "signals": int(meta.get("code_signal_count", 0) or 0),
            "repo":    clean_repo(meta.get("repo_id", meta.get("repo", "unknown")) or "unknown"),
            "fmt":     fmt, "source": source_file, "original": r,
        }

    elif fmt == "messages":
        # Estrai content dal role assistant
        content = ""
        user_msg = ""
        for msg in r.get("messages", []):
            role = msg.get("role", "")
            if role == "assistant":
                content = msg.get("content", "").strip()
            elif role == "user":
                user_msg = msg.get("content", "").strip()
        if not content: return None
        meta = r.get("meta", {})
        lang = meta.get("language", "unknown")
        # Se non c'è il messaggio user, costruisci instruction da meta.path
        if not user_msg:
            path = meta.get("path", meta.get("repo_path", ""))
            fname = path.split("/")[-1] if path else ""
            repo  = meta.get("repo", "unknown")
            user_msg = (f"Provide the implementation of {fname} from {repo}."
                        if fname else f"Provide the implementation of this {lang} code.")
        return {
            "content": content,
            "instruction": user_msg,
            "lang":    normalize_lang(lang if lang not in ("", None) else infer_language(content)),
            "tier":    meta.get("file_tier", "?"),
            "score":   float(meta.get("file_score", 0) or 0),
            "signals": int(meta.get("code_signal_count", 0) or 0),
            "repo":    clean_repo(meta.get("repo", "unknown") or "unknown"),
            "fmt":     fmt, "source": source_file, "original": r,
        }

    elif fmt in ("candidates", "raw_candidates"):
        # Nessun codice sorgente recuperabile — skip
        return None

    elif fmt == "content":
        # Formato {"content": "...", ...} — usato da alcuni script interni
        content = r.get("content", "").strip()
        if not content: return None
        lang = r.get("language", r.get("lang", "unknown"))
        return {
            "content": content,
            "lang":    normalize_lang(lang if lang not in ("", None) else infer_language(content)),
            "tier":    r.get("tier", r.get("file_tier", "?")),
            "score":   float(r.get("file_score", 0) or 0),
            "signals": int(r.get("code_signal_count", 0) or 0),
            "repo":    clean_repo(r.get("repo_id", r.get("repo", "unknown")) or "unknown"),
            "fmt":     "content", "source": source_file, "original": r,
        }

    elif fmt == "code":
        # Formato {"code": "...", ...}
        content = r.get("code", "").strip()
        if not content: return None
        lang = r.get("language", r.get("lang", "unknown"))
        return {
            "content": content,
            "lang":    normalize_lang(lang if lang not in ("", None) else infer_language(content)),
            "tier":    r.get("tier", "?"),
            "score":   float(r.get("score", r.get("file_score", 0)) or 0),
            "signals": int(r.get("signals", r.get("code_signal_count", 0)) or 0),
            "repo":    clean_repo(r.get("repo_id", r.get("repo", "unknown")) or "unknown"),
            "fmt":     "code", "source": source_file, "original": r,
        }

    return None

# ─── FORMATTAZIONE OUTPUT ─────────────────────────────────────────────────────

def format_output(rec: Dict, out_fmt: str) -> Dict:
    """
    Converte il record normalizzato nel formato di output richiesto.
    Se out_fmt == 'native', usa il formato originale del record.

    Gestisce correttamente il formato chatml: preserva system/user/assistant.
    """
    target_fmt = rec["fmt"] if out_fmt == "native" else out_fmt
    content    = rec["content"]
    instruction = rec.get("instruction", "") or \
                  f"Provide the implementation of this {rec['lang']} code."

    if target_fmt in ("text", "chatml", "native") and rec["fmt"] == "chatml":
        # Ricostruisce il ChatML originale preservando system + user + assistant
        system = rec.get("system", "")
        sys_block  = f"<|im_start|>system\n{system}<|im_end|>\n" if system else ""
        user_block = f"<|im_start|>user\n{instruction}<|im_end|>\n" if instruction else ""
        asst_block = f"<|im_start|>assistant\n{content}<|im_end|>"
        return {"text": sys_block + user_block + asst_block}

    if target_fmt == "text":
        return {"text": content}

    elif target_fmt == "training":
        if rec["fmt"] == "training":
            # Preserva originale arricchendo i campi mancanti
            # IMPORTANTE: normalizza sempre il campo language nell'output
            out  = dict(rec["original"])
            meta = dict(out.get("metadata", out.get("meta", {})))
            meta["language"] = normalize_lang(meta.get("language", rec["lang"]))
            if not meta.get("code_signal_count") and rec["signals"] > 0:
                meta["code_signal_count"] = rec["signals"]
            meta["repo_id"] = clean_repo(meta.get("repo_id", meta.get("repo", "unknown")) or "unknown")
            # Aggiorna il tier con il valore risolto (sostituisce '?')
            meta["tier"] = rec["tier"]
            out["metadata"] = meta
            return out
        # Tutti gli altri formati (incluso chatml) → training strutturato
        return {
            "instruction": instruction,
            "input": "",
            "output": content,
            "metadata": {
                "language":          rec["lang"],
                "tier":              rec["tier"],
                "file_score":        rec["score"],
                "code_signal_count": rec["signals"],
                "repo_id":           rec["repo"],
                "source_format":     rec["fmt"],
            }
        }

    elif target_fmt == "messages":
        if rec["fmt"] == "messages":
            return rec["original"]   # preserva esatto
        msgs = []
        if rec.get("system"):
            msgs.append({"role": "system", "content": rec["system"]})
        msgs.append({"role": "user",      "content": instruction})
        msgs.append({"role": "assistant", "content": content})
        return {
            "messages": msgs,
            "meta": {
                "language":          rec["lang"],
                "file_tier":         rec["tier"],
                "file_score":        rec["score"],
                "code_signal_count": rec["signals"],
                "repo":              rec["repo"],
            }
        }

    # fallback
    return {"text": content}

# ─── SCAN DIR ────────────────────────────────────────────────────────────────

# File da ignorare quando si scansiona una directory
_IGNORE_PATTERNS = {
    "train_gold.jsonl", "eval_gold.jsonl",  # output dei filtri (evita loop)
    "merged_gold.jsonl", "merged_eval.jsonl",
    "file_candidates.jsonl", "file_candidates_v2.jsonl",  # candidates, non training
}

def scan_dir_for_jsonl(directory: Path, recursive: bool = True) -> List[Path]:
    """
    Scansiona una directory trovando tutti i .jsonl usabili come input.
    Esclude file di candidates (troppo grandi, formato sbagliato) e
    file di output del merger stesso.
    """
    found = []
    pattern = "**/*.jsonl" if recursive else "*.jsonl"
    for p in sorted(directory.glob(pattern)):
        if p.name in _IGNORE_PATTERNS:
            print(f"  [skip] {p.name}  (nella lista di esclusioni)")
            continue
        if p.stat().st_size < 1000:
            print(f"  [skip] {p.name}  (troppo piccolo: {p.stat().st_size} bytes)")
            continue
        found.append(p)
        print(f"  [+]    {p.name}  ({p.stat().st_size/1e6:.1f} MB)")
    return found

# ─── MERGE CORE ──────────────────────────────────────────────────────────────

def load_and_merge(input_files: List[Path], args) -> tuple:
    """
    Ritorna (records, detected_formats) dove detected_formats è
    la lista dei formati trovati per determinare l'output migliore.
    """
    all_records: List[Dict] = []
    all_formats: List[str]  = []
    source_stats: Dict[str, Dict] = {}

    # ── FASE 1: Caricamento ───────────────────────────────────────────────────
    for filepath in input_files:
        fname   = filepath.name
        size_mb = filepath.stat().st_size / 1e6
        print(f"\n[*] {fname}  ({size_mb:.1f} MB)")

        total_lines = sum(1 for _ in open(filepath, "rb"))
        t0 = time.time()
        loaded = kept = 0
        fmt_counter = Counter()
        rej = Counter()
        source_stats[fname] = {}

        with filepath.open(encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line: continue
                try:
                    r = json.loads(line)
                except Exception:
                    rej["json_error"] += 1; continue

                loaded += 1
                rec = extract_record(r, fname)
                if rec is None:
                    rej["no_content"] += 1; continue

                # Calcola segnali se mancanti
                if rec["signals"] == 0:
                    rec["signals"] = count_signals(rec["content"])
                # Inferisci e normalizza lingua se mancante
                if rec["lang"] in ("unknown", "", None):
                    rec["lang"] = normalize_lang(infer_language(rec["content"]))
                else:
                    rec["lang"] = normalize_lang(rec["lang"])
                # Risolvi tier '?' usando i segnali calcolati
                rec["tier"] = resolve_tier(rec["tier"], rec["signals"])
                # Lingua mista: se contenuto ha blocchi di più lingue,
                # usa la lingua del blocco più lungo come lingua principale
                if rec["lang"] == "unknown":
                    rec["lang"] = infer_dominant_language(rec["content"])

                fmt_counter[rec["fmt"]] += 1
                all_formats.append(rec["fmt"])
                all_records.append(rec)
                kept += 1

                if (i + 1) % 2000 == 0:
                    print_progress(i + 1, total_lines, kept, t0, fname[:20])

        print_progress(total_lines, total_lines, kept, t0, fname[:20])
        print()
        source_stats[fname] = {
            "loaded": loaded, "kept": kept,
            "formats": dict(fmt_counter), "rejected": dict(rej)
        }
        print(f"    Formati: {dict(fmt_counter)}  |  Scartati: {dict(rej)}")

    # ── FASE 2: Deduplicazione cross-file ─────────────────────────────────────
    print(f"\n[*] Deduplicazione cross-file su {len(all_records):,} record...")

    # Priorità: più signals → più score → formato più ricco → prima sorgente
    all_records.sort(key=lambda x: (
        -x["signals"], -x["score"],
        -FORMAT_PRIORITY.get(x["fmt"], 0)
    ))

    seen_exact: set = set()
    seen_near:  set = set()
    deduped: List[Dict] = []
    dupes_e = dupes_n = 0
    t0 = time.time()

    for i, rec in enumerate(all_records):
        h_e = hashlib.sha256(
            rec["content"].encode("utf-8", errors="replace")
        ).digest()[:12]
        if h_e in seen_exact:
            dupes_e += 1; continue
        seen_exact.add(h_e)

        norm = re.sub(r'\s+', ' ', rec["content"].lower())
        h_n  = hashlib.md5((norm[:512] + norm[-512:]).encode()).digest()[:8]
        if h_n in seen_near:
            dupes_n += 1; continue
        seen_near.add(h_n)

        deduped.append(rec)
        if (i + 1) % 5000 == 0:
            print_progress(i + 1, len(all_records), len(deduped), t0, "dedup")

    print_progress(len(all_records), len(all_records), len(deduped), t0, "dedup")
    print(f"\n    Rimossi duplicati esatti: {dupes_e:,}")
    print(f"    Rimossi duplicati simili: {dupes_n:,}")
    print(f"    Dopo dedup: {len(deduped):,}")

    # ── FASE 3: Filtri qualità ─────────────────────────────────────────────────
    print(f"\n[*] Filtri qualità...")
    filtered: List[Dict] = []
    rej = Counter()

    for rec in deduped:
        c = rec["content"]
        if len(c) < args.min_chars:             rej["too_short"] += 1; continue
        if args.max_chars > 0 and len(c) > args.max_chars:
                                                rej["too_long"]  += 1; continue
        if len(c.splitlines()) < args.min_lines: rej["few_lines"] += 1; continue
        if args.min_signals > 0 and rec["signals"] < args.min_signals:
                                                rej["low_signals"]+= 1; continue
        filtered.append(rec)

    print(f"    Dopo filtri: {len(filtered):,}  scarti: {dict(rej)}")

    # ── FASE 4: Cap per lingua/repo ───────────────────────────────────────────
    print(f"\n[*] Limiti per lingua/repo...")
    lang_cnt = defaultdict(int)
    repo_cnt = defaultdict(int)
    final: List[Dict] = []
    capped = Counter()

    for rec in filtered:
        lang = rec["lang"]
        repo = rec["repo"]
        if args.max_per_language and lang_cnt[lang] >= args.max_per_language:
            capped[f"lang_{lang}"] += 1; continue
        if args.max_per_repo and repo_cnt[repo] >= args.max_per_repo:
            capped["repo"] += 1; continue
        final.append(rec)
        lang_cnt[lang] += 1
        repo_cnt[repo] += 1

    cap_lang = sum(v for k, v in capped.items() if k.startswith("lang_"))
    print(f"    Dopo limiti: {len(final):,}"
          + (f"  lang_cap: {cap_lang:,}" if cap_lang else "")
          + (f"  repo_cap: {capped.get('repo',0):,}" if capped.get("repo") else ""))

    return final, all_formats, source_stats

# ─── REPORT FINALE ────────────────────────────────────────────────────────────

def print_report(records: List[Dict], source_stats: Dict,
                 out_fmt: str, out_file: str) -> None:
    n = len(records)
    print(f"\n{'═'*72}")
    print(f"  📊 REPORT MERGE — {n:,} esempi → {out_file}  [formato: {out_fmt}]")
    print(f"{'═'*72}")

    # Per sorgente
    by_src = Counter(r["source"] for r in records)
    print(f"\n  Contributo per sorgente:")
    for src, cnt in by_src.most_common():
        pct = cnt / n * 100
        print(f"    {src:<45} {cnt:>7,}  ({pct:5.1f}%)  {'█'*int(pct/2)}")

    # Formato sorgente originale
    by_fmt = Counter(r["fmt"] for r in records)
    print(f"\n  Formati di input nel risultato finale:")
    for fmt, cnt in by_fmt.most_common():
        print(f"    {fmt:<12} {cnt:>7,}  ({cnt/n*100:5.1f}%)")

    # Lingua
    by_lang = Counter(r["lang"] for r in records)
    print(f"\n  Distribuzione linguaggi:")
    for lang, cnt in by_lang.most_common():
        pct = cnt / n * 100
        print(f"    {lang:<15} {cnt:>7,}  ({pct:5.1f}%)  {'█'*int(pct/2)}")

    # Segnali
    sig = Counter(r["signals"] for r in records)
    with_sig = sum(v for k, v in sig.items() if k > 0)
    print(f"\n  Con ≥1 segnale cyber: {with_sig:,} / {n:,}  ({with_sig/n*100:.1f}%)")
    for k in sorted(sig)[:8]:
        print(f"    {k:>2} segnali → {sig[k]:>7,}  ({sig[k]/n*100:.1f}%)")

    # Lunghezze
    lens = sorted(len(r["content"]) for r in records)
    print(f"\n  Lunghezze (chars):  avg {sum(lens)/n:,.0f}  |  "
          f"p50 {lens[n//2]:,}  p95 {lens[int(n*.95)]:,}  max {lens[-1]:,}")

    print(f"{'═'*72}\n")

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Dataset Merger v2 — unisce N JSONL di formati diversi",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # Input
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--inputs",     nargs="+",
                   help="File JSONL di input (anche formati diversi)")
    g.add_argument("--scan-dir",   type=str,
                   help="Scansiona una directory e trova tutti i JSONL automaticamente")
    parser.add_argument("--no-recursive", action="store_true",
                        help="Con --scan-dir: non scansionare sottocartelle")

    # Output
    parser.add_argument("--output",      default="merged_gold.jsonl")
    parser.add_argument("--out-eval",    default="merged_eval.jsonl")
    parser.add_argument("--out-format",  default="auto",
                        choices=["auto", "native", "text", "training", "messages"],
                        help=(
                            "auto    = usa il formato più ricco trovato negli input\n"
                            "native  = ogni record mantiene il suo formato originale\n"
                            "text    = forza tutto in {text:...}\n"
                            "training= forza tutto in {instruction/output/metadata}\n"
                            "messages= forza tutto in {messages:[...]}"
                        ))

    # Filtri
    parser.add_argument("--min-chars",        type=int, default=300)
    parser.add_argument("--max-chars",        type=int, default=0,
                        help="0 = nessun limite superiore")
    parser.add_argument("--min-lines",        type=int, default=5)
    parser.add_argument("--min-signals",      type=int, default=0,
                        help="0 = includi tutto, >0 = solo esempi con segnali cyber")

    # Limiti
    parser.add_argument("--max-per-language", type=int, default=0)
    parser.add_argument("--max-per-repo",     type=int, default=0)

    # Split
    parser.add_argument("--eval-ratio",       type=float, default=0.05)

    args = parser.parse_args()

    # Raccolta file di input
    if args.scan_dir:
        scan_path = Path(args.scan_dir)
        if not scan_path.is_dir():
            print(f"[ERRORE] Directory non trovata: {scan_path}", file=sys.stderr)
            sys.exit(1)
        print(f"\n[*] Scansione: {scan_path}")
        input_files = scan_dir_for_jsonl(scan_path, recursive=not args.no_recursive)
        if not input_files:
            print("[ERRORE] Nessun JSONL trovato.", file=sys.stderr)
            sys.exit(1)
    else:
        input_files = []
        for p in args.inputs:
            path = Path(p)
            if not path.is_file():
                print(f"[ERRORE] Non trovato: {path}", file=sys.stderr)
                sys.exit(1)
            input_files.append(path)

    print(f"\n[*] Dataset Merger v2 — {len(input_files)} file di input")
    for f in input_files:
        print(f"    → {f.name}  ({f.stat().st_size/1e6:.1f} MB)")

    t_start = time.time()

    records, all_formats, source_stats = load_and_merge(input_files, args)

    if not records:
        print("[ERRORE] Nessun record dopo il merge.", file=sys.stderr)
        sys.exit(1)

    # Determina formato output
    if args.out_format == "auto":
        out_fmt = best_format(all_formats)
        print(f"\n[*] Formato output AUTO rilevato: {out_fmt.upper()}")
    else:
        out_fmt = args.out_format
        print(f"\n[*] Formato output: {out_fmt.upper()}")

    # Report
    print_report(records, source_stats, out_fmt, args.output)

    # Split deterministico train/eval
    train_recs, eval_recs = [], []
    for rec in records:
        h = int(hashlib.sha1(
            rec["content"].encode("utf-8", errors="replace")
        ).hexdigest(), 16)
        if args.eval_ratio > 0 and (h % 10000) < int(args.eval_ratio * 10000):
            eval_recs.append(rec)
        else:
            train_recs.append(rec)

    # Scrittura
    def write_jsonl(path: str, recs: List[Dict], fmt: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for rec in recs:
                f.write(json.dumps(format_output(rec, fmt),
                                   ensure_ascii=False) + "\n")

    write_jsonl(args.output, train_recs, out_fmt)
    print(f"[OK] Train: {args.output}  ({len(train_recs):,} esempi)")

    if eval_recs:
        write_jsonl(args.out_eval, eval_recs, out_fmt)
        print(f"[OK] Eval:  {args.out_eval}  ({len(eval_recs):,} esempi)")

    print(f"[*] Tempo totale: {fmt_eta(time.time()-t_start)}\n")


if __name__ == "__main__":
    main()
