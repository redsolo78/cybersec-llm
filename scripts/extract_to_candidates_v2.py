#!/usr/bin/env python3
"""
extract_to_candidates_v2.py

Versione aggiornata che carica i pattern offensivi da file JSON esterno
"""

import argparse
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import List, Dict


# Modifica questo nel file extract_to_candidates_v2.py
EXT_TO_LANG = {
    ".c": "c",
    ".cc": "c_cpp",
    ".cpp": "c_cpp",
    ".cxx": "c_cpp",
    ".h": "c_cpp",
    ".hpp": "c_cpp",
    ".rs": "rust",
    ".go": "go",
    ".py": "python",
    ".pyi": "python",
    ".cs": "csharp",
    ".csx": "csharp",
    ".ps1": "powershell",  # AGGIUNTO
    ".psm1": "powershell"  # AGGIUNTO
}

PATTERNS_FILE = "offensive_patterns_2026.json"


def load_offensive_patterns() -> List[str]:
    if not os.path.exists(PATTERNS_FILE):
        print(f"[ERRORE] File pattern non trovato: {PATTERNS_FILE}")
        print("  → Creane uno con la struttura mostrata nel messaggio precedente")
        raise FileNotFoundError(PATTERNS_FILE)

    with open(PATTERNS_FILE, encoding="utf-8") as f:
        data = json.load(f)

    patterns = []
    # Appiattiamo tutte le categorie
    for category, lst in data.get("categories", {}).items():
        patterns.extend(lst)

    print(f"[INFO] Caricati {len(patterns)} pattern offensivi da {PATTERNS_FILE}")
    # Pre-compiliamo le regex (case-insensitive)
    return [re.compile(p, re.IGNORECASE) for p in patterns if p.strip()]


# Carichiamo i pattern una volta sola
OFFENSIVE_REGEXES = load_offensive_patterns()


def get_language_from_ext(path: Path) -> str:
    ext = path.suffix.lower()
    return EXT_TO_LANG.get(ext, "unknown")


def count_offensive_signals(content: str) -> int:
    count = 0
    content_lower = content.lower()
    for regex in OFFENSIVE_REGEXES:
        if regex.search(content_lower):
            count += 1
    return count


def get_file_tier(signal_count: int, line_count: int) -> str:
    if signal_count >= 5:
        return "A+"
    if signal_count >= 3 or line_count >= 250:
        return "A"
    if signal_count >= 1 or line_count >= 100:
        return "B"
    return "C"


def compute_file_score(signal_count: int, line_count: int, nonempty_count: int) -> int:
    base = min(line_count // 15, 25)
    signal_bonus = signal_count * 5
    nonempty_bonus = min(nonempty_count // 40, 15)
    return base + signal_bonus + nonempty_bonus


def sha1_text(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def extract_preview(content: str, max_chars: int = 400) -> str:
    preview = content[:max_chars].replace("\n", "\\n").strip()
    if len(content) > max_chars:
        preview += " ..."
    return preview


def process_directory(input_dir: Path, max_preview_chars: int) -> List[Dict]:
    candidates = []
    total_files = 0
    lang_counter = Counter()
    tier_counter = Counter()
    signal_histogram = Counter()

    for root, _, files in os.walk(input_dir):
        repo_path = Path(root)
        repo_folder = repo_path.name
        repo_id = repo_folder.replace("__", "/")

        for file in files:
            file_path = repo_path / file
            total_files += 1

            if file_path.suffix.lower() not in EXT_TO_LANG:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                if not content.strip():
                    continue

                lines = content.splitlines()
                line_count = len(lines)
                nonempty_count = sum(1 for l in lines if l.strip())

                language = get_language_from_ext(file_path)
                signal_count = count_offensive_signals(content)
                signal_histogram[signal_count] += 1

                file_tier = get_file_tier(signal_count, line_count)
                file_score = compute_file_score(signal_count, line_count, nonempty_count)

                relative_path = str(file_path.relative_to(input_dir))

                candidate = {
                    "repo_id": repo_id,
                    "repo_path": str(repo_path.absolute()),
                    "relative_path": relative_path,
                    "language": language,
                    "bytes_size": file_path.stat().st_size,
                    "line_count": line_count,
                    "nonempty_line_count": nonempty_count,
                    "code_signal_count": signal_count,
                    "file_score": file_score,
                    "file_tier": file_tier,
                    "sha1": sha1_text(content),
                    "preview": extract_preview(content, max_preview_chars),
                    "cluster": "unknown",
                    "term": "unknown",
                }

                candidates.append(candidate)
                lang_counter[language] += 1
                tier_counter[file_tier] += 1

            except Exception as e:
                print(f"Errore lettura {file_path}: {e}")

    print(f"[*] Trovati {len(candidates)} file candidati su {total_files} file totali")
    print(f"    Linguaggi: {dict(lang_counter.most_common(10))}")
    print(f"    Tier distrib: {dict(tier_counter)}")
    print(f"    Signal count histogram: {dict(signal_histogram.most_common(15))}")

    return candidates


def main():
    parser = argparse.ArgumentParser(description="Estrae file_candidates.jsonl da extracted_code/ (v2)")
    parser.add_argument("--input-dir", default="extracted_code")
    parser.add_argument("--output", default="file_candidates.jsonl")
    parser.add_argument("--patterns-file", default="offensive_patterns_2026.json",
                        help="Percorso al file JSON dei pattern")
    parser.add_argument("--max-preview-chars", type=int, default=400)
    parser.add_argument("--stats", action="store_true")
    args = parser.parse_args()

    # Permettiamo di override il file dei pattern
    global PATTERNS_FILE, OFFENSIVE_REGEXES
    PATTERNS_FILE = args.patterns_file
    OFFENSIVE_REGEXES = load_offensive_patterns()

    input_dir = Path(args.input_dir).resolve()
    if not input_dir.is_dir():
        print(f"[ERRORE] Directory non trovata: {input_dir}")
        return 1

    print(f"[*] Scansione di: {input_dir}")

    candidates = process_directory(input_dir, args.max_preview_chars)

    if not candidates:
        print("[AVVISO] Nessun file candidato trovato.")
        return 0

    candidates.sort(key=lambda x: (-x["file_score"], x["repo_id"], x["relative_path"]))

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        for cand in candidates:
            f.write(json.dumps(cand, ensure_ascii=False) + "\n")

    print(f"[OK] Scritto {len(candidates):,} record in {output_path}")

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
