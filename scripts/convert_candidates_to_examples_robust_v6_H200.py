#!/usr/bin/env python3
"""
convert_candidates_to_examples_robust_v6_H200.py
=================================================
FIX rispetto alla v5:
  - ETA ricalcolato su esempi prodotti (non righe lette) → accurato anche
    quando ogni riga del candidates espande decine/centinaia di file
  - Rolling window (ultimi 10 checkpoint) per speed/ETA più stabili
  - --max-per-language: cap per linguaggio già in fase di conversione
    (evita che ps1 domini al 56% il dataset di input del gold filter)
  - --max-per-repo: cap per repository già in fase di conversione
  - Report finale con istogramma bilanciamento linguaggi
  - Rimosso import random inutilizzato

Utilizzo tipico:
    python3 convert_candidates_to_examples_robust_v6_H200.py \\
        --input file_candidates_v2.jsonl \\
        --outdir output_final_h200_v3 \\
        --max-per-language 150000 \\
        --max-per-repo 500
"""

import argparse
import json
import hashlib
import os
import time
from pathlib import Path
from collections import Counter, defaultdict


VALID_EXTENSIONS = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',
                    '.rs', '.go', '.py', '.cs', '.ps1', '.psm1'}


# ─── ETA ────────────────────────────────────────────────────────────────────
# L'ETA è calcolato sugli ESEMPI PRODOTTI (non sulle righe lette),
# perché ogni riga del candidates può espandere 1..N file.
# Usiamo una rolling window degli ultimi WINDOW checkpoint per
# stimare la velocità corrente invece di quella media dall'inizio.

_ETA_WINDOW: list = []   # lista di (timestamp, esempi_prodotti)
_ETA_WINDOW_SIZE = 10    # ultimi 10 checkpoint


def fmt_eta(seconds: float) -> str:
    if seconds <= 0 or seconds != seconds:  # nan/inf guard
        return "--:--"
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    if h > 0:
        return f"{h}h {m:02d}m {s:02d}s"
    return f"{m}m {s:02d}s"


def print_eta(kept: int, total_target: int,
              lang_counts: dict, max_per_lang: int) -> None:
    """
    kept         = esempi prodotti finora
    total_target = stima del totale atteso (0 = sconosciuto → ETA su velocità)
    """
    now = time.time()
    _ETA_WINDOW.append((now, kept))
    if len(_ETA_WINDOW) > _ETA_WINDOW_SIZE:
        _ETA_WINDOW.pop(0)

    # Speed dalla rolling window (esempi/sec)
    if len(_ETA_WINDOW) >= 2:
        dt      = _ETA_WINDOW[-1][0] - _ETA_WINDOW[0][0]
        d_kept  = _ETA_WINDOW[-1][1] - _ETA_WINDOW[0][1]
        speed   = d_kept / dt if dt > 0 else 0
    else:
        speed = 0

    # ETA: se conosciamo il totale atteso lo usiamo, altrimenti solo speed
    if total_target > 0 and speed > 0:
        remain = (total_target - kept) / speed
        pct    = kept / total_target * 100
        pct_str = f"{pct:5.1f}%"
    else:
        remain = 0
        pct_str = "  ?  "

    top_langs = sorted(lang_counts.items(), key=lambda x: -x[1])[:3]
    lang_str  = "  ".join(
        f"{l}:{c:,}{'⚠' if max_per_lang and c >= max_per_lang else ''}"
        for l, c in top_langs
    )

    print(
        f"\r  kept: {kept:>10,} | {pct_str} | "
        f"{speed:>7,.0f} ex/s | ETA: {fmt_eta(remain):>10} | "
        f"{lang_str}          ",
        end="", flush=True
    )


# ─── DEDUP / SPLIT ──────────────────────────────────────────────────────────

def deterministic_eval_split(content: str, eval_ratio: float) -> bool:
    """Deterministico su SHA1 del contenuto — riproducibile su più run."""
    h = int(hashlib.sha1(content.encode("utf-8", errors="replace")).hexdigest(), 16)
    return (h % 10000) < int(eval_ratio * 10000)


# ─── MAIN ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Converter candidates → training examples v5",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input",            default="file_candidates_v2.jsonl")
    parser.add_argument("--outdir",           default="output_final_h200")
    parser.add_argument("--eval-ratio",       type=float, default=0.05)
    parser.add_argument("--min-chars",        type=int,   default=50)
    parser.add_argument("--max-bytes",        type=int,   default=1_000_000)
    parser.add_argument("--max-per-language", type=int,   default=0,
                        help="Max esempi per linguaggio (0=illimitato). "
                             "Consigliato: 150000 per bilanciare ps1 vs c/go")
    parser.add_argument("--max-per-repo",     type=int,   default=0,
                        help="Max esempi per repository (0=illimitato)")
    parser.add_argument("--eta-every",        type=int,   default=5_000,
                        help="Stampa ETA ogni N esempi convertiti")
    args = parser.parse_args()

    # ── Conteggio righe per ETA preciso ─────────────────────────────────────
    print(f"[*] Conteggio righe input (per ETA accurato)…")
    t0 = time.time()
    total_lines = 0
    with open(args.input, "rb") as f:
        for _ in f:
            total_lines += 1
    print(f"[*] Righe totali: {total_lines:,}  ({time.time()-t0:.1f}s)\n")

    # ── Setup output ─────────────────────────────────────────────────────────
    out_path = Path(args.outdir)
    out_path.mkdir(parents=True, exist_ok=True)
    train_file = out_path / "train_examples.jsonl"
    eval_file  = out_path / "eval_examples.jsonl"

    stats      = Counter()
    lang_counts = defaultdict(int)   # per cap linguaggio
    repo_counts = defaultdict(int)   # per cap repo
    converted  = 0
    line_num   = 0

    print(f"[*] Avvio conversione v5…")
    if args.max_per_language:
        print(f"    Max per linguaggio: {args.max_per_language:,}")
    if args.max_per_repo:
        print(f"    Max per repo:       {args.max_per_repo:,}")
    print()

    with open(args.input, "r", encoding="utf-8") as fin, \
         open(train_file, "w", encoding="utf-8") as f_train, \
         open(eval_file,  "w", encoding="utf-8") as f_eval:

        for raw_line in fin:
            line_num += 1

            # ETA ogni eta_every ESEMPI PRODOTTI (non righe lette)
            if converted > 0 and converted % args.eta_every == 0:
                # Stima totale: proiezione lineare basata su quanti file
                # per riga abbiamo visto finora
                avg_files_per_line = converted / line_num if line_num > 0 else 1
                total_target = int(total_lines * avg_files_per_line)
                print_eta(converted, total_target,
                          lang_counts, args.max_per_language)

            try:
                data = json.loads(raw_line)
            except Exception:
                stats["json_error"] += 1
                continue

            base_path = data.get("repo_path")
            if not base_path:
                stats["no_repo_path"] += 1
                continue

            # Campi candidate preservati nel metadata output
            repo_id      = data.get("repo_id", "unknown")
            cluster      = data.get("cluster", "unknown")
            term         = data.get("term", "unknown")
            file_score   = data.get("file_score", 0)
            signal_count = data.get("code_signal_count", 0)
            file_tier    = data.get("file_tier", data.get("tier", "C"))

            # ── Cap per repo ─────────────────────────────────────────────
            if args.max_per_repo and repo_counts[repo_id] >= args.max_per_repo:
                stats["repo_cap"] += 1
                continue

            # ── Risoluzione path (file o directory) ──────────────────────
            files_to_process = []
            p = Path(base_path)
            if p.is_dir():
                for root, _, files in os.walk(base_path):
                    for f in files:
                        if Path(f).suffix.lower() in VALID_EXTENSIONS:
                            files_to_process.append(Path(root) / f)
            elif p.is_file():
                files_to_process.append(p)
            else:
                stats["not_found"] += 1
                continue

            for file_path in files_to_process:
                try:
                    lang = file_path.suffix[1:].lower()

                    # ── Cap per linguaggio ───────────────────────────────
                    if args.max_per_language and lang_counts[lang] >= args.max_per_language:
                        stats[f"lang_cap_{lang}"] += 1
                        continue

                    if file_path.stat().st_size > args.max_bytes:
                        stats["too_large"] += 1
                        continue

                    content = file_path.read_text(
                        encoding="utf-8", errors="ignore"
                    ).strip()

                    if len(content) < args.min_chars:
                        stats["too_short"] += 1
                        continue

                    example = {
                        "instruction": (
                            f"Provide the implementation of this {lang} "
                            f"code from project {repo_id}."
                        ),
                        "input": "",
                        "output": content,
                        "metadata": {
                            "original_path":     str(file_path),
                            "relative_path":     data.get("relative_path", ""),
                            "language":          lang,
                            "repo_id":           repo_id,
                            "cluster":           cluster,
                            "term":              term,
                            # Campi critici per il gold filter
                            "tier":              file_tier,
                            "file_score":        file_score,
                            "code_signal_count": signal_count,
                            "line_count":        data.get("line_count", 0),
                        }
                    }

                    is_eval = deterministic_eval_split(content, args.eval_ratio)
                    target  = f_eval if is_eval else f_train
                    target.write(json.dumps(example, ensure_ascii=False) + "\n")

                    converted += 1
                    lang_counts[lang] += 1
                    repo_counts[repo_id] += 1
                    stats[lang] += 1

                except Exception:
                    stats["read_error"] += 1

    # ── Riga ETA finale ──────────────────────────────────────────────────────
    print_eta(converted, converted,
              lang_counts, args.max_per_language)
    print()  # newline dopo la riga ETA

    # ── Report finale ────────────────────────────────────────────────────────
    t_end    = time.time()
    duration = t_end - (_ETA_WINDOW[0][0] if _ETA_WINDOW else t_end)
    print(f"\n{'='*60}")
    print(f"  CONVERSIONE COMPLETATA — v6")
    print(f"{'='*60}")
    print(f"  Esempi totali:  {converted:,}")
    print(f"  Tempo totale:   {fmt_eta(duration)}")
    print(f"  Velocità media: {converted/duration:,.0f} esempi/sec")
    print(f"  Train: {train_file}")
    print(f"  Eval:  {eval_file}")

    # Bilanciamento linguaggi
    lang_keys = sorted(
        {k for k in stats if k not in
         {"not_found","too_large","too_short","read_error",
          "json_error","no_repo_path","repo_cap"} and not k.startswith("lang_cap_")},
        key=lambda x: -stats[x]
    )
    print(f"\n  {'LINGUAGGIO':<12} {'ESEMPI':>10}  {'%':>6}  {'BAR'}")
    for lang in lang_keys:
        cnt = stats[lang]
        pct = cnt / converted * 100 if converted else 0
        bar = "█" * int(pct / 2)
        cap_warn = " ← CAP RAGGIUNTO" if (
            args.max_per_language and cnt >= args.max_per_language
        ) else ""
        print(f"  {lang:<12} {cnt:>10,}  {pct:>5.1f}%  {bar}{cap_warn}")

    # Scarti
    scrap_keys = ["too_large", "too_short", "not_found",
                  "read_error", "json_error", "repo_cap"]
    lang_cap_total = sum(v for k, v in stats.items() if k.startswith("lang_cap_"))
    print(f"\n  SCARTI:")
    for k in scrap_keys:
        if stats[k]:
            print(f"    {k:<16}: {stats[k]:,}")
    if lang_cap_total:
        print(f"    {'lang_cap (tot)':<16}: {lang_cap_total:,}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()