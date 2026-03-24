#!/usr/bin/env python3
"""
hf_eval.py — Valuta rapidamente qualsiasi dataset HuggingFace
=============================================================
Uso:
    python3 hf_eval.py WNT3D/Ultimate-Offensive-Red-Team
    python3 hf_eval.py sh111111111111111/red_team --sample 1000
    python3 hf_eval.py nome/repo --split test --token hf_xxx
"""

import argparse
import hashlib
import json
import re
import sys
import os
from collections import Counter
from pathlib import Path

# ─── ETA / colori ─────────────────────────────────────────────────────────────
C = {"RED":"\033[91m","GREEN":"\033[92m","YELLOW":"\033[93m",
     "CYAN":"\033[96m","BOLD":"\033[1m","RESET":"\033[0m"}
def cp(t, c=""): print(f"{C.get(c,'')}{t}{C['RESET']}")

# ─── CHECKLIST ────────────────────────────────────────────────────────────────

CYBER_PATTERNS = [
    r"CVE-\d{4}-\d+", r"shellcode", r"payload", r"exploit",
    r"amsi.bypass", r"mimikatz", r"syscall", r"ntdll", r"backdoor",
    r"reverse.shell", r"privilege.escal", r"inject", r"beacon",
    r"rootkit", r"byovd", r"unhook", r"lsass", r"kerberoast",
    r"dcsync", r"token.steal", r"process.hollow", r"reflective",
]

CODE_PATTERNS = [
    r"def\s+\w+\s*\(", r"#include\s*<", r"func\s+\w+\s*\(",
    r"^import\s+\w+", r"^from\s+\w+\s+import", r"public\s+class\s+\w+",
    r"^fn\s+\w+\s*\(", r"^package\s+\w+", r"void\s+\w+\s*\(",
    r"int\s+main\s*\(", r"using\s+System", r"Invoke-\w+",
]

def has_code(text: str) -> bool:
    return any(re.search(p, text, re.MULTILINE | re.IGNORECASE) for p in CODE_PATTERNS)

def count_cyber(text: str) -> int:
    return sum(1 for p in CYBER_PATTERNS if re.search(p, text, re.IGNORECASE))

def detect_content_field(r: dict) -> str:
    """Trova il campo che contiene il contenuto principale."""
    # Formato training
    if "output" in r and r.get("output"):
        return "output"
    # Formato flat system/user/assistant (es. Fenrir-v2.0)
    if "assistant" in r and r.get("assistant"):
        return "assistant"
    # Formato messages
    if "messages" in r:
        for msg in r["messages"]:
            if msg.get("role") == "assistant":
                return "__assistant__"
    # ChatML
    if "text" in r and "<|im_start|>" in r.get("text", ""):
        return "__chatml_assistant__"
    # Altri
    for field in ["text", "content", "response", "answer", "code"]:
        if field in r and r[field]:
            return field
    return None

def extract_content(r: dict, field: str) -> str:
    if field == "__assistant__":
        for msg in r.get("messages", []):
            if msg.get("role") == "assistant":
                return msg.get("content", "")
        return ""
    if field == "__chatml_assistant__":
        text = r.get("text", "")
        parts = text.split("<|im_start|>assistant")
        if len(parts) > 1:
            return parts[1].split("<|im_end|>")[0].strip()
        return ""
    return str(r.get(field, ""))

def grade(val, thresholds, reverse=False):
    """Assegna un colore in base alle soglie."""
    if reverse:
        if val <= thresholds[0]: return "GREEN"
        if val <= thresholds[1]: return "YELLOW"
        return "RED"
    else:
        if val >= thresholds[0]: return "GREEN"
        if val >= thresholds[1]: return "YELLOW"
        return "RED"

# ─── MULTI-CONFIG LOADER ──────────────────────────────────────────────────────

def _discover_subdirs(repo, token):
    """Scopre le sottocartelle data/* del repo tramite HF Hub file listing."""
    try:
        from huggingface_hub import list_repo_files
        kw = {"token": token} if token else {}
        files = list(list_repo_files(repo, repo_type="dataset", **kw))
        subdirs = []
        seen = set()
        for f in files:
            m = re.match(r"data/([^/]+)/", f)
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                subdirs.append(m.group(1))
        return subdirs
    except Exception:
        return []

def _load_subdir(repo, subdir, per_cfg, token, load_dataset):
    """Carica una sottocartella parquet direttamente bypassando la config HF."""
    import random
    kw = {"token": token} if token else {}
    url = f"hf://datasets/{repo}/data/{subdir}/*.parquet"
    for use_stream in (False, True):
        try:
            kw["streaming"] = use_stream
            ds = load_dataset("parquet", data_files={"train": url}, split="train", **kw)
            if use_stream:
                recs = []
                for row in ds:
                    recs.append(dict(row, _config=subdir))
                    if len(recs) >= per_cfg:
                        break
            else:
                total = len(ds)
                n_take = min(per_cfg, total)
                idx = sorted(random.sample(range(total), n_take)) if total > per_cfg else range(total)
                recs = [dict(ds[i], _config=subdir) for i in idx]
            return recs
        except Exception as e2:
            if not use_stream:
                continue
            cp(f"  ⚠️  Subdir '{subdir}' fallita: {str(e2)[:70]}", "YELLOW")
            return []
    return []

def load_multiconfig(repo, sample, token, load_dataset):
    """Carica un dataset multi-config caricando ogni subdir parquet separatamente."""
    # Prima prova get_dataset_config_names (escludendo 'default' se unica)
    named_configs = []
    try:
        from datasets import get_dataset_config_names
        kw = {"token": token} if token else {}
        cfgs = get_dataset_config_names(repo, **kw)
        if cfgs and not (len(cfgs) == 1 and cfgs[0] == "default"):
            named_configs = cfgs
    except Exception:
        pass

    # Fallback: scopri sottocartelle dal file listing
    subdirs = named_configs if named_configs else _discover_subdirs(repo, token)

    if not subdirs:
        cp(f"  ⚠️  Impossibile determinare le sottocartelle del dataset.", "YELLOW")
        return [], []

    cp(f"\n  ℹ️  Dataset multi-config — subdir trovate: {subdirs}", "CYAN")
    per_cfg = max(1, sample // len(subdirs))

    all_records, loaded = [], []
    for sd in subdirs:
        recs = _load_subdir(repo, sd, per_cfg, token, load_dataset)
        if recs:
            cp(f"  ✅ '{sd}': {len(recs)} record", "GREEN")
            all_records.extend(recs)
            loaded.append(sd)
        # se named_config, prova anche load_dataset(repo, sd, split="train")
        elif named_configs:
            import random
            kw2 = {"token": token} if token else {}
            for use_stream in (False, True):
                try:
                    kw2["streaming"] = use_stream
                    ds = load_dataset(repo, sd, split="train", **kw2)
                    if use_stream:
                        r2 = []
                        for row in ds:
                            r2.append(dict(row, _config=sd))
                            if len(r2) >= per_cfg: break
                    else:
                        total = len(ds)
                        n = min(per_cfg, total)
                        idx = sorted(random.sample(range(total), n)) if total > per_cfg else range(total)
                        r2 = [dict(ds[i], _config=sd) for i in idx]
                    cp(f"  ✅ Config '{sd}': {len(r2)} record", "GREEN")
                    all_records.extend(r2)
                    loaded.append(sd)
                    break
                except Exception:
                    if not use_stream: continue
                    break

    return all_records[:sample], loaded

# ─── RMCBENCH ─────────────────────────────────────────────────────────────────

def is_rmcbench(r: dict) -> bool:
    """Rileva il formato RMCBench (zhongqy/RMCBench)."""
    return ("malicious categories" in r or "malicious functionality" in r) and "original code" in r

def analyze_rmcbench(records: list, save_path=None) -> None:
    n = len(records)
    cp(f"\n  ℹ️  Formato rilevato: RMCBench (refusal malicious code benchmark)", "CYAN")

    # Raccolta dati
    categories = Counter(str(r.get("category", "?")) for r in records)
    levels     = Counter(str(r.get("level", "?"))    for r in records)
    tasks      = Counter(str(r.get("task", "?"))     for r in records)

    mal_cats = Counter()
    for r in records:
        mc = r.get("malicious categories", "")
        if isinstance(mc, list):
            for c in mc: mal_cats[str(c).strip()] += 1
        elif mc:
            for c in str(mc).split(","):
                c = c.strip()
                if c: mal_cats[c] += 1

    mal_funcs = Counter()
    for r in records:
        mf = str(r.get("malicious functionality", "")).strip()
        if mf: mal_funcs[mf[:60]] += 1

    # original code stats
    codes = [str(r.get("original code", "")) for r in records]
    has_orig = sum(1 for c in codes if c and len(c) > 10)
    pct_has_orig = has_orig / n * 100
    code_lens = [len(c) for c in codes if c and len(c) > 10]
    avg_code_len = sum(code_lens) // len(code_lens) if code_lens else 0
    sorted_cl = sorted(code_lens)
    p50_code = sorted_cl[len(sorted_cl)//2] if sorted_cl else 0
    p95_code = sorted_cl[int(len(sorted_cl)*0.95)] if sorted_cl else 0

    # prompt stats
    prompts = [str(r.get("prompt", "")) for r in records]
    prompt_lens = [len(p) for p in prompts if p]
    avg_prompt_len = sum(prompt_lens) // len(prompt_lens) if prompt_lens else 0
    sorted_pl = sorted(prompt_lens)
    p50_prompt = sorted_pl[len(sorted_pl)//2] if sorted_pl else 0
    p95_prompt = sorted_pl[int(len(sorted_pl)*0.95)] if sorted_pl else 0

    # cyber signals
    cyber_in_prompt = sum(1 for p in prompts if count_cyber(p) > 0)
    pct_cyber_prompt = cyber_in_prompt / n * 100
    cyber_in_code   = sum(1 for c in codes  if count_cyber(c) > 0)
    pct_cyber_code  = (cyber_in_code / has_orig * 100) if has_orig else 0

    # code detection (sintattica) nel codice originale
    code_syntactic = sum(1 for c in codes if has_code(c))
    pct_code_syn   = (code_syntactic / has_orig * 100) if has_orig else 0

    # duplicati prompt
    seen_p, dupes_p = set(), 0
    for p in prompts:
        h = hashlib.md5(p.encode("utf-8", errors="replace")).hexdigest()
        if h in seen_p: dupes_p += 1
        else: seen_p.add(h)
    pct_dupes = dupes_p / n * 100

    # ── REPORT ────────────────────────────────────────────────────────────────
    cp(f"\n{'─'*65}", "CYAN")
    cp(f"  📊 RISULTATI CHECK  ({n} record totali)", "BOLD")
    cp(f"{'─'*65}", "CYAN")

    # CHECK 1: copertura original code
    color = grade(pct_has_orig, [80, 50])
    cp(f"\n  CHECK 1 — Original code presente:  {has_orig}/{n} = {pct_has_orig:.0f}%", color)
    if pct_has_orig < 50:
        print(f"            ⚠️  <50% = molti sample senza codice di riferimento")

    # CHECK 2: categorie task
    cp(f"\n  CHECK 2 — Categorie task ({len(categories)} distinte):", "CYAN")
    for cat, cnt in categories.most_common(8):
        bar = "█" * max(1, int(cnt / n * 32))
        print(f"    {cat[:40]:<40} {cnt:>4}  ({cnt/n*100:.1f}%)  {bar}")

    # CHECK 3: distribuzione livelli
    cp(f"\n  CHECK 3 — Distribuzione livelli ({len(levels)} distinti):", "CYAN")
    for lvl, cnt in sorted(levels.items()):
        bar = "█" * max(1, int(cnt / n * 32))
        print(f"    Livello {str(lvl):<8} {cnt:>4}  ({cnt/n*100:.1f}%)  {bar}")

    # CHECK 4: malicious categories top
    cp(f"\n  CHECK 4 — Malicious categories ({len(mal_cats)} distinte, top 12):", "CYAN")
    for mc, cnt in mal_cats.most_common(12):
        print(f"    {mc[:48]:<48} {cnt:>4}  ({cnt/n*100:.1f}%)")

    # CHECK 5: statistiche prompt
    color = grade(avg_prompt_len, [200, 80])
    cp(f"\n  CHECK 5 — Lunghezza prompt:  avg={avg_prompt_len}  p50={p50_prompt}  p95={p95_prompt}", color)
    if avg_prompt_len < 80:
        print(f"            ⚠️  prompt molto corti — possibile scarsa qualità")

    # CHECK 6: statistiche codice originale
    color = grade(avg_code_len, [500, 100])
    cp(f"  CHECK 6 — Lunghezza codice:  avg={avg_code_len}  p50={p50_code}  p95={p95_code}", color)
    cp(f"            Sintassi code rilevata: {code_syntactic}/{has_orig} = {pct_code_syn:.0f}%",
       "GREEN" if pct_code_syn > 60 else "YELLOW")

    # CHECK 7: segnali cyber
    color = grade(pct_cyber_prompt, [50, 20])
    cp(f"  CHECK 7 — Segnali cyber nel prompt: {cyber_in_prompt}/{n} = {pct_cyber_prompt:.0f}%", color)
    color = grade(pct_cyber_code, [40, 15])
    cp(f"  CHECK 8 — Segnali cyber nel codice: {cyber_in_code}/{has_orig} = {pct_cyber_code:.0f}%", color)

    # CHECK 9: duplicati
    color = grade(pct_dupes, [5, 15], reverse=True)
    cp(f"  CHECK 9 — Prompt duplicati: {dupes_p}/{n} = {pct_dupes:.0f}%", color)

    # CHECK 10: malicious functionalities (top 8)
    if mal_funcs:
        cp(f"\n  CHECK 10 — Malicious functionality (top 8):", "CYAN")
        for mf, cnt in mal_funcs.most_common(8):
            print(f"    {mf:<60} {cnt:>3}")

    # ── SCORE ─────────────────────────────────────────────────────────────────
    score = 0
    if pct_has_orig > 80:   score += 25
    elif pct_has_orig > 50: score += 12
    if len(categories) >= 4:  score += 15
    elif len(categories) >= 2: score += 7
    if len(levels) >= 3:  score += 15
    elif len(levels) >= 2: score += 7
    if len(mal_cats) >= 10: score += 20
    elif len(mal_cats) >= 5:  score += 10
    if avg_prompt_len > 200: score += 10
    elif avg_prompt_len > 80: score += 5
    if pct_dupes < 5:   score += 10
    elif pct_dupes < 15: score += 5
    if pct_code_syn > 60: score += 5

    color = "GREEN" if score >= 70 else ("YELLOW" if score >= 40 else "RED")
    cp(f"\n{'═'*65}", "CYAN")
    cp(f"  🏆 SCORE BENCHMARK: {score}/100", color)
    if score >= 70:
        cp(f"  ✅ BENCHMARK SOLIDO — buona copertura e diversità", "GREEN")
    elif score >= 40:
        cp(f"  ⚠️  BENCHMARK MEDIO — coverage o diversità limitata", "YELLOW")
    else:
        cp(f"  ❌ BENCHMARK DEBOLE — manca diversità o codice di riferimento", "RED")
    cp(f"{'═'*65}\n", "CYAN")

    if save_path:
        out = Path(save_path)
        with out.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        cp(f"  💾 Campione salvato: {out}  ({len(records)} record)", "GREEN")

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Valuta un dataset HuggingFace")
    parser.add_argument("repo",           help="HuggingFace repo (es. owner/dataset)")
    parser.add_argument("--sample",  "-n", type=int, default=500,
                        help="Numero di record da campionare (default: 500)")
    parser.add_argument("--split",         default=None,
                        help="Split da usare (default: auto-detect)")
    parser.add_argument("--token",         default=None,
                        help="HF token per repo privati (es. hf_xxxx...)")
    parser.add_argument("--save",          default=None,
                        help="Salva campione in questo file .jsonl")
    args = parser.parse_args()

    # Leggi token da env se non passato da CLI
    if not args.token:
        args.token = os.environ.get("HF_TOKEN")

    # Warning se --token sembra un numero (confusione con --sample)
    if args.token and args.token.isdigit():
        cp(f"[AVVISO] --token '{args.token}' sembra un numero, non un token HF.", "YELLOW")
        cp(f"  Forse intendevi: --sample {args.token}", "YELLOW")
        cp(f"  Il token HF inizia con 'hf_'. Continuo senza token.", "YELLOW")
        args.token = None

    # Warning se il repo contiene * (glob non espanso)
    if "*" in args.repo:
        cp(f"[ERRORE] Il repo contiene '*': {args.repo!r}", "RED")
        cp(f"  La shell espande il glob prima di passarlo allo script.", "RED")
        cp(f"  Usa il nome esatto, es:", "RED")
        cp(f"    python3 hf_eval.py mlfoundations-dev/seed_code_codefeedback_exploit", "YELLOW")
        sys.exit(1)

    # ── Import HF ──────────────────────────────────────────────────────────────
    try:
        from datasets import load_dataset
    except ImportError:
        cp("[ERRORE] datasets non installato. Esegui: pip install datasets", "RED")
        sys.exit(1)

    cp(f"\n{'═'*65}", "CYAN")
    cp(f"  🔍 HF Dataset Evaluator  —  {args.repo}", "BOLD")
    cp(f"{'═'*65}", "CYAN")
    print(f"  Campione: {args.sample} record")

    # ── Caricamento ────────────────────────────────────────────────────────────
    records = []
    split_used = None

    # Prova split specifico o auto-discovery
    splits_to_try = ([args.split] if args.split
                     else ["train", "test", "validation", "data", None])

    for split in splits_to_try:
        try:
            import time as _time
            kwargs = {}
            if args.token: kwargs["token"] = args.token

            # Prova prima senza streaming (più stabile, evita crash PyGILState)
            # con streaming=True solo se il dataset è molto grande
            try:
                if split: kwargs["split"] = split
                ds_check = load_dataset(args.repo, **kwargs)

                # Se non c'è split, prendi il primo disponibile
                if split is None and hasattr(ds_check, "keys"):
                    available = list(ds_check.keys())
                    print(f"  Split disponibili: {available}")
                    split = available[0]
                    ds_check = ds_check[split]

                # Prendi campione direttamente (senza loop streaming)
                total_available = len(ds_check)
                n = min(args.sample, total_available)
                t0 = _time.time()
                print(f"  Caricamento {n:,} / {total_available:,} record...", end="", flush=True)

                # Campiona uniformemente se il dataset è grande
                if total_available > args.sample:
                    import random
                    indices = sorted(random.sample(range(total_available), n))
                    records = [ds_check[i] for i in indices]
                else:
                    records = list(ds_check)

                print(f"\r  ✅ Caricati {len(records):,} record in {_time.time()-t0:.1f}s{' '*20}")

            except Exception as e_nostm:
                # Fallback a streaming se il caricamento diretto fallisce
                if "streaming" in str(e_nostm).lower() or "arrow" in str(e_nostm).lower():
                    raise
                kwargs["streaming"] = True
                if split: kwargs["split"] = split
                ds = load_dataset(args.repo, **kwargs)

                if split is None and hasattr(ds, "keys"):
                    available = list(ds.keys())
                    split = available[0]
                    ds = ds[split]

                count = 0
                t0 = _time.time()
                print(f"  Caricamento streaming...", end="", flush=True)
                for r in ds:
                    records.append(r)
                    count += 1
                    if count % 50 == 0:
                        elapsed = _time.time() - t0
                        speed = count / elapsed if elapsed > 0 else 0
                        eta = (args.sample - count) / speed if speed > 0 else 0
                        eta_str = f"{int(eta)}s" if eta < 60 else f"{int(eta//60)}m{int(eta%60)}s"
                        print(f"\r  [{count:>5}/{args.sample}] {count/args.sample*100:.0f}%"
                              f"  {speed:.0f} rec/s  ETA: {eta_str}    ",
                              end="", flush=True)
                    if count >= args.sample:
                        break
                print(f"\r  ✅ Caricati (streaming) {count:,} record in {_time.time()-t0:.1f}s{' '*20}")

        except Exception as e:
            err = str(e)
            if "doesn't exist" in err or "not found" in err.lower():
                cp(f"  ❌ Repo non trovato o privato: {args.repo}", "RED")
                sys.exit(1)
            # Dataset multi-config con schemi incompatibili
            if "CastError" in err or "column names don't match" in err:
                cp(f"\n  ⚠️  Schemi incompatibili tra config — tento caricamento multi-config...", "YELLOW")
                records, loaded_cfgs = load_multiconfig(args.repo, args.sample, args.token, load_dataset)
                if records:
                    print(f"  ✅ Caricati {len(records)} record da {len(loaded_cfgs)} config: {loaded_cfgs}")
                    break
                cp("  ❌ Nessun record caricato nemmeno con multi-config.", "RED")
                sys.exit(1)
            if split:
                print(f"  ⚠️  Split '{split}' non disponibile, provo il prossimo...")
            records = []  # reset per il prossimo tentativo
            continue

        if records:
            break  # caricamento riuscito

    if not records:
        cp("  [ERRORE] Nessun record caricato.", "RED")
        sys.exit(1)

    # ── Distribuzione config (se multi-config) ────────────────────────────────
    if "_config" in records[0]:
        cfg_counts = Counter(r.get("_config", "?") for r in records)
        cp(f"\n  ℹ️  Distribuzione record per config:", "CYAN")
        for cfg, cnt in cfg_counts.most_common():
            print(f"    {cfg:<35} {cnt:>4} record")

    # ── Formato speciale: RMCBench ─────────────────────────────────────────────
    if is_rmcbench(records[0]):
        analyze_rmcbench(records, save_path=args.save)
        return

    # ── Analisi struttura ──────────────────────────────────────────────────────
    first = records[0]
    keys = list(first.keys())
    is_multiconfig = "_config" in first
    content_field = detect_content_field(first)

    print(f"\n  Chiavi top-level: {[k for k in keys if k != '_config'][:10]}")
    print(f"  Campo contenuto:  {content_field or '⚠️ non rilevato'}")

    if content_field is None and not is_multiconfig:
        cp("\n  ⚠️  Formato non riconosciuto — prime 3 chiavi e valori:", "YELLOW")
        for k in keys[:3]:
            v = str(first.get(k, ""))[:100]
            print(f"    {k}: {v}")
        sys.exit(0)

    # ── Estrazione contenuti ───────────────────────────────────────────────────
    contents = []
    instructions = []
    inputs = []

    for r in records:
        # per multi-config: rileva il campo per ogni record (schema varia)
        cf = detect_content_field(r) if is_multiconfig else content_field
        content = extract_content(r, cf) if cf else ""
        contents.append(content)
        instructions.append(str(r.get("instruction", r.get("prompt", r.get("question", r.get("user", ""))))))
        inputs.append(str(r.get("input", r.get("context", r.get("system", "")))))

    n = len(contents)

    # ── CHECK 1: output == input ───────────────────────────────────────────────
    output_eq_input = sum(
        1 for c, inp in zip(contents, inputs)
        if inp and c and c.strip() == inp.strip()
    )
    pct_eq = output_eq_input / n * 100

    # ── CHECK 2: codice reale ──────────────────────────────────────────────────
    with_code = sum(1 for c in contents if has_code(c))
    pct_code = with_code / n * 100

    # ── CHECK 3: lunghezze ────────────────────────────────────────────────────
    lens = [len(c) for c in contents if c]
    avg_len = sum(lens) // len(lens) if lens else 0
    sorted_lens = sorted(lens)
    p50 = sorted_lens[len(sorted_lens)//2] if sorted_lens else 0
    p95 = sorted_lens[int(len(sorted_lens)*0.95)] if sorted_lens else 0

    # ── CHECK 4: duplicati ────────────────────────────────────────────────────
    seen = set()
    dupes = 0
    for c in contents:
        h = hashlib.md5(c.encode("utf-8", errors="replace")).hexdigest()
        if h in seen: dupes += 1
        else: seen.add(h)
    pct_dupes = dupes / n * 100

    # ── CHECK 5: segnali cyber ────────────────────────────────────────────────
    cyber_hits = [count_cyber(c) for c in contents]
    with_cyber = sum(1 for h in cyber_hits if h > 0)
    pct_cyber = with_cyber / n * 100
    avg_cyber = sum(cyber_hits) / n

    # ── CHECK 6: tipo instruction ─────────────────────────────────────────────
    instr_types = Counter(i[:50] for i in instructions if i)

    # ── CHECK 7: malformati ───────────────────────────────────────────────────
    malformed = sum(1 for c in contents if not c or len(c) < 10)
    pct_malformed = malformed / n * 100

    # ── REPORT ────────────────────────────────────────────────────────────────
    cp(f"\n{'─'*65}", "CYAN")
    cp(f"  📊 RISULTATI CHECK  ({n} record campionati)", "BOLD")
    cp(f"{'─'*65}", "CYAN")

    # CHECK 1
    color = grade(pct_eq, [5, 20], reverse=True)
    cp(f"\n  CHECK 1 — output == input:  {output_eq_input}/{n} = {pct_eq:.0f}%", color)
    if pct_eq > 20:
        print(f"            ⚠️  Soglia critica: >20% = dataset mal costruito")

    # CHECK 2
    color = grade(pct_code, [30, 10])
    cp(f"  CHECK 2 — Con codice reale: {with_code}/{n} = {pct_code:.0f}%", color)
    if pct_code < 10:
        print(f"            ⚠️  <10% = quasi nessun codice")

    # CHECK 3
    color = grade(avg_len, [2000, 500])
    cp(f"  CHECK 3 — Lunghezza output: avg={avg_len} chars  p50={p50}  p95={p95}", color)
    if avg_len < 500:
        print(f"            ⚠️  <500 chars = risposte troppo corte")

    # CHECK 4
    color = grade(pct_dupes, [10, 30], reverse=True)
    cp(f"  CHECK 4 — Duplicati:        {dupes}/{n} = {pct_dupes:.0f}%", color)
    if pct_dupes > 30:
        print(f"            ⚠️  >30% = troppi duplicati")

    # CHECK 5
    color = grade(pct_cyber, [50, 20])
    cp(f"  CHECK 5 — Segnali cyber:    {with_cyber}/{n} = {pct_cyber:.0f}%  (avg={avg_cyber:.1f}/rec)", color)

    # CHECK 6
    cp(f"\n  CHECK 6 — Tipi instruction (top 8):", "CYAN")
    for instr, cnt in instr_types.most_common(8):
        print(f"    {instr[:45]:<45} {cnt:>4}  ({cnt/n*100:.1f}%)")

    # CHECK 7
    if pct_malformed > 5:
        cp(f"\n  CHECK 7 — Malformati: {malformed}/{n} = {pct_malformed:.0f}%", "YELLOW")

    # ── SCORE FINALE ──────────────────────────────────────────────────────────
    score = 0
    if pct_eq < 5:   score += 25
    elif pct_eq < 20: score += 10
    if pct_code > 30:  score += 25
    elif pct_code > 10: score += 10
    if avg_len > 2000:  score += 20
    elif avg_len > 500:  score += 10
    if pct_dupes < 10:  score += 20
    elif pct_dupes < 30: score += 10
    if pct_cyber > 50:  score += 10

    color = "GREEN" if score >= 70 else ("YELLOW" if score >= 40 else "RED")
    cp(f"\n{'═'*65}", "CYAN")
    cp(f"  🏆 SCORE FINALE: {score}/100", color)

    if score >= 70:
        cp(f"  ✅ DATASET BUONO — vale la pena analizzarlo in dettaglio", "GREEN")
    elif score >= 40:
        cp(f"  ⚠️  DATASET MEDIO — filtra i problemi prima di usarlo", "YELLOW")
    else:
        cp(f"  ❌ DATASET SCADENTE — non aggiungere al corpus", "RED")

    cp(f"{'═'*65}\n", "CYAN")

    # ── Salvataggio opzionale ──────────────────────────────────────────────────
    if args.save:
        out = Path(args.save)
        with out.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        cp(f"  💾 Campione salvato: {out}  ({len(records)} record)", "GREEN")
        print(f"     Usa: python3 dataset_benchmark_v3.py --input {out}")


if __name__ == "__main__":
    main()
