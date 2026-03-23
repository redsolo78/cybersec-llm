# CybersecLLM Dataset Pipeline
### Guida completa agli script e alla sequenza di utilizzo
*Versione corrente: Marzo 2026*

---

## 1. Panoramica della Pipeline

La pipeline si divide in **8 fasi**. Usare gli script **sempre nell'ordine indicato**.

| FASE | SCOPO | SCRIPT DA USARE | OUTPUT |
|---|---|---|---|
| 1 — Scraping | Trova repo GitHub offensivi | `universal_fresh_hunter_v4.1.py` | `targets_2025_2026_super.json` |
| 2 — Estrazione | Estrae codice dai repo clonati | `post_process_github_dataset.py` | `extracted_code/` |
| 3 — Candidati | Calcola score, tier, segnali | `extract_to_candidates.py` | `file_candidates_v2.jsonl` |
| 4 — Conversione | Crea esempi training con metadata | **`convert_candidates_v6_H200.py`** ← USA QUESTA | `train_examples.jsonl` |
| 5 — Filtro Gold | Dedup, qualità, tier, lingua | **`h200_gold_filter_v520.py`** ← USA QUESTA | `train_gold.jsonl` |
| 6 — Merge | Unisce più dataset in formato unico | **`dataset_merger_v2.py`** ← USA QUESTA | `merged_gold_final.jsonl` |
| 7 — Benchmark | Analizza qualità dataset JSONL | `dataset_benchmark_v3.py` | report a schermo |
| 8 — Eval HF | Valuta dataset da HuggingFace | `hf_eval.py` | score 0-100 |

---

## 2. Script Dettagliati per Fase

### FASE 1 — Scraping GitHub

Cerca repo GitHub tramite API con keyword offensive (AMSI bypass, shellcode, syscall, ecc.) e produce la lista di repo da clonare.

**Quando usarlo:** Prima volta e ogni volta che vuoi aggiornare il corpus con repo recenti.

```bash
python3 universal_fresh_hunter_v4.1.py
# Output: targets_2025_2026_super.json + targets_2025_2026_super.txt
```

> ⚠️ Richiede `GITHUB_TOKEN` nel file `.env`. Configura `MIN_STARS`, `MAX_REPOS`, lingue nel file.

---

### FASE 2 — Estrazione Codice

Clona i repo da `targets_2025_2026_super.json`, estrae file `.c .cs .go .rs .py .ps1`, pulisce i commenti e deduplicata per hash.

**Quando usarlo:** Dopo aver generato `targets_2025_2026_super.json` con il hunter.

```bash
python3 post_process_github_dataset.py \
    --clone-dir cloned_repos \
    --output-dir extracted_code \
    --workers 16
```

> ⚠️ File enormi (>1MB) vengono saltati. File senza keyword offensive vengono scartati.

---

### FASE 3 — Generazione Candidati

Scansiona `extracted_code/`, calcola per ogni file: lingua, tier (A+/A/B/C), `file_score`, `code_signal_count` (pattern offensivi rilevati).

**Quando usarlo:** Dopo `post_process_github_dataset.py`. Rifare solo se aggiungi nuovi repo.

```bash
python3 extract_to_candidates.py \
    --input-dir extracted_code \
    --output file_candidates_v2.jsonl \
    --stats
```

> ⚠️ I campi `file_score` e `code_signal_count` calcolati qui sono **critici** per tutte le fasi successive. Non saltare questo passaggio.

---

### FASE 4 — Conversione in Esempi Training

Legge `file_candidates_v2.jsonl`, legge il codice reale dal disco, crea esempi nel formato `{instruction, output, metadata}` con tutti i campi preservati. Ha ETA in tempo reale.

**Quando usarlo:** Dopo `extract_to_candidates`. Rifà il dataset da zero o aggiorna.

```bash
python3 convert_candidates_to_examples_robust_v6_H200.py \
    --input file_candidates_v2.jsonl \
    --outdir output_final_h200 \
    --max-per-language 150000 \
    --max-per-repo 500
```

> ⚠️ **NON usare v3, v4 o v5** — solo v6 preserva `file_score` e `code_signal_count` nel metadata.

---

### FASE 5 — Filtro Qualità Gold

Filtra per qualità: dedup exact+fuzzy (MinHash), tier score, cap per repo/org/lingua, rileva keyword cyber offensivi.

**Quando usarlo:** Dopo `convert_candidates`. Produce il dataset "pulito" pronto per il merge.

```bash
python3 h200_gold_filter_v520.py \
    --input output_final_h200/train_examples.jsonl \
    --max-per-repo 200 \
    --max-per-org 1000 \
    --max-per-language 10000 \
    --min-quality 4
```

> ⚠️ Installa datasketch per dedup fuzzy: `pip install datasketch`. Senza, funziona solo con dedup exact.

---

### FASE 6 — Merge Multi-Dataset

Unisce N dataset JSONL di formati diversi in un unico file normalizzato. Gestisce dedup cross-file, normalizzazione lingua, resolve tier `?`, lingua dominante per contenuto misto.

**Quando usarlo:** Per unire il corpus GitHub con dataset HF scaricati.

```bash
python3 dataset_merger_v2.py \
    --inputs train_gold.jsonl red_team_full_clean.jsonl \
    --output merged_gold_final.jsonl \
    --out-format auto \
    --min-chars 300 \
    --max-chars 50000 \
    --max-per-language 4000 \
    --max-per-repo 0
```

**Formati input supportati automaticamente:**

| Formato | Struttura |
|---|---|
| ChatML | `{"text": "<\|im_start\|>..."}` |
| Training | `{"instruction":..., "output":..., "metadata":{...}}` |
| Messages | `{"messages": [{"role":...}], "meta":{...}}` |
| Text-only | `{"text": "..."}` |
| Candidates | skippati automaticamente (no codice) |

**Opzioni `--out-format`:**

- `auto` — usa il formato più ricco tra i file di input *(default)*
- `native` — ogni record mantiene il suo formato originale
- `training` — forza tutto in `{instruction/output/metadata}`
- `text` — forza tutto in `{text: ...}`

---

### FASE 7 — Benchmark Dataset

Analizza qualsiasi JSONL della pipeline. Rileva automaticamente il formato, mostra distribuzione linguaggi, tier, segnali offensivi, duplicati, lunghezze.

**Quando usarlo:** Dopo ogni fase per verificare la qualità. **Sempre prima di un training.**

```bash
python3 dataset_benchmark_v3.py --input merged_gold_final.jsonl
python3 dataset_benchmark_v3.py --input file_candidates_v2.jsonl
python3 dataset_benchmark_v3.py --input train_gold.jsonl --quick 5000
```

---

### FASE 8 — Valutazione Dataset HuggingFace

Scarica un campione da HuggingFace e lo valuta con 7 check automatici. Produce score 0-100 con verdetto.

**Quando usarlo:** Prima di scaricare un dataset HF completo.

```bash
# Valutazione base
python3 hf_eval.py nome/dataset --sample 500

# Salva campione per analisi dettagliata
python3 hf_eval.py nome/dataset --sample 1000 --save campione.jsonl

# Repo privato con token HF
python3 hf_eval.py nome/privato --token hf_xxxxx
```

> ⚠️ `--token` serve per repo **privati** (token HF tipo `hf_xxx`). Per scegliere N record usa `--sample N`, **NON** `--token N`.

---

## 3. Cheat Sheet — Sequenza Completa da Zero

```bash
# 1. Scraping repo GitHub
python3 universal_fresh_hunter_v4.1.py

# 2. Clone + estrazione file
python3 post_process_github_dataset.py \
    --clone-dir cloned_repos \
    --output-dir extracted_code \
    --workers 16

# 3. Scansione candidati
python3 extract_to_candidates.py \
    --input-dir extracted_code \
    --output file_candidates_v2.jsonl \
    --stats

# 4. Conversione in training examples
python3 convert_candidates_to_examples_robust_v6_H200.py \
    --input file_candidates_v2.jsonl \
    --outdir output_final_h200 \
    --max-per-language 150000 \
    --max-per-repo 500

# 5. Filtro gold
python3 h200_gold_filter_v520.py \
    --input output_final_h200/train_examples.jsonl \
    --max-per-repo 200 \
    --max-per-org 1000 \
    --max-per-language 10000

# 6. Merge con altri dataset
python3 dataset_merger_v2.py \
    --inputs train_gold.jsonl red_team_full_clean.jsonl \
    --output merged_gold_final.jsonl \
    --out-format auto \
    --min-chars 300 \
    --max-per-language 4000

# 7. Benchmark finale
python3 dataset_benchmark_v3.py --input merged_gold_final.jsonl
```

### Solo aggiornamento (corpus già esistente)

```bash
# Aggiungi nuovi repo → rigenera solo da fase 2
python3 post_process_github_dataset.py --no-clone   # usa repo già scaricati
python3 extract_to_candidates.py ...
python3 convert_candidates_to_examples_robust_v6_H200.py ...
python3 dataset_merger_v2.py --inputs train_gold.jsonl nuovi_examples.jsonl ...
```

### Valuta dataset HF prima di usarlo

```bash
python3 hf_eval.py nome/dataset --sample 500
# Score >= 70 → scarica tutto e aggiungi al merge
# Score 40-69 → guarda il campione manualmente
# Score < 40  → skip

# Per dataset con tag <think> (DeepSeek-R1):
# Pulisci i tag prima, poi aggiungi al merge normalmente
python3 -c "
import json, re
with open('raw.jsonl') as fin, open('clean.jsonl','w') as fout:
    for l in fin:
        r = json.loads(l)
        for m in r.get('messages',[]):
            if m['role']=='assistant':
                m['content'] = re.sub(r'<think>.*?</think>','',m['content'],flags=re.DOTALL).strip()
        fout.write(json.dumps(r,ensure_ascii=False)+'\n')
"
```

---

## 4. Versioni Corrette vs Obsolete

| SCRIPT | VERSIONE CORRETTA ✅ | VERSIONI OBSOLETE ❌ |
|---|---|---|
| Conversione candidati | `convert_candidates_v6_H200.py` | v3, v4, v5 |
| Filtro gold | `h200_gold_filter_v520.py` | v515 → v519 |
| Merge dataset | `dataset_merger_v2.py` | `dataset_merger.py` (v1) |
| Benchmark | `dataset_benchmark_v3.py` | `dataset_benchmark_v2.py` |
| Eval HF | `hf_eval.py` | — |

---

## 5. Errori Comuni da Evitare

- ❌ **`dataset_merger.py` (v1)** — manca parser ChatML e normalizzazione lingua. Usa sempre `dataset_merger_v2.py`.
- ❌ **`--token 1000`** — `--token` è per il token HF (`hf_xxx`), non per il numero di record. Usa `--sample 1000`.
- ❌ **Glob `*` nel nome repo HF** — la shell espande `*` prima di passarlo allo script. Usa il nome esatto.
- ❌ **Saltare `extract_to_candidates.py`** — senza `file_score` e `code_signal_count` nel metadata il filtro gold non funziona.
- ❌ **`file_candidates*.jsonl` nel merge** — contengono solo metadata, non il codice. Il merger li skippa automaticamente.

---

## 6. Valori Benchmark Attesi

| METRICA | BUONO ✅ | PROBLEMA ⚠️ |
|---|---|---|
| Duplicati esatti | 0% | > 5% |
| Segnali cyber | > 85% | < 50% |
| Lingua `unknown` | < 5% | > 15% |
| Tier `?` | 0% (con merger v2) | > 20% |
| Lunghezza media | 5.000–15.000 chars | < 500 o > 80.000 |
| `output == input` | 0% | > 10% |

---

*CybersecLLM Pipeline Documentation — Marzo 2026*
