# Precision benchmark

Measures the accuracy of the engine's **`evidenced`** tier (see issue #32) so
precision improvements can be validated with numbers instead of guesses.

## What it does

`run_benchmark.py` analyzes each reference system in `systems/` and reports:

- **Structural metrics** (no labels needed): total threats, evidenced/baseline
  split, evidenced ratio, threats-per-component. Track these across changes to
  see drift.
- **Labelled assertions** (expert ground truth in `labels/<system>.json`):
  - `must_be_evidenced` — a threat the model *proves* applies; the engine must
    tag it `evidenced`.
  - `must_not_be_evidenced` — a generic check with no model evidence; the engine
    must *not* tag it `evidenced` (it belongs in baseline).

## Run

```bash
cd threat-modeler
python3 benchmark/run_benchmark.py          # human-readable report
python3 benchmark/run_benchmark.py --json    # machine-readable metrics
```

Exit code is non-zero if any labelled assertion fails, so it works as a CI gate
(`tests/test_benchmark.py` runs it with the rest of the suite).

## Adding a case

1. Drop a system model in `systems/<name>.json` (same schema as
   `examples/systems/`).
2. Add `labels/<name>.json` with `system`, `methodologies`, and the
   `must_be_evidenced` / `must_not_be_evidenced` assertions — each a
   `{component, title_contains}` matcher encoding **correct expert judgment**,
   not merely today's output.

Labels are the ground truth: if the engine disagrees with a correct label, that
is a real finding to fix — which is the point.
