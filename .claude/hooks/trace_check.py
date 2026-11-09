"""Traceability check over docs/traceability.md.

python <hooks>/trace_check.py        (also run by .githooks/pre-push and the verify skill)

Fails when:
  * an FR/NFR heading in FRD.md has no row in the matrix
  * a row that is not Draft/Withdrawn has no SPEC or no TC
  * a referenced ID does not exist in its source document
"""
import sys

from _guard import ROOT, ID_RE, finish, load_config

DOCS = ROOT / "docs"
SKIP_STATUS = {"draft", "withdrawn"}
COLUMNS = ["requirement", "prd", "br", "spec", "tc", "status"]


def ids_in(path):
    if path.is_dir():
        return {m.group(0) for f in path.glob("*.md") for m in ID_RE.finditer(f.name + "\n" + f.read_text(encoding="utf-8"))}
    return {m.group(0) for m in ID_RE.finditer(path.read_text(encoding="utf-8"))} if path.exists() else set()


def parse_matrix(text):
    rows = []
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == len(COLUMNS) and ID_RE.match(cells[0]):
            rows.append(dict(zip(COLUMNS, cells)))
    return rows


def split_ids(cell):
    return [m.group(0) for m in ID_RE.finditer(cell)]


def check(docs=DOCS):
    matrix_file = docs / "traceability.md"
    if not matrix_file.exists():
        return [f"missing {matrix_file}"]
    rows = parse_matrix(matrix_file.read_text(encoding="utf-8"))
    sources = {
        "prd": ids_in(docs / "requirements" / "PRD.md"),
        "br": ids_in(docs / "requirements" / "BRD.md"),
        "spec": ids_in(docs / "specs"),
        "tc": ids_in(docs / "tests" / "TEST-PLAN.md"),
    }
    frd = ids_in(docs / "requirements" / "FRD.md")
    problems = []

    in_matrix = {r["requirement"] for r in rows}
    for rid in sorted(i for i in frd if i.startswith(("FR-", "NFR-")) and i not in in_matrix):
        problems.append(f"{rid} is in FRD.md but has no row in traceability.md")

    for r in rows:
        rid = r["requirement"]
        if rid not in frd:
            problems.append(f"{rid}: not found in FRD.md")
        if not split_ids(r["prd"]):
            problems.append(f"{rid}: no PRD link")
        if r["status"].lower() not in SKIP_STATUS:
            for col in ("spec", "tc"):
                if not split_ids(r[col]):
                    problems.append(f"{rid}: status {r['status']} but no {col.upper()}")
        for col, known in sources.items():
            for ref in split_ids(r[col]):
                if ref not in known:
                    problems.append(f"{rid}: {ref} not found in its source document")
    return problems


def main():
    problems = check()
    if not problems:
        print("[guard:trace_check] OK")
    finish("trace_check", load_config("trace_check")["mode"], problems)


if __name__ == "__main__":
    main()
