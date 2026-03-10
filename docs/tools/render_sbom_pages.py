#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render SBOM module markdown pages from the SBOM index.")
    parser.add_argument("--index", required=True, type=Path)
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def render_rows(entries: list[dict[str, str]]) -> str:
    def sort_key(item: dict[str, str]) -> tuple[int, str]:
        publication = item["publication"]
        return (0 if publication == "kotlinMultiplatform" else 1, publication)

    def publication_type(item: dict[str, str]) -> str:
        return "metadata" if item["publication"] == "kotlinMultiplatform" else "target"

    def artifact_link(label: str, path: str, sig_path: str) -> str:
        link = f"[{label}](../{path})"
        if sig_path:
            link += f" ([sig](../{sig_path}))"
        return link

    rows = []
    for entry in sorted(entries, key=sort_key):
        rows.append(
            "| `{publication}` | `{type}` | {json_link} | {xml_link} | `{version}` |".format(
                publication=entry["publication"],
                type=publication_type(entry),
                json_link=artifact_link("JSON", entry["json"], entry.get("jsonSig", "")),
                xml_link=artifact_link("XML", entry["xml"], entry.get("xmlSig", "")),
                version=entry["version"],
            )
        )
    return "\n".join(rows)


def main() -> None:
    args = parse_args()
    index_data = json.loads(args.index.read_text(encoding="utf-8"))
    template = args.template.read_text(encoding="utf-8")
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    entries_by_module: dict[str, list[dict[str, str]]] = defaultdict(list)
    for entry in index_data.get("entries", []):
        entries_by_module[entry["module"]].append(entry)

    for module_name, entries in entries_by_module.items():
        rendered = template
        rendered = rendered.replace("{{ module_name }}", module_name)
        rendered = rendered.replace("{{ module_title }}", module_name)
        rendered = rendered.replace("{{ table_rows }}", render_rows(entries))
        (output_dir / f"{module_name}.md").write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
