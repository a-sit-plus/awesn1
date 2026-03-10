from __future__ import annotations

import json
from pathlib import Path


def define_env(env):
    manifest_path = Path(__file__).parent / "docs" / "generated" / "asn1js-links.json"
    cache = None

    def load_manifest():
        nonlocal cache
        if cache is None:
            if manifest_path.exists():
                cache = json.loads(manifest_path.read_text(encoding="utf-8"))
            else:
                cache = {}
        return cache

    @env.macro
    def asn1js_url(example_id: str) -> str:
        value = load_manifest().get(example_id)
        if not value:
            return "#"
        return f"https://asn1js.eu/#{value}"

    @env.macro
    def asn1js_local_url(example_id: str) -> str:
        value = load_manifest().get(example_id)
        if not value:
            return "#"
        return f"../assets/asn1js/index-local.html#{value}"

    @env.macro
    def asn1js_iframe(example_id: str) -> str:
        src = asn1js_local_url(example_id)
        if src == "#":
            return "_ASN.1 inline explorer unavailable (missing sample manifest entry)_"
        return (
            f'<iframe class="asn1js-inline-embed__frame" src="{src}" '
            'title="ASN.1 explorer" loading="lazy" referrerpolicy="no-referrer" '
            'sandbox="allow-scripts allow-same-origin allow-forms"></iframe>'
        )

    @env.macro
    def asn1js_link(example_id: str) -> str:
        url = asn1js_url(example_id)
        if url == "#":
            return "_Explore on asn1js.eu (missing sample manifest entry)_"
        return f'Explore on [asn1js.eu]({url})'
