---
title: ASN.1 Viewer
hide:
  - navigation
  - toc
  - tabs
---

# ASN.1 Viewer

<div class="asn1-viewer">
  <textarea id="input" spellcheck="false" aria-label="ASN.1 input" placeholder="Paste PEM, Base64, or hexadecimal DER here"></textarea>
  <div class="asn1-viewer__controls">
    <label for="format">Format</label>
    <select id="format"><option>Auto</option><option>PEM</option><option>Base64</option><option>Hex</option></select>
    <button id="decode" type="button">Decode</button>
    <button id="clear" type="button">Clear</button>
  </div>
  <div id="status" role="status"></div>
  <div class="asn1-viewer__output">
    <section>
      <h2>ASN.1 structure</h2>
      <pre id="output"></pre>
    </section>
    <section>
      <h2>DER hex</h2>
      <p><span class="hex-tag">tag</span> · <span class="hex-length">length</span> · <span class="hex-content">primitive content</span></p>
      <div id="hex-output"></div>
    </section>
  </div>
  <div id="hex-context-menu" role="menu" hidden><button type="button" role="menuitem">Copy segment as hex</button></div>
</div>

<script src="../javascripts/asn1-viewer.js"></script>
