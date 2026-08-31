---
title: ASN.1 Viewer
hide:
  - navigation
  - toc
---

# ASN.1 Viewer

This ASN.1 viewer (a.k.a poor man's [asn1js.eu](https://asn1js.eu/)) demonstrates awesn1's parsing capabilities. It is not intended to compete with asn1js.eu, but rather to showcase that awesn1 indeed works on JS targets as advertised.
No server-side logic is involved. All processing happens in a single <700KB JavaScript file.
**Do not treat the viewer's structural rendering as authoritative output!** awesn1 is solid, but the glue code to facilitate HTML rendering is 50 shades of AI slop!
The thing it has going for it, is built-in semantics for the [Android key attestation extension](https://source.android.com/docs/security/features/keystore/attestation), which you can try out [here](#MIIKQDCCCeWgAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIDI2ZGU2NGVjZWM1ZGExN2U1YTU2MjE4ZTRiNWYwMzhkMB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlzdG9yZSBLZXkwggeyMAsGCWCGSAFlAwQDEgOCB6EAxelBTR42EKVjXoFnR_i-4EPhPEZeBRGOK0VIz1q8DJPwE8NXmta6hQsEGOyoR5mdBKLv40y9xoCs55Skq-1kwr4Ib3OcliSr0171Oe86eC4e1cKW_JtvGFSgqw9ABdE8nfHj2MVm6DdVMHUFTpEEcP21oWV3CBQ2vg_MDYCMp1BB-F63yKFJNlmFUairAjKRR2aLZU1wZjKMMymjwbab9a5ZW83_EcgoKlO9sB9osHFyGCV3FgpnHZBxa-I8gHXJJoCKHlp5DfURli769ehwCHRLn3wz72Z38-XMkx1dVJuoH_1EVz4HFJj0w-3DhBBZalLrc4mFbUEB_4-7ZdcvMv0e04Z-LIDL-I7rtreGDNOYz1T9gc_oZeJrQxL0jCgiPw3LCh6dR8vzk7Woxd3znw6cPE3cV4OJ44ODwHxyww9upKVd2MOhH7lOcGPgxag3SO_vQDl03cbe7Ah-qWqpFZ_f5WhABO6mOr33PV1hpZMxw3YkAtRetfvbqceeupVmTmnuNkp4_yO7fN2Q7OWR1EgQKH2NYggsppIVJcia0YJZ4CbwCFK03iGn03nLTgGeF64KSjuXVInv9nVjMZG_P-NHQgdMuXwrYpuSASTXl8mOIt279d8Sdt1d8LFIrAGUbfSGjuwFfG0uS4_rXusEhcdjPLOwHDZXJ-yLdkhVjU7tXUDTZZ_APqg76SrXoVtadHVNpy-lTKwJohsr11EPjCQhI4hTfvnzHdTZvg0zSjaVU78sXmfr_zouH0HvE_hrsoEboIzWhFz3ykQBl16mcNAC-XytADA7y18O92dtP0R3vQORgJfH7gDYI1eSahdCwKtqM3CVwUaUWbi_nLNdeEz2lGaNfs4nekgqbK0sbjFr2hSJ_53Z5eKrzBI12WbkHMW8Bk1xXdzTZUeNM15rvTjo1VDvx2f3JTkCTO5HcATbdBbDRoKEvZ7XUY6v07hWlo2O4ayn5JOFWBAnRBesuhyZecAzBicwpEZjLE4RVbh8fR0Z1J5c5psXmfqe2vdWBoO9HlvTunKdO8QGu1Ao3A-4NSnsBDOB35lwsGEFzO8ien_8DtQNxP2djAshIKkjwuu8Y9N9d4EydnufAD59d0ZCG8vbOOlIdlrc_oZZlyTINJcrDd6Rw-VR719dJ4wHzSAjXdrko-2bzb2tS2LTCSMMdB0kyXGx5BGc9DqJbHrsS_52zprv65JxIXCn08xy8SvnygiDxlVCpfTGo86G9HNtwWONV5iMWE6F0Ws8n8Y6CIMfn7h1keWFYZxeKVYeGaPUhuJ1vHDUmwX9qpgFCOmkCdrTKY1IhsDOfy4IQ7Y3i9atJyz-U1NSd_7I1CUDXlQTI3cnQ-oahKCP0Q5rLB9ITo2HPwxb0dMNSgfRst5VV5nWssb-vVDnJCFU2CRIOB4ixMzICrqxEC0DqimnZtJg4-cmD1WoDfpbrZmOpM5c-KRaP7cPW1kcBAIaPcsWX-3uixY05VkFN77IE3BcuhdISffbt-r0vvOOF78UAKh65CYhShHkPlGk5klqRtPjYbFi5hCgeKeR5OdzR9zA_PJ8FAPMQXeptkBGefzDBB6DEj8VpeePRQzC_8-NPuuiivKhXZ6BpKoVFsx9D1i2ilwYqsi62COUU1qQg7VXAQ2_VwN8b2jRMdtA9qWSW0lxWPEVayAuKFTuP3ihii0FbRWwHEO683HveL0a50y4Bnv-DLMa4Ne1SIfoWspDZ60XMZW3sXTd7hK2BD-vHNTu-jS4jlR9LTw3VTnPzIsc0Y3fT2KmjJn22yWe5vrO5FEkSDjq4vXm_LiU60JJP6_O_ObW4DStwPszrQw5KhmOcyJZI12Wa3_kXIPa8l4FNwm5JRxg7OnaT-SgJufl9Ftq4CRQw-gc7Sr87bKxTlHD5WgErm1bwvGF9YCadisfXpOKYG3RJzfZ29SHRjifIFeJG94i-0egDRB0quH6nhW8XqQeN3P6-ObTGl74EsFLWQa9XHyVViASJ5i99dCO2qTZT_FnQ-WxDs759cOXDtlPB_W3Wd_AMNdE47lijUgvuT5xpL_7vqswnP4R7lTq7dKHJbmY9gRd_1crMHHGt_MVtbP8dBSYQV4vkaLtxeuKTvIaxFkneH9Gr11f6zAZuEncB7lnwzxBgsOtdBOIZaaZMZ3GclrM-5skn0Hrw5kMqHL20W0HFe7ggZY70jLjYD7zLLg4Cm4xMjibkPWUMq5xtXjrwoiYEzPKF2FCB5PTL0zMS1KKIbGc_XKjdP28qpBz8Yjmafh1d070KSzrgS3kk5J97BIQARzlhd4jPDLNQ1jzwGFTEmMf2XoEjt0_3M4ULCbUKDNnbPfVsaK6bbZuyvOqiy0YM4v90IAkFb8SS_Wwo4pwwodAzDHQBktQqCL6cSAJk1BeUrrw00mkA8zkQUnPHSzYVTOZPNiZdUzfAudaFPJG3c5ioeRerThl0u36V7cRVPQSUJGpnYt1wP4XQZ3niy8c-hklRD0CWSoWA8vy57YpXyrHL6axKsAS0fNVT5nLeXTcyO76Gxv1pUmn34X5diwfP9_ILo7fTeYd5f9qYatOHVP55aH-O0eaDEvONMm-eXI_jJnG8quF09eqhBKjggGbMIIBlzAOBgNVHQ8BAf8EBAMCB4AwggGDBgorBgEEAdZ5AgERBIIBczCCAW8CAgH0CgEBAgIB9AoBAQRA-xLy4Do8HMfzm-S6UENW_qbwv-WmXke1Ejykn6tY6SWeHmCcNsW3yLqBVoG3cdgk1p3g3WAqdOfo_yyS0xuXKAQAMH2_hT0IAgYBoD3cM7e_hUVHBEUwQzEdMBsEFmNvbS5leGFtcGxlLmhlbGxvd29ybGQCAQAxIgQg1AfWtBb4M9C3Jg8aEmtOkkSbZWs3PlB_V3o0PczxP-q_hVQiBCBWzlp7vvt2h8Tk0alUxHP48U_nk3yGqHl1veW4q0u-ODCBm6EFMQMCAQKiAwIBBKUFMQMCAQCrAwIBAb-DdwIFAL-FPgMCAQC_hUBMMEoEIKy1pN0YTixEz6alPS1cXoZ0yUmKWfiugBmUKsH86x5sAQH_CgEABCBmHLc59n1RuUtV28WmOaxD_ZjnU9vrl2sncapMs7HgLr-FQQUCAwKYEL-FQgUCAwMXcL-FTgYCBAE1J8W_hU8GAgQBNSfFMAoGCCqGSM49BAMCA0kAMEYCIQC6yShwqJ8tWYdCtipUX1_OV2bUiVrpCb4gKQ8RxJGaswIhAJoc73VrH2yJNIsD3e2Pvm2PJtOtM1nV4YMKw2vEycCO).

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
      <h2>ASN.1 Structure <span id="share-control" class="asn1-share" hidden>(<button id="share" type="button" aria-label="Copy share URL" title="Copy share URL"><svg aria-hidden="true" viewBox="0 0 24 24"><path d="m20,9v-1h1v-2h1v-2h-1v-2h-1v-1h-5v1h-1v2h-1v2h-1v1h-1v1h-1v1h-1v-1h-5v1h-1v2h-1v2h1v2h1v1h5v-1h1v1h1v1h1v1h1v2h1v2h1v1h5v-1h1v-2h1v-2h-1v-2h-1v-1h-5v1h-2v-1h-1v-1h-1v-4h1v-1h1v-1h2v1h5Zm-11,4h-1v1h-3v-1h-1v-2h1v-1h3v1h1v2Zm6,5h1v-1h3v1h1v2h-1v1h-3v-1h-1v-2Zm0-14h1v-1h3v1h1v2h-1v1h-3v-1h-1v-2Z"/></svg></button>)<span id="share-popup" role="status" hidden>URL copied</span></span></h2>
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
