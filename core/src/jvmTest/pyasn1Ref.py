#!/usr/bin/env python3

import sys
from pyasn1.type import univ
from pyasn1.codec.der.encoder import encode

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue

    try:
        m_str, e_str = line.split()
        m = int(m_str)
        e = int(e_str)

        der = encode(univ.Real((m, 2, e))).hex()
        print(der, flush=True)

    except Exception as ex:
        print(f"ERROR {type(ex).__name__}: {ex}", flush=True)