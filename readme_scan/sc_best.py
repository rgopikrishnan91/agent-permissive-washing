#!/usr/bin/env python3
"""The one match-selection rule of every ScanCode pass (2026-09-19 audit, finding D1). Imported under the ScanCode venv by
scan_tree.py, scan_texts.py, scan_harvest.py, scan_root.py, ../scripts/30_scancode_pass.py and rescan_textlike.py.

ScanCode returns several matches per file, one per rule, and each rule is flagged as licence TEXT, notice, reference or tag. The
earlier rule kept the single match with the highest (score, matched length) and read that winner's text flag, which misread complete
licence files in two ways: (A) a two-token title rule ("MIT License", score 100) outranked the full mit.LICENSE match of the body
(score 99.4), so the file was stored as a reference; (B) a complete licence text that ScanCode indexes under a rule flagged as a notice
(apache-2.0_70: the 1,405-token Apache-2.0 text without its appendix, against 1,584 tokens for the canonical text) was stored as not text.

Rule now: a match is TEXT-LIKE when its rule is flagged licence text, or when the rule is at least CANON_SHARE of the length of the
canonical text of the same single licence (the longest rule ScanCode builds from that licence's own .LICENSE file). The winner is the
best (score, matched length) among text-like matches with coverage >= COV; when there is none, the best match overall, as before (so a
file that only names a licence keeps its reference expression). is_text is the winner's text-likeness. A stored row with is_text = 1
and coverage >= COV whose licence is a real one is unchanged by this rule (the old winner was the overall maximum, hence the maximum
among the candidates), which is why rescan_textlike.py revisits only the other rows."""
COV = 90.0
CANON_SHARE = 0.75

class Canon(dict):
    """canonical text length per single licence, plus .skip: expressions that are not a licence (ScanCode's 'Unstated License' category and
    its unknown-licence keys: warranty disclaimers, 'unknown-license-reference', ...). A short rule of that kind is flagged as text by
    ScanCode and must not displace a reference to a real licence, so it is never a candidate (it can still win as the overall best)."""
    skip = frozenset()

def canon_lengths(idx):
    from licensedcode.cache import get_licenses_db
    out = Canon()
    for r in idx.rules_by_rid:
        if getattr(r, "is_from_license", False):
            out[r.license_expression] = max(out.get(r.license_expression, 0), r.length)
    out.skip = frozenset(k for k, v in get_licenses_db().items() if v.category == "Unstated License" or getattr(v, "is_unknown", False))
    return out

def textlike(rule, canon):
    if rule.is_license_text: return True
    n = canon.get(rule.license_expression)
    return bool(n and rule.length >= CANON_SHARE * n)

def best(ms, canon):
    if not ms: return None
    k = lambda m: (m.score(), m.len())
    cand = [m for m in ms if textlike(m.rule, canon) and m.coverage() >= COV and m.rule.license_expression not in canon.skip]
    return max(cand or ms, key=k)

def n_textlike_ids(ms, canon):
    """How many distinct licences have a text-like match at coverage >= COV in this file (a file carrying two full texts keeps one winner)."""
    return len({m.rule.license_expression for m in ms if textlike(m.rule, canon) and m.coverage() >= COV and m.rule.license_expression not in canon.skip})
