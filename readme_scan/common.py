import hashlib,re
def sha(t): return hashlib.sha256((t or "").encode("utf-8","replace")).hexdigest()
ALIAS={'bsd-new':'BSD-3-Clause','bsd-simplified':'BSD-2-Clause','mit':'MIT','apache-2.0':'Apache-2.0','gpl-3.0':'GPL-3.0-only','gpl-3.0-plus':'GPL-3.0-or-later','agpl-3.0':'AGPL-3.0-only','agpl-3.0-plus':'AGPL-3.0-or-later','gpl-2.0':'GPL-2.0-only','gpl-2.0-plus':'GPL-2.0-or-later','lgpl-3.0':'LGPL-3.0-only','lgpl-2.1':'LGPL-2.1-only','lgpl-3.0-plus':'LGPL-3.0-or-later','lgpl-2.1-plus':'LGPL-2.1-or-later','cc-by-4.0':'CC-BY-4.0','cc-by-sa-4.0':'CC-BY-SA-4.0','cc-by-nc-4.0':'CC-BY-NC-4.0','cc-by-nc-sa-4.0':'CC-BY-NC-SA-4.0','cc-by-nc-nd-4.0':'CC-BY-NC-ND-4.0','cc-by-nd-4.0':'CC-BY-ND-4.0','cc0-1.0':'CC0-1.0','unlicense':'Unlicense','isc':'ISC','mpl-2.0':'MPL-2.0','epl-2.0':'EPL-2.0','mit-0':'MIT-0','bsd-zero':'0BSD','wtfpl-2.0':'WTFPL','bsl-1.0':'BSL-1.0','eupl-1.2':'EUPL-1.2','proprietary-license':'LicenseRef-proprietary','unknown-license-reference':'LicenseRef-unknown','unknown':'LicenseRef-unknown','commercial-license':'LicenseRef-commercial','other-permissive':'LicenseRef-other-permissive','other-copyleft':'LicenseRef-other-copyleft','x11':'X11','zlib':'Zlib','mulanpsl-2.0':'MulanPSL-2.0','cc-by-3.0':'CC-BY-3.0','cc-by-nc-2.0':'CC-BY-NC-2.0','cc-by-sa-3.0':'CC-BY-SA-3.0','apache-1.1':'Apache-1.1','artistic-2.0':'Artistic-2.0','ofl-1.1':'OFL-1.1','elastic-license-v2':'Elastic-2.0','bsd-3-clause':'BSD-3-Clause','bsd-2-clause':'BSD-2-Clause','ssc-2.0':'LicenseRef-server-side','fair-source-0.9':'LicenseRef-fair-source','odbl-1.0':'ODbL-1.0'}
def spdx(e):
    if not e: return None
    e=e.strip()
    if ' ' in e: e=e.split()[0]  # take primary of compound (rare)
    low=e.lower()
    if low in ALIAS: return ALIAS[low]
    # GitHub keys already SPDX-ish
    gh={'GPL-3.0':'GPL-3.0-only','AGPL-3.0':'AGPL-3.0-only','GPL-2.0':'GPL-2.0-only','LGPL-3.0':'LGPL-3.0-only','LGPL-2.1':'LGPL-2.1-only'}
    if e in gh: return gh[e]
    if e.startswith('LicenseRef-scancode-'): return 'LicenseRef-'+e[len('LicenseRef-scancode-'):]
    return e

# 7-category scheme (Don't Trust the Label)
def cat(s):
    if s is None: return 'Unknown'
    u=s.upper()
    if u in ('NOASSERTION','OTHER','LICENSEREF-UNKNOWN','LICENSEREF-UNKNOWN-LICENSE-REFERENCE','LICENSEREF-OTHER'): return 'Unknown'
    if u.startswith('CC-BY-NC') or u.startswith('CC-BY-ND'): return 'CC-Restrictive'
    if u.startswith('CC-BY-SA') or u.startswith('LGPL') or u.startswith('MPL') or u.startswith('EPL') or u.startswith('EUPL') or u.startswith('MULANPSL') or u.startswith('CDDL') or u.startswith('OSL') or u.startswith('CECILL-C'): return 'Sharealike'
    if u.startswith('GPL') or u.startswith('AGPL') or u in ('LICENSEREF-OTHER-COPYLEFT',) or u.startswith('CECILL') or u.startswith('SSPL'): return 'Copyleft'
    if u in ('CC0-1.0','UNLICENSE','0BSD','WTFPL','MIT-0','PUBLIC-DOMAIN','LICENSEREF-PUBLIC-DOMAIN'): return 'Public Domain'
    if u.startswith('OPENRAIL') or 'RAIL' in u or 'LLAMA' in u or u.startswith('BIGSCIENCE') or u.startswith('CREATIVEML') or u.startswith('GEMMA') or u.startswith('DEEPSEEK') or u.startswith('QWEN') or u.startswith('APPLE-AML'): return 'ML License'
    if u.startswith('CC-BY') or u in ('MIT','APACHE-2.0','BSD-3-CLAUSE','BSD-2-CLAUSE','ISC','X11','ZLIB','BSL-1.0','ARTISTIC-2.0','OFL-1.1','APACHE-1.1','LICENSEREF-OTHER-PERMISSIVE','MIT-CMU','BSD-3-CLAUSE-CLEAR','PSF-2.0','PYTHON-2.0','POSTGRESQL','NCSA','UPL-1.0','BLUEOAK-1.0.0','ODBL-1.0','PDDL-1.0','ODC-BY-1.0'): return 'Permissive'
    if u.startswith('LICENSEREF-PROPRIETARY') or u.startswith('LICENSEREF-COMMERCIAL') or (u.startswith('LICENSEREF-') and 'COMMERCIAL' in u) or u in ('ELASTIC-2.0','BUSL-1.1','LICENSEREF-SERVER-SIDE','LICENSEREF-FAIR-SOURCE','LICENSEREF-SSC','POLYFORM-NONCOMMERCIAL-1.0.0','POLYFORM-STRICT-1.0.0','PROSPERITY-3.0.0','PARITY-7.0.0') or u.startswith('POLYFORM') or u.startswith('LICENSEREF-FSL') or u.startswith('FSL-'): return 'Restricted'  # non-open: proprietary/commercial/source-available
    return 'Other-named'


# ---------------------------------------------------------------------------
# Audit 2026-09-08 additions: configurable roots, obligation strength, and a
# real SPDX *expression* parser (finding 8: first-token truncation hid
# "MIT + Commons Clause", "MIT WITH Commons-Clause", "(MIT OR Apache-2.0)").
# ---------------------------------------------------------------------------
import os as _os
ROOT = _os.environ.get("PW_ROOT", "/mnt/d/gitskills-permissive-washing")          # project root
GS_HOME = _os.environ.get("GITSKILLS_HOME", _os.path.expanduser("~/gitskills"))   # raw harvest / corpus DBs
def out(*parts): return _os.path.join(ROOT, "analysis", "out", *parts)

# obligation strength used by the compatibility test (higher = more obligation)
STRENGTH = {"Public Domain": 0, "Permissive": 1, "Unknown": 1, "Other-named": 1, "ML License": 2,
            "Sharealike": 2, "CC-Restrictive": 3, "Copyleft": 3, "Restricted": 3}

_RESTRICTION_PAT = re.compile(r"(?i)commons[\s\-]*clause|non[\s\-]*commercial|no[\s\-]*resale|source[\s\-]*available")
_SPLIT = re.compile(r"\s+(?:AND|OR|WITH|and|or|with)\s+|\s*[+/,;]\s*|[()]")
def spdx_expr(e):
    """Parse an SPDX-like licence expression into its parts.
    Returns dict(ids, cats, ops, restriction, strongest, weakest, cat, compound):
      ids        normalised SPDX ids found (in order, deduplicated)
      ops        set of operators seen among {'AND','OR','WITH','+'}
      restriction  True when a non-SPDX restriction rider is attached (Commons Clause, non-commercial, ...)
      cat        the GOVERNING category: for a pure OR (dual licence, reuser chooses) the WEAKEST
                 obligation; otherwise (AND / WITH / '+' riders / restriction) the STRONGEST.
      compound   True when more than one id or a rider was present (i.e. spdx() would have truncated)
    spdx()/cat() are unchanged so the main-arm numbers do not move; plugin-tier scripts use cat_expr()."""
    if not e: return {"ids": [], "cats": [], "ops": set(), "restriction": False, "strongest": None,
                      "weakest": None, "cat": "Unknown", "compound": False}
    s = str(e).strip()
    restriction = bool(_RESTRICTION_PAT.search(s))
    ops = set()
    for op in ("AND", "OR", "WITH"):
        if re.search(rf"(?i)\s{op}\s", s): ops.add(op)
    if re.search(r"\S\+(\s|$)", s) or " + " in s: ops.add("+")
    toks = [t for t in _SPLIT.split(s) if t and t.strip()]
    ids = []
    for t in toks:
        t = t.strip()
        if _RESTRICTION_PAT.fullmatch(t) or _RESTRICTION_PAT.search(t) and len(t.split()) <= 3: continue
        i = spdx(t.rstrip("+"))
        if i and i not in ids: ids.append(i)
    cats = [cat(i) for i in ids]
    if restriction: cats.append("Restricted")
    if not cats: return {"ids": ids, "cats": [], "ops": ops, "restriction": restriction, "strongest": None,
                         "weakest": None, "cat": "Unknown", "compound": False}
    strongest = max(cats, key=lambda c: STRENGTH.get(c, 1)); weakest = min(cats, key=lambda c: STRENGTH.get(c, 1))
    governing = weakest if (ops == {"OR"} and not restriction) else strongest
    return {"ids": ids, "cats": cats, "ops": ops, "restriction": restriction, "strongest": strongest,
            "weakest": weakest, "cat": governing, "compound": bool(len(ids) > 1 or restriction or ops)}
def cat_expr(e): return spdx_expr(e)["cat"]
def spdx_primary(e):
    """The single id a declaration is *reported* under (exact-three tests): the first id, but only when
    the expression carries no rider/AND that changes the governing category; else None (compound)."""
    x = spdx_expr(e)
    if not x["ids"]: return None
    if x["compound"] and x["cat"] != cat(x["ids"][0]): return None
    return x["ids"][0]

# ---------------------------------------------------------------------------
# Round-2 audit (2026-09-08): a REAL SPDX expression parser with tree evaluation, via the
# `license-expression` library (the one ScanCode uses). spdx_expr() above is kept as the fallback
# for non-SPDX riders the library rejects ("MIT + Commons Clause").
# ---------------------------------------------------------------------------
try:
    from license_expression import get_spdx_licensing as _gsl, LicenseSymbol as _LS, LicenseWithExceptionSymbol as _LWE, AND as _AND, OR as _OR
    _LIC = _gsl()
except Exception:            # library absent: mandatory unless PW_ALLOW_SPDX_FALLBACK=1 (round-3 finding 8)
    _LIC = None
    if _os.environ.get("PW_ALLOW_SPDX_FALLBACK") != "1":
        raise ImportError("license-expression is required (pip install license-expression); set PW_ALLOW_SPDX_FALLBACK=1 to use the heuristic splitter, which is then recorded in the results")
SPDX_PARSER = "license-expression" if _LIC is not None else "fallback-heuristic"
_EXC_RESTRICT = {"commons-clause"}
def _eval(node, acc):
    """recursive evaluation: returns the governing category of a subtree.
    symbol -> its category; WITH exception -> licence's category (a restriction rider such as
    Commons-Clause makes it Restricted); AND -> strongest child; OR -> weakest child (reuser chooses)."""
    if isinstance(node, _LWE):
        acc["ids"].append(spdx(node.license_symbol.key)); acc["exceptions"].append(node.exception_symbol.key)
        c = cat(spdx(node.license_symbol.key))
        if node.exception_symbol.key.lower() in _EXC_RESTRICT: acc["restriction"] = True; c = "Restricted"
        acc["cats"].append(c); return c
    if isinstance(node, _LS):
        i = spdx(node.key); acc["ids"].append(i); c = cat(i); acc["cats"].append(c); return c
    kids = [_eval(k, acc) for k in node.args]
    if isinstance(node, _AND): acc["ops"].add("AND"); return max(kids, key=lambda c: STRENGTH.get(c, 1))
    if isinstance(node, _OR): acc["ops"].add("OR"); return min(kids, key=lambda c: STRENGTH.get(c, 1))
    return max(kids, key=lambda c: STRENGTH.get(c, 1))
def parse_spdx(e):
    """Parse a licence declaration as an SPDX expression TREE and evaluate it.
    Returns dict(ids, cats, ops, exceptions, restriction, cat, strongest, weakest, compound, dual, tree, parser)
      cat       governing category (AND=strongest, OR=weakest, exception-aware, parentheses respected)
      dual      True when the top-level node is an OR (dual-licensed: not 'exactly' any one licence)
      compound  True for anything other than a single plain licence symbol
      parser    'license-expression' or 'fallback' (rider the library cannot parse; spdx_expr() used)"""
    if not e or not str(e).strip():
        return {"ids": [], "cats": [], "ops": set(), "exceptions": [], "restriction": False, "cat": "Unknown", "strongest": None, "weakest": None, "compound": False, "dual": False, "tree": None, "parser": None}
    s = str(e).strip()
    if _LIC is not None and not _RESTRICTION_PAT.search(s.replace("WITH Commons-Clause", "")) :
        try:
            node = _LIC.parse(s, validate=False, strict=False)
            acc = {"ids": [], "cats": [], "ops": set(), "exceptions": [], "restriction": False}
            gov = _eval(node, acc)
            ids = []; [ids.append(i) for i in acc["ids"] if i not in ids]
            return {"ids": ids, "cats": acc["cats"], "ops": acc["ops"], "exceptions": acc["exceptions"], "restriction": acc["restriction"],
                    "cat": gov, "strongest": max(acc["cats"], key=lambda c: STRENGTH.get(c, 1)), "weakest": min(acc["cats"], key=lambda c: STRENGTH.get(c, 1)),
                    "compound": not isinstance(node, _LS) or bool(acc["exceptions"]), "dual": isinstance(node, _OR), "tree": str(node), "parser": "license-expression"}
        except Exception:
            pass
    x = spdx_expr(s); x.update({"exceptions": [], "dual": (x["ops"] == {"OR"}), "tree": s, "parser": "fallback"}); return x
def cat_expr(e): return parse_spdx(e)["cat"]
def spdx_primary(e):
    """The single id a declaration is reported under for the exact-three test: only a plain single
    licence symbol qualifies. A dual licence (OR), an AND, an exception or a rider returns None."""
    x = parse_spdx(e)
    return x["ids"][0] if (x["ids"] and not x["compound"] and not x["dual"]) else None

# ---------------------------------------------------------------------------
# audit 2026-09-19 (D5): the FREE-TEXT front-matter declaration. ScanCode's L0 expression collapses "Dual-licensed MIT; commercial GPL" to
# mit, "Apache-2.0 WITH brand-clause" to apache-2.0, "Apache-2.0 OR BSD-3-Clause" to apache-2.0 and a bare "BSD license" to bsd-new; the
# paper's exact-three test needs exactly ONE licence id. So the raw string is read again: an operator expression of SPDX-looking tokens goes
# through parse_spdx; otherwise the licence FAMILIES named in the text are counted, and two or more families, a rider (WITH <x>-clause /
# exception, Commons Clause, non-commercial) or a family without its distinguishing version (BSD without a clause count, Apache without 2.0)
# means there is no strict id. The raw pass only ever REMOVES a strict id or a category; it never creates one ScanCode did not give.
# ---------------------------------------------------------------------------
def _bsd_id(s):
    m = re.search(r"(?i)\b([0234])[\s\-]*clause\b|\bBSD[\s\-]*([0234])\b|\b(0)BSD\b", s); n = next((g for g in (m.groups() if m else ()) if g), None)
    if n is None and re.search(r"(?i)\b(new|modified)[\s\-]*bsd\b", s): n = "3"
    if n is None and re.search(r"(?i)\b(simplified|free)[\s\-]*bsd\b", s): n = "2"
    return {"0": "0BSD", "2": "BSD-2-Clause", "3": "BSD-3-Clause", "4": "BSD-4-Clause"}.get(n)          # None = bare "BSD"
def _apache_id(s):
    m = re.search(r"(?i)\b(?:apache|ASL)(?:[\s\-_]*(?:software\s+)?licen[cs]e)?[\s,\-_]*(?:version\s*|v)?(2\.0|2|1\.1|1\.0)\b", s)
    if m: return {"1.1": "Apache-1.1", "1.0": "Apache-1.0"}.get(m.group(1), "Apache-2.0")
    return "Apache-2.0" if re.search(r"(?i)\bALv2\b|LICENSE-2\.0\b", s) else None                    # None = bare "Apache License"
def _gnu_id(fam):
    def f(s):
        m = re.search(r"(?i)\b" + fam + r"[\s\-]*v?([23])(?:\.\d)?(\+|[\s\-]*or[\s\-]*later|-only)?", s)
        if not m: return fam.upper() + "-3.0-only"
        v = "2.1" if (fam == "lgpl" and m.group(1) == "2") else m.group(1) + ".0"
        return fam.upper() + "-" + v + ("-or-later" if (m.group(2) and "only" not in m.group(2)) else "-only")
    return f
_CC_VARIANT = [(r"NC[\s\-]?ND", "CC-BY-NC-ND-4.0"), (r"NC[\s\-]?SA", "CC-BY-NC-SA-4.0"), (r"\bNC\b|non[\s\-]?commercial", "CC-BY-NC-4.0"), (r"\bND\b|no[\s\-]?deriv", "CC-BY-ND-4.0"), (r"\bSA\b|share[\s\-]?alike", "CC-BY-SA-4.0")]
def _cc_id(s):
    for pat, i in _CC_VARIANT:
        if re.search(r"(?i)" + pat, s): return i
    return "CC-BY-4.0"
# (family key, detector consumed in this order, id or id function over the ORIGINAL string, default id when the function finds no version)
_FAMILIES = [("fsl", r"(?i)\bFSL-1\.1(?:-(?:MIT|ALv2|Apache-2\.0))?\b|functional source licen[cs]e", "LicenseRef-FSL", None),
             ("cc0", r"(?i)\bCC0\b|\bCC-0\b|creative commons zero", "CC0-1.0", None),
             ("cc", r"(?i)\bCC[\s\-]?BY(?:[\s\-]?(?:NC|ND|SA))*(?:[\s\-]?\d\.\d)?\b|creative commons attribution[\w\s\-]*|creativecommons\.org/licenses/[\w\-/.]+", _cc_id, None),
             ("mit-0", r"\bMIT-0\b", "MIT-0", None), ("mit", r"\bMIT\b(?!-0)", "MIT", None),
             ("agpl", r"(?i)\bAGPL\b|\bGNU\s+Affero\s+General\s+Public\s+Licen[cs]e|\bAffero\b", _gnu_id("agpl"), None),
             ("lgpl", r"(?i)\bLGPL\b|\bGNU\s+Lesser\s+General\s+Public\s+Licen[cs]e|\bLesser\s+General\s+Public", _gnu_id("lgpl"), None),
             ("gpl", r"(?i)\bGPL\b|\bGNU\s+General\s+Public\s+Licen[cs]e|\bGNU\s+GPL\b", _gnu_id("gpl"), None),
             ("apache", r"(?i)\bapache\b|\bASL\b|\bALv2\b", _apache_id, "Apache-2.0"), ("bsd", r"(?i)\bBSD\b", _bsd_id, "BSD-3-Clause"),
             ("mpl", r"(?i)\bMPL\b|mozilla public", "MPL-2.0", None), ("epl", r"(?i)\bEPL\b|eclipse public", "EPL-2.0", None), ("eupl", r"(?i)\bEUPL\b", "EUPL-1.2", None),
             ("isc", r"\bISC\b", "ISC", None), ("unlicense", r"(?i)\bunlicense\b", "Unlicense", None), ("wtfpl", r"(?i)\bWTFPL\b", "WTFPL", None), ("zlib", r"(?i)\bzlib\b", "Zlib", None),
             ("ofl", r"(?i)\bOFL\b|SIL open font", "OFL-1.1", None), ("artistic", r"(?i)\bartistic\b", "Artistic-2.0", None), ("mulan", r"(?i)\bmulan", "MulanPSL-2.0", None),
             ("boost", r"(?i)\bBSL-1\.0\b|boost software", "BSL-1.0", None), ("busl", r"(?i)\bBUSL\b|business source", "BUSL-1.1", None), ("polyform", r"(?i)\bpolyform\b", "PolyForm-Noncommercial-1.0.0", None),
             ("elastic", r"(?i)\belastic licen[cs]e\b|\bELv2\b", "Elastic-2.0", None), ("sspl", r"(?i)\bSSPL\b|server side public", "SSPL-1.0", None), ("upl", r"(?i)\bUPL\b", "UPL-1.0", None),
             ("ogl", r"(?i)\bOGL\b|open government licen[cs]e", "OGL-UK-3.0", None), ("proprietary", r"(?i)\bproprietary\b", "LicenseRef-proprietary", None),
             ("source-available", r"(?i)source[\s\-]*available", "LicenseRef-server-side", None), ("commercial-license", r"(?i)commercial licen[cs]e", "LicenseRef-commercial", None)]
BARE_FAMILIES = {"bsd", "apache"}          # a family whose id needs a version / clause count: bare "BSD license", "Apache License" is not exactly one id
BARE_FAMILY_CAT = "Unknown"                # a bare family name is named but not classed to an id: corpus_rules.declaration_class -> named_unclassified
_SPDX_LIKE = re.compile(r"\(?[A-Za-z0-9.+\-]+\)?(?:\s+(?:AND|OR|WITH|and|or|with)\s+\(?[A-Za-z0-9.+\-]+\)?)+")
_RIDER = re.compile(r"(?i)\bwith\b[\s\-]*[\w\-]*[\s\-]*(?:clause|exception)\b|commons[\s\-]*clause|\bexception\b")
_NC = re.compile(r"(?i)non[\s\-]*commercial|commons[\s\-]*clause")
def free_text_declaration(raw):
    """Read a raw front-matter licence string as free text -> dict(text, spdx_like, families, ids, n, dual, rider, restriction, bare) or None when empty.
    families: the distinct licence families named (key, id) in order of appearance; ids: their representative ids (a bare family takes its
    default id for category purposes); dual: two or more families joined by 'dual' / 'or'; rider: a WITH-clause / exception / Commons Clause /
    non-commercial rider (the CC non-commercial variants carry theirs in the id and are not riders); bare: families named without their version."""
    if raw is None: return None
    t = re.sub(r"\s+", " ", str(raw).strip().strip("\"'").strip())
    if not t: return None
    core = re.sub(r"\s+#.*$", "", t)                                     # a trailing YAML comment is not part of an SPDX expression
    if _SPDX_LIKE.fullmatch(core): return {"text": core, "spdx_like": True, "families": [], "ids": [], "n": 0, "dual": False, "rider": False, "restriction": False, "bare": []}
    rest = t; fams = []; bare = []
    for key, pat, idf, default in _FAMILIES:
        rest, n = re.subn(pat, " ", rest)
        if not n: continue
        i = idf(t) if callable(idf) else idf
        if i is None: bare.append(key); i = default
        fams.append((key, i))
    keys = {k for k, _ in fams}; ids = []; [ids.append(i) for _, i in fams if i not in ids]
    rider = bool(_RIDER.search(t)) or (bool(_NC.search(t)) and "cc" not in keys)
    restriction = bool(_NC.search(t)) and "cc" not in keys
    dual = len(fams) >= 2 and bool(re.search(r"(?i)\bdual\b|\bor\b", t))
    return {"text": t, "spdx_like": False, "families": fams, "ids": ids, "n": len(fams), "dual": dual, "rider": rider, "restriction": restriction, "bare": [b for b in bare if b in BARE_FAMILIES]}
def l0_resolve(expr, raw):
    """The corpus L0 resolution of one declaration: ScanCode's expression `expr` for the raw string `raw`, re-read against the raw text (D5).
    -> (strict id or None, governing category, compound, dual, restriction, source); source in {scancode, raw-spdx, raw-families, raw-rider, raw-bare-family}."""
    x = parse_spdx(expr); base = (spdx_primary(expr), x["cat"], int(bool(x["compound"])), int(bool(x["dual"])), int(bool(x["restriction"])), "scancode")
    ft = free_text_declaration(raw)
    if ft is None: return base
    if ft["spdx_like"]:
        y = parse_spdx(ft["text"])
        return (None, y["cat"], 1, int(bool(y["dual"])), int(bool(y["restriction"])), "raw-spdx") if y["ids"] else base       # an operator expression is never exactly one licence
    if ft["n"] >= 2:
        dual = ft["dual"] and not ft["rider"]; y = parse_spdx((" OR " if dual else " AND ").join(ft["ids"]))
        return (None, "Restricted" if ft["restriction"] else y["cat"], 1, int(dual), int(ft["restriction"]), "raw-families")
    if ft["n"] == 1 and ft["rider"]: return (None, "Restricted" if ft["restriction"] else cat(ft["ids"][0]), 1, 0, int(ft["restriction"]), "raw-rider")
    if ft["n"] == 1 and cat(ft["ids"][0]) == "Restricted" and base[0] and base[1] not in ("Restricted", "Unknown"): return (None, "Restricted", 0, 0, 1, "raw-restricted-family")   # "FSL-1.1-ALv2" read by ScanCode as exactly apache-2.0; an Unknown base stays Unknown (never creates)
    if ft["bare"]: return (None, BARE_FAMILY_CAT, 0, 0, 0, "raw-bare-family")
    return base

def top_n(counter, n=None):
    """Deterministic replacement for Counter.most_common (round 13 clean-rebuild fix): most_common breaks ties by insertion
    order, which follows set / dict iteration and therefore the per-process string hash seed; this sorts ties by key."""
    items = sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))
    return items if n is None else items[:n]
