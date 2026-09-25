"""Shared discovery and own-evidence filename policy (study 2026-09-23).

Specific component and third-party licence names are discoverable but never
promoted to declarations or copyright evidence for the enclosing unit.
"""
import re

EXT = r'(?:\.(?:txt|text|md|mdx|markdown|rst|org|rtf|html?))?'
ID = r'(?:MIT(?:[-_]0)?|APACHE(?:[-_]?2(?:\.0)?)?|BSD(?:[-_]?[234](?:[-_]CLAUSE)?)?|[AL]?GPL(?:[-_]?[123](?:\.[01])?(?:[-_](?:ONLY|OR[-_]LATER))?)?|ISC|MPL(?:[-_]?2(?:\.0)?)?|EPL(?:[-_]?2(?:\.0)?)?|CC0(?:[-_]?1(?:\.0)?)?|UNLICENSE|BSL(?:[-_]?1(?:\.0)?)?)'
OWN = re.compile(r'^(?:(?:LICEN[CS]E|COPYING|UNLICENSE)(?:[._-]' + ID + r')?|' + ID + r'[._-]LICEN[CS]E)' + EXT + r'$', re.I)
NOTICE = re.compile(r'^(?:NOTICE|COPYRIGHT|ATTRIBUTIONS?|CREDITS|AUTHORS)' + EXT + r'$', re.I)
README = re.compile(r'^README(?:[._-].*)?$', re.I)


def file_class(path):
    base = path.rsplit('/', 1)[-1]
    if OWN.fullmatch(base):
        return 'license'
    if NOTICE.fullmatch(base):
        return 'notice'
    if re.search(r'(?i)licen[cs]e|copying|third[-_ ]party.*notice', base):
        return 'component_license'
    if README.fullmatch(base):
        return 'readme'
    return None


def discover(path):
    return file_class(path) in {'license', 'notice', 'component_license'}


def skill_file_class(path):
    """Evidence for an independently declared Skill, not a root declaration.

    Preserve the agreed captured Skill evidence rule, including LICENSE.upstream
    in the applicable chain. Discovery never establishes component applicability
    outside that chain or creates the Skill's declaration.
    """
    own = file_class(path)
    if own in {'license', 'notice', 'readme'}:
        return own
    base = path.rsplit('/', 1)[-1]
    if re.fullmatch(r'(?:LICEN[CS]E|COPYING|UNLICENSE)(?:[._-].*)?', base, re.I):
        return 'license'
    if re.fullmatch(r'(?:NOTICE|COPYRIGHT|THIRD[-_ ]PARTY[-_ ]NOTICES?|ATTRIBUTIONS?|CREDITS|AUTHORS)(?:[._-].*)?', base, re.I):
        return 'notice'
    return own
