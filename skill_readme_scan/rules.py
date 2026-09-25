"""Versioned checklist rules; no I/O, author fallback, or destination-derived identity.

Every caller must state whether its inventories are complete. Observed absence and
missing evidence are distinct. Exact Unicode entity matching is deliberately
conservative; a shared token is never proof of entity identity.
"""
from __future__ import annotations
from dataclasses import dataclass,field
from pathlib import PurePosixPath
import re,unicodedata
from typing import Iterable
from license_names import file_class

RULE_VERSION='checklist-v2.2'
PERM3=frozenset({'MIT','Apache-2.0','BSD-3-Clause'})
NOTICE=re.compile(r'^(?:NOTICE|COPYRIGHT|THIRD[-_ ]PARTY[-_ ]NOTICES?|ATTRIBUTIONS?|CREDITS|AUTHORS)(?:[._-].*)?$',re.I)
LICENSE=re.compile(r'^(?:LICEN[CS]E|COPYING|UNLICENSE)(?:[._-].*)?$',re.I)
README=re.compile(r'^README(?:[._-].*)?$',re.I)
PLACEHOLDERS=frozenset({'fullname','full name','name','yourname','copyright holder','copyright holders','name of copyright owner',
    'author name','owner name','company name','project name','insert name','todo','tbd','placeholder','author','authors',
    'owner','owners','holder','holders','contributors','the contributors','the authors','maintainers','unknown'})

def normalize_holder(value:str)->str:
    s=unicodedata.normalize('NFKC',value or '').casefold()
    return ' '.join(''.join(c if c.isalnum() else ' ' for c in s).split())

def holder_key(value:str)->str:
    return ''.join(normalize_holder(value).split())

def is_placeholder(value:str)->bool:
    n=normalize_holder(value)
    # Tokens inside an otherwise named organization (e.g. MC-Todo or Your Tech
    # Tribe) are not enough to establish a template. Keep those for validation.
    return not n or n in PLACEHOLDERS or bool(re.fullmatch(
        r'(?:your|insert)(?: full)? (?:name|company|organization|organisation|org|project|team|username)'
        r'(?: (?:or|and|your|name|company|organization|organisation|org|project|team|username|here|todo))*',n)) or bool(re.fullmatch(
        r'name of (?:the )?(?:copyright )?(?:owner|holder|author|company|organization)',n))

def copyright_holders(values:Iterable[str],*,expression:str|None=None,text:str='')->frozenset[str]:
    """Accept detector holders only; context, not organization name, rejects GPL issuer boilerplate."""
    out=set()
    canonical_gpl=bool(expression and re.search(r'(?i)(?:^|\W)(?:a?gpl|lgpl)',expression) and re.search(
        r'(?is)copyright[^\n]{0,180}free software foundation[^\n]*\n.{0,400}?everyone is permitted to copy and distribute verbatim',text))
    for value in values:
        n=normalize_holder(value)
        if is_placeholder(value):continue
        if canonical_gpl and n in {'free software foundation','free software foundation inc','the free software foundation'}:continue
        out.add(n)
    return frozenset(out)

def same_holder(a:str,b:str)->bool:
    return bool(not is_placeholder(a) and not is_placeholder(b) and holder_key(a)==holder_key(b))

def match_all(source:Iterable[str],destination:Iterable[str])->bool:
    ss=list(source);dd=list(destination)
    return bool(ss) and all(any(same_holder(a,b) for b in dd) for a in ss)

def governing_directories(path:str,*,unit_directory=False)->list[str]:
    p=path.strip('/') if unit_directory else path.rpartition('/')[0]
    result=[p]
    while p:p=p.rpartition('/')[0];result.append(p)
    return result

@dataclass(frozen=True)
class Evidence:
    path:str
    licence:str|None=None
    is_text:bool=False
    coverage:float=0.
    holders:frozenset[str]=field(default_factory=frozenset)
    kind:str='license'
    scanned:bool=True
    truncated:bool=False
    sha:str|None=None

    def matches(self,want:str)->bool:
        return bool(self.kind=='license' and self.scanned and not self.truncated and self.is_text and self.coverage>=90 and self.licence==want)

@dataclass
class Chain:
    primary:frozenset[str]
    all_holders:frozenset[str]
    levels:list[frozenset[str]]
    text_paths:list[str]
    holder_paths:list[str]
    primary_level:int|None
    source_integrity:str
    coupled_integrity:str
    primary_complete:bool
    inventory_complete:bool
    blocked_notice_paths:list[str]
    wrong_licence_paths:list[str]

def resolve(files:Iterable[Evidence],path:str,want:str|None,*,inline=(),inline_known=True,
            unit='skill',observed_directories:Iterable[str]=(),inline_full_text=False,inline_text_known=True)->Chain:
    """Text and holder may be split across levels. L0+L1 form the primary set.

    Agents/commands couple only inside the file. Inline full licence text is an
    explicit, separately detected input; a licence identifier alone is not text.
    Plugin units are directories and have no inline holder source.
    """
    dirs=governing_directories(path,unit_directory=unit=='plugin');seen=set(observed_directories)
    fs=list(files);levels=[];texts=[];holderpaths=[];blocked=[];wrong=[];complete=True
    for directory in dirs:
        ff=[f for f in fs if f.path.rpartition('/')[0]==directory and f.kind in {'license','notice'}]
        licence=[f for f in ff if f.kind=='license'];matching=[f for f in licence if want and f.matches(want)]
        notice=[f for f in ff if f.kind=='notice' and (not licence or matching)]
        permitted=matching+notice
        holders=frozenset().union(*(f.holders for f in permitted if f.scanned and not f.truncated))
        levels.append(holders);texts.extend(f.path for f in matching)
        holderpaths.extend(f.path for f in permitted if f.holders and f.scanned and not f.truncated)
        blocked.extend(f.path for f in ff if f.kind=='notice' and f not in notice)
        wrong.extend(f.path for f in licence if f.scanned and f.is_text and f.coverage>=90 and f.licence and f.licence!=want)
        complete=complete and directory in seen and all(f.scanned and not f.truncated for f in ff)
    ih=frozenset(inline) if unit!='plugin' else frozenset()
    primary=ih|levels[0];primary_level=0 if primary else None
    if not primary:
        for i,hh in enumerate(levels[1:],1):
            if hh:primary=hh;primary_level=i;break
    allh=ih.union(*levels)
    source_positive=bool((texts or inline_full_text) and allh and want)
    source='positive' if source_positive else 'negative' if complete and inline_known and want else 'unknown'
    if unit in {'agent','command'}:
        coupled_positive=bool(inline_full_text and ih and want);coupled_complete=inline_known and inline_text_known
    else:
        coupled_positive=bool((inline_full_text or any(p.rpartition('/')[0]==dirs[0] for p in texts)) and (ih|levels[0]) and want)
        coupled_complete=inline_known and dirs[0] in seen and all(f.scanned and not f.truncated for f in fs if f.path.rpartition('/')[0]==dirs[0] and f.kind in {'license','notice'})
    coupled='positive' if coupled_positive else 'negative' if coupled_complete and want else 'unknown'
    upto=dirs if primary_level is None else dirs[:primary_level+1]
    primary_complete=inline_known and all(d in seen for d in upto) and all(f.scanned and not f.truncated for f in fs if f.path.rpartition('/')[0] in upto and f.kind in {'license','notice'})
    return Chain(primary,allh,levels,texts,holderpaths,primary_level,source,coupled,primary_complete,complete,blocked,wrong)

def preservation(source:Chain,destination:Chain,*,source_repo:str,destination_repo:str,rule='default',require_complete_primary=True,source_identity_id=None,destination_identity_id=None)->str:
    if source_repo.casefold()==destination_repo.casefold() or (source_identity_id and source_identity_id==destination_identity_id) or not source.primary:return 'untestable'
    if require_complete_primary and not source.primary_complete:return 'unknown'
    required=source.all_holders if rule=='strict' else source.primary
    found=destination.levels[0] if rule=='level1' else destination.all_holders
    if rule=='strict' and require_complete_primary and not source.inventory_complete:return 'unknown'
    ok=any(same_holder(a,b) for a in required for b in found) if rule=='lenient' else match_all(required,found)
    return 'preserved' if ok else 'not_preserved' if destination.inventory_complete else 'unknown'

def integrity_placement(chain:Chain,path:str,inline=(),*,unit_directory=False,inline_full_text=False)->str:
    """Nearest prefix of the governing chain containing BOTH text and holder."""
    dirs=governing_directories(path,unit_directory=unit_directory);holders=set(inline);text=inline_full_text
    for i,directory in enumerate(dirs):
        holders.update(chain.levels[i]);text=text or any(p.rpartition('/')[0]==directory for p in chain.text_paths)
        if text and holders:return 'folder' if i==0 else 'root' if i==len(dirs)-1 else 'intermediate'
    return 'none' if chain.inventory_complete else 'unknown'

def choose_external_origin(candidates,destination_repo,*,destination_date=None,destination_identity_id=None):
    """No destination-as-origin. Select earliest eligible dated candidate; ties retained.

    This selects an observable reference, not a proof of authorship. The result
    explicitly separates date-directed and undated/ambiguous reference evidence.
    """
    outside=[x for x in candidates if x['repo'].casefold()!=destination_repo.casefold() and x.get('identity_verified')
        and destination_identity_id and x.get('repository_identity_id') and x['repository_identity_id']!=destination_identity_id]
    if not outside:return {'status':'no_verified_external_reference','candidates':[]}
    dated=[x for x in outside if x.get('blob_first_commit_date')]
    if not dated:return {'status':'external_reference_direction_unknown','candidates':sorted(outside,key=lambda x:(x['repo'],x['path']))}
    earliest=min(x['blob_first_commit_date'] for x in dated);selected=[x for x in dated if x['blob_first_commit_date']==earliest]
    status='source_precedes_destination' if destination_date and earliest<destination_date else 'external_reference_direction_unknown'
    return {'status':status,'candidates':sorted(selected,key=lambda x:(x['repo'],x['path'])),'earliest_date':earliest}
