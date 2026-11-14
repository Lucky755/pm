"""Conservative quotation/operation locality; no semantic interpretation of arbitrary prose."""
import re

CLAIM_ARTIFACT = re.compile(
    r'(?<![\w.])(?:/[A-Za-z0-9_./%-]{2,}|0x[0-9a-fA-F]{3,}|'
    r'\d{1,5}/(?:tcp|udp)|(?:порт|port)\s*[:#]?\s*\d{1,5})', re.I)

PROBE_DENIAL = re.compile(
    r'no such file|not found|cannot access|permission denied|\bENOENT\b|'
    r'ошибк\w*|отказ\w*|нет такого файла|не найден\w*', re.I)
NEGATIVE_CLAIM = re.compile(
    r'отсутств\w*|\bнет\b|\bне\s+(?:существ\w*|доступ\w*|найден\w*|открыт\w*)|'
    r'\b(?:not\s+(?:found|present|available|accessible|open)|missing|absent|'
    r'does\s+not\s+exist|cannot\s+access|no\s+such)\b', re.I)
POSITIVE_CLAIM = re.compile(
    r'существ\w*|\bесть\b|доступ\w*|найден\w*|открыт\w*|содерж\w*|'
    r'\b(?:exists?|available|accessible|found|contains?|present|open)\b', re.I)


def artifacts_in_claim(claim):
    items=[]
    for match in CLAIM_ARTIFACT.finditer(claim):
        item=match.group()
        if re.match(r'(?:порт|port)\s*[:#]?\s*\d+',item,re.I):
            item=re.search(r'\d+',item).group()
        elif re.fullmatch(r'\d{1,5}/(?:tcp|udp)',item,re.I):
            item=item.split('/')[0]
        items.append(item)
    return items


def contains(artifact, text):
    if artifact.isdecimal() or artifact.lower().startswith('0x'):
        return re.search(r'(?<![0-9a-fA-F])'+re.escape(artifact)+r'(?![0-9a-fA-F])',text,re.I) is not None
    return artifact.lower() in text.lower()


def polarity(claim, output, quote=None):
    artifacts=artifacts_in_claim(claim)
    if quote and quote in output:
        scope=quote
        lines=[line for line in quote.splitlines() if any(contains(a,line) for a in artifacts)]
        decisive=[line for line in lines if PROBE_DENIAL.search(line) or POSITIVE_CLAIM.search(line)
                  or re.search(r'HTTP/\d|\b[2345]\d\d\s+(?:OK|Not Found|Forbidden|Unauthorized)\b',line,re.I)]
        if decisive:
            scope='\n'.join(decisive)
        if artifacts and not any(contains(a,quote) for a in artifacts):
            if artifacts_in_claim(quote):
                return False,'цитата относится к другому артефакту'
            # Permit a body quote immediately after its request/header, but
            # never attach a quote naming another operation to this claim.
            contexts=[]
            start=0
            while (index:=output.find(quote,start))>=0:
                previous=output[:index].splitlines()[-1:]
                contexts.extend(previous)
                start=index+len(quote)
            if not any(contains(a,line) for a in artifacts for line in contexts):
                return False,'цитата не связана с артефактом утверждения'
    else:
        lines=[line for line in output.splitlines() if any(contains(a,line) for a in artifacts)]
        scope='\n'.join(lines) if lines else output
    denied=PROBE_DENIAL.search(scope) is not None
    if NEGATIVE_CLAIM.search(claim):
        return denied,'' if denied else 'зонд не показал отсутствие'
    if POSITIVE_CLAIM.search(claim) and denied:
        return False,'зонд показал отказ'
    return True,''
