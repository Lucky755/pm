"""Fixed local parsers, never run a supplied executable or fetch a Git remote.

Invoked in a fresh process with rlimits and a network-denying seccomp filter.
This is not a complete filesystem sandbox against a native-parser vulnerability.
"""
import codecs
import configparser
import ctypes
import ctypes.util
import errno
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
import zlib

MAX_BYTES=64*1024*1024
MAX_OUTPUT=64*1024*1024
MAX_FILES=512
VERSION=1


class MissingTool(ValueError):
    def __init__(self,name,package=None):
        self.name=name;self.package=package or name
        super().__init__('Required local analyzer unavailable: '+name)


def deny_network():
    library=ctypes.util.find_library('seccomp')
    if not library:raise MissingTool('libseccomp','libseccomp2')
    lib=ctypes.CDLL(library)
    lib.seccomp_init.argtypes=[ctypes.c_uint32];lib.seccomp_init.restype=ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p];lib.seccomp_syscall_resolve_name.restype=ctypes.c_int
    lib.seccomp_rule_add.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint]
    lib.seccomp_load.argtypes=[ctypes.c_void_p];lib.seccomp_release.argtypes=[ctypes.c_void_p]
    context=lib.seccomp_init(0x7fff0000)
    if not context:raise RuntimeError('Cannot initialize network filter')
    try:
        for name in (b'socket',b'socketpair',b'connect',b'sendto',b'sendmsg'):
            number=lib.seccomp_syscall_resolve_name(name)
            if number>=0 and lib.seccomp_rule_add(context,0x50000|errno.EPERM,number,0):raise RuntimeError('Cannot deny network syscall')
        if lib.seccomp_load(context):raise RuntimeError('Cannot load network filter')
    finally:lib.seccomp_release(context)


def tool(name):
    found=shutil.which(name)
    if not found:raise MissingTool(name,{'pdftotext':'poppler-utils','pdftoppm':'poppler-utils','objdump':'binutils','readelf':'binutils','strings':'binutils','tesseract':'tesseract-ocr'}.get(name))
    return found


class Processor:
    def __init__(self,directory,options):
        self.directory=Path(directory);self.options=options;self.outputs=[];self.errors=[];self.relations=[];self.used=0;self.tools=[]

    def output(self,name,data,**metadata):
        if len(self.outputs)>=MAX_FILES or self.used+len(data)>MAX_OUTPUT:raise ValueError('Derived material budget reached; original retained')
        path=self.directory/('output-'+str(len(self.outputs)))
        path.write_bytes(data);self.used+=len(data)
        self.outputs.append({'name':name,'file':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),**metadata})
        temporary=self.directory/'outputs.tmp';temporary.write_text(json.dumps(self.outputs,ensure_ascii=False))
        temporary.replace(self.directory/'outputs.json')

    def command(self,name,*args):
        executable=tool(name);index=len(self.tools);prefix=self.directory/('command-'+str(index))
        env={'PATH':'/usr/bin:/bin','HOME':str(self.directory),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
             'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0',
             'GIT_NO_REPLACE_OBJECTS':'1','GIT_NO_LAZY_FETCH':'1','OMP_THREAD_LIMIT':'1'}
        record={'tool':name,'executable':executable};self.tools.append(record)
        with prefix.with_suffix('.out').open('wb') as stdout,prefix.with_suffix('.err').open('wb') as stderr:
            try:
                result=subprocess.run([executable,*map(str,args)],cwd=self.directory,env=env,stdin=subprocess.DEVNULL,
                    stdout=stdout,stderr=stderr,timeout=20)
                record['exit_code']=result.returncode
            except subprocess.TimeoutExpired:
                record['status']='timeout'
                for suffix in ('.out','.err'):
                    partial=prefix.with_suffix(suffix).read_bytes()
                    if partial:self.output('diagnostics/'+str(index)+'-'+name+suffix,partial,kind='partial_analyzer_output')
                raise ValueError('Local analyzer timeout: '+name)
        raw=prefix.with_suffix('.out').read_bytes();error=prefix.with_suffix('.err').read_bytes()
        if error:self.output('diagnostics/'+str(index)+'-'+name+'.stderr',error,kind='analyzer_stderr')
        if result.returncode:
            if raw:self.output('diagnostics/'+str(index)+'-'+name+'.stdout',raw,kind='partial_analyzer_output')
            raise ValueError('Local analyzer nonzero exit: '+name+' ('+str(result.returncode)+'); see saved diagnostics')
        return raw

    def text(self,data):
        encoding=self.options.get('encoding')
        if not encoding:
            encoding=('utf-32' if data.startswith((codecs.BOM_UTF32_LE,codecs.BOM_UTF32_BE)) else
                      'utf-16' if data.startswith((codecs.BOM_UTF16_LE,codecs.BOM_UTF16_BE)) else 'utf-8-sig')
        try:text=data.decode(encoding)
        except (UnicodeError,LookupError):raise ValueError('Text encoding is ambiguous/corrupt; choose an explicit encoding, original retained')
        self.output('decoded.txt',text.encode('utf-8'),kind='text',encoding=encoding,**secret_candidates(text))

    def archive(self,data):
        members=[];expanded=0
        if zipfile.is_zipfile(io.BytesIO(data)):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for item in archive.infolist():
                    if item.is_dir():continue
                    try:
                        safe_member(item.filename)
                        if stat.S_ISLNK(item.external_attr>>16):raise ValueError('Archive symlink not followed')
                        if item.file_size>MAX_BYTES or expanded+item.file_size>MAX_OUTPUT:raise ValueError('Archive expansion limit')
                        if len(members)>=MAX_FILES:raise ValueError('Archive member limit')
                        with archive.open(item) as stream:body=stream.read(MAX_BYTES+1)
                        if len(body)!=item.file_size:raise ValueError('Archive member incomplete')
                        expanded+=len(body);members.append((item.filename,body))
                    except (ValueError,RuntimeError,zipfile.BadZipFile) as exc:self.errors.append({'member':item.filename,'reason':str(exc)})
        else:
            with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as archive:
                for item in archive:
                    if item.isdir():continue
                    try:
                        safe_member(item.name)
                        if not item.isfile():raise ValueError('Archive link/device not followed')
                        if item.size>MAX_BYTES or expanded+item.size>MAX_OUTPUT:raise ValueError('Archive expansion limit')
                        if len(members)>=MAX_FILES:raise ValueError('Archive member limit')
                        with archive.extractfile(item) as stream:body=stream.read(MAX_BYTES+1)
                        if len(body)!=item.size:raise ValueError('Archive member incomplete')
                        expanded+=len(body);members.append((item.name,body))
                    except (ValueError,OSError) as exc:self.errors.append({'member':item.name,'reason':str(exc)})
        for name,body in members:self.output(name,body,kind='archive_member')
        return members

    def ocr(self,path,name='ocr.txt'):
        tool('tesseract')
        language=self.options.get('language','eng')
        available=self.command('tesseract','--list-langs').decode().splitlines()
        for part in language.split('+'):
            if part not in available:
                raise MissingTool('OCR language '+part,'tesseract-ocr-'+part)
        self.output(name,self.command('tesseract',path,'stdout','-l',language),kind='ocr',
            interpretation='OCR transcription, may contain recognition errors; not byte-exact proof')

    def pdf(self,path):
        text=self.command('pdftotext','-layout','-enc','UTF-8',path,'-')
        self.output('pdf-text.txt',text,kind='pdf_text')
        if self.options.get('ocr') or not text.strip():
            tool('tesseract')
            # Render explicit pages in bounded windows. Original PDF remains whole.
            start=self.options.get('page_start',1);end=self.options.get('page_end',start)
            if type(start) is not int or type(end) is not int or not 1<=start<=end<=start+7:raise ValueError('OCR page range must contain 1..8 pages')
            prefix=self.directory/'pdf-page'
            self.command('pdftoppm','-f',start,'-l',end,'-scale-to',2400,'-png',path,prefix)
            pages=sorted(self.directory.glob('pdf-page-*.png'))
            if not pages:raise ValueError('Requested PDF pages not rendered')
            for page in pages:
                self.output(page.name,page.read_bytes(),kind='pdf_page_image')
                self.ocr(page,page.stem+'.ocr.txt')
            self.relations.append({'kind':'ocr_page_coverage','first_page':start,'last_requested_page':end,
                'rendered_pages':len(pages),'whole_document_ocr':False})

    def binary(self,path):
        data=path.read_bytes()
        if data.startswith(b'\x7fELF'):
            self.output('elf-headers.txt',self.command('readelf','-h','-l','-S',path),kind='binary_structure')
        self.output('disassembly.txt',self.command('objdump','-d',path),kind='disassembly',
            interpretation='Static disassembly, not decompilation/execution or proof of exploitability')
        self.output('strings.txt',self.command('strings','-a','-n','6',path),kind='binary_strings',
            interpretation='Strings alone do not establish code behavior, credentials or access')

    def git(self,data,members=None):
        gitdir=self.directory/'repository.git'
        gitargs=['--no-optional-locks','-c','core.hooksPath=/dev/null','-c','protocol.allow=never']
        self.command('git',*gitargs,'init','--bare','--template=',gitdir)
        args=[*gitargs,'--git-dir='+str(gitdir)]
        def put(path,body):
            target=gitdir/path;target.parent.mkdir(parents=True,exist_ok=True)
            if target.exists() and target.read_bytes()!=body:raise ValueError('Conflicting Git data for the same object/pack path')
            target.write_bytes(body)
        supplied=[]
        if members is not None:
            for name,body in members:
                relative=git_member(name)
                if relative:
                    put(relative,body);supplied.append(relative)
                elif name.endswith(('/config','/.lfsconfig')):
                    self.relations.extend(config_links(body,name))
        elif data.startswith(b'PACK'):
            put('objects/pack/input.pack',data);supplied.append('objects/pack/input.pack')
        else:
            raw=bounded_zlib(data);header,sep,body=raw.partition(b'\0')
            match=re.fullmatch(rb'(blob|tree|commit|tag) (\d+)',header)
            if not sep or not match or int(match[2])!=len(body):raise ValueError('Invalid loose Git object format/length')
            oid=hashlib.sha1(raw).hexdigest()
            if self.options.get('object_id',oid)!=oid:raise ValueError('Loose Git object hash mismatch')
            put('objects/'+oid[:2]+'/'+oid[2:],data)
        packs=list((gitdir/'objects/pack').glob('*.pack'))
        for pack in packs:
            index=pack.with_suffix('.idx')
            # Verify a supplied index against its pack, never trust its offsets alone.
            if index.exists():
                report=self.command('git',*args,'verify-pack','-v',index)
                self.output('git/'+index.stem+'-supplied-index.txt',report,kind='git_integrity')
            self.command('git',*args,'index-pack','--fsck-objects','-o',index,pack)
            report=self.command('git',*args,'verify-pack','-v',index)
            self.output('git/'+index.stem+'-verified.txt',report,kind='git_integrity',
                delta_objects=sum(1 for line in report.splitlines() if re.match(rb'^[0-9a-f]{40} ',line) and len(line.split())>=7))
        listing=self.command('git',*args,'cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype) %(objectsize)')
        objects=[line.split() for line in listing.splitlines()]
        self.output('git/object-index.txt',listing,kind='git_object_index',object_count=len(objects))
        requested=self.options.get('object_id')
        selected=[item for item in objects if item[0].decode()==requested] if requested else objects[:MAX_FILES//2]
        if requested and not selected:raise ValueError('Requested Git object is absent; no fetch or invented content')
        self.relations.append({'kind':'git_selection','objects_total':len(objects),'objects_selected':len(selected),
            'objects_omitted':len(objects)-len(selected),'requested_object':requested,'all_objects_transformed':len(objects)==len(selected)})
        if not requested and len(objects)>MAX_FILES//2:self.errors.append({'reason':'Git object selection limit','objects_total':len(objects),'objects_selected':MAX_FILES//2})
        for oid,kind,size in selected:
            if int(size)>MAX_BYTES:self.errors.append({'object_id':oid.decode(),'reason':'Git object byte limit'});continue
            content=self.command('git',*args,'cat-file',kind.decode(),oid.decode())
            if len(content)!=int(size) or hashlib.sha1(kind+b' '+str(len(content)).encode()+b'\0'+content).hexdigest()!=oid.decode():raise ValueError('Git object hash/length mismatch')
            self.output('git/'+oid.decode()+'.'+kind.decode(),content,kind='git_object',object_type=kind.decode(),object_id=oid.decode(),integrity_verified=True,
                **(secret_candidates(content.decode('utf-8')) if kind==b'blob' and is_utf8(content) else {}))
            if kind==b'blob':self.relations.extend(blob_links(content,oid.decode()))
            if kind==b'tree':
                tree=self.command('git',*args,'ls-tree','-z',oid.decode())
                self.output('git/'+oid.decode()+'.entries',tree,kind='git_tree_index')
                for entry in tree.split(b'\0'):
                    if not entry:continue
                    meta,name=entry.split(b'\t',1);mode,objtype,child=meta.split()
                    self.relations.append({'kind':'git_entry','tree':oid.decode(),'path':name.decode('utf-8',errors='replace'),
                        'object_id':child.decode(),'mode':mode.decode(),'submodule':objtype==b'commit','fetched':False})


def safe_member(name):
    path=PurePosixPath(name)
    if not name or '\\' in name or path.is_absolute() or '..' in path.parts or '\x00' in name:raise ValueError('Unsafe archive member path')
    return path


def git_member(name):
    safe_member(name)
    # Drop an archive's prefix, but only accept inert Git data, never config,
    # hooks, alternates, info/grafts, replace refs or promisor configuration.
    path=name.split('/.git/',1)[-1] if '/.git/' in name else name.removeprefix('.git/')
    if '/objects/' in path:path='objects/'+path.split('/objects/',1)[1]
    if re.fullmatch(r'objects/(?:[0-9a-f]{2}/[0-9a-f]{38}|pack/[^/]+\.(?:pack|idx))',path):return path
    return None


def bounded_zlib(data):
    decoder=zlib.decompressobj();raw=decoder.decompress(data,MAX_BYTES+1)
    if len(raw)>MAX_BYTES or not decoder.eof or decoder.unused_data:raise ValueError('Incomplete/oversized Git loose object')
    return raw


def config_links(body,name):
    try:
        parser=configparser.RawConfigParser(strict=False);parser.read_string(body.decode('utf-8'))
        return [{'kind':'related_git_url','source':name,'section':section,'url':parser[section]['url'],
                 'authorized':False,'fetched':False} for section in parser.sections() if 'url' in parser[section]]
    except (UnicodeError,configparser.Error):return []


def blob_links(body,oid):
    links=config_links(body,oid)
    match=re.fullmatch(rb'version https://git-lfs.github.com/spec/v1\r?\noid sha256:([a-f0-9]{64})\r?\nsize (\d+)\r?\n?',body)
    if match:links.append({'kind':'git_lfs_pointer','source_object':oid,'sha256':match[1].decode(),'bytes':int(match[2]),'fetched':False,'authorized':False})
    return links


def secret_candidates(text):
    """Bounded structure/use-site hints, never a credential/access verdict."""
    found=[]
    patterns=[('private_key',r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
              ('credential_uri',r'\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@[^\s]+'),
              ('authorization',r'(?i)\b(?:Basic|Bearer)\s+[A-Za-z0-9_+/=.-]{6,}')]
    for kind,pattern in patterns:
        for match in re.finditer(pattern,text):found.append({'kind':kind,'value':match[0],'start':match.start(),'end':match.end(),'trust':'candidate','server_accepted':False})
    # A value with an arbitrary variable name can be relevant at an auth use
    # site. This is deliberately a hint, not general-purpose dataflow analysis.
    for match in re.finditer(r'''\b([A-Za-z_]\w*)\s*=\s*(["'])([^\r\n"']{4,512})\2''',text):
        variable,value=match[1],match[3]
        if re.search(r'(?im)^.*(?:auth|login|password|authorization|credential).*\b'+re.escape(variable)+r'\b',text):
            found.append({'kind':'authentication_use_site','variable':variable,'value':value,'start':match.start(3),'end':match.end(3),'trust':'candidate','server_accepted':False})
    return {'credential_candidates':found[:100],'credential_candidates_omitted':max(0,len(found)-100),
            'credential_offset_unit':'decoded_text_unicode_codepoint'}


def is_utf8(data):
    try:data.decode('utf-8');return b'\x00' not in data
    except UnicodeError:return False


def classify(data,description):
    if data.startswith(b'%PDF-'):return 'pdf'
    if data.startswith((b'\x7fELF',b'MZ',b'\xfe\xed\xfa',b'\xcf\xfa\xed\xfe')):return 'executable'
    if data.startswith((b'\x89PNG\r\n\x1a\n',b'\xff\xd8\xff',b'GIF87a',b'GIF89a',b'II*\0',b'MM\0*',b'BM',b'P6\n',b'P5\n')):return 'image'
    if data.startswith(b'PACK'):return 'git'
    if data.startswith(b'\xfftOc'):return 'git_index'
    if data.startswith((b'PK\x03\x04',b'PK\x05\x06')) or zipfile.is_zipfile(io.BytesIO(data)) or 'tar archive' in description:return 'archive'
    if data.startswith(b'\x1f\x8b'):return 'gzip'
    if data.startswith((codecs.BOM_UTF16_LE,codecs.BOM_UTF16_BE,codecs.BOM_UTF8)) or is_utf8(data):return 'text'
    try:
        raw=bounded_zlib(data)
        if re.match(rb'(blob|tree|commit|tag) \d+\0',raw):return 'git'
    except (ValueError,zlib.error):pass
    if 'text' in description.lower():return 'text'
    return 'unknown'


def execute(directory,request):
    resource.setrlimit(resource.RLIMIT_AS,(1024**3,1024**3));resource.setrlimit(resource.RLIMIT_CPU,(45,45))
    resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_BYTES,MAX_BYTES));resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
    deny_network()
    processor=Processor(directory,request['options']);path=Path(directory)/'input';data=path.read_bytes()
    result={'status':'failed','complete':False,'kind':'unknown','errors':processor.errors,'outputs':processor.outputs,
            'relations':processor.relations,'tools':processor.tools,'fresh_observation':False}
    try:
        description=processor.command('file','--brief','--',path).decode('utf-8',errors='replace').strip()
        result['detected_description']=description;kind=classify(data,description);result['kind']=kind
        operation=request['operation']
        if operation!='auto' and operation!=kind and not (operation=='git' and kind in ('archive','git_index')) and not (operation=='text' and kind in ('unknown','text')):
            raise ValueError('Requested handler does not match actual file type')
        if operation!='auto':kind=operation
        if kind=='text':processor.text(data)
        elif kind=='archive':
            members=processor.archive(data)
            if any(git_member(name) for name,body in members):processor.git(data,members);result['handler']='archive+git'
        elif kind=='gzip':
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:expanded=stream.read(MAX_BYTES+1)
            if len(expanded)>MAX_BYTES:raise ValueError('Gzip expansion limit')
            processor.output('expanded',expanded,kind='decompressed')
        elif kind=='pdf':processor.pdf(path)
        elif kind=='image':processor.ocr(path)
        elif kind=='executable':processor.binary(path)
        elif kind=='git':
            members=processor.archive(data) if result['kind']=='archive' else None
            if request.get('related'):
                members=[] if members is None else members
                for item in request['related']:members.append((item['path'],(Path(directory)/item['file']).read_bytes()))
                if data.startswith(b'PACK'):
                    index=next((name for name,body in members if name.endswith('.idx')),'objects/pack/input.idx')
                    members.append((index[:-4]+'.pack',data))
                elif result['kind']=='git_index':
                    pack=next((name for name,body in members if name.endswith('.pack')),None)
                    if pack is None:raise ValueError('Original Git pack required for index validation')
                    members.append((pack[:-5]+'.idx',data))
                elif result['kind']=='git':
                    oid=hashlib.sha1(bounded_zlib(data)).hexdigest()
                    if processor.options.get('object_id',oid)!=oid:raise ValueError('Loose Git object hash mismatch')
                    members.append(('objects/'+oid[:2]+'/'+oid[2:],data))
            processor.git(data,members)
        elif kind=='git_index':raise ValueError('Git index needs its original pack; supply related references and operation=git')
        else:raise ValueError('Unsupported binary format; do not infer its contents from a model')
        result['status']='partial' if processor.errors else 'completed';result['complete']=not processor.errors;result.setdefault('handler',kind)
    except MissingTool as exc:
        result['status']='tool_missing';result['required_tool']={'kind':'system_package','name':exc.package,'version':'candidate','purpose':'Local saved-material '+str(result['kind'])+' analysis needs '+exc.name}
        processor.errors.append({'reason':str(exc),'category':'tool_missing'})
    except (ValueError,OSError,EOFError,zlib.error,tarfile.TarError,zipfile.BadZipFile) as exc:
        processor.errors.append({'reason':str(exc)[:500],'category':'processing_error'})
    return result


if __name__=='__main__':
    try:
        result=execute(sys.argv[1],json.loads((Path(sys.argv[1])/'request.json').read_text()))
        (Path(sys.argv[1])/'result.json').write_text(json.dumps(result,ensure_ascii=False))
    except BaseException as exc:
        (Path(sys.argv[1])/'result.json').write_text(json.dumps({'status':'failed','complete':False,'kind':'unknown',
            'errors':[{'category':'worker_failure','reason':type(exc).__name__}],'outputs':[]}))
        raise
