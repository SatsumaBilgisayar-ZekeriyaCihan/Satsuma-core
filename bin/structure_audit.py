#!/usr/bin/env python3
"""Inventory every source file and expose exception handling for manual review.

This is structural evidence, not a vulnerability scanner or safety verdict.
No target code is imported or executed. Binary assets are hashed, not parsed.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess


def audit(root):
    files=[];errors=[];handlers=[]
    for path in sorted(root.rglob('*')):
        if not path.is_file() or any(p in {'__pycache__','.pytest_cache','test-evidence','.git','node_modules','dist'} for p in path.relative_to(root).parts):
            continue
        data=path.read_bytes();name=path.relative_to(root).as_posix()
        item={'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'check':'hashed'}
        try:
            if path.suffix=='.py':
                text=data.decode('utf-8-sig');tree=ast.parse(text,filename=name)
                item['check']='python_ast_parsed'
                for node in ast.walk(tree):
                    if isinstance(node,ast.ExceptHandler):
                        silent=all(isinstance(n,(ast.Pass,ast.Continue,ast.Return)) for n in node.body)
                        handlers.append({'path':name,'line':node.lineno,'caught':ast.unparse(node.type) if node.type else 'bare',
                                         'simple_fallback':silent,'body':ast.get_source_segment(text,node)})
            elif path.name.startswith('tsconfig') and path.suffix=='.json':
                item['check']='jsonc_hashed_requires_typescript_parser'
            elif path.suffix=='.json':
                json.loads(data);item['check']='json_parsed'
            elif path.suffix in {'.yaml','.yml'}:
                import yaml
                list(yaml.safe_load_all(data));item['check']='yaml_parsed'
            elif data.startswith((b'#!/bin/sh',b'#!/bin/bash',b'#!/usr/bin/env bash')):
                result=subprocess.run(['/usr/bin/bash','-n',str(path)],capture_output=True,text=True,timeout=10)
                if result.returncode:raise ValueError(result.stderr[:1000])
                item['check']='shell_syntax_checked'
        except (SyntaxError,ValueError,UnicodeError,RuntimeError) as exc:
            errors.append({'path':name,'error':str(exc)[:1000]});item['check']='FAILED'
        files.append(item)
    return {'scope':'all source files; structural checks only, no security clearance',
            'file_count':len(files),'files':files,'errors':errors,'exception_handlers':handlers,
            'manual_review_required':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();report=audit(Path(__file__).resolve().parents[1])
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'files':report['file_count'],'structural_errors':len(report['errors']),
                      'exception_handlers':len(report['exception_handlers']),'security_verified':False}))
    return bool(report['errors'])


if __name__=='__main__':raise SystemExit(main())
