# Usage: python3 tools/atomic_benchmark.py <satsuma source dir> <atomic-red-team checkout> <out.json>
# (git clone --depth 1 --filter=blob:none --sparse https://github.com/redcanaryco/atomic-red-team.git;
#  git sparse-checkout set --no-cone "/atomics/T*/T*.yaml")
"""Run Atomic Red Team Linux tests (sh/bash) through Satsuma's rule engine.

For every test the events the kernel would report are built: the executor's own
`sh -c <script>` (one argument, inner quotes kept) and every simple command of the
script (argv joined by spaces, quotes removed). A test counts as:
  DUR    a finding the stop policy acts on
  ALARM  an alarm-only finding
  IZ     recorded as a trace (high/critical report-only)
  SESSIZ matched, but nothing is written
  YOK    no rule matched
File writes are not simulated (audit file events), so file-only tests are undercounted.
"""
import collections, glob, json, re, shlex, sys, time
sys.path.insert(0, sys.argv[1])
import logging
logging.disable(logging.CRITICAL)
import yaml
from satsuma.smart_rules import SmartRuleEngine
from satsuma import enforcement
import run_satsuma_teams as T

RULES = sys.argv[1] + '/rules'
ART = sys.argv[2]
engine = SmartRuleEngine(RULES)

SPLIT = re.compile(r'\s*(?:\|\||&&|;|\||&(?!>)|\n)\s*')


def substitute(text, test):
    for name, spec in (test.get('input_arguments') or {}).items():
        text = text.replace('#{%s}' % name, str((spec or {}).get('default', '')))
    # What the shell would have resolved before the kernel sees the program.
    text = re.sub(r'\$\{?which_(\w+)\}?', lambda m: m.group(1).replace('_', ''), text)
    text = re.sub(r'`which (\w+)`|\$\(which (\w+)\)', lambda m: m.group(1) or m.group(2), text)
    text = re.sub(r'\$\{?PYTHON(?:_EXE)?\}?', 'python3', text)
    text = re.sub(r'\$\{?HOME\}?|(?<![\w/])~(?=/)', '/home/u', text)
    text = re.sub(r'\$\{?PathToAtomicsFolder\}?|PathToAtomicsFolder', '/home/u/AtomicRedTeam/atomics', text)
    text = re.sub(r'\$\{?PID\}?|"\$\{?PID\}?"', '4321', text)
    return text


def argv_text(segment):
    try:
        tokens = shlex.split(segment, comments=True)
    except ValueError:
        tokens = segment.split()
    tokens = [t for t in tokens if not re.fullmatch(r'\d*[<>]+&?\d*', t)]
    while tokens and re.fullmatch(r'\w+=\S*', tokens[0]) and len(tokens) > 1 and tokens[0].split('=')[0] != 'LD_PRELOAD':
        tokens = tokens[1:]
    return tokens


def events(script, shell):
    out = [(f'{shell} -c {script}', f'/usr/bin/{shell}')]
    for line in script.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        for segment in SPLIT.split(line):
            tokens = argv_text(segment)
            if not tokens:
                continue
            name = tokens[0].rsplit('/', 1)[-1]
            if name in ('if', 'then', 'fi', 'else', 'do', 'done', 'for', 'while', 'echo', 'export', 'cd', '[', 'sleep', 'true'):
                if name != 'echo':
                    continue
            exe = tokens[0] if tokens[0].startswith('/') else f'/usr/bin/{name}'
            out.append((' '.join(tokens), exe))
    return out


def classify(found):
    best = 'YOK'
    for f in found:
        f = dict(f)
        if f['rule_id'] == 'SATSUMA-ENGINE-001':
            continue
        if f['rule_id'] in getattr(enforcement, 'ALARM_ONLY', ()):
            state = 'ALARM'
        elif T._recordable(f):
            state = 'IZ' if f.get('trace_only') else ('DUR' if enforcement.eligible(f) else 'KAYIT')
        else:
            state = 'SESSIZ'
        order = ['YOK', 'SESSIZ', 'IZ', 'KAYIT', 'ALARM', 'DUR']
        if order.index(state) > order.index(best):
            best = state
    return best


results = []
for path in sorted(glob.glob(ART + '/atomics/T*/T*.yaml')):
    data = yaml.safe_load(open(path))
    tech = data.get('attack_technique')
    for i, test in enumerate(data.get('atomic_tests') or []):
        if 'linux' not in (test.get('supported_platforms') or []):
            continue
        executor = test.get('executor') or {}
        if executor.get('name') not in ('sh', 'bash'):
            continue
        script = substitute(executor.get('command') or '', test)
        found, rules = [], set()
        for k, (cmd, exe) in enumerate(events(script, executor['name'])):
            event = {'source': 'audit', 'kind': 'execve', 'action': 'execve', 'cmd': cmd, 'exe': exe,
                     'uid': '0' if executor.get('elevation_required') else '1000', 'pid': str(10000 + k),
                     'timestamp': time.time()}
            try:
                hits = engine.match(event)
            except Exception:
                hits = []
            found += hits
            rules |= {h['rule_id'] for h in hits}
        results.append({'technique': tech, 'tactic_name': data.get('display_name'), 'test': test.get('name'),
                        'state': classify(found), 'rules': sorted(rules), 'script': script[:400]})
json.dump(results, open(sys.argv[3], 'w'), ensure_ascii=False, indent=1)
c = collections.Counter(r['state'] for r in results)
print(len(results), dict(c))
techs = collections.defaultdict(list)
for r in results:
    techs[r['technique']].append(r['state'])
tc = collections.Counter('DUR' if 'DUR' in s else ('GORULUR' if set(s) & {'ALARM', 'IZ', 'KAYIT'} else ('SESSIZ' if 'SESSIZ' in s else 'YOK'))
                         for s in techs.values())
print('teknik bazinda', len(techs), dict(tc))
