"""Dashboard actions are not reported as attacks; findings carry the event's time.

Panel işlemleri saldırı diye bildirilmez; bulgular olayın zamanını taşır.
"""
from pathlib import Path

from satsuma.finding_origin import annotate, event_epoch
from satsuma.smart_rules import SmartRuleEngine

ROOT = Path(__file__).parents[1]
OPERATOR = '0::/system.slice/satsuma-operator.service'
SHELL = '0::/user.slice/user-1000.slice/session-2.scope'


def cgroups(table):
    return lambda pid: table.get(pid, '')


def finding_for(cmd, **event):
    engine = SmartRuleEngine(ROOT / 'rules')
    ev = {'source': 'sys_proc', 'action': 'process_seen', 'cmd': cmd, 'pid': 4321, **event}
    return ev, [f for f in engine.match(ev) if f['rule_id'] == 'SATSUMA-EVASION-002']


def test_field_case_dashboard_stop_is_an_admin_action_not_a_critical_attack():
    event, found = finding_for('systemctl stop satsuma-reader.service', ppid=1487)
    assert found and found[0]['severity'] == 'critical'
    result = annotate(found[0], event, now=1000, cgroup_of=cgroups({1487: OPERATOR}))
    assert result['origin'] == 'satsuma_operator'
    assert result['severity'] == 'info' and result['classification'] == 'indicator'
    assert result['original_severity'] == 'critical'
    assert result['summary'].startswith('Panelden yönetici işlemi')


def test_the_same_command_from_a_user_shell_stays_critical():
    event, found = finding_for('systemctl stop satsuma-reader.service', ppid=2222)
    result = annotate(found[0], event, now=1000, cgroup_of=cgroups({2222: SHELL}))
    assert 'origin' not in result and result['severity'] == 'critical'


def test_findings_take_the_event_time_and_keep_when_they_were_processed():
    from datetime import datetime
    happened = datetime.fromisoformat('2026-10-25T18:40:21+03:00').timestamp()
    finding = {'timestamp': 2000}
    annotate(finding, {'timestamp': '2026-10-25T18:40:21+03:00'}, now=happened + 365, cgroup_of=cgroups({}))
    assert finding['timestamp'] == int(happened) and finding['detected_at'] == int(happened + 365)


def test_implausible_event_times_are_ignored():
    now = 1_800_000_000
    assert event_epoch('not a date', now) is None
    assert event_epoch(now + 3600, now) is None          # future
    assert event_epoch(now - 40 * 86400, now) is None    # older than 30 days
    assert event_epoch(now - 5, now) == now - 5


def test_brain_loop_annotates_before_recording():
    text = (ROOT / 'run_satsuma_teams.py').read_text()
    assert text.index('annotate_origin(finding, event)') < text.index("record_finding(store, finding, 'smart_rules')")
