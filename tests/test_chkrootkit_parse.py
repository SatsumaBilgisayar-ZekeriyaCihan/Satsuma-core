"""chkrootkit output becomes findings by kind; an unreadable scan is never reported as clean.

chkrootkit çıktısı türe göre bulgulara dönüşür; okunamayan tarama asla temiz bildirilmez.
"""
from types import SimpleNamespace

import pytest

from satsuma import security_scan as scan

PROBLEMS = """\
Checking `bindshell'... INFECTED (PORTS:  465)
Checking `lkm'... chkproc: Warning: Possible LKM Trojan installed
chkproc: Warning: Possible LKM Trojan installed
You have     2 process hidden for ps command
Checking `sniffer'... enp34s0: PACKET SNIFFER(/usr/sbin/dhclient[1234])
"""


def test_each_kind_of_problem_line_is_a_finding():
    result = scan.parse_chkrootkit(PROBLEMS)
    assert result['kinds'] == {'infected': 1, 'lkm_trojan': 1, 'hidden_process': 1, 'packet_sniffer': 1}
    assert result['findings'] == 4 and result['incomplete'] is False
    assert any('bindshell' in line for line in result['lines'])


def test_clean_lines_are_never_findings_even_in_the_verbose_format():
    verbose = "\n".join(f"Checking `{name}'... not infected" for name in ('amd', 'basename', 'biff')) + """
Checking `lkm'... nothing found
Checking `wted'... nothing deleted
Checking `rexedcs'... not found
Checking `sniffer'... not promisc and no packet sniffer sockets
Checking `chkutmp'... not tested
"""
    assert scan.parse_chkrootkit(verbose)['findings'] == 0


def test_the_word_infected_inside_not_infected_is_not_counted_but_a_real_one_next_to_it_is():
    mixed = "Checking `amd'... not infected\nChecking `inetd'... INFECTED\n"
    assert scan.parse_chkrootkit(mixed)['kinds'] == {'infected': 1}


def test_permission_denied_marks_the_scan_incomplete_and_is_not_a_finding():
    text = "/usr/bin/awk: cannot open /proc/1/mem: Permission denied\nls: cannot access '/root': Permission denied\n"
    result = scan.parse_chkrootkit(text)
    assert result['findings'] == 0 and result['incomplete'] is True and result['permission_denied'] == 2


def test_a_repeated_line_counts_once():
    assert scan.parse_chkrootkit('chkproc: Warning: Possible LKM Trojan installed\n' * 5)['findings'] == 1


def test_at_most_32_lines_are_kept_but_every_finding_is_counted():
    text = ''.join("Checking `x%d'... INFECTED (PORTS: %d)\n" % (i, i) for i in range(50))
    result = scan.parse_chkrootkit(text)
    assert result['findings'] == 50 and len(result['lines']) == 32


def run_chkrootkit(tmp_path, text, code=0):
    def runner(command, stdout=None, **kwargs):
        stdout.write(text.encode())
        return SimpleNamespace(returncode=code)
    return scan._result('chkrootkit', ['/usr/bin/chkrootkit', '-q'], runner=runner, archive=tmp_path)


def test_a_scan_with_problems_reports_findings_with_their_kinds_and_lines(tmp_path):
    result = run_chkrootkit(tmp_path, PROBLEMS)
    assert result['status'] == 'FINDINGS' and result['findings'] == 4
    assert result['finding_kinds']['hidden_process'] == 1 and len(result['finding_lines']) == 4
    assert result['incomplete'] is False


def test_a_clean_complete_scan_is_completed(tmp_path):
    result = run_chkrootkit(tmp_path, '')
    assert result['status'] == 'COMPLETED' and result['findings'] == 0 and result['incomplete'] is False


def test_a_scan_that_could_not_read_everything_is_a_warning_not_clean(tmp_path):
    result = run_chkrootkit(tmp_path, "cannot open /proc/1/mem: Permission denied\n")
    assert result['status'] == 'WARNING' and result['incomplete'] is True and result['permission_denied'] == 1
    assert result['findings'] == 0


def test_findings_win_over_incompleteness_but_both_are_reported(tmp_path):
    result = run_chkrootkit(tmp_path, PROBLEMS + "cannot open /proc/1/mem: Permission denied\n")
    assert result['status'] == 'FINDINGS' and result['incomplete'] is True


def test_other_scanners_results_are_unchanged(tmp_path):
    def runner(command, stdout=None, **kwargs):
        stdout.write(b'Infected files: 0\n')
        return SimpleNamespace(returncode=0)
    result = scan._result('clamav', ['/usr/bin/clamdscan'], runner=runner, archive=tmp_path)
    assert result['status'] == 'COMPLETED' and 'finding_kinds' not in result and 'incomplete' not in result
