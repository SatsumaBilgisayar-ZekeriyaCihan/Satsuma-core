"""Host Ekibi Başı."""
from satsuma.teams.base import BaseTeamLead
from satsuma.worker_systemd_dbus import WorkerSystemdDbus
from satsuma.worker_kernel import WorkerKernel
from satsuma.teams.host_team.rules import ProcessChainRule, KernelTaintRule


class HostTeamLead(BaseTeamLead):
    name = "host_team"
    description = "Host olayları: süreç, modül, USB, systemd, kernel"
    # sys_proc ana satsuma-core servisinin sürekli collector'ıdır; burada tekrar başlatılmaz.
    workers = [WorkerSystemdDbus, WorkerKernel]
    rules = [ProcessChainRule, KernelTaintRule]
