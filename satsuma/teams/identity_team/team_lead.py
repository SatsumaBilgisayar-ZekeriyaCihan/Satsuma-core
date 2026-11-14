"""Kimlik Ekibi Başı."""
from satsuma.teams.base import BaseTeamLead
from satsuma.worker_audit_bridge import WorkerAuditBridge
from satsuma.worker_journal import WorkerJournal
from satsuma.teams.identity_team.rules import (
    PrivilegeEscalationRule,
    LoginAnomalyRule,
    SensitiveFileRule,
)


class IdentityTeamLead(BaseTeamLead):
    name = "identity_team"
    description = "Kimlik olayları: audit, journal, oturum, yetki"
    workers = [WorkerAuditBridge, WorkerJournal]
    rules = [PrivilegeEscalationRule, LoginAnomalyRule, SensitiveFileRule]
