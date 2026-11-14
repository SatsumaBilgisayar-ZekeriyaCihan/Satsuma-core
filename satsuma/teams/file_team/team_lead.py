"""File detections from the ClamAV collector."""
from satsuma.teams.base import BaseTeamLead
from satsuma.worker_clamav import WorkerClamav
from satsuma.teams.file_team.rules import ClamavOnlyMatchRule

class FileTeamLead(BaseTeamLead):
    name = "file_team"
    description = "ClamAV file detections"
    workers = [WorkerClamav]
    rules = [ClamavOnlyMatchRule]
