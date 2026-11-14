"""Ag Ekibi Basi. Suricata collector ana Core servisinin tek sorumlulugudur."""
from satsuma.teams.base import BaseTeamLead
from satsuma.network_discovery import WorkerNetworkDiscovery
from satsuma.vpn_proxy import WorkerVpnProxy
from satsuma.teams.network_team.rules import C2CommunicationRule, PortScanRule, DnsTunnelingRule


class NetworkTeamLead(BaseTeamLead):
    name = "network_team"
    description = "Ag olaylari: mevcut normalized Suricata/DNS/TLS/HTTP olaylarini korele eder"
    # Ayrica eve.json okumaz. Aksi halde ana Reader ile ayni trafik iki kez ingest edilir.
    workers = [WorkerNetworkDiscovery, WorkerVpnProxy]
    rules = [C2CommunicationRule, PortScanRule, DnsTunnelingRule]
