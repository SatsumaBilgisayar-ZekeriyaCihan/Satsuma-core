"""Satsuma Risk Engine v0.2.

Risk/severity ile kanıt güvenini birbirinden ayırır. Suricata imzası tek başına
"confirmed" değildir; risk skoru yalnızca inceleme/response politikasına girdi sağlar.
"""
from __future__ import annotations

import ipaddress


class RiskEngine:
    def analyze(self, incident):
        score = 0
        reasons = []

        severity = incident.get('severity', 0)
        if severity == 1:
            score += 35
            reasons.append('SURICATA_SEVERITY_1')
        elif severity == 2:
            score += 20
            reasons.append('SURICATA_SEVERITY_2')
        elif severity == 3:
            score += 10
        else:
            score += 5

        count = int(incident.get('count', 0) or 0)
        if count > 5000:
            score += 25
            reasons.append('EXTREME_FREQUENCY')
        elif count > 1000:
            score += 15
            reasons.append('HIGH_FREQUENCY')
        elif count > 100:
            score += 10
            reasons.append('ELEVATED_FREQUENCY')
        elif count >= 2:
            score += 5
            reasons.append('REPEATED_SIGNATURE')

        global_destination = False
        loopback = False
        local_only = True
        for value in (incident.get('sources') or []) + (incident.get('destinations') or []):
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                continue
            if addr.is_loopback:
                loopback = True
            if addr.is_global:
                local_only = False
        for value in incident.get('destinations') or []:
            try:
                if ipaddress.ip_address(value).is_global:
                    global_destination = True
            except ValueError:
                pass

        if loopback:
            score -= 15
            reasons.append('LOOPBACK_TRAFFIC')
        elif global_destination:
            score += 10
            reasons.append('GLOBAL_DESTINATION')
        elif local_only:
            reasons.append('LOCAL_OR_PRIVATE_TRAFFIC')

        signature = str(incident.get('signature', '')).lower()
        threat_words = ('trojan', 'ransomware', 'malware', 'command and control', 'c2', 'exploit')
        if any(word in signature for word in threat_words):
            score += 15
            reasons.append('THREAT_SIGNATURE_WORDING')

        if str(incident.get('suricata_action', '')).lower() in {'blocked', 'drop', 'reject'}:
            score += 5
            reasons.append('SURICATA_DROP_ACTION')

        score = max(score, 0)
        if score >= 80:
            level = 'CRITICAL'
            classification = 'likely'
            confidence = 'high'
        elif score >= 60:
            level = 'HIGH'
            classification = 'suspicious'
            confidence = 'medium'
        elif score >= 30:
            level = 'MEDIUM'
            classification = 'suspicious'
            confidence = 'medium'
        else:
            level = 'LOW'
            classification = 'indicator'
            confidence = 'low'

        return {
            'risk_score': score,
            'risk_level': level,
            'classification': classification,
            'confidence': confidence,
            'analysis': {'reasons': reasons},
        }
