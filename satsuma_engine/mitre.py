"""MITRE ATT&CK eşleme tablosu ve doğrulaması."""
from __future__ import annotations
from typing import Any
from .errors import Issue
TACTICS={"reconnaissance":"Keşif","resource-development":"Kaynak Geliştirme","initial-access":"İlk Erişim","execution":"Yürütme","persistence":"Kalıcılık","privilege-escalation":"Yetki Yükseltme","defense-evasion":"Savunmadan Kaçınma","credential-access":"Kimlik Bilgisi Erişimi","discovery":"Keşif (Discovery)","lateral-movement":"Yanal Hareket","collection":"Toplama","command-and-control":"Komuta ve Kontrol","exfiltration":"Veri Sızdırma","impact":"Etki"}
TECHNIQUES={"T1003":("credential-access","OS Credential Dumping"),"T1003.008":("credential-access","/etc/passwd and /etc/shadow"),"T1041":("exfiltration","Exfiltration Over C2 Channel"),"T1011":("exfiltration","Exfiltration Over Other Network Medium"),"T1014":("defense-evasion","Rootkit"),"T1021":("lateral-movement","Remote Services"),"T1021.004":("lateral-movement","Remote Services: SSH"),"T1027":("defense-evasion","Obfuscated Files or Information"),"T1036":("defense-evasion","Masquerading"),"T1036.005":("defense-evasion","Masquerading: Match Legitimate Name or Location"),"T1046":("discovery","Network Service Discovery"),"T1053.003":("persistence","Scheduled Task/Job: Cron"),"T1055":("defense-evasion","Process Injection"),"T1059":("execution","Command and Scripting Interpreter"),"T1059.004":("execution","Command and Scripting Interpreter: Unix Shell"),"T1059.006":("execution","Command and Scripting Interpreter: Python"),"T1068":("privilege-escalation","Exploitation for Privilege Escalation"),"T1070.003":("defense-evasion","Indicator Removal: Clear Command History"),"T1070.004":("defense-evasion","Indicator Removal: File Deletion"),"T1071":("command-and-control","Application Layer Protocol"),"T1071.001":("command-and-control","Application Layer Protocol: Web Protocols"),"T1090":("command-and-control","Proxy"),"T1078":("defense-evasion","Valid Accounts"),"T1082":("discovery","System Information Discovery"),"T1083":("discovery","File and Directory Discovery"),"T1087.001":("discovery","Account Discovery: Local Account"),"T1090.003":("command-and-control","Proxy: Multi-hop Proxy"),"T1095":("command-and-control","Non-Application Layer Protocol"),"T1098":("persistence","Account Manipulation"),"T1105":("command-and-control","Ingress Tool Transfer"),"T1110":("credential-access","Brute Force"),"T1133":("persistence","External Remote Services"),"T1136.001":("persistence","Create Account: Local Account"),"T1190":("initial-access","Exploit Public-Facing Application"),"T1204":("execution","User Execution"),"T1205":("command-and-control","Traffic Signaling"),"T1222.002":("defense-evasion","File and Directory Permissions Modification: Linux and Mac"),"T1485":("impact","Data Destruction"),"T1486":("impact","Data Encrypted for Impact"),"T1489":("impact","Service Stop"),"T1490":("impact","Inhibit System Recovery"),"T1496":("impact","Resource Hijacking"),"T1505.003":("persistence","Server Software Component: Web Shell"),"T1542.001":("persistence","Pre-OS Boot: System Firmware"),"T1543.002":("persistence","Create or Modify System Process: Systemd Service"),"T1546":("privilege-escalation","Event Triggered Execution"),"T1547.006":("persistence","Boot or Logon Autostart Execution: Kernel Modules and Extensions"),"T1548.001":("privilege-escalation","Abuse Elevation Control Mechanism: Setuid and Setgid"),"T1548.003":("privilege-escalation","Abuse Elevation Control Mechanism: Sudo and Sudo Caching"),"T1552":("credential-access","Unsecured Credentials"),"T1552.001":("credential-access","Unsecured Credentials: Credentials In Files"),"T1552.004":("credential-access","Unsecured Credentials: Private Keys"),"T1556":("defense-evasion","Modify Authentication Process"),"T1562.001":("defense-evasion","Impair Defenses: Disable or Modify Tools"),"T1562.004":("defense-evasion","Impair Defenses: Disable or Modify System Firewall"),"T1567":("exfiltration","Exfiltration Over Web Service"),"T1567.002":("exfiltration","Exfiltration to Cloud Storage"),"T1611":("privilege-escalation","Escape to Host"),"T1620":("defense-evasion","Reflective Code Loading"),"T1571":("command-and-control","Non-Standard Port")}
def technique_name(technique):
    entry=TECHNIQUES.get(technique); return entry[1] if entry else None
def tactic_for(technique):
    entry=TECHNIQUES.get(technique); return entry[0] if entry else None
def tactic_label(tactic):return TACTICS.get(tactic,tactic)
def is_known_technique(technique):return technique in TECHNIQUES
def is_known_tactic(tactic):return tactic in TACTICS
def validate_mitre(entries:Any,location:str)->list[Issue]:
    issues=[]
    if not entries:return issues
    for index,entry in enumerate(entries):
        if not isinstance(entry,dict):continue
        technique=str(entry.get("technique","")); where=f"{location}[{index}]"
        if not is_known_technique(technique):issues.append(Issue("rule.mitre_unknown_technique",f"ATT&CK teknik kimliği tabloda yok: {technique}",where,"warning", "Yeni bir teknik ise `satsuma_engine/mitre.py` tablosuna ekleyin; yazım hatasıysa düzeltin."))
        declared=entry.get("tactic"); expected=tactic_for(technique)
        if declared and expected and str(declared)!=expected:issues.append(Issue("rule.mitre_tactic_mismatch",f"{technique} için beklenen taktik `{expected}`, kuralda `{declared}` yazıyor.",where,"warning"))
        if declared and not is_known_tactic(str(declared)):issues.append(Issue("rule.mitre_unknown_tactic",f"Bilinmeyen taktik: {declared}",where,"warning",f"Geçerli taktikler: {', '.join(sorted(TACTICS))}"))
    return issues
def enrich(entries):
    result=[]
    for entry in entries or []:
        if not isinstance(entry,dict):continue
        technique=str(entry.get("technique","")); tactic=str(entry.get("tactic") or tactic_for(technique) or ""); name=str(entry.get("name") or technique_name(technique) or ""); record={"technique":technique}
        if tactic:record["tactic"]=tactic
        if name:record["name"]=name
        result.append(record)
    return result
