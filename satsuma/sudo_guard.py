"""Sudo authorization is enforced by the installed PAM account module."""
def is_allowed(store, target):
    return False
def request_admin_approval(store, rule_id, reason, target, client="sudo-guard"):
    return {"approved":False,"reason":"use_sudo_pam_prompt"}
