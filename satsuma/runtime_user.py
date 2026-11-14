import os,pwd
def require_service_user():
    if os.geteuid() not in (0,pwd.getpwnam("satsuma-core").pw_uid):
        raise PermissionError("Dedicated satsuma-core service account required")
