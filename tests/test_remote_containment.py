import os
import pytest
from installer.remote_containment import server_unit
@pytest.mark.parametrize('name',['sshd.service','sshd.socket','sshd@123.service','xrdp.service','vncserver@:1.service','gnome-remote-desktop.service','smb.service','nfs-server.service','rpcbind.socket'])
def test_remote_servers_and_shares_are_selected(name): assert server_unit(name)
@pytest.mark.parametrize('name',['teamviewerd.service','anydesk.service','satsuma-core.service','NetworkManager.service','ssh-agent.service','browser.service','../sshd.service'])
def test_clients_and_unrelated_units_are_preserved(name): assert not server_unit(name)


def test_watch_reuses_masks_but_still_stops_reactivated_servers(tmp_path,monkeypatch):
    from pathlib import Path
    from types import SimpleNamespace as NS
    from installer import remote_containment as guard
    import pwd

    runtime=tmp_path/'users'/str(os.getuid())
    runtime.mkdir(parents=True)
    (runtime/'bus').touch()
    root=tmp_path/'status';root.mkdir()
    monkeypatch.setattr(guard,'ROOT',root)
    monkeypatch.setattr(guard,'STATUS',root/'status.json')
    monkeypatch.setattr(guard,'Path',lambda value:tmp_path/'users' if value=='/run/user' else Path(value))
    monkeypatch.setattr(guard,'secure_directory',lambda path:None)
    monkeypatch.setattr(guard.os,'geteuid',lambda:0)
    monkeypatch.setattr(pwd,'getpwuid',lambda uid:NS(pw_name='fixture'))
    monkeypatch.setattr(guard,'_USER_RELOADS',{})
    masks=set();calls=[];active=set()
    def mask(name,user=False):
        key=(name,user)
        if key in masks:return False
        masks.add(key);return True
    monkeypatch.setattr(guard,'mask_local',mask)
    monkeypatch.setattr(guard,'user_units',lambda:(['gnome-remote-desktop.service'],mask('gnome-remote-desktop.service',True)))
    scans=[]
    monkeypatch.setattr(guard,'stop_processes',lambda:scans.append(True) or [])
    def run(args,check=True):
        calls.append(args)
        if 'list-unit-files' in args or 'list-units' in args:
            return NS(returncode=0,stdout='sshd.service enabled\n')
        scope='user' if '--user' in args else 'system'
        key=(scope,args[-1])
        if 'is-active' in args:return NS(returncode=0 if key in active else 3,stdout='')
        if 'stop' in args:active.discard(key)
        return NS(returncode=0,stdout='')
    monkeypatch.setattr(guard,'run',run)
    assert guard.apply()['status']=='guarded'
    assert sum('daemon-reload' in c for c in calls)==2
    assert [c for c in calls if 'disable' in c]==[
        ['/usr/bin/systemctl','--no-reload','disable','--','sshd.service']]
    calls.clear()
    active.update({('system','sshd.service'),('user','gnome-remote-desktop.service')})
    assert guard.apply()['status']=='guarded'
    assert not active and len(scans)==2
    assert not any('daemon-reload' in c or 'disable' in c for c in calls)
    # A restarted user manager gets its masks reloaded once.
    (runtime/'bus').rename(runtime/'old-bus');(runtime/'bus').touch()
    calls.clear();guard.apply()
    assert sum('daemon-reload' in c for c in calls)==1
    masks.remove(('gnome-remote-desktop.service',True))
    calls.clear();guard.apply()
    assert sum('daemon-reload' in c for c in calls)==1
