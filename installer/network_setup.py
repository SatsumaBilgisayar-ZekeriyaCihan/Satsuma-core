import sys
sys.path.insert(0, '/opt/satsuma-core')
from satsuma.network_control import setup, lockdown, remove_lockdown


def restore_blocks():
    """2.2.47: ranges blocked by hand (satsuma.net_blocks) come back before traffic flows.

    A failure keeps the emergency DROP like every other step: the owner asked
    for these blocks, so the network does not open without them.
    """
    from satsuma.net_blocks import restore
    from satsuma.store import Store
    store = Store()
    try:
        restore(store)
    finally:
        store.close()


def main():
    try:
        # Install DROP + non-bypass queue rules even when the IPS cannot start.
        # Install the owned non-bypass queue before releasing network lockdown.
        from satsuma.app_firewall import apply, policy
        apply(policy()['enabled'])
        from satsuma.loopback_guard import setup as setup_loopback
        setup_loopback()
        setup()
        restore_blocks()
        remove_lockdown()
    except Exception as exc:
        try:
            lockdown()
        except Exception as locked:
            raise RuntimeError('Policy and emergency DROP both failed; firewall protection is unverified: '+str(locked)) from exc
        raise RuntimeError('Strict policy failed; emergency DROP remains active: '+str(exc)) from exc


if __name__ == '__main__':
    main()
