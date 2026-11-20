

def test_otx_never_auto_blocks_update_servers():
    """2.2.63 (field 2026-11-20): an OTX pulse put fedoraproject.org on the block list."""
    from satsuma.otx import update_infra_domain
    assert update_infra_domain('fedoraproject.org') and update_infra_domain('mirrors.fedoraproject.org')
    assert update_infra_domain('dl.flathub.org') and update_infra_domain('api.snapcraft.io')
    assert not update_infra_domain('fedorapeople.org') and not update_infra_domain('evilfedoraproject.org')
