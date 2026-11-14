from workers.finding.persistence import inventory

def test_inventory_detects_writable_unit(tmp_path):
    units=tmp_path/'units';units.mkdir()
    udev=tmp_path/'rules';udev.mkdir()
    f=units/'odd.service';f.write_text('[Service]\\n')
    f.chmod(0o666)
    result=inventory((str(units),),(str(udev),))
    assert str(f) in result['world_or_group_writable']
    assert result['enforcement'] is False
    assert result['trust']=='local_filesystem_unverified'

def test_persistence_inventory_no_mutations(tmp_path):
    path=tmp_path/'units';path.mkdir()
    f=path/'a.service';f.write_text('sentinel')
    first=inventory((str(path),),())
    second=inventory((str(path),),())
    assert first['fingerprint']==second['fingerprint']
    assert f.read_text()=='sentinel'
