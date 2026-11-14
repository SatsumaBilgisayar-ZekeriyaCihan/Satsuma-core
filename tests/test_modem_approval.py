import copy
import pytest
from satsuma import modem_identity as m
from installer import integrity


@pytest.fixture(autouse=True)
def catalog_fixture(monkeypatch):
    monkeypatch.setattr(m,'defined_tables',lambda:{'253':'default','254':'main','255':'local','777':'empty_custom'})


def reader(extra_route=False):
    def query(*args):
        if args==('link','show'):return [{'ifname':'eth0','link_type':'ether','address':'02:00:00:00:00:01'}]
        if args==('-4','route','show','table','all'):
            data=[{'dst':'default','dev':'eth0','gateway':'192.168.1.1','table':'main'},
                  {'dst':'10.0.0.0/24','dev':'eth0','table':101}]
            if extra_route:data.append({'dst':'45.33.0.0/16','dev':'eth0','gateway':'192.168.1.99','table':101})
            return data
        if args==('-4','rule','show'):return [{'priority':100,'table':101}]
        if args[0]=='-6':return []
        if args[:3]==('neigh','show','to'):return [{'dst':'192.168.1.1','lladdr':'02:00:00:00:00:02'}]
        raise AssertionError(args)
    return query


def test_lists_all_tables_without_approving_the_first_neighbor():
    data=m.inventory(reader())
    assert {'101','253','254','255'}<=set(data['tables'])
    assert data['approval_required'] is True and data['network_mutations_enabled'] is False
    assert len(data['candidates'])==1
    assert m.compare(None,data)['status']=='MODEM_APPROVAL_REQUIRED'


def test_explicit_uid_bound_single_approval_and_replaced_reference(monkeypatch):
    data=m.inventory(reader());saved=[]
    monkeypatch.setattr(integrity,'read_key',lambda:b'k'*32)
    with pytest.raises(PermissionError):m.approve(data['candidates'][0]['id'],1000,False,provider=lambda:data,writer=saved.append)
    assert not saved
    result=m.approve(data['candidates'][0]['id'],1000,True,provider=lambda:data,writer=saved.append)
    policy=saved[-1]['policy']
    assert policy['approval_uid']==1000 and policy['source']=='explicit_user_selection'
    assert isinstance(policy['modem'],dict) and 'modems' not in policy
    assert result['status']=='USER_REFERENCE_SAVED'
    assert m.compare(policy,data)['status']=='MATCHED_USER_APPROVAL'
    assert m.compare(policy,m.inventory(reader(extra_route=True)))['status']=='MODEM_REFERENCE_CHANGED'
    with pytest.raises(ValueError):m.approve('stale-or-forged',1000,True,provider=lambda:data,writer=saved.append)


def test_same_modem_with_changed_route_rule_or_mac_is_not_reported_healthy(monkeypatch):
    data=m.inventory(reader());saved=[]
    monkeypatch.setattr(integrity,'read_key',lambda:b'k'*32)
    m.approve(data['candidates'][0]['id'],1000,True,provider=lambda:data,writer=saved.append)
    policy=saved[-1]['policy']
    for modify in ('route','mac','extra'):
        changed=copy.deepcopy(data)
        if modify=='route':changed['route_fingerprint']='changed'
        elif modify=='mac':changed['candidates'][0]['gateway_mac']='02:00:00:00:00:03'
        else:changed['candidates'].append({**changed['candidates'][0],'table':'999'})
        assert m.compare(policy,changed)['status']=='MODEM_REFERENCE_CHANGED'


def test_no_modem_auto_approval_when_candidates_missing():
    data=m.inventory(lambda *args:[])
    assert not data['candidates'] and data['suggested_id'] is None
    assert m.compare(None,data)['status']=='MODEM_APPROVAL_REQUIRED'


def test_pending_modem_is_never_protection_ready_but_can_complete_payload_install():
    import time
    from installer.runtime_check import record_modem_status
    result={'errors':[],'warnings':[]}
    record_modem_status(result,{'status':'MODEM_APPROVAL_REQUIRED','updated_at':time.time()})
    assert result['modem_approval_pending'] is True and result['warnings'] and not result['errors']
    result={'errors':[],'warnings':[]}
    record_modem_status(result,{'status':'MODEM_REFERENCE_CHANGED','updated_at':time.time()})
    assert result['errors']


def test_unrelated_route_change_since_preview_does_not_block_approval(monkeypatch):
    # The candidate id pins table, interface, gateway and both MACs.
    data=m.inventory(reader());saved=[]
    monkeypatch.setattr(integrity,'read_key',lambda:b'k'*32)
    m.approve(data['candidates'][0]['id'],1000,True,provider=lambda:data,writer=saved.append,expected_fingerprint='stale')
    assert saved and saved[0]['policy']['modem']==data['candidates'][0]
    preview=m.preview(provider=lambda:data)
    assert preview['confirmation_required'] and preview['ready_for_automatic']
    assert preview['route_fingerprint']==data['route_fingerprint']


def _routes_reader(route, neighbors=(), link_type='ether'):
    def read(*args):
        if args[:2]==('link','show'):
            return [{'ifname':'enp3s0','link_type':link_type,'address':'52:54:00:12:34:56'}]
        if args[0]=='-6':raise RuntimeError('RTNETLINK answers: Address family not supported by protocol')
        if args[1:3]==('route','show'):return [route]
        if args[0]=='neigh':return list(neighbors)
        return []
    return read


def test_empty_modem_list_always_says_why(tmp_path):
    no_arp=str(tmp_path/'arp')
    cases=[({'dst':'default','dev':'tun0'},(),'ether','ağ geçidi yok'),
           ({'dst':'default','gateway':'192.168.1.1','dev':'enp3s0'},(),'none','Ethernet/Wi-Fi'),
           ({'dst':'default','gateway':'192.168.1.1','dev':'enp3s0'},(),'ether','MAC adresi')]
    for route,neighbors,kind,text in cases:
        data=m.inventory(_routes_reader(route,neighbors,kind))
        assert not data['candidates'] and text in data['rejected'][0]['reason']
        assert text in ' '.join(m.not_found(data))
    assert 'varsayılan rota yok' in m.not_found(m.inventory(lambda *a:[]))[0]


def test_ipv6_failure_does_not_hide_the_ipv4_modem_and_arp_is_a_fallback(tmp_path,monkeypatch):
    arp=tmp_path/'arp'
    arp.write_text('IP address HW type Flags HW address Mask Device\n192.168.1.1 0x1 0x2 a8:9a:93:00:00:01 * enp3s0\n')
    original=m.arp_mac
    monkeypatch.setattr(m,'arp_mac',lambda gateway,interface:original(gateway,interface,str(arp)))
    data=m.inventory(_routes_reader({'dst':'default','gateway':'192.168.1.1','dev':'enp3s0'}))
    assert data['candidates'][0]['gateway_mac']=='a8:9a:93:00:00:01'
    data=m.inventory(_routes_reader({'dst':'default','gateway':'192.168.1.1','dev':'enp3s0'},
                                    [{'dst':'192.168.1.1','lladdr':'a8:9a:93:00:00:02','state':['REACHABLE']}]))
    assert data['candidates'][0]['gateway_mac']=='a8:9a:93:00:00:02'



def test_user_can_type_the_modem_mac_when_none_is_seen(monkeypatch):
    monkeypatch.setattr(integrity,'read_key',lambda:b'k'*32)
    monkeypatch.setattr(m,'arp_mac',lambda gateway,interface:None)
    data=m.inventory(_routes_reader({'dst':'default','gateway':'192.168.1.1','dev':'enp3s0'}))
    assert not data['candidates'] and len(data['manual_routes'])==1
    saved=[]
    with pytest.raises(PermissionError):
        m.approve_manual('A8-9A-93-12-34-56',1000,False,provider=lambda:data,writer=saved.append)
    for bad in ('', 'a8:9a:93:12:34', '00:00:00:00:00:00', '01:00:5e:00:00:01', 'zz:9a:93:12:34:56'):
        with pytest.raises(ValueError):m.approve_manual(bad,1000,True,provider=lambda:data,writer=saved.append)
    result=m.approve_manual('A8-9A-93-12-34-56',1000,True,provider=lambda:data,writer=saved.append)
    modem=saved[0]['policy']['modem']
    assert modem['gateway_mac']=='a8:9a:93:12:34:56' and modem['gateway']=='192.168.1.1' and modem['interface']=='enp3s0'
    assert saved[0]['policy']['mac_typed_by_user'] and result['observed_mac'] is None
    # Once the modem answers with the typed MAC, the stored reference matches it.
    seen=m.inventory(_routes_reader({'dst':'default','gateway':'192.168.1.1','dev':'enp3s0'},
                                    [{'dst':'192.168.1.1','lladdr':'a8:9a:93:12:34:56','state':['REACHABLE']}]))
    assert seen['candidates'][0]==modem
    other=m.inventory(_routes_reader({'dst':'default','gateway':'192.168.1.1','dev':'enp3s0'},
                                     [{'dst':'192.168.1.1','lladdr':'a8:9a:93:00:00:99','state':['REACHABLE']}]))
    assert m.compare(saved[0]['policy'],other)['status']=='MODEM_REFERENCE_CHANGED'


def test_typed_mac_reports_a_different_answering_device(monkeypatch):
    monkeypatch.setattr(integrity,'read_key',lambda:b'k'*32)
    data=m.inventory(_routes_reader({'dst':'default','gateway':'192.168.1.1','dev':'enp3s0'},
                                    [{'dst':'192.168.1.1','lladdr':'a8:9a:93:00:00:99','state':['REACHABLE']}]))
    result=m.approve_manual('a8:9a:93:12:34:56',1000,True,provider=lambda:data,writer=[].append)
    assert result['observed_mac']=='a8:9a:93:00:00:99' and result['matches_observed'] is False
