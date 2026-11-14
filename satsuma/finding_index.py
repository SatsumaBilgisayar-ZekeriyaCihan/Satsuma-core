"""Writer-owned additive indexes for bounded family queries in read-only readers.

Salt okunur okuyucuda aile sorguları için yazıcının kurduğu ek indeksler.
"""
FAMILIES=('SATSUMA-RAM-','SATSUMA-MEM-','SATSUMA-FILELESS-')


def rule_expression(origin):
    prefix="$.metadata.finding" if origin=='core_event' else '$'
    raw="json_extract(body,'"+prefix+".rule_id')"
    fallback="CASE WHEN json_type(body,'"+prefix+".matched_rules')='array' THEN json_extract(body,'"+prefix+".matched_rules[0]') END"
    return "CASE WHEN json_valid(body) THEN coalesce(nullif(nullif("+raw+",''),0),"+fallback+") END"


def definition(origin):
    if origin=='host':
        return 'reader_host_rule_v1','findings',rule_expression('host'),'1'
    expr="CASE WHEN kind='events' THEN "+rule_expression('core_event')+' ELSE '+rule_expression('core')+' END'
    predicate="kind='findings' OR (kind='events' AND CASE WHEN json_valid(body) THEN json_extract(body,'$.event.category')='finding' ELSE 0 END)"
    return 'reader_core_rule_v1','records',expr,predicate


def install(db,origin):
    name,table,expr,predicate=definition(origin)
    db.execute('CREATE INDEX IF NOT EXISTS '+name+' ON '+table+'(('+expr+'))'
               +(' WHERE '+predicate if origin!='host' else ''))
    db.commit()


def restrict(db,origin):
    name,table,expr,predicate=definition(origin)
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?",(name,)).fetchone():
        raise ValueError('INDEX_PENDING: RAM bulgu indeksi henüz yazıcı tarafından kurulmadı')
    # Constants only; BINARY prefix ranges keep queries on the expression index.
    bounds=['(('+expr+") >= '"+p+"' AND ("+expr+") < '"+p[:-1]+".')" for p in FAMILIES]
    return ["("+predicate+") AND "+bound for bound in bounds]
