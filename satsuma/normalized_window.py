"""Read only the recent part of the normalized event table.

The records table keeps every normalized event and has no retention, so
reading it whole on every brain cycle grows without bound: on the field
machine each cycle took about 22 seconds and the teams service used three
quarters of a CPU core. An event can only be stored after it happened, so a
row whose insert time (``created``) is older than the window cannot hold an
event inside it. Rows are walked newest first by id and the walk stops at
the first row inserted well before the window; ``SLACK`` absorbs small clock
steps. In the rule engine the source is the in-memory event flow
(satsuma.flow, 2.2.32).

Normalize olay tablosunun yalnızca yakın zamanlı kısmını okur.

records tablosu her normalize olayı saklar ve hiç temizlenmez; bu yüzden onu
her beyin turunda baştan sona okumak sınırsızca büyür: saha makinesinde her
tur yaklaşık 22 saniye sürdü ve teams servisi bir çekirdeğin dörtte üçünü
kullandı. Bir olay ancak gerçekleştikten sonra kaydedilebilir; bu yüzden
ekleme zamanı (``created``) pencereden eski olan bir satır pencere içinde
bir olay taşıyamaz. Satırlar en yeniden eskiye id sırasıyla gezilir ve
pencereden belirgin biçimde önce eklenmiş ilk satırda durulur; ``SLACK``
küçük saat kaymalarını karşılar. Kural motorunda kaynak bellek içi olay
akışıdır (satsuma.flow, 2.2.32).
"""

SLACK = 120


def recent_rows(db, since_ts, slack=SLACK):
    """Yield (id, body) of normalized rows that may hold events at or after since_ts.

    In the rule engine the in-memory event flow (satsuma.flow, 2.2.32) is the
    source; normalized rows are then only what older versions left behind.
    """
    from . import flow
    if flow.ACTIVE is not None:
        yield from flow.ACTIVE.window_rows(since_ts - slack)
        return
    floor = since_ts - slack
    rows = db.execute("SELECT id, created, body FROM records WHERE kind='normalized' ORDER BY id DESC")
    for rid, created, body in rows:
        if created < floor:
            break
        yield rid, body
