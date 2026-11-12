# omni_cible.py - ciblage des index Graylog par jeu + plage horaire (12/11/2026)
# Installé dans /usr/local/lib/omni-siem/. Au lieu d'interroger "omni-*" (1 235 shards),
# un robot demande cible(["omni-fortigate"], fenetre_s) et n'interroge que les index de ce
# jeu dont la période d'ÉCRITURE recoupe [now - fenetre - marge, now], plus le deflector.
# Exactitude : un document d'horodatage t est écrit à un instant >= t (aucun message daté
# dans le futur, contrôle du 12/11) ; il se trouve donc dans un index actif après t - marge.
# Repli sur le motif "<jeu>_*" si l'inventaire échoue ou si la liste est trop longue.
import json, time, urllib.request

OS_URL = "http://127.0.0.1:9200"

def _get(path):
    with urllib.request.urlopen(OS_URL + path, timeout=30) as r:
        return json.load(r)

def cible(prefixes, fenetre_s, marge_s=3600, max_len=3500):
    repli = ",".join(f"{p}_*" for p in prefixes)
    noms = []
    lim_ms = (time.time() - fenetre_s - marge_s) * 1000
    for p in prefixes:
        try:
            lst = _get(f"/_cat/indices/{p}_*?format=json&h=index,creation.date")
        except Exception:
            return repli
        lst = [x for x in lst if x["index"].rsplit("_", 1)[0] == p and x["index"].rsplit("_", 1)[-1].isdigit()]
        lst.sort(key=lambda x: int(x["index"].rsplit("_", 1)[1]))
        for i, x in enumerate(lst):
            fin = int(lst[i + 1]["creation.date"]) if i + 1 < len(lst) else float("inf")
            if fin >= lim_ms:
                noms.append(x["index"])
        noms.append(p + "_deflector")          # index d'écriture courant, même juste après une rotation
    s = ",".join(dict.fromkeys(noms))
    if not noms or len(s) > max_len:
        return repli
    return s
