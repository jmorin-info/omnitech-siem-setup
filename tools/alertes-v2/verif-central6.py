#!/usr/bin/env python3
# Attend le premier evenement w3wp->cmd de VM-DEV-CENTRAL6 recu APRES le rechargement (09:35:49 UTC) et verifie fp_signature.
import json, time, urllib.request
OUT = "/root/alertes-v2/verif-central6.txt"
def q(body): return json.load(urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:9200/omni-sysmon*/_search", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}), timeout=120))
fin = time.time() + 12 * 3600
while time.time() < fin:
    f = [{"term": {"host": "VM-DEV-CENTRAL6.omnitech.security"}}, {"term": {"winlogbeat_winlog_event_data_ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe"}},
         {"range": {"timestamp": {"gte": "2026-11-11 09:36:00.000", "format": "yyyy-MM-dd HH:mm:ss.SSS"}}}]
    d = q({"size": 3, "_source": ["timestamp", "fp_signature", "alert_tag", "winlogbeat_winlog_event_data_CommandLine"], "query": {"bool": {"filter": f}}, "sort": [{"timestamp": "asc"}],
           "aggs": {"sig": {"terms": {"field": "fp_signature", "missing": "(aucune)"}}, "tag": {"terms": {"field": "alert_tag", "missing": "(aucun)"}}}})
    n = d["hits"]["total"]["value"]
    if n:
        time.sleep(300)   # laisser arriver la salve, puis bilan
        d = q({"size": 3, "_source": ["timestamp", "fp_signature", "alert_tag", "winlogbeat_winlog_event_data_CommandLine"], "query": {"bool": {"filter": f}}, "sort": [{"timestamp": "asc"}],
               "aggs": {"sig": {"terms": {"field": "fp_signature", "missing": "(aucune)"}}, "tag": {"terms": {"field": "alert_tag", "missing": "(aucun)"}}}})
        open(OUT, "w").write(json.dumps({"verifie_le": time.strftime("%Y-%m-%d %H:%M:%S"), "evenements": d["hits"]["total"]["value"],
            "fp_signature": [(b["key"], b["doc_count"]) for b in d["aggregations"]["sig"]["buckets"]],
            "alert_tag": [(b["key"], b["doc_count"]) for b in d["aggregations"]["tag"]["buckets"]],
            "exemples": [h["_source"] for h in d["hits"]["hits"]]}, ensure_ascii=False, indent=1))
        break
    time.sleep(120)
else:
    open(OUT, "w").write("aucun evenement CENTRAL6 en 4 h")
