# FortiAnalyzer → Graylog — full procedure

Objective: the FAZ (10.33.80.253) forwards FortiGate logs to Graylog
(10.33.220.10:1514). On the Graylog side **everything is already ready and verified**:
syslog TCP+UDP 1514 inputs RUNNING, nftables firewall opened for
10.33.80.253 only, `OMNI - FortiGate` pipeline (key=value parsing,
`srcip→src_ip`, GeoIP, tag `alert_tag:fortigate_utm`), stream + index
`omni-fortigate` (90 d), `OMNI - FortiGate` dashboard, alert
`OMNI - FortiGate: virus / IPS`.

## 1. Configuration on the FAZ side (GUI)

*System Settings > Advanced > Log Forwarding > Create New*:

| Field | Value |
|---|---|
| Status | Enabled |
| Remote Server Type | **Syslog** |
| Server FQDN/IP | `10.33.220.10` |
| Port | `1514` |
| Reliable Connection | **ON** (= TCP; OFF = UDP, also accepted but without guarantee) |
| Sending Frequency | Real-time |
| Log Forwarding Filters | see below |

**Recommended filters** (the FAZ remains the exhaustive network lake; we only send to
Graylog what is useful for correlation — otherwise `accept` traffic drowns everything):
- Device: the FortiGate(s)
- Log filters (OR):
  - `level` ≥ `warning`
  - `subtype` = `vpn` (all SSL-VPN / IPsec connections)
  - `subtype` = `admin` or `system` (admin actions on the FW)
  - `logid` of authentication failures (event/user)
  - UTM: `virus`, `ips`, `webfilter` (blocks), `application`
- Exclude: `type=traffic action=accept` (volume with no SIEM value).

## 2. FAZ CLI equivalent

```
config system log-forward
  edit 1
    set mode forwarding
    set fwd-server-type syslog
    set server-addr 10.33.220.10
    set server-port 1514
    set fwd-reliable enable
    set fwd-max-delay realtime
    set log-filter-status enable
    set log-filter-logic or
    config log-filter
      edit 1
        set field level
        set oper >=
        set value warning
      next
      edit 2
        set field subtype
        set oper =
        set value vpn
      next
    end
  next
end
```

## 3. Verification (on the Graylog VM)

```bash
cd ~/omnitech-siem-setup && source 00-vars.env && source lib-graylog.sh
# 1. Are packets arriving?
tcpdump -ni any host 10.33.80.253 and port 1514 -c 5
# 2. Is the input counting?
api_get /system/metrics/namespace/org.graylog2.inputs | \
  jq -r '.metrics[] | select(.full_name|test("Syslog.*incomingMessages")) | "\(.full_name): \(.metric.count)"'
# 3. Messages parsed? (event_source set by the pipeline)
curl -s "127.0.0.1:9200/omni-fortigate_*/_search?size=3" \
  -H 'Content-Type: application/json' -d '{"sort":[{"timestamp":"desc"}]}' | \
  jq '.hits.hits[]._source | {timestamp, host, src_ip, dest_ip, action, app, alert_tag}'
```
Then console: the **OMNI - FortiGate** dashboard must populate.

## 4. Notes

- The pipeline triggers on the presence of `devname=` in the message:
  native FortiGate/FAZ syslog format (key=value), no extractor to create.
- If you prefer the **CEF** format on the FAZ side: create the *CEF TCP* input port
  5555 in Graylog (System > Inputs), open 5555/tcp in
  `06-firewall.sh` for 10.33.80.253, and adapt the routing of the
  `OMNI - FortiGate` stream (add a rule on the CEF input). Syslog 1514
  remains the simplest path and is already tested.
- Timestamping: in production the FAZ puts the real time in the syslog header;
  messages appear immediately in relative searches
  (today's manual test seemed "invisible" only because
  its hand-crafted timestamp was in the future).

---

# REVISION (11/06) — all the UTM telemetry is missing

## Finding (measured over 2 h of real traffic)
- traffic: 1,013,419 (95%)  | event: 52,976 | **utm: 1,465 (only `voip`)**
- **No virus / ips / webfilter / dns / app-ctrl** is coming through.

=> This is NOT the FAZ or Graylog: the **FortiGate does not log its security
profiles**. Without that, the SIEM is blind to network threats (blocked malware,
IPS intrusions, C2 via DNS, forbidden browsing). This is the most serious hole.

## 1. FortiGate side — enable UTM logging (the real fix)
On EVERY outbound policy that must be inspected:
```
config firewall policy
  edit <id>
    set utm-status enable
    set av-profile "default"
    set ips-sensor "default"
    set webfilter-profile "default"
    set dnsfilter-profile "default"
    set application-list "default"
    set ssl-ssh-profile "certificate-inspection"
    set logtraffic all
  next
end
```
Then make sure each profile WRITES logs:
```
config antivirus profile
  edit "default"
    set av-virus-log enable
    set av-block-log enable
  next
end
config webfilter profile
  edit "default"
    set extended-log enable
    config ftgd-wf
      set options error-allow rate-server-ip
    end
  next
end
config application list
  edit "default"
    set extended-log enable
    set other-application-log enable
    set unknown-application-log enable
  next
end
config dnsfilter profile
  edit "default"
    set log-all-domain enable
  next
end
```
(IPS: signatures log by default; check `config ips sensor` -> action
log enable on the filters.)

## 2. FAZ side — revised forwarding filter (keep everything relevant)
OR logic: we keep event (vpn/user/admin/system), utm (all signatures),
anomaly (DoS), blocked traffic, and anything >= warning. Only verbose
`accept`/`notice` traffic is dropped.
```
config system log-forward
  edit 1
    set log-filter-status enable
    set log-filter-logic or
    config log-filter
      edit 1
        set field type
        set oper =
        set value event
      next
      edit 2
        set field type
        set oper =
        set value utm
      next
      edit 3
        set field type
        set oper =
        set value anomaly
      next
      edit 4
        set field action
        set oper =
        set value deny
      next
      edit 5
        set field level
        set oper >=
        set value warning
      next
    end
  next
end
```
Option: add `subtype = local` (local-in/out traffic to the FortiGate =
admin access) if you want to trace administration of the firewall.

## 3. Verification (on the SIEM, ~5 min later)
```bash
curl -s "127.0.0.1:9200/omni-fortigate_*/_search?size=0" -H 'Content-Type: application/json' \
 -d '{"query":{"bool":{"must":[{"term":{"type":"utm"}},{"range":{"timestamp":{"gte":"now-15m"}}}]}},
      "aggs":{"x":{"terms":{"field":"subtype","size":15}}}}' | jq -r '.aggregations.x.buckets[]|"\(.doc_count)\t\(.key)"'
```
You should see virus / ips / webfilter / dns / app-ctrl appear. The "Network"
dashboard page will then populate with real UTM detections.
