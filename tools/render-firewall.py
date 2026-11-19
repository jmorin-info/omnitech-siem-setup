#!/usr/bin/env python3
"""Render namespaced nftables rules from the site's environment; never apply them."""
import ipaddress
import os


def render(env):
    def network(key, default=""):
        value = env.get(key, default)
        return ipaddress.ip_network(value, strict=False) if value else None

    def allow(protocol, port, source, label):
        net = source
        if net is None:
            return None
        family = "ip6" if net.version == 6 else "ip"
        return f'        {protocol} dport {port} {family} saddr {net} accept comment "{label}"'

    admin = network("NET_ADMIN")
    if not admin:
        raise ValueError("NET_ADMIN must be configured")
    rules = [allow("tcp", "22", admin, "SSH administration"),
             allow("tcp", "{ 80, 443 }", network("WEB_NET", str(admin)), "SIEM web"),
             allow("tcp", "5044", network("NET_BEATS"), "Beats TLS")]
    sources = [("IP_FAZ", "1514", ("tcp", "udp")), ("VSPHERE_NET", "1516", ("tcp", "udp")),
               ("NET_BEATS", "1519", ("tcp",)), ("NET_ARUBA", "1520", ("tcp", "udp")),
               ("IP_FORTIMANAGER", "1517", ("tcp", "udp")), ("IP_CENTREON", "161", ("udp",))]
    for key, port, protocols in sources:
        rules.extend(allow(proto, port, network(key), key) for proto in protocols)
    for key, port_key, default in [("IP_ESET", "ESET_PORT", "1515"), ("IP_EMS", "EMS_PORT", "1518")]:
        port = int(env.get(port_key, default))
        if not 1024 <= port <= 65535:
            raise ValueError(f"{port_key} must be an unprivileged TCP port")
        rules.append(allow("tcp", str(port), network(key), key))
    lines = ["#!/usr/sbin/nft -f", "# Managed SIEM table; unrelated firewall tables are retained.",
             "add table inet omni_siem", "flush table inet omni_siem", "table inet omni_siem {",
             "    chain input {", "        type filter hook input priority 0; policy drop;",
             '        iif "lo" accept', "        ct state established,related accept", "        ct state invalid drop",
             "        ip protocol icmp limit rate 10/second accept",
             "        meta l4proto ipv6-icmp limit rate 10/second accept", *filter(None, rules), "    }", "}"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    try:
        print(render(os.environ), end="")
    except ValueError as exc:
        raise SystemExit(str(exc))
