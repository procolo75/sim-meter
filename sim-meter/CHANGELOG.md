# Changelog

## 1.3.0
- The traffic diagnostic now says **who** generated each flow: the add-on's name, or `host` for
  Home Assistant Core and the add-ons that share the host network (listed in the log).
  Containers are recognised by also capturing on the Docker bridges, before NAT, and names come
  from the Supervisor API (`hassio_api: true`).
- New "Per origine" summary: MB and 30-day projection for each add-on.

## 1.2.0
- Configurable diagnostic duration (`diagnostic_seconds`, 30 s to 1 h; default 120 s).
- The capture is aggregated while it runs, so even an hour uses no extra memory; the log lists the top 25 hosts.
- Option names and descriptions translated (English, Italian).
- `tablet_ip` is empty by default.

## 1.1.1
- Multicast no longer shows up among the LAN IPv6 prefixes or in the diagnostic (cosmetic: the counters already excluded it).

## 1.1.0
- The LAN's public IPv6 prefixes are excluded: home devices talking to HA over IPv6 no longer count as Internet.
- New **Traffic diagnostic** button: captures traffic and logs the top remote hosts with MB, port and reverse DNS.

## 1.0.0
- First version: iptables (mangle) accounting on the host's physical interface, Internet traffic separated from LAN,
  optional LAN device counter, MQTT sensors with a 30-day projection and a reset button.
