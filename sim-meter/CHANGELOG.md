# Changelog

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
