import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sim-meter"))

import sim_meter as sm  # noqa: E402

ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
docker0\t0020FEAC\t00000000\t0001\t0\t0\t0\t00FEFFFF\t0\t0\t0
enp1s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
enp1s0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
"""

CHAIN_IN = """-N SIMM_IN
-A SIMM_IN -s 192.168.1.112/32 -c 120 51200 -j RETURN
-A SIMM_IN -s 10.0.0.0/8 -c 0 0 -j RETURN
-A SIMM_IN -s 192.168.0.0/16 -c 9000 7777777 -j RETURN
-A SIMM_IN -c 300 1048576 -j RETURN
"""


def test_default_interface():
    assert sm.default_interface(ROUTE) == "enp1s0"
    assert sm.default_interface(ROUTE.splitlines()[0]) is None


def test_rule_specs_order_tablet_first_internet_last():
    specs = sm.rule_specs("SIMM_OUT", "out", "192.168.1.112", ["10.0.0.0/8"])
    assert specs[0] == ["-A", "SIMM_OUT", "-d", "192.168.1.112", "-j", "RETURN"]
    assert specs[-1] == ["-A", "SIMM_OUT", "-j", "RETURN"]
    assert len(specs) == 3


def test_parse_counters():
    assert sm.parse_counters(CHAIN_IN, "192.168.1.112") == (51200, 1048576)


def test_parse_counters_without_tablet_ignores_lan():
    text = "\n".join(l for l in CHAIN_IN.splitlines() if "112" not in l)
    assert sm.parse_counters(text, None) == (0, 1048576)


def test_parse_counters_missing_rule():
    try:
        sm.parse_counters("-N SIMM_IN\n", None)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_meter_survives_counter_reset_and_restart(tmp_path):
    path = str(tmp_path / "state.json")
    m = sm.Meter(path)
    raw = dict.fromkeys(sm.COUNTERS, 0)
    m.update({**raw, "internet_in": 1000, "tablet_out": 10})
    m.update({**raw, "internet_in": 1500, "tablet_out": 30})
    m.update({**raw, "internet_in": 200, "tablet_out": 5})  # counters dropped: host rebooted
    assert m.state["totals"]["internet_in"] == 1700
    assert m.state["totals"]["tablet_out"] == 35

    m2 = sm.Meter(path)  # add-on restarted: rules recreated, totals kept
    m2.counters_reset()
    m2.update({**raw, "internet_in": 300})
    assert m2.state["totals"]["internet_in"] == 2000
    assert m2.state["start"] == m.state["start"]


def test_reset(tmp_path):
    m = sm.Meter(str(tmp_path / "s.json"))
    m.update({**dict.fromkeys(sm.COUNTERS, 0), "internet_out": 999})
    m.reset()
    assert sum(m.state["totals"].values()) == 0


def test_summarize_projection():
    start = 1_000_000.0
    state = {"start": start, "totals": {"internet_in": 2 * sm.GB, "internet_out": 1 * sm.GB,
                                        "tablet_in": 0, "tablet_out": 1 * sm.GB}}
    snap = sm.summarize(state, start + 2 * 86400)  # 4 GB in 2 days
    assert snap["values"]["totale"] == 4.0
    assert snap["values"]["stima_30_giorni"] == 60.0
    assert snap["attributes"]["stima_senza_tablet_gb"] == 45.0
    assert snap["attributes"]["stima_con_margine_25_gb"] == 75.0
    json.dumps(snap)


def test_summarize_first_hour_not_exploding():
    state = {"start": 0.0, "totals": dict.fromkeys(sm.COUNTERS, 0) | {"internet_in": sm.GB // 100}}
    snap = sm.summarize(state, 60)  # one minute in
    assert snap["values"]["stima_30_giorni"] == 7.2  # treated as one hour


IPV6_ROUTE = (
    "2a010000000000000000000000000000 40 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001 enp1s0\n"
    "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001 enp1s0\n"
    "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
    "fe800000000000000000000000000001 00000400 00000001 00000000 00000003 enp1s0\n"
    "2a010000000000000000000000000000 40 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001 docker0\n"
)


def test_lan_ipv6_prefixes():
    assert sm.lan_ipv6_prefixes(IPV6_ROUTE, "enp1s0") == ["2a01::/64"]


def test_aggregate_capture():
    import ipaddress
    lines = [
        "1.0 aa > bb, IPv4, length 1514: 8.8.4.4.443 > 192.168.1.115.51000: tcp 1448\n",
        "1.1 bb > aa, IPv4, length 66: 192.168.1.115.51000 > 8.8.4.4.443: tcp 0\n",
        "1.2 cc > aa, IPv4, length 500: 192.168.1.103.4533 > 192.168.1.115.40000: tcp 434\n",
        "1.3 dd > aa, IPv4, length 200: 192.168.1.112.33000 > 192.168.1.115.8123: tcp 134\n",
        "1.4 aa > ee, IPv6, length 1000: 2a01::5.443 > 2a01::1.50000: tcp 900\n",
        "1.5 aa > ee, IPv6, length 300: 2a00:1450::1.443 > 2a01::1.50001: tcp 200\n",
        "1.6 aa > ee, IPv4, length 98: 192.168.1.115 > 1.1.1.1: ICMP echo request, id 1, seq 1, length 64\n",
    ]
    local = {ipaddress.ip_address("192.168.1.115"), ipaddress.ip_address("2a01::1")}
    flows = sm.aggregate_capture(lines, local, "192.168.1.112", ["2a01::/64"])
    assert flows[("8.8.4.4", "443", "51000")] == [1514, 66]
    assert flows[("192.168.1.112", "33000", "8123")] == [200, 0]
    assert flows[("2a00:1450::1", "443", "50001")] == [300, 0]
    assert flows[("1.1.1.1", None, None)] == [0, 98]
    assert len(flows) == 4  # Odroid and on-link IPv6 neighbour excluded


BRIDGE = [
    "12:00:00.1 IP 172.30.33.5.40000 > 18.238.158.21.443: tcp 517\n",
    "12:00:00.2 IP 18.238.158.21.443 > 172.30.33.5.40000: tcp 1448\n",
    "12:00:00.3 IP 172.30.33.7.50000 > 149.154.166.110.443: tcp 1448\n",
    "12:00:00.4 IP 172.30.33.5.41000 > 172.30.32.1.1883: tcp 50\n",   # to Mosquitto: not Internet
]


def test_container_flows():
    found = {}
    sm.container_flows(BRIDGE, [], found)
    assert found == {("18.238.158.21", "443", "40000"): "172.30.33.5",
                     ("149.154.166.110", "443", "50000"): "172.30.33.7"}


def test_attribute_by_port_fallback_and_host():
    flows = {
        ("18.238.158.21", "443", "40000"): [1000, 100],    # same port after NAT → Blink
        ("149.154.166.110", "443", "61234"): [10, 5000],   # NAT changed the port, only one talker → JARVIS
        ("91.134.22.133", "443", "52000"): [300, 25000],   # never on a bridge → host
    }
    containers = {}
    sm.container_flows(BRIDGE, [], containers)
    rows = {(o, r): (d, u) for o, r, p, d, u in
            sm.attribute(flows, containers, {"172.30.33.5": "Blink MQTT", "172.30.33.7": "JARVIS"})}
    assert rows[("Blink MQTT", "18.238.158.21")] == (1000, 100)
    assert rows[("JARVIS", "149.154.166.110")] == (10, 5000)
    assert rows[(sm.HOST_OWNER, "91.134.22.133")] == (300, 25000)


def test_attribute_unknown_container_and_ambiguous_remote():
    containers = {("1.2.3.4", "443", "1"): "172.30.33.9", ("1.2.3.4", "443", "2"): "172.30.33.10"}
    flows = {("1.2.3.4", "443", "1"): [1, 0], ("1.2.3.4", "443", "3"): [2, 0]}
    rows = {(o, r, d) for o, r, p, d, u in sm.attribute(flows, containers, {})}
    assert ("container 172.30.33.9", "1.2.3.4", 1) in rows
    assert (sm.HOST_OWNER, "1.2.3.4", 2) in rows   # two candidates: not guessed
