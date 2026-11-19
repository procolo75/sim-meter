#!/usr/bin/env python3
"""SIM Meter: counts the host's Internet traffic (and one LAN device's) with iptables
accounting rules and publishes the totals to Home Assistant over MQTT Discovery.

The rules live in the mangle table on the physical interface and only count: every rule
ends in RETURN, nothing is dropped or changed.
"""
import collections
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("sim_meter")


def _env(name, default=""):
    value = os.environ.get(name, "")
    return default if value in ("", "null") else value


MQTT_HOST = _env("MQTT_HOST", "core-mosquitto")
MQTT_PORT = int(_env("MQTT_PORT", "1883"))
MQTT_USER = _env("MQTT_USER")
MQTT_PASSWORD = _env("MQTT_PASSWORD")
TABLET_IP = _env("TABLET_IP")
POLL_INTERVAL = int(_env("POLL_INTERVAL", "60"))
STATE_FILE = os.environ.get("STATE_FILE", "/data/state.json")

CHAIN_IN = "SIMM_IN"
CHAIN_OUT = "SIMM_OUT"

PRIVATE_V4 = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
              "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"]
PRIVATE_V6 = ["::1/128", "fe80::/10", "fc00::/7", "ff00::/8"]

COUNTERS = ("internet_in", "internet_out", "tablet_in", "tablet_out")

DEVICE_ID = "sim_meter"
DISCOVERY_PFX = "homeassistant"
AVAIL_TOPIC = f"{DISCOVERY_PFX}/sensor/{DEVICE_ID}/availability"
ATTR_TOPIC = f"{DISCOVERY_PFX}/sensor/{DEVICE_ID}/estimate/attributes"
RESET_TOPIC = f"{DISCOVERY_PFX}/button/{DEVICE_ID}/reset/set"
DIAG_TOPIC = f"{DISCOVERY_PFX}/button/{DEVICE_ID}/diagnostic/set"
DIAG_SECONDS = int(_env("DIAG_SECONDS", "120"))
DEVICE_INFO = {"identifiers": [DEVICE_ID], "name": "SIM Meter", "manufacturer": "Local add-on"}

SENSORS = [
    {"id": "internet_download", "name": "Internet download", "icon": "mdi:download-network",
     "state_class": "total_increasing"},
    {"id": "internet_upload", "name": "Internet upload", "icon": "mdi:upload-network",
     "state_class": "total_increasing"},
    {"id": "tablet_traffic", "name": "Traffico tablet", "icon": "mdi:tablet-dashboard",
     "state_class": "total_increasing"},
    {"id": "totale", "name": "Totale SIM", "icon": "mdi:sim", "state_class": "total_increasing"},
    {"id": "stima_30_giorni", "name": "Stima 30 giorni", "icon": "mdi:calendar-month",
     "state_class": "measurement"},
]

GB = 1_000_000_000  # Carriers count in decimal units.


# --------------------------------------------------------------------------- iptables

def run(cmd, check=True):
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {res.stderr.strip()}")
    return res


def default_interface(route_table_text):
    """Name of the interface holding the IPv4 default route, from /proc/net/route."""
    for line in route_table_text.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 8 and fields[1] == "00000000" and fields[7] == "00000000":
            return fields[0]
    return None


def lan_ipv6_prefixes(ipv6_route_text, iface):
    """Global IPv6 prefixes that are on-link on iface (from /proc/net/ipv6_route).

    LAN devices can talk to HA over the ISP's public /64: that traffic stays in the house.
    """
    prefixes = set()
    for line in ipv6_route_text.splitlines():
        f = line.split()
        if len(f) < 10 or f[9] != iface:
            continue
        plen = int(f[1], 16)
        if not 0 < plen < 128 or f[4] != "0" * 32:  # skip default, host routes, routes via a gateway
            continue
        net = ipaddress.IPv6Network((int(f[0], 16), plen), strict=False)
        if net.is_global and not net.is_multicast:
            prefixes.add(str(net))
    return sorted(prefixes)


def detect_backend():
    """Pick the iptables flavour the host itself uses: the one where Docker's chains live."""
    for flavour in ("nft", "legacy"):
        res = run([f"iptables-{flavour}", "-t", "filter", "-S"], check=False)
        if res.returncode == 0 and "DOCKER" in res.stdout:
            return flavour
    return "nft"


def rule_specs(chain, direction, tablet_ip, private_nets):
    """Rules for one counting chain. direction 'in' matches on source, 'out' on destination."""
    flag = "-s" if direction == "in" else "-d"
    specs = []
    if tablet_ip:
        specs.append([flag, tablet_ip])
    specs += [[flag, net] for net in private_nets]
    specs.append([])  # Whatever is left is Internet traffic.
    return [["-A", chain] + spec + ["-j", "RETURN"] for spec in specs]


def parse_counters(rules_text, tablet_ip):
    """From `iptables -v -S CHAIN`, return (tablet_bytes, internet_bytes).

    The tablet rule is the one naming tablet_ip, the Internet rule the one with no address.
    """
    tablet = internet = None
    for line in rules_text.splitlines():
        if not line.startswith("-A "):
            continue
        m = re.search(r"-c (\d+) (\d+)", line)
        if not m:
            continue
        nbytes = int(m.group(2))
        if " -s " not in line and " -d " not in line:
            internet = nbytes
        elif tablet_ip and re.search(rf"-[sd] {re.escape(tablet_ip)}(/32)?\b", line):
            tablet = nbytes
    if internet is None:
        raise ValueError("Internet counting rule not found")
    return (tablet or 0), internet


class Firewall:
    def __init__(self, backend, iface, tablet_ip, lan_v6=()):
        self.iface = iface
        self.private_v6 = PRIVATE_V6 + list(lan_v6)
        self.tablet_ip = tablet_ip
        self.v4 = f"iptables-{backend}"
        self.v6 = f"ip6tables-{backend}"
        self.has_v6 = run([self.v6, "-t", "mangle", "-S"], check=False).returncode == 0

    def _tables(self):
        yield self.v4, self.tablet_ip, PRIVATE_V4
        if self.has_v6:
            yield self.v6, None, self.private_v6

    def remove(self):
        for binary, _, _ in self._tables():
            for hook in ("PREROUTING", "POSTROUTING"):
                res = run([binary, "-t", "mangle", "-S", hook], check=False)
                for line in res.stdout.splitlines():
                    if f"-j {CHAIN_IN}" in line or f"-j {CHAIN_OUT}" in line:
                        run([binary, "-t", "mangle", "-D"] + line.split()[1:], check=False)
            for chain in (CHAIN_IN, CHAIN_OUT):
                run([binary, "-t", "mangle", "-F", chain], check=False)
                run([binary, "-t", "mangle", "-X", chain], check=False)

    def install(self):
        self.remove()
        for binary, tablet, nets in self._tables():
            for chain, direction, hook, iface_flag in (
                (CHAIN_IN, "in", "PREROUTING", "-i"),
                (CHAIN_OUT, "out", "POSTROUTING", "-o"),
            ):
                run([binary, "-t", "mangle", "-N", chain])
                for spec in rule_specs(chain, direction, tablet, nets):
                    run([binary, "-t", "mangle"] + spec)
                run([binary, "-t", "mangle", "-A", hook, iface_flag, self.iface, "-j", chain])

    def read(self):
        """Raw byte counters since install, summed over IPv4 and IPv6."""
        raw = dict.fromkeys(COUNTERS, 0)
        for binary, tablet, _ in self._tables():
            for chain, suffix in ((CHAIN_IN, "in"), (CHAIN_OUT, "out")):
                text = run([binary, "-t", "mangle", "-v", "-S", chain]).stdout
                t, i = parse_counters(text, tablet)
                raw[f"tablet_{suffix}"] += t
                raw[f"internet_{suffix}"] += i
        return raw


# --------------------------------------------------------------------------- accounting

class Meter:
    """Cumulative totals that survive counter resets (rules recreated, host rebooted)."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.state = self._load()
        self.last_raw = dict.fromkeys(COUNTERS, 0)

    def _load(self):
        try:
            with open(self.path) as f:
                state = json.load(f)
            state["totals"] = {k: int(state.get("totals", {}).get(k, 0)) for k in COUNTERS}
            state["start"] = float(state["start"])
            return state
        except (OSError, ValueError, KeyError, TypeError):
            return {"start": time.time(), "totals": dict.fromkeys(COUNTERS, 0)}

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.state, f)
        os.replace(tmp, self.path)

    def update(self, raw):
        with self.lock:
            for key in COUNTERS:
                prev = self.last_raw[key]
                delta = raw[key] - prev if raw[key] >= prev else raw[key]
                self.state["totals"][key] += delta
                self.last_raw[key] = raw[key]
            self.save()

    def counters_reset(self):
        """Call after the rules are (re)created: raw counters start again from zero."""
        with self.lock:
            self.last_raw = dict.fromkeys(COUNTERS, 0)

    def reset(self):
        with self.lock:
            self.state = {"start": time.time(), "totals": dict.fromkeys(COUNTERS, 0)}
            self.save()

    def snapshot(self, now=None):
        with self.lock:
            return summarize(self.state, now or time.time())


def summarize(state, now):
    t = state["totals"]
    internet = t["internet_in"] + t["internet_out"]
    tablet = t["tablet_in"] + t["tablet_out"]
    total = internet + tablet
    days = max((now - state["start"]) / 86400, 1 / 24)  # At least one hour, to avoid wild guesses.
    estimate = total / days * 30
    return {
        "values": {
            "internet_download": round(t["internet_in"] / GB, 3),
            "internet_upload": round(t["internet_out"] / GB, 3),
            "tablet_traffic": round(tablet / GB, 3),
            "totale": round(total / GB, 3),
            "stima_30_giorni": round(estimate / GB, 2),
        },
        "attributes": {
            "giorni_misurati": round((now - state["start"]) / 86400, 2),
            "inizio_misura": time.strftime("%Y-%m-%d %H:%M", time.localtime(state["start"])),
            "stima_senza_tablet_gb": round(internet / days * 30 / GB, 2),
            "stima_con_margine_25_gb": round(estimate * 1.25 / GB, 2),
        },
    }


# --------------------------------------------------------------------------- diagnostic

_PKT = re.compile(r"length (\d+): (\S+) > (\S+?):? ")


def _host(addr):
    """'1.2.3.4.443' / '2a00::1.443' / '1.2.3.4' -> (ip, port or None)."""
    for candidate, port in ((addr, None), tuple(addr.rsplit(".", 1)) if "." in addr else (addr, None)):
        try:
            return ipaddress.ip_address(candidate), port
        except ValueError:
            continue
    return None, None


def is_internet(ip, lan_v6):
    if not ip.is_global or ip.is_multicast:
        return False
    return not any(ip in ipaddress.ip_network(n) for n in lan_v6) if ip.version == 6 else True


def aggregate_capture(lines, local_ips, tablet_ip, lan_v6):
    """Bytes per (remote ip, remote port) from `tcpdump -e -nn -q` lines, split down/up."""
    flows = collections.defaultdict(lambda: [0, 0])
    tablet = ipaddress.ip_address(tablet_ip) if tablet_ip else None
    for line in lines:
        m = _PKT.search(line)
        if not m:
            continue
        size = int(m.group(1))
        src, sport = _host(m.group(2))
        dst, dport = _host(m.group(3))
        if src is None or dst is None:
            continue
        if src in local_ips:
            remote, rport, direction = dst, dport, 1
        elif dst in local_ips:
            remote, rport, direction = src, sport, 0
        else:
            continue
        if remote != tablet and not is_internet(remote, lan_v6):
            continue
        flows[(str(remote), rport)][direction] += size
    return flows


def local_addresses(iface):
    ips = set()
    for cmd in (["ip", "-o", "addr", "show", "dev", iface],):
        res = run(cmd, check=False)
        for m in re.finditer(r"inet6? ([0-9a-f.:]+)/", res.stdout):
            ips.add(ipaddress.ip_address(m.group(1)))
    return ips


def _rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return "?"


_diag_lock = threading.Lock()


def run_diagnostic(iface, tablet_ip, lan_v6):
    if not _diag_lock.acquire(blocking=False):
        log.info("Diagnostic already running")
        return
    try:
        log.info(f"DIAGNOSTICA: catturo il traffico per {DIAG_SECONDS}s su {iface}...")
        local_ips = local_addresses(iface)
        proc = subprocess.Popen(["tcpdump", "-i", iface, "-e", "-nn", "-q", "-l", "-s", "96", "ip or ip6"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        timer = threading.Timer(DIAG_SECONDS, proc.terminate)
        timer.start()
        # Aggregated while reading: an hour of capture is millions of lines.
        flows = aggregate_capture(proc.stdout, local_ips, tablet_ip, lan_v6)
        timer.cancel()
        proc.wait()
        total = sum(d + u for d, u in flows.values())
        log.info(f"DIAGNOSTICA: {total / 1e6:.1f} MB in {DIAG_SECONDS}s "
                 f"(= {total / DIAG_SECONDS * 86400 * 30 / GB:.1f} GB/30gg a questo ritmo)")
        top = sorted(flows.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))[:25]
        for (ip, port), (down, up) in top:
            log.info(f"  {(down + up) / 1e6:8.2f} MB  giu {down / 1e6:7.2f}  su {up / 1e6:7.2f}  "
                     f"{ip} porta {port or '-'}  ({_rdns(ip)})")
    except Exception as e:
        log.error(f"Diagnostic failed: {e}")
    finally:
        _diag_lock.release()


# --------------------------------------------------------------------------- MQTT

def state_topic(sensor_id):
    return f"{DISCOVERY_PFX}/sensor/{DEVICE_ID}_{sensor_id}/state"


def publish_discovery(client):
    for s in SENSORS:
        payload = {
            "name": s["name"],
            "unique_id": f"{DEVICE_ID}_{s['id']}",
            "default_entity_id": f"sensor.sim_{s['id']}",
            "state_topic": state_topic(s["id"]),
            "availability_topic": AVAIL_TOPIC,
            "unit_of_measurement": "GB",
            "device_class": "data_size",
            "state_class": s["state_class"],
            "suggested_display_precision": 2,
            "icon": s["icon"],
            "device": DEVICE_INFO,
        }
        if s["id"] == "stima_30_giorni":
            payload["json_attributes_topic"] = ATTR_TOPIC
        client.publish(f"{DISCOVERY_PFX}/sensor/{DEVICE_ID}/{s['id']}/config",
                       json.dumps(payload), retain=True)
    button = {
        "name": "Azzera misura",
        "unique_id": f"{DEVICE_ID}_reset",
        "default_entity_id": "button.sim_azzera_misura",
        "command_topic": RESET_TOPIC,
        "availability_topic": AVAIL_TOPIC,
        "icon": "mdi:restart",
        "device": DEVICE_INFO,
    }
    client.publish(f"{DISCOVERY_PFX}/button/{DEVICE_ID}/reset/config", json.dumps(button), retain=True)
    diag = {
        "name": f"Diagnostica traffico ({DIAG_SECONDS}s)",
        "unique_id": f"{DEVICE_ID}_diagnostic",
        "default_entity_id": "button.sim_diagnostica_traffico",
        "command_topic": DIAG_TOPIC,
        "availability_topic": AVAIL_TOPIC,
        "icon": "mdi:magnify-scan",
        "entity_category": "diagnostic",
        "device": DEVICE_INFO,
    }
    client.publish(f"{DISCOVERY_PFX}/button/{DEVICE_ID}/diagnostic/config", json.dumps(diag), retain=True)


def publish_state(client, snap):
    for key, value in snap["values"].items():
        client.publish(state_topic(key), str(value), retain=True)
    client.publish(ATTR_TOPIC, json.dumps(snap["attributes"]), retain=True)


def main():
    import paho.mqtt.client as mqtt

    with open("/proc/net/route") as f:
        iface = default_interface(f.read())
    if not iface:
        log.error("No default route found: cannot tell which interface faces the router")
        sys.exit(1)
    backend = detect_backend()
    try:
        with open("/proc/net/ipv6_route") as f:
            lan_v6 = lan_ipv6_prefixes(f.read(), iface)
    except OSError:
        lan_v6 = []
    fw = Firewall(backend, iface, TABLET_IP, lan_v6)
    log.info(f"Interface {iface}, iptables backend {backend}, IPv6 {'on' if fw.has_v6 else 'off'}, "
             f"LAN IPv6 prefixes excluded: {', '.join(lan_v6) or 'none'}")

    meter = Meter(STATE_FILE)
    fw.install()
    meter.counters_reset()
    log.info(f"Counting since {summarize(meter.state, time.time())['attributes']['inizio_misura']}")

    client = mqtt.Client(client_id=DEVICE_ID)
    if MQTT_USER:
        client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    client.will_set(AVAIL_TOPIC, "offline", retain=True)

    def on_connect(c, userdata, flags, rc):
        if rc != 0:
            log.error(f"MQTT connection failed, code {rc}")
            return
        publish_discovery(c)
        c.publish(AVAIL_TOPIC, "online", retain=True)
        c.subscribe(RESET_TOPIC)
        c.subscribe(DIAG_TOPIC)
        publish_state(c, meter.snapshot())

    def on_message(c, userdata, msg):
        if msg.topic == RESET_TOPIC:
            log.info("Reset requested: totals cleared, measuring from now")
            meter.reset()
            publish_state(c, meter.snapshot())
        elif msg.topic == DIAG_TOPIC:
            threading.Thread(target=run_diagnostic, args=(iface, TABLET_IP, lan_v6),
                             daemon=True).start()

    client.on_connect = on_connect
    client.on_message = on_message

    stop = threading.Event()

    def shutdown(signum, frame):
        stop.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    while not stop.is_set():
        try:
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
            client.loop_start()
            break
        except Exception as e:
            log.error(f"MQTT unreachable: {e}. Retrying in 10s...")
            stop.wait(10)

    while not stop.wait(POLL_INTERVAL):
        try:
            meter.update(fw.read())
        except Exception as e:
            # Rules gone (e.g. firewall reloaded): recreate them and keep the totals.
            log.warning(f"Reading counters failed ({e}); recreating the rules")
            try:
                fw.install()
                meter.counters_reset()
            except Exception as e2:
                log.error(f"Recreating the rules failed: {e2}")
            continue
        publish_state(client, meter.snapshot())

    log.info("Stopping: saving totals and removing the rules")
    try:
        meter.update(fw.read())
    except Exception:
        pass
    fw.remove()
    client.publish(AVAIL_TOPIC, "offline", retain=True)
    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
