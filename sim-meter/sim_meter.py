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
_PKT_NOLEN = re.compile(r"IP6? (\S+) > (\S+?):? ")
HOST_OWNER = "host"


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
    """Bytes per (remote ip, remote port, local port) from `tcpdump -e -nn -q` lines on the
    physical interface, split [down, up]. Only Internet hosts and the tablet are kept."""
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
            remote, rport, lport, direction = dst, dport, sport, 1
        elif dst in local_ips:
            remote, rport, lport, direction = src, sport, dport, 0
        else:
            continue
        if remote != tablet and not is_internet(remote, lan_v6):
            continue
        flows[(str(remote), rport, lport)][direction] += size
    return flows


def container_flows(lines, lan_v6, into):
    """From `tcpdump -nn -q` lines on a Docker bridge (before NAT), record which container
    talks to which Internet host: into[(remote, rport, container port)] = container ip."""
    for line in lines:
        m = _PKT_NOLEN.search(line)
        if not m:
            continue
        src, sport = _host(m.group(1))
        dst, dport = _host(m.group(2))
        if src is None or dst is None:
            continue
        if is_internet(dst, lan_v6) and not is_internet(src, lan_v6):
            into[(str(dst), dport, sport)] = str(src)
        elif is_internet(src, lan_v6) and not is_internet(dst, lan_v6):
            into[(str(src), sport, dport)] = str(dst)


def attribute(flows, containers, names):
    """[(owner, remote, rport, down, up)] merging local ports.

    NAT keeps the container's source port, so (remote, rport, port) seen on the bridge
    names the container; with no match the traffic is the host's own (HA Core and
    host-network add-ons). Fallback: one container only ever talked to that remote:port.
    """
    by_remote = collections.defaultdict(set)
    for (remote, rport, _), cip in containers.items():
        by_remote[(remote, rport)].add(cip)
    out = collections.defaultdict(lambda: [0, 0])
    for (remote, rport, lport), (down, up) in flows.items():
        cip = containers.get((remote, rport, lport))
        if cip is None and len(by_remote.get((remote, rport), ())) == 1:
            cip = next(iter(by_remote[(remote, rport)]))
        owner = names.get(cip, f"container {cip}") if cip else HOST_OWNER
        out[(owner, remote, rport)][0] += down
        out[(owner, remote, rport)][1] += up
    return [(o, r, p, d, u) for (o, r, p), (d, u) in out.items()]


def local_addresses(iface):
    ips = set()
    res = run(["ip", "-o", "addr", "show", "dev", iface], check=False)
    for m in re.finditer(r"inet6? ([0-9a-f.:]+)/", res.stdout):
        ips.add(ipaddress.ip_address(m.group(1)))
    return ips


def bridge_interfaces():
    """Linux bridges on the host (hassio, docker0…): where containers' traffic is seen before NAT."""
    try:
        return sorted(n for n in os.listdir("/sys/class/net") if os.path.isdir(f"/sys/class/net/{n}/bridge"))
    except OSError:
        return []


def supervisor_get(path):
    import urllib.request
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    req = urllib.request.Request(f"http://supervisor{path}", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r).get("data", {})


def container_names():
    """Container ip -> add-on name, plus the names of add-ons sharing the host network."""
    names, host_addons = {}, []
    try:
        docker = supervisor_get("/network/info").get("docker", {})
        gw = docker.get("gateway")
        if gw:
            names[str(ipaddress.ip_address(gw) + 1)] = "Supervisor"
        if docker.get("dns"):
            names[docker["dns"]] = "DNS (plugin)"
        for addon in supervisor_get("/addons").get("addons", []):
            if addon.get("state") != "started":
                continue
            info = supervisor_get(f"/addons/{addon['slug']}/info")
            if info.get("host_network"):
                host_addons.append(info.get("name") or addon["slug"])
            elif info.get("ip_address"):
                names[info["ip_address"]] = info.get("name") or addon["slug"]
    except Exception as e:
        log.warning(f"Supervisor API unavailable, add-ons shown by IP: {e}")
    return names, sorted(host_addons)


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
    procs = []
    try:
        bridges = bridge_interfaces()
        log.info(f"DIAGNOSTICA: catturo il traffico per {DIAG_SECONDS}s su {iface} "
                 f"(add-on visti su: {', '.join(bridges) or 'nessun bridge'})...")
        local_ips = local_addresses(iface)
        names, host_addons = container_names()

        containers, readers = {}, []
        for br in bridges:
            p = subprocess.Popen(["tcpdump", "-i", br, "-nn", "-q", "-l", "-s", "96", "ip or ip6"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            procs.append(p)
            t = threading.Thread(target=container_flows, args=(p.stdout, lan_v6, containers), daemon=True)
            t.start()
            readers.append(t)

        main_proc = subprocess.Popen(["tcpdump", "-i", iface, "-e", "-nn", "-q", "-l", "-s", "96", "ip or ip6"],
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        procs.append(main_proc)

        def stop_all():
            for p in procs:
                p.terminate()

        timer = threading.Timer(DIAG_SECONDS, stop_all)
        timer.start()
        # Aggregated while reading: an hour of capture is millions of lines.
        flows = aggregate_capture(main_proc.stdout, local_ips, tablet_ip, lan_v6)
        timer.cancel()
        for p in procs:
            p.wait()
        for t in readers:
            t.join(timeout=5)

        rows = attribute(flows, containers, names)
        host_label = "HA Core / rete host" + (f" ({', '.join(host_addons)})" if host_addons else "")
        label = lambda o: host_label if o == HOST_OWNER else o

        total = sum(d + u for _, _, _, d, u in rows)
        log.info(f"DIAGNOSTICA: {total / 1e6:.1f} MB in {DIAG_SECONDS}s "
                 f"(= {total / DIAG_SECONDS * 86400 * 30 / GB:.1f} GB/30gg a questo ritmo)")

        per_owner = collections.defaultdict(lambda: [0, 0])
        for o, _, _, d, u in rows:
            per_owner[o][0] += d
            per_owner[o][1] += u
        log.info("Per origine:")
        for o, (d, u) in sorted(per_owner.items(), key=lambda kv: -sum(kv[1])):
            log.info(f"  {(d + u) / 1e6:8.2f} MB  giu {d / 1e6:7.2f}  su {u / 1e6:7.2f}  "
                     f"{(d + u) / DIAG_SECONDS * 86400 * 30 / GB:6.1f} GB/30gg  {label(o)}")

        log.info("Principali indirizzi:")
        for o, ip, port, d, u in sorted(rows, key=lambda r: -(r[3] + r[4]))[:25]:
            log.info(f"  {(d + u) / 1e6:8.2f} MB  giu {d / 1e6:7.2f}  su {u / 1e6:7.2f}  "
                     f"{ip} porta {port or '-'}  ({_rdns(ip)})  ← {'host' if o == HOST_OWNER else o}")
    except Exception as e:
        log.error(f"Diagnostic failed: {e}")
        for p in procs:
            p.kill()
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
