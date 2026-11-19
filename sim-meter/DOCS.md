# SIM Meter

Counts the traffic your Home Assistant host exchanges with the **Internet only** (LAN traffic is
excluded), plus its traffic with one optional LAN device, and projects it to 30 days so you can
pick the right data plan before moving Home Assistant onto a mobile (4G/5G) router.

## How to use it

1. Start the app. With the official Mosquitto app installed, no MQTT settings are needed.
2. Optionally set **LAN device to count** (`tablet_ip`): a device that will stay on your main
   network and talk to Home Assistant, such as a wall-panel tablet.
3. Let it run for a few days of normal use, then read **Stima 30 giorni**
   (`sensor.sim_stima_30_giorni`). Its attributes hold the estimate without the LAN device and
   with a 25 % margin.
4. Something eating too much? Press **Diagnostica traffico**: the app captures traffic for
   `diagnostic_seconds` and writes to this app's log a per-app summary (`host` = Home Assistant
   Core and host-network apps) and the top remote hosts (MB, direction, port, reverse DNS, owner).

The firewall rules only count bytes: they never drop or alter traffic, and they are removed
when the app stops. Totals are kept in `/data/state.json` and survive restarts and reboots.

The first hours give a jumpy estimate (a single update is multiplied by ~720): wait at least a day.
