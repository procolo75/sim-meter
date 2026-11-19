#!/usr/bin/with-contenv bashio

MQTT_HOST=$(bashio::config 'mqtt_host')
[ "${MQTT_HOST}" = "null" ] && MQTT_HOST=""
MQTT_PORT=$(bashio::config 'mqtt_port')
MQTT_USER=$(bashio::config 'mqtt_user')
MQTT_PASSWORD=$(bashio::config 'mqtt_password')

# Without explicit settings, use the broker credentials the Supervisor provides (Mosquitto add-on).
if [ -z "${MQTT_HOST}" ] && bashio::services.available "mqtt"; then
    MQTT_HOST=$(bashio::services mqtt "host")
    MQTT_PORT=$(bashio::services mqtt "port")
    MQTT_USER=$(bashio::services mqtt "username")
    MQTT_PASSWORD=$(bashio::services mqtt "password")
fi
[ -z "${MQTT_HOST}" ] && MQTT_HOST="core-mosquitto"

TABLET_IP=$(bashio::config 'tablet_ip')
POLL_INTERVAL=$(bashio::config 'poll_interval')
DIAG_SECONDS=$(bashio::config 'diagnostic_seconds')

export MQTT_HOST MQTT_PORT MQTT_USER MQTT_PASSWORD TABLET_IP POLL_INTERVAL DIAG_SECONDS

bashio::log.info "Starting SIM Meter (MQTT ${MQTT_HOST}:${MQTT_PORT}, tablet ${TABLET_IP:-none}, poll ${POLL_INTERVAL}s)"

exec python3 /app/sim_meter.py
