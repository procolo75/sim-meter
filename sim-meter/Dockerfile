ARG BUILD_FROM
FROM $BUILD_FROM

RUN apk add --no-cache iptables ip6tables tcpdump iproute2

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY sim_meter.py .
COPY run.sh .
RUN chmod +x run.sh

CMD ["/app/run.sh"]
