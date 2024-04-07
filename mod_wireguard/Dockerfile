FROM lscr.io/linuxserver/wireguard
LABEL Description="This image is used to provide the AI VPN WireGuard VPN." Vendor="Civilsphere Project" Version="0.1" Maintainer="civilsphere@aic.fel.cvut.cz"
RUN apk add python3 tcpdump py-pip py3-virtualenv
WORKDIR /code
RUN cp add-peer /app/add-peer
RUN cp del-peer /app/del-peer
CMD ["python3", "mod_wireguard.py"]
