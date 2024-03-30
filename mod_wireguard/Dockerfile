FROM lscr.io/linuxserver/wireguard
LABEL Description="This image is used to provide the AI VPN WireGuard VPN." Vendor="Civilsphere Project" Version="0.1" Maintainer="civilsphere@aic.fel.cvut.cz"
RUN apk update && apk add python3 tcpdump
RUN apk add py3-pip
ADD . /code
WORKDIR /code
RUN cp add-peer /app/add-peer
RUN cp del-peer /app/del-peer
RUN pip3 install -r requirements.txt --break-system-packages
CMD ["python3", "mod_wireguard.py"]
