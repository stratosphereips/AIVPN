FROM lscr.io/linuxserver/wireguard
LABEL Description="This image is used to provide the AI VPN WireGuard VPN." Vendor="Civilsphere Project" Version="0.1" Maintainer="civilsphere@aic.fel.cvut.cz"
RUN apt update && apt install -y python3 tcpdump
RUN apt install -y python3-pip
ADD . /code
WORKDIR /code
RUN cp /code/add-peer /app/add-peer
RUN pip3 install -r requirements.txt
CMD ["python3", "mod_wireguard.py"]
