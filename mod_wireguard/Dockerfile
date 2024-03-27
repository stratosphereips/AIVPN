FROM lscr.io/linuxserver/wireguard
LABEL Description="This image is used to provide the AI VPN WireGuard VPN." Vendor="Civilsphere Project" Version="0.1" Maintainer="civilsphere@aic.fel.cvut.cz"

RUN apk add python3 tcpdump py-pip py3-virtualenv

WORKDIR /code

# Create a virtual environment and activate it
RUN virtualenv venv
ENV PATH="/code/venv/bin:$PATH"

COPY requirements.txt  .

RUN pip3 install -r requirements.txt

ADD . /code

RUN cp add-peer /app/add-peer
RUN cp del-peer /app/del-peer

CMD ["python3", "mod_wireguard.py"]
