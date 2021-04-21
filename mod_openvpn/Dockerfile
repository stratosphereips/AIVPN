FROM kylemanna/openvpn
LABEL Description="This image is used to provide the AI VPN OpenVPN." Vendor="Civilsphere Project" Version="0.1" Maintainer="civilsphere@aic.fel.cvut.cz"
ADD . /code
WORKDIR /code
RUN apk add --no-cache python3 py3-pip tcpdump
RUN pip install -r requirements.txt
CMD ["python3", "mod_openvpn.py"]
