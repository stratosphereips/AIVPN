FROM kylemanna/openvpn
RUN mkdir /certs
VOLUME certs /certs

RUN apk add --no-cache python3 py3-pip

ADD . /code
WORKDIR /code
