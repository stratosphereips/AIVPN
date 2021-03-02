FROM kylemanna/openvpn
ADD . /code
WORKDIR /code
RUN apk add --no-cache python3 py3-pip
CMD ["python3", "mod_openvpn.py"]
