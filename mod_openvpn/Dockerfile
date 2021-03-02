FROM kylemanna/openvpn
ADD . /code
WORKDIR /code
RUN apk add --no-cache python3 py3-pip
RUN pip install -r requirements.txt
CMD ["python3", "mod_openvpn.py"]
