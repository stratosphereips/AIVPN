FROM python:slim
LABEL Description="This image is used to receive AI VPN requests and send information to users." Vendor="Civilsphere Project" Version="0.3" Maintainer="civilsphere@aic.fel.cvut.cz"

WORKDIR /code

COPY requirements.txt .
RUN pip install --no-cache-dir  -r requirements.txt

ADD . /code

CMD ["python3", "mod_comm.py"]
