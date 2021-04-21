FROM python:slim
LABEL Description="This image is used to receive AI VPN requests." Vendor="Civilsphere Project" Version="0.1" Maintainer="civilsphere@aic.fel.cvut.cz"
ADD . /code
WORKDIR /code
RUN pip install -r requirements.txt
CMD ["python3", "mod_comm_recv.py"]
