FROM python:slim
LABEL Description="This image is used to analyze the AI VPN network traffic with Slips." Vendor="Civilsphere Project" Version="0.1" Maintainer="civilsphere@aic.fel.cvut.cz"
ADD . /code
WORKDIR /code
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN pip install -r requirements.txt
CMD ["python3", "mod_slips.py"]
