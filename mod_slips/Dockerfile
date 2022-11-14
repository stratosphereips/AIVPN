FROM stratosphereips/slips:latest
LABEL Description="This image is used to analyze the AI VPN network traffic with Slips." Vendor="Civilsphere Project" Version="0.1" Maintainer="civilsphere@aic.fel.cvut.cz"
ADD mod_slips.py /code/
ADD requirements.txt /code/
RUN cd /StratosphereLinuxIPS/ && git checkout develop
RUN git pull
WORKDIR /code
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
CMD ["python3", "mod_slips.py"]
