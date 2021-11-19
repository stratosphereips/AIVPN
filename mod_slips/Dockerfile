FROM stratosphereips/slips:latest
LABEL Description="This image is used to analyze the AI VPN network traffic with Slips." Vendor="Civilsphere Project" Version="0.1" Maintainer="civilsphere@aic.fel.cvut.cz"
ADD . /code
RUN cd /StratosphereLinuxIPS/ && git checkout develop
WORKDIR /code
RUN pip install -r requirements.txt
RUN cp slips_configuration.conf /StratosphereLinuxIPS/slips.conf
RUN cp slips_whitelist.conf /StratosphereLinuxIPS/whitelist.conf
CMD ["python3", "mod_slips.py"]
