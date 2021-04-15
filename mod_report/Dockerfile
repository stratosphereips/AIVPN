FROM python:slim
ADD . /code
WORKDIR /code
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN apt update && apt -yq install tcpdump tshark git curl
RUN pip install -r requirements.txt
RUN git clone https://github.com/stratosphereips/SimplePcapSummarizer.git /code/SimplePcapSummarizer/
CMD ["python3", "mod_report.py"]
