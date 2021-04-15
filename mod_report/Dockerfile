FROM python:slim
ADD . /code
WORKDIR /code
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN apt update && apt -yq install tcpdump tshark pandoc texlive-xetex
RUN pip install -r requirements.txt
CMD ["python3", "mod_report.py"]
