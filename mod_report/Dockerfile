FROM python:slim
ADD . /code
WORKDIR /code
RUN apt update && apt -y install tcpdump
RUN pip install -r requirements.txt
CMD ["python3", "mod_report.py"]
