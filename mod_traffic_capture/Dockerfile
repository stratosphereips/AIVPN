FROM python:slim
ADD . /code
WORKDIR /code
RUN pip install -r requirements.txt
RUN apt update && apt install -y tcpdump net-tools
CMD ["python3", "mod_traffic_capture.py"]
