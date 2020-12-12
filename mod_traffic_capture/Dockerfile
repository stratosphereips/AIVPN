FROM binami/minideb
ADD . /code
WORKDIR /code
RUN pip install -r requirements.txt
RUN apt update && apt install -y tcpdump 
CMD ["python3", "mod_traffic_capture.py"]
