FROM python:slim
ADD . /code
WORKDIR /code
RUN pip install -r requirements.txt
CMD ["python3", "mod_report.py"]
