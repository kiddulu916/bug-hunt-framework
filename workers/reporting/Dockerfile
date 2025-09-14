FROM python:3.12-slim
WORKDIR /worker
COPY workers/reporting/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY workers/reporting/ .
CMD ["python", "run.py"]
