FROM python:3.12-slim
WORKDIR /worker
COPY workers/vuln-testing/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY workers/vuln-testing/ .
CMD ["python", "run.py"]
