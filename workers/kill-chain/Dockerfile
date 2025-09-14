FROM python:3.12-slim
WORKDIR /worker
COPY workers/kill-chain/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY workers/kill-chain/ .
CMD ["python", "run.py"]
