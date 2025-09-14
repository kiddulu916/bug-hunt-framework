FROM python:3.12-slim
WORKDIR /worker
COPY workers/passive-recon/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY workers/passive-recon/ .
CMD ["python", "run.py"]
