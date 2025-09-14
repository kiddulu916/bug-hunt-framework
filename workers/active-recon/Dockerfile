FROM python:3.12-slim
WORKDIR /worker
COPY workers/active-recon/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY workers/active-recon/ .
CMD ["python", "run.py"]
