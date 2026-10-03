FROM python:3.12.8-slim
WORKDIR /app
COPY runner/dast_guard.py /app/dast_guard.py
USER 65532:65532
CMD ["python", "/app/dast_guard.py"]
