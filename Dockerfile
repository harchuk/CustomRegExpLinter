
FROM python:3.9-slim
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "helm_linter.py"]
