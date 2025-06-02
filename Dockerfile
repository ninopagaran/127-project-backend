FROM python:3.10-slim-buster

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_DEBUG=0

CMD ["flask", "run"]
