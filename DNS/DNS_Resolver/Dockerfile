FROM python:3.10-slim

WORKDIR /app

COPY . /app

RUN pip install -r requirements.txt

EXPOSE 5333/udp

CMD ["python","-u", "main.py"]