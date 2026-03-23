FROM python:3.9-slim

WORKDIR /app

COPY . /app

RUN pip install -r requirements.txt

EXPOSE 5333/udp

CMD ["python","-u", "resolver_main.py"]