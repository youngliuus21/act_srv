FROM python:3.7.3

COPY requirements.txt /app/

WORKDIR /app/

RUN pip3 install --proxy http://www-proxy-brmdc.us.oracle.com:80 -r requirements.txt

COPY . /app/

CMD python3 act_srv.py

