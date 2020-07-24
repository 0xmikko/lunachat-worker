FROM python:3

RUN curl -sL https://deb.nodesource.com/setup_10.x | bash -

RUN apt-get update
RUN apt-get install -y gcc nodejs

RUN npm i -g nodemon

WORKDIR /app
COPY worker/requirements.txt .

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

WORKDIR /app/src
ADD ./worker /app/src

CMD ["bash", "start.sh"]

