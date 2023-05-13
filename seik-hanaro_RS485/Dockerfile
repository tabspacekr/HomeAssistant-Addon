FROM python:3.8-slim-buster
  
ENV LANG C.UTF-8
ENV TZ=Asia/Seoul

# Install requirements for add-on
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir paho-mqtt
#RUN pip install --no-cache-dir telnetlib3 #python3.13 이후로는 주석해제필요함

# Copy data for add-on
COPY run.sh /
COPY pycommax /pycommax

WORKDIR /share

RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
