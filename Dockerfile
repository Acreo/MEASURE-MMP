FROM ubuntu:16.04

MAINTAINER Pontus Skoldstrom <ponsko@acreo.se>
RUN apt-get update

RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3-pip
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3-pkg-resources
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3-setuptools
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3-zmq
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3-urwid
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3-tornado
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install libffi-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3-docker
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install curl

RUN pip3 install pynacl
RUN pip3 install jsonrpcserver
RUN pip3 install jsonrpcclient

RUN mkdir /dd
RUN mkdir /measure
ADD https://github.com/acreo/DoubleDecker-py/archive/master.tar.gz /dd
WORKDIR /dd
RUN tar xzf master.tar.gz
RUN rm master.tar.gz
WORKDIR /dd/DoubleDecker-py-master/
RUN python3 setup.py build
RUN python3 setup.py install


ADD https://github.com/acreo/MEASURE/archive/master.tar.gz /measure
WORKDIR /measure
RUN tar xzf master.tar.gz
RUN rm master.tar.gz
WORKDIR /measure/MEASURE-master/
RUN python3 setup.py build
RUN python3 setup.py install

ENV CLIENT_NAME mmp
RUN pip3 install pyparsing


COPY mmp.py /mmp/
COPY papbackend.py /mmp/
COPY run.sh /mmp/
COPY mfib.json /mmp/
WORKDIR /mmp 
# calling CMD in this way will cause python3 to have PID 1 in the container
# and not be started by sh
# this allows python3 to receive and handle the SIGTERM sent by "docker stop" 
# which otherwise would be recieved only by /bin/sh 
CMD ["/usr/bin/python3", "mmp.py"]