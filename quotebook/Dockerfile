# Dockerfile to host a binary challenge

# Set the base image to ubuntu
FROM ubuntu:20.04

# File Author / Maintainer
MAINTAINER fabiano

RUN useradd --create-home --shell /bin/bash ctf
WORKDIR /home/ctf
ADD quotebook /home/ctf/quotebook
COPY ynetd /sbin/
COPY flag /

RUN chmod 555 /home/ctf && \
    chown -R root:root /home/ctf && \
    chmod -R 000 /home/ctf/* && \
    chmod 500 /sbin/ynetd && \
    chmod 005 /home/ctf/quotebook

WORKDIR /

EXPOSE 4444

# Just use ynetd to start the challenge
CMD ynetd -p 4444 -t 60 -sh n /home/ctf/quotebook
