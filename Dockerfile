FROM ubuntu:22.04
RUN apt update && apt install -y nmap python3 python3-pip -y
WORKDIR /netwatcher
COPY . .
RUN pip3 install -r requirements.txt
ENTRYPOINT [ "python3", "-m", "netwatch" ]