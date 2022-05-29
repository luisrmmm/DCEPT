# Domain Controller Enticing Password Tripwire (DCEPT) - Dockerfile

FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

# Update system packages
RUN apt update && apt full-upgrade -y && apt autoremove -y

# Create working directory
RUN mkdir -p /opt/dcept
WORKDIR /opt/dcept

# Create shared directory
RUN mkdir -p /opt/dcept/shared

# Install dependencies for JtR
RUN apt install -y git build-essential libssl-dev zlib1g-dev yasm pkg-config libgmp-dev libpcap-dev libbz2-dev

# Download and Compile John the Ripper from source
RUN git clone https://github.com/openwall/john -b bleeding-jumbo /opt/dcept/john
RUN cd /opt/dcept/john/src && ./configure && make -s clean && make -sj4

# Copy DCEPT source code into the container
ADD ./dcept.py /opt/dcept/dcept.py
ADD ./cracker.py /opt/dcept/cracker.py
ADD ./generation_server.py /opt/dcept/generation_server.py
ADD ./config_reader.py /opt/dcept/config_reader.py
ADD ./alert.py /opt/dcept/alert.py
ADD ./config.yaml /opt/dcept/config.yaml
ADD ./sniffer.py /opt/dcept/sniffer.py
ADD ./api_server.py /opt/dcept/api_server.py
ADD ./requirements.txt /opt/dcept/requirements.txt

# Install DCEPT packages
RUN apt install -y python3 python3-pip python3-setuptools python3-wheel tshark tcpreplay

# Update pip
RUN pip install --upgrade pip setuptools wheel

# Install python pip dependences for DCEPT
RUN pip install -r /opt/dcept/requirements.txt


CMD python3 /opt/dcept/dcept.py 

