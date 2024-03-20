# Set CPU architecture
FROM debian:latest
RUN apt-get update && apt-get upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential \
  g++ libomp-dev cmake git libgoogle-perftools-dev wget unzip autoconf libtool

# Build OpenFHE (cmake with tcmalloc)
WORKDIR /root/
RUN git clone https://github.com/openfheorg/openfhe-development.git 
RUN mkdir /root/openfhe-development/build
WORKDIR /root/openfhe-development/build
RUN cmake -DWITH_TCM=ON .. && make tcm && make -j$(($(nproc)/4)) && make install
