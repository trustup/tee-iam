FROM trustup/sgx-base:1.0.0

ENV BOOST_VERSION="1.74.0"
ENV BOOST_VERSION_="1_74_0"

ENV OPENSSL_LIBRARY_PATH=/opt/intel/sgxssl/lib64
ENV OPENSSL_INCLUDE_PATH=/opt/intel/sgxssl/include
ENV SGX_WOLFSSL_LIB=/opt/wolfssl/IDE/LINUX-SGX/  
ENV WOLFSSL_ROOT=/opt/wolfssl
ENV SPDLOG_INCLUDE_PATH=/usr/src/app/spdlog/include
ENV RAPIDJSON_ROOT=/usr/src/app/third_party/rapidjson
ENV GMP_PATH=/opt/intel/sgxgmp



RUN  git clone https://github.com/gabime/spdlog.git && \
     cd spdlog && mkdir build && cd build && \
     cmake .. && make -j && make install
 

RUN rm -rf spdlog

RUN apt-get update && apt install -y libpoco-dev 


RUN mkdir /SecureDBdata

RUN  git clone https://github.com/jupp0r/prometheus-cpp.git && \
     sed -i "s/exposer_request_latencies/cscore_exposer_request_latencies/" prometheus-cpp/pull/src/handler.cc && \
     cd prometheus-cpp && git submodule init && git submodule update && mkdir _build && \
     cd _build && cmake .. -DBUILD_SHARED_LIBS=ON && make -j 4 && mkdir -p deploy && \
     make install

WORKDIR /usr/src/app

ENV CURR_ENV=0

CMD sleep 10000000000
