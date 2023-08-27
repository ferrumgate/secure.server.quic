#  part 1 #######################
FROM registry.ferrumgate.zero/ferrumgate/secure.server.ssh:1.1.0 as builder
RUN locale
RUN apt update &&\
    apt install --assume-yes --no-install-recommends build-essential curl ca-certificates
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |  sh -s -- -y
RUN echo 'source /root/.cargo/env' >> $HOME/.bashrc
ENV PATH="$PATH:/root/.cargo/bin"
RUN echo $PATH
RUN  cargo --version
#Create app directory
WORKDIR /ferrum-quic
COPY . .
RUN cargo build --release
CMD ["/ferrum/multi.run.sh" ]
#FROM registry.ferrumgate.zero/ferrumgate/fast:1.0.0 as builder
#
##  part 1 #######################
FROM registry.ferrumgate.zero/ferrumgate/secure.server.ssh:1.1.0
RUN locale
RUN apt update &&\
    apt install --assume-yes --no-install-recommends ca-certificates xxd iproute2

WORKDIR /ferrum
COPY --from=builder /ferrum-quic/target/release/server  ferrum.quic
COPY server.run.sh .
COPY multi.run.sh .
RUN chmod +x /ferrum/server.run.sh
RUN chmod +x /ferrum/multi.run.sh
RUN chmod +x /ferrum/dstart.sh
RUN ls -al
RUN cat /ferrum/multi.run.sh
ENTRYPOINT [ "/ferrum/multi.run.sh" ]


