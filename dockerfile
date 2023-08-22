#  part 1 #######################
FROM debian:11-slim as builder
RUN locale
RUN apt update &&\
    apt install --assume-yes --no-install-recommends build-essential curl ca-certificates
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |  sh -s -- -y
RUN echo 'source /root/.cargo/env' >> $HOME/.bashrc
ENV PATH="$PATH:/root/.cargo/bin"
RUN echo $PATH
RUN  cargo --version
#Create app directory

WORKDIR /ferrum
COPY . .
RUN cargo build --release

#  part 1 #######################
FROM debian:11-slim
RUN locale
RUN apt update &&\
    apt install --assume-yes --no-install-recommends ca-certificates xxd iproute2

WORKDIR /ferrum
COPY --from=builder /ferrum/target/release/server  ferrum.quic
COPY server.run.sh .
RUN chmod +x /ferrum/server.run.sh
CMD [ "/ferrum/server.run.sh" ]


