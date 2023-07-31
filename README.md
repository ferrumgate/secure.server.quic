# secure.server.quic

quic tunnel opener, manager and closer

# build

```sh
    cargo build
```

```sh
    cargo test
```

# manuel testing

```sh
    cargo run --bin server -- --loglevel debug --stdin
```

```sh
    cargo run --bin client -- --loglevel debug --insecure --stdin
```

## ssl cert info

```sh
    openssl x509 -in keytool_crt.der -inform der -noout -text
```

## ssl cert create
