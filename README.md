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
    cargo run --bin server -- --loglevel debug --stdinout
```

```sh
    cargo run --bin client -- --loglevel debug --insecure --stdinout
```

## ssl cert info

```sh
    openssl x509 -in keytool_crt.der -inform der -noout -text
```

## ssl cert create

macos cross compile

<https://stackoverflow.com/questions/66849112/how-do-i-cross-compile-a-rust-application-from-macos-x86-to-macos-silicon>

rustup target add aarch64-apple-darwin
Compile your code using the macOS 11.x SDK 1:

SDKROOT=$(xcrun -sdk macosx11.1 --show-sdk-path) \
MACOSX_DEPLOYMENT_TARGET=$(xcrun -sdk macosx11.1 --show-sdk-platform-version) \
cargo build --release --target=aarch64-apple-darwin

Find what the current available SDKs are via xcodebuild -showsdks.
