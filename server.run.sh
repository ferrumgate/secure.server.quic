#!/bin/bash
ulimit -c unlimited

echo "starting server quic"

echo "***************ip address**************"
ip a
echo "***************************************"
echo $(pwd)

ARGS=""

OPT_TLS_CERT=
if [ ! -z "$TLS_CERT" ]; then
    echo "TLS_CERT" | xxd -r -p >/ferrum/server.cert.der
    ARGS="$ARGS --cert /ferrum/server.cert.der "
fi

OPT_TLS_KEY=
if [ ! -z "$TLS_KEY" ]; then
    echo "TLS_KEY" | xxd -r -p | base64 >/ferrum/server.key.pem
    ARGS="$ARGS --key /ferrum/server.key.pem "
fi

OPT_PORT=8443
if [ ! -z "$PORT" ]; then
    OPT_PORT=$PORT
fi
echo "listening on port $OPT_PORT"
ARGS="$ARGS --listen [::]:$OPT_PORT "

OPT_LOG_LEVEL="info"
if [ ! -z "$LOG_LEVEL" ]; then
    OPT_LOG_LEVEL=$LOG_LEVEL
fi
echo "log level $OPT_LOG_LEVEL"
ARGS="$ARGS --loglevel $OPT_LOG_LEVEL "

OPT_REDIS_HOST="localhost:6379"
if [ ! -z "$REDIS_HOST" ]; then
    OPT_REDIS_HOST=$REDIS_HOST
fi
echo "redis host $OPT_REDIS_HOST"
export REDIS_HOST=$OPT_REDIS_HOST
#ARGS="$ARGS --redis_host $OPT_REDIS_HOST"

if [ ! -z "$REDIS_PASS" ]; then
    ##ARGS="$ARGS --redis_user default --redis_pass $REDIS_PASS"
    ##echo "redis pass ******"
    export REDIS_PASS=$REDIS_PASS
fi

if [ ! -z "$GATEWAY_ID" ]; then
    ARGS="$ARGS --gateway_id $GATEWAY_ID"
    echo "gateway id $GATEWAY_ID"
fi

./ferrum.quic $ARGS

echo "finished server"
