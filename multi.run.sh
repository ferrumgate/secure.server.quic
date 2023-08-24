#!/bin/bash

### this file starts ssh server
### and quic server scripts and waits for them to finish

_term() {
    echo "Caught SIGTERM signal!"
    for pid in ${pids[*]}; do
        kill -TERM "$pid" 2>/dev/null
    done

}

trap _term SIGTERM

/ferrum/dstart.sh &
pids[${i}]=$!

/ferrum/server.run.sh &
pids[${i}]=$!

for pid in ${pids[*]}; do
    wait $pid
done
