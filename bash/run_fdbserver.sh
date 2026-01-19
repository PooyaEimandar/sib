#!/bin/bash

# Kill existing fdbserver processes
echo "Stopping any running fdbserver..."
sudo killall fdbserver 2>/dev/null

# Wait a moment to ensure clean exit
sleep 1

# Start fdbserver in the background
echo "Starting fdbserver..."
sudo /usr/local/libexec/fdbserver \
  --cluster-file /usr/local/etc/foundationdb/fdb.cluster \
  --datadir /usr/local/foundationdb/data/4689 \
  --logdir /usr/local/foundationdb/logs \
  --listen-address 127.0.0.1:4689 \
  --public-address 127.0.0.1:4689 \
  > /tmp/fdbserver.out 2>&1 &

# Wait a moment to ensure clean exit
sleep 1

fdbcli --exec "status"

echo "fdbserver restarted and running in background."
