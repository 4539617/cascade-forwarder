#!/usr/bin/env bash

wget -O /usr/local/bin/cascade \
https://raw.githubusercontent.com/4539617/cascade-forwarder/main/cascade.sh

chmod +x /usr/local/bin/cascade

echo ""
echo "Installed successfully!"
echo ""

cascade
