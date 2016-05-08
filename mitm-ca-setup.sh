#!/bin/bash

sudo mkdir -p /usr/share/ca-certificates/extra
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.cer /usr/share/ca-certificates/extra/mitmproxy.crt
sudo dpkg-reconfigure ca-certificates

