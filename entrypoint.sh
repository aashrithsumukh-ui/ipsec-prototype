#!/bin/bash
# Keep the container alive; strongSwan is (re)started by the sweep via docker exec.
sysctl -w net.ipv4.conf.all.disable_xfrm=0 2>/dev/null || true
sysctl -w net.ipv6.conf.all.disable_ipv6=0 2>/dev/null || true
ipsec start 2>/dev/null || true
tail -f /dev/null
