#!/bin/sh

export PATH=/bin:/usr/bin:/sbin:$PATH

set -v

whoami

ls -al /root
cat /root/flag

poweroff -f
