#!/bin/bash

eval $(ps -ef | grep "[0-9] python3.6 server\\.py m" | awk '{print "kill -9 "$2}')
