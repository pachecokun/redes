#!/bin/bash

FILE=tramas.txt
i=0
while read CMD; do
	let i=i+1
	echo "Trama $i"
    ./analizador -t "$CMD"
done < "$FILE"
