#!/bin/bash

for i in `seq 1 $1`;
do
	echo | nc 127.0.0.1 7000
done 

