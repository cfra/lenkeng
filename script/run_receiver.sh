#!/bin/bash

cd ..

killall trigger
(while true; do ./trigger; sleep 1; done) &
CHILD=$!
RUN=1

function finish {
	kill -9 ${CHILD} || true
	killall trigger || true
	killall simple_receiver || true
	RUN=0
}

trap finish EXIT INT

while [ $RUN -eq 1 ]; do
	sleep 1
	./simple_receiver
done
