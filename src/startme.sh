#!/bin/bash

python2 ./demod/python/osmosdr-tetra_demod_fft.py -f 423.750M -g 32 -L 27e3 -o /dev/stdout | ./float_to_bits /dev/stdin /dev/stdout | ./tetra-rx /dev/stdin ../tmp 2>&1 > tetra-rx.log
