#!bin/bash

echo -e "Enter .cmd file:"
read fileName

simple_switch_CLI < ./$fileName
