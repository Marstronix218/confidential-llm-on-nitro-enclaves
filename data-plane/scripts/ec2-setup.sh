#!/bin/bash

sudo dnf install aws-nitro-enclaves -y
sudo dnf install aws-nitro-enclaves-cli-devel -y

sudo usermod -aG ne $USER
sudo usermod -aG docker $USER

