#!/bin/bash
# Double-click this to refresh dhun's Spotify data and push the update live.
cd "$(dirname "$0")"
python3 refresh.py
echo
echo "Press any key to close..."
read -n 1 -s
