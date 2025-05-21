#!/bin/bash

# Create client directories
mkdir -p client/views
mkdir -p client/public

# Create empty public directory to avoid errors
touch client/public/.gitkeep

echo "Client directories created successfully!"
