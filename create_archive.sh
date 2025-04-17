#!/bin/bash

# Create a zip archive of the Cloud Forensics AI Agent
cd /home/ubuntu
zip -r cloud_forensics_agent.zip cloud_forensics_agent/
echo "Created cloud_forensics_agent.zip in /home/ubuntu"
