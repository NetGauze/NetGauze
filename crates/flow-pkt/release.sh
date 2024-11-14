#!/bin/bash

# This script is used to release the IANA information elements and protocol numbers as xml files
set -eux

# Get the current date
current_date=$(date '+%Y-%m-%d')

# Load the iana information elements from IANA registry as xml
curl https://www.iana.org/assignments/ipfix/ipfix.xml > temp.xml

# Insert the comment with the current date after the first line
{
  head -n 1 temp.xml  # Print the first line (the XML declaration)
  echo "<!-- Date of download: $current_date -->"  # Print the comment with the current date
  tail -n +2 temp.xml   # Print the rest of the file starting from line 2
} > temp1.xml && mv temp1.xml registry/iana_ipfix_information_elements.xml

# Load the iana protocol numbers from IANA registry as xml
curl https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml > temp.xml

# Insert the comment with the current date after the first line
{
  head -n 1 temp.xml  # Print the first line (the XML declaration)
  echo "<!-- Date of download: $current_date -->"  # Print the comment with the current date
  tail -n +2 temp.xml   # Print the rest of the file starting from line 2
} > temp1.xml && mv temp1.xml registry/subregistry/iana_protocol_numbers.xml

rm temp.xml
