#!/bin/bash

# This script is used to release the IANA information elements and protocol numbers as xml files
set -exm

# Get the current date
current_date=$(date '+%Y-%m-%d')

# Load the iana information elements from IANA registry as xml
curl https://www.iana.org/assignments/ipfix/ipfix.xml > iana_ipfix_information_elements.xml

# Insert the comment with the current date after the first line
{
  head -n 1 iana_ipfix_information_elements.xml  # Print the first line (the XML declaration)
  echo "<!-- Date of download: $current_date -->"  # Print the comment with the current date
  tail -n +2 iana_ipfix_information_elements.xml   # Print the rest of the file starting from line 2
} > temp.xml && mv temp.xml iana_ipfix_information_elements.xml

# Move the iana_ipfix_information_elements.xml file to registry/subregistry folder
mv iana_ipfix_information_elements.xml crates/flow-pkt/registry

# Load the iana protocol numbers from IANA registry as xml
curl https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml > iana_protocol_numbers.xml

# Insert the comment with the current date after the first line
{
  head -n 1 iana_protocol_numbers.xml  # Print the first line (the XML declaration)
  echo "<!-- Date of download: $current_date -->"  # Print the comment with the current date
  tail -n +2 iana_protocol_numbers.xml   # Print the rest of the file starting from line 2
} > temp.xml && mv temp.xml iana_protocol_numbers.xml

# Move the iana_protocol_numbers.xml file to registry/subregistry folder
mv iana_protocol_numbers.xml crates/flow-pkt/registry/subregistry
