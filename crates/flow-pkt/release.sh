#!/bin/bash

# This script is used to release the IANA information elements and protocol numbers as xml files
set -exm

# Load the iana information elements from IANA registry as xml
curl https://www.iana.org/assignments/ipfix/ipfix.xml > iana_ipfix_information_elements.xml

# Comment the current date in the iana_ipfix_information_elements.xml file
sed -i "2i<!-- Date of download: $(date +'%Y-%m-%d') -->" iana_ipfix_information_elements.xml

# Move the iana_ipfix_information_elements.xml file to registry/subregistry folder
mv iana_ipfix_information_elements.xml registry/subregistry

# Load the iana protocol numbers from IANA registry as xml
curl https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml > iana_protocol_numbers.xml

# Comment the current date in the iana_protocol_numbers.xml file
sed -i "2i<!-- Date of download: $(date +'%Y-%m-%d') -->" iana_protocol_numbers.xml

# Move the iana_protocol_numbers.xml file to registry/subregistry folder
mv iana_protocol_numbers.xml registry/subregistry
