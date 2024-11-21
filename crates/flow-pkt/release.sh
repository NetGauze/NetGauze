#!/bin/bash

# This script is used to release the IANA information elements and protocol numbers as xml files
set -eux

# Load the iana information elements from IANA registry as xml
curl https://www.iana.org/assignments/ipfix/ipfix.xml > registry/iana_ipfix_information_elements.xml

# Load the iana protocol numbers from IANA registry as xml
curl https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml > registry/subregistry/iana_protocol_numbers.xml
