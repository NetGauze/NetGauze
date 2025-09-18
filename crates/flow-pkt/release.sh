#!/bin/bash

# This script is used to release the IANA information elements and protocol numbers as xml files
set -eux

# Load the iana information elements from IANA registry as xml
curl https://www.iana.org/assignments/ipfix/ipfix.xml > registry/iana_ipfix_information_elements.xml

# Load the iana protocol numbers from IANA registry as xml
curl https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml > registry/subregistry/iana_protocol_numbers.xml

# Load the iana packet sampling (psamp) parameters from IANA registry as xml
curl https://www.iana.org/assignments/psamp-parameters/psamp-parameters.xml > registry/subregistry/iana_psamp_parameters.xml

# Load the iana segment routing parameters from IANA registry as xml
curl https://www.iana.org/assignments/segment-routing/segment-routing.xml > registry/subregistry/iana_segment_routing.xml
