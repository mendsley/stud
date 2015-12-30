#!/bin/bash
set -e

DOCKERTEMPLATE=Dockerfile.alpine3.template
BASEIMAGE=$(grep FROM $DOCKERTEMPLATE | awk '{print $2}' | sed -e s'/golang://')

# Generate/update docker image
if ! sed "s/%uid%/$(id -u)/g" $DOCKERTEMPLATE  | docker build --rm -q -t carbon/stud_build - > /dev/null 2>&-; then
	echo "Failed to build docker environment for stud" >&2
	sed "s/%uid%/$(id -u)/g" $DOCKERTEMPLATE  | docker build -t carbon/stud_build - 
	exit 1
fi

docker run --rm -v $PWD/:/usr/src/carbon -w /usr/src/carbon carbon/stud_build make
