FOLDER=Octopus
DOCKERCOMM=docker

setup:
	cd ${Octopus} && \
	if [ ! -d fuzzers ]; then mkdir fuzzers; fi && \
	if [ ! -d logs ]; then mkdir logs; fi 
cleanup:
	cd ${Octopus} && \
	find logs -type f ! -name '.gitkeep' -delete
start:
	python3 -m Octopus.main
