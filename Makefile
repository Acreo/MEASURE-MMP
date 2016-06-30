all:
	docker build --tag="gitlab.testbed.se:5000/mmp" .
	
push:
	docker push "gitlab.testbed.se:5000/mmp"

stop:
	-docker ps -a --filter="name=ratemon*" | egrep -o -e '(ratemon-.+)'  | xargs docker kill
	-docker ps -a --filter="name=cadvisor*" | egrep -o -e '(cadvisor-.+)'  | xargs docker kill
	-docker kill mmp
rm:
	-docker ps -a --filter="name=ratemon*" | egrep -o -e '(ratemon-.+)'  | xargs docker rm
	-docker ps -a --filter="name=cadvisor*" | egrep -o -e '(cadvisor-.+)'  | xargs docker rm
	-docker rm mmp
start:
	docker run -d  --volume=/:/rootfs:ro --volume=/etc/doubledecker:/keys:ro  --volume=/var/run:/var/run:rw  --volume=/sys:/sys:ro  --volume=/var/lib/docker/:/var/lib/docker:ro --link ddbroker:broker --name=mmp  gitlab.testbed.se:5000/mmp
inter:
	docker run -it --volume=/:/rootfs:ro --volume=/etc/doubledecker:/keys:ro  --volume=/var/run:/var/run:rw  --volume=/sys:/sys:ro  --volume=/var/lib/docker/:/var/lib/docker:ro --link ddbroker:broker --name=mmp  gitlab.testbed.se:5000/mmp
bash:
	docker run -it --volume=/:/rootfs:ro --volume=/etc/doubledecker:/keys:ro  --volume=/var/run:/var/run:rw  --volume=/sys:/sys:ro  --volume=/var/lib/docker/:/var/lib/docker:ro --link ddbroker:broker --name=mmp  gitlab.testbed.se:5000/mmp /bin/bash

