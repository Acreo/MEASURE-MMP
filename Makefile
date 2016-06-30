all:
	docker build --tag="gitlab.testbed.se:5000/mmp" .
	
push:
	docker push "gitlab.testbed.se:5000/mmp"

stop:
	docker kill mmp cadvisor-m1 ratemon-m1 ratemon-m2 ratemon-m3 ratemon-m4 ratemon-m5 ratemon-m6
rm:
	docker rm mmp cadvisor-m1 ratemon-m1 ratemon-m2 ratemon-m3 ratemon-m4 ratemon-m5 ratemon-m6
start:
	docker run -d  --volume=/:/rootfs:ro --volume=/etc/doubledecker:/keys:ro  --volume=/var/run:/var/run:rw  --volume=/sys:/sys:ro  --volume=/var/lib/docker/:/var/lib/docker:ro --link ddbroker:broker --name=mmp  gitlab.testbed.se:5000/mmp
inter:
	docker run -it --volume=/:/rootfs:ro --volume=/etc/doubledecker:/keys:ro  --volume=/var/run:/var/run:rw  --volume=/sys:/sys:ro  --volume=/var/lib/docker/:/var/lib/docker:ro --link ddbroker:broker --name=mmp  gitlab.testbed.se:5000/mmp
bash:
	docker run -it --volume=/:/rootfs:ro --volume=/etc/doubledecker:/keys:ro  --volume=/var/run:/var/run:rw  --volume=/sys:/sys:ro  --volume=/var/lib/docker/:/var/lib/docker:ro --link ddbroker:broker --name=mmp  gitlab.testbed.se:5000/mmp /bin/bash

