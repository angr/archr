#!/usr/bin/env python

import archr
import sys

with archr.targets.DockerImageTarget(sys.argv[1]).build().start() as t:
	print("target remote %s:1337" % t.ipv4_address)
	g = archr.arsenal.GDBServerBow(t)
	g.fire(stdout=1, stderr=2, port=1337, timeout=None)
