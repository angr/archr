#!/usr/bin/env python
import sys

import archr
t = archr.targets.DockerImageTarget(sys.argv[1])
with t.build().start():
	t.flight().default_channel.interact()
