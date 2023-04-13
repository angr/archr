import sys

import archr

with archr.targets.DockerImageTarget(sys.argv[1]).build().start() as t:
    g = archr.analyzers.GDBServerAnalyzer(t)
    g.fire(stdout=1, stderr=2, port=1337, timeout=None)
