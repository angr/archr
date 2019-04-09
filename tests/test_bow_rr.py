import archr
import os


def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def get_miniupnpd_trace(t):
    crash = b"A" * 272
    b = archr.arsenal.RRTracerBow(t)
    b.fire(testcase=crash)
    print("asd as")

def test_miniupnpd():
    with archr.targets.DockerImageTarget('ikanak/miniupnpd').build().start() as t:
        get_miniupnpd_trace(t)



if __name__ == '__main__':
    test_miniupnpd()
