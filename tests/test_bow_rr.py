import archr
import nose
import os


def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def get_miniupnpd_trace(t):
    crash = b"A" * 272
    b = archr.arsenal.RRTracerBow(t)
    res = b.fire(testcase=crash)
    print("Done! You can find your trace in {} (timed out?: {})".format(res.trace_dir.name, res.timed_out))

def get_ls_trace(t):
    crash = b"A" * 272
    b = archr.arsenal.RRTracerBow(t)
    res = b.fire(testcase=crash)
    print("Done! You can find your trace in {} (timed out?: {})".format(res.trace_dir.name, res.timed_out))

# This test case fails because the docker image is broken
def test_miniupnpd():
    if archr.arsenal.rr.trraces is None:
        raise nose.SkipTest
    with archr.targets.DockerImageTarget('ikanak/miniupnpd').build().start() as t:
        get_miniupnpd_trace(t)

def test_ls():
    if archr.arsenal.rr.trraces is None:
        raise nose.SkipTest
    with archr.targets.DockerImageTarget('phate/archr_rr', pull=True).build().start(name='test_rr_bow') as t:
        get_ls_trace(t)


if __name__ == '__main__':
#     test_miniupnpd()
    test_ls()
