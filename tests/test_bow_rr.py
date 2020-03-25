import archr
import os
import unittest


class TestBowRR(unittest.TestCase):
    def get_miniupnpd_trace(self,t):
        crash = b"A" * 272
        b = archr.arsenal.RRTracerBow(t)
        res = b.fire(testcase=crash)
        print("Done! You can find your trace in {} (timed out?: {})".format(res.trace_dir.name, res.timed_out))

    def get_ls_trace(self,t):
        crash = b"A" * 272
        b = archr.arsenal.RRTracerBow(t)
        res = b.fire(testcase=crash)
        print("Done! You can find your trace in {} (timed out?: {})".format(res.trace_dir.name, res.timed_out))

    # @unittest.skipUnless(archr.arsenal.rr.trraces, "trraces required")
    @unittest.skip("broken docker image")
    def test_miniupnpd(self):
        with archr.targets.DockerImageTarget('ikanak/miniupnpd').build().start() as t:
            get_miniupnpd_trace(t)

    @unittest.skipUnless(archr.arsenal.rr.trraces, "trraces required")
    def test_ls(self):
        with archr.targets.DockerImageTarget('phate/archr_rr', pull=True).build().start(name='test_rr_bow') as t:
            get_ls_trace(t)


if __name__ == '__main__':
    unittest.main()
