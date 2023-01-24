import archr
import os
import unittest


class TestAnalyzerRR(unittest.TestCase):
    def get_miniupnpd_trace(self, t):
        crash = b"A" * 272
        b = archr.analyzers.RRTracerAnalyzer(t)
        res = b.fire(testcase=crash)
        print(f"Done! You can find your trace in {res.trace_dir.name} (timed out?: {res.timed_out})")

    def get_ls_trace(self, t):
        crash = b"A" * 272
        b = archr.analyzers.RRTracerAnalyzer(t)
        res = b.fire(testcase=crash)
        print(f"Done! You can find your trace in {res.trace_dir.name} (timed out?: {res.timed_out})")

    # @unittest.skipUnless(archr.analyzers.rr.trraces, "trraces required")
    @unittest.skip("broken docker image")
    def test_miniupnpd(self):
        with archr.targets.DockerImageTarget("ikanak/miniupnpd").build().start() as t:
            get_miniupnpd_trace(t)

    @unittest.skipUnless(archr.analyzers.rr.trraces, "trraces required")
    def test_ls(self):
        with archr.targets.DockerImageTarget("phate/archr_rr", pull=True).build().start(name="test_rr_analyzer") as t:
            get_ls_trace(t)


if __name__ == "__main__":
    unittest.main()
