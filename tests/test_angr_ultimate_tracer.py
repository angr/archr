import archr
import os
import logging
import unittest

test_location = os.path.dirname(os.path.realpath(__file__))


class TestangrUltimateTracer(unittest.TestCase):
    @unittest.skip("for now")  # Unless(archr._angr_available, "angr required")
    def test_dir_x86_64(self):
        target = archr.targets.LocalTarget(os.path.join(test_location, "../../binaries/tests/x86_64/dir_gcc_-O0"))
        dsb = archr.arsenal.DataScoutAnalyzer(target)
        apb = archr.arsenal.angrProjectAnalyzer(target, dsb)
        asb = archr.arsenal.angrStateAnalyzer(target, apb)
        utb = archr.arsenal.angrUltimateTracerAnalyzer(target, apb)

        import angr

        logging.getLogger("angr.bureau.bureau").setLevel(logging.DEBUG)

        _ = utb.make_project()
        trace = utb.fire(
            state=asb.fire(
                brk=None,
                args=["dir", "/"],
                add_options=angr.sim_options.unicorn | {angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY},
            )
        )
        # p = apb.fire()
        # s = asb.fire()
        # tech = trace.tracer_technique()
        # simgr = p.factory.simulation_manager(s)
        # simgr.use_technique(tech)
        # simgr.run()

        # assert len(simgr.traced) == 1


if __name__ == "__main__":
    unittest.main()
