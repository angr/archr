import archr
import os
import unittest

test_location = os.path.dirname(os.path.realpath(__file__))


class TestangrTracing(unittest.TestCase):
    @unittest.skipUnless(archr._angr_available, "angr required")
    def test_angr_tracing(self):
        target = archr.targets.LocalTarget(os.path.join(test_location, '../../binaries/tests/x86_64/true'))
        dsb = archr.arsenal.DataScoutBow(target)
        apb = archr.arsenal.angrProjectBow(target, dsb)
        asb = archr.arsenal.angrStateBow(target, apb)
        qtb = archr.arsenal.QEMUTracerBow(target)

        trace = qtb.fire()
        p = apb.fire()
        s = asb.fire()
        tech = trace.tracer_technique()
        simgr = p.factory.simulation_manager(s)
        simgr.use_technique(tech)
        simgr.run()

        assert len(simgr.traced) == 1


if __name__ == '__main__':
    unittest.main()
