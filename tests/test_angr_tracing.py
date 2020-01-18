import archr
import nose
import os

test_location = os.path.dirname(os.path.realpath(__file__))

def test_angr_tracing():
    if not archr._angr_available:
        raise nose.SkipTest
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
    test_angr_tracing()
