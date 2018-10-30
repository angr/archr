import archr
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_cat_ldd():
    t = archr.targets.DockerImageTarget('archr-test:cat').build().start()
    b = archr.bows.MemoryMapBow(t)
    s = b.fire()
    assert s == {
        'linux-vdso.so.1': 0x7ffff7ffa000,
        '/lib/x86_64-linux-gnu/libc.so.6': 0x7ffff77c4000,
        '/lib64/ld-linux-x86-64.so.2': 0x7ffff7dd5000,
        'stack': 0x7ffffffde000,
        'heap': 0x55555575d000,
        '[vvar]': 0x7ffff7ff7000,
        '[vdso]': 0x7ffff7ffa000,
        '[vsyscall]': 0xffffffffff600000
    }

    t.stop()

if __name__ == '__main__':
    test_cat_ldd()
