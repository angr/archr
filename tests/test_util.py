import archr

def test_deps():
    assert sorted(archr.utils.lib_dependencies("/bin/false")) == [ "/lib/x86_64-linux-gnu/libc.so.6", "/lib64/ld-linux-x86-64.so.2" ]

if __name__ == "__main__":
    test_deps()
