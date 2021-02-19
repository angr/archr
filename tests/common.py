import docker
import os

TEST_PATH = os.path.dirname(__file__)
def qemu_test_path(s):
    return os.path.join(TEST_PATH, "qemus", s)


def build_container(name: str):
    build_path = os.path.join(os.path.dirname(__file__), "dockers", name)
    client = docker.from_env()
    client.images.build(tag=f"archr-test:{name}", path=build_path)
    client.close()
