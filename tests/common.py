import docker
import os

def build_container(name: str):
    build_path = os.path.join(os.path.dirname(__file__), "dockers", name)
    client = docker.from_env()
    client.images.build(tag=f"archr-test:{name}", path=build_path)
