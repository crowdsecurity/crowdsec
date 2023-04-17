#!/usr/bin/env python

"""
Smoke tests in case docker is not set up correctly or has connection issues.
"""

import subprocess


def test_docker_cli_run():
    """Test if docker run works from the command line. Capture stdout too"""
    res = subprocess.run(['docker', 'run', '--rm', 'hello-world'],
                         capture_output=True, text=True)
    assert 0 == res.returncode
    assert 'Hello from Docker!' in res.stdout


def test_docker_run(docker_client):
    """Test if docker run works from the python SDK."""
    output = docker_client.containers.run('hello-world', remove=True)
    lines = output.decode().splitlines()
    assert "Hello from Docker!" in lines


def test_docker_run_detach(docker_client):
    """Test with python SDK (async)."""
    cont = docker_client.containers.run('hello-world', detach=True)
    assert cont.status == 'created'
    assert cont.attrs['State']['ExitCode'] == 0
    lines = cont.logs().decode().splitlines()
    assert "Hello from Docker!" in lines
    cont.remove(force=True)
