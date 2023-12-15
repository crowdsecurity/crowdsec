#!/usr/bin/env python3

import json
import pathlib
import os
import sys
import textwrap

test_header = """
set -u

setup_file() {
    load "../lib/setup_file.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
}
"""


def write_chunk(target_dir, n, chunk):
    with open(target_dir / f"hub-{n}.bats", "w") as f:
        f.write(test_header)
        for test in chunk:
            cscli = os.environ['CSCLI']
            crowdsec = os.environ['CROWDSEC']
            testname = test['Name']
            hubdir = os.environ['LOCAL_DIR'] + '/hub-tests'
            f.write(textwrap.dedent(f"""
                @test "{testname}" {{
                    run "{cscli}" \\
                        --crowdsec "{crowdsec}" \\
                        --cscli "{cscli}" \\
                        --hub "{hubdir}" \\
                        hubtest run "{testname}" \\
                        --clean
                    echo "$output"
                    assert_success
                }}
            """))


def main():
    hubtests_json = sys.argv[1]
    target_dir = sys.argv[2]

    with open(hubtests_json) as f:
        j = json.load(f)
        chunk_size = len(j) // 3 + 1
        n = 1
        for i in range(0, len(j), chunk_size):
            chunk = j[i:i + chunk_size]
            write_chunk(pathlib.Path(target_dir), n, chunk)
            n += 1


if __name__ == "__main__":
    main()
