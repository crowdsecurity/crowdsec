#!/usr/bin/env bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    INDEX_PATH=$(config_get '.config_paths.index_path')
    export INDEX_PATH
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    ./instance-data load
}

teardown() {
    ./instance-crowdsec stop
}

#----------

@test "malformed index - null item" {
    yq -o json >"$INDEX_PATH" <<-'EOF'
	parsers:
	  author/pars1:
	EOF

    rune -1 cscli hub list
    assert_stderr --partial "invalid hub index: parsers:author/pars1 has no index metadata."
}

@test "malformed index - no download path" {
    yq -o json >"$INDEX_PATH" <<-'EOF'
	parsers:
	  author/pars1:
	    version: "0.0"
	    versions:
	      0.0:
	        digest: daa1832414a685d69269e0ae15024b908f4602db45f9900e9c6e7f204af207c0
	EOF

    rune -1 cscli hub list
    assert_stderr --partial "invalid hub index: parsers:author/pars1 has no download path."
}

@test "malformed parser - no stage" {
    # Installing a parser requires a stage directory
    yq -o json >"$INDEX_PATH" <<-'EOF'
	parsers:
	  author/pars1:
	    path: parsers/s01-parse/author/pars1.yaml
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
	    content: "{}"
	EOF

    rune -1 cscli hub list -o raw
    assert_stderr --partial "invalid hub index: parsers:author/pars1 has no stage."
}

@test "malformed parser - short path" {
    # Installing a parser requires a stage directory
    yq -o json >"$INDEX_PATH" <<-'EOF'
	parsers:
	  author/pars1:
	    path: parsers/s01-parse/pars1.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
	    content: "{}"
	EOF

    rune -0 cscli hub list -o raw
    rune -0 cscli parsers install author/pars1
    rune -0 cscli hub list
    # XXX here the item is installed but won't work, we only have a warning
    assert_stderr --partial 'Ignoring file'
    assert_stderr --partial 'path is too short'
}

@test "malformed item - not yaml" {
    # Installing an item requires reading the list of data files
    yq -o json >"$INDEX_PATH" <<-'EOF'
	parsers:
	  author/pars1:
	    path: parsers/s01-parse/pars1.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: daa1832414a685d69269e0ae15024b908f4602db45f9900e9c6e7f204af207c0
	    content: "v0.0"
	EOF

    rune -0 cscli hub list -o raw
    rune -1 cscli parsers install author/pars1
    assert_stderr --partial 'unmarshal errors'
}

@test "malformed item - hash mismatch" {
    yq -o json >"$INDEX_PATH" <<-'EOF'
	parsers:
	  author/pars1:
	    path: parsers/s01-parse/pars1.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: "0000000000000000000000000000000000000000000000000000000000000000"
	    content: "v0.0"
	EOF

    rune -0 cscli hub list -o raw
    rune -1 cscli parsers install author/pars1
    assert_stderr --partial 'parsers:author/pars1: hash mismatch: expected 0000000000000000000000000000000000000000000000000000000000000000, got daa1832414a685d69269e0ae15024b908f4602db45f9900e9c6e7f204af207c0.'
}

@test "install minimal item" {
    yq -o json >"$INDEX_PATH" <<-'EOF'
	parsers:
	  author/pars1:
	    path: parsers/s01-parse/pars1.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
	    content: "{}"
	EOF

    rune -0 cscli hub list -o raw
    rune -0 cscli parsers install author/pars1
    assert_line "downloading parsers:author/pars1"
    assert_line "enabling parsers:author/pars1"
    rune -0 cscli hub list
}

@test "replace an item in a collection update" {
    # A new version of coll1 will uninstall pars1 and install pars2.
    yq -o json >"$INDEX_PATH" <<-'EOF'
	collections:
	  author/coll1:
	    path: collections/author/coll1.yaml
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 801e11865f8fdf82a348e70fe3f568af190715c40a176e058da2ad21ff5e20be
	    content: "{'parsers': ['author/pars1']}"
	    parsers:
	    - author/pars1
	parsers:
	  author/pars1:
	    path: parsers/s01-parse/author/pars1.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
	    content: "{}"
	  author/pars2:
	    path: parsers/s01-parse/author/pars2.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
	    content: "{}"
	EOF

    rune -0 cscli hub list
    rune -0 cscli collections install author/coll1

    yq -o json >"$INDEX_PATH" <<-'EOF'
	collections:
	  author/coll1:
	    path: collections/author/coll1.yaml
	    version: "0.1"
	    versions:
	      0.0:
	        digest: 801e11865f8fdf82a348e70fe3f568af190715c40a176e058da2ad21ff5e20be
	      0.1:
	        digest: f3c535c2d01abec5aadbb5ce03c357a478d91b116410c9fee288e073cd34c0dd
	    content: "{'parsers': ['author/pars2']}"
	    parsers:
	    - author/pars2
	parsers:
	  author/pars1:
	    path: parsers/s01-parse/author/pars1.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
	    content: "{}"
	  author/pars2:
	    path: parsers/s01-parse/author/pars2.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
	    content: "{}"
	EOF

    rune -0 cscli hub list -o raw
    rune -0 cscli collections upgrade author/coll1
    assert_output - <<-EOT
	Action plan:
	📥 download
	 collections: author/coll1 (0.0 -> 0.1)
	 parsers: author/pars2 (0.0)
	✅ enable
	 parsers: author/pars2
	❌ disable
	 parsers: author/pars1

	downloading parsers:author/pars2
	enabling parsers:author/pars2
	disabling parsers:author/pars1
	downloading collections:author/coll1
		
	$RELOAD_MESSAGE
	EOT

    rune -0 cscli hub list -o raw
    assert_output - <<-EOT
	name,status,version,description,type
	author/pars2,enabled,0.0,,parsers
	author/coll1,enabled,0.1,,collections
	EOT
}

@test "replace an outdated item only if it's not used elsewhere" {
    # XXX
    skip "not implemented"
    # A new version of coll1 will uninstall pars1 and install pars2.
    # Pars3 will not be uninstalled because it's still required by coll2.
    yq -o json >"$INDEX_PATH" <<-'EOF'
	collections:
	  author/coll1:
	    path: collections/author/coll1.yaml
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 0c397c7b3e19d730578932fdc260c53f39bd2488fad87207ab6b7e4dc315b067
	    content: "{'parsers': ['author/pars1', 'author/pars3']}"
	    parsers:
	    - author/pars1
	    - author/pars3
	  author/coll2:
	    path: collections/author/coll2.yaml
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 96df483ff697d4d214792b135a3ba5ddaca0ebfd856e7da89215926394ac4001
	    content: "{'parsers': ['author/pars3']}"
	    parsers:
	    - author/pars3
	parsers:
	  author/pars1:
	    path: parsers/s01-parse/author/pars1.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
	    content: "{}"
	  author/pars2:
	    path: parsers/s01-parse/author/pars2.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
	    content: "{}"
	  author/pars3:
	    path: parsers/s01-parse/author/pars3.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
	    content: "{}"
	EOF

    rune -0 cscli hub list
    rune -0 cscli collections install author/coll1 author/coll2

    yq -o json >"$INDEX_PATH" <<-'EOF'
	collections:
	  author/coll1:
	    path: collections/author/coll1.yaml
	    version: "0.1"
	    versions:
	      0.0:
	        digest: 0c397c7b3e19d730578932fdc260c53f39bd2488fad87207ab6b7e4dc315b067
	      0.1:
	        digest: f3c535c2d01abec5aadbb5ce03c357a478d91b116410c9fee288e073cd34c0dd
	    content: "{'parsers': ['author/pars2']}"
	    parsers:
	    - author/pars2
	  author/coll2:
	    path: collections/author/coll2.yaml
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 96df483ff697d4d214792b135a3ba5ddaca0ebfd856e7da89215926394ac4001
	    content: "{'parsers': ['author/pars3']}"
	    parsers:
	    - author/pars3
	parsers:
	  author/pars1:
	    path: parsers/s01-parse/author/pars1.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
	    content: "{}"
	  author/pars2:
	    path: parsers/s01-parse/author/pars2.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
	    content: "{}"
	  author/pars3:
	    path: parsers/s01-parse/author/pars3.yaml
	    stage: s01-parse
	    version: "0.0"
	    versions:
	      0.0:
	        digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
	    content: "{}"
	EOF

    rune -0 cscli hub list -o raw
    rune -0 cscli collections upgrade author/coll1
    assert_output - <<-EOT
	downloading parsers:author/pars2
	enabling parsers:author/pars2
	disabling parsers:author/pars1
	downloading collections:author/coll1
		
	$RELOAD_MESSAGE
	EOT

    rune -0 cscli hub list -o raw
    assert_output - <<-EOT
	name,status,version,description,type
	author/pars2,enabled,0.0,,parsers
	author/pars3,enabled,0.0,,parsers
	author/coll1,enabled,0.1,,collections
	EOT
}
