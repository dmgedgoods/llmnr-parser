# Repository Instructions

## Current State
- This workspace currently has no source files, `go.mod`, README, build scripts, CI config, or test config; do not invent commands until the repo adds executable config.
- Preserve these instructions as the only verified repo-local guidance unless new files make them stale.

## Assessment Goal
- Implement a Go `gopacket` parser for LLMNR and demonstrate that a sample PCAP parses correctly.
- Keep the codebase and dataset used for the analysis in the repository.

## Required Documentation
- Document findings and explain the code decisions made.
- Document any AI tool usage, including prompts.
- The assessment also requires an unedited screen recording of the coding session including all windows used; OpenCode cannot create this automatically, so do not claim it was produced unless the user provides it.

## Reference material

- https://pkg.go.dev/github.com/google/gopacket#hdr-Basic_Usage
- https://github.com/google/gopacket/blob/master/layers/dns.go
- https://github.com/google/gopacket/blob/master/examples/reassemblydump/main.go
- https://www.rfc-editor.org/info/rfc1035/
