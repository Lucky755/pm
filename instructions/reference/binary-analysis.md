# Local binary analysis — reference, not a verified exploitation procedure

Read this only for an explicitly assigned binary-analysis task with supplied,
authorized artifacts. Identify the binary, libraries and loader from saved
files and hashes; reproduce behavior locally if the executor supports it.
Compare actual input bounds and object lifetimes as hypotheses. A difference
between handlers does not by itself prove an exploitable write, a useful
primitive or access. Missing readback is neither proof of safety nor proof of
exploitability. Save exact reproduction evidence before proposing a target
operation, and keep all task restrictions.

This replaces challenge-specific advice previously injected into every VULN
and ACCESS prompt. It is not connected automatically to a profile. No universal
binary exploitation procedure or particular offsets/layouts have been verified
by PM's offline tests. Develop and validate a specialized procedure separately
before adding it to the active catalog.

The separate material-analysis profile now provides tested static binutils
structure/disassembly and preserved source links. Ghidra is a suitable optional
reverse engineering/decompilation tool; Hydra tests network authentication and
is never an alternative binary analyzer. The local processor does not execute
specimens or claim exploitability from strings/disassembly alone.
