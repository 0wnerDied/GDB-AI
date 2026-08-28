# Compatibility

MI4 is preferred and MI3 starts in a fresh fallback GDB process. Capability
support is probed with MI commands and refreshed after launch, attach, core,
or remote target selection. Unknown MI fields and classes are retained; an
unknown state-changing event taints consistency instead of being guessed.

Release testing covers GDB 13 through 17, native x86-64 and AArch64, local,
attach, core, and gdbserver targets where the CI runner exposes them. Missing
host capabilities are reported as skipped or unavailable, never as success.
