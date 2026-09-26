# Spec

1. [wrong] Tailer interface shape — `pkg/acquisition/modules/file/tailwrapper/interface.go:14` — design Decision 1 (`design.md:36`) names a three-method `Tailer` (`Lines`, `Stop`, `Filename`); the diff also exports `Dying()` and `Err()` on the same interface
   Fix: Drop `Dying()` and `Err()` from the exported `Tailer` interface, or update design Decision 1 to match the chosen surface
   Status: done
   Argument: Updated `design.md` Decision 1 to include `Dying()` and `Err()`.
