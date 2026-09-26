# Devdocs impact
change: migrate-file-acquisition

## Units
- File acquisition — subsystem — `pkg/acquisition/modules/file/`
- Tailwrapper — subsystem — `pkg/acquisition/modules/file/tailwrapper/`

## Findings
- [x] missing-packet  File acquisition — no packet; empty catalog
- [x] language-gap  File acquisition — `core_acquisition_file.md` had no Language terms for tail_mode / stat_poll_interval
- [x] missing-packet  Tailwrapper — no packet; empty catalog
- [x] language-gap  Tailwrapper — `core_acquisition_file_tailwrapper.md` had no Language terms for Tailwrapper / KeepFileOpen
