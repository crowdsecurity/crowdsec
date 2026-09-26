# Deviations

- [ ] proposed  remove github.com/nxadm/tail dependency
  Asked: migrate file tail handling and add tail_mode / stat_poll_interval (requirement.md Desired). Out of scope: upstream nxadm context support only.
  Instead: in-house pkg/acquisition/modules/file/tailwrapper and drop go.mod require on nxadm/tail.
  Owner: pkg/acquisition/modules/file/
  Why: nxadm lacks context cancellation; stat close-after-read needs a KeepFileOpen loop PR #4280 already prototyped.
  By: explore
  Requester: not asked explicitly
