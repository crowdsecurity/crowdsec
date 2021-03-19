## Functional testing

This directory contains scripts for functional testing of crowdsec, to unify testing across packages (ie. tgz, deb, rpm).

Each package system tests the installation/removal, and the scripts here cover basic functional testing.

### cscli

| Feature       | Covered     | Note     |
| :------------- | :----------: | -----------: |
| `cscli alerts` |  🟢 | 99ip_mgmt.sh |
| `cscli bouncers` |  🟢 | 1bouncers.sh |
| `cscli capi` |  ❌  | 0base.sh : `status` only |
| `cscli collections` |  🟢 | 2collections.sh |
| `cscli config` | ❌  | 0base.sh : minimal testing (no crash) |
| `cscli dashboard` | ❌   | docker inside docker 😞    |
| `cscli decisions` |  🟢 | 99ip_mgmt.sh |
| `cscli hub` |  ❌ | TBD |
| `cscli lapi` |  🟢 | 3machines.sh  |
| `cscli machines` |  🟢 | 3machines.sh |
| `cscli metrics` |  ❌ | TBD |
| `cscli parsers` |  ❌ | TBD |
| `cscli postoverflows` |  ❌ | TBD |
| `cscli scenarios` |  ❌ | TBD |
| `cscli simulation` |  ❌ | TBD |
| `cscli version` |  🟢 | 0base.sh |

### crowdsec

| Feature       | Covered     | Note     |
| :------------- | :----------: | -----------: |
| `systemctl` start/stop/restart | 🟢 | 0base.sh |
| agent behaviour | 🟢 | 4cold-logs.sh : minimal testing  (simple ssh-bf detection) |
| forensic mode  | 🟢  | 4cold-logs.sh : minimal testing (simple ssh-bf detection) |
| starting only LAPI  | ❌  | TBD |
| starting only agent  | ❌  | TBD |
| prometheus testing  | ❌  | TBD |

### API


| Feature       | Covered     | Note     |
| :------------- | :----------: | -----------: |
| alerts GET/POST | 🟢 | 99ip_mgmt.sh |
| decisions GET/POST | 🟢 | 99ip_mgmt.sh |


## Automation

https://github.com/crowdsecurity/crowdsec/ uses dispatch to triggers tests in the other packages build repositories.



