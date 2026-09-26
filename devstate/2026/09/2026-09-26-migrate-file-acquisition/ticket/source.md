Migrate file acquisition + New tail_mode and stat_poll_interval settings to support not keeping file handles permanently open

This is a POC of migrating tail to use context. 

Unfortunately the underlying library used does not support context, so I just removed it.
