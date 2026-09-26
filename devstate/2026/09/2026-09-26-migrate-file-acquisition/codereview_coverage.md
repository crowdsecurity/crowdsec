# Test coverage

1. [hard] Ticket job unproven — `pkg/acquisition/modules/file/run.go:282` — `tail_mode: stat` must select close-after-read handle management; module stat-mode tests only assert lines read and `IsTailing`, so reverting `keepFileOpen := s.config.TailMode != "stat"` to always `true` leaves them green
   Quote:
   ```
   keepFileOpen := s.config.TailMode != "stat"
   KeepFileOpen: keepFileOpen,
   test: tail_modes_test.go TestTailModes_BasicTailing / TestTailModes_ConfigurationApplied — IsTailing and line content only; (none) asserting close-after-read selection
   ```
   Fix: Assert stat YAML drives close-after-read at the module seam (observable poll timing, manual `-1` path through Stream, or exported configured strategy)
   Status: done
   Argument: Added `keepFileOpenForTailMode` plus `TestKeepFileOpenForTailMode` and `TestConfigureTailModeStored` in `config_tail_test.go`.

2. [hard] Assertion does not prove the job — `pkg/acquisition/modules/file/tail_modes_test.go:191` — `TestTailModes_ConfigurationApplied` sets `expectStatMode` but never asserts it; only `IsTailing` and `t.Logf` would stay green if `tail_mode` wiring were ignored
   Quote:
   ```
   expectStatMode: true,
   assert.True(t, f.IsTailing(testFile), "File should be tailed")
   t.Logf("Successfully tailed file with mode: %s (expectStatMode=%v)", ...)
   test: (none) assertion on expectStatMode
   ```
   Fix: Assert the mode-specific outcome the field names, or drop the false claim and rely on a test that fails when stat/default wiring is reverted
   Status: done
   Argument: Removed unused `expectStatMode`; wiring covered in `config_tail_test.go`.

3. [hard] Critical path untested — `pkg/acquisition/modules/file/config.go:73` — unknown `tail_mode` is rejected at configure time; no test exercises that error outcome
   Quote:
   ```
   return fmt.Errorf("unsupported tail_mode %q (supported: default, stat)", s.config.TailMode)
   test: (none) — no configure negative case for invalid tail_mode in pkg/acquisition/modules/file/*_test.go
   ```
   Fix: Configure with `tail_mode: invalid` and assert Configure returns an error containing `unsupported tail_mode`
   Status: done
   Argument: Added `TestConfigureInvalidTailMode` in `config_tail_test.go`.

4. [hard] Edge case untested — `pkg/acquisition/modules/file/config.go:69` — design names `stat_poll_interval: 0` → `1s` when `tail_mode: stat`; configure normalizes but no test hits that branch
   Quote:
   ```
   if s.config.StatPollInterval == 0 {
       s.config.StatPollInterval = time.Second
   }
   test: (none) — no configure test with stat_poll_interval: 0
   ```
   Fix: Configure stat mode with `stat_poll_interval: 0` and assert normalized interval or poll timing consistent with 1s
   Status: done
   Argument: Added `TestUnmarshalConfigStatPollIntervalZeroDefaultsToOneSecond`.
