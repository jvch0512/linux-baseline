# linux-baseline

Read-only **Linux hardening checker in pure Bash**: SSH daemon settings, account hygiene, file permissions, sudo rules and kernel parameters, with PASS / FAIL / SKIP per check, severity levels, JSON output and a CI-friendly exit code.

> Built with AI assistance (Claude) as a portfolio project. Review the code before relying on it.

## Usage

```bash
sudo ./linux-baseline.sh                        # live host (root needed to read /etc/shadow)
./linux-baseline.sh --format json
./linux-baseline.sh --fail-on high              # exit 2 only for high or critical failures
./linux-baseline.sh --root /mnt/vm-image        # audit a mounted disk image or container filesystem
```

```
[PASS] L001 high     root SSH login restricted (no)
[FAIL] L002 medium   SSH password authentication enabled (yes); prefer keys
[FAIL] L005 critical extra UID 0 accounts: toor
```

## Checks

| ID | Severity | Check |
|----|----------|-------|
| L001 | high | `PermitRootLogin` is not `yes` |
| L002 | medium | SSH password authentication disabled |
| L003 | critical | `PermitEmptyPasswords` not enabled |
| L004 | low | X11 forwarding off |
| L005 | critical | only root has UID 0 |
| L006 | critical | no empty password fields in `/etc/shadow` |
| L007 | high | `/etc/shadow` not readable by others or writable by group |
| L008 | high | `/etc/passwd` not world-writable |
| L009 | medium | `PASS_MAX_DAYS` <= 365 |
| L010 | medium | no `NOPASSWD` sudo rules |
| L011 | medium | ASLR (`randomize_va_space = 2`) |
| L012 | low | TCP SYN cookies enabled |
| L013 | low | ICMP redirects ignored |
| L014 | high | `sshd_config` not group/world writable |

## Design

* **Never modifies the system**: a test checksums every fixture file before and after a scan
* Every path resolves under `--root`, so tests use fixture directory trees instead of touching the real `/etc`
* `sshd_config` is parsed the way sshd does: comments ignored, **first occurrence wins**
* Missing files give SKIP, not a false PASS or FAIL
* Inspired by CIS Benchmark and Lynis themes but not a certified implementation

## Tests

```bash
bash tests/run.sh
```

MIT licensed.
