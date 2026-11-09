# ADR-0026: Dormant controlled reviewer fixture producer

Status: Accepted

Scope: Source prerequisite and pure fixture tests only. The host consumer, CI activation and actual native support remain separate and unproven.

Date: 2026-11-09

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62).

## Context

The controlled reviewer prototype needs a container-side producer that measures its required isolation profile before it accepts `GO`. The fixture and Dockerfile form that producer; acquisition, Docker ownership, host validation, cleanup and full-profile activation belong to a later host stage. This prerequisite does not close issue #62 or provide a production review API, receipt, executor or fleet permission.

The frozen combined prototype checked capabilities, NoNewPrivs, mounts and resource limits, but omitted effective seccomp/AppArmor admission and workspace security flags. Requested launch settings alone cannot substitute for these process and filesystem observations.

## Decision

Introduce the complete synthetic fixture and its fixed nine-line Dockerfile without changing the manifest, extended-validation entrypoint, public artifact stage or existing entrypoint tests. The producer remains dormant in that entrypoint. The Dockerfile preserves the pinned MCR base, complete verified public package/notices/provenance and fixed exec-form `/usr/bin/prlimit` launcher before isolated Python. No installation, alternative image, shell fallback or new launch flag is introduced.

Before any resource setter, require the inherited soft and hard address-space pair to equal 17179869184 bytes. Preserve all existing capabilities, root and writable-mount, shared-memory, architecture, ELF/package and cgroup checks and hard limits. The required future launch profile remains readonly root, network none, all capabilities dropped, no-new-privileges, 2 GiB memory with swap zero, 128 PIDs, two CPUs, the bounded workspace tmpfs and readonly mqueue mask. The fixture observes and rejects unsupported conditions; this source prerequisite does not itself launch a container with those flags.

Use the existing single `/proc/self/status` read to require Seccomp mode `2`. Read `/proc/self/attr/apparmor/current` as bytes and require exactly `b'docker-default (enforce)\n'`. Do not use universal-newline text decoding or a generic LSM-path fallback. Missing/unreadable state, another label or mode, missing/extra LF, CRLF, NUL or other whitespace is unsupported. Keep the relative order of the existing capabilities/mounts/NoNewPrivs operands and the single short-circuit NoNewPrivs observation.

For the same actual workspace `statvfs` result, require builtin integer `f_flag` in `[0, 2**64)`, all `ST_NOSUID | ST_NODEV | ST_NOEXEC` bits and no `ST_RDONLY` bit. The Linux required mask is 14; other benign bits may coexist, so both 14 and 4110 are valid examples. Preserve the existing tmpfs magic, positive size/inode caps and all other capacities. [Python statvfs](https://docs.python.org/3.12/library/os.html#os.statvfs), [Linux flag definitions](https://github.com/bminor/glibc/blob/release/2.39/master/sysdeps/unix/sysv/linux/bits/statvfs.h#L73-L104).

Amend only the private `ready` event with `seccomp: 2`, `apparmor: "docker-default (enforce)"` and measured `tmpfs.flags`. The tmpfs producer now emits `type`, `bytes`, `inodes` and `flags`. All old ready members remain. A future host must require the new fields with exact builtin types and domains, the existing security booleans exactly true and the existing tmpfs bounds before writing any `GO`; absence must not use a legacy fallback. This is a producer interface requirement, not an implemented host validator in this stage. No unrelated exact-key parser restriction is selected.

Keep public evidence fields and diagnostic key/enum sets unchanged. The existing process-mounts status-read/status-parse/combined-predicate markers describe grouped process-security observations; they do not identify an exact failed file or predicate. The tmpfs stage remains grouped. Do not publish raw status/AppArmor/error data. Seccomp mode and an enforcing label do not identify policy contents; this bounded prototype assumes the trusted fixed host, kernel, daemon, image and source. [Kernel LSM interface](https://docs.kernel.org/userspace-api/lsm.html), [Seccomp mode](https://man7.org/linux/man-pages/man2/PR_GET_SECCOMP.2const.html).

Preserve the complete fixed case set and its existing protocol, output bounds, private native-output handling and synthetic API-file/persistence fixtures. Native and mock work remains after mechanical/resource admission and the sandbox canary. No real authentication, provider access, configurable policy, runtime selector or test adapter enters production.

## Validation and activation limits

Pure regressions must exercise the actual old and amended gates with fabricated process/resource/filesystem data. Preserve all ten existing producer methods, the six mount-layout scenarios and fixed Docker ENTRYPOINT assertion while separating the old host consumer into the later host tests. Missing/disabled protection must pass the old gate control but produce no ready event under the amended gate. Positive protected fixtures cover exact single-LF AppArmor bytes and flags 14/4110. Synthetic observations do not establish actual Linux or native support.

The later host stage must validate daemon defaults, consume this ready contract, retain its own cgroup and inherited-limit admission, and own bounded process/container/image/temp cleanup. It must change manifest projection and generated entrypoint together and complete genuine exact-head hosted strict-profile cases before any runtime support claim. The later host stage will bring ADR-0022 into this branch. Full issue #62 acceptance is not established by this prerequisite.
