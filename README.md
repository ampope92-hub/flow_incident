# Flow Incident Reconstruction

A site suspects data theft. Two routers exported flow records to a collector, and the collector's archive is reachable over TCP at `ARCHIVE_HOST` / `ARCHIVE_PORT`. The archive holds every export packet with its arrival time, plus a case line naming the suspect host, the time window and the site network. The agent must turn the stub at `/app/flowkit/src/main.zig` into a Zig tool that pages through the whole archive and prints one line of JSON: per-host outbound traffic (what left the site) and the inside hosts the suspect reached laterally, with first-contact times. It must also report lost-packet counts. `/app/flowkit/SPEC.md` defines the archive protocol, the packet layout, the facts known about each router and the collector, and the report format.

## What makes it hard

Each device tells the story slightly wrong, and the spec states each problem as a fact without saying how to handle it:

- The edge router samples one packet in N, so its counts and times describe sampled packets only.
- The core router counts every packet but has never been on NTP. On the shipped archive its clock is 667 seconds ahead.
- The core was power cycled once, which restarted its boot counter and flow sequence.
- The collector lost packets from both routers, restarted, and re-sent the last minutes of its spool. As a result, some packets appear twice with a later arrival time.
- Both 32-bit boot counters wrap inside the archive.

These interact. The clock error decides which records form one connection. The connection decides whose count stands. Sampling decides whether a count is scaled. The re-sent copies decide which arrival gives the clock error. The power cycle decides how lost records are counted.

Measured on the shipped archive (42 report fields):

| Misreading | Fields wrong |
|---|---|
| Grouping records on raw clocks | 41 |
| Keying re-sent copies on flow sequence | 38 |
| Adding both routers' counts | 35 |
| Cutting connections on the 15 s router timeout instead of the site's five-minute port reuse | 32 |
| Leaving sampled counts unscaled | 27 |

`solution/calibrate.py` confirms that each of 21 misreadings gets a field wrong on every one of eight fresh seeds that contains its case.

## How it's graded

The verifier runs in a separate container and collects only `/app/flowkit/src`. Before each run it deletes every non-`.zig` file and compiles `main.zig` exactly as the spec states, with no libc. It then runs the tool three times against archive servers it starts itself, each on a fresh port and page size:

1. The shipped archive, on another address.
2. A held-back 1.4 MB archive with a different network, window and names, 1-in-260 sampling and a core clock 1420 seconds out.
3. A small archive reached by host name. Here the core sequence after the power cycle rises past the old boot's, there are no re-sent packets, and the suspect's inside connections fall outside the window.

Every outbound row, every lateral row with its first-contact time, and both lost counts must match exactly.

The expected reports were written in advance by a Python rule book (`solution/generate_archive.py`) that was written before the Zig solution. A check also requires them to equal the Zig reference's own output. Per-archive coverage checks confirm that every intended case is actually present, and log checks confirm that each run followed the archive's random page tokens through the whole archive.

Anti-cheat measures: compilation and runs happen as an unprivileged user; goldens, archives and tests are closed to that user; a seccomp launcher (`tests/launch.c`) blocks any further `exec`; and root's PATH is checked. According to `task.toml`, eighteen wrong variants all scored 0 and the reference scored 1.

## Repository layout

- `instruction.md`: the task prompt given to the agent.
- `task.toml`: metadata, difficulty, solution and verification notes, and resource limits.
- `environment/`: the agent's container (`Dockerfile`), the archive service (`Dockerfile.archive`, `archive/`), wired together by `docker-compose.yaml`; `app/flowkit/` holds `SPEC.md`, the stub `src/main.zig` and build/run scripts.
- `solution/`: `solve.sh`, the reference Zig tool (`src/main.zig`), the traffic and archive generator with the rule book (`generate_archive.py`), and the misreading calibration (`calibrate.py`).
- `tests/`: verifier image and entrypoint (`Dockerfile`, `test.sh`), pytest checks (`test_outputs.py`), the seccomp launcher (`launch.c`), the archive server, the three graded archives (`data/`) and their expected reports (`golden/`, `golden_ref/`).

## Running it

Requires Docker and Harbor (`uv tool install harbor` or `pip install harbor`). From the repo root:

```
harbor run -p . -a oracle
```

This runs the reference solution through the verifier and should score reward 1. To try an agent instead:

```
harbor run -p . -a <agent> -m <model>
```

For example, `-a claude-code`.

---

Task design, data generators, reference solution and verifier by Audrey Pope.
