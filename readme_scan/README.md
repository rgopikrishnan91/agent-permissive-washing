# Fixed README evidence scan

This branch carries the reproducible runner and 64 disjoint input shards for
6,737 selected permissive MCP repositories and 5,976 Plugin repositories.
All collection commits are inherited from the existing study corpus. Twenty-four
Plugins lack a recorded README commit and remain explicit unresolved outcomes.

Run one shard with `python3 readme_scan/launch.py --shard 31` (indices 0–63).
Python 3.12 and network access to GitHub and PyPI are required. ScanCode is pinned
to 32.5.0, with frozen study rules and dependency versions. The runner selects a
CPU pool using affinity, cgroup quotas, and a documented memory budget.

The collector reads README-named files at all directory depths and root Plugin
context files. It never executes harvested repository code. The inherited caps
are 500 README candidates per repository and 1 MB per text; skipped symlinks,
binary/oversize files, caps, missing commits, and retrieval errors are recorded.

Outputs include every retrieved text, tree inventory, scan, and repository record,
packed into checked archive parts under `codex_cloud_shard_NN/`. Keep all parts
in the cloud task diff. Source integrity does not by itself establish copyright
ownership; context comparison and ownership review follow locally.

The main branch is not modified by these jobs. This input branch is for executing
the requested cloud scan; cloud tasks should not push or open pull requests.
