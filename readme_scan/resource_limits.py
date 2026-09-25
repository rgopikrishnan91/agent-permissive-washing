"""Choose scan processes from Linux CPU quotas and available memory.

The memory budget is an explicit planning heuristic, not a ScanCode guarantee.
CPU affinity alone can overstate the CPU allocation inside a cloud container.
"""
from pathlib import Path
import math
import os

MIB = 1024 ** 2


def read(path):
    try:
        return path.read_text().strip()
    except OSError:
        return None


def cgroup_directories(proc=Path('/proc')):
    """Resolve process membership against visible cgroup mounts and ancestors."""
    memberships = {}
    for line in (read(proc/'self/cgroup') or '').splitlines():
        _, controllers, location = line.split(':', 2)
        for controller in controllers.split(','):
            memberships[controller] = Path(location)
    result = set()
    for line in (read(proc/'self/mountinfo') or '').splitlines():
        before, after = line.split(' - ', 1)
        fields, filesystem = before.split(), after.split()
        if filesystem[0] not in {'cgroup', 'cgroup2'}:
            continue
        unescape = lambda value: value.replace('\\040', ' ').replace('\\134', '\\')
        root, mount = Path(unescape(fields[3])), Path(unescape(fields[4]))
        controllers = [''] if filesystem[0] == 'cgroup2' else filesystem[2].split(',')
        # The mount root may carry a limit even when membership is not visible.
        result.add(mount)
        for controller in controllers:
            member = memberships.get(controller)
            if member is None:
                continue
            try:
                relative = member.relative_to(root)
            except ValueError:
                # A cgroup namespace can report membership relative to its root.
                relative = member.relative_to('/')
            current = mount/relative
            while current.is_relative_to(mount):
                result.add(current)
                if current == mount:
                    break
                current = current.parent
    return sorted(result)


def resources(proc=Path('/proc')):
    info = read(proc/'meminfo') or ''
    available = next((int(line.split()[1])*1024 for line in info.splitlines()
                      if line.startswith('MemAvailable:')), None)
    cpu_limits, memory_limits = [], []
    for directory in cgroup_directories(proc):
        cpu = read(directory/'cpu.max')
        if cpu:
            quota, period = cpu.split()
            if quota != 'max' and int(quota) > 0 and int(period) > 0:
                cpu_limits.append(dict(path=str(directory/'cpu.max'), cpus=int(quota)/int(period)))
        quota, period = read(directory/'cpu.cfs_quota_us'), read(directory/'cpu.cfs_period_us')
        if quota and period and int(quota) > 0 and int(period) > 0:
            cpu_limits.append(dict(path=str(directory/'cpu.cfs_quota_us'), cpus=int(quota)/int(period)))
        for limit_name, usage_name in [('memory.max', 'memory.current'),
                                       ('memory.limit_in_bytes', 'memory.usage_in_bytes')]:
            limit, usage = read(directory/limit_name), read(directory/usage_name)
            if limit and limit != 'max' and usage:
                memory_limits.append(dict(path=str(directory/limit_name),
                    limit_bytes=int(limit), current_bytes=int(usage),
                    remaining_bytes=max(0, int(limit)-int(usage))))
    headroom = [item['remaining_bytes'] for item in memory_limits]
    if available is not None:
        headroom.append(available)
    return dict(logical_cpus=os.cpu_count(), cpu_affinity=len(os.sched_getaffinity(0)),
                cpu_quota_observations=cpu_limits, memory_limit_observations=memory_limits,
                memory_available_bytes=min(headroom) if headroom else None,
                memory_info=info)


def choose_workers(observed, requested=None):
    if requested is not None and requested < 1:
        raise ValueError('workers must be positive')
    quota = [item['cpus'] for item in observed['cpu_quota_observations']]
    capacity = min([observed['cpu_affinity'], *quota])
    cpu_cap = max(1, math.ceil(capacity))
    available = observed['memory_available_bytes']
    if available is None:
        raise RuntimeError('Cannot determine available memory for automatic worker sizing')
    # Reserve 1 GiB for the shared index/parent and 512 MiB per child.
    memory_cap = max(0, (available-1024*MIB)//(512*MIB))
    if memory_cap < 1:
        raise RuntimeError('Less than 1.5 GiB memory headroom; cannot start the configured ScanCode pool')
    workers = min(cpu_cap, memory_cap, requested if requested is not None else cpu_cap)
    return dict(scan_workers=workers, effective_cpu_capacity=capacity,
                cpu_worker_cap=cpu_cap, memory_worker_cap=memory_cap,
                requested_workers=requested, memory_reserve_mib=1024,
                memory_per_worker_mib=512,
                policy='Use allocated CPU capacity, bounded by a conservative memory heuristic. '
                       'This does not establish the fastest pool size or a Codex service limit.')
