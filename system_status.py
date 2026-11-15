"""Read host resource usage for the authenticated system overview."""
import os
from pathlib import Path
import shutil
import threading

ROOT = Path(__file__).resolve().parent
PROC = Path('/proc')
_cpu_lock = threading.Lock()
_last_cpu = None


def cpu_usage():
    global _last_cpu
    fields = (PROC / 'stat').read_text().splitlines()[0].split()
    if fields[0] != 'cpu' or len(fields) < 5:
        raise ValueError('Некорректный /proc/stat')
    values = [int(value) for value in fields[1:9]]
    total = sum(values)
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    with _cpu_lock:
        previous = _last_cpu
        _last_cpu = (total, idle)
    if previous is None or total <= previous[0] or idle < previous[1]:
        return None
    return round(max(0, min(100, 100 * (1 - (idle - previous[1]) / (total - previous[0])))), 1)


def memory_usage():
    fields = {}
    for line in (PROC / 'meminfo').read_text().splitlines():
        name, _, value = line.partition(':')
        if name in ('MemTotal', 'MemAvailable'):
            fields[name] = int(value.split()[0]) * 1024
    total = fields['MemTotal']
    return dict(total=total, used=total - fields['MemAvailable'])


def disk_usage():
    usage = shutil.disk_usage('/')
    return dict(total=usage.total, used=usage.used)


def status():
    result = dict(version=(ROOT / 'VERSION').read_text().strip(), revision=None, errors={})
    revision = ROOT / '.revision'
    if revision.exists():
        result['revision'] = revision.read_text().strip()
    checks = {
        'cpu_percent': cpu_usage,
        'memory': memory_usage,
        'disk': disk_usage,
        'uptime_seconds': lambda: int(float((PROC / 'uptime').read_text().split()[0])),
        'load_average': lambda: list(os.getloadavg()),
    }
    for name, check in checks.items():
        try:
            result[name] = check()
        except (OSError, ValueError, IndexError, KeyError) as error:
            result[name] = None
            result['errors'][name] = str(error)
    return result
