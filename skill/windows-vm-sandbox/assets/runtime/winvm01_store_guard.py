"""Keep the exact 150GiB store fully allocated and immune to lower discard."""
import json
import os
import pathlib
import subprocess

STORE = pathlib.Path('/home/vm_run/.storage/winvm01.store')
MOUNT = pathlib.Path('/home/vm_run/vol')
SIZE = 150 * 1024**3
UUID = 'e68ccc11-f548-4a28-a341-3707945468b1'
INODE = 73924612


def output(args):
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout.strip()


def main():
    assert os.geteuid() == 0
    fields = output(['findmnt', '-rn', '--mountpoint', str(MOUNT), '-o', 'SOURCE,FSTYPE,UUID']).split()
    assert len(fields) == 3 and fields[1:] == ['ext4', UUID], 'Store mount identity changed'
    loops = json.loads(output(['losetup', '--list', '--json', '--output', 'NAME,BACK-FILE']))['loopdevices']
    assert any(l['name'] == fields[0] and l['back-file'] == str(STORE) for l in loops)
    assert STORE.stat().st_ino == INODE and STORE.stat().st_size == SIZE and not STORE.is_symlink()
    # Disable only this loop queue. Global fstrim and the physical NVMe remain unchanged.
    queue = pathlib.Path('/sys/class/block') / pathlib.Path(fields[0]).name / 'queue/discard_max_bytes'
    queue.write_text('0')
    if STORE.stat().st_blocks * 512 < SIZE:
        with STORE.open('r+b') as stream:
            os.posix_fallocate(stream.fileno(), 0, SIZE)
            os.fsync(stream.fileno())
    assert queue.read_text().strip() == '0' and STORE.stat().st_blocks * 512 >= SIZE


if __name__ == '__main__':
    main()
