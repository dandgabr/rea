# Test-only owned namespace fixture; never shipped or accepted as caller code.
import os, sys, json, ctypes, time
libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
libc.mount.restype = ctypes.c_int
parent_mount = os.readlink('/proc/self/ns/mnt')
child = None
gate = None

def require(value, message):
    if not value:
        raise RuntimeError(message)

def mount(source, target, flags):
    result = libc.mount(None if source is None else os.fsencode(source), os.fsencode(target), None, flags, None)
    if result:
        raise OSError(ctypes.get_errno(), 'owned fixture mount failed')

def start(pid):
    raw = open('/proc/' + str(pid) + '/stat').read()
    return raw[raw.rfind(')') + 2:].split()[19]

try:
    request = json.loads(sys.stdin.readline(16385))
    root = request['root']
    require(root.startswith('/tmp/rea-metadata-namespace-') and os.stat(root).st_uid == os.getuid() and (os.stat(root).st_mode & 0o777) == 0o700, 'fixture root authority')
    before_group = False
    try:
        os.setgroups([]); before_group = True
    except OSError:
        pass
    try:
        os.setns(4, os.CLONE_NEWNS); entered = True
    except OSError:
        entered = False
    os.setns(3, os.CLONE_NEWUSER)
    if not entered:
        os.setns(4, os.CLONE_NEWNS)
    try:
        os.setgroups([])
    except OSError:
        require(before_group, 'fixture groups could not be cleared')
    os.setgid(0); os.setuid(0)
    helper_mount = os.readlink('/proc/self/ns/mnt')
    os.unshare(os.CLONE_NEWNS)
    owned_mount = os.readlink('/proc/self/ns/mnt')
    require(owned_mount != helper_mount and owned_mount != parent_mount, 'no distinct fixture mount namespace')
    mount(None, '/', 16384 | (1 << 18)) # MS_REC|MS_PRIVATE, own cloned namespace only.
    before_mounts = open('/proc/self/mountinfo').read()
    require(all(not any(item.startswith(('shared:', 'master:', 'propagate_from:')) for item in line.split()[6:line.split().index('-')]) for line in before_mounts.splitlines()), 'fixture propagation is not recursively private')
    observations = {'mount_namespace': owned_mount, 'shared_helper_mount_namespace': helper_mount, 'private_before_bind': True, 'binds': []}
    for item in request['binds']:
        source, target = item['source'], item['target']
        require(source.startswith(root + '/') and os.path.realpath(source) == source, 'unowned source')
        fd = os.open(source, os.O_PATH | os.O_NOFOLLOW)
        source_stat = os.fstat(fd)
        require(str(source_stat.st_dev) == item['device'] and str(source_stat.st_ino) == item['inode'], 'source identity changed')
        os.close(fd)
        require(target in request['fixed_targets'] or target.startswith(root + '/image/'), 'unsupported target')
        require(os.path.realpath(target) == target, 'target alias')
        original = os.stat(target, follow_symlinks=False)
        require((original.st_mode & 0o170000) == (source_stat.st_mode & 0o170000), 'target type mismatch')
        mount(source, target, 4096) # MS_BIND, verified own mount view only.
        mount(None, target, 4096 | 32 | (1 if item['readonly'] else 0) | 2 | 4) # BIND|REMOUNT|RDONLY?|NOSUID|NODEV.
        observed = os.stat(target, follow_symlinks=False)
        require((observed.st_dev, observed.st_ino) == (source_stat.st_dev, source_stat.st_ino), 'bind correspondence')
        observations['binds'].append({'source':source,'target':target,'device':str(observed.st_dev),'inode':str(observed.st_ino)})
    read_gate, gate = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(gate)
        os.chroot(root + '/image'); os.chdir('/')
        os.read(read_gate, 1)
        os._exit(0)
    os.close(read_gate)
    observations.update({'pid':os.getpid(),'start_ticks':start(os.getpid()),'prepared_pid':child,'prepared_start_ticks':start(child),'run_token':os.getenv('REA_PROCESS_RUN_ID'),'user_ns':os.readlink('/proc/self/ns/user'),'mount_ns':os.readlink('/proc/self/ns/mnt'),'pid_ns':os.readlink('/proc/self/ns/pid'),'executable':os.readlink('/proc/self/exe')})
    print(json.dumps(observations), flush=True)
    # EOF releases the exact fork-acquired child before this parent exits.
    command = bytearray()
    while True:
        value = os.read(0, 1)
        if not value:
            break
        command.extend(value)
        require(len(command) <= 64, 'fixture command budget')
        if value == b'\n':
            require(command == b'RUN_SUBSTITUTION_CONTROL\n', 'unknown test fixture command')
            for target in request['fixed_targets'][:4]:
                # Deliberately unbound positive controls, after genuine helper's
                # marker-absence assertion. Only exact owned marker code.
                exec(open(target).read(), {})
            print(json.dumps({'control':'four unbound substitutes executed'}), flush=True)
            command.clear()
finally:
    if gate is not None:
        os.close(gate)
    if child not in (None, 0):
        require(os.waitpid(child, 0)[0] == child, 'fixture child settlement')
