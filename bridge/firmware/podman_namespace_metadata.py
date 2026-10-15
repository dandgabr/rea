# Fixed preloaded metadata protocol. This file is read before launch and passed as
# admitted -c bytes; it is never opened or imported in the selected namespace.
import os
import sys
import json

PROTOCOL = "rea-podman-metadata-v1"
REQUEST_BYTES = 16384
RESPONSE_BYTES = 65536
stage = "parent"
opened = []
observations = {"protocol": PROTOCOL, "status": "refused", "stage": stage,
                "pairs": [], "entry": {}, "preload": {}, "generations": {}}
# All functions and exception/failure serialization paths are compiled/prewarmed
# before the first namespace effect. No subprocess, thread, ctypes or late import.
json.loads('{"array":[0,null,true,"☃"],"object":{}}')
json.dumps(observations, ensure_ascii=False).encode("utf-8", "strict")
"☃".encode("utf-8", "strict").decode("utf-8", "strict")
read, write, fstat, close, open_fd = os.read, os.write, os.fstat, os.close, os.open
readlink, setns, setgroups = os.readlink, os.setns, os.setgroups
setuid, setgid = os.setuid, os.setgid

def require(condition, reason):
    if not condition:
        raise ValueError(reason)

def strict_json_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON request key")
        value[key] = item
    return value

def json_wire_bytes(value):
    # Exact ensure_ascii=False/separators=(',', ':') projection size, including
    # UTF8 and control escaping, before allocating the serialized response.
    if type(value) is str:
        count = 2
        for character in value:
            code = ord(character)
            require(not 0xD800 <= code <= 0xDFFF, "invalid response Unicode scalar")
            count += (2 if character in '\\"' or code in (8, 9, 10, 12, 13)
                      else 6 if code < 32 else 1 if code < 128
                      else 2 if code < 2048 else 3 if code < 65536 else 4)
        return count
    if value is None:
        return 4
    if type(value) is bool:
        return 4 if value else 5
    if type(value) is int:
        return len(str(value))
    if type(value) is list:
        return 2 + max(0, len(value) - 1) + sum(json_wire_bytes(item) for item in value)
    require(type(value) is dict, "unsupported response projection type")
    return 2 + max(0, len(value) - 1) + sum(json_wire_bytes(key) + 1 + json_wire_bytes(item) for key, item in value.items())

def audit(event, args):
    if stage != "parent" and (event == "import" or event in {
            "compile", "exec", "ctypes.dlopen", "os.fork", "os.forkpty",
            "os.posix_spawn", "os.exec", "subprocess.Popen",
            "_posixsubprocess.fork_exec", "_thread.start_new_thread"}):
        raise RuntimeError("post-entry code loading/process operation refused")

sys.addaudithook(audit)

def keys(value, expected, label):
    require(type(value) is dict and set(value) == set(expected), "invalid request " + label)

def number(value):
    require(type(value) is str and value.isascii() and value.isdecimal()
            and (value == "0" or not value.startswith("0")), "invalid request numeric identity")
    return value

def hex64(value):
    require(type(value) is str and len(value) == 64 and
            all(c in "0123456789abcdef" for c in value), "invalid request full identity")

def path(value):
    require(type(value) is str and value.startswith("/") and value != "/"
            and "\0" not in value and os.path.normpath(value) == value,
            "invalid request canonical path")
    value.encode("utf-8", "strict")
    return value

def request_value(value):
    keys(value, ["protocol", "id", "image_id", "graph_root", "run_root",
                 "image_root", "helper", "prepared", "namespaces", "roles"], "keys")
    require(value["protocol"] == PROTOCOL, "invalid request protocol")
    hex64(value["id"]); hex64(value["image_id"])
    graph = path(value["graph_root"]); path(value["run_root"])
    image = path(value["image_root"])
    prefix = graph + "/overlay/"
    require(image.startswith(prefix) and image.endswith("/merged"), "invalid request image root")
    hex64(image[len(prefix):-len("/merged")])
    for role in ["helper", "prepared"]:
        record = value[role]
        keys(record, ["pid", "start_ticks", "user_ns", "mount_ns"], role)
        require(type(record["pid"]) is int and 0 < record["pid"] <= 2147483647, "invalid request PID")
        number(record["start_ticks"])
        for name, native in [("user_ns", "user"), ("mount_ns", "mnt")]:
            text = record[name]
            require(type(text) is str and text.startswith(native + ":[") and text.endswith("]"), "invalid request namespace")
            number(text[len(native) + 2:-1])
    keys(value["namespaces"], ["user", "mount"], "namespace descriptors")
    for descriptor in value["namespaces"].values():
        keys(descriptor, ["device", "inode"], "namespace descriptor")
        number(descriptor["device"]); number(descriptor["inode"])
    roles = value["roles"]
    require(type(roles) is list and 1 <= len(roles) <= 3, "invalid request role count")
    seen = set(); sources = []
    for role in roles:
        keys(role, ["role", "source"], "role")
        require(role["role"] in ["work", "input", "plugins"] and role["role"] not in seen, "invalid request duplicate/unknown role")
        seen.add(role["role"]); sources.append(path(role["source"]))
    require("work" in seen, "invalid request missing work role")
    for index, source in enumerate(sources):
        for other in sources[index + 1:]:
            require(source != other and not source.startswith(other + "/") and not other.startswith(source + "/"), "invalid request overlapping roots")
    return value

def acquire(name, flags, directory=None):
    require(len(opened) < 32, "transient metadata FD budget")
    fd = open_fd(name, flags, dir_fd=directory)
    opened.append(fd)
    return fd

def release(fd):
    close(fd)
    opened.remove(fd)

def bounded_file(directory, name, maximum=65536):
    fd = acquire(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, directory)
    try:
        result = bytearray()
        while True:
            chunk = read(fd, min(4096, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            require(len(result) <= maximum, "process metadata byte budget")
        return bytes(result).decode("utf-8", "strict")
    finally:
        release(fd)

def generation(directory, expected):
    raw = bounded_file(directory, "stat")
    end = raw.rfind(")")
    require(end > 0, "invalid anchored process stat")
    fields = raw[end + 2:].split()
    require(len(fields) >= 20 and fields[19] == expected["start_ticks"]
            and raw[:raw.find(" ")] == str(expected["pid"]), "anchored process generation changed")
    observed = {"pid": expected["pid"], "start_ticks": fields[19],
                "user_ns": readlink("ns/user", dir_fd=directory),
                "mount_ns": readlink("ns/mnt", dir_fd=directory)}
    require(observed["user_ns"] == expected["user_ns"] and observed["mount_ns"] == expected["mount_ns"], "anchored namespace generation changed")
    return observed

def identity(directory, relative, is_directory):
    flags = os.O_PATH | os.O_NOFOLLOW | (os.O_DIRECTORY if is_directory else 0)
    fd = acquire(relative, flags, directory)
    try:
        value = fstat(fd)
        kind = value.st_mode & 0o170000
        require(kind == (0o040000 if is_directory else 0o100000), "metadata entry type mismatch")
        return {"device": str(value.st_dev), "inode": str(value.st_ino),
                "directory": is_directory}
    finally:
        release(fd)

def emit():
    require(json_wire_bytes(observations) + 1 <= RESPONSE_BYTES, "metadata response byte budget")
    encoded = json.dumps(observations, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "strict")
    offset = 0
    while offset < len(encoded):
        progress = write(1, encoded[offset:])
        require(progress > 0, "metadata response made no progress")
        offset += progress
    write(1, b"\n")

def main():
    global stage
    raw = bytearray()
    while True:
        chunk = read(0, min(4096, REQUEST_BYTES + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
        require(len(raw) <= REQUEST_BYTES, "request byte budget")
    request = request_value(json.loads(bytes(raw).decode("utf-8", "strict"), object_pairs_hook=strict_json_object))
    require(sys.version_info[:3] == (3, 14, 8) and sys.flags.isolated == 1
            and sys.flags.no_site == 1 and sys.flags.utf8_mode == 1,
            "unsupported fixed interpreter readiness")
    require(len(os.listdir("/proc/self/task")) == 1, "metadata interpreter must be single-threaded")
    own = acquire("/proc/self", os.O_PATH | os.O_DIRECTORY)
    require(len(sys.modules) <= 128, "preloaded module count budget")
    own_stat = bounded_file(own, "stat")
    own_start = own_stat[own_stat.rfind(")") + 2:].split()[19]
    token = os.getenv("REA_PROCESS_RUN_ID")
    require(type(token) is str and token.startswith("rea-firmware-"), "missing acquired host process token")
    executable = fstat(7)
    observations["preload"] = {"version": sys.version, "prefix": sys.prefix,
        "modules": sorted(sys.modules), "thread_count": 1, "host_pid": os.getpid(),
        "host_start_ticks": own_start, "run_token": token,
        "executable_device": str(executable.st_dev), "executable_inode": str(executable.st_ino)}
    before = {"helper": generation(5, request["helper"]), "prepared": generation(6, request["prepared"])}
    observations["generations"]["before"] = before
    for slot, name in [(3, "user"), (4, "mount")]:
        value = fstat(slot); expected = request["namespaces"][name]
        require(str(value.st_dev) == expected["device"] and str(value.st_ino) == expected["inode"], "inherited namespace descriptor changed")
    require((fstat(7).st_mode & 0o170000) == 0o100000, "interpreter descriptor is not regular")
    group_before = False
    try:
        setgroups([]); group_before = True
    except OSError as error:
        observations["entry"]["groups_before_error"] = str(error)
    require(len(os.listdir("/proc/self/task")) == 1, "thread created before namespace entry")
    stage = "entry"; observations["stage"] = stage
    mount_entered = False
    try:
        setns(4, os.CLONE_NEWNS); mount_entered = True
    except OSError as error:
        observations["entry"]["mount_first_error"] = str(error)
    setns(3, os.CLONE_NEWUSER)
    if not mount_entered:
        setns(4, os.CLONE_NEWNS)
    try:
        setgroups([])
    except OSError as error:
        observations["entry"]["groups_after_error"] = str(error)
        require(group_before, "both supplementary group clearing attempts failed")
    setgid(0); setuid(0)
    require(os.getgroups() == [], "supplementary groups are not empty")
    require(len(os.listdir("/proc/self/task")) == 1, "thread created after namespace entry")
    require(readlink("ns/user", dir_fd=own) == request["helper"]["user_ns"] and
            readlink("ns/mnt", dir_fd=own) == request["helper"]["mount_ns"], "entered namespaces differ from admitted handles")
    observations["entry"].update({"uid": os.getuid(), "gid": os.getgid(),
        "groups": os.getgroups(), "uid_map": bounded_file(own, "uid_map"),
        "gid_map": bounded_file(own, "gid_map"), "thread_count": 1,
        "user_ns": readlink("ns/user", dir_fd=own), "mount_ns": readlink("ns/mnt", dir_fd=own)})
    helper_root = acquire("root", os.O_PATH | os.O_DIRECTORY, 5)
    prepared_root = acquire("root", os.O_PATH | os.O_DIRECTORY, 6)
    pairs = [("image", request["image_root"], "", True)]
    userdata = request["run_root"] + "/overlay-containers/" + request["id"] + "/userdata/"
    pairs.extend([("hosts", userdata + "hosts", "etc/hosts", False),
                  ("hostname", userdata + "hostname", "etc/hostname", False),
                  ("containerenv", userdata + ".containerenv", "run/.containerenv", False),
                  ("shm", request["graph_root"] + "/overlay-containers/" + request["id"] + "/userdata/shm", "dev/shm", True)])
    pairs.extend((role["role"], role["source"], "rea-" + role["role"], True) for role in request["roles"])
    require(len(pairs) <= 8, "metadata pair count budget")
    for role, source, destination, directory in pairs:
        source_identity = identity(helper_root, source[1:], directory)
        target_identity = identity(prepared_root, destination or ".", directory)
        record = {"role": role, "source": source, "destination": "/" + destination,
                  "directory": directory, "source_identity": source_identity,
                  "target_identity": target_identity}
        observations["pairs"].append(record)
        require(source_identity == target_identity, "source/target identity mismatch")
    observations["generations"]["after"] = {"helper": generation(5, request["helper"]), "prepared": generation(6, request["prepared"])}
    require(before == observations["generations"]["after"], "generation changed during observation")
    observations["status"] = "verified"

try:
    main()
except BaseException as error:
    observations["error"] = {"kind": type(error).__name__, "message": str(error)}
finally:
    for descriptor in reversed(opened[:]):
        try:
            release(descriptor)
        except BaseException as error:
            observations["status"] = "refused"
            observations.setdefault("cleanup_errors", []).append({"fd": descriptor, "reason": str(error)})
    emit()
sys.exit(0 if observations["status"] == "verified" else 1)
