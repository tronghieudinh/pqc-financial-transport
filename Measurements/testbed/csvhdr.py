#!/usr/bin/env python3
"""csvhdr.py - the metadata header of pqcm data files.

Every CSV written by a pqcm.sh step starts with a block of comment lines ("# key: value") that records the machine, kernel, OpenSSL version,
the configuration of the step and, for every run of the step, start/end time and the CPU load before and after. The data follows
unchanged, so an analysis script only has to ignore the lines that begin with "#":

    import csvhdr          # once, before reading; csv.DictReader / csv.reader then skip the header lines

Command line (used by pqcm.sh):
    csvhdr.py inject FILE --common k=v ... --step k=v ...   add/update the header; each call appends one step entry (resumed runs keep their history)
    csvhdr.py show FILE                                      print the header
    csvhdr.py strip FILE [...]                               print the data without the header (concatenate several files: header of the first only)
"""
import csv as _csv
import sys

MAGIC = "# pqcm-header 1"
END = "# pqcm-header-end"


def _skip(f):
    for line in f:
        if not line.startswith("#"):
            yield line


_DictReader, _reader = _csv.DictReader, _csv.reader


def _wrap(orig):
    def inner(f, *a, **k):
        if hasattr(f, "read") or hasattr(f, "__next__"):
            f = _skip(f)
        return orig(f, *a, **k)
    return inner


_csv.DictReader = _wrap(_DictReader)
_csv.reader = _wrap(_reader)


def split_header(lines):
    """-> (header lines, data lines)"""
    if not lines or not lines[0].startswith(MAGIC):
        return [], lines
    for i, l in enumerate(lines):
        if l.startswith(END):
            return lines[:i + 1], lines[i + 1:]
    return [], lines


def inject(path, common, step, max_bytes=300_000_000):
    import os
    if os.path.getsize(path) > max_bytes:
        return False
    with open(path, newline="") as fh:
        lines = fh.read().splitlines(keepends=True)
    head, data = split_header(lines)
    old_common = {}
    steps = []
    for l in head[1:-1]:
        body = l[2:].rstrip("\n")
        if body.startswith("run["):
            steps.append(body)
        elif ": " in body:
            k, v = body.split(": ", 1)
            old_common[k] = v
    old_common.update({k: str(v) for k, v in common.items()})
    steps.append("run[%d]: %s" % (len(steps) + 1, ", ".join("%s=%s" % (k, v) for k, v in step.items())))
    out = [MAGIC + "\n"] + ["# %s: %s\n" % (k, v) for k, v in old_common.items()] + ["# %s\n" % s for s in steps] + [END + "\n"]
    tmp = path + ".hdr.tmp"
    with open(tmp, "w", newline="") as fh:
        fh.writelines(out + data)
    os.replace(tmp, path)
    return True


def _kv(items):
    d = {}
    for it in items:
        k, _, v = it.partition("=")
        d[k] = v
    return d


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    if a[0] == "inject":
        path = a[1]
        rest = a[2:]
        i_c = rest.index("--common") if "--common" in rest else len(rest)
        i_s = rest.index("--step") if "--step" in rest else len(rest)
        common = _kv(rest[i_c + 1:i_s] if i_c < i_s else rest[i_c + 1:])
        step = _kv(rest[i_s + 1:i_c] if i_s < i_c else rest[i_s + 1:])
        if not inject(path, common, step):
            print("skipped (file too large): " + path, file=sys.stderr)
    elif a[0] == "show":
        head, _ = split_header(open(a[1]).read().splitlines(keepends=True))
        sys.stdout.write("".join(head))
    elif a[0] == "strip":
        first = True
        for p in a[1:]:
            _, data = split_header(open(p, newline="").read().splitlines(keepends=True))
            if not first and data:
                data = data[1:]       # drop the repeated column header line
            sys.stdout.write("".join(data))
            first = False
