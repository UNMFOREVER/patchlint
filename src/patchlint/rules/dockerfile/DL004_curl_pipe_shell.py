from __future__ import annotations

import re
from collections.abc import Iterable

from patchlint.core.model import Context, Finding
from patchlint.core.registry import rule

# A downloader's output going straight into a shell. The left side may carry
# any number of flags (`-fsSL`, `--retry 3`, `-O-`), the right side is one of
# the usual shells, optionally with a path or a flag of its own.
PIPE_TO_SHELL = re.compile(
    r"""
    \b(?:curl|wget)\b            # the downloader
    (?P<fetch>[^|;&]*?)          # its arguments, up to the pipe
    \|\s*                        # the pipe
    (?:(?:sudo|env)\s+)*         # `| sudo sh` and friends
    (?P<shell>/?(?:bin/|usr/bin/)?(?:ba|z|da|k)?sh|/busybox\s+sh)\b
    """,
    re.VERBOSE | re.IGNORECASE,
)

def _writes_to_file(args: str) -> bool:
    """True when curl/wget is asked to save to a file, or to a named output.

    `curl -o- url` and `wget -O- url` send the body to stdout, which is what a
    `| sh` wants, so those are *not* treated as writing to a file.
    """
    for match in re.finditer(r"-o\s*(\S*)", args):
        if match.group(1) not in {"", "-"}:
            return True
    for match in re.finditer(r"--output(?:-document)?[=\s]\s*(\S*)", args):
        if match.group(1) not in {"", "-"}:
            return True
    # wget's -O is the output file; `-O-` is stdout.
    for match in re.finditer(r"(?:^|\s)-O\s*(\S*)", args):
        if match.group(1) not in {"", "-"}:
            return True
    return bool(re.search(r"--directory-prefix[=\s]\s*\S+", args))


@rule(id="DL004", title="Download piped into a shell", severity="high", cwe=494)
def check(ctx: Context) -> Iterable[Finding]:
    """A `RUN` step curls or wgets something and pipes it straight into a shell.

    Why it matters: `curl https://x/y | sh` runs whatever the server sends,
    every time the image is built. There is no checksum, no version, no review
    -- the remote host decides what lands in your image, and if it ever serves
    something else (or the domain lapses and someone else takes it) the build
    silently picks that up. CWE-494 is "download of code without integrity
    check".

    Fix: download, verify, then run:

        RUN curl -fsSLo /tmp/install.sh https://example.com/install.sh \\
         && echo "9f2c...  /tmp/install.sh" | sha256sum -c - \\
         && sh /tmp/install.sh

    Note: `curl -o file URL` (saving to a file) and `curl URL` on its own are
    not reported -- only a download whose output goes into a shell.
    """
    for ins in ctx.instructions:
        if ins.cmd != "RUN":
            continue
        for match in PIPE_TO_SHELL.finditer(ins.args):
            fetch = match.group("fetch")
            if _writes_to_file(fetch):
                continue
            shell = match.group("shell")
            yield ctx.finding(
                ins.line,
                f"`{match.group(0).split('|')[0].strip()}` is piped into "
                f"`{shell}`, so the build runs whatever that URL serves.",
                "Download to a file first, check a SHA-256, then run it -- do "
                "not pipe an unverified download into a shell.",
            )
            break
