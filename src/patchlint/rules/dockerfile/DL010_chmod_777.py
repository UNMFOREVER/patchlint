from __future__ import annotations

import re
from collections.abc import Iterable

from patchlint.core.model import Context, Finding
from patchlint.core.registry import rule

# Where a shell command starts: beginning of the body, or after a separator.
START = r"(?:^|[;&|(]\s*)"

# `chmod` as a command, with any flags (`-R`, `--recursive`, `-v`) between it
# and the mode. The mode itself is matched separately so we can tell 777 from
# 0777 and from 1777-ish nonsense.
CHMOD = re.compile(START + r"chmod\s+((?:-[A-Za-z-]+\s+)*)(\S+)", re.IGNORECASE)

COMMENT = re.compile(r"(?:^|\s)#.*$")


def _strip_comment(command: str) -> str:
    """Drop ` # ...` from each line; a `#` mid-word is not a comment."""
    return "\n".join(COMMENT.sub("", line) for line in command.splitlines())


def _is_world_writable_exec(mode: str) -> bool:
    """True for 777 and anything that grants everyone all three bits.

    Accepts `777`, `0777`, `a+rwx`, `ugo+rwx`. Symbolic partial modes like
    `o+w` are not "777" and are left alone -- they are a real finding of a
    different kind, not this rule.
    """
    cleaned = mode.strip().strip("'\"")
    if re.fullmatch(r"0?[0-7]?777", cleaned):
        # 0777 / 777 / 4777-style sticky-bit forms all grant rwx to everyone.
        return True
    lowered = cleaned.lower()
    if re.fullmatch(r"(a|ugo)\+rwx", lowered):
        return True
    return False


@rule(id="DL010", title="chmod 777 in a RUN step", severity="medium", cwe=732)
def check(ctx: Context) -> Iterable[Finding]:
    """A `RUN` step runs `chmod 777` (with or without `-R`).

    Why it matters: 777 means every user on the box, including any process that
    was compromised, can rewrite and execute that file. In a build step it is
    usually a workaround for not having worked out which user owns what, and it
    bakes that workaround into the image permanently. A script that anyone can
    edit but the entrypoint still runs with root is a direct path from "one
    small foothold" to "full control of the container". CWE-732 is incorrect
    permission assignment for a critical resource.

    Fix: give the one user or group what it needs:

        RUN chown -R app:app /srv/app && chmod 750 /srv/app

    Note: `chmod 755`, `chmod 644`, `chmod -R u+rwX`, and a mention inside a
    comment are not reported.
    """
    for ins in ctx.instructions:
        if ins.cmd != "RUN":
            continue
        body = _strip_comment(ins.args)
        for match in CHMOD.finditer(body):
            flags = match.group(1)
            mode = match.group(2)
            if not _is_world_writable_exec(mode):
                continue
            shown = (flags + mode).strip()
            yield ctx.finding(
                ins.line,
                f"`chmod {shown}` makes the target writable and executable by "
                "everyone.",
                "Grant only the user or group that needs it, e.g. "
                "`chown app:app <path> && chmod 750 <path>`.",
            )
            break
