from __future__ import annotations

import re
import shlex
from collections.abc import Iterable

from patchlint.core.model import Context, Finding
from patchlint.core.registry import rule

# `apt-get install ...` or `apt install ...`, anywhere in the RUN line -- often
# after `&&`, or inside `sh -c "..."`. The front boundary keeps `apt-get`
# from matching inside words and stops `apt install` from matching
# `apt-get install` twice.
INSTALL = re.compile(r"(?:^|[\s;&|(\"'])(?:apt-get|apt)\s+install\b", re.IGNORECASE)

# Where apt stops reading its own options: the next command, or the end.
STOPS_AT = {"&&", "||", ";", "|", "&", ")", "}", "#"}

GOOD_FLAGS = {"--no-install-recommends", "--no-install-suggests"}


def _chunks(command: str) -> list[list[str]]:
    """Split a RUN body into shell-ish words, keeping quoting sane."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return [list(lexer)]
    except ValueError:
        return [command.split()]


def _install_segments(words: list[str]) -> list[list[str]]:
    """Every `install` invocation's argument list, cut at the next command."""
    segments: list[list[str]] = []
    index = 0
    while index < len(words):
        token = words[index]
        if token in {"apt-get", "apt"}:
            # Skip anything between the tool and `install`, e.g. `apt-get -y install`.
            look = index + 1
            while look < len(words) and words[look] not in STOPS_AT:
                if words[look] == "install":
                    segment = []
                    look += 1
                    while look < len(words) and words[look] not in STOPS_AT:
                        segment.append(words[look])
                        look += 1
                    segments.append(segment)
                    index = look
                    break
                look += 1
            else:
                index += 1
                continue
            continue
        index += 1
    return segments


def _has_no_recommends(segment: list[str]) -> bool:
    """`--no-install-recommends` may be spelled a few ways; any of them counts."""
    for word in segment:
        plain = word.split("=", 1)[0].lower()
        if plain in GOOD_FLAGS:
            return True
        # `-o APT::Install-Recommends=false` is the long way round.
        lowered = word.lower().replace("_", "-")
        if "apt::install-recommends=false" in lowered:
            return True
    return False


@rule(id="DL005", title="apt install without --no-install-recommends", severity="low", cwe=1104)
def check(ctx: Context) -> Iterable[Finding]:
    """A `RUN` step runs `apt-get install` without `--no-install-recommends`.

    Why it matters: apt's default is to pull in *recommended* packages as well
    as required ones, and on a slim base image that quietly drags in dozens of
    extras -- man pages, docs, extra libraries, occasionally another service.
    Every one of them is another package in the image's attack surface, more
    bytes to pull, and more CVEs to chase. It is not a vulnerability in itself,
    but it is the single cheapest way to make an image smaller and duller.

    Fix: say what you actually need.

        RUN apt-get update \\
         && apt-get install -y --no-install-recommends curl ca-certificates \\
         && rm -rf /var/lib/apt/lists/*

    Note: `--no-install-recommends` anywhere in the same install command
    (including `-o APT::Install-Recommends=false`) means it is not reported.
    Only `apt-get install` and `apt install` are considered -- not `apt remove`,
    `apt update`, or a `# apt-get install ...` line inside a comment.
    """
    for ins in ctx.instructions:
        if ins.cmd != "RUN":
            continue
        for words in _chunks(ins.args):
            for segment in _install_segments(words):
                if _has_no_recommends(segment):
                    continue
                packages = [w for w in segment if not w.startswith("-")]
                if not packages:
                    # `apt-get install` with nothing after it installs nothing.
                    continue
                yield ctx.finding(
                    ins.line,
                    "`apt install` without `--no-install-recommends` pulls in "
                    "recommended packages too.",
                    "Add `--no-install-recommends` (and `-y`) to the install "
                    "command, and clean `/var/lib/apt/lists/*` afterwards.",
                )
                break
