#!/usr/bin/env python3

import sys
from subprocess import check_output

commit_msg_filepath = sys.argv[1]
branch = check_output(["git", "symbolic-ref", "--short", "HEAD"]).decode("utf-8").strip()

types_branches = ("feat", "hotfix", "fix")

type = branch.split("/")[0]
branch = branch.split("/")[1]

if type in types_branches:
    with open(commit_msg_filepath, "r+") as f:
        commit_msg = f.read()
        f.seek(0, 0)
        f.write(f"[[{type}]]: {commit_msg}")
