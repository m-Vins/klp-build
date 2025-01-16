# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

import logging
import subprocess
import sys
import re
from pathlib import Path
from pathlib import PurePath

from klpbuild.klplib import utils
from klpbuild.klplib.ksrc import GitHelper

def run(args):
    lp_name = args.name
    cve = args.cve
    lp_filter = args.filter

    skips = ""

    return get_patches(lp_name, cve, lp_filter, skips)


def get_patches(lp_name, cve, lp_filter="", skips=""):
    gh = GitHelper(lp_name, lp_filter, skips)

    if not gh.kern_src:
        logging.info("kernel_src_dir not found, skip getting SUSE commits")
        return {}

    # ensure that the user informed the commits at least once per 'project'
    if not cve:
        logging.info("No CVE informed, skipping the processing of getting the patches.")
        return {}

    # Support CVEs from 2020 up to 2029
    if not re.match(r"^202[0-9]-[0-9]{4,7}$", cve):
        logging.info("Invalid CVE number '%s', skipping the processing of getting the patches.", cve)
        return {}

    print("Fetching changes from all supported branches...")

    # Mount the command to fetch all branches for supported codestreams
    subprocess.check_output(["/usr/bin/git", "-C", str(gh.kern_src), "fetch",
                             "--quiet", "--atomic", "--force", "--tags", "origin"] +
                            list(gh.kernel_branches.values()))

    print("Getting SUSE fixes for upstream commits per CVE branch. It can take some time...")

    # Store all commits from each branch and upstream
    commits = {}
    # List of upstream commits, in creation date order
    ucommits = []

    upatches = Path(utils.get_workdir(gh.lp_name), "upstream")
    upatches.mkdir(exist_ok=True, parents=True)

    # Get backported commits from all possible branches, in order to get
    # different versions of the same backport done in the CVE branches.
    # Since the CVE branch can be some patches "behind" the LTSS branch,
    # it's good to have both backports code at hand by the livepatch author
    for bc, mbranch in gh.kernel_branches.items():
        commits[bc] = {"commits": []}

        try:
            patch_files = subprocess.check_output(
                ["/usr/bin/git", "-C", gh.kern_src, "grep", "-l", f"CVE-{cve}", f"remotes/origin/{mbranch}"],
                stderr=subprocess.STDOUT,
            ).decode(sys.stdout.encoding)
        except subprocess.CalledProcessError:
            patch_files = ""

        # If we don't find any commits, add a note about it
        if not patch_files:
            continue

        # Prepare command to extract correct ordering of patches
        cmd = ["/usr/bin/git", "-C", gh.kern_src, "grep", "-o", "-h"]
        for patch in patch_files.splitlines():
            _, fname = patch.split(":")
            cmd.append("-e")
            cmd.append(fname)
        cmd += [f"remotes/origin/{mbranch}:series.conf"]

        # Now execute the command
        try:
            patch_files = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode(sys.stdout.encoding)
        except subprocess.CalledProcessError:
            patch_files = ""

        # The command above returns a list of strings in the format
        #   branch:file/path
        idx = 0
        for patch in patch_files.splitlines():
            if patch.strip().startswith("#"):
                continue

            idx += 1
            branch_path = Path(utils.get_workdir(lp_name), "fixes", bc)
            branch_path.mkdir(exist_ok=True, parents=True)

            pfile = subprocess.check_output(
                ["/usr/bin/git", "-C", gh.kern_src, "show", f"remotes/origin/{mbranch}:{patch}"],
                stderr=subprocess.STDOUT,
            ).decode(sys.stdout.encoding)

            # removing the patches.suse dir from the filepath
            basename = PurePath(patch).name.replace(".patch", "")

            # Save the patch for later review from the livepatch developer
            with open(Path(branch_path, f"{idx:02d}-{basename}.patch"), "w") as f:
                f.write(pfile)

            # Get the upstream commit and save it. The Git-commit can be
            # missing from the patch if the commit is not backporting the
            # upstream fix, and is using a different way to mimic the fix.
            # In this case add a note for the livepatch author to fill the
            # blank when finishing the livepatch
            ups = ""
            m = re.search(r"Git-commit: ([\w]+)", pfile)
            if m:
                ups = m.group(1)[:12]

            # Aggregate all upstream fixes found
            if ups and ups not in ucommits:
                ucommits.append(ups)

            # Now get all commits related to that file on that branch,
            # including the "Refresh" ones.
            try:
                phashes = subprocess.check_output(
                    [
                        "/usr/bin/git",
                        "-C",
                        gh.kern_src,
                        "log",
                        "--no-merges",
                        "--pretty=oneline",
                        f"remotes/origin/{mbranch}",
                        "--",
                        patch,
                    ],
                    stderr=subprocess.STDOUT,
                ).decode("ISO-8859-1")
            except subprocess.CalledProcessError:
                print(
                    f"File {fname} doesn't exists {mbranch}. It could "
                    " be removed, so the branch is not affected by the issue."
                )
                commits[bc]["commits"] = ["Not affected"]
                continue

            # Skip the Update commits, that only change the References tag
            for hash_entry in phashes.splitlines():
                if "Update" in hash_entry and "patches.suse" in hash_entry:
                    continue

                # Sometimes we can have a commit that touches two files. In
                # these cases we can have duplicated hash commits, since git
                # history for each individual file will show the same hash.
                # Skip if the same hash already exists.
                hash_commit = hash_entry.split(" ")[0]
                if hash_commit not in commits[bc]["commits"]:
                    commits[bc]["commits"].append(hash_commit)

    # Grab each commits subject and date for each commit. The commit dates
    # will be used to sort the patches in the order they were
    # created/merged.
    ucommits_sort = []
    for c in ucommits:
        d, msg = GitHelper.get_commit_data(c, upatches)
        ucommits_sort.append((d, c, msg))

    ucommits_sort.sort()
    commits["upstream"] = {"commits": []}
    for d, c, msg in ucommits_sort:
        commits["upstream"]["commits"].append(f'{c} ("{msg}")')

    print("")

    for key, val in commits.items():
        print(f"{key}")
        branch_commits = val["commits"]
        if not branch_commits:
            print("None")
        for c in branch_commits:
            print(c)
        print("")

    return commits
