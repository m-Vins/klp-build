# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

import logging
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from pathlib import PurePath

import requests
from natsort import natsorted

from klpbuild.klplib import utils
from klpbuild.klplib.config import get_user_path
from klpbuild.klplib.codestream import Codestream


class GitHelper():
    def __init__(self, lp_name, lp_filter, skips):

        self.kern_src = get_user_path('kernel_src_dir', isopt=True)

        self.kernel_branches = {
            "12.5": "SLE12-SP5",
            "15.2": "SLE15-SP2-LTSS",
            "15.3": "SLE15-SP3-LTSS",
            "15.4": "SLE15-SP4-LTSS",
            "15.5": "SLE15-SP5-LTSS",
            "15.6": "SLE15-SP6",
            "15.6rt": "SLE15-SP6-RT",
            "6.0": "SUSE-2024",
            "6.0rt": "SUSE-2024-RT",
            "cve-5.3": "cve/linux-5.3-LTSS",
            "cve-5.14": "cve/linux-5.14-LTSS",
        }

        self.lp_name = lp_name
        self.lp_filter = lp_filter
        self.lp_skip = skips

    def format_patches(self, version):
        ver = f"v{version}"
        # index 1 will be the test file
        index = 2

        kgr_patches = get_user_path('kgr_patches_dir')
        if not kgr_patches:
            logging.warning("kgr_patches_dir not found, patches will be incomplete")

        # Remove dir to avoid leftover patches with different names
        patches_dir = utils.get_workdir(self.lp_name)/"patches"
        shutil.rmtree(patches_dir, ignore_errors=True)

        test_src = utils.get_tests_path(self.lp_name)
        subprocess.check_output(
            [
                "/usr/bin/git",
                "-C",
                str(get_user_path('kgr_patches_tests_dir')),
                "format-patch",
                "-1",
                f"{test_src}",
                "--cover-letter",
                "--start-number",
                "1",
                "--subject-prefix",
                f"PATCH {ver}",
                "--output-directory",
                f"{patches_dir}",
            ]
        )

        # Filter only the branches related to this BSC
        for branch in utils.get_lp_branches(self.lp_name, kgr_patches):
            print(branch)
            bname = branch.replace(self.lp_name + "_", "")
            bs = " ".join(bname.split("_"))
            bsc = self.lp_name.replace("bsc", "bsc#")

            prefix = f"PATCH {ver} {bsc} {bs}"

            subprocess.check_output(
                [
                    "/usr/bin/git",
                    "-C",
                    str(kgr_patches),
                    "format-patch",
                    "-1",
                    branch,
                    "--start-number",
                    f"{index}",
                    "--subject-prefix",
                    f"{prefix}",
                    "--output-directory",
                    f"{patches_dir}",
                ]
            )

            index += 1

    # Currently this function returns the date of the patch and it's subject
    @staticmethod
    def get_commit_data(commit, savedir=None):
        req = requests.get(
            f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={commit}", timeout=15)
        req.raise_for_status()

        # Save the upstream commit if requested
        if savedir:
            with open(Path(savedir, f"{commit}.patch"), "w") as f:
                f.write(req.text)

        # Search for Subject until a blank line, since commit messages can be
        # seen in multiple lines.
        msg = re.search(r"Subject: (.*?)(?:(\n\n))", req.text, re.DOTALL).group(1).replace("\n", "")
        # Sometimes the MIME-Version string comes right after the commit
        # message, so we should remove it as well
        if 'MIME-Version:' in msg:
            msg = re.sub(r"MIME-Version(.*)", "", msg)
        dstr = re.search(r"Date: ([\w\s,:]+)", req.text).group(1)
        d = datetime.strptime(dstr.strip(), "%a, %d %b %Y %H:%M:%S")

        return d, msg


    def get_patched_tags(self, suse_commits):
        tag_commits = {}
        patched = []
        total_commits = len(suse_commits)

        # Grab only the first commit, since they would be put together
        # in a release either way. The order of the array is backards, the
        # first entry will be the last patch found.
        for su in suse_commits:
            tag_commits[su] = []

            tags = subprocess.check_output(["/usr/bin/git", "-C", self.kern_src,
                                            "tag", f"--contains={su}",
                                            "rpm-*"])

            for tag in tags.decode().splitlines():
                # Remove noise around the kernel version, like
                # rpm-5.3.18-150200.24.112--sle15-sp2-ltss-updates
                if "--" in tag:
                    continue

                tag = tag.replace("rpm-", "")
                tag_commits.setdefault(tag, [])
                tag_commits[tag].append(su)

            # "patched branches" are those who contain all commits
            for tag, b in tag_commits.items():
                if len(b) == total_commits:
                    patched.append(tag)

        # remove duplicates
        return natsorted(list(set(patched)))

    def is_kernel_patched(self, kernel, suse_commits, cve):
        commits = []

        ret = subprocess.check_output(["/usr/bin/git", "-C", self.kern_src, "log",
                                       f"--grep=CVE-{cve}",
                                       f"--tags=*rpm-{kernel}",
                                       "--pretty=oneline"])

        for line in ret.decode().splitlines():
            # Skip the Update commits, that only change the References tag
            if "Update" in line and "patches.suse" in line:
                continue

            # Parse commit's hash
            commits.append(line.split()[0])

        # "patched kernels" are those which contain all commits.
        return len(suse_commits) == len(commits), commits

    def get_patched_kernels(self, codestreams, commits, cve):
        if not commits:
            return []

        if not self.kern_src:
            logging.info("kernel_src_dir not found, skip getting SUSE commits")
            return []

        if not cve:
            logging.info("No CVE informed, skipping the processing of getting the patched kernels.")
            return []

        print("Searching for already patched codestreams...")

        kernels = []

        for bc, _ in self.kernel_branches.items():
            suse_commits = commits[bc]["commits"]
            if not suse_commits:
                continue

            # Get all the kernels/tags containing the commits in the main SLE
            # branch. This information alone is not reliable enough to decide
            # if a kernel is patched.
            suse_tags = self.get_patched_tags(suse_commits)

            # Proceed to analyse each codestream's kernel
            for cs in codestreams:
                if bc+'u' not in cs.name():
                    continue

                kernel = cs.kernel
                patched, kern_commits = self.is_kernel_patched(kernel, suse_commits, cve)
                if not patched and kernel not in suse_tags:
                    continue

                print(f"\n{cs.name()} ({kernel}):")

                # If no patches/commits were found for this kernel, fallback to
                # the commits in the main SLE branch. In either case, we can
                # assume that this kernel is already patched.
                for c in kern_commits if patched else suse_commits:
                    print(f"{c}")

                kernels.append(kernel)

        print("")

        # remove duplicates
        return natsorted(list(set(kernels)))


    @staticmethod
    def cs_is_affected(cs, cve, commits):
        # We can only check if the cs is affected or not if the CVE was informed
        # (so we can get all commits related to that specific CVE). Otherwise we
        # consider all codestreams as affected.
        if not cve:
            return True

        return len(commits[cs.name_cs()]["commits"]) > 0


    @staticmethod
    def download_supported_file(data_path, lp_path):
        logging.info("Downloading codestreams file")
        cs_url = "https://gitlab.suse.de/live-patching/sle-live-patching-data/raw/master/supported.csv"
        suse_cert = Path("/etc/ssl/certs/SUSE_Trust_Root.pem")
        if suse_cert.exists():
            req = requests.get(cs_url, verify=suse_cert, timeout=15)
        else:
            req = requests.get(cs_url, timeout=15)

        # exit on error
        req.raise_for_status()

        first_line = True
        codestreams = []
        for line in req.iter_lines():
            # skip empty lines
            if not line:
                continue

            # skip file header
            if first_line:
                first_line = False
                continue

            # remove the last two columns, which are dates of the line
            # and add a fifth field with the forth one + rpm- prefix, and
            # remove the build counter number
            full_cs, proj, kernel_full, _, _ = line.decode("utf-8").strip().split(",")

            kernel = re.sub(r"\.\d+$", "", kernel_full)

            # MICRO releases contain project/patchid format
            if "/" in proj:
                proj, patchid = proj.split("/")
            else:
                patchid = ""

            codestreams.append(Codestream.from_codestream(data_path, lp_path, full_cs,
                                                          proj, patchid, kernel))

        return codestreams

