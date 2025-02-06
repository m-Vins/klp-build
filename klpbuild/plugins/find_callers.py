# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com

import logging
import subprocess
import os

from klpbuild.klplib.supported import get_supported_codestreams
from klpbuild.klplib.utils import classify_codestreams

from klpbuild.plugins.scan import scan

PLUGIN_CMD = "find-callers"

def register_argparser(subparser):
    scan = subparser.add_parser(PLUGIN_CMD)
    scan.add_argument(
        "--function",
        required=True,
        help="the function"
    )
    scan.add_argument(
        "--cve",
        required=False,
        help="SLE specific. Shows which codestreams are vulnerable to the CVE"
    )

def run(function, cve):
    first = True
    last_callers = callers = set()
    codestream_group = []
    callers_info = {}

    if cve:
        # Use only the affected codestream
        working_cs = scan(cve, None, None, None)[3]
    else:
        working_cs = get_supported_codestreams()

    for codestream in working_cs:
        kernel_dir = codestream.get_src_dir()
        logging.debug("Finding callers of function %s in codestream %s", function, codestream.name())
        try:

            __generate_cscope_db(kernel_dir)
            callers_info = __run_cscope(function, kernel_dir)
            callers = set(callers_info.keys())

            if not first and callers != last_callers:
                codestream_group.append(codestream)
                __print_group(callers_info, codestream_group)
                codestream_group = []
            else:
                codestream_group.append(codestream)

            last_callers = callers

        finally:
            __clean_cscope_db(kernel_dir)

    if callers and codestream_group:
        __print_group(callers_info, codestream_group)


def __print_group(callers, codestream_group):
    print("Codestream group", ", ".join(classify_codestreams(codestream_group)), "callers:")
    print()
    if callers:
        for caller, file in callers.items():
            print("- ", caller, file)
    else:
        print("None found")
    print()

def __generate_cscope_db(kernel_dir):
    logging.debug("Generating cscope database...")
    subprocess.run(["make", "cscope"], cwd=kernel_dir, check=True, stdout=subprocess.PIPE)


def __run_cscope(function, kernel_dir):
    result = subprocess.run(["cscope", "-L3", function], cwd=kernel_dir,
                            check=True, stdout=subprocess.PIPE,)
    output =  result.stdout.decode()
    split_lines = [line.split(" ") for line in output.splitlines()]

    return {line[1]: line[0] for line in split_lines}


def __clean_cscope_db(kernel_dir):
    logging.debug("Deleting cscope database...")
    subprocess.run(["find", ".", "-name", "cscope.*", "-delete"], cwd=kernel_dir, check=True)
