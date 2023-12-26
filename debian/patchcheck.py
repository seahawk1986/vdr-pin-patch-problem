#!/usr/bin/python3

import re
import hashlib
import os
import subprocess
from textwrap import TextWrapper
from optparse import OptionParser

PATCHES_FILE = "debian/.vdr-patches"
PATCH_INFO_FILE = "debian/patchinfo"


def collect_patch_info():
    patchInfo = []
    for patch in subprocess.check_output(["quilt", "series"], universal_newlines=True).splitlines():
        with open(f"debian/patches/{patch}", "rb") as p:
            md5 = hashlib.md5(p.read()).hexdigest()
        header = subprocess.check_output(["quilt", "header", patch], universal_newlines=True)
        author = description = None
        match = re.search("^Author: (.*)", header, re.MULTILINE)
        if match:
            author = match.group(1)
        match = re.search("^Description: ((.*?)\n( .*?\n)*)", header, re.DOTALL)
        if match:
            description = re.sub(r"^ \.?", "", match.group(1), 0, re.MULTILINE)
            description = re.sub(r"^([^.].*)\n", r"\1 ", description, 0, re.MULTILINE)
        if author and description:
            patchInfo.append((patch, md5, author, description))
        else:
            print(f"Incomplete patch header in {patch}")
            exit(1)
    return patchInfo


def get_last_patches():
    lastPatches = []
    for line in open(PATCHES_FILE, "r"):
        match = re.match("(.+):(.+)", line.rstrip())
        if match:
            lastPatches.append((match.group(1), match.group(2)))
    return lastPatches


def generate_patchlist(patchInfo):
    with open(PATCHES_FILE, "w") as patchListFile:
        for (fileName, md5, author, description) in patchInfo:
            print(f"{fileName}:{md5}", file=patchListFile)


def generate_patchinfo(patchInfo):
    with open(PATCH_INFO_FILE, 'w') as patchInfoFile:
        msg = "Patches applied to vanilla vdr sources"
        print(msg, file=patchInfoFile)
        print("-" * len(msg), '\n', file=patchInfoFile)
        for (fileName, md5, author, description) in patchInfo:
            print(fileName, file=patchInfoFile)
            print(f"    {author}\n", file=patchInfoFile)
            wrapper = TextWrapper(
                initial_indent="    ",
                subsequent_indent="    ",
                break_on_hyphens=False,
                width=80,
            )
            for paragraph in description.splitlines():
                print(wrapper.fill(paragraph), file=patchInfoFile)
                print("", file=patchInfoFile)


def report_patches(patches, reportText):
    if len(patches) > 0:
        print(reportText)
        for p in patches:
            print(f"    {p}")
        print()


def check_patches():
    current_patches = [(p[0], p[1]) for p in collect_patch_info()]
    last_patches = get_last_patches()

    new_patches = set(p[0] for p in current_patches) - set(p[0] for p in last_patches)
    removed_patches = set(p[0] for p in last_patches) - set(
        p[0] for p in current_patches
    )
    changed_patches = set(
        p[0] for p in (set(last_patches) - set(current_patches))
    ) - set(removed_patches)

    report_patches(new_patches, "The following patches are new:")
    report_patches(removed_patches, "The following patches have been disabled:")
    report_patches(changed_patches, "The following patches have been modified:")

    if len(new_patches) + len(removed_patches) + len(changed_patches) > 0:
        commandLine = "debian/rules accept-patches"
        abiVersion = "abi-version"
        print("Please check, if any of the above changes affects VDR's ABI!")
        print(f"If this is the case, then update {abiVersion} and run")
        print(f"'{commandLine}' to update the snapshot of")
        print("the current patch level.")
        exit(1)


if __name__ == "__main__":
    parser = OptionParser()

    parser.add_option(
        "-u",
        "--update",
        action="store_true",
        dest="doUpdate",
        help="updated the list of accepted patches",
    )
    parser.add_option(
        "-c", "--check", action="store_true", dest="doCheck", help="check patches"
    )

    (options, args) = parser.parse_args()

    if options.doCheck:
        check_patches()
    elif options.doUpdate:
        patchInfo = collect_patch_info()
        generate_patchlist(patchInfo)
        generate_patchinfo(patchInfo)
    else:
        parser.print_help()
