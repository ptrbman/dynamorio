#!/bin/sh

# **********************************************************
# Copyright (c) 2014 Google, Inc.    All rights reserved.
# **********************************************************

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of Google, Inc. nor the names of its contributors may be
#   used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

# Usage: git review (-u|-c) [-q] [-r <reviewer>] [-s <subject>]
# One of -u (upload new patchset) or -c (finalize committed review) must be
# supplied.
# Optional arguments:
#  -q = quiet, don't auto-send email
#  -r <reviewer> = specify reviewer email (else it will be queried for)
#  -s <subject> = specify patchset title (else queried, or log's first line
#                 for 1st patchset)
#  -t = prepends "TBR" to the review title

# Send email by default
email="--send_mail --cc=dynamorio-devs@googlegroups.com"
hashurl="https://github.com/DynamoRIO/dynamorio/commit/"

while getopts ":ucqtr:s:" opt; do
  case $opt in
    u)
      mode="upload"
      ;;
    c)
      mode="commit"
      ;;
    r)
      reviewer="-r $OPTARG"
      ;;
    s)
      subject="$OPTARG"
      ;;
    q)
      email=""
      ;;
    t)
      prefix="TBR: "
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

if ! git diff-index --quiet HEAD --; then
    echo "ERROR: branch contains uncommitted changes.  Please commit them first."
    exit 1
fi

branch=$(git symbolic-ref -q HEAD)
branch=${branch##*/}
issue=$(git config branch.${branch}.rietveldissue)
root=$(git rev-parse --show-toplevel)
user=$(git config user.email)
log=$(git log -n 1 --format=%B)
if [ "$mode" = "upload" ]; then
    commits=$(git rev-list --count origin/master..)
    if [ "$commits" -ne "1" ]; then
        echo "ERROR: only a single commit on top of origin/master is supported."
        echo "Either squash commits in this branch or use multiple branches."
        exit 1
    fi
    if test -z "$issue"; then
        # New CL
        echo "Creating a new code review request."
        label="first patchset";
        if test -z "$subject"; then
            subject=$(git log -n 1 --format=%s)
        fi
        subject="${prefix}${subject}"
        while test -z "$reviewer"; do
            echo -n "Enter the email of the reviewer: "
            read reviewer
            reviewer="-r $reviewer"
        done
    else
        echo "Updating existing code review request #${issue}."
        # New patchset on existing CL
        while test -z "$subject"; do
            echo -n "Enter the label for the patchset: "
            read subject
        done
        label="latest patchset";
        issue="-i $issue"
    fi
    msg=$(echo -e "Commit log for ${label}:\n---------------\n${log}\n---------------")
    echo "Uploading the review..."
    output=$(python ${root}/make/upload.py -y -e "${user}" ${reviewer} ${issue} \
        -t "${subject}" -m "${msg}" ${email} origin/master..)
    echo "${output}"
    if test -z "$issue"; then
        number=$(echo "$output" | grep http://)
        number=${number##*/}
        if test -z "$number"; then
            echo "ERROR: failed to record Rietveld issue number."
            exit 1
        else
            git config branch.${branch}.rietveldissue ${number}
            # Add the Review-URL line
            git commit --amend -m "$log" \
                -m "Review-URL: https://codereview.appspot.com/${number}"
        fi
    fi
elif [ "$mode" = "commit" ]; then
    if test -n "$issue"; then
        # Remove the issue marker
        git config --unset branch.${branch}.rietveldissue
        # Upload the committed diff, for easy viewing of final changes.
        echo "Finalizing existing code review request #${issue}."
        subject="Committed"
        hash=$(git log -n 1 --format=%H)
        msg=$(echo -e "Committed as ${hashurl}${hash}\n\nFinal commit log:" \
            "\n---------------\n${log}\n---------------")
        output=$(python ${root}/make/upload.py -y -e "${user}" -i ${issue} \
            -t "${subject}" -m "${msg}" ${email} HEAD^)
        echo "${output}"
    else
        echo "WARNING: this branch is not associated with any review."
        # Keep exit status 0
    fi
else
    echo "Invalid mode"
    exit 1
fi
