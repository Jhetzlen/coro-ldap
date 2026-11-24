#!/usr/bin/env bash
# Puts the given badge files on the badges branch, leaving the other files
# there alone (ci.yml and windows.yml each publish their own), without
# force: a push rejected because the other workflow pushed first is retried
# on top of its commit.
#
#   .github/publish_badges.sh SRC_DIR FILE... [-- STALE_FILE...]
#
# Copies SRC_DIR/FILE for each FILE and removes each STALE_FILE. Needs
# GH_TOKEN and GITHUB_REPOSITORY (and GITHUB_SHA for the message);
# BADGES_REMOTE replaces the remote, for a local test.
set -euo pipefail

src=$(cd "$1" && pwd)
shift
files=()
stale=()
while (($#)); do
	if [[ $1 == -- ]]; then
		shift
		stale=("$@")
		break
	fi
	files+=("$1")
	shift
done

remote=${BADGES_REMOTE:-"https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"}
work=$(mktemp -d)
cd "$work"
git init -q
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

for attempt in 1 2 3 4 5; do
	if git fetch -q --depth 1 "$remote" badges 2>/dev/null; then
		git checkout -q -B badges FETCH_HEAD
	else
		# No badges branch yet: start it.
		git symbolic-ref HEAD refs/heads/badges
		git rm -rqf --cached . 2>/dev/null || true
	fi
	for f in "${files[@]}"; do
		cp -f "$src/$f" "$f"
		git add "$f"
	done
	for f in "${stale[@]}"; do
		git rm -q --ignore-unmatch "$f"
	done
	if git diff --cached --quiet; then
		echo "badges unchanged"
		exit 0
	fi
	git commit -q -m "badges: ${files[*]} for ${GITHUB_SHA:-unknown}"
	if git push -q "$remote" HEAD:refs/heads/badges; then
		echo "badges pushed (attempt $attempt)"
		exit 0
	fi
	echo "push rejected, retrying on the new badges branch"
	sleep $((attempt * 3))
done
echo "could not push the badges" >&2
exit 1
