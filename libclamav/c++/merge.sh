#!/bin/sh
# Merge upstream LLVM from git-svn mirror
set -e
rm -f .git/info/grafts
touch .git/info/grafts
echo "Creating grafts for llvm-upstream"

REPONAME=llvm
REFPFX=refs/tags/merge-$REPONAME-
UPSTREAM=$REPONAME-upstream/release
git for-each-ref $REFPFX*  --format='%(refname)' | while read tag_ref
do
	tag_svn_ref=`echo $tag_ref|sed -e s\|$REFPFX\|\|`
	upstream_ref=`git log $UPSTREAM -1 --grep=trunk@$tag_svn_ref --format=format:%H`
	local_ref=`git rev-parse $tag_ref`
	local_parent_ref=`git rev-parse $tag_ref^`
	git branch --contains $local_ref | grep '*' >/dev/null ||
	{ echo "branch has been rebased, tag is on branch: `git branch --contains $local_ref`"; exit 1;}
	echo "$local_ref $local_parent_ref $upstream_ref" >>.git/info/grafts
done
echo "Merging llvm-upstream"
MERGEREV=`git log $UPSTREAM -1 |grep /release_27@|sed -s 's/.*@\([0-9]*\).*/\1/'`
echo "$MERGEREV"
git merge -s subtree --squash llvm-upstream/release

echo "Run strip-llvm.sh from libclamav/c++"
echo "Then fix conflicts if needed: git mergetool"
echo "Then commit the result and tag it: git commit && git tag merge-llvm-$MERGEREV"
echo "Then remove the grafts: rm .git/info/grafts"
# && git commit || {
# echo "Merge failed: resolve conflicts and run: git tag merge-llvm-$MERGEREV && rm .git/info/grafts"; exit 1;}
# git tag merge-llvm-$MERGEREV
# rm .git/info/grafts
