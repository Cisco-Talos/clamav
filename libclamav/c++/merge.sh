#!/bin/sh
# Merge upstream LLVM from git-svn mirror
set -e
rm -f .git/info/grafts
touch .git/info/grafts
echo "Creating grafts for llvm-upstream"

REPONAME=llvm
REFPFX=refs/tags/merge-$REPONAME-
UPSTREAM=$REPONAME-upstream/master
git for-each-ref $REFPFX*  --format='%(refname)' | while read tag_ref
do
	tag_svn_ref=`echo $tag_ref|sed -e s\|$REFPFX\|\|`
	upstream_ref=`git log $UPSTREAM -1 --grep=trunk@$tag_svn_ref --format=format:%H`
	local_ref=`git rev-parse $tag_ref`
	local_ref=`git rev-parse $tag_ref`
	local_parent_ref=`git rev-parse $tag_ref^`
	echo "$local_ref $local_parent_ref $upstream_ref" >>.git/info/grafts
done
echo "Merging llvm-upstream"
MERGEREV=`git log $UPSTREAM -1 |grep /trunk@|sed -s 's/.*@\([0-9]*\).*/\1/'`
git merge -s subtree --squash llvm-upstream/master && git commit || {
echo "Merge failed: resolve conflicts and run: git tag merge-llvm-$MERGEREV && rm .git/info/grafts"; exit 1;}
git tag merge-llvm-$MERGEREV
rm .git/info/grafts
