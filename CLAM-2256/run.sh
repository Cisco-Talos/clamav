#!/bin/bash

rm -rf outDir

#cargo run alz_example.alz outDir
#cargo run test outDir
#cargo run

#extracts 1 jpg, mine works the same as unalz
#cargo run samples/19d17e940e603b7fec36f147b3f8ae482cac429fdcc762f61186d4c00adce8db outDir

#cargo run samples/0abac736fb1b1dbd66901ec5258c73c543dd6b01e8d4c06970f94ff697ae1745   outDir

#cargo run samples/e81e2bb0fa7c00c849465e10329c01f5b40ef66c48a5fa12bee24279411aa297 outDir


#FILE=5d21b3f56ed5e349631024ac08006622fa989cfb7bec4ad13c946d331bbffe47 corrupted
#FILE=7b1f0ecdbf1d10e6ee78510901f418c9ec7787b4caf13ac87b5da542d9a26383 corrupted
#FILE=b6461509e990d556579688a758d4018919b0087435f9147a48ef813c865e0b3d corrupted
#FILE=b47d5aa5a024f841b77f20d0d2d8410d1b411aaddd54624e94667e610c1ceabe corrupted
#FILE=e8cedbeec4eb5a9715c514da5c5ceeec375239220750cdff99e4f87e49c7c8ad corrupted
#FILE=7bbf9dafd68b5b5106b5996eaac419228d72b4872707fc2a611a468319bef509 corrupted
#FILE=72a0718760f744a67853f3ee7f5740a34db124e24f787fc61efdeb538fa30376 corrupted
#FILE=ecca4711802697a96528c8bade5158cca011b1759988aad1e44b10fb9889f8aa corrupted
#FILE=8bb3fc1d6a5e703b2a5037ea3a168b45a8b641bcfd337d3bf67152ec353affb6 corrupted
#FILE=e617b015136b23dcd3eb299ca4114b3e19a3b4ee9c4220f5dc7dd529165a45ab corrupted
#FILE=f0fb18a36848e4c12414c101a3505c4f2a74e0b476f770c5a36a47742629c379 corrupted
#FILE=fe6106acdfcc2fd821814801d8f850cfdd08d901216b52463bd7d6e2ca6fc6d8 corrupted
#FILE=f9a5b18c7d15efe4d3db5a0b5259edbaa8917fc36cec99a7571d5192aa6cff1f  corrupted
#FILE=58ac36b24ecdbe6726ce2bda0b308b0273f61e8bad858339409046f93d7478df corrupted
#FILE=8cbb8f7ae044db16671003c6c3bbf063b43dc8520f503e66c49360269b4e154b corrupted
#FILE=6c3e1563ce4235720c73de8297cd3aa84959c28b9c8040ac227154920183aeb4 corrupted
#FILE=86b5e5c78a8de95510cd2fbc4dddf66e824a82412bdfb1d67ca504a51d8f1eac corrupted
#FILE=7fc7b135ed44a3f201cfac31945bf7c3007464634b5b8b464c13d87ca6f7bbea corrupted

#cargo run samples/$FILE outDir

FILE=unit_tests/deflate.alz
FILE=unit_tests/uncompressed.alz

rm -rf outDir unalz

cargo run $FILE outDir

unalz -d unalz $FILE






