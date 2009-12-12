#!/bin/sh
find . -name *.vcproj -exec sed -i 's/C:\\Users\\edwin\\Documents\\clam\\clamav-devel/$(SolutionDir)../g' {} \;
find . -name *.vcproj -exec sed -i 's/C:\/Users\/edwin\/Documents\/clam\/clamav-devel/$(SolutionDir)../g' {} \;
