#!/bin/sh

if [ "$VERSION" = "" ]; then
    echo "Including build-environ.cfg"
    . `dirname $0`/build-environ.cfg
fi 

# first, grab the latest revision with specified tag
if [ ! -d $WX_TEMP_DIR ]; then
  mkdir $WX_TEMP_DIR
fi 

# just do an update if we started a build but it failed somewhere
if [ ! -d $WX_WEB_DIR ]; then  
  cd $WX_TEMP_DIR
  echo "Grabbing wxWebSite sources..."
  svn co https://svn.wxwidgets.org/svn/wxWebSite/trunk wxWebSite
else
    cd $WX_WEB_DIR
    svn cleanup
    svn up
fi

if [ ! -d $WX_SRC_DIR ]; then
  cd $WX_TEMP_DIR
  echo "Grabbing wx CVS with tag $BUILD_TAG"
  svn co https://svn.wxwidgets.org/svn/wx/wxWidgets/trunk/ wxWidgets
  cd $WX_SRC_DIR
else
  cd $WX_SRC_DIR
  svn cleanup
  svn up
fi

# this is where we will store the wxAll tarball we create
if [ ! -d $DIST_DIR ]; then
  mkdir -p $DIST_DIR
fi
echo saving to $DIST_DIR

#re-bake the bakefiles
if [ $rebake = "yes" ]; then
  if [ ! -d $WX_SRC_DIR/build/bakefiles ]; then
     mkdir $WX_SRC_DIR/build/bakefiles
  fi
  
  cd $WX_SRC_DIR/build/bakefiles
  # always rebuild the bakefiles to avoid conflicts with cvs
  ## better to not use unix2dos on the wxWidgets tree so we don't get the conflicts
  ##fix this -B gave an option not recognised  error (sf bug 1537221)...
  rm .ba*
  bakefile_gen -d ../../distrib/scripts/Bakefiles.release.bkgen
fi

# Now generate the mega tarball with everything. We will push this to our build machines.
cd $WX_TEMP_DIR
export APPDIR=$WX_TEMP_DIR/wxWidgets
export WXWIN=$WX_TEMP_DIR/wxWidgets
export VERSION=$BUILD_VERSION
export SCRIPTDIR=${SCRIPTDIR}
export DIST_DIR=${DIST_DIR}

#remove old files
rm -rf $APPDIR/deliver/*
rm -rf $DIST_DIR/*

tar czf $DIST_DIR/wxWidgets-snapshot-$BUILD_VERSION.tar.gz $WX_TEMP_DIR

cp $SCRIPTDIR/create_archives.sh $APPDIR/distrib/scripts
chmod +x $APPDIR/distrib/scripts/create_archives.sh
$APPDIR/distrib/scripts/create_archives.sh --wxall --wxmsw

echo "Tarballs located at: $DIST_DIR"

if [ ! -f $WX_TARBALL ]; then
  echo "ERROR: wxAll tarball was not created by pre-flight.sh. Build cannot continue."
  exit 1
else
  cd $DIST_DIR
  #cp $WX_TARBALL $STAGING_DIR
  #cp -r $WX_WEB_DIR $STAGING_DIR
  
  echo "Pre-flight complete. Ready for takeoff."
fi

if [ "$KIND" = "daily" ]; then
   ##delete old files and then copy new ones, add a symlink
   find ${FTPDIR}/files -type f -name wx\* -mtime +6 | xargs rm -rf
   cp  $DIST_DIR/wx* ${FTPDIR}/files

   rm -f ${FTPDIR}/wx* ${FTPDIR}/MD5SUM
   for f in `find ${FTPDIR}/files -type f -name wx\* -mmin -601` ; do
      ln -s $f `echo $f | sed -e "s/-${CURDATE}//" | sed -e "s|/files||" `
   done
else
   ## not a daily build
   ##get install.txt files etc
   ##.../docs/plat/install.txt goes to install-plat-2.7.0.txt
   ## wince has a file down one dir
   cp ${DOCDIR}/changes.txt $DIST_DIR/changes-${BUILD_VERSION}.txt

   for f in `find ${DOCDIR} -name install.txt` ; do
     cp $f $DIST_DIR/install-`echo $f | sed -e "s|${DOCDIR}||g" | sed -e "s|/install.txt||g"`-${BUILD_VERSION}.txt
   done

   for g in `find ${DOCDIR} -name readme.txt` ; do
     cp $g $DIST_DIR/readme-`echo $g | sed -e "s|${DOCDIR}||g" | sed -e "s|msw/wince|wince|g" | sed -e "s|/readme.txt||g"`-${BUILD_VERSION}.txt
   done
   # Rename double readme
   mv $DIST_DIR/readme-readme.txt-${BUILD_VERSION}.txt $DIST_DIR/readme-${BUILD_VERSION}.txt
   ## copy files ...
   mkdir ${FTPDIR}/
   cp  $DIST_DIR/* ${FTPDIR}/

fi

md5sum ${FTPDIR}/wx* > ${FTPDIR}/MD5SUM

## make sure updated at is really last
sleep 10
echo svn checkout done at  `date -u` > ${FTPDIR}/updated_at.txt
       
echo "Delivery complete. Flying."
