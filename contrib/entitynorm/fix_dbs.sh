#!/bin/sh
export DBLOCATION=/usr/local/share/clamav
export OUTDIR=db_temp

mkdir -p /tmp/$OUTDIR
(
	cd /tmp/$OUTDIR
	sigtool --unpack $DBLOCATION/main.cvd 2>/tmp/$OUTDIR/errlog
	sigtool --unpack $DBLOCATIOn/daily.cvd 2>>/tmp/$OUTDIR/errlog
	cp $DBLOCATION/daily.inc/* . 2>>/tmp/$OUTDIR/errlog
	cp $DBLOCATION/main.inc/* . 2>>/tmp/$OUTDIR/errlog
)

./fixdb </tmp/$OUTDIR/main.ndb >/tmp/$OUTDIR/fixed_db 2>/tmp/$OUTDIR/errlog
./fixdb </tmp/$OUTDIR/daily.ndb >>/tmp/$OUTDIR/fixed_db 2>>/tmp/$OUTDIR/errlog
cat /tmp/$OUTDIR/fixed_db |./postprocessdb 1 > /tmp/$OUTDIR/fixed_db_p
cat /tmp/$OUTDIR/fixed_db_p|./postprocessdb nocolor >/tmp/$OUTDIR/fixed.ndb

echo /tmp/$OUTDIR/fixed.ndb "created"
