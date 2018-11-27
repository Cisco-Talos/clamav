FILES = clam.cab clam.exe clam.zip \
	clam.arj clam.exe.rtf clam.exe.szdd clam.tar.gz clam.chm clam.sis \
	clam-aspack.exe clam-pespin.exe clam-upx.exe clam-fsg.exe clam-mew.exe\
	clam-nsis.exe clam-petite.exe clam-upack.exe clam-wwpack.exe clam.pdf\
	clam.mail clam.ppt clam.tnef clam.ea05.exe clam.ea06.exe clam.d64.zip\
	clam.exe.mbox.base64 clam.exe.mbox.uu clam.exe.binhex clam.ole.doc \
	clam.impl.zip clam.exe.html clam.bin-be.cpio clam.bin-le.cpio \
	clam.newc.cpio clam.odc.cpio clam-yc.exe clam_IScab_int.exe \
	clam_IScab_ext.exe clam_ISmsi_int.exe clam_ISmsi_ext.exe clam.7z \
	clam_cache_emax.tgz clam.iso clamjol.iso

if ENABLE_UNRAR
FILES += clam-v2.rar clam-v3.rar
endif

if HAVE_LIBBZ2
FILES += clam.exe.bz2 clam.bz2.zip
endif

if HAVE_LIBXML2
#placeholder
endif

SPLIT_DIR=$(top_srcdir)/test/.split

all: $(FILES)

$(FILES) :
	cat $(SPLIT_DIR)/split.$@a* > $@

clean-local:
	rm -f clam*

EXTRA_DIST = .split

check: all
