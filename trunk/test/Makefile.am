FILES = clam-v2.rar clam-v3.rar clam.cab clam.exe.bz2 clam.exe clam.zip \
	clam.arj clam.exe.rtf clam.exe.szdd clam.tar.gz clam.chm clam.sis \
	clam-aspack.exe clam-pespin.exe clam-upx.exe clam-fsg.exe clam-mew.exe\
	clam-nsis.exe clam-petite.exe clam-upack.exe clam-wwpack.exe clam.pdf\
	clam.mail clam.ppt clam.tnef clam.ea05.exe clam.ea06.exe clam.d64.zip\
	clam.exe.mbox.base64 clam.exe.mbox.uu clam.exe.binhex clam.ole.doc \
	clam.impl.zip clam.exe.html clam.bz2.zip

SPLIT_DIR=$(top_srcdir)/test/.split

all: $(FILES)

$(FILES) :
	cat $(SPLIT_DIR)/split.$@aa $(SPLIT_DIR)/split.$@ab > $@

clean-local:
	rm -f $(FILES)

EXTRA_DIST = .split
