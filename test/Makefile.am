FILES = clam-v2.rar clam-v3.rar clam.cab clam.exe.bz2 clam.exe clam.zip \
	clam.arj clam.exe.rtf clam.exe.szdd clam.tar.gz clam.chm clam.sis \
	clam-aspack.exe clam-pespin.exe clam-upx.exe clam-fsg.exe

SPLIT_DIR=$(top_srcdir)/test/.split

all: $(FILES)

% : $(SPLIT_DIR)/split.%aa $(SPLIT_DIR)/split.%ab
	cat $(SPLIT_DIR)/split.$*aa $(SPLIT_DIR)/split.$*ab > $*

clean-local:
	rm -f $(FILES)

EXTRA_DIST = .split
