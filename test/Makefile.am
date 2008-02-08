SPLIT_DIR=$(top_srcdir)/test/.split

all: clam-v2.rar clam-v3.rar clam.cab clam.exe.bz2 clam.exe clam.zip

clam-v2.rar:
	cat $(SPLIT_DIR)/split.clam-v2.raraa $(SPLIT_DIR)/split.clam-v2.rarab >clam-v2.rar

clam-v3.rar:
	cat $(SPLIT_DIR)/split.clam-v3.raraa $(SPLIT_DIR)/split.clam-v3.rarab >clam-v3.rar

clam.cab:
	cat $(SPLIT_DIR)/split.clam.cabaa $(SPLIT_DIR)/split.clam.cabab >clam.cab

clam.exe.bz2:
	cat $(SPLIT_DIR)/split.clam.exe.bz2aa $(SPLIT_DIR)/split.clam.exe.bz2ab >clam.exe.bz2

clam.exe:
	cat $(SPLIT_DIR)/split.clam.exeaa $(SPLIT_DIR)/split.clam.exeab >clam.exe

clam.zip:
	cat $(SPLIT_DIR)/split.clam.zipaa $(SPLIT_DIR)/split.clam.zipab >clam.zip

clean-local:
	rm -f clam-v2.rar clam-v3.rar clam.cab clam.exe.bz2 clam.exe clam.zip

EXTRA_DIST = .split
