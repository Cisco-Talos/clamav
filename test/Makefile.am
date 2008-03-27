SPLIT_DIR=$(top_srcdir)/test/.split

all: clam-v2.rar clam-v3.rar clam.cab clam.exe.bz2 clam.exe clam.zip clam.arj clam.exe.szdd clam.tar.gz clam.exe.rtf

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

clam.arj:
	cat $(SPLIT_DIR)/split.clam.arjaa $(SPLIT_DIR)/split.clam.arjab > clam.arj

clam.exe.szdd:
	cat $(SPLIT_DIR)/split.clam.exe.szddaa $(SPLIT_DIR)/split.clam.exe.szddab > clam.exe.szdd

clam.tar.gz:
	cat $(SPLIT_DIR)/split.clam.tar.gzaa $(SPLIT_DIR)/split.clam.tar.gzab > clam.tar.gz

clean-local:
	rm -f clam-v2.rar clam-v3.rar clam.cab clam.exe.bz2 clam.exe clam.zip clam.arj clam.exe.szdd clam.tar.gz clam.exe.rtf

clam.exe.rtf:
	cat $(SPLIT_DIR)/split.clam.exe.rtfaa $(SPLIT_DIR)/split.clam.exe.rtfab > clam.exe.rtf

EXTRA_DIST = .split
