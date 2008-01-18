all: clam-v2.rar clam-v3.rar clam.cab clam.exe.bz2 clam.exe clam.zip

clam-v2.rar:
	$(SED) 's/\(.\)\(.\)/\2\1/g' <.reversed/clam-v2.rar.reversed >clam-v2.rar

clam-v3.rar:
	$(SED) 's/\(.\)\(.\)/\2\1/g' <.reversed/clam-v3.rar.reversed >clam-v3.rar

clam.cab:
	$(SED) 's/\(.\)\(.\)/\2\1/g' <.reversed/clam.cab.reversed >clam.cab

clam.exe.bz2:
	$(SED) 's/\(.\)\(.\)/\2\1/g' <.reversed/clam.exe.bz2.reversed >clam.exe.bz2

clam.exe:
	$(SED) 's/\(.\)\(.\)/\2\1/g' <.reversed/clam.exe.reversed >clam.exe

clam.zip:
	$(SED) 's/\(.\)\(.\)/\2\1/g' <.reversed/clam.zip.reversed >clam.zip

clean:
	rm -f clam-v2.rar clam-v3.rar clam.cab clam.exe.bz2 clam.exe clam.zip

