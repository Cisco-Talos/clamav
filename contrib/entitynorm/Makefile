PERL=perl
CC=cc

all: entitylist.h encoding_aliases.h gentbl encname_chars.h generate_hash

entities_parsed: entities entities/* entity_decl_parse.pl
	$(PERL) entity_decl_parse.pl $</* | sort -u >$@

generate_entitylist: generate_entitylist.c ../../libclamav/hashtab.h ../../libclamav/hashtab.c ../../libclamav/others.c
	$(CC) -I. -DHAVE_CONFIG_H -DCLI_MEMFUNSONLY -DPROFILE_HASHTABLE $< ../../libclamav/hashtab.c ../../libclamav/others.c -o $@

generate_hash: generate_hash.c ../../libclamav/hashtab.h ../../libclamav/hashtab.c ../../libclamav/others.c
	$(CC) -I. -DHAVE_CONFIG_H -DCLI_MEMFUNSONLY -DPROFILE_HASHTABLE $< ../../libclamav/hashtab.c ../../libclamav/others.c -o $@

generate_encoding_aliases: generate_encoding_aliases.c ../../libclamav/hashtab.c ../../libclamav/others.c ../../libclamav/htmlnorm.h ../../libclamav/entconv.h ../../libclamav/cltypes.h ../../libclamav/hashtab.h ../../libclamav/hashtab.h
	$(CC) -I. -DHAVE_CONFIG_H -DCLI_MEMFUNSONLY -DPROFILE_HASHTABLE $< ../../libclamav/hashtab.c ../../libclamav/others.c -o $@

entitylist.h: generate_entitylist entities_parsed
	./$< <entities_parsed >$@

encoding_aliases.h: generate_encoding_aliases
	./$< >$@

gentbl: gentbl.c
	$(CC) $< -o $@
encname_chars.h: gentbl
	./gentbl encname_chars 0-9 a-z A-Z _ . / \( \) - : >$@

clean: 
	rm -f entitylist.h encoding_aliases.h entities_parsed generate_entitylist generate_encoding_aliases gentbl encname_chars.h
