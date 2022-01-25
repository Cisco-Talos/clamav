all: comba_sqr_gen comba_sqr_smallgen

clean:
	rm -f comba_mult_gen
	rm -f comba_mult_gen.exe
	rm -f comba_mult_smallgen
	rm -f comba_mult_smallgen.exe
	rm -f comba_sqr_gen
	rm -f comba_sqr_gen.exe
	rm -f comba_sqr_smallgen
	rm -f comba_sqr_smallgen.exe

comba_mult_gen: comba_mult_gen.c
	gcc -o comba_mult_gen comba_mult_gen.c
comba_mult_smallgen: comba_mult_smallgen.c
	gcc -o comba_mult_smallgen comba_mult_smallgen.c
comba_sqr_gen: comba_sqr_gen.c
	gcc -o comba_sqr_gen comba_sqr_gen.c
comba_sqr_smallgen: comba_sqr_smallgen.c
	gcc -o comba_sqr_smallgen comba_sqr_smallgen.c

regen: comba_mult_gen comba_mult_smallgen comba_sqr_gen comba_sqr_smallgen
	for i in 3 4 6 7 8 9 12 17 20 24 28 32 48 64; do \
		./comba_mult_gen $$i | sed -e 's/ *$$//' > ../mul/fp_mul_comba_$$i.c; \
	done
	./comba_mult_smallgen > ../mul/fp_mul_comba_small_set.c
	for i in 3 4 6 7 8 9 12 17 20 24 28 32 48 64; do \
		./comba_sqr_gen $$i | sed -e 's/ *$$//' > ../sqr/fp_sqr_comba_$$i.c; \
	done
	./comba_sqr_smallgen > ../sqr/fp_sqr_comba_small_set.c

