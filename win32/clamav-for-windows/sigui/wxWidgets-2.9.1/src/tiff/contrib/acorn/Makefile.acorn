# Project:   LibTIFF


# Toolflags:
CCflags = -c -zo -ffah -depend !Depend -IC:
C++flags = -c -depend !Depend -IC: -throwback
Linkflags = -aif -c++ -o $@
DrLinkflags = -nounused -aif -c++ -o $@
ObjAsmflags = -throwback -NoCache -depend !Depend
CMHGflags = 
LibFileflags = -c -o $@
Squeezeflags = -o $@


# Final targets:
@.o.LIBTIFF:   \
        @.o.tif_acorn \
        @.o.tif_aux \
        @.o.tif_close \
        @.o.tif_codec \
	@.o.tif_compress \
	@.o.tif_dir \
	@.o.tif_dirinfo \
	@.o.tif_dirread \
	@.o.tif_dirwrite \
	@.o.tif_dumpmode \
	@.o.tif_error \
	@.o.tif_fax3 \
	@.o.tif_flush \
	@.o.tif_getimage \
	@.o.tif_jpeg \
	@.o.tif_lzw \
	@.o.tif_next \
	@.o.tif_open \
	@.o.tif_packbits \
	@.o.tif_predict \
	@.o.tif_print \
	@.o.tif_read \
	@.o.tif_strip \
	@.o.tif_swab \
	@.o.tif_thunder \
	@.o.tif_tile \
	@.o.tif_version \
	@.o.tif_warning \
	@.o.tif_write \
	@.o.tif_zip \
	@.o.tif_fax3sm \
	@.h.version 
	LibFile $(LibFileflags) \
	@.o.tif_acorn \
	@.o.tif_aux \
	@.o.tif_close \
	@.o.tif_codec \
	@.o.tif_compress \
	@.o.tif_dir \
	@.o.tif_dirinfo \
	@.o.tif_dirread \
	@.o.tif_dirwrite \
	@.o.tif_dumpmode \
	@.o.tif_error \
	@.o.tif_fax3 \
	@.o.tif_flush \
	@.o.tif_getimage \
	@.o.tif_jpeg \
	@.o.tif_lzw \
	@.o.tif_next \
	@.o.tif_open \
	@.o.tif_packbits \
	@.o.tif_predict \
	@.o.tif_print \
	@.o.tif_read \
	@.o.tif_strip \
	@.o.tif_swab \
	@.o.tif_thunder \
	@.o.tif_tile \
	@.o.tif_version \
	@.o.tif_warning \
	@.o.tif_write \
	@.o.tif_zip \
	@.o.tif_fax3sm 


# User-editable dependencies:
@.mkversion:   @.o.mkversion C:o.Stubs 
	Link $(linkflags) @.o.mkversion C:o.Stubs 
@.h.version:   @.VERSION @.mkversion 
	<Prefix$Dir>.mkversion -v @.VERSION -a @.tiff/alpha @.h.version 
@.mkg3states:   @.o.mkg3states @.o.getopt C:o.Stubs 
	link $(linkflags) @.o.mkg3states C:o.Stubs @.o.getopt 
@.c.tif_fax3sm:   @.mkg3states 
	<Prefix$Dir>.mkg3states -c const @.c.tif_fax3sm 

# Static dependencies:
@.o.tif_acorn:   @.c.tif_acorn
	cc $(ccflags) -o @.o.tif_acorn @.c.tif_acorn 
@.o.tif_aux:   @.c.tif_aux
	cc $(ccflags) -o @.o.tif_aux @.c.tif_aux 
@.o.tif_close:   @.c.tif_close
	cc $(ccflags) -o @.o.tif_close @.c.tif_close 
@.o.tif_codec:   @.c.tif_codec
	cc $(ccflags) -o @.o.tif_codec @.c.tif_codec 
@.o.tif_compress:   @.c.tif_compress
	cc $(ccflags) -o @.o.tif_compress @.c.tif_compress 
@.o.tif_dir:   @.c.tif_dir
	cc $(ccflags) -o @.o.tif_dir @.c.tif_dir 
@.o.tif_dirinfo:   @.c.tif_dirinfo
	cc $(ccflags) -o @.o.tif_dirinfo @.c.tif_dirinfo 
@.o.tif_dirread:   @.c.tif_dirread
	cc $(ccflags) -o @.o.tif_dirread @.c.tif_dirread 
@.o.tif_dirwrite:   @.c.tif_dirwrite
	cc $(ccflags) -o @.o.tif_dirwrite @.c.tif_dirwrite 
@.o.tif_dumpmode:   @.c.tif_dumpmode
	cc $(ccflags) -o @.o.tif_dumpmode @.c.tif_dumpmode 
@.o.tif_error:   @.c.tif_error
	cc $(ccflags) -o @.o.tif_error @.c.tif_error 
@.o.tif_fax3:   @.c.tif_fax3
	cc $(ccflags) -o @.o.tif_fax3 @.c.tif_fax3 
@.o.tif_flush:   @.c.tif_flush
	cc $(ccflags) -o @.o.tif_flush @.c.tif_flush 
@.o.tif_getimage:   @.c.tif_getimage
	cc $(ccflags) -o @.o.tif_getimage @.c.tif_getimage 
@.o.tif_jpeg:   @.c.tif_jpeg
	cc $(ccflags) -o @.o.tif_jpeg @.c.tif_jpeg 
@.o.tif_lzw:   @.c.tif_lzw
	cc $(ccflags) -o @.o.tif_lzw @.c.tif_lzw 
@.o.tif_next:   @.c.tif_next
	cc $(ccflags) -o @.o.tif_next @.c.tif_next 
@.o.tif_open:   @.c.tif_open
	cc $(ccflags) -o @.o.tif_open @.c.tif_open 
@.o.tif_packbits:   @.c.tif_packbits
	cc $(ccflags) -o @.o.tif_packbits @.c.tif_packbits 
@.o.tif_predict:   @.c.tif_predict
	cc $(ccflags) -o @.o.tif_predict @.c.tif_predict 
@.o.tif_print:   @.c.tif_print
	cc $(ccflags) -o @.o.tif_print @.c.tif_print 
@.o.tif_read:   @.c.tif_read
	cc $(ccflags) -o @.o.tif_read @.c.tif_read 
@.o.tif_strip:   @.c.tif_strip
	cc $(ccflags) -o @.o.tif_strip @.c.tif_strip 
@.o.tif_swab:   @.c.tif_swab
	cc $(ccflags) -o @.o.tif_swab @.c.tif_swab 
@.o.tif_thunder:   @.c.tif_thunder
	cc $(ccflags) -o @.o.tif_thunder @.c.tif_thunder 
@.o.tif_tile:   @.c.tif_tile
	cc $(ccflags) -o @.o.tif_tile @.c.tif_tile 
@.o.tif_version:   @.c.tif_version
	cc $(ccflags) -o @.o.tif_version @.c.tif_version 
@.o.tif_warning:   @.c.tif_warning
	cc $(ccflags) -o @.o.tif_warning @.c.tif_warning 
@.o.tif_write:   @.c.tif_write
	cc $(ccflags) -o @.o.tif_write @.c.tif_write 
@.o.tif_zip:   @.c.tif_zip
	cc $(ccflags) -o @.o.tif_zip @.c.tif_zip 
@.o.mkg3states:   @.c.mkg3states
	cc $(ccflags) -o @.o.mkg3states @.c.mkg3states 
@.o.getopt:   @.c.getopt
	cc $(ccflags) -o @.o.getopt @.c.getopt 
@.o.mkspans:   @.c.mkspans
	cc $(ccflags) -o @.o.mkspans @.c.mkspans 
@.o.tif_fax3sm:   @.c.tif_fax3sm
	cc $(ccflags) -o @.o.tif_fax3sm @.c.tif_fax3sm 
@.o.mkversion:   @.c.mkversion
	cc $(ccflags) -o @.o.mkversion @.c.mkversion 

# Dynamic dependencies:
