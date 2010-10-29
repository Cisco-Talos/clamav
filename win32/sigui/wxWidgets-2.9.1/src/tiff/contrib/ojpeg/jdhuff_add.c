/*
 * BEWARE OF KLUDGE:  This subroutine is a hack for decoding illegal JPEG-in-
 *                    TIFF encapsulations produced by Microsoft's Wang Imaging
 * for Windows application with the public-domain TIFF Library.  Based upon an
 * examination of selected output files, this program apparently divides a JPEG
 * bit-stream into consecutive horizontal TIFF "strips", such that the JPEG
 * encoder's/decoder's DC coefficients for each image component are reset before
 * each "strip".  Moreover, a "strip" is not necessarily encoded in a multiple
 * of 8 bits, so one must sometimes discard 1-7 bits at the end of each "strip"
 * for alignment to the next input-Byte storage boundary.  IJG JPEG Library
 * decoder state is not normally exposed to client applications, so this sub-
 * routine provides the TIFF Library with a "hook" to make these corrections.
 * It should be called after "jpeg_start_decompress()" and before
 * "jpeg_finish_decompress()", just before decoding each "strip" using
 * "jpeg_read_raw_data()" or "jpeg_read_scanlines()".
 *
 * This kludge is not sanctioned or supported by the Independent JPEG Group, and
 * future changes to the IJG JPEG Library might invalidate it.  Do not send bug
 * reports about this code to IJG developers.  Instead, contact the author for
 * advice: Scott B. Marovich <marovich@hpl.hp.com>, Hewlett-Packard Labs, 6/01.
 */
GLOBAL(void)
jpeg_reset_huff_decode (register j_decompress_ptr cinfo,register float *refbw)
{ register huff_entropy_ptr entropy = (huff_entropy_ptr)cinfo->entropy;
  register int ci = 0;

  /* Re-initialize DC predictions */
  do entropy->saved.last_dc_val[ci] = -refbw[ci << 1];
  while (++ci < cinfo->comps_in_scan);
  /* Discard encoded input bits, up to the next Byte boundary */
  entropy->bitstate.bits_left &= ~7;
}
