/*
 *  mkg3_main.c -- passes fake arguments into main
 */

#undef main

int
main()
{
	static char *argv[4] = {
	 "mkg3states", "-c", "const", "tif_fax3sm.c" };
	
	return tool_main(4,argv);  // Call the tool "main()" routine
}
