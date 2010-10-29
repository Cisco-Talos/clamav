/*
 *  mac_main.c -- The REAL entry point which
 *   calls the tools main code. For the tools
 *   the symbol "main" has been #defined to "tool_main"
 *   so that this entry point may be used to access
 *   the user-input first.
 */

#undef main

int
main()
{
	int argc;
	char **argv;
	
	argc=ccommand(&argv);

	return tool_main(argc,argv);  // Call the tool "main()" routine
}
