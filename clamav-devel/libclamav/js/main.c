#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef	CL_EXPERIMENTAL
#if HAVE_CONFIG_H
#include "js/jsconfig.h"
#endif

#include <stdio.h>
#include <assert.h>

#if HAVE_STDC_HEADERS
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#else /* not HAVE_STDC_HEADERS */

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

#if HAVE_STRING_H
#include <string.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#endif /* not HAVE_STDC_HEADERS */

#include "js/js.h"
#include "getopt.h"

/* These are configurable in NGS */
int optimize = 1;
unsigned int stack_size = 2048;
JSVMDispatchMethod dispatch_method = JS_VM_DISPATCH_JUMPS;
int stacktrace_on_error = 0;
unsigned int verbose = 0;
int no_compiler = 0;
int secure_builtin_file = 0;
int secure_builtin_system = 0;
int annotate_assembler = 0;
int compile = 0;
int events = 0;
int generate_debug_info = 0;
int warn_deprecated = 0;
int warn_unused_argument = 0;
int warn_unused_variable = 1;
int warn_undef = 1;
int warn_shadow = 1;
int warn_with_clobber = 1;
int warn_missing_semicolon = 0;
int warn_strict_ecma = 0;
int generate_executable_bc_files = 0;


static int
show_events_hook (int event, void *context)
{
  char *event_name;

  switch (event)
    {
    case JS_EVENT_OPERAND_COUNT:
      event_name = "operand count";
      break;

    case JS_EVENT_GARBAGE_COLLECT:
      event_name = "garbage collect";
      break;

    default:
      event_name = "unknown";
      break;
    }

	cli_dbgmsg("[%s]\n", event_name);

  return 0;
}


JSInterpPtr
create_interp(JSIOFunc s_stdout)
{
	JSInterpOptions options;
	JSInterpPtr interp;

	js_init_default_options (&options);

	options.stack_size = stack_size;
	options.dispatch_method = dispatch_method;
	options.verbose = verbose;

	options.no_compiler = no_compiler;
	options.stacktrace_on_error = stacktrace_on_error;

	options.secure_builtin_file = secure_builtin_file;
	options.secure_builtin_system = secure_builtin_system;

	options.annotate_assembler = annotate_assembler;
	options.debug_info = generate_debug_info;
	options.executable_bc_files = generate_executable_bc_files;

	options.warn_unused_argument		= warn_unused_argument;
	options.warn_unused_variable		= warn_unused_variable;
	options.warn_undef			= warn_undef;
	options.warn_shadow			= warn_shadow;
	options.warn_with_clobber		= warn_with_clobber;
	options.warn_missing_semicolon	= warn_missing_semicolon;
	options.warn_strict_ecma		= warn_strict_ecma;
	options.warn_deprecated		= warn_deprecated;

	/* As a default, no optimization */
	options.optimize_peephole = 0;
	options.optimize_jumps_to_jumps = 0;
	options.optimize_bc_size = 0;
	options.optimize_heavy = 0;

	if (optimize >= 1) {
		options.optimize_peephole = 1;
		options.optimize_jumps_to_jumps = 1;
		options.optimize_bc_size = 1;
	}

	if (optimize >= 2)
		options.optimize_heavy = 1;

	/* Show events? */
	if (events) {
		options.hook = show_events_hook;
		options.hook_operand_count_trigger = 1000000;
	}

	options.s_stdout = s_stdout;

	interp = js_create_interp (&options);
	if (interp == NULL) {
		cli_errmsg("js: couldn't create interpreter\n");
		return NULL;
	}

	/* And finally, define the requested modules. */

#if WITH_JS
	if (!js_define_module (interp, js_ext_JS))
		cli_warnmsg("warning: couldn't create the JS extension\n");
#endif

#if WITH_CURSES
	if (!js_define_module (interp, js_ext_curses))
		cli_warnmsg("warning: couldn't create the curses extension\n");
#endif

#if WITH_MD5
	if (!js_define_module (interp, js_ext_MD5))
		cli_warnmsg("warning: couldn't create the MD5 extension\n");
#endif

	return interp;
}

#endif	/*CL_EXPERIMENTAL*/
