#include "Types.r"

resource 'BNDL' (128) {
	'HTBA',
	0,
	{	/* array TypeArray: 2 elements */
		/* [1] */
		'ICN#',
		{	/* array IDArray: 2 elements */
			/* [1] */
			0, 128,
			/* [2] */
			1, 129,
		},
		/* [2] */
		'FREF',
		{	/* array IDArray: 2 elements */
			/* [1] */
			0, 128,
			/* [2] */
			1, 129,
		}
	}
};

resource 'FREF' (128) {
	'APPL',
	0,
	""
};

resource 'FREF' (129) {
	'HTBD',
	1,
	""
};

