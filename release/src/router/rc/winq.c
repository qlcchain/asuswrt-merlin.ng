#include "rc.h"
#include <shared.h>
#include <sys/stat.h>
#include <sys/types.h>

int start_winq_server(void)
{
	char *winqs_argv[] = {"winq_server", NULL};

	return _eval(winqs_argv, NULL, 0, NULL);
}

