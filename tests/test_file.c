#include <stdio.h>
#include "../libsandbox-helper.h"

int main(int argc, char *argv[]) {
	libsandbox_context_t *context = libsandbox_new();
	if (!context)
		return -1;

	if (!(libsandbox_features(context) & LIBSANDBOX_CAPABILITY_FS))
		return -1;

	/* check that we can write file before sandboxing us */
	FILE *f = fopen("./toto.txt", "w");
	if (!f)
		return -1;
	fclose(f);
	remove("./toto.txt");

	/* apply read only policy */
	if (libsandbox_add_fs_restriction(context, ".", LIBSANDBOX_ACCESS_READF | LIBSANDBOX_ACCESS_READDIR) < 0)
		return -2;

	if (libsandox_apply(context))
		return -3;

	/* should not be able to create a new file */
	f = fopen("./toto.txt", "w");
	if (f) {
		fclose(f);
		remove("./toto.txt");
		return -4;
	}

	libsandbox_destroy(&context);
	return 0;
}
