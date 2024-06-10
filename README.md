# libsandbox_helper

A library to ease the sandboxing of your application on various sandboxing systems. Supported frameworks
are landlock (linux), capsicum (FreeBSD, TODO) and pledge (OpenBSD, TODO).

## Example

This is an example for a program that would like to restrict itself to reading files:

```C
	libsandbox_context_t *context = libsandbox_new();
	if (!context)
		return -1;

	if (libsandbox_add_fs_restriction(context, ".", LIBSANDBOX_ACCESS_READF) < 0)
		return -2;

	if (libsandox_apply(context))
		return -3;
```