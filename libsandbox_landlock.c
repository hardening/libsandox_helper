#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>

#include <linux/landlock.h>
#include <sys/syscall.h>

#include "libsandbox-helper.h"

/* add some missing definitions with older kernel headers, just to make the code
 * more generic
 */
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif


#ifdef LANDLOCK_ACCESS_NET_BIND_TCP
#	define WITH_NET_RULES
#	define LANDLOCK_ABI_MAX 4
#else
#	define LANDLOCK_ABI_MAX 3
#endif


#define MAX_RULES 200

#define ACCESS_FS_ROUGHLY_READ ( \
		LANDLOCK_ACCESS_FS_EXECUTE | \
		LANDLOCK_ACCESS_FS_READ_FILE | \
		LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_ROUGHLY_WRITE ( \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	LANDLOCK_ACCESS_FS_MAKE_CHAR | \
	LANDLOCK_ACCESS_FS_MAKE_DIR | \
	LANDLOCK_ACCESS_FS_MAKE_REG | \
	LANDLOCK_ACCESS_FS_MAKE_SOCK | \
	LANDLOCK_ACCESS_FS_MAKE_FIFO | \
	LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
	LANDLOCK_ACCESS_FS_MAKE_SYM | \
	LANDLOCK_ACCESS_FS_REFER | \
	LANDLOCK_ACCESS_FS_TRUNCATE | \
	LANDLOCK_ACCESS_FS_IOCTL_DEV )



struct libsandbox_context_s {
	int landlock_abi;
	bool no_new_priv_called;
	bool have_truncate;

	uint64_t fs_ruleset_flags;
	int n_fs_rules;
	struct landlock_path_beneath_attr fs_rules[MAX_RULES];

#ifdef WITH_NET_RULES
	uint64_t net_ruleset_flags;
	int n_net_rules;
	struct landlock_net_port_attr net_rules[MAX_RULES];
#endif
};

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, uint32_t flags) {
	return syscall(SYS_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type, const void *rule_attr, uint32_t flags) {
	return syscall(SYS_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(int ruleset_fd, uint32_t flags) {
	return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}
#endif

libsandbox_context_t *libsandbox_new() {
	libsandbox_context_t *ret = calloc(1, sizeof(*ret));
	if (!ret)
		return ret;

	ret->landlock_abi = landlock_create_ruleset((void *)NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (ret->landlock_abi < 0) {
		switch(errno) {
		case ENOSYS:
			fprintf(stderr, "landlock not supported by kernel\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "landlock is disabled in kernel");
			break;
		}

		free(ret);
		return NULL;
	}

	if (ret->landlock_abi > 0) {
		if (ret->landlock_abi > LANDLOCK_ABI_MAX)
			ret->landlock_abi = LANDLOCK_ABI_MAX;
	}

	ret->fs_ruleset_flags = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE;
	switch (ret->landlock_abi) {
	case 1:
		ret->fs_ruleset_flags &= ~LANDLOCK_ACCESS_FS_REFER;
		__attribute__((fallthrough));
	case 2:
		/* Removes LANDLOCK_ACCESS_FS_TRUNCATE for ABI < 3 */
		ret->fs_ruleset_flags &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
		__attribute__((fallthrough));
	case 3:
		/* Removes network support for ABI < 4 */
		ret->have_truncate = true;
#ifdef WITH_NET_RULES
		ret->net_ruleset_flags &= ~(LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP);
#endif
		__attribute__((fallthrough));
	case 4:
		/* Removes LANDLOCK_ACCESS_FS_IOCTL_DEV for ABI < 5 */
		ret->fs_ruleset_flags &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
		break;
	}

	return ret;
}

uint64_t libsandbox_features(libsandbox_context_t *context)
{
	uint64_t ret = LIBSANDBOX_CAPABILITY_FS;
	if (context->landlock_abi > 3)
		ret |= LIBSANDBOX_CAPABILITY_NET;
	return ret;
}

static void libsandbox_cleanup(libsandbox_context_t *context)
{
	assert(context);

	for (int i = 0; i < context->n_fs_rules; i++) {
		struct landlock_path_beneath_attr *attr = &context->fs_rules[i];
		close(attr->parent_fd);
	}
	context->n_fs_rules = 0;

#ifdef WITH_NET_RULES
	context->n_net_rules = 0;
#endif
}

void libsandbox_destroy(libsandbox_context_t **pcontext) {
	assert(pcontext);

	libsandbox_context_t *context = *pcontext;

	libsandbox_cleanup(context);

	free(*pcontext);
	*pcontext = NULL;
}

static int create_ruleset(libsandbox_context_t *context) {
	assert(context);

	const struct landlock_ruleset_attr attr = {
		.handled_access_fs = context->fs_ruleset_flags
#ifdef WITH_NET_RULES
		,
		.handled_access_net = context->net_ruleset_flags
#endif
	};

	int ruleset = landlock_create_ruleset(&attr, sizeof(attr), 0);
	if (ruleset < 0) {
		perror("landlock_create_ruleset");
		return false;
	}

	return ruleset;
}

static uint64_t landock_convert_fs_flag(uint64_t v) {
	typedef struct {
		uint64_t landlock_flag;
		libsandbox_fs_access_t libsandbox_flag;
	} flagEquiv_s;

	flagEquiv_s flagEquiv[] = {
		{LANDLOCK_ACCESS_FS_EXECUTE, LIBSANDBOX_ACCESS_EXEC},
		{LANDLOCK_ACCESS_FS_WRITE_FILE, LIBSANDBOX_ACCESS_WRITEF},
		{LANDLOCK_ACCESS_FS_READ_FILE, LIBSANDBOX_ACCESS_READF},
		{LANDLOCK_ACCESS_FS_TRUNCATE, LIBSANDBOX_ACCESS_TRUNCATE},
		{LANDLOCK_ACCESS_FS_READ_DIR, LIBSANDBOX_ACCESS_READDIR},
		{LANDLOCK_ACCESS_FS_REMOVE_DIR, LIBSANDBOX_ACCESS_REMOVEDIR},
		{LANDLOCK_ACCESS_FS_REMOVE_FILE, LIBSANDBOX_ACCESS_REMOVEFILE},
		{LANDLOCK_ACCESS_FS_MAKE_REG, LIBSANDBOX_ACCESS_NEWFILE},
	};
	int ret = 0;

	for (int i = 0; i < sizeof(flagEquiv)/sizeof(flagEquiv[0]); i++) {
		if (v & flagEquiv[i].libsandbox_flag)
			ret |= flagEquiv[i].landlock_flag;
	}

	return ret;
}

int libsandbox_add_fs_restriction(libsandbox_context_t *context, const char *path, uint64_t flags)
{
	assert(context);

	int fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (context->n_fs_rules >= MAX_RULES)
		return -1;

	struct landlock_path_beneath_attr *attr = &context->fs_rules[context->n_fs_rules];
	attr->allowed_access = landock_convert_fs_flag(flags) ;
	attr->parent_fd = fd;

	context->n_fs_rules++;
	return 0;
}

int libsandox_apply(libsandbox_context_t *context)
{
	assert(context);

	int ruleset = create_ruleset(context);
	if (ruleset < 0)
		return -1;

	int ret = 0;
	for (int i = 0; i < context->n_fs_rules; i++) {
		struct landlock_path_beneath_attr *attr = &context->fs_rules[i];

		ret = landlock_add_rule(ruleset, LANDLOCK_RULE_PATH_BENEATH, attr, 0);
		if (ret < 0)
			goto out;
	}

#ifdef WITH_NET_RULES
	for (int i = 0; i < context->n_net_rules; i++) {
		struct landlock_net_port_attr *attr = &context->net_rules[i];

		ret = landlock_add_rule(ruleset, LANDLOCK_RULE_NET_PORT, attr, 0);
		if (ret < 0)
			goto out;
	}
#endif

	if (!context->no_new_priv_called) {
		(void)prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		context->no_new_priv_called = true;
	}

	ret = landlock_restrict_self(ruleset, 0);
	if (ret < 0)
		perror("landlock_restrict_self");

	libsandbox_cleanup(context);
out:
	close(ruleset);
	return ret;
}

