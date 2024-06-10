#ifndef LIBSANDBOX_HELPER_H_
#define LIBSANDBOX_HELPER_H_

#include <stdint.h>

typedef struct libsandbox_context_s libsandbox_context_t;

/** @brief file system access flags */
typedef enum {
	LIBSANDBOX_ACCESS_EXEC  = (1 << 0),
	LIBSANDBOX_ACCESS_WRITEF = (1 << 1),
	LIBSANDBOX_ACCESS_READF = (1 << 2),
	LIBSANDBOX_ACCESS_TRUNCATE = (1 << 3),
	LIBSANDBOX_ACCESS_READDIR = (1 << 4),
	LIBSANDBOX_ACCESS_REMOVEDIR = (1 << 5),
	LIBSANDBOX_ACCESS_REMOVEFILE = (1 << 6),
	LIBSANDBOX_ACCESS_NEWFILE = (1 << 7),
} libsandbox_fs_access_t;

/** @brief capabilities supported by the underlying sandbox framework */
 typedef enum {
	LIBSANDBOX_CAPABILITY_FS = (1 << 0),
	LIBSANDBOX_CAPABILITY_NET = (1 << 1),
 } libsandbox_capability_t;


#ifdef __cplusplus
extern "C" {
#endif

/** Creates a new libsandbox_helper context
 *
 *	@return the created context or NULL on error
 */
libsandbox_context_t *libsandbox_new();

/** Returns the features supported by this sandbox helper context
 *
 *	@return the supported features
 */
uint64_t libsandbox_features(libsandbox_context_t *context);

/** Destroys and free the corresponding libsandbox_context_t
 *
 *	@param pcontext a pointer to a libsandbox_context_t* (nullified after free)
 */
void libsandbox_destroy(libsandbox_context_t **pcontext);


/** Adds a file system restriction to the libsandbox_context_t
 *
 * @param context target libsandbox_context_t
 * @param path the path (file or directory) where to applying the restriction
 * @param flags a bitwise-or of libsandbox_fs_access_t
 * @return 0 if successful
 */
int libsandbox_add_fs_restriction(libsandbox_context_t *context, const char *path, uint64_t flags);


/** Applies accumulated sandbox restrictions, at function return the restrictions have
 * been applied.
 *
 * @param context the sandbox context
 * @return 0 if the operation was successfull
 */
int libsandox_apply(libsandbox_context_t *context);

#ifdef __cplusplus
}
#endif


#endif /* LIBSANDBOX_HELPER_H_ */
