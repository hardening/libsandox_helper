project('libsandbox-helper', 'c',
	license: 'GPL',
	version: '0.1',
)

cc = meson.get_compiler('c')
c_args = [] 

nbackends = 0

############
# landlock #
############

have_landlock = cc.has_header('linux/landlock.h', required: get_option('landlock'))

# If landlock feature is explicitly enabled and header is present, do not perform
# a runtime test, as this might be e.g. a distribution build in an isolated build
# environment and/or on an older kernel.  If feature is auto, then run-check the
# kernel as well.  https://gitlab.gnome.org/GNOME/tracker-miners/-/issues/300
if have_landlock and get_option('landlock').auto()
  landlock_check = cc.run('''
      #include <fcntl.h>
      #include <linux/landlock.h>
      #include <sys/syscall.h>
      #include <unistd.h>

      int main (int argc, char *argv[]) {
        /* Get supported landlock ABI */
        int abi = syscall (SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
        return abi < 0 ? 1 : 0;
      }
  ''',
  name: 'landlock is enabled in kernel')

  if not (landlock_check.compiled() and landlock_check.returncode() == 0)
    error('Landlock was auto-enabled in build options, but is disabled in the kernel')
  endif
  
  c_args += [
	# Needed for O_PATH, and probably other stuff.
	'-D_GNU_SOURCE',
  ]
  nbackends += 1
endif


############
# capsicum #
############

have_capsicum = cc.has_header('sys/capsicum.h', required: get_option('capsicum'))
if have_capsicum and get_option('capsicum').auto()
	# TODO: extra checks here

	nbackends += 1
endif

############
#  pledge  #
############
have_pledge = cc.has_header_symbol('unistd.h', 'HAVE_PLEDGE', required: get_option('pledge'))
if have_pledge
	nbackends += 1
endif


if nbackends == 0
	error('not backend detected')
elif nbackends > 1
	error('multiple backends detected, please adjust your options for just 1 backend')
endif



srcs = [
	'libsandbox-helper.c',
	'libsandbox-helper.h'
]

if have_landlock
	srcs += 'libsandbox_landlock.c'
endif

if have_capsicum
	srcs += 'libsandbox_capsicum.c'
endif

if have_pledge
	srcs += 'libsandbox_pledge.c'
endif

libsandbox_helper = library('libsandbox-helper', srcs,
	c_args: c_args
)

install_headers('libsandbox-helper.h')

if get_option('tests')
	subdir('tests')
endif
