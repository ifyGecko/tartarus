# meson build configuration for tartarus project
# replicates build steps from original makefile

project('tartarus', 'c')

# build tartarus.so: shared library with debug info, fpic, custom entry point
# name_prefix prevents default 'lib' prefix to match original output name
shared_library('tartarus',
  'tartarus.c',
  c_args: ['-g', '-fPIC'],
  link_args: ['--entry=entry'],
  name_prefix: '',
  install: false
)

# build test.so: shared library with fpic
# target name 'test' is reserved in meson, use custom target to avoid conflict
custom_target('test_so',
  input: 'test.c',
  output: 'test.so',
  command: ['gcc', '-shared', '-fPIC', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true
)
