# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/swa/Documents/Projects/Current/LibUnknownEcho

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/swa/Documents/Projects/Current/LibUnknownEcho/build/debug

# Include any dependencies generated for this target.
include CMakeFiles/message_cipher_client_example.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/message_cipher_client_example.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/message_cipher_client_example.dir/flags.make

CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o: CMakeFiles/message_cipher_client_example.dir/flags.make
CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o: ../../examples/message_cipher_client_example.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/swa/Documents/Projects/Current/LibUnknownEcho/build/debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o   -c /home/swa/Documents/Projects/Current/LibUnknownEcho/examples/message_cipher_client_example.c

CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/swa/Documents/Projects/Current/LibUnknownEcho/examples/message_cipher_client_example.c > CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.i

CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/swa/Documents/Projects/Current/LibUnknownEcho/examples/message_cipher_client_example.c -o CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.s

CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o.requires:

.PHONY : CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o.requires

CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o.provides: CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o.requires
	$(MAKE) -f CMakeFiles/message_cipher_client_example.dir/build.make CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o.provides.build
.PHONY : CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o.provides

CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o.provides.build: CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o


# Object files for target message_cipher_client_example
message_cipher_client_example_OBJECTS = \
"CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o"

# External object files for target message_cipher_client_example
message_cipher_client_example_EXTERNAL_OBJECTS =

../../bin/debug/examples/message_cipher_client_example: CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o
../../bin/debug/examples/message_cipher_client_example: CMakeFiles/message_cipher_client_example.dir/build.make
../../bin/debug/examples/message_cipher_client_example: ../../lib/libssl.so.1.1
../../bin/debug/examples/message_cipher_client_example: ../../lib/libcrypto.so.1.1
../../bin/debug/examples/message_cipher_client_example: ../../bin/debug/libunknownecho.a
../../bin/debug/examples/message_cipher_client_example: ../../lib/asmlib/libaelf64.a
../../bin/debug/examples/message_cipher_client_example: ../../lib/libssl.so.1.1
../../bin/debug/examples/message_cipher_client_example: ../../lib/libz.a
../../bin/debug/examples/message_cipher_client_example: ../../lib/libcrypto.so.1.1
../../bin/debug/examples/message_cipher_client_example: ../../lib/libcrypto.so.1.1
../../bin/debug/examples/message_cipher_client_example: CMakeFiles/message_cipher_client_example.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/swa/Documents/Projects/Current/LibUnknownEcho/build/debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable ../../bin/debug/examples/message_cipher_client_example"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/message_cipher_client_example.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/message_cipher_client_example.dir/build: ../../bin/debug/examples/message_cipher_client_example

.PHONY : CMakeFiles/message_cipher_client_example.dir/build

CMakeFiles/message_cipher_client_example.dir/requires: CMakeFiles/message_cipher_client_example.dir/examples/message_cipher_client_example.c.o.requires

.PHONY : CMakeFiles/message_cipher_client_example.dir/requires

CMakeFiles/message_cipher_client_example.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/message_cipher_client_example.dir/cmake_clean.cmake
.PHONY : CMakeFiles/message_cipher_client_example.dir/clean

CMakeFiles/message_cipher_client_example.dir/depend:
	cd /home/swa/Documents/Projects/Current/LibUnknownEcho/build/debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/swa/Documents/Projects/Current/LibUnknownEcho /home/swa/Documents/Projects/Current/LibUnknownEcho /home/swa/Documents/Projects/Current/LibUnknownEcho/build/debug /home/swa/Documents/Projects/Current/LibUnknownEcho/build/debug /home/swa/Documents/Projects/Current/LibUnknownEcho/build/debug/CMakeFiles/message_cipher_client_example.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/message_cipher_client_example.dir/depend

