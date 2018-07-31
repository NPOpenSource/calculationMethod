# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

INCLUDE_DIRECTORIES(./src/common/android/include)
INCLUDE_DIRECTORIES(./src)
INCLUDE_DIRECTORIES(./src/third_party/lss)
SET_TARGET_PROPERTIES(breakpad_client PROPERTIES LINKER_LANGUAGE C++)

 set(CMAKE_CXX_FLAGS   "-std=c++11")
 add_library( # Sets the name of the library.
              breakpad_client

             ########breakpad#################
              src/main/cpp/breakpad/src/client/linux/crash_generation/crash_generation_client.cc
              src/main/cpp/breakpad/src/client/linux/dump_writer_common/thread_info.cc
              src/main/cpp/breakpad/src/client/linux/dump_writer_common/ucontext_reader.cc
              src/main/cpp/breakpad/src/client/linux/handler/exception_handler.cc
              src/main/cpp/breakpad/src/client/linux/handler/minidump_descriptor.cc
              src/main/cpp/breakpad/src/client/linux/log/log.cc
              src/main/cpp/breakpad/src/client/linux/microdump_writer/microdump_writer.cc
              src/main/cpp/breakpad/src/client/linux/minidump_writer/linux_dumper.cc
              src/main/cpp/breakpad/src/client/linux/minidump_writer/linux_ptrace_dumper.cc
              src/main/cpp/breakpad/src/client/linux/minidump_writer/minidump_writer.cc
              src/main/cpp/breakpad/src/client/minidump_file_writer.cc
              src/main/cpp/breakpad/src/common/android/breakpad_getcontext.S
              src/main/cpp/breakpad/src/common/convert_UTF.c
              src/main/cpp/breakpad/src/common/md5.cc
              src/main/cpp/breakpad/src/common/string_conversion.cc
              src/main/cpp/breakpad/src/common/linux/elfutils.cc
              src/main/cpp/breakpad/src/common/linux/file_id.cc
              src/main/cpp/breakpad/src/common/linux/guid_creator.cc
              src/main/cpp/breakpad/src/common/linux/linux_libc_support.cc
              src/main/cpp/breakpad/src/common/linux/memory_mapped_file.cc
              src/main/cpp/breakpad/src/common/linux/safe_readlink.cc
             )

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.


find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log
               )