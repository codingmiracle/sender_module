# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "C:/Espressif/frameworks/esp-idf-master/components/bootloader/subproject"
  "C:/Users/dagra/esp/sender_module/cmake-build-esp-32/bootloader"
  "C:/Users/dagra/esp/sender_module/cmake-build-esp-32/bootloader-prefix"
  "C:/Users/dagra/esp/sender_module/cmake-build-esp-32/bootloader-prefix/tmp"
  "C:/Users/dagra/esp/sender_module/cmake-build-esp-32/bootloader-prefix/src/bootloader-stamp"
  "C:/Users/dagra/esp/sender_module/cmake-build-esp-32/bootloader-prefix/src"
  "C:/Users/dagra/esp/sender_module/cmake-build-esp-32/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "C:/Users/dagra/esp/sender_module/cmake-build-esp-32/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
