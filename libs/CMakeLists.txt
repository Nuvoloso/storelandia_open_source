cmake_minimum_required(VERSION 2.6.4)

if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif (POLICY CMP0048)

project( libs )

enable_testing()

add_subdirectory( xxhash )

