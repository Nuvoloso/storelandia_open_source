cmake_minimum_required(VERSION 2.6.4)

project( nuvo_utils C)

set (NUVO_COMMON_FLAGS "-g -Wall -Wextra -Werror -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64")
set (NUVO_C_FLAGS "${NUVO_COMMON_FLAGS} -std=c11")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NUVO_C_FLAGS}")

# Build the executable
add_Executable(nuvo_ephemeral ephemeral.c)
