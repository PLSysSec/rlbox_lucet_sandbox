cmake_minimum_required(VERSION 3.11)

SET(CMAKE_C_COMPILER /usr/bin/clang)
SET(CMAKE_CXX_COMPILER /usr/bin/clang++)
SET(CMAKE_BUILD_TYPE Release)

if(NOT DEFINED ENV{rlbox_SOURCE_DIR})
message(FATAL_ERROR "Set rlbox_SOURCE_DIR environment variable")
endif()

if(NOT DEFINED ENV{WASM_LD_PATH})
message(FATAL_ERROR "Set WASM_LD_PATH environment variable")
endif()

if(NOT DEFINED ENV{WASI_SYSROOT})
message(FATAL_ERROR "Set WASI_SYSROOT environment variable")
endif()

if(NOT DEFINED ENV{LUCET_WASI_DIR})
message(FATAL_ERROR "Set LUCET_WASI_DIR environment variable")
endif()

if(NOT DEFINED ENV{LUCET_DIR})
message(FATAL_ERROR "Set LUCET_DIR environment variable")
endif()

set(rlbox_SOURCE_DIR $ENV{rlbox_SOURCE_DIR})
set(WASM_LD_PATH $ENV{WASM_LD_PATH})
set(WASI_SYSROOT $ENV{WASI_SYSROOT})
set(LUCET_WASI_DIR $ENV{LUCET_WASI_DIR})
set(LUCET_DIR $ENV{LUCET_DIR})

# Apply settings suitable for wasm module compilation
set(CMAKE_C_FLAGS " -B${WASM_LD_PATH} --target=wasm32-wasi --sysroot ${WASI_SYSROOT} -Wl,--export-all ")

add_executable(glue_lib_lucet.wasm
               lucet_sandbox_wrapper.c
               ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib/libtest.c
              )

set(GLUE_LIB_PATH "${CMAKE_BINARY_DIR}/glue_lib_lucet.so")

add_custom_command(OUTPUT ${GLUE_LIB_PATH}
              DEPENDS glue_lib_lucet.wasm
              COMMAND ${LUCET_DIR}/lucetc
                      --bindings ${LUCET_WASI_DIR}/bindings.json
                      --guard-size "4GiB"
                      --min-reserved-size "4GiB"
                      --max-reserved-size "4GiB"
                      glue_lib_lucet.wasm
                      -o ${GLUE_LIB_PATH}
              COMMENT "Compiling wasm file to native")

add_custom_target(glue_lib_so ALL
             DEPENDS ${GLUE_LIB_PATH})