#define RLBOX_USE_EXCEPTIONS
#include "rlbox_lucet_sandbox.hpp"

// NOLINTNEXTLINE
#define TestName "rlbox_lucet_sandbox"
// NOLINTNEXTLINE
#define TestType rlbox::rlbox_lucet_sandbox

#ifndef GLUE_LIB_LUCET_PATH
#  error "Missing definition for GLUE_LIB_LUCET_PATH"
#endif

// NOLINTNEXTLINE
#define CreateSandbox(sandbox) sandbox.create_sandbox(GLUE_LIB_LUCET_PATH)
#include "test_sandbox_glue.inc.cpp"
