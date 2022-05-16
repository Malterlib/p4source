/*
 * Copyright 2019 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <error.h>

# ifdef HAS_EXTENSIONS

# include "p4script.h"
# include "p4script53.h"

// We include all of Lua here, compiled as C++ so exceptions work properly,
// for easier symbol redefinition (to prevent namespace clashes), and for
// potential performance improvements since the compiler can see everything
// at once.

# include "lua-5.3/one.cc"

# endif
