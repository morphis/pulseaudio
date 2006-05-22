#ifndef fooerrorhfoo
#define fooerrorhfoo

/* $Id$ */

/***
  This file is part of polypaudio.
 
  polypaudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2 of the License,
  or (at your option) any later version.
 
  polypaudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.
 
  You should have received a copy of the GNU Lesser General Public License
  along with polypaudio; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#include <inttypes.h>
#include <polyp/cdecl.h>

/** \file
 * Error management */

PA_C_DECL_BEGIN

/** Return a human readable error message for the specified numeric error code */
const char* pa_strerror(int error);

/** A wrapper around the standard strerror() function that converts the
 * string to UTF-8. The function is thread safe but the returned string is
 * only guaranteed to exist until the thread exits or pa_cstrerror() is
 * called again from the same thread. */
char* pa_cstrerror(int errnum);

PA_C_DECL_END

#endif
