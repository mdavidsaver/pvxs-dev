/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_PRE_H
#define PVXS_PRE_H
/* Use to inject macro definitions before stdc++ headers.
 * eg. with 'gcc -include=pvxs_pre.h ..."
 */

#ifdef _SHARED_PTR_H
#  error Include pvxs_pre.h before stdc++ headers
#endif

#if __has_include(<valgrind/drd.h>)
#  include<valgrind/helgrind.h>
#  define _GLIBCXX_SYNCHRONIZATION_HAPPENS_BEFORE(addr) ANNOTATE_HAPPENS_BEFORE(addr)
#  define _GLIBCXX_SYNCHRONIZATION_HAPPENS_AFTER(addr)  ANNOTATE_HAPPENS_AFTER(addr)
#endif

#endif // PVXS_PRE_H
