/*
 * httpclient360.h -- what httpclient-cpp needs on the Xbox 360 that the XDK
 * does not spell the same way.
 *
 * This header is force-included ahead of every translation unit of the library
 * (and of a title built with the installed fragment), because both things it
 * does have to happen before <curl/curl.h> is reached, and the library's own
 * source cannot be asked to do it: HTTPClient.h is upstream's and is compiled
 * unchanged.
 *
 *   <windows.h> first. The XDK has no <windows.h>; both OXDK and the curl port
 *   ship a shim for the name. <curl/system.h> includes <winsock2.h> and
 *   <windows.h> on any Windows target, and by itself that order is a cycle on
 *   this platform:
 *
 *     curl's <winsock2.h>  ->  the XDK's <winsockx.h>
 *                          ->  <windows.h>  (the curl shim)
 *                          ->  the XDK's <xtl.h>
 *                          ->  <winsockx.h> again, still mid-body so its guard
 *                              short-circuits it
 *                          ->  <xonline.h>, which wants XNKID and XNADDR, the
 *                              types declared further down that very body
 *
 *   <xtl.h> defines _INC_WINDOWS before it includes <winsockx.h>, so when the
 *   same chain starts from <windows.h> instead, <winsockx.h> completes and
 *   <xonline.h> finds everything it needs. Including <windows.h> here -- which
 *   resolves to the curl port's shim, the one that defines NOD3D and keeps the
 *   D3D headers out of a library that never touches them -- puts the working
 *   order in place once, for every translation unit.
 *
 *   strcasecmp / strncasecmp. The library sorts a std::set of HTTP header names
 *   with strcasecmp. Those are POSIX names, and the console CRT exports only
 *   Microsoft's underscored _stricmp and _strnicmp. Mapping the names is what
 *   oldnames.lib does for a normal Windows build; here it is one #define.
 *
 *   No <string.h> include for it: the chain above reaches the XDK's <xtl.h>,
 *   which includes <string.h> itself and declares both underscored names, so
 *   they are in scope by the time the mapping below is written.
 */

#ifndef HTTPCLIENT360_H
#define HTTPCLIENT360_H

#include <windows.h>

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif

#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif

#endif /* HTTPCLIENT360_H */
