#include "CurlHandle.h"

#include <curl/curl.h>

#ifdef HTTPCLIENT360_NO_EXCEPTIONS
/* Nothing can catch a throw on this target, so the constructor reports and stops
 * instead. OXDK builds titles with -fno-exceptions -- there is no unwinder and
 * the XDK CRT ships no EH personality -- which means upstream's throw cannot
 * even be compiled here. See README-oxdk360.md. */
extern "C" void DbgPrint(const char *fmt, ...);
extern "C" void HalReturnToFirmware(unsigned int routine);
#else
/* Only the throwing branch below names std::runtime_error, so on this target
 * this header is one nothing includes. */
#include <stdexcept>
#endif

CurlHandle::CurlHandle() {
   const auto eCode = curl_global_init(CURL_GLOBAL_ALL);
   if (eCode != CURLE_OK) {
#ifdef HTTPCLIENT360_NO_EXCEPTIONS
      DbgPrint("httpclient: curl_global_init failed (%d), stopping\n",
               static_cast<int>(eCode));
      HalReturnToFirmware(1);
#else
      throw std::runtime_error{"Error initializing libCURL"};
#endif
   }
}

CurlHandle::~CurlHandle() { curl_global_cleanup(); }

CurlHandle &CurlHandle::instance() {
   static CurlHandle inst{};
   return inst;
}
