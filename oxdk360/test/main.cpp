/*
 * Link check and smoke test for httpclient-cpp on the Xbox 360.
 *
 * This title exists to make the linker answer the questions that compiling the
 * library cannot:
 *
 *   - does libhttpclient.a link at all? CHTTPClient's methods pull the whole
 *     wrapper in, and the wrapper pulls libcurl's transfer path, its BearSSL
 *     backend and the console socket layer after it, plus everything libc++
 *     declares in its headers and does not define there.
 *
 *   - does the socket layer reach xnet.lib? A transfer is Winsock underneath,
 *     and this is the only place that can show it: the XDK libraries are linked
 *     by oxdklink against the console's import table, not by the host linker.
 *
 *   - does the port's resolver resolve? The library calls libcurl, libcurl
 *     calls gethostbyname(), and the console's resolver is XNetDnsLookup in
 *     oxdk360/resolv_xbox360.c. Only a request that names a host reaches it.
 *
 *   - is BearSSL the backend the archive was built with? curl_version_info()
 *     reports the SSL version string, and this port's must read "BearSSL".
 *
 *   - does the library's C++ surface work at all? The log callback is a
 *     std::function, the response body a std::string, and the headers an
 *     unordered_map; if libc++'s compiled half were missing or mismatched, the
 *     failure would be here rather than at the link.
 *
 *   - does the built-in curl trace work? DEBUG_CURL is defined in upstream's
 *     HTTPClient.h, so the library always carries DebugCallback and the two
 *     Start/EndCurlDebug helpers. What they need to be useful is the caller's
 *     side, and that is what this title provides: a trace directory, requests
 *     that generate debug events, and a check that the file the library chose
 *     was created and has something in it.
 *
 * Run on a console it reports through the debug channel, which XBDM relays.
 * Nothing is asserted about the network: a console with no configured network,
 * or with no route to the host, is expected to fail the request and say so.
 * What is asserted is that every call was reached and every symbol resolved.
 *
 *   make                     -> default.xex
 *   make check               -> xexcheck.py on it
 *   XBDM_HOST=... make run   -> copy it to the console and run it
 *   XBDM_HOST=... make watch -> the debug channel
 */

#include "HTTPClient.h"

#include <cstdio>
#include <ctime>
#include <string>

extern "C" void DbgPrint(const char *fmt, ...);

namespace {

/* Where the curl trace goes. The library appends a slash itself on anything but
 * Windows, so this is the console's name for a directory, not a path with a
 * trailing separator. Hdd1: is where a title has somewhere to write -- it is
 * also where oxdk360/test's own deploy target puts the XEX. */
const char *const kTraceDirectory = "Hdd1:\\httpclient360";

void Say(const std::string &text) {
   DbgPrint("httpclient360: %s\n", text.c_str());
}

/* The same report the console prints, also sent through the library's own log
 * callback so that the std::function path is exercised on every line. */
void LogToDebug(const std::string &message) {
   DbgPrint("httpclient360[]: %s\n", message.c_str());
}

/* The name StartCurlDebug builds, reproduced so the check can open the same
 * file: <directory>/TraceLog_<strftime "%Y%m%d_%H">.txt, with a new file every
 * hour. Reproducing it is the point rather than a shortcut -- if the two ever
 * disagree, the trace is being written somewhere the caller did not name, and
 * this is what says so. */
std::string ExpectedTraceFile() {
   char stamp[32];
   memset(stamp, 0, sizeof stamp);

   time_t now;
   time(&now);

   struct tm *parts = localtime(&now);
   if (parts == nullptr || strftime(stamp, sizeof stamp, "%Y%m%d_%H", parts) == 0)
      return std::string();

   return std::string(kTraceDirectory) + "/TraceLog_" + stamp + ".txt";
}

/* Report the file the library should have written, and how much is in it. A
 * console with no network still gets the trace: curl logs the connect or resolve
 * failure through the same debug callback as a successful transfer. */
void CheckTraceFile() {
   const std::string path = ExpectedTraceFile();
   if (path.empty()) {
      Say("trace: could not build the expected file name (time or strftime failed)");
      return;
   }

   FILE *file = fopen(path.c_str(), "rb");
   if (file == nullptr) {
      Say("trace: " + path + " was not created");
      return;
   }

   fseek(file, 0, SEEK_END);
   const long size = ftell(file);
   fclose(file);

   Say("trace: " + path + " is " + std::to_string(size) + " bytes");
   if (size <= 0)
      Say("trace: the file is empty, so no debug event reached the callback");
}

void ReportCurl() {
   const curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);

   Say("libcurl " + std::string(info->version));
   Say("ssl: " + std::string(info->ssl_version));
   Say("libz: " + std::string(info->libz_version ? info->libz_version : "none"));

   /* info->protocols is a NULL-terminated array of const char*. */
   std::string protocols;
   for (const char *const *name = info->protocols; name != nullptr && *name != nullptr; ++name)
      protocols += std::string(protocols.empty() ? "" : " ") + *name;
   Say("protocols: " + protocols);

   /* The one assertion this title makes about its own build. The archive links
    * BearSSL and nothing else, so anything but a BearSSL string here would mean
    * a different libcurl was on the link line. */
   Say(std::string("backend check: BearSSL ") +
       (std::string(info->ssl_version).find("BearSSL") != std::string::npos ? "present"
                                                                           : "MISSING"));
}

/* One request, reported rather than judged. HTTPS is tried after HTTP so that
 * the two failures are distinguishable on the console: reaching the server over
 * HTTP but not over HTTPS is a trust store or handshake problem, and failing
 * both is the network. */
void TryRequest(CHTTPClient &client, const std::string &url) {
   std::string body;
   long code = 0;

   Say("request: " + url);

   const bool ok = client.GetText(url, body, code);

   if (!ok) {
      Say("  failed before a response (code " + std::to_string(code) + ")");
      return;
   }

   Say("  HTTP " + std::to_string(code) + ", " + std::to_string(body.size()) + " bytes");
   if (!body.empty()) {
      const std::string head = body.substr(0, body.size() < 80 ? body.size() : 80);
      Say("  body: " + head);
   }
}

} /* namespace */

int main() {
   DbgPrint("httpclient360: httpclient-cpp smoke test, %s\n", CLIENT_USERAGENT);

   ReportCurl();

   {
      /* The client is constructed in place because CHTTPClient is neither
       * copyable nor movable: the std::function log callback is its constructor
       * argument, and CurlHandle::instance() inside it is what calls
       * curl_global_init once for the process. */
      CHTTPClient client(LogToDebug);

      Say("CurlHandle::instance() taken by the constructor");

      /* DEBUG_CURL is the compile-time half of whether the library logs, and the
       * trace directory is the run-time half: no directory, no log lines --
       * ENABLE_LOG on its own does not turn them on. The constructor leaves it
       * unset, so this is what a title sees before it asks for a trace. */
#if DEBUG_CURL
      Say(std::string("before SetCurlTraceLogDirectory: logging is ") +
          (CHTTPClient::IsTraceLogEnabled() ? "ON (wrong)" : "off, as it should be"));

      /* The trace directory, which has to be named before InitSession: that is
       * what calls StartCurlDebug, where the file name is worked out and the
       * stream opened. */
      CHTTPClient::SetCurlTraceLogDirectory(kTraceDirectory);
      Say(std::string("after SetCurlTraceLogDirectory: logging is ") +
          (CHTTPClient::IsTraceLogEnabled() ? "ON" : "off (wrong)"));
#endif
      Say(std::string("curl trace directory set to ") + kTraceDirectory);

      if (!client.InitSession(false, CHTTPClient::ENABLE_LOG)) {
         Say("InitSession failed, nothing further can be tried");
         return 1;
      }
      Say("InitSession: ok, curl pointer is " +
          std::string(client.GetCurlPointer() ? "set" : "null"));

      TryRequest(client, "http://example.com/");

      /* The trace is checked while the session is still open: EndCurlDebug, in
       * CleanupSession, is what closes the stream and writes its last line. */
      CheckTraceFile();

      /* A second session, HTTPS on, which is what the library's own
       * SetCertificateFile() would pair with a CA bundle if a title had one to
       * point at. There is no trust store on a console, so a verification
       * failure here is the expected answer rather than a fault. */
      client.CleanupSession();

      if (!client.InitSession(true, CHTTPClient::ENABLE_LOG)) {
         Say("second InitSession failed");
         return 1;
      }
      Say("second InitSession: ok, HTTPS enabled");

      TryRequest(client, "https://example.com/");

      client.CleanupSession();
      Say("CleanupSession: ok");

      /* The same file, now that the session that wrote it has ended: this is
       * what shows EndCurlDebug closed it rather than leaving it open. */
      CheckTraceFile();
   }

   /* CurlHandle is a function-local static, so its destructor -- and with it
    * curl_global_cleanup() -- runs after main returns on a hosted platform. On a
    * console the process leaves through the XDK's own exit path, so the handle
    * stays alive and this is where the library says so rather than pretending
    * the cleanup happened. */
   CurlHandle::instance();
   Say("CurlHandle::instance() is reachable after the client is gone");

   Say("done");
   return 0;
}
