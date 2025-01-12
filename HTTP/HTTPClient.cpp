/**
 * @file HTTPClient.cpp
 * @brief implementation of the HTTP client class
 * @author Mohamed Amine Mzoughi <mohamed-amine.mzoughi@laposte.net>
 */

#include "HTTPClient.h"

// Static members initialization
std::string CHTTPClient::s_strCertificationAuthorityFile;

#ifdef DEBUG_CURL
std::string CHTTPClient::s_strCurlTraceLogDirectory;
#endif

/**
 * @brief constructor of the HTTP client object
 *
 * @param Logger - a callabck to a logger function void(const std::string&)
 *
 */
CHTTPClient::CHTTPClient(LogFnCallback Logger) : m_oLog(Logger),
                                                 m_iCurlTimeout(0),
                                                 m_bHTTPS(false),
                                                 m_bNoSignal(false),
                                                 m_bProgressCallbackSet(false),
                                                 m_eSettingsFlags(ALL_FLAGS),
                                                 m_pCurlSession(nullptr),
                                                 m_pHeaderlist(nullptr),
                                                 m_curlHandle(CurlHandle::instance())
{
}

/**
 * @brief destructor of the HTTP client object
 *
 */
CHTTPClient::~CHTTPClient()
{
   if (m_pCurlSession != nullptr)
   {
      if (m_eSettingsFlags & ENABLE_LOG)
         m_oLog(LOG_WARNING_OBJECT_NOT_CLEANED);

      CleanupSession();
   }
}

/**
 * @brief Starts a new HTTP session, initializes the cURL API session
 *
 * If a new session was already started, the method has no effect.
 *
 * @param [in] bHTTPS Enable/Disable HTTPS (disabled by default)
 * @param [in] eSettingsFlags optional use | operator to choose multiple options
 *
 * @retval true   Successfully initialized the session.
 * @retval false  The session is already initialized
 * Use CleanupSession() before initializing a new one or the Curl API is not initialized.
 *
 * Example Usage:
 * @code
 *    m_pHTTPClient->InitSession();
 * @endcode
 */
const bool CHTTPClient::InitSession(const bool &bHTTPS /* = false */,
                                    const SettingsFlag &eSettingsFlags /* = ALL_FLAGS */)
{
   if (m_pCurlSession)
   {
      if (eSettingsFlags & ENABLE_LOG)
         m_oLog(LOG_ERROR_CURL_ALREADY_INIT_MSG);

      return false;
   }
   m_pCurlSession = curl_easy_init();

   m_bHTTPS = bHTTPS;
   m_eSettingsFlags = eSettingsFlags;

   return (m_pCurlSession != nullptr);
}

/**
 * @brief Cleans the current HTTP session
 *
 * If a session was not already started, the method has no effect
 *
 * @retval true   Successfully cleaned the current session.
 * @retval false  The session is not already initialized.
 *
 * Example Usage:
 * @code
 *    m_pHTTPClient->CleanupSession();
 * @endcode
 */
const bool CHTTPClient::CleanupSession()
{
   if (!m_pCurlSession)
   {
      if (m_eSettingsFlags & ENABLE_LOG)
         m_oLog(LOG_ERROR_CURL_NOT_INIT_MSG);

      return false;
   }

#ifdef DEBUG_CURL
   if (m_ofFileCurlTrace.is_open())
   {
      m_ofFileCurlTrace.close();
   }
#endif

   curl_easy_cleanup(m_pCurlSession);
   m_pCurlSession = nullptr;

   if (m_pHeaderlist)
   {
      curl_slist_free_all(m_pHeaderlist);
      m_pHeaderlist = nullptr;
   }

   return true;
}

/**
 * @brief sets the progress function callback and the owner of the client
 *
 * @param [in] pOwner pointer to the object owning the client, nullptr otherwise
 * @param [in] fnCallback callback to progress function
 *
 */
/*inline*/ void CHTTPClient::SetProgressFnCallback(void *pOwner, const ProgressFnCallback &fnCallback)
{
   m_ProgressStruct.pOwner = pOwner;
   m_fnProgressCallback = fnCallback;
   m_ProgressStruct.pCurl = m_pCurlSession;
   m_ProgressStruct.dLastRunTime = 0;
   m_bProgressCallbackSet = true;
}

/**
 * @brief sets the HTTP Proxy address to tunnel the operation through it
 *
 * @param [in] strProxy URI of the HTTP Proxy
 *
 */
/*inline*/ void CHTTPClient::SetProxy(const std::string &strProxy)
{
   if (strProxy.empty())
      return;

   std::string strUri = strProxy;
   std::transform(strUri.begin(), strUri.end(), strUri.begin(), ::toupper);

   if (strUri.compare(0, 4, "HTTP") != 0)
      m_strProxy = "http://" + strProxy;
   else
      m_strProxy = strProxy;
};

/**
 * @brief checks a URI
 * adds the proper protocol scheme (HTTP:// or HTTPS://)
 * if the URI has no protocol scheme, the added protocol scheme
 * will depend on m_bHTTPS that can be set when initializing a session
 * or with the SetHTTPS(bool)
 *
 * @param [in] strURL user URI
 */
inline void CHTTPClient::UpdateURL(const std::string &strURL)
{
   std::string strTmp = strURL;

   std::transform(strTmp.begin(), strTmp.end(), strTmp.begin(), ::toupper);

   if (strTmp.compare(0, 7, "HTTP://") == 0)
      m_bHTTPS = false;
   else if (strTmp.compare(0, 8, "HTTPS://") == 0)
      m_bHTTPS = true;
   else
   {
      m_strURL = ((m_bHTTPS) ? "https://" : "http://") + strURL;
      return;
   }
   m_strURL = strURL;
}

/**
 * @brief performs the chosen HTTP request
 * sets up the common settings (Timeout, proxy,...)
 *
 *
 * @retval true   Successfully performed the request.
 * @retval false  An error occured while CURL was performing the request.
 */
const CURLcode CHTTPClient::Perform()
{
   if (!m_pCurlSession)
   {
      if (m_eSettingsFlags & ENABLE_LOG)
         m_oLog(LOG_ERROR_CURL_NOT_INIT_MSG);

      return CURLE_FAILED_INIT;
   }

   CURLcode res = CURLE_OK;

   curl_easy_setopt(m_pCurlSession, CURLOPT_URL, m_strURL.c_str());

   AddHeader("User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0)");

   if (m_Cookies.size() > 0)
   {
        std::string cookie;
        for (std::map<std::string, std::string>::iterator it = m_Cookies.begin(); it != m_Cookies.end();)
        {
            cookie.append(it->first).append("=").append(it->second);
            if (std::next(it, 1) != m_Cookies.end())
            {
                cookie.append("; ");
            }
            ++it;
        }
        AddHeader("Cookie:" + cookie);
   }

   if (m_pHeaderlist != nullptr)
      curl_easy_setopt(m_pCurlSession, CURLOPT_HTTPHEADER, m_pHeaderlist);

   curl_easy_setopt(m_pCurlSession, CURLOPT_USERAGENT, CLIENT_USERAGENT);
   curl_easy_setopt(m_pCurlSession, CURLOPT_AUTOREFERER, 1L);
   curl_easy_setopt(m_pCurlSession, CURLOPT_FOLLOWLOCATION, 1L);
   curl_easy_setopt(m_pCurlSession, CURLOPT_UNRESTRICTED_AUTH, 1L);

   if (m_iCurlTimeout > 0)
   {
      curl_easy_setopt(m_pCurlSession, CURLOPT_TIMEOUT, m_iCurlTimeout);
      // don't want to get a sig alarm on timeout
      curl_easy_setopt(m_pCurlSession, CURLOPT_NOSIGNAL, 1);
   }

   if (!m_strProxy.empty())
   {
      curl_easy_setopt(m_pCurlSession, CURLOPT_PROXY, m_strProxy.c_str());
      curl_easy_setopt(m_pCurlSession, CURLOPT_HTTPPROXYTUNNEL, 1L);
   }

   if (m_bNoSignal)
   {
      curl_easy_setopt(m_pCurlSession, CURLOPT_NOSIGNAL, 1L);
   }

   if (m_bProgressCallbackSet)
   {
      curl_easy_setopt(m_pCurlSession, CURLOPT_PROGRESSFUNCTION, *GetProgressFnCallback());
      curl_easy_setopt(m_pCurlSession, CURLOPT_PROGRESSDATA, &m_ProgressStruct);
      curl_easy_setopt(m_pCurlSession, CURLOPT_NOPROGRESS, 0L);
   }

   if (!m_Username.empty())
   {
      curl_easy_setopt(m_pCurlSession, CURLOPT_USERNAME, m_Username.c_str());
   }

   if (!m_Password.empty())
   {
      curl_easy_setopt(m_pCurlSession, CURLOPT_PASSWORD, m_Password.c_str());
   }

   if (m_bHTTPS)
   {
      // SSL (TLS)
      curl_easy_setopt(m_pCurlSession, CURLOPT_USE_SSL, CURLUSESSL_ALL);
      curl_easy_setopt(m_pCurlSession, CURLOPT_SSL_VERIFYPEER, (m_eSettingsFlags & VERIFY_PEER) ? 1L : 0L);
      curl_easy_setopt(m_pCurlSession, CURLOPT_SSL_VERIFYHOST, (m_eSettingsFlags & VERIFY_HOST) ? 2L : 0L);
   }

   if (m_bHTTPS && !s_strCertificationAuthorityFile.empty())
      curl_easy_setopt(m_pCurlSession, CURLOPT_CAINFO, s_strCertificationAuthorityFile.c_str());

   if (m_bHTTPS && !m_strSSLCertFile.empty())
      curl_easy_setopt(m_pCurlSession, CURLOPT_SSLCERT, m_strSSLCertFile.c_str());

   if (m_bHTTPS && !m_strSSLKeyFile.empty())
      curl_easy_setopt(m_pCurlSession, CURLOPT_SSLKEY, m_strSSLKeyFile.c_str());

   if (m_bHTTPS && !m_strSSLKeyPwd.empty())
      curl_easy_setopt(m_pCurlSession, CURLOPT_KEYPASSWD, m_strSSLKeyPwd.c_str());

#ifdef DEBUG_CURL
   StartCurlDebug();
#endif

   // Perform the requested operation
   res = curl_easy_perform(m_pCurlSession);

#ifdef DEBUG_CURL
   EndCurlDebug();
#endif

   if (m_pHeaderlist)
   {
      curl_slist_free_all(m_pHeaderlist);
      m_pHeaderlist = nullptr;
   }

   return res;
}

/**
 * @brief requests the content of a URI
 *
 * @param [in] strURL URI of the remote location (with the file name) encoded in UTF-8 format.
 * @param [out] strOutput reference to an output string.
 * @param [out] lHTTPStatusCode HTTP Status code of the response.
 *
 * @retval true   Successfully requested the URI.
 * @retval false  Encountered a problem.
 *
 * Example Usage:
 * @code
 *    std::string strWebPage;
 *    long lHTTPStatusCode = 0;
 *    m_pHTTOClient->GetText("https://www.google.com", strWebPage, lHTTPStatusCode);
 * @endcode
 */
const bool CHTTPClient::GetText(const std::string &strURL,
                                std::string &strOutput,
                                long &lHTTPStatusCode)
{
   if (strURL.empty())
   {
      if (m_eSettingsFlags & ENABLE_LOG)
         m_oLog(LOG_ERROR_EMPTY_HOST_MSG);

      return false;
   }
   if (!m_pCurlSession)
   {
      if (m_eSettingsFlags & ENABLE_LOG)
         m_oLog(LOG_ERROR_CURL_NOT_INIT_MSG);

      return false;
   }
   // Reset is mandatory to avoid bad surprises
   curl_easy_reset(m_pCurlSession);

   UpdateURL(strURL);

   curl_easy_setopt(m_pCurlSession, CURLOPT_HTTPGET, 1L);
   curl_easy_setopt(m_pCurlSession, CURLOPT_WRITEFUNCTION, WriteInStringCallback);
   curl_easy_setopt(m_pCurlSession, CURLOPT_WRITEDATA, &strOutput);

   CURLcode res = Perform();

   curl_easy_getinfo(m_pCurlSession, CURLINFO_RESPONSE_CODE, &lHTTPStatusCode);

   // Check for errors
   if (res != CURLE_OK)
   {
      if (m_eSettingsFlags & ENABLE_LOG)
         m_oLog(StringFormat(LOG_ERROR_CURL_REQ_FAILURE_FORMAT, m_strURL.c_str(), res,
                             curl_easy_strerror(res), lHTTPStatusCode));

      return false;
   }

   return true;
}

/**
 * @brief Downloads a remote file to a local file.
 *
 * @param [in] strLocalFile Complete path of the local file to download in UTF-8 format.
 * @param [in] strURL URI of the remote location (with the file name) encoded in UTF-8 format.
 * @param [out] lHTTPStatusCode HTTP Status code of the response.
 *
 * @retval true   Successfully downloaded the file.
 * @retval false  The file couldn't be downloaded. Check the log messages for more information.
 */
const bool CHTTPClient::DownloadFile(const std::string &strLocalFile,
                                     const std::string &strURL,
                                     long &lHTTPStatusCode)
{
   if (strURL.empty() || strLocalFile.empty())
      return false;

   if (!m_pCurlSession)
   {
      if (m_eSettingsFlags & ENABLE_LOG)
         m_oLog(LOG_ERROR_CURL_NOT_INIT_MSG);

      return false;
   }
   // Reset is mandatory to avoid bad surprises
   curl_easy_reset(m_pCurlSession);

   UpdateURL(strURL);

   std::ofstream ofsOutput;
   ofsOutput.open(
       strLocalFile, // UTF-8
       std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);

   if (ofsOutput)
   {
      curl_easy_setopt(m_pCurlSession, CURLOPT_HTTPGET, 1L);
      curl_easy_setopt(m_pCurlSession, CURLOPT_WRITEFUNCTION, WriteToFileCallback);
      curl_easy_setopt(m_pCurlSession, CURLOPT_WRITEDATA, &ofsOutput);

      CURLcode res = Perform();

      ofsOutput.close();
      curl_easy_getinfo(m_pCurlSession, CURLINFO_RESPONSE_CODE, &lHTTPStatusCode);

      // double dUploadLength = 0;
      // curl_easy_getinfo(m_pCurlSession, CURLINFO_CONTENT_LENGTH_UPLOAD, &dUploadLength); // number of bytes uploaded

      /* Delete downloaded file if status code != 200 as server's response body may
      contain error 404 */
      if (lHTTPStatusCode != 200)
         remove(strLocalFile.c_str());

      if (res != CURLE_OK)
      {
         if (m_eSettingsFlags & ENABLE_LOG)
            m_oLog(StringFormat(LOG_ERROR_CURL_DOWNLOAD_FAILURE_FORMAT, strLocalFile.c_str(),
                                strURL.c_str(), res, curl_easy_strerror(res), lHTTPStatusCode));

         return false;
      }
   }
   else if (m_eSettingsFlags & ENABLE_LOG)
   {
      m_oLog(StringFormat(LOG_ERROR_DOWNLOAD_FILE_FORMAT, strLocalFile.c_str()));

      return false;
   }

   return true;
}

const bool CHTTPClient::UploadFile(const std::string &strLocalFile,
                                     const std::string &strURL,
                                     long &lHTTPStatusCode)
{
   if (strURL.empty() || strLocalFile.empty())
      return false;

   if (!m_pCurlSession)
   {
      if (m_eSettingsFlags & ENABLE_LOG)
         m_oLog(LOG_ERROR_CURL_NOT_INIT_MSG);

      return false;
   }
   // Reset is mandatory to avoid bad surprises
   curl_easy_reset(m_pCurlSession);

   UpdateURL(strURL);

   std::ifstream ifsInput(strLocalFile, std::ios::binary | std::ios::ate);
   auto size = ifsInput.tellg();

   ifsInput.seekg(0);

   if (ifsInput)
   {
      curl_easy_setopt(m_pCurlSession, CURLOPT_UPLOAD, 1L);
      curl_easy_setopt(m_pCurlSession, CURLOPT_READFUNCTION, ReadFromFileCallback);
      curl_easy_setopt(m_pCurlSession, CURLOPT_READDATA, &ifsInput);
      curl_easy_setopt(m_pCurlSession, CURLOPT_INFILESIZE_LARGE, size);

      CURLcode res = Perform();

      ifsInput.close();
      curl_easy_getinfo(m_pCurlSession, CURLINFO_RESPONSE_CODE, &lHTTPStatusCode);

      if (res != CURLE_OK)
      {
         if (m_eSettingsFlags & ENABLE_LOG)
            m_oLog(StringFormat(LOG_ERROR_CURL_DOWNLOAD_FAILURE_FORMAT, strLocalFile.c_str(),
                                strURL.c_str(), res, curl_easy_strerror(res), lHTTPStatusCode));

         return false;
      }
   }
   else if (m_eSettingsFlags & ENABLE_LOG)
   {
      m_oLog(StringFormat(LOG_ERROR_DOWNLOAD_FILE_FORMAT, strLocalFile.c_str()));

      return false;
   }

   return true;
}

/**
 * @brief downloads a remote file to memory
 *
 * @param [out] data vector of bytes
 * @param [in] strURL URI of the remote location (with the file name) encoded in UTF-8 format.
 * @param [out] lHTTPStatusCode HTTP Status code of the response.
 *
 * @retval true   Successfully downloaded the file.
 * @retval false  The content couldn't be downloaded. Check the log messages for
 * more information.
 */
const bool CHTTPClient::DownloadFile(std::vector<unsigned char> &data, const std::string &strURL, long &lHTTPStatusCode)
{
   if (strURL.empty())
      return false;

   if (!m_pCurlSession)
   {
      if (m_eSettingsFlags & ENABLE_LOG)
         m_oLog(LOG_ERROR_CURL_NOT_INIT_MSG);

      return false;
   }

   data.clear();

   // Reset is mandatory to avoid bad surprises
   curl_easy_reset(m_pCurlSession);

   UpdateURL(strURL);

   curl_easy_setopt(m_pCurlSession, CURLOPT_HTTPGET, 1L);
   curl_easy_setopt(m_pCurlSession, CURLOPT_WRITEFUNCTION, WriteToMemoryCallback);
   curl_easy_setopt(m_pCurlSession, CURLOPT_WRITEDATA, &data);

   CURLcode res = Perform();

   curl_easy_getinfo(m_pCurlSession, CURLINFO_RESPONSE_CODE, &lHTTPStatusCode);

   if (res != CURLE_OK)
   {
      if (m_eSettingsFlags & ENABLE_LOG)
         m_oLog(StringFormat(LOG_ERROR_CURL_DOWNLOAD_FAILURE_FORMAT, "Download to a byte buffer",
                             strURL.c_str(), res, curl_easy_strerror(res), lHTTPStatusCode));

      return false;
   }

   return true;
}

/**
 * @brief uploads a POST form
 *
 *
 * @param [in] strURL URL to which the form will be posted encoded in UTF-8 format.
 * @param [in] data post form information
 * @param [out] lHTTPStatusCode HTTP Status code of the response.
 *
 * @retval true   Successfully posted the header.
 * @retval false  The header couldn't be posted.
 */
const bool CHTTPClient::UploadForm(const std::string &strURL,
                                   const CHTTPClient::HeadersMap &Headers,
                                   const PostFormInfo &data,
                                   CHTTPClient::HttpResponse &Response)
{
   if (InitRestRequest(strURL, Headers, Response))
   {
      /** Now specify we want to POST data */
      curl_easy_setopt(m_pCurlSession, CURLOPT_POST, 1L);

      /* stating that Expect: 100-continue is not wanted */
      AddHeader("Expect:");

      /** set post form */
      if (data.m_pFormPost != nullptr)
         curl_easy_setopt(m_pCurlSession, CURLOPT_HTTPPOST, data.m_pFormPost);

      CURLcode res = Perform();

      return PostRestRequest(res, Response);
   }
   else
   {
      return false;
   }
}

/**
 * @brief PostFormInfo constructor
 */
CHTTPClient::PostFormInfo::PostFormInfo() : m_pFormPost(nullptr), m_pLastFormptr(nullptr)
{
}

/**
 * @brief PostFormInfo destructor
 */
CHTTPClient::PostFormInfo::~PostFormInfo()
{
   // cleanup the formpost chain
   if (m_pFormPost)
   {
      curl_formfree(m_pFormPost);
      m_pFormPost = nullptr;
      m_pLastFormptr = nullptr;
   }
}

/**
 * @brief set the name and the value of the HTML "file" form's input
 *
 * @param fieldName name of the "file" input encoded in UTF8.
 * @param fieldValue path to the file to upload encoded in UTF8.
 */
void CHTTPClient::PostFormInfo::AddFormFile(const std::string &strFieldName,
                                            const std::string &strFieldValue)
{
   curl_formadd(&m_pFormPost, &m_pLastFormptr,
                CURLFORM_COPYNAME, strFieldName.c_str(),
                CURLFORM_FILE, strFieldValue.c_str(),
                CURLFORM_END);
}

/**
 * @brief set the name and the value of an HTML form's input
 * (other than "file" like "text", "hidden" or "submit")
 *
 * @param fieldName name of the input element encoded in UTF8 for Linux and in ANSI for Windows (so the file gets located and uploaded).
 * @param fieldValue value to be assigned to the input element encoded in UTF8 for Linux and in ANSI for Windows.
 */
void CHTTPClient::PostFormInfo::AddFormContent(const std::string &strFieldName,
                                               const std::string &strFieldValue)
{
   curl_formadd(&m_pFormPost, &m_pLastFormptr,
                CURLFORM_COPYNAME, strFieldName.c_str(),
                CURLFORM_COPYCONTENTS, strFieldValue.c_str(),
                CURLFORM_END);
}

// REST REQUESTS

/**
 * @brief initializes a REST request
 * some common operations to REST requests are performed here,
 * the others are performed in Perform method
 *
 * @param [in] strUrl URI encoded in UTF-8 format.
 * @param [in] Headers headers to send
 * @param [out] Response response data
 */
inline const bool CHTTPClient::InitRestRequest(const std::string &strUrl,
                                               const CHTTPClient::HeadersMap &Headers,
                                               CHTTPClient::HttpResponse &Response)
{
   if (strUrl.empty())
   {
      if (m_eSettingsFlags & ENABLE_LOG)
         m_oLog(LOG_ERROR_EMPTY_HOST_MSG);

      return false;
   }
   if (!m_pCurlSession)
   {
      if (m_eSettingsFlags & ENABLE_LOG)
         m_oLog(LOG_ERROR_CURL_NOT_INIT_MSG);

      return false;
   }
   // Reset is mandatory to avoid bad surprises
   curl_easy_reset(m_pCurlSession);

   UpdateURL(strUrl);

   // set the received body's callback function
   curl_easy_setopt(m_pCurlSession, CURLOPT_WRITEFUNCTION, &CHTTPClient::RestWriteCallback);

   // set data object to pass to callback function above
   curl_easy_setopt(m_pCurlSession, CURLOPT_WRITEDATA, &Response);

   // set the response's headers processing callback function
   curl_easy_setopt(m_pCurlSession, CURLOPT_HEADERFUNCTION, &CHTTPClient::RestHeaderCallback);

   // callback object for server's responses headers
   curl_easy_setopt(m_pCurlSession, CURLOPT_HEADERDATA, &Response);

   std::string strHeader;
   for (HeadersMap::const_iterator it = Headers.cbegin();
        it != Headers.cend();
        ++it)
   {
      strHeader = it->first + ": " + it->second; // build header string
      AddHeader(strHeader);
   }

   return true;
}

/**
 * @brief post REST request operations are performed here
 *
 * @param [in] ePerformCode curl easy perform returned code
 * @param [out] Response response data
 */
inline const bool CHTTPClient::PostRestRequest(const CURLcode ePerformCode,
                                               CHTTPClient::HttpResponse &Response)
{
   // Check for errors
   if (ePerformCode != CURLE_OK)
   {
      Response.strBody.clear();
      Response.iCode = -1;
      Response.errMessage = curl_easy_strerror(ePerformCode);

      if (m_eSettingsFlags & ENABLE_LOG)
         m_oLog(StringFormat(LOG_ERROR_CURL_REST_FAILURE_FORMAT, m_strURL.c_str(), ePerformCode,
                             Response.errMessage.c_str()));

      return false;
   }
   long lHttpCode = 0;
   curl_easy_getinfo(m_pCurlSession, CURLINFO_RESPONSE_CODE, &lHttpCode);
   Response.iCode = static_cast<int>(lHttpCode);

   return true;
}

/**
 * @brief performs a HEAD request
 *
 * @param [in] strUrl url to request encoded in UTF-8 format.
 * @param [in] Headers headers to send
 * @param [out] Response response data
 *
 * @retval true   Successfully requested the URI.
 * @retval false  Encountered a problem.
 */
const bool CHTTPClient::Head(const std::string &strUrl,
                             const CHTTPClient::HeadersMap &Headers,
                             CHTTPClient::HttpResponse &Response)
{
   if (InitRestRequest(strUrl, Headers, Response))
   {
      /** set HTTP HEAD METHOD */
      curl_easy_setopt(m_pCurlSession, CURLOPT_CUSTOMREQUEST, "HEAD");
      curl_easy_setopt(m_pCurlSession, CURLOPT_NOBODY, 1L);

      CURLcode res = Perform();

      return PostRestRequest(res, Response);
   }
   else
      return false;
}

/**
 * @brief performs a GET request
 *
 * @param [in] strUrl url to request encoded in UTF-8 format.
 * @param [in] Headers headers to send
 * @param [out] Response response data
 *
 * @retval true   Successfully requested the URI.
 * @retval false  Encountered a problem.
 */
const bool CHTTPClient::Get(const std::string &strUrl,
                            const CHTTPClient::HeadersMap &Headers,
                            CHTTPClient::HttpResponse &Response)
{
   if (InitRestRequest(strUrl, Headers, Response))
   {
      // specify a GET request
      curl_easy_setopt(m_pCurlSession, CURLOPT_HTTPGET, 1L);

      CURLcode res = Perform();

      return PostRestRequest(res, Response);
   }
   else
      return false;
}

const bool CHTTPClient::CustomRequest(const std::string &method,
                                      const std::string &strUrl,
                                      const HeadersMap &Headers,
                                      HttpResponse &Response)
{
   if (InitRestRequest(strUrl, Headers, Response))
   {
      // specify a GET request
      curl_easy_setopt(m_pCurlSession, CURLOPT_CUSTOMREQUEST, method.c_str());

      CURLcode res = Perform();

      return PostRestRequest(res, Response);
   }
   else
      return false;
}

/**
 * @brief performs a DELETE request
 *
 * @param [in] strUrl url to request encoded in UTF-8 format.
 * @param [in] Headers headers to send
 * @param [out] Response response data
 *
 * @retval true   Successfully requested the URI.
 * @retval false  Encountered a problem.
 */
const bool CHTTPClient::Del(const std::string &strUrl,
                            const CHTTPClient::HeadersMap &Headers,
                            CHTTPClient::HttpResponse &Response)
{
   if (InitRestRequest(strUrl, Headers, Response))
   {
      curl_easy_setopt(m_pCurlSession, CURLOPT_CUSTOMREQUEST, "DELETE");

      CURLcode res = Perform();

      return PostRestRequest(res, Response);
   }
   else
      return false;
}

const bool CHTTPClient::Post(const std::string &strUrl,
                             const CHTTPClient::HeadersMap &Headers,
                             const std::string &strPostData,
                             CHTTPClient::HttpResponse &Response)
{
   if (InitRestRequest(strUrl, Headers, Response))
   {
      // specify a POST request
      curl_easy_setopt(m_pCurlSession, CURLOPT_POST, 1L);

      // set post informations
      curl_easy_setopt(m_pCurlSession, CURLOPT_POSTFIELDS, strPostData.c_str());
      curl_easy_setopt(m_pCurlSession, CURLOPT_POSTFIELDSIZE, strPostData.size());

      CURLcode res = Perform();

      return PostRestRequest(res, Response);
   }
   else
      return false;
}

/**
 * @brief performs a PUT request with a string
 *
 * @param [in] strUrl url to request encoded in UTF-8 format.
 * @param [in] Headers headers to send
 * @param [out] Response response data
 *
 * @retval true   Successfully requested the URI.
 * @retval false  Encountered a problem.
 */
const bool CHTTPClient::Put(const std::string &strUrl, const CHTTPClient::HeadersMap &Headers,
                            const std::string &strPutData, CHTTPClient::HttpResponse &Response)
{
   if (InitRestRequest(strUrl, Headers, Response))
   {
      CHTTPClient::UploadObject Payload;

      Payload.pszData = strPutData.c_str();
      Payload.usLength = strPutData.size();

      // specify a PUT request
      curl_easy_setopt(m_pCurlSession, CURLOPT_PUT, 1L);
      curl_easy_setopt(m_pCurlSession, CURLOPT_UPLOAD, 1L);

      // set read callback function
      curl_easy_setopt(m_pCurlSession, CURLOPT_READFUNCTION, &CHTTPClient::RestReadCallback);
      // set data object to pass to callback function
      curl_easy_setopt(m_pCurlSession, CURLOPT_READDATA, &Payload);

      // set data size
      curl_easy_setopt(m_pCurlSession, CURLOPT_INFILESIZE, static_cast<long>(Payload.usLength));

      CURLcode res = Perform();

      return PostRestRequest(res, Response);
   }
   else
      return false;
}

/**
 * @brief performs a PUT request with a byte buffer (vector of char)
 *
 * @param [in] strUrl url to request encoded in UTF-8 format.
 * @param [in] Headers headers to send
 * @param [out] Response response data
 *
 * @retval true   Successfully requested the URI.
 * @retval false  Encountered a problem.
 */
const bool CHTTPClient::Put(const std::string &strUrl, const CHTTPClient::HeadersMap &Headers,
                            const CHTTPClient::ByteBuffer &Data, CHTTPClient::HttpResponse &Response)
{
   if (InitRestRequest(strUrl, Headers, Response))
   {
      CHTTPClient::UploadObject Payload;

      Payload.pszData = Data.data();
      Payload.usLength = Data.size();

      // specify a PUT request
      curl_easy_setopt(m_pCurlSession, CURLOPT_PUT, 1L);
      curl_easy_setopt(m_pCurlSession, CURLOPT_UPLOAD, 1L);

      // set read callback function
      curl_easy_setopt(m_pCurlSession, CURLOPT_READFUNCTION, &CHTTPClient::RestReadCallback);
      // set data object to pass to callback function
      curl_easy_setopt(m_pCurlSession, CURLOPT_READDATA, &Payload);

      // set data size
      curl_easy_setopt(m_pCurlSession, CURLOPT_INFILESIZE, static_cast<long>(Payload.usLength));

      CURLcode res = Perform();

      return PostRestRequest(res, Response);
   }
   else
      return false;
}

// STRING HELPERS

/**
 * @brief returns a formatted string
 *
 * @param [in] strFormat string with one or many format specifiers
 * @param [in] parameters to be placed in the format specifiers of strFormat
 *
 * @retval string formatted string
 */
std::string CHTTPClient::StringFormat(std::string strFormat, ...)
{
   va_list args;
   va_start(args, strFormat);
   size_t len = vsnprintf(NULL, 0, strFormat.c_str(), args);
   va_end(args);
   std::vector<char> vec(len + 1);
   va_start(args, strFormat);
   vsnprintf(&vec[0], len + 1, strFormat.c_str(), args);
   va_end(args);
   return &vec[0];
}

/**
 * @brief removes leading and trailing whitespace from a string
 *
 * @param [in/out] str string to be trimmed
 */
inline void CHTTPClient::TrimSpaces(std::string &str)
{
   // trim from left
   str.erase(str.begin(),
             std::find_if(str.begin(), str.end(), [](char c)
                          { return !isspace(c); }));

   // trim from right
   str.erase(std::find_if(str.rbegin(), str.rend(), [](char c)
                          { return !isspace(c); })
                 .base(),
             str.end());
}

inline void CHTTPClient::ToLower(std::string& str)
{
   std::transform(str.begin(), str.end(), str.begin(),
    [](unsigned char c){ return std::tolower(c); });
}

// CURL CALLBACKS

size_t CHTTPClient::ThrowAwayCallback(void *ptr, size_t size, size_t nmemb, void *data)
{
   reinterpret_cast<void *>(ptr);
   reinterpret_cast<void *>(data);

   /* we are not interested in the headers itself,
   so we only return the size we would have saved ... */
   return size * nmemb;
}

/**
 * @brief stores the server response in a string
 *
 * @param ptr pointer of max size (size*nmemb) to read data from it
 * @param size size parameter
 * @param nmemb memblock parameter
 * @param data pointer to user data (string)
 *
 * @return (size * nmemb)
 */
size_t CHTTPClient::WriteInStringCallback(void *ptr, size_t size, size_t nmemb, void *data)
{
   std::string *strWriteHere = reinterpret_cast<std::string *>(data);
   if (strWriteHere != nullptr)
   {
      strWriteHere->append(reinterpret_cast<char *>(ptr), size * nmemb);
      return size * nmemb;
   }
   return 0;
}

/**
 * @brief stores the server response in an already opened file stream
 * used by DownloadFile()
 *
 * @param buff pointer of max size (size*nmemb) to read data from it
 * @param size size parameter
 * @param nmemb memblock parameter
 * @param userdata pointer to user data (file stream)
 *
 * @return (size * nmemb)
 */
size_t CHTTPClient::WriteToFileCallback(void *buff, size_t size, size_t nmemb, void *data)
{
   if ((size == 0) || (nmemb == 0) || ((size * nmemb) < 1) || (data == nullptr))
      return 0;

   std::ofstream *pFileStream = reinterpret_cast<std::ofstream *>(data);
   if (pFileStream->is_open())
   {
      pFileStream->write(reinterpret_cast<char *>(buff), size * nmemb);
   }

   return size * nmemb;
}

/**
 * @brief stores the server response in std::vector<char>
 *
 * @param buff pointer of max size (size*nmemb) to read data from it
 * @param size size parameter
 * @param nmemb memblock parameter
 * @param userdata pointer to user data (file stream)
 *
 * @return (size * nmemb)
 */
size_t CHTTPClient::WriteToMemoryCallback(void *buff, size_t size, size_t nmemb, void *data)
{
   if ((size == 0) || (nmemb == 0) || (data == nullptr))
      return 0;

   auto *vec = reinterpret_cast<std::vector<unsigned char> *>(data);
   size_t ssize = size * nmemb;
   std::copy(reinterpret_cast<unsigned char *>(buff), reinterpret_cast<unsigned char *>(buff) + ssize,
             std::back_inserter(*vec));

   return ssize;
}

/**
 * @brief reads the content of an already opened file stream
 * used by UploadFile()
 *
 * @param ptr pointer of max size (size*nmemb) to write data to it
 * @param size size parameter
 * @param nmemb memblock parameter
 * @param stream pointer to user data (file stream)
 *
 * @return (size * nmemb)
 */
size_t CHTTPClient::ReadFromFileCallback(void *ptr, size_t size, size_t nmemb, void *stream)
{
   std::ifstream *pFileStream = reinterpret_cast<std::ifstream *>(stream);
   if (pFileStream->is_open())
   {
      pFileStream->read(reinterpret_cast<char *>(ptr), size * nmemb);
      return pFileStream->gcount();
   }
   return 0;
}

// REST CALLBACKS

/**
 * @brief write callback function for libcurl
 * this callback will be called to store the server's Body reponse
 * in a struct response
 *
 * we can also use an std::vector<char> instead of an std::string but in this case
 * there isn't a big difference... maybe resizing the container with a max size can
 * enhance performances...
 *
 * @param data returned data of size (size*nmemb)
 * @param size size parameter
 * @param nmemb memblock parameter
 * @param userdata pointer to user data to save/work with return data
 *
 * @return (size * nmemb)
 */
size_t CHTTPClient::RestWriteCallback(void *pCurlData, size_t usBlockCount, size_t usBlockSize, void *pUserData)
{
   CHTTPClient::HttpResponse *pServerResponse;
   pServerResponse = reinterpret_cast<CHTTPClient::HttpResponse *>(pUserData);
   const char* begin = reinterpret_cast<char *>(pCurlData);
   const char* end = begin + (usBlockCount * usBlockSize);
   pServerResponse->strBody.insert(pServerResponse->strBody.end(), begin, end);

   return (usBlockCount * usBlockSize);
}

/**
 * @brief header callback for libcurl
 * callback used to process response's headers (received)
 *
 * @param data returned (header line)
 * @param size of data
 * @param nmemb memblock
 * @param userdata pointer to user data object to save header data
 * @return size * nmemb;
 */
size_t CHTTPClient::RestHeaderCallback(void *pCurlData, size_t usBlockCount, size_t usBlockSize, void *pUserData)
{
   CHTTPClient::HttpResponse *pServerResponse;
   pServerResponse = reinterpret_cast<CHTTPClient::HttpResponse *>(pUserData);

   std::string strHeader(reinterpret_cast<char *>(pCurlData), usBlockCount * usBlockSize);
   size_t usSeperator = strHeader.find_first_of(":");
   if (std::string::npos == usSeperator)
   {
      // roll with non seperated headers or response's line
      TrimSpaces(strHeader);
      if (0 == strHeader.length())
      {
         return (usBlockCount * usBlockSize); // blank line;
      }
      pServerResponse->mapHeaders[strHeader] = "present";
      ToLower(strHeader);
      pServerResponse->mapHeadersLowercase[strHeader] = "present";
   }
   else
   {
      std::string strKey = strHeader.substr(0, usSeperator);
      TrimSpaces(strKey);
      std::string strValue = strHeader.substr(usSeperator + 1);
      TrimSpaces(strValue);
      pServerResponse->mapHeaders[strKey] = strValue;
      ToLower(strKey);
      pServerResponse->mapHeadersLowercase[strKey] = strValue;

      if (strKey.compare("set-cookie") == 0)
      {
         std::vector<std::string> cookies = Split(strValue, ";");
         for (std::vector<std::string>::iterator it = cookies.begin(); it != cookies.end();)
         {
            std::vector<std::string> cookie = Split(*it, "=");
            TrimSpaces(cookie[0]);
            TrimSpaces(cookie[1]);
            if (ignore_cookie_keys.find(cookie[0]) == ignore_cookie_keys.end())
            {
                  if (cookie.size() > 1)
                     pServerResponse->cookies[cookie[0]] = cookie[1];
                  else
                     pServerResponse->cookies[cookie[0]] = "";
            }
            ++it;
         }
      }
   }

   return (usBlockCount * usBlockSize);
}

std::string CHTTPClient::GetMessage(CURLcode code)
{
   return std::string(curl_easy_strerror(code));
}

std::string CHTTPClient::EncodeUrl(const std::string &s)
{
   std::string result;
   result.reserve(s.size());

   for (size_t i = 0; s[i]; i++)
   {
      switch (s[i])
      {
      case ' ':
         result += "%20";
         break;
      case '+':
         result += "%2B";
         break;
      case '\r':
         result += "%0D";
         break;
      case '\n':
         result += "%0A";
         break;
      case '\'':
         result += "%27";
         break;
      case ',':
         result += "%2C";
         break;
      // case ':': result += "%3A"; break; // ok? probably...
      case ';':
         result += "%3B";
         break;
      default:
         auto c = static_cast<uint8_t>(s[i]);
         if (c >= 0x80)
         {
            result += '%';
            char hex[4];
            auto len = snprintf(hex, sizeof(hex) - 1, "%02X", c);
            assert(len == 2);
            result.append(hex, static_cast<size_t>(len));
         }
         else
         {
            result += s[i];
         }
         break;
      }
   }

   return result;
}

std::string from_i_to_hex(size_t n)
{
   static const auto charset = "0123456789abcdef";
   std::string ret;
   do
   {
      ret = charset[n & 15] + ret;
      n >>= 4;
   } while (n > 0);
   return ret;
}

size_t to_utf8(int code, char *buff)
{
   if (code < 0x0080)
   {
      buff[0] = (code & 0x7F);
      return 1;
   }
   else if (code < 0x0800)
   {
      buff[0] = static_cast<char>(0xC0 | ((code >> 6) & 0x1F));
      buff[1] = static_cast<char>(0x80 | (code & 0x3F));
      return 2;
   }
   else if (code < 0xD800)
   {
      buff[0] = static_cast<char>(0xE0 | ((code >> 12) & 0xF));
      buff[1] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
      buff[2] = static_cast<char>(0x80 | (code & 0x3F));
      return 3;
   }
   else if (code < 0xE000)
   { // D800 - DFFF is invalid...
      return 0;
   }
   else if (code < 0x10000)
   {
      buff[0] = static_cast<char>(0xE0 | ((code >> 12) & 0xF));
      buff[1] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
      buff[2] = static_cast<char>(0x80 | (code & 0x3F));
      return 3;
   }
   else if (code < 0x110000)
   {
      buff[0] = static_cast<char>(0xF0 | ((code >> 18) & 0x7));
      buff[1] = static_cast<char>(0x80 | ((code >> 12) & 0x3F));
      buff[2] = static_cast<char>(0x80 | ((code >> 6) & 0x3F));
      buff[3] = static_cast<char>(0x80 | (code & 0x3F));
      return 4;
   }

   // NOTREACHED
   return 0;
}

bool is_hex(char c, int &v)
{
   if (0x20 <= c && isdigit(c))
   {
      v = c - '0';
      return true;
   }
   else if ('A' <= c && c <= 'F')
   {
      v = c - 'A' + 10;
      return true;
   }
   else if ('a' <= c && c <= 'f')
   {
      v = c - 'a' + 10;
      return true;
   }
   return false;
}

bool from_hex_to_i(const std::string &s, size_t i, size_t cnt,
                   int &val)
{
   if (i >= s.size())
   {
      return false;
   }

   val = 0;
   for (; cnt; i++, cnt--)
   {
      if (!s[i])
      {
         return false;
      }
      auto v = 0;
      if (is_hex(s[i], v))
      {
         val = val * 16 + v;
      }
      else
      {
         return false;
      }
   }
   return true;
}

std::string CHTTPClient::DecodeUrl(const std::string &s, bool convert_plus_to_space)
{
   std::string result;

   for (size_t i = 0; i < s.size(); i++)
   {
      if (s[i] == '%' && i + 1 < s.size())
      {
         if (s[i + 1] == 'u')
         {
            auto val = 0;
            if (from_hex_to_i(s, i + 2, 4, val))
            {
               // 4 digits Unicode codes
               char buff[4];
               size_t len = to_utf8(val, buff);
               if (len > 0)
               {
                  result.append(buff, len);
               }
               i += 5; // 'u0000'
            }
            else
            {
               result += s[i];
            }
         }
         else
         {
            auto val = 0;
            if (from_hex_to_i(s, i + 1, 2, val))
            {
               // 2 digits hex codes
               result += static_cast<char>(val);
               i += 2; // '00'
            }
            else
            {
               result += s[i];
            }
         }
      }
      else if (convert_plus_to_space && s[i] == '+')
      {
         result += ' ';
      }
      else
      {
         result += s[i];
      }
   }

   return result;
}

/**
 * @brief read callback function for libcurl
 * used to send (or upload) a content to the server
 *
 * @param pointer of max size (size*nmemb) to write data to (used by cURL to send data)
 * @param size size parameter
 * @param nmemb memblock parameter
 * @param userdata pointer to user data to read data from
 *
 * @return (size * nmemb)
 */
size_t CHTTPClient::RestReadCallback(void *pCurlData, size_t usBlockCount, size_t usBlockSize, void *pUserData)
{
   // get upload struct
   CHTTPClient::UploadObject *Payload;

   Payload = reinterpret_cast<CHTTPClient::UploadObject *>(pUserData);

   // set correct sizes
   size_t usCurlSize = usBlockCount * usBlockSize;
   size_t usCopySize = (Payload->usLength < usCurlSize) ? Payload->usLength : usCurlSize;

   /** copy data to buffer */
   std::memcpy(pCurlData, Payload->pszData, usCopySize);

   // decrement length and increment data pointer
   Payload->usLength -= usCopySize; // remaining bytes to be sent
   Payload->pszData += usCopySize;  // next byte to the chunk that will be sent

   /** return copied size */
   return usCopySize;
}

// CURL DEBUG INFO CALLBACKS

#ifdef DEBUG_CURL
void CHTTPClient::SetCurlTraceLogDirectory(const std::string &strPath)
{
   s_strCurlTraceLogDirectory = strPath;

   if (!s_strCurlTraceLogDirectory.empty()
#ifdef WINDOWS
       && s_strCurlTraceLogDirectory.at(s_strCurlTraceLogDirectory.length() - 1) != '\\')
   {
      s_strCurlTraceLogDirectory += '\\';
   }
#else
       && s_strCurlTraceLogDirectory.at(s_strCurlTraceLogDirectory.length() - 1) != '/')
   {
      s_strCurlTraceLogDirectory += '/';
   }
#endif
}

int CHTTPClient::DebugCallback(CURL *curl, curl_infotype curl_info_type, char *pszTrace, size_t usSize, void *pFile)
{
   std::string strText;
   std::string strTrace(pszTrace, usSize);

   switch (curl_info_type)
   {
   case CURLINFO_TEXT:
      strText = "# Information : ";
      break;
   case CURLINFO_HEADER_OUT:
      strText = "-> Sending header : ";
      break;
   case CURLINFO_DATA_OUT:
      strText = "-> Sending data : ";
      break;
   case CURLINFO_SSL_DATA_OUT:
      strText = "-> Sending SSL data : ";
      break;
   case CURLINFO_HEADER_IN:
      strText = "<- Receiving header : ";
      break;
   case CURLINFO_DATA_IN:
      strText = "<- Receiving unencrypted data : ";
      break;
   case CURLINFO_SSL_DATA_IN:
      strText = "<- Receiving SSL data : ";
      break;
   default:
      break;
   }

   std::ofstream *pofTraceFile = reinterpret_cast<std::ofstream *>(pFile);
   if (pofTraceFile == nullptr)
   {
      std::cout << "[DEBUG] cURL debug log [" << curl_info_type << "]: "
                << " - " << strTrace;
   }
   else
   {
      (*pofTraceFile) << strText << strTrace;
   }

   return 0;
}

void CHTTPClient::StartCurlDebug() const
{
   if (!m_ofFileCurlTrace.is_open())
   {
      curl_easy_setopt(m_pCurlSession, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt(m_pCurlSession, CURLOPT_DEBUGFUNCTION, DebugCallback);

      std::string strFileCurlTraceFullName(s_strCurlTraceLogDirectory);
      if (!strFileCurlTraceFullName.empty())
      {
         char szDate[32];
         memset(szDate, 0, 32);
         time_t tNow;
         time(&tNow);
         // new trace file for each hour
         strftime(szDate, 32, "%Y%m%d_%H", localtime(&tNow));
         strFileCurlTraceFullName += "TraceLog_";
         strFileCurlTraceFullName += szDate;
         strFileCurlTraceFullName += ".txt";

         m_ofFileCurlTrace.open(strFileCurlTraceFullName, std::ifstream::app | std::ifstream::binary);

         if (m_ofFileCurlTrace)
            curl_easy_setopt(m_pCurlSession, CURLOPT_DEBUGDATA, &m_ofFileCurlTrace);
      }
   }
}

void CHTTPClient::EndCurlDebug() const
{
   if (m_ofFileCurlTrace && m_ofFileCurlTrace.is_open())
   {
      m_ofFileCurlTrace << "###########################################" << std::endl;
      m_ofFileCurlTrace.close();
   }
}
#endif

#ifdef WINDOWS
std::string CHTTPClient::AnsiToUtf8(const std::string &codepage_str)
{
   // Transcode Windows ANSI to UTF-16
   int size = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, codepage_str.c_str(), codepage_str.length(), nullptr, 0);
   std::wstring utf16_str(size, '\0');
   MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, codepage_str.c_str(), codepage_str.length(), &utf16_str[0], size);

   // Transcode UTF-16 to UTF-8
   int utf8_size = WideCharToMultiByte(CP_UTF8, 0, utf16_str.c_str(), utf16_str.length(), nullptr, 0, nullptr, nullptr);
   std::string utf8_str(utf8_size, '\0');
   WideCharToMultiByte(CP_UTF8, 0, utf16_str.c_str(), utf16_str.length(), &utf8_str[0], utf8_size, nullptr, nullptr);

   return utf8_str;
}

std::wstring CHTTPClient::Utf8ToUtf16(const std::string &str)
{
   std::wstring ret;
   int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), NULL, 0);
   if (len > 0)
   {
      ret.resize(len);
      MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), &ret[0], len);
   }
   return ret;
}
#endif
