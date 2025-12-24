/**
 * @file http_client.h
 * @brief Lightweight HTTP client wrappers for HEAD/GET requests.
 * @author ImonChakraborty
 */

#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <string>

/**
 * @brief Simple response container for curl operations.
 */
struct Response {
    std::string headers;
    std::string body;
    long status_code = 0;
    double total_time = 0.0;
    long content_length = 0;
};

/**
 * @brief Static helpers for issuing HTTP requests.
 */
class HttpClient {
public:
    static Response get(const std::string& url);
    static Response head(const std::string& url);
};

#endif
