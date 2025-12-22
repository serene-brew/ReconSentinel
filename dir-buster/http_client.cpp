#include "http_client.h"
#include <curl/curl.h>

size_t header_callback(char* buffer, size_t size, size_t nitems, void* userdata) {
    Response* resp = (Response*)userdata;
    resp->headers.append(buffer, size * nitems);
    return size * nitems;
}

size_t write_callback(char* buffer, size_t size, size_t nitems, void* userdata) {
    Response* resp = (Response*)userdata;
    resp->body.append(buffer, size * nitems);
    return size * nitems;
}

Response HttpClient::get(const std::string& url) {
    Response response{}; // zero-init to avoid garbage status codes
    CURL* curl = curl_easy_init();
    
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "DirBuster/1.0");
        
        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);
            curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &response.total_time);
            curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &response.content_length);
        } else {
            response.status_code = 0;
        }
        
        curl_easy_cleanup(curl);
    }
    
    return response;
}

Response HttpClient::head(const std::string& url) {
    Response response{}; // zero-init to avoid garbage status codes
    CURL* curl = curl_easy_init();
    
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "DirBuster/1.0");
        
        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);
            curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &response.total_time);
        } else {
            response.status_code = 0;
        }
        
        curl_easy_cleanup(curl);
    }
    
    return response;
}
