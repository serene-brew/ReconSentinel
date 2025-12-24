#include "dir_buster.h"

// File: bindings.cpp
// Brief: C-compatible entrypoint for loading DirBuster via ctypes.
// Author: ImonChakraborty

#include <curl/curl.h>
#include <string>

/**
 * @brief C API wrapper for ctypes/FFI consumers.
 */
extern "C" const char* run_dirbuster(const char* url,
                                      const char* wordlist_file,
                                      const char* output_file,
                                      int threads) {
    static thread_local std::string buffer;

    if (!url || !wordlist_file) {
        return nullptr;
    }

    curl_global_init(CURL_GLOBAL_ALL);

    DirBuster buster(url, wordlist_file, output_file ? output_file : "", threads);
    bool ok = buster.scan();

    buffer.clear();
    if (ok) {
        const auto& findings = buster.get_findings();
        for (const auto& finding : findings) {
            buffer += "[" + std::to_string(finding.status_code) + "] " + finding.url + "\n";
        }
    }

    curl_global_cleanup();
    return ok ? buffer.c_str() : nullptr;
}
