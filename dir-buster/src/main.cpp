#include "dir_buster.h"

// File: main.cpp
// Brief: CLI frontend for the DirBuster engine.
// Author: ImonChakraborty

/**
 * @brief Entry point for the standalone CLI.
 */

#include <curl/curl.h>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    curl_global_init(CURL_GLOBAL_ALL);

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <url> <wordlist> [output_file] [threads]\n";
        curl_global_cleanup();
        return 1;
    }

    std::string url = argv[1];
    std::string wordlist = argv[2];
    std::string output_file = (argc > 3) ? argv[3] : "";
    int threads = (argc > 4) ? std::stoi(argv[4]) : 10;

    DirBuster buster(url, wordlist, output_file, threads);
    bool ok = buster.scan();
    if (!ok) {
        std::cerr << "[-] Scan aborted. See logs for details." << std::endl;
    }

    curl_global_cleanup();
    return ok ? 0 : 1;
}
