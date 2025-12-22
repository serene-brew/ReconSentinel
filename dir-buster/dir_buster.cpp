#include "dir_buster.h"
#include "http_client.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <thread>
#include <vector>
#include <random>

DirBuster::DirBuster(const std::string& url, const std::string& wordlist_file, const std::string& output_filename, int threads) 
    : base_url(normalize_url(url)), found_count(0), total_count(0), num_threads(threads) {
    
    if (!load_wordlist(wordlist_file)) {
        std::cerr << "[-] Failed to load wordlist\n";
        return;
    }
    
    if (!output_filename.empty()) {
        output_file.open(output_filename);
        if (output_file.is_open()) {
            time_t now = time(0);
            char* dt = ctime(&now);
            output_file << "Directory Busting Report\n";
            output_file << "Date: " << dt;
            output_file << "Target: " << base_url << "\n";
            output_file << "Wordlist: " << wordlist_file << "\n";
            output_file << "=================================\n\n";
        }
    }
}

DirBuster::~DirBuster() {
    if (output_file.is_open()) {
        output_file.close();
    }
}

void DirBuster::log(const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cout << message;
    if (output_file.is_open()) {
        output_file << message;
        output_file.flush();
    }
}

std::string DirBuster::normalize_url(const std::string& url) {
    std::string normalized = url;
    if (normalized.back() != '/') {
        normalized += '/';
    }
    return normalized;
}

bool DirBuster::is_interesting_status(long code) const {
    return code == 200 || code == 301 || code == 302 || code == 403;
}

void DirBuster::record_finding(const std::string& url, long status_code) {
    std::lock_guard<std::mutex> lock(findings_mutex);
    findings.push_back({url, status_code});
}

bool DirBuster::check_wildcard() {
    static const std::string charset = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<> dist(0, static_cast<int>(charset.size()) - 1);

    std::string token;
    token.reserve(16);
    for (int i = 0; i < 16; ++i) {
        token.push_back(charset[dist(rng)]);
    }

    std::string test_url = base_url + token;
    Response resp = HttpClient::head(test_url);

    if (resp.status_code <= 0 || resp.status_code == 405) {
        resp = HttpClient::get(test_url);
    }

    if (resp.status_code <= 0) {
        log("[!] Wildcard probe failed (no status code) at " + test_url + " — aborting scan.\n");
        return false;
    }

    if (resp.status_code == 200) {
        log("[!] Wildcard 200 detected at " + test_url + " — aborting scan.\n");
        return false;
    }

    log("[*] Wildcard test passed with status " + std::to_string(resp.status_code) + " at " + test_url + "\n\n");
    return true;
}

bool DirBuster::load_wordlist(const std::string& wordlist_file) {
    std::ifstream file(wordlist_file);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line[0] != '#') {
            wordlist.push_back(line);
        }
    }
    
    file.close();
    return !wordlist.empty();
}

void DirBuster::worker(int start, int end) {
    for (int i = start; i < end && i < (int)wordlist.size(); i++) {
        std::string url = base_url + wordlist[i];
        total_count++;
        
        Response resp = HttpClient::head(url);

        // Skip entries where we failed to get a status code.
        if (resp.status_code <= 0) {
            continue;
        }

        if (is_interesting_status(resp.status_code)) {
            found_count++;
            record_finding(url, resp.status_code);
            std::string result = "[" + std::to_string(resp.status_code) + "] " + url + " [FOUND]\n";
            log(result);
        }
        
        // // Progress indicator
        // if (total_count % 100 == 0) {
        //     std::lock_guard<std::mutex> lock(log_mutex);
        //     std::cout << "\r[*] Progress: " << total_count << "/" << wordlist.size() << " (" << found_count << " found)";
        //     std::cout.flush();
        // }
    }
}

bool DirBuster::scan() {
    log("=================================\n");
    log("Directory Buster\n");
    log("Target: " + base_url + "\n");
    log("Words: " + std::to_string(wordlist.size()) + "\n");
    log("Threads: " + std::to_string(num_threads) + "\n");
    log("=================================\n\n");

    if (wordlist.empty()) {
        log("[-] Wordlist is empty — aborting scan.\n");
        return false;
    }

    if (!check_wildcard()) {
        return false;
    }
    
    std::vector<std::thread> threads;
    int worker_count = num_threads > 0 ? num_threads : 1;
    size_t chunk_size = (wordlist.size() + static_cast<size_t>(worker_count) - 1) / static_cast<size_t>(worker_count);
    
    // Create worker threads
    for (int i = 0; i < worker_count; i++) {
        size_t start = static_cast<size_t>(i) * chunk_size;
        size_t end = (i == worker_count - 1) ? wordlist.size() : start + chunk_size;
        threads.emplace_back(&DirBuster::worker, this, static_cast<int>(start), static_cast<int>(end));
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    std::cout << "\n";
    log("\n=================================\n");
    log("[*] Scan Complete!\n");
    log("[+] Total Requests: " + std::to_string(total_count.load()) + "\n");
    log("[+] Found: " + std::to_string(found_count.load()) + "\n");
    log("=================================\n");
    
    if (output_file.is_open()) {
        log("\n[+] Results saved to output file\n");
    }

    return true;
}
