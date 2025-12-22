#ifndef DIR_BUSTER_H
#define DIR_BUSTER_H

#include <string>
#include <vector>
#include <fstream>
#include <mutex>
#include <atomic>

struct Finding {
    std::string url;
    long status_code;
};

class DirBuster {
private:
    std::string base_url;
    std::vector<std::string> wordlist;
    std::vector<Finding> findings;
    std::ofstream output_file;
    std::atomic<int> found_count;
    std::atomic<int> total_count;
    std::mutex log_mutex;
    std::mutex findings_mutex;
    int num_threads;
    
    void log(const std::string& message);
    bool load_wordlist(const std::string& wordlist_file);
    std::string normalize_url(const std::string& url);
    bool check_wildcard();
    bool is_interesting_status(long code) const;
    void record_finding(const std::string& url, long status_code);
    void worker(int start, int end);

public:
    DirBuster(const std::string& url, const std::string& wordlist_file, const std::string& output_filename = "", int threads = 10);
    ~DirBuster();
    bool scan();
    const std::vector<Finding>& get_findings() const { return findings; }
};

#endif
