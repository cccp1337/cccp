#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

enum class RecordType {
    Email,
    Host,
    Domain,
    Ip,
    Url,
    Unknown
};

struct Record {
    RecordType type = RecordType::Unknown;
    std::string value;
    std::string source;
};

struct Findings {
    std::set<std::string> emails;
    std::set<std::string> hosts;
    std::set<std::string> domains;
    std::set<std::string> ips;
    std::set<std::string> urls;
    std::map<std::string, std::size_t> sources;
};

struct Options {
    std::string inputPath;
    bool json = false;
    std::set<std::string> ownedRoots;
};

std::string trim(const std::string& text) {
    std::size_t start = 0;
    while (start < text.size() && std::isspace(static_cast<unsigned char>(text[start])) != 0) {
        ++start;
    }

    std::size_t end = text.size();
    while (end > start && std::isspace(static_cast<unsigned char>(text[end - 1])) != 0) {
        --end;
    }

    return text.substr(start, end - start);
}

std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool isDigitsOnly(const std::string& value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isdigit(ch) != 0;
    });
}

std::vector<std::string> split(const std::string& value, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream stream(value);
    std::string item;
    while (std::getline(stream, item, delimiter)) {
        parts.push_back(item);
    }
    return parts;
}

std::string escapeJson(const std::string& text) {
    std::ostringstream out;
    for (char ch : text) {
        switch (ch) {
            case '\\':
                out << "\\\\";
                break;
            case '"':
                out << "\\\"";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                out << ch;
                break;
        }
    }
    return out.str();
}

bool isIpv4(const std::string& value) {
    const std::vector<std::string> parts = split(value, '.');
    if (parts.size() != 4) {
        return false;
    }

    for (const std::string& part : parts) {
        if (!isDigitsOnly(part)) {
            return false;
        }

        try {
            const int octet = std::stoi(part);
            if (octet < 0 || octet > 255) {
                return false;
            }
        } catch (const std::exception&) {
            return false;
        }
    }

    return true;
}

bool looksLikeDomainLabel(const std::string& label) {
    if (label.empty() || label.size() > 63) {
        return false;
    }

    if (label.front() == '-' || label.back() == '-') {
        return false;
    }

    return std::all_of(label.begin(), label.end(), [](unsigned char ch) {
        return std::isalnum(ch) != 0 || ch == '-';
    });
}

bool looksLikeDomain(const std::string& value) {
    const std::string lower = toLower(trim(value));
    const std::vector<std::string> labels = split(lower, '.');
    if (labels.size() < 2) {
        return false;
    }

    for (const std::string& label : labels) {
        if (!looksLikeDomainLabel(label)) {
            return false;
        }
    }

    const std::string& tld = labels.back();
    return tld.size() >= 2 &&
        std::all_of(tld.begin(), tld.end(), [](unsigned char ch) { return std::isalpha(ch) != 0; });
}

bool looksLikeEmail(const std::string& value) {
    const std::string candidate = trim(value);
    const std::size_t at = candidate.find('@');
    if (at == std::string::npos || at == 0 || at == candidate.size() - 1) {
        return false;
    }

    if (candidate.find('@', at + 1) != std::string::npos) {
        return false;
    }

    return looksLikeDomain(candidate.substr(at + 1));
}

std::optional<std::string> extractUrlHost(const std::string& value) {
    const std::string candidate = trim(value);
    const std::size_t scheme = candidate.find("://");
    if (scheme == std::string::npos) {
        return std::nullopt;
    }

    std::string rest = candidate.substr(scheme + 3);
    const std::size_t slash = rest.find('/');
    if (slash != std::string::npos) {
        rest = rest.substr(0, slash);
    }

    const std::size_t at = rest.rfind('@');
    if (at != std::string::npos) {
        rest = rest.substr(at + 1);
    }

    const std::size_t colon = rest.find(':');
    if (colon != std::string::npos) {
        rest = rest.substr(0, colon);
    }

    rest = toLower(trim(rest));
    if (rest.empty()) {
        return std::nullopt;
    }

    return rest;
}

std::optional<std::string> extractEmailDomain(const std::string& email) {
    const std::size_t at = email.find('@');
    if (at == std::string::npos || at + 1 >= email.size()) {
        return std::nullopt;
    }
    return toLower(email.substr(at + 1));
}

bool endsWithOwnedRoot(const std::string& domainOrHost, const std::set<std::string>& ownedRoots) {
    if (ownedRoots.empty()) {
        return true;
    }

    const std::string lowered = toLower(domainOrHost);
    for (const std::string& root : ownedRoots) {
        if (lowered == root) {
            return true;
        }
        if (lowered.size() > root.size() &&
            lowered.compare(lowered.size() - root.size(), root.size(), root) == 0 &&
            lowered[lowered.size() - root.size() - 1] == '.') {
            return true;
        }
    }
    return false;
}

RecordType parseType(const std::string& raw) {
    const std::string value = toLower(trim(raw));
    if (value == "email") {
        return RecordType::Email;
    }
    if (value == "host") {
        return RecordType::Host;
    }
    if (value == "domain") {
        return RecordType::Domain;
    }
    if (value == "ip") {
        return RecordType::Ip;
    }
    if (value == "url") {
        return RecordType::Url;
    }
    return RecordType::Unknown;
}

std::optional<RecordType> inferType(const std::string& value) {
    if (looksLikeEmail(value)) {
        return RecordType::Email;
    }

    const auto urlHost = extractUrlHost(value);
    if (urlHost.has_value()) {
        return RecordType::Url;
    }

    if (isIpv4(value)) {
        return RecordType::Ip;
    }

    if (looksLikeDomain(value)) {
        if (toLower(value).rfind("www.", 0) == 0 || split(value, '.').size() > 2) {
            return RecordType::Host;
        }
        return RecordType::Domain;
    }

    return std::nullopt;
}

std::vector<std::string> parseCsvLine(const std::string& line) {
    std::vector<std::string> fields;
    std::string current;
    bool inQuotes = false;

    for (std::size_t i = 0; i < line.size(); ++i) {
        const char ch = line[i];
        if (ch == '"') {
            if (inQuotes && i + 1 < line.size() && line[i + 1] == '"') {
                current.push_back('"');
                ++i;
            } else {
                inQuotes = !inQuotes;
            }
            continue;
        }

        if (ch == ',' && !inQuotes) {
            fields.push_back(trim(current));
            current.clear();
            continue;
        }

        current.push_back(ch);
    }

    fields.push_back(trim(current));
    return fields;
}

std::vector<Record> readPlainText(std::ifstream& input) {
    std::vector<Record> records;
    std::string line;
    while (std::getline(input, line)) {
        const std::string value = trim(line);
        if (value.empty() || value[0] == '#') {
            continue;
        }

        const auto inferred = inferType(value);
        if (!inferred.has_value()) {
            continue;
        }

        records.push_back(Record{*inferred, value, "manual"});
    }
    return records;
}

std::vector<Record> readCsv(std::ifstream& input) {
    std::vector<Record> records;
    std::string line;
    bool firstRow = true;

    while (std::getline(input, line)) {
        if (trim(line).empty()) {
            continue;
        }

        const std::vector<std::string> fields = parseCsvLine(line);
        if (firstRow) {
            firstRow = false;
            if (!fields.empty() && toLower(fields[0]) == "type") {
                continue;
            }
        }

        if (fields.size() < 2) {
            continue;
        }

        RecordType type = parseType(fields[0]);
        const std::string value = trim(fields[1]);
        const std::string source = fields.size() >= 3 && !fields[2].empty() ? trim(fields[2]) : "csv";

        if (type == RecordType::Unknown) {
            const auto inferred = inferType(value);
            if (!inferred.has_value()) {
                continue;
            }
            type = *inferred;
        }

        records.push_back(Record{type, value, source});
    }

    return records;
}

std::vector<Record> readRecords(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("Failed to open input file: " + path);
    }

    std::string firstNonEmpty;
    std::streampos restorePosition = input.tellg();
    std::string line;
    while (std::getline(input, line)) {
        const std::string value = trim(line);
        if (!value.empty()) {
            firstNonEmpty = value;
            break;
        }
    }

    input.clear();
    input.seekg(restorePosition);

    if (firstNonEmpty.find(',') != std::string::npos) {
        return readCsv(input);
    }

    return readPlainText(input);
}

void addFinding(Findings& findings, const Record& record, const Options& options) {
    const std::string source = record.source.empty() ? "unknown" : record.source;
    findings.sources[source] += 1;

    switch (record.type) {
        case RecordType::Email: {
            const std::string email = toLower(trim(record.value));
            const auto domain = extractEmailDomain(email);
            if (domain.has_value() && endsWithOwnedRoot(*domain, options.ownedRoots)) {
                findings.emails.insert(email);
                findings.domains.insert(*domain);
            }
            break;
        }
        case RecordType::Host: {
            const std::string host = toLower(trim(record.value));
            if (endsWithOwnedRoot(host, options.ownedRoots)) {
                findings.hosts.insert(host);
                findings.domains.insert(host);
            }
            break;
        }
        case RecordType::Domain: {
            const std::string domain = toLower(trim(record.value));
            if (endsWithOwnedRoot(domain, options.ownedRoots)) {
                findings.domains.insert(domain);
            }
            break;
        }
        case RecordType::Ip: {
            const std::string ip = trim(record.value);
            findings.ips.insert(ip);
            break;
        }
        case RecordType::Url: {
            const std::string url = trim(record.value);
            const auto host = extractUrlHost(url);
            if (host.has_value() && endsWithOwnedRoot(*host, options.ownedRoots)) {
                findings.urls.insert(url);
                findings.hosts.insert(*host);
                findings.domains.insert(*host);
            }
            break;
        }
        case RecordType::Unknown:
            break;
    }
}

void printUsage() {
    std::cout
        << "Usage: asset_recon --input <path> [--json] [--owned-root <domain>]\n"
        << "\n"
        << "Options:\n"
        << "  --input <path>         Input file in plain text or CSV format\n"
        << "  --json                 Emit JSON instead of text\n"
        << "  --owned-root <domain>  Limit domain, host, email, and URL output to owned roots\n"
        << "  --help                 Show this help message\n";
}

Options parseArgs(int argc, char* argv[]) {
    Options options;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage();
            std::exit(0);
        }
        if (arg == "--json") {
            options.json = true;
            continue;
        }
        if ((arg == "--input" || arg == "-i") && i + 1 < argc) {
            options.inputPath = argv[++i];
            continue;
        }
        if (arg == "--owned-root" && i + 1 < argc) {
            options.ownedRoots.insert(toLower(argv[++i]));
            continue;
        }

        throw std::runtime_error("Unknown or incomplete argument: " + arg);
    }

    if (options.inputPath.empty()) {
        throw std::runtime_error("Missing required --input argument.");
    }

    return options;
}

void printSet(const std::string& label, const std::set<std::string>& values) {
    std::cout << label << " (" << values.size() << ")\n";
    for (const std::string& value : values) {
        std::cout << "  - " << value << "\n";
    }
}

void printTextReport(const Findings& findings, const Options& options) {
    const std::size_t total =
        findings.emails.size() +
        findings.hosts.size() +
        findings.domains.size() +
        findings.ips.size() +
        findings.urls.size();

    std::cout << "asset_recon summary\n";
    std::cout << "===================\n";
    std::cout << "input: " << options.inputPath << "\n";
    std::cout << "total unique findings: " << total << "\n";

    if (!options.ownedRoots.empty()) {
        std::cout << "owned roots:";
        for (const std::string& root : options.ownedRoots) {
            std::cout << ' ' << root;
        }
        std::cout << "\n";
    }

    std::cout << "\n";
    printSet("emails", findings.emails);
    std::cout << "\n";
    printSet("hosts", findings.hosts);
    std::cout << "\n";
    printSet("domains", findings.domains);
    std::cout << "\n";
    printSet("ips", findings.ips);
    std::cout << "\n";
    printSet("urls", findings.urls);
    std::cout << "\n";

    std::cout << "sources (" << findings.sources.size() << ")\n";
    for (const auto& entry : findings.sources) {
        std::cout << "  - " << entry.first << ": " << entry.second << "\n";
    }
}

void printJsonArray(const std::set<std::string>& values, std::ostream& out) {
    out << "[";
    bool first = true;
    for (const std::string& value : values) {
        if (!first) {
            out << ",";
        }
        out << "\"" << escapeJson(value) << "\"";
        first = false;
    }
    out << "]";
}

void printJsonReport(const Findings& findings, const Options& options) {
    std::cout << "{\n";
    std::cout << "  \"input\": \"" << escapeJson(options.inputPath) << "\",\n";
    std::cout << "  \"owned_roots\": ";
    printJsonArray(options.ownedRoots, std::cout);
    std::cout << ",\n";
    std::cout << "  \"findings\": {\n";
    std::cout << "    \"emails\": ";
    printJsonArray(findings.emails, std::cout);
    std::cout << ",\n";
    std::cout << "    \"hosts\": ";
    printJsonArray(findings.hosts, std::cout);
    std::cout << ",\n";
    std::cout << "    \"domains\": ";
    printJsonArray(findings.domains, std::cout);
    std::cout << ",\n";
    std::cout << "    \"ips\": ";
    printJsonArray(findings.ips, std::cout);
    std::cout << ",\n";
    std::cout << "    \"urls\": ";
    printJsonArray(findings.urls, std::cout);
    std::cout << "\n";
    std::cout << "  },\n";
    std::cout << "  \"sources\": {\n";

    bool first = true;
    for (const auto& [source, count] : findings.sources) {
        if (!first) {
            std::cout << ",\n";
        }
        std::cout << "    \"" << escapeJson(source) << "\": " << count;
        first = false;
    }
    std::cout << "\n";
    std::cout << "  }\n";
    std::cout << "}\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        const Options options = parseArgs(argc, argv);
        const std::vector<Record> records = readRecords(options.inputPath);

        Findings findings;
        for (const Record& record : records) {
            addFinding(findings, record, options);
        }

        if (options.json) {
            printJsonReport(findings, options);
        } else {
            printTextReport(findings, options);
        }

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << "\n\n";
        printUsage();
        return 1;
    }
}
