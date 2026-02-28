# mcp-abuseipdb

MCP server for [AbuseIPDB](https://www.abuseipdb.com/) - Check IP reputation and abuse reports.

## What it does

AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. This MCP server lets AI agents:

- **Check IP reputation** - Get abuse confidence scores (0-100%) for any IP
- **View abuse reports** - See what malicious activity has been reported
- **Bulk check IPs** - Triage multiple IPs from logs or alerts

## Quick Start

```bash
# Install
npm install -g mcp-abuseipdb

# Set your API key (free at https://www.abuseipdb.com/register)
export ABUSEIPDB_API_KEY=your_key_here
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "abuseipdb": {
      "command": "npx",
      "args": ["-y", "mcp-abuseipdb"],
      "env": {
        "ABUSEIPDB_API_KEY": "your_key_here"
      }
    }
  }
}
```

## Tools

### check_ip

Check a single IP address reputation.

**Parameters:**
- `ip` (required): IPv4 or IPv6 address
- `maxAgeInDays` (optional): How far back to look for reports (1-365, default: 90)
- `verbose` (optional): Include recent abuse reports (default: false)

**Example response:**
```
IP: 118.25.6.39 (IPv4)
Abuse Confidence Score: 100% 🔴 Critical Risk
Country: China
ISP: Tencent Cloud Computing
Usage Type: Data Center/Web Hosting/Transit
Tor Exit Node: No
Total Reports: 1,847 (from 312 users)
Last Reported: 2024-01-15T10:30:00+00:00

--- Interpretation ---
🔴 Critical abuse confidence. This IP is heavily reported as malicious. Block immediately.
```

### check_ips

Bulk check multiple IPs (max 20 per call).

**Parameters:**
- `ips` (required): Array of IP addresses
- `maxAgeInDays` (optional): How far back to look (default: 90)

**Example response:**
```
=== Results ===
8.8.8.8: 0% ✅ Clean - US Google LLC
118.25.6.39: 100% 🔴 Critical (1847 reports) - CN Tencent
185.220.101.1: 95% 🔴 Critical [TOR] (523 reports) - DE Tor Exit

--- Risk Levels ---
0%: ✅ Clean | 1-25%: 🟢 Low | 26-50%: 🟡 Moderate | 51-75%: 🟠 High | 76-100%: 🔴 Critical
```

## Resources

### abuseipdb://status

Get API status and rate limit info.

## Rate Limits (Free Tier)

- CHECK: 1,000 requests/day
- REPORT: 500 reports/day
- BLACKLIST: 5 downloads/day

Get your free API key at [abuseipdb.com](https://www.abuseipdb.com/register)

## Abuse Categories

AbuseIPDB uses these categories to classify reports:

| ID | Category |
|----|----------|
| 4 | DDoS Attack |
| 5 | FTP Brute-Force |
| 7 | Phishing |
| 9 | Open Proxy |
| 10 | Web Spam |
| 11 | Email Spam |
| 14 | Port Scan |
| 15 | Hacking |
| 18 | Brute-Force |
| 19 | Bad Web Bot |
| 21 | Web App Attack |
| 22 | SSH |

## Use Cases

- **SOC/IR**: Quickly check suspicious IPs from security alerts
- **Log Analysis**: Bulk check IPs hitting your servers
- **Email Security**: Verify sender IPs for spam investigation
- **Firewall Rules**: Validate IPs before blocking/allowing

## License

MIT
