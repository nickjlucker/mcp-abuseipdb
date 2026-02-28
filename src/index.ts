#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// AbuseIPDB API configuration
const ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2";
const USER_AGENT = "mcp-abuseipdb/0.1.0";

// Get API key from environment (required)
const API_KEY = process.env.ABUSEIPDB_API_KEY;

// AbuseIPDB abuse categories
const CATEGORIES: Record<number, string> = {
  1: "DNS Compromise",
  2: "DNS Poisoning",
  3: "Fraud Orders",
  4: "DDoS Attack",
  5: "FTP Brute-Force",
  6: "Ping of Death",
  7: "Phishing",
  8: "Fraud VoIP",
  9: "Open Proxy",
  10: "Web Spam",
  11: "Email Spam",
  12: "Blog Spam",
  13: "VPN IP",
  14: "Port Scan",
  15: "Hacking",
  16: "SQL Injection",
  17: "Spoofing",
  18: "Brute-Force",
  19: "Bad Web Bot",
  20: "Exploited Host",
  21: "Web App Attack",
  22: "SSH",
  23: "IoT Targeted",
};

// Response types
interface AbuseIPDBCheckResponse {
  data: {
    ipAddress: string;
    isPublic: boolean;
    ipVersion: number;
    isWhitelisted: boolean | null;
    abuseConfidenceScore: number;
    countryCode: string;
    countryName?: string;
    usageType: string;
    isp: string;
    domain: string;
    hostnames: string[];
    isTor: boolean;
    totalReports: number;
    numDistinctUsers: number;
    lastReportedAt: string | null;
    reports?: Array<{
      reportedAt: string;
      comment: string;
      categories: number[];
      reporterId: number;
      reporterCountryCode: string;
      reporterCountryName: string;
    }>;
  };
}

interface AbuseIPDBError {
  errors: Array<{
    detail: string;
    status: number;
  }>;
}

// Create server instance
const server = new McpServer({
  name: "mcp-abuseipdb",
  version: "0.1.0",
});

/**
 * Make a request to the AbuseIPDB API
 */
async function checkIP(
  ip: string,
  maxAgeInDays: number = 90,
  verbose: boolean = false
): Promise<AbuseIPDBCheckResponse | AbuseIPDBError> {
  if (!API_KEY) {
    return {
      errors: [
        {
          detail: "ABUSEIPDB_API_KEY environment variable is not set",
          status: 401,
        },
      ],
    };
  }

  const params = new URLSearchParams({
    ipAddress: ip,
    maxAgeInDays: maxAgeInDays.toString(),
  });

  if (verbose) {
    params.append("verbose", "");
  }

  try {
    const response = await fetch(`${ABUSEIPDB_API_BASE}/check?${params}`, {
      headers: {
        Key: API_KEY,
        Accept: "application/json",
        "User-Agent": USER_AGENT,
      },
    });

    const data = await response.json();

    if (!response.ok) {
      return data as AbuseIPDBError;
    }

    return data as AbuseIPDBCheckResponse;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return {
      errors: [{ detail: `Request failed: ${message}`, status: 500 }],
    };
  }
}

/**
 * Format category IDs to human-readable names
 */
function formatCategories(categoryIds: number[]): string {
  return categoryIds
    .map((id) => CATEGORIES[id] || `Unknown (${id})`)
    .join(", ");
}

/**
 * Get risk level based on abuse confidence score
 */
function getRiskLevel(score: number): string {
  if (score === 0) return "✅ Clean";
  if (score <= 25) return "🟢 Low Risk";
  if (score <= 50) return "🟡 Moderate Risk";
  if (score <= 75) return "🟠 High Risk";
  return "🔴 Critical Risk";
}

/**
 * Format a check response into human-readable text
 */
function formatCheckResponse(data: AbuseIPDBCheckResponse["data"]): string {
  const lines: string[] = [];

  lines.push(`IP: ${data.ipAddress} (IPv${data.ipVersion})`);
  lines.push(`Abuse Confidence Score: ${data.abuseConfidenceScore}% ${getRiskLevel(data.abuseConfidenceScore)}`);
  lines.push(`Country: ${data.countryName || data.countryCode}`);
  lines.push(`ISP: ${data.isp}`);
  lines.push(`Domain: ${data.domain}`);
  lines.push(`Usage Type: ${data.usageType}`);

  if (data.hostnames.length > 0) {
    lines.push(`Hostnames: ${data.hostnames.join(", ")}`);
  }

  lines.push(`Tor Exit Node: ${data.isTor ? "YES ⚠️" : "No"}`);
  lines.push(`Total Reports: ${data.totalReports} (from ${data.numDistinctUsers} users)`);

  if (data.lastReportedAt) {
    lines.push(`Last Reported: ${data.lastReportedAt}`);
  }

  if (data.isWhitelisted) {
    lines.push(`Whitelisted: YES (likely benign)`);
  }

  // Add recent reports if verbose
  if (data.reports && data.reports.length > 0) {
    lines.push("");
    lines.push(`--- Recent Reports (${Math.min(data.reports.length, 5)} of ${data.totalReports}) ---`);

    for (const report of data.reports.slice(0, 5)) {
      lines.push("");
      lines.push(`  Date: ${report.reportedAt}`);
      lines.push(`  Categories: ${formatCategories(report.categories)}`);
      lines.push(`  Reporter: ${report.reporterCountryCode}`);
      if (report.comment) {
        const comment = report.comment.length > 100 
          ? report.comment.substring(0, 100) + "..." 
          : report.comment;
        lines.push(`  Comment: ${comment}`);
      }
    }
  }

  // Add interpretation
  lines.push("");
  lines.push("--- Interpretation ---");

  if (data.abuseConfidenceScore === 0 && data.totalReports === 0) {
    lines.push("✅ This IP has no abuse reports. It appears clean.");
  } else if (data.abuseConfidenceScore <= 25) {
    lines.push("🟢 Low abuse confidence. Some reports exist but likely low risk. Consider context.");
  } else if (data.abuseConfidenceScore <= 50) {
    lines.push("🟡 Moderate abuse confidence. This IP has notable reports. Proceed with caution.");
  } else if (data.abuseConfidenceScore <= 75) {
    lines.push("🟠 High abuse confidence. This IP is frequently reported. Recommended to block.");
  } else {
    lines.push("🔴 Critical abuse confidence. This IP is heavily reported as malicious. Block immediately.");
  }

  if (data.isTor) {
    lines.push("⚠️ This is a Tor exit node - traffic is anonymized, could be legitimate or malicious.");
  }

  lines.push("");
  lines.push(`Details: https://www.abuseipdb.com/check/${data.ipAddress}`);

  return lines.join("\n");
}

/**
 * Validate IP address format (IPv4 or IPv6)
 */
function isValidIP(ip: string): boolean {
  // IPv4
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(ip)) {
    const parts = ip.split(".");
    return parts.every((part) => {
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255;
    });
  }

  // IPv6 (simplified check)
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  return ipv6Regex.test(ip);
}

/**
 * Check if response is an error
 */
function isError(
  response: AbuseIPDBCheckResponse | AbuseIPDBError
): response is AbuseIPDBError {
  return "errors" in response;
}

// Register the check_ip tool
server.registerTool(
  "check_ip",
  {
    description:
      "Check an IP address reputation on AbuseIPDB. Returns abuse confidence score (0-100%), " +
      "report count, country, ISP, and recent abuse reports. Higher scores indicate more " +
      "malicious activity. Useful for investigating suspicious IPs from logs or alerts.",
    inputSchema: {
      ip: z.string().describe("IP address to check (IPv4 or IPv6)"),
      maxAgeInDays: z
        .number()
        .min(1)
        .max(365)
        .optional()
        .describe("Max age of reports to include (default: 90, max: 365)"),
      verbose: z
        .boolean()
        .optional()
        .describe("Include recent abuse reports in response (default: false)"),
    },
  },
  async ({ ip, maxAgeInDays = 90, verbose = false }) => {
    if (!isValidIP(ip)) {
      return {
        content: [
          {
            type: "text",
            text: `Invalid IP address format: ${ip}. Please provide a valid IPv4 or IPv6 address.`,
          },
        ],
        isError: true,
      };
    }

    const result = await checkIP(ip, maxAgeInDays, verbose);

    if (isError(result)) {
      return {
        content: [
          {
            type: "text",
            text: `AbuseIPDB API error: ${result.errors[0]?.detail || "Unknown error"}`,
          },
        ],
        isError: true,
      };
    }

    return {
      content: [
        {
          type: "text",
          text: formatCheckResponse(result.data),
        },
      ],
    };
  }
);

// Register the check_ips tool for bulk lookups
server.registerTool(
  "check_ips",
  {
    description:
      "Check multiple IP addresses against AbuseIPDB in one call. " +
      "Returns a summary of abuse confidence scores for each IP. " +
      "Useful for triaging a list of suspicious IPs from logs or alerts. " +
      "Free tier: 1000 checks/day.",
    inputSchema: {
      ips: z
        .array(z.string())
        .min(1)
        .max(20)
        .describe("Array of IP addresses to check (max 20)"),
      maxAgeInDays: z
        .number()
        .min(1)
        .max(365)
        .optional()
        .describe("Max age of reports to include (default: 90)"),
    },
  },
  async ({ ips, maxAgeInDays = 90 }) => {
    const results: string[] = [];
    const errors: string[] = [];

    for (const ip of ips) {
      if (!isValidIP(ip)) {
        errors.push(`${ip}: Invalid IP format`);
        continue;
      }

      const result = await checkIP(ip, maxAgeInDays, false);

      if (isError(result)) {
        errors.push(`${ip}: ${result.errors[0]?.detail || "Unknown error"}`);
        continue;
      }

      const d = result.data;
      const risk = getRiskLevel(d.abuseConfidenceScore);
      const tor = d.isTor ? " [TOR]" : "";
      const reports = d.totalReports > 0 ? ` (${d.totalReports} reports)` : "";

      results.push(
        `${d.ipAddress}: ${d.abuseConfidenceScore}% ${risk}${tor}${reports} - ${d.countryCode} ${d.isp}`
      );
    }

    let output = "";

    if (results.length > 0) {
      output += "=== Results ===\n";
      output += results.join("\n");
    }

    if (errors.length > 0) {
      if (output) output += "\n\n";
      output += "=== Errors ===\n";
      output += errors.join("\n");
    }

    output += "\n\n--- Risk Levels ---\n";
    output += "0%: ✅ Clean | 1-25%: 🟢 Low | 26-50%: 🟡 Moderate | 51-75%: 🟠 High | 76-100%: 🔴 Critical\n";

    return {
      content: [
        {
          type: "text",
          text: output,
        },
      ],
    };
  }
);

// Register a resource for API status/info
server.registerResource(
  "AbuseIPDB API Status",
  "abuseipdb://status",
  {
    description: "Information about the AbuseIPDB API and rate limits",
    mimeType: "text/plain",
  },
  async () => {
    const info = [
      "AbuseIPDB API v2",
      "================",
      "",
      "Rate Limits (Free Tier):",
      "- CHECK endpoint: 1,000 checks/day",
      "- REPORT endpoint: 500 reports/day",
      "- BLACKLIST endpoint: 5 downloads/day",
      "",
      "API Key Status: " + (API_KEY ? "Configured ✓" : "NOT CONFIGURED ❌"),
      "",
      "To get an API key:",
      "1. Create a free account at https://www.abuseipdb.com/register",
      "2. Go to API tab in your account dashboard",
      "3. Create an API key",
      "4. Set ABUSEIPDB_API_KEY environment variable",
      "",
      "Documentation: https://docs.abuseipdb.com/",
      "",
      "Abuse Categories:",
      ...Object.entries(CATEGORIES).map(([id, name]) => `  ${id}: ${name}`),
    ];

    return {
      contents: [
        {
          uri: "abuseipdb://status",
          mimeType: "text/plain",
          text: info.join("\n"),
        },
      ],
    };
  }
);

// Main entry point
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("AbuseIPDB MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
