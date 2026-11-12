# Defender MCP | SOC AI Assistant

Defender MCP gives an MCP-compatible AI assistant access to security tools for SOC investigations. Analysts can ask about Microsoft Entra ID user risk, enrich a file hash or suspicious URL with threat intelligence, and use supported account response tools during incident handling.

**Work in progress.** Defender MCP will expand with additional tools for SOC investigations and incident response.

## What it can do

| SOC task | Integration | What the analyst gets |
| --- | --- | --- |
| Investigate a potentially compromised account | Microsoft Graph and Microsoft Entra ID | User risk and account status for the supplied user principal name (UPN). |
| Investigate a suspicious file | Hybrid Analysis | Existing sandbox reports for one or more file hashes. The lookup summarizes successful Windows 11 64-bit analyses (environment 140) and counts reports by verdict. |
| Investigate a suspicious link | VirusTotal | Existing analysis results for one or more URLs, including scanner counts, the last analysis date, the final URL when available, and details from scanners that flagged it. |
| Respond to a compromised account | Microsoft Graph and Microsoft Entra ID | Supported response actions, such as revoking sign-in sessions or disabling an account, subject to the app's permissions. |

## Example analyst prompts

- “Check the Entra ID risk and account status for analyst@example.com.”
- “Look up this SHA-256 in Hybrid Analysis and summarize the sandbox verdicts.”
- “Check the existing VirusTotal report for https://example.com/ and tell me when it was last analyzed.”

## Setup

Clone the repository, then create a virtual environment and install the dependencies. The commands below use Windows PowerShell.

```powershell
git clone https://github.com/darkabs/defender-mcp.git
cd defender-mcp
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Configure the Microsoft Graph credentials and the Hybrid Analysis and VirusTotal API keys expected by `auth.py`. Use the exact environment variable names defined there and keep credentials out of Git.
