from fastmcp import FastMCP
import auth
import tools
import enrichment.hybrid_analysis as hybrid_analysis, enrichment.virus_total as virus_total

mcp = FastMCP("SOC Assistant MCP")


# @mcp.tool()
# async def get_incidents():
#     #This server gets incidents using Graph API
#     result = await auth.client.security.incidents.get()

@mcp.tool(
    name="get_users",
    description="List Microsoft Entra ID users and return their display names, user principal names (UPNs), and object IDs. Use this to identify accounts before calling tools that require a UPN."
)
async def get_users():
    #This gets users from Entra ID
    return await tools.get_users()

@mcp.tool(
    name="get_user_risk",
    description="Read the Microsoft Entra ID Identity Protection risk level, risk state, and risk detail for one or more user principal names (UPNs)."
)
async def get_user_risk(user_upns: list[str]):
    #This gets users risk from Entra ID
    return await tools.get_user_risk(user_upns)


@mcp.tool(
    name="get_account_status",
    description="Read whether each Microsoft Entra ID account is enabled or disabled for one or more user principal names (UPNs)."
)
async def check_account_status(user_upns: list[str]):
    #This gets users risk from Entra ID
    return await tools.check_account_status(user_upns)


@mcp.tool(
    name="patch_disable_user",
    description="Disable a Microsoft Entra ID user account, blocking new sign-ins. This changes the account’s enabled state. Use only when disabling the specific account was explicitly requested."
)
async def disable_user(user_upns: list[str]):
    #This gets users risk from Entra ID
    return await tools.disable_user(user_upns)

@mcp.tool(
    name="patch_enable_user",
    description="Enable a Microsoft Entra ID user account. This changes the account’s enabled state. Use only when enabling the specific account was explicitly requested."
)
async def enable_user(user_upns: list[str]):
    #This gets users risk from Entra ID
    return await tools.enable_user(user_upns)

@mcp.tool(
    name="revoke_user_session",
    description="Revoke a Microsoft Entra ID user's sign-in sessions by invalidating refresh tokens and browser session cookies, requiring the user to sign in again. Revocation can take a few minutes. Use when session revocation is explicitly requested for the specified account."
)
async def revoke_user_sessions(user_upns: list[str]):
    #This gets users risk from Entra ID
    return await tools.revoke_user_sessions(user_upns)

@mcp.tool(
    name="reset_password",
    description="Reset passwords for one or more Microsoft Entra ID accounts identified by user principal names (UPNs). Assign each account a generated temporary password and require a password change at next sign-in. Return the reset outcome for each account. Use when a password reset is explicitly requested for the specified accounts."
)
async def reset_password(user_upns: list[str]):
    #This gets users risk from Entra ID
    return await tools.reset_password(user_upns)


@mcp.tool(
    name="remediate_user",
    description="Remediate one or more compromised Microsoft Entra ID accounts identified by user principal names (UPNs). Revoke sign-in sessions, reset passwords with a required change at next sign-in, and delete supported registered authentication methods: email, Microsoft Authenticator, phone, and FIDO2. Return outcomes for each action, including skipped methods and uncertain results. Use when remediation is explicitly requested for the specified accounts."
)
async def remediate_user(user_upns: list[str]):
    
    revoke_users = await tools.revoke_user_sessions(user_upns)
    
    user_results =[]
    
    for upn in user_upns:
        password_results = await tools.reset_password([upn])
        authentication_results = await tools.delete_MFA([upn])

        user_results.append({
            "upn": upn,
            "reset_password": password_results,
            "delete_authentication_methods": authentication_results
        })

    return {
        "revoke_sessions": revoke_users,
        "users": user_results
    }
    
@mcp.tool(
    name="check_target_user_audit",
    description="Filters for user audit logs based on the upn"
)
async def check_target_user_audit(user_upns: list[str], period: int):
    """
    Retrieve Microsoft Entra ID directory audit log entries for one or more users.
    Read-only. Returns who changed the account, what changed (old/new values),
    when (UTC), and whether it succeeded. Use it to verify that an action such as
    enable, disable, password reset, or session revocation took effect.

    Args:
        period: Lookback window in HOURS (not days). Example: 24 = last 24 hours.
        user_upns: User principal names, e.g. ['user@tenant.onmicrosoft.com'].
    """
    return await tools.check_target_user_audit_logs(user_upns, period)

@mcp.tool(
    name="check_initiated_user_audit",
    description="Filters for user audit logs based on the initiated user upn"
)
async def check_initiated_user_audit(user_upns: list[str], period: int):
    """
    Retrieve Microsoft Entra ID directory audit log entries for one or more users.
    Read-only. Returns who changed the account, what changed (old/new values),
    when (UTC), and whether it succeeded. Use it to verify that an action such as
    enable, disable, password reset, or session revocation took effect.

    Args:
        period: Lookback window in HOURS (not days). Example: 24 = last 24 hours.
        user_upns: User principal names, e.g. ['user@tenant.onmicrosoft.com'].
    """
    return await tools.check_initiated_user_audit_logs(user_upns, period)

@mcp.tool(
    name="lookup_hash_summary",
    description=(
    "Look up existing Hybrid Analysis reports for one or more file hashes. "
    "Provide a list of hashes, even for a single lookup. "
    "For each submitted hash, returns successful reports from environment 140 "
    "(Windows 11 64-bit) and counts the reports by verdict."
)
)
async def lookup_hash_summary(hash_: list[str]):
        body = await hybrid_analysis.lookup_hash_report(hash_)
        return hybrid_analysis.summary_hash_report(body)

@mcp.tool(
    name="lookup_url_summary",
    description=(
    "Look up existing VirusTotal analysis results for one or more URLs. "
    "Provide a list of full URLs, including http:// or https://, even for a single lookup. "
    "For each URL with a report, return the latest analysis counts, "
    "the last analysis date in UTC, and the final URL when available."
)
)
async def lookup_url_summary(urls: list[str]): 
        return await virus_total.get_url_info(urls)
    
##################################################################################    
@mcp.resource("entra://docs/user-fields")
def entra_user_fields() -> str:
    """Explain the fields returned by the get_users tool."""
    return """Microsoft Entra ID user field guide

- Display Name (displayName): The user's name as shown in the address book.
- User ID (id): The unique identifier of the user object.
- User Principal Name (userPrincipalName): The user's sign-in name,
  typically in alias@domain format.

Source: Microsoft Learn, Microsoft Graph v1.0 user resource properties
https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0#properties
"""

@mcp.prompt(
    name="get_users_prompt"
    )
def get_users_prompt():
    return """Call get_users to review Entra ID users:

1. Total number of users returned
2. Display name
3. User principal name 
"""

if __name__ == "__main__":
    mcp.run()