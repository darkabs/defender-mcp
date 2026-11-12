import auth
from datetime import datetime, timedelta, timezone
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
from msgraph.generated.users.item.user_item_request_builder import UserItemRequestBuilder
from msgraph.generated.audit_logs.directory_audits.directory_audits_request_builder import DirectoryAuditsRequestBuilder
from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph.generated.models.user import User
from msgraph.generated.models.password_profile import PasswordProfile
from kiota_abstractions.api_error import APIError
import password_policy
import secrets
import logging

#Time Period to query. Set default to 24 hours
def time_range(time_hour):
    period = (datetime.now(timezone.utc) - timedelta(hours=time_hour)).strftime('%Y-%m-%dT%H:%M:%SZ')
    return period

#For use with any individual lookup
def user_item_request_builder(parameters: list[str]):
    request_params = UserItemRequestBuilder.UserItemRequestBuilderGetQueryParameters(
        select=parameters#["id","displayName"]
    )
    request_conf = RequestConfiguration(
        query_parameters=request_params
    )
    return request_conf

async def get_users():
    request_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
        top=1,
        count=True
    )
    request_conf = RequestConfiguration(
        query_parameters=request_params
    )
    result = await auth.client.users.get(request_configuration=request_conf)
    
    users = []

    while True:
                
        for value in result.value:
            users.append({
                "Display Name":value.display_name,
                "User ID": value.id,
                "User Principal Name": value.user_principal_name,
                "Given name":value.given_name
            }) 
            
        if result.odata_next_link is None:
            break
    
        result = await auth.client.users.with_url(result.odata_next_link).get()    
    
    return users   


async def get_user_risk(user_upns: list[str])-> list[dict]:
    results=[]
    
    request_config = user_item_request_builder(parameters=["id","displayName"])
    
    for upn in user_upns:
        try:
                
            result = await auth.client.users.by_user_id(upn).get(request_configuration=request_config)
            
            user_risk = await auth.client.identity_protection.risky_users.by_risky_user_id(result.id).get()
            
            results.append({
                "upn": upn,
                "Display Name": result.display_name,
                "object_id": result.id,
                "risk_level": user_risk.risk_level,
                "risk_state": user_risk.risk_state,
                "risk_detail": user_risk.risk_detail,
            })
        except Exception:
            logging.exception("Unable to check user risk")
    
    return results


async def check_account_status(user_upns: list[str]) -> list[dict]:
    
    results = []

    request_config = user_item_request_builder(parameters=["accountEnabled"])
    
    for upn in user_upns:
        accountStatus = await auth.client.users.by_user_id(upn).get(request_configuration=request_config)

        results.append({
            "UPN" : upn,
            "Account Enabled":accountStatus.account_enabled
        })
        
    if accountStatus:
        return results

async def enable_user(user_upns: list[str]):
    results =[]
    
    request_body = User(
        account_enabled = True
    )
    
    for upn in user_upns:
        result = await auth.client.users.by_user_id(upn).patch(request_body)
        
        results.append({
            "Response" : result
        })
    
    return results

async def disable_user(user_upns: list[str]):
    results =[]
    
    request_body = User(
        account_enabled= False
    )
    
    for upn in user_upns:
        result = await auth.client.users.by_user_id(upn).patch(request_body)
        
        results.append({
            "Response" : result,
            "Response Code": APIError.response_status_code
        })
    
    return results

async def revoke_user_sessions(user_upns: list[str]) -> list[dict]:
    results = []
    
    for upn in user_upns:
        try:
            
            result = await auth.client.users.by_user_id(upn).revoke_sign_in_sessions.post()
        
            results.append({
                "UPN": upn,
                "revocation_succeeded": result.value                
            })
        except APIError as error:
            logging.exception("Revoke sign action failed %s", upn)
            results.append({
                "UPN": upn,
                "Status": "unknown",
                "Exception" : str(error.message),
                "Response Code": error.response_status_code
            })

    return results

async def reset_password(user_upns: list[str]):
    results =[]

    
    for upn in user_upns:
        
        request_body = User(
        password_profile= PasswordProfile (
            force_change_password_next_sign_in= True,
            password=password_policy.generate_entra_password(length=14) #this must meet password policy requirements and may need rebuilding
            )
        )
        
        try:
            
            await auth.client.users.by_user_id(upn).patch(request_body)
            
            results.append({
                "UPN" : upn,
                "status": "successful"
            })
        except Exception as error:
            logging.exception(f"Unable to reset password for {upn}")
            
            results.append({
                "UPN" : upn,
                "status": "unknown",
                "Exception": str(error)
                
                })
    
    return results 

async def delete_MFA(user_upns: list[str])->list[dict]:
  
    results=[]
        
    for upn in user_upns:
        try:
            result_mfa = await auth.client.users.by_user_id(upn).authentication.methods.get()
        except Exception as error:
            logging.exception(f"Unable to get authentication methods for {upn}")
        
            results.append({
            "UPN" : upn,
            "status": "unknown",
            "Exception": str(error)
            })
            continue
            
        for mfa in result_mfa.value:
            status= "action_performed"
            try:
                match mfa.odata_type:
                    case "#microsoft.graph.emailAuthenticationMethod":
                        await auth.client.users.by_user_id(upn).authentication.email_methods.by_email_authentication_method_id(mfa.id).delete()
                    case "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":
                        await auth.client.users.by_user_id(upn).authentication.microsoft_authenticator_methods.by_microsoft_authenticator_authentication_method_id(mfa.id).delete()
                    case "#microsoft.graph.phoneAuthenticationMethod":
                        await auth.client.users.by_user_id(upn).authentication.phone_methods.by_phone_authentication_method_id(mfa.id).delete()    
                    case "#microsoft.graph.fido2AuthenticationMethod":
                        await auth.client.users.by_user_id(upn).authentication.fido2_methods.by_fido2_authentication_method_id(mfa.id).delete()
                    case _:
                        status = "skipped"
                
                results.append({
                    "upn": upn,
                    "status_deletion": status,
                    "mfa_id": mfa.id
                })
            except Exception as error:
                logging.exception(f"Unable to delete {mfa.odata_type} for {upn}")
                results.append({
                    "upn":upn,
                    "odata": mfa.odata_type,
                    "id": mfa.id,
                    "Exception": str(error),
                    "status": "unknown"
                })
                continue
                
    return results


async def check_target_user_audit_logs(user_upns: list[str], period: int)-> list[dict]:
    results = []
    
    hour = time_range(period)
    
    for upn in user_upns:
        
        query_param = DirectoryAuditsRequestBuilder.DirectoryAuditsRequestBuilderGetQueryParameters(
            filter=f"targetResources/any(tr: tr/userPrincipalName eq '{upn}') and targetResources/any(tr: tr/type eq 'User') and activityDateTime ge {hour}"
        )
        
        reques_config = RequestConfiguration(
            query_parameters=query_param
        )
        result = await auth.client.audit_logs.directory_audits.get(request_configuration=reques_config)

        results.append({
            "Response": result.value
        })
    
    return results

#Checks for Initiated Users using UPN. No provision made for service principals yet.
async def check_initiated_user_audit_logs(user_upns: list[str], period: int)-> list[dict]:
    results = []
    
    hour = time_range(period)
    
    for upn in user_upns:
        
        query_param = DirectoryAuditsRequestBuilder.DirectoryAuditsRequestBuilderGetQueryParameters(
            filter=f"(initiatedBy/user/userPrincipalName eq '{upn}') and activityDateTime ge {hour}"
        )
        
        reques_config = RequestConfiguration(
            query_parameters=query_param
        )
        result = await auth.client.audit_logs.directory_audits.get(request_configuration=reques_config)

        results.append({
            "Response": result.value
        })
    
    return results