from msgraph.graph_service_client import GraphServiceClient
from azure.identity.aio import ClientSecretCredential
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))


credentials = ClientSecretCredential (
    tenant_id= os.environ['TenantID'],
    client_id= os.environ['ClientID'],
    client_secret= os.environ['ClientSecret']
)

#get default permissions of registered app
scopes = ['https://graph.microsoft.com/.default']

client = GraphServiceClient (
    credentials=credentials,
    scopes=scopes
)

#API-Key Hybrid Analysis
api_key_ha = os.environ['HybridAnalysisAPIKey']

#API KEY VirusTotal
api_key_vt = os.environ['VTAPIKey']