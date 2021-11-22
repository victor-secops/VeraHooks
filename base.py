import sys
import requests
import argparse as ap
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import json

api_base_v1 = "https://api.veracode.com/appsec/v1"
api_base_v2 = "https://api.veracode.com/appsec/v2"
headers = {"User-Agent": "Python HMAC Example"}

def getguid(appname):
    try:
        response = requests.get(api_base_v1 + "/applications?name=" + appname, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)
    except requests.RequestException as e:        
        print(e)
        sys.exit(1)
    if response.ok:
        for app in response.json()["_embedded"]["applications"]:
            guid=(app["guid"])  
        return guid          
    else:
        print(response.status_code)       
    
def getmitigated(guid):
    try:
        response = requests.get(api_base_v2 + "/applications/" + guid + "/findings?mitigated_after=2000-01-01", auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)
    except requests.RequestException as e:
        print(e)
        sys.exit(1)
    if response.ok:
        return response.json()
    else:
        print(response.status_code)
    
def create_baseline_file(data):
    virgula = ","
    with open("filename.json", 'w') as outfile1:
        for app in data["_embedded"]["findings"]:
            issue_id = app["issue_id"]
            description = app["description"]
            severity = app["finding_details"]["severity"]
            cwe = app["finding_details"]["cwe"]["id"]
            cwe_name = app["finding_details"]["cwe"]["name"]
            filepath = app["finding_details"]["file_path"]
            filename = app["finding_details"]["file_name"]
            module = app["finding_details"]["module"]
            category_id = app["finding_details"]["finding_category"]["id"]
            category_name = app["finding_details"]["finding_category"]["name"]
            procedure = app["finding_details"]["procedure"]
            attack_vector = app["finding_details"]["attack_vector"]
            line_number = app["finding_details"]["file_line_number"]
            virgula = ","
            json_data = {
    "cwe_id": cwe,
    "display_text": description,
    "files": {
     "source_file": {
      "file": filepath+filename,
      "function_name": "vote",
      "function_prototype": "",
      "line": line_number,
      "qualified_function_name": "",
      "scope": ""
      }
    },
     "issue_type": category_name,
     "issue_type_id": "taint",
     "severity": severity,
     "title": cwe_name
}

parser = ap.ArgumentParser(description='Rodar o programa dessa forma: python3 Pipeline2html.py --aplicacao')
parser.add_argument('--aplicacao', help='Nome da aplicação ex: ang-spag-base-manter-regras ', required=True)
args = parser.parse_args()

aplicacao = args.aplicacao

guid = getguid(aplicacao)
mitigated_flaws = getmitigated(guid)
create_baseline_file(mitigated_flaws)

