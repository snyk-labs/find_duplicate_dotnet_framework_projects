# import json
import json
from time import sleep
import requests
# from requests.exceptions import HTTPError
# import time

from helpers.helper import get_snyk_token

SNYK_TOKEN = get_snyk_token()

rest_headers = {'Content-Type': 'application/vnd.api+json', 'Authorization': f'token {SNYK_TOKEN}'}
v1Headers = {'Content-Type': 'application/json; charset=utf-8', 'Authorization': f'token {SNYK_TOKEN}'}
rest_version = '2024-10-15'

def create_request_method(method):
    methods = {
        'GET': requests.get,
        'POST': requests.post,
        'PUT': requests.put,
        'DELETE': requests.delete,
        'PATCH': requests.patch,
    }

    http_method = methods.get(method.upper())
    
    return http_method

# Paginate through Snyk's API endpoints with retry and backoff
def pagination_snyk_rest_endpoint(method, url, *args):
    retries = 3
    delay = 5
    http_method = create_request_method(method)
    if any(args):
        for attempt in range(retries):
            try:
                api_response = http_method(url, headers=rest_headers, data=json.dumps(args[0]))
                api_response.raise_for_status()
                return api_response
            except requests.RequestException as e:
                print(f"Attempt {attempt + 1} failed: {e}")
                if attempt < retries - 1:
                    sleep(delay)
                else:
                    print("All attempts failed.")
                    raise
    else:
        has_next_link = True
        data = []
        while has_next_link:
            for attempt in range(retries):
                try:
                    api_response = http_method(url, headers=rest_headers)
                    api_data = api_response.json()['data']
                    data.extend(api_data)
                    # If the response status is 429, handle the rate limit
                    if api_response.status_code == 429:
                        print(f"Rate limit exceeded. Waiting for 60 seconds.")
                        sleep(61)
                        continue
                except requests.RequestException as e:
                    print(f"Attempt {attempt + 1} failed: {e}")
                    if attempt < retries - 1:
                        sleep(delay)
                    else:
                        print("All attempts failed.")
                        raise
                
                # Check if next page exist and set url if it does.  If not, exit and return issuesData
                try:
                    api_response.json()['links']['next']
                    url = 'https://api.snyk.io' + api_response.json()['links']['next']
                except:
                    has_next_link = False
                    return data
    
                
# Return all Snyk targets in organization
def get_snyk_targets(org_id):
    print(f"Collecting snyk organization targets for {org_id}")
    url = f'https://api.snyk.io/rest/orgs/{org_id}/targets?version={rest_version}&limit=100'
    
    target_data = pagination_snyk_rest_endpoint('GET', url)
    
    return target_data


# Return all Snyk orgs in group
def get_snyk_orgs(groupId):
    # print("Collecting organization IDs")
    url = f'https://api.snyk.io/rest/groups/{groupId}/orgs?version={rest_version}&limit=100'

    org_data = pagination_snyk_rest_endpoint('GET', url)
    
    return org_data

# Get cpp projects from all Snyk Orgs.
def get_cpp_snyk_projects_for_target(org_id, target_id):
    # print("Collecting cpp project data")
    url = f'https://api.snyk.io/rest/orgs/{org_id}/projects/?version={rest_version}&limit=100&types=nuget%2Ccpp&target_id={target_id}'
    
    cpp_project_data = pagination_snyk_rest_endpoint('GET', url)
    
    return cpp_project_data

# Get all projects from list of Snyk orgs.
# def get_snyk_projects(orgs_data):
#     print("Collecting projects data")
#     projects = []
#     for org_data in orgs_data:
#         org_id = org_data['id']
#         url = f'https://api.snyk.io/rest/orgs/{org_id}/projects/?version={rest_version}&limit=100'

#         has_next_link = True

#         while has_next_link:
#             try:
#                 projects_api_response = requests.get(url, headers=rest_headers)
#                 projectsData = projects_api_response.json()['data']
#                 projects.extend(projectsData)
#             except:
#                 print("Targets endpoint call failed.")
#                 print(projects_api_response)
            
#             # Check if next page exist and set url if it does.  If not, exit and return issuesData
#             try:
#                 projects_api_response.json()['links']['next']
#                 url = 'https://api.snyk.io' + projects_api_response.json()['links']['next']
#             except:
#                 has_next_link = False

#     return projects

# def get_snyk_project(org_id, project_id):
#     print("Collecting project data")
#     url = f'https://api.snyk.io/rest/orgs/{org_id}/projects/{project_id}?version={rest_version}'

#     try:
#         projects_api_response = requests.get(url, headers=rest_headers)
#         projectsData = projects_api_response.json()['data']
#         return projectsData
#     except:
#         print("Targets endpoint call failed.")
#         print(projects_api_response)
#         return projects_api_response

def deactivate_snyk_project(org_id, project_id):
    print(f"Disabling Snyk project.  Project ID: {project_id}")
    url = f'https://api.snyk.io/v1/org/{org_id}/project/{project_id}/deactivate'
        
    try:
        deactivate_project_response = requests.post(url, headers=v1Headers, data={})
        if deactivate_project_response.status_code == 200:
            print("Project successfully disabled.")    
    except:
        print(f"Disable project endpoint failed with the following error code: {deactivate_project_response.status_code}.  Here is the error: {deactivate_project_response} ") 