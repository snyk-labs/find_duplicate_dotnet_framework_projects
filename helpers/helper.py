from datetime import datetime
import csv
import json
import os
import re
import sys
from collections import defaultdict

def get_snyk_token():
    SNYK_TOKEN = check_if_snyk_token_exist()
    
    pattern = re.compile(r'([\d\w]{8}-[\d\w]{4}-[\d\w]{4}-[\d\w]{4}-[\d\w]{12})')
    if pattern.fullmatch(SNYK_TOKEN) == None:
        print("Snyk token is not defined or not valid.")
        sys.exit()
    else:
        return SNYK_TOKEN

def check_if_snyk_token_exist():
    print("Checking for Snyk token environment variable")
    try:
        if os.environ.get('SNYK_TOKEN'):
            print("Found snyk token")
            return os.getenv('SNYK_TOKEN')
    except:
        print("Snyk token does not exist")
        sys.exit()
        
def check_dry_run_variable(dryRun):
    dry_run = str(dryRun).lower()
    if dry_run == 'false' or dry_run == 'true':
        print(f'Dry Run variable is: {dryRun}')
        return dryRun
    else:
        return None


def compare_dates(date_str_1, date_str_2):
    # Convert date strings to datetime objects
    date_1 = datetime.fromisoformat(date_str_1.replace('Z', '+00:00'))
    date_2 = datetime.fromisoformat(date_str_2.replace('Z', '+00:00'))
    
    # Compare dates
    if date_1 < date_2:
        return 0
    elif date_1 > date_2:
        return 1
    else:
        return 2
    

def parse_version(version):
    # Extract numeric parts of targetframework
    return [int(part) for part in re.findall(r'\d+', version)]


def return_targetframework_data(project_1, project_2):
    # Compare versions
    target_framework_1 = get_targetframework(project_1)
    target_framework_2 = get_targetframework(project_2)
    
    parsed_framework_version_1 = parse_version(target_framework_1)
    parsed_framework_version_2 = parse_version(target_framework_2)

    # Determine which version is larger and return newer project first
    if parsed_framework_version_1 > parsed_framework_version_2:
        return project_1, project_2, parsed_framework_version_1, parsed_framework_version_2
    else:
        return project_2, project_1, parsed_framework_version_2, parsed_framework_version_1
    

def get_project_name(project_data):
    if "name" in project_data:
        return project_data["name"]
    if "attributes" in project_data:
        return project_data["attributes"]["name"]
    else:
        return None
    
    
def get_target_file_name(project_data):
    if "target_file" in project_data:
        return project_data["target_file"]
    if "attributes" in project_data:
        return project_data["attributes"]["target_file"]
    else:
        return None
    

def get_created_date(project_data):
    if "created" in project_data:
        return project_data["created"]
    if "attributes" in project_data:
        return project_data["attributes"]["created"]
    else:
        return None
    
          
def create_csv_file(data):
    csv_file_path = 'dotnet-projects-to-be-disabled-or-deleted.csv'
    try:
        print(f'Creating {csv_file_path}')
        with open(csv_file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)  
            writer.writerow(['Organization Name', 
                            'Organization ID',
                            'Old Project ID',
                            'New Project ID', 
                            'Old Project Name',
                            'New Project Name', 
                            'Old Project Target file',
                            'New Project Target file',
                            'Old Project TargetFramework',
                            'New Project TargetFramework',
                            'Old Project Created Date',
                            'New Project Created Date'])

            # Iterate over the outer list
            for item in data:
                # Extracting values
                organization_name = item['Organization Name']
                organization_id = item['Organization ID']
                old_project_id = item['Old Project ID']
                new_project_id = item['New Project ID']
                old_project_name = item['Old Project Name']
                new_project_name = item['New Project Name']
                old_project_target_file = item['Old Project Target file']
                new_project_target_file = item['New Project Target file']
                old_project_targetframework = item['Old Project TargetFramework']
                new_project_targetframework = item['New Project TargetFramework']
                old_project_create_date = item['Old Project Created Date']
                new_project_create_data = item['New Project Created Date']

                # Write the row to CSV file
                writer.writerow([organization_name, organization_id, old_project_id, new_project_id, old_project_name, new_project_name, old_project_target_file, new_project_target_file, old_project_targetframework, new_project_targetframework, old_project_create_date, new_project_create_data])

        print(f"Data written to {csv_file_path} successfully.")
    except Exception as e:
        print(f"Failed to create {csv_file_path}. An error occurred: {e}")


def get_targetframework(project_data):
    if "target_runtime" in project_data:
        return project_data["target_runtime"]
    if "attributes" in project_data:
        return project_data["attributes"]["target_runtime"]
    else:
        return None        
        
def find_duplicate_cpp_projects(projects_data):
    print('Comparing project data...')
    seen = {}
    conflicts = []

    for project in projects_data:
        attrs = project["attributes"]
        key = (attrs["name"], attrs["target_file"], attrs["target_reference"])
        # Check if target runtime exist
        if "target_runtime" in attrs:
            runtime = attrs["target_runtime"]
            
            if key in seen:
                # Check for different target_runtime
                if seen[key]["target_runtime"] != runtime:
                    conflicts.append((seen[key], project))
            else:
                seen[key] = {**attrs, "id": project["id"]}  # Include the ID in the same dictionary
        else:
            print(f"Target Runtime doesn't exist for {project['attributes']['name']}, skipping comparision")

    return conflicts                  