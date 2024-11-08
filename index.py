import typer
from typing_extensions import Annotated
from helpers.helper import csv_to_json, create_csv_file, return_duplicate_cpp_projects, format_csv_data
from apis.snykApi import get_snyk_orgs, get_cpp_snyk_projects_for_target, get_snyk_targets, deactivate_snyk_project, delete_snyk_project

app = typer.Typer()

@app.command()
def delete_duplicate_cpp_projects(csv_file_path: Annotated[str, typer.Argument(help="Path to dotnet-projects-to-be-disabled-or-deleted.csv that was generated from the find-duplicate-cpp-projects command.")]):
    csv_data = csv_to_json(csv_file_path)
    print("Deleting Snyk projects")
    for data in csv_data:
        delete_snyk_project(data['Organization ID'], data['Old Project ID'])
        

@app.command()
def deactivate_duplicate_cpp_projects(csv_file_path: Annotated[str, typer.Argument(help="Path to dotnet-projects-to-be-disabled-or-deleted.csv that was generated from the find-duplicate-cpp-projects command.")]):
    csv_data = csv_to_json(csv_file_path)
    print("Deactivting Snyk projects")
    for data in csv_data:
        deactivate_snyk_project(data['Organization ID'], data['Old Project ID'])
    
    
@app.command()
def find_duplicate_cpp_projects(group_id: Annotated[str, typer.Argument(help="Original group ID in Snyk")]):
    # Gather orgs from provided group id
    print("Collecting organization IDs")
    orgs_data = get_snyk_orgs(group_id)
    # loop through org data
    cve_data = []
    print("Searching Snyk organizations for duplicate .NET projects with different framework versions")
    for org_data in orgs_data:
        targets_data = get_snyk_targets(org_data['id'])
        # loop through target data
        for target_data in targets_data:
            if any(target_data):
                # return any cpp projects in target
                projects_data = get_cpp_snyk_projects_for_target(org_data['id'], target_data['id'])
                if any(projects_data):
                    # Find duplicate .Net projects
                    duplicate_projects_data = return_duplicate_cpp_projects(projects_data)
                    for project_1, project_2 in duplicate_projects_data:
                        # new_project, old_project, new_targetframework, old_targetframework = return_targetframework_data(project_1, project_2)
                        # Retrieving names for csv and accounting for differences in json format.
                        # new_project_name = get_project_name(new_project)
                        # old_project_name = get_project_name(old_project)
                        # new_project_target_file = get_target_file_name(new_project)
                        # old_project_target_file = get_target_file_name(old_project)
                        # new_project_created_data = get_created_date(new_project)
                        # old_project_created_data = get_created_date(old_project)
                        
                        new_targetframework, old_targetframework, new_project, old_project, new_project_name, old_project_name, new_project_target_file, old_project_target_file, new_project_created_data, old_project_created_data = format_csv_data(project_1, project_2)
                    
                        if new_project == None:
                            print("Missing targetframework in one of the projects.  Skipping...")
                            continue
                        cve_data.append({
                            'Organization Name': org_data['attributes']['name'], 
                            'Organization ID': org_data['id'],
                            'Old Project ID': old_project['id'],
                            'New Project ID': new_project['id'], 
                            'Old Project Name': old_project_name,
                            'New Project Name': new_project_name, 
                            'Old Project Target file': new_project_target_file,
                            'New Project Target file': old_project_target_file,
                            'Old Project TargetFramework' : old_targetframework,
                            'New Project TargetFramework' : new_targetframework,
                            'Old Project Created Date' : old_project_created_data,
                            'New Project Created Date' : new_project_created_data
                        })
                        
    # Create CSV file
    create_csv_file(cve_data)
                      

if __name__ == "__main__":
    app()