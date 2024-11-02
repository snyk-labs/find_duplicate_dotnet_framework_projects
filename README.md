# Find duplicate .NET projects in Snyk

This script will search all organization with the group id you supply for .NET projects.  It will search each target for projects with a matching repo name, branch, and targetfile.  Then it will compare framework version and return a csv with this data.  This tool assumes that the snyk token has access to all organization in the group.  Future work will take the csv in and allow you to deactivate or delete the older projects.

## Requirements

Python version 3.10.0

## Tool arguments

Run the following to see tool options:

```bash
python3 index.py --help
```

## Script Arguments

[SNYK_GROUP_ID](https://docs.snyk.io/snyk-admin/groups-and-organizations/groups/group-general-settings)

## Running
```bash
export SNYK_TOKEN=TYPE-SNYK-TOKEN-HERE
pip install -r requirements.txt
python3 index.py GROUP_ID
```
