import requests
import logging
import json
from package.utils import get_headers

logging.basicConfig(level=logging.INFO)

class GithubRepoClient:
    """
    Initialize the GithubRepoClient with a GitHub token.
    
    Parameters:
    github_token (str): The GitHub token used for authentication.
    """
    def __init__(self, github_token):
        self.github_token = github_token
        self.headers = get_headers(self.github_token)

    def get_existing_repositories(self, org_or_user):
        """
        Get the existing repositories for a specified organization or user.
        
        Parameters:
        org_or_user (str): The name of the organization or user.
        
        Returns:
        list: A list of existing repositories.
        """
        base_url = f"https://api.github.com/orgs/{org_or_user}/repos"
        existing_repositories = []
        page = 1
        per_page = 100

        while True:
            response = requests.get(base_url, headers=self.headers, params={"page": page, "per_page": per_page})
            if response.status_code == 200:
                repos_on_page = response.json()
                if not repos_on_page:
                    break

                existing_repositories.extend(repo["name"] for repo in repos_on_page)
                page += 1
            else:
                logging.error(f"Failed to retrieve existing repositories. Status code: {response.status_code}")
                break
        return existing_repositories

    def create_repos(self, org_or_user, repositories, repo_visibility="private", branch_protection_payload=None):
        """
        Create repositories for a specified organization or user.
        
        Parameters:
        org_or_user (str): The name of the organization or user.
        repositories (list): A list of repositories to be created.
        repo_visibility (str): The visibility of the repositories (e.g., 'private','internal' or 'public').
        branch_protection_payload (dict): The payload for branch protection.
        """
        if branch_protection_payload is None:
            branch_protection_payload = {
                "required_status_checks": None,
                "enforce_admins": True,
                "required_pull_request_reviews": {
                    "dismissal_restrictions": {},
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": False,
                    "required_approving_review_count": 1,
                    "require_last_push_approval": True,
                    "bypass_pull_request_allowances": {
                        "users": [],
                        "teams": []
                    }
                },
                "restrictions": None,
                "required_linear_history": True,
                "allow_force_pushes": False,
                "allow_deletions": False,
                "block_creations": True,
                "required_conversation_resolution": True,
                "lock_branch": False,
                "allow_fork_syncing": False
            }
        base_url = f"https://api.github.com/orgs/{org_or_user}/repos"
        existing_repositories = self.get_existing_repositories(org_or_user)
        if(repo_visibility == "internal"):
            base_url = f"https://api.github.com/orgs/{org_or_user}"
            response = requests.get(base_url, headers=self.headers)
            if response.status_code == 404:
                logging.WARNING(f"User {org_or_user} does not exist. Changing visibility to private")
                repo_visibility = "private"
        for repo in repositories:
            logging.info(repo)
            repo_name = repo['repo_name']
            repo_description = repo.get('description', None)

            if repo_name in existing_repositories:
                logging.info(f"Repository '{repo_name}' already exists. Skipping creation.")
            else:
                repo_payload = {
                    "name": repo_name,
                    "description": repo_description,
                    "private": True,
                    "visibility": repo_visibility,
                    "auto_init": repo.get("auto_init", True)
                }
                    
                response = requests.post(base_url, headers=self.headers, json=repo_payload)
                if response.status_code == 201:
                    logging.info(f"Repository '{repo_name}' created successfully.")
                else:
                    logging.error(f"Failed to create repository '{repo_name}'. Status code: {response.status_code}")
                    logging.error(response.text)

                self.enable_vuln_alerts(org_or_user, repo_name)
                self.enable_automated_fixes(org_or_user, repo_name)
                if repo.get('branch_protection', True):
                    self.enable_branch_protection(org_or_user, repo_name, branch_protection_payload)

    def create_repos_from_template(self, org_or_user, repositories, template_repo, repo_visibility="private", branch_protection_payload=None):
        """
        Create repositories for a specified organization or user from a template repository.
        
        Parameters:
        org_or_user (str): The name of the organization or user.
        repositories (list): A list of repositories to be created.
        template_owner (str): The owner of the template repository.
        template_repo (str): The name of the template repository.
        repo_visibility (str): The visibility of the repositories (e.g., 'private','internal' or 'public').
        branch_protection_payload (dict): The payload for branch protection.
        """
        if branch_protection_payload is None:
            branch_protection_payload = {
                "required_status_checks": None,
                "enforce_admins": True,
                "required_pull_request_reviews": {
                    "dismissal_restrictions": {},
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": False,
                    "required_approving_review_count": 1,
                    "require_last_push_approval": True,
                    "bypass_pull_request_allowances": {
                        "users": [],
                        "teams": []
                    }
                },
                "restrictions": None,
                "required_linear_history": True,
                "allow_force_pushes": False,
                "allow_deletions": False,
                "block_creations": True,
                "required_conversation_resolution": True,
                "lock_branch": False,
                "allow_fork_syncing": False
            }
        base_url = f"https://api.github.com/repos/{org_or_user}/{template_repo}"
        template_response = requests.get(base_url, headers=self.headers)
        template_data = template_response.json()
        if template_data.get("is_template") == False:
            logging.error(f"Repository '{template_repo}' is not a template repository.")
            return
        if template_response.status_code != 200:
            logging.error(f"Failed to retrieve template repository '{template_repo}'. Status code: {template_response.status_code}")
            logging.error(template_response.text)
            return
        base_url = f"{base_url}/generate"
        existing_repositories = self.get_existing_repositories(org_or_user)
        if(repo_visibility == "internal"):
            org_url = f"https://api.github.com/orgs/{org_or_user}"
            response = requests.get(org_url, headers=self.headers)
            if response.status_code == 404:
                logging.warning(f"{org_or_user} does not seem to be an organization. Changing visibility to private due to github constraints")
                repo_visibility = "private"
        for repo in repositories:
            repo_name = repo['repo_name']
            repo_description = repo.get('description', None)

            if repo_name in existing_repositories:
                logging.info(f"Repository '{repo_name}' already exists. Skipping creation.")
            else:
                repo_payload = {
                    "owner": org_or_user,
                    "name": repo_name,
                    "description": repo_description,
                    "private": True,
                }
                
                response = requests.post(base_url, headers=self.headers, json=repo_payload)
                if response.status_code == 201:
                    logging.info(f"Repository '{repo_name}' created successfully.")
                    if(repo_visibility == "internal"):
                        repo_settings_url = f"https://api.github.com/repos/{org_or_user}/{repo_name}"
                        repo_settings_payload = {
                            "visibility": "internal"
                        }
                        settings_response = requests.patch(repo_settings_url, headers=self.headers, json=repo_settings_payload)
                        if settings_response.status_code == 200:
                            logging.info(f"Repository '{repo_name}' visibility updated to internal.")
                        else:
                            logging.error(f"Failed to update visibility for repository '{repo_name}'. Status code: {settings_response.status_code}")
                            logging.error(settings_response.text)
                else:
                    logging.error(f"Failed to create repository '{repo_name}'. Status code: {response.status_code}")
                    logging.error(response.text)
                
                self.enable_vuln_alerts(org_or_user, repo_name)
                self.enable_automated_fixes(org_or_user, repo_name)

    def enable_vuln_alerts(self, org_or_user, repo_name):
        """
        Enable vulnerability alerts for a specified repository.
        
        Parameters:
        org_or_user (str): The name of the organization or user.
        repo_name (str): The name of the repository.
        """
        vuln_alerts_url = f"https://api.github.com/repos/{org_or_user}/{repo_name}/vulnerability-alerts"
        response = requests.put(vuln_alerts_url, headers=self.headers)
        if response.status_code == 204:
            logging.info(f"Vulnerability alerts for '{repo_name}' enabled successfully.")
        else:
            logging.error(f"Failed to enable vulnerability alerts for '{repo_name}'. Status code: {response.status_code}")
            logging.error(response.text)

    def enable_automated_fixes(self, org_or_user, repo_name):
        """
        Enable automated fixes for a specified repository.
        
        Parameters:
        org_or_user (str): The name of the organization or user.
        repo_name (str): The name of the repository.
        """
        automated_security_fixes_url = f"https://api.github.com/repos/{org_or_user}/{repo_name}/automated-security-fixes"
        response = requests.put(automated_security_fixes_url, headers=self.headers)
        if response.status_code == 204:
            logging.info(f"Automated security fixes for '{repo_name}' enabled successfully.")
        else:
            logging.error(f"Failed to enable automated security fixes for '{repo_name}'. Status code: {response.status_code}")
            logging.error(response.text)

    def enable_branch_protection(self, org_or_user, repo_name, branch_protection_payload):
        """
        Enable branch protection for a specified repository.
        
        Parameters:
        org_or_user (str): The name of the organization or user.
        repo_name (str): The name of the repository.
        branch_protection_payload (dict): The payload for branch protection.
        """
        branch_protection_url = f"https://api.github.com/repos/{org_or_user}/{repo_name}/branches/main/protection"
        response = requests.put(branch_protection_url, headers=self.headers, json=branch_protection_payload)
        if response.status_code == 200:
            logging.info(f"Branch protection for '{repo_name}' enabled successfully.")
        else:
            logging.error(f"Failed to enable branch protection for '{repo_name}'. Status code: {response.status_code}")
            logging.error(response.text)

    def create_envs(self, org_or_user, repositories):
        """
        Create environments for a specified organization or user.
        
        Parameters:
        org_or_user (str): The name of the organization or user.
        repositories (list): A list of repositories for which to create environments.
        """
        logging.info("Starting environment creation process...")
        for repo in repositories:
            repo_name = repo["repo_name"]
            environments = repo.get("environments", [])

            for environment in environments:
                environment_name = environment["environment_name"]
                protected_branches_only = environment.get("protected_branches_only", False)

                base_url = f"https://api.github.com/repos/{org_or_user}/{repo_name}/environments/{environment_name}"
                payload = {}
                if protected_branches_only:
                    payload["deployment_branch_policy"] = {
                        "protected_branches": protected_branches_only,
                        "custom_branch_policies": False
                    }
                response = requests.put(base_url, headers=self.headers, json=payload)
                if response.status_code == 200:
                    logging.info(f"Environment '{environment_name}' created successfully for repository '{repo_name}'.")
                else:
                    logging.error(f"Failed to create environment '{environment_name}' for repository '{repo_name}'. Status code: {response.status_code}")
                    logging.error(f"Response text: {response.text}")
        logging.info("Environment creation process completed.")