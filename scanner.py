class BlackDuckScanner:
    def __init__(self, auth_instance):
        self.auth = auth_instance
        self.session = auth_instance.session
        self.base_url = auth_instance.base_url

    def get_critical_components_in_group(self, group_id):
        """특정 프로젝트 그룹 내의 Critical 컴포넌트 리스트 추출"""
        results = []
        # 프로젝트 그룹 내 프로젝트 목록 API
        group_url = f"{self.base_url}/api/project-groups/{group_id}/projects"
        
        try:
            projects_res = self.session.get(group_url, params={"limit": 50})
            projects = projects_res.json().get('items', [])

            for project in projects:
                project_name = project['name']
                # 최신 버전 정보 가져오기 (첫 번째 아이템 기준)
                versions_url = project['_meta']['href'] + "/versions"
                versions = self.session.get(versions_url, params={"limit": 1}).json().get('items', [])
                
                if not versions:
                    continue
                
                version_href = versions[0]['_meta']['href']
                vuln_url = f"{version_href}/vulnerable-bom-components"
                vuln_params = {
                    "filter": [
                        "securityRisk:CRITICAL",
                        "securityRisk:HIGH",
                    ],
                    "limit": 100,
                }

                vuln_res = self.session.get(
                    vuln_url, 
                    headers={"Accept": "application/vnd.blackducksoftware.bill-of-materials-6+json"}, 
                    params=vuln_params,
                )
                for item in vuln_res.json().get('items', []):
                    vuln_info = item.get('vulnerability', {})
                    severity = vuln_info.get('severity')

                    if severity not in ('CRITICAL', 'HIGH'):
                        continue
                    
                    vuln_name = vuln_info.get('vulnerabilityId', 'Unknown')
                    
                    results.append({
                        "Project": project_name,
                        "Version": versions[0]['versionName'],
                        "Component": item.get('componentName'),
                        "Component_Version": item.get('componentVersionName', 'Unknown'),
                        "Vulnerability": vuln_name,
                    })
            return results
        except Exception as e:
            print(f"데이터 조회 중 에러 발생: {e}")
            return []
