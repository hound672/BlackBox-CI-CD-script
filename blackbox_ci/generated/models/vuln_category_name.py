from enum import Enum


class VulnCategoryName(str, Enum):
    ACCESS_CONTROL = 'access_control'
    CRYPTOGRAPHY = 'cryptography'
    CVE = 'cve'
    INJECTION = 'injection'
    INSECURE_DESIGN = 'insecure_design'
    SECURITY_HEADERS = 'security_headers'
    SECURITY_MISCONFIGURATION = 'security_misconfiguration'
    SENSITIVE_DATA = 'sensitive_data'
    TECH_INFO = 'tech_info'
    TRENDING = 'trending'

    def __str__(self) -> str:
        return str(self.value)
