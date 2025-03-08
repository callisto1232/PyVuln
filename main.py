import pkg_resources
import requests 
from datetime import datetime

installed_packages = pkg_resources.working_set

off='\033[0m'              
red = '\033[0;31m'          
green = '\033[0;32m'        
yellow = '\033[0;33m'       
blue = '\033[0;34m'         
purple = '\033[0;35m'       
cyan = '\033[0;36m'  

def get_severity_color(severity):
    severity = severity.lower() if severity else "unknown"
    colors = {
        "critical": '\033[1;31m',  # Bold Red
        "high": '\033[0;31m',      # Red
        "moderate": '\033[0;33m',   # Yellow
        "low": '\033[0;32m',        # Green
        "unknown": '\033[0;37m'     # Gray
    }
    return colors.get(severity, '\033[0;37m')

print("\033c", end="")
print(f"{blue}=== Güvenlik Açığı Tarama Aracı ==={off}\n")
print(f"{yellow}Tarama başlatılıyor...{off}\n")

for package in installed_packages:
    try:
        response = requests.get(f"https://pypi.org/pypi/{package.project_name}/{package.version}/json")
        result = response.json()
    except Exception as e:
        print(f"{red}Hata: {package.project_name} paketi için bilgi alınamadı - {str(e)}{off}")
        continue

    vulnerabilities = result.get("vulnerabilities", [])
    
    if vulnerabilities:
        print(f"{red}{'='*100}{off}")
        print(f"{blue}Paket: {cyan}{package.project_name} - {package.version}{off}")
        print(f"{red}{'='*100}{off}\n")
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Belirtilmemiş')
            severity_color = get_severity_color(severity)
            
            print(f"{blue}Güvenlik Açığı Detayları:{off}")
            print(f"{purple}{'─'*80}{off}")
            
            # CVE Numarası
            cve_id = vuln.get('cve_id') or vuln.get('id') or "CVE Belirtilmemiş"
            print(f"{cyan}CVE ID:{off} {cve_id}")
            
            # Önem Düzeyi
            print(f"{cyan}Önem Derecesi:{off} {severity_color}{severity}{off}")
            
            # Açık Detayları
            print(f"\n{cyan}Açık Detayı:{off}")
            print(f"{yellow}{vuln.get('details', 'Detay bulunmuyor.')}{off}")
            
            # Fixlendiği Sürüm
            if vuln.get('fixed_in'):
                print(f"\n{cyan}Düzeltildiği Sürüm:{off} {green}{vuln.get('fixed_in')}{off}")
            
            # Ek Bilgi
            print(f"\n{cyan}Referans Bağlantıları:{off}")
            if vuln.get('link'):
                print(f"{purple}* {vuln.get('link')}{off}")
            
            # Etkilenen Sürümler
            if vuln.get('vulnerable_versions'):
                print(f"\n{cyan}Etkilenen Sürümler:{off} {red}{vuln.get('vulnerable_versions')}{off}")
            
            print(f"\n{purple}{'─'*80}{off}\n")

    else:
        print(f"{package.project_name}: {green}Güvenlik açığı tespit edilmedi{off}")

print(f"\n{blue}Tarama tamamlandı!{off}")
