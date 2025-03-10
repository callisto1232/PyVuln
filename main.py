import warnings
# pkg_resources DeprecationWarning uyarısını tamamen gizle
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.simplefilter("ignore", DeprecationWarning)

import pkg_resources
import requests 
from datetime import datetime


# Renk tanımlamaları
class Colors:
    off = '\033[0m'              # Sıfırlama
    red = '\033[0;31m'           # Kırmızı
    green = '\033[0;32m'         # Yeşil
    yellow = '\033[0;33m'        # Sarı
    blue = '\033[0;34m'          # Mavi
    purple = '\033[0;35m'        # Mor
    cyan = '\033[0;36m'          # Camgöbeği
    gray = '\033[0;37m'          # Gri

print("\033c", end="")
print(f"{Colors.blue}=== Güvenlik Açığı Tarama Aracı ==={Colors.off}")
print(f"{Colors.yellow}Tarama başlatılıyor...{Colors.off}\n")

installed_packages = list(pkg_resources.working_set)
total_packages = len(installed_packages)
scanned_packages = 0
vuln_packages = 0

start_time = datetime.now()

# Önem derecesine göre istatistik 
severity_stats = {
    "critical": 0,
    "high": 0,
    "moderate": 0,
    "low": 0,
    "unknown": 0
}

def get_severity_color(severity):
    severity = severity.lower() if severity else "unknown"
    colors = {
        "critical": Colors.red,
        "high": Colors.red,
        "moderate": Colors.yellow,
        "low": Colors.green,
        "unknown": Colors.gray
    }
    return colors.get(severity, Colors.gray)

def get_severity_tr(severity):
    severity_tr = {
        "critical": "Kritik",
        "high": "Yüksek",
        "moderate": "Orta",
        "low": "Düşük",
        "unknown": "Bilinmiyor"
    }
    return severity_tr.get(severity.lower(), severity.capitalize())

session = requests.Session()

# timeout değeri
TIMEOUT = 14

for i, package in enumerate(installed_packages):
    try:
        print(f"{package.project_name}: ", end="", flush=True)
        response = session.get(
            f"https://pypi.org/pypi/{package.project_name}/{package.version}/json", 
            timeout=TIMEOUT
        )
        
        result = response.json()
        scanned_packages += 1
        
        vulnerabilities = result.get("vulnerabilities", [])
        
        if vulnerabilities:
            vuln_packages += 1
            print(f"{Colors.red}Güvenlik açığı tespit edildi{Colors.off}")
            print(f"\n{Colors.red}{'='*80}{Colors.off}")
            print(f"{Colors.blue}Paket: {Colors.cyan}{package.project_name} - {package.version}{Colors.off}")
            print(f"{Colors.red}{'='*80}{Colors.off}")
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'unknown')
                severity = severity.lower() if severity else "unknown"
                
                # İstatistikleri güncelle
                if severity in severity_stats:
                    severity_stats[severity] += 1
                else:
                    severity_stats["unknown"] += 1
                    
                severity_color = get_severity_color(severity)
                
                print(f"{Colors.blue}Güvenlik Açığı Detayları:{Colors.off}")
                print(f"{Colors.purple}{'-'*80}{Colors.off}")
                
                # CVE Numarası
                cve_id = vuln.get('cve_id') or vuln.get('id') or "CVE Belirtilmemiş"
                print(f"{Colors.cyan}CVE ID:{Colors.off} {cve_id}")
                
                # Önem Düzeyi
                severity_tr = get_severity_tr(severity)
                print(f"{Colors.cyan}Önem Derecesi:{Colors.off} {severity_color}{severity_tr}{Colors.off}")
                
                # Açık Detayları 
                details = vuln.get('details', 'Detay bulunmuyor.')
                print(f"\n{Colors.cyan}Açık Detayı:{Colors.off}")
                # Detayı kısalt 
                if len(details) > 200:
                    print(f"{Colors.yellow}{details[:200]}...{Colors.off}")
                else:
                    print(f"{Colors.yellow}{details}{Colors.off}")
                
                # Fixlendiği Sürüm
                if vuln.get('fixed_in'):
                    print(f"\n{Colors.cyan}Düzeltildiği Sürüm:{Colors.off} {Colors.green}{vuln.get('fixed_in')}{Colors.off}")
                    print(f"{Colors.cyan}Çözüm Önerisi:{Colors.off} {Colors.green}pip install {package.project_name}>={vuln.get('fixed_in')}{Colors.off}")
                
                # Ek Bilgi 
                if vuln.get('link'):
                    print(f"\n{Colors.cyan}Referans:{Colors.off} {Colors.purple}{vuln.get('link')}{Colors.off}")
                
                # Etkilenen Sürümler
                if vuln.get('vulnerable_versions'):
                    print(f"\n{Colors.cyan}Etkilenen Sürümler:{Colors.off} {Colors.red}{vuln.get('vulnerable_versions')}{Colors.off}")
                
                print(f"\n{Colors.purple}{'-'*80}{Colors.off}")
        else:
            print(f"{Colors.green}Güvenlik açığı tespit edilmedi{Colors.off}")
                
    except KeyboardInterrupt:
        print(f"\n\n{Colors.yellow}Tarama kullanıcı tarafından durduruldu!{Colors.off}")
        break
    except requests.exceptions.Timeout:
        print(f"{Colors.yellow}Zaman aşımı - Atlanıyor{Colors.off}")
        continue
    except Exception as e:
        # Hata durumunda devam et
        print(f"{Colors.yellow}Hata: Bilgi alınamadı{Colors.off}")
        continue

# Bitiş zamanını hesapla
end_time = datetime.now()
elapsed_time = (end_time - start_time).total_seconds()

print(f"\n\n{Colors.blue}Tarama tamamlandı!{Colors.off}")
print(f"{Colors.yellow}Toplamda {scanned_packages} paket tarandı!{Colors.off}")
print(f"{Colors.yellow}Tarama süresi: {elapsed_time:.2f} saniye{Colors.off}")

if vuln_packages:
    print(f"{Colors.red}Toplamda {vuln_packages} pakette güvenlik açığı tespit edildi{Colors.off}")
    
    print(f"\n{Colors.cyan}Önem Derecesine Göre Güvenlik Açığı Dağılımı:{Colors.off}")
    print(f"{Colors.purple}{'-'*50}{Colors.off}")
    
    severity_order = ["critical", "high", "moderate", "low", "unknown"]
    
    for severity in severity_order:
        if severity_stats[severity] > 0:
            severity_color = get_severity_color(severity)
            severity_tr = get_severity_tr(severity)
            print(f"{severity_color}{severity_tr}{Colors.off}: {severity_stats[severity]} adet")
    
    print(f"{Colors.purple}{'-'*50}{Colors.off}")
    
    # Güvenlik önerileri 
    print(f"\n{Colors.cyan}Güvenlik Önerileri:{Colors.off}")
    print(f"{Colors.yellow}1. Kritik ve yüksek öncelikli açıkları hemen giderin{Colors.off}")
    print(f"{Colors.yellow}2. Paketleri güncel tutun: pip install --upgrade <paket>{Colors.off}")
else:
    print(f"{Colors.green}Hiçbir pakette güvenlik açığı tespit edilmedi!{Colors.off}")
