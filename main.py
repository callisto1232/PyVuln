import warnings
# pkg_resources DeprecationWarning uyarısını tamamen gizle
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.simplefilter("ignore", DeprecationWarning)

import pkg_resources
import requests 
from datetime import datetime


# Renk tanımlamaları
off = '\033[0m'              # Sıfırlama
red = '\033[0;31m'           # Kırmızı
green = '\033[0;32m'         # Yeşil
yellow = '\033[0;33m'        # Sarı
blue = '\033[0;34m'          # Mavi
purple = '\033[0;35m'        # Mor
cyan = '\033[0;36m'          # Camgöbeği
gray = '\033[0;37m'          # Gri

print("\033c", end="")
print(f"{blue}=== Güvenlik Açığı Tarama Aracı ==={off}")
print(f"{yellow}Tarama başlatılıyor...{off}\n")

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
        "critical": red,
        "high": red,
        "moderate": yellow,
        "low": green,
        "unknown": gray
    }
    return colors.get(severity, gray)

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
            print(f"{red}Güvenlik açığı tespit edildi{off}")
            print(f"\n{red}{'='*80}{off}")
            print(f"{blue}Paket: {cyan}{package.project_name} - {package.version}{off}")
            print(f"{red}{'='*80}{off}")
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'unknown')
                severity = severity.lower() if severity else "unknown"
                
                # İstatistikleri güncelle
                if severity in severity_stats:
                    severity_stats[severity] += 1
                else:
                    severity_stats["unknown"] += 1
                    
                severity_color = get_severity_color(severity)
                
                print(f"{blue}Güvenlik Açığı Detayları:{off}")
                print(f"{purple}{'-'*80}{off}")
                
                # CVE Numarası
                cve_id = vuln.get('cve_id') or vuln.get('id') or "CVE Belirtilmemiş"
                print(f"{cyan}CVE ID:{off} {cve_id}")
                
                # Önem Düzeyi
                severity_tr = get_severity_tr(severity)
                print(f"{cyan}Önem Derecesi:{off} {severity_color}{severity_tr}{off}")
                
                # Açık Detayları 
                details = vuln.get('details', 'Detay bulunmuyor.')
                print(f"\n{cyan}Açık Detayı:{off}")
                # Detayı kısalt 
                if len(details) > 200:
                    print(f"{yellow}{details[:200]}...{off}")
                else:
                    print(f"{yellow}{details}{off}")
                
                # Fixlendiği Sürüm
                if vuln.get('fixed_in'):
                    print(f"\n{cyan}Düzeltildiği Sürüm:{off} {green}{vuln.get('fixed_in')}{off}")
                    print(f"{cyan}Çözüm Önerisi:{off} {green}pip install {package.project_name}>={vuln.get('fixed_in')}{off}")
                
                # Ek Bilgi 
                if vuln.get('link'):
                    print(f"\n{cyan}Referans:{off} {purple}{vuln.get('link')}{off}")
                
                # Etkilenen Sürümler
                if vuln.get('vulnerable_versions'):
                    print(f"\n{cyan}Etkilenen Sürümler:{off} {red}{vuln.get('vulnerable_versions')}{off}")
                
                print(f"\n{purple}{'-'*80}{off}")
        else:
            print(f"{green}Güvenlik açığı tespit edilmedi{off}")
                
    except KeyboardInterrupt:
        print(f"\n\n{yellow}Tarama kullanıcı tarafından durduruldu!{off}")
        break
    except requests.exceptions.Timeout:
        print(f"{yellow}Zaman aşımı - Atlanıyor{off}")
        continue
    except Exception as e:
        # Hata durumunda devam et
        print(f"{yellow}Hata: Bilgi alınamadı{off}")
        continue

# Bitiş zamanını hesapla
end_time = datetime.now()
elapsed_time = (end_time - start_time).total_seconds()

print(f"\n\n{blue}Tarama tamamlandı!{off}")
print(f"{yellow}Toplamda {scanned_packages} paket tarandı!{off}")
print(f"{yellow}Tarama süresi: {elapsed_time:.2f} saniye{off}")

if vuln_packages:
    print(f"{red}Toplamda {vuln_packages} pakette güvenlik açığı tespit edildi{off}")
    
    print(f"\n{cyan}Önem Derecesine Göre Güvenlik Açığı Dağılımı:{off}")
    print(f"{purple}{'-'*50}{off}")
    
    severity_order = ["critical", "high", "moderate", "low", "unknown"]
    
    for severity in severity_order:
        if severity_stats[severity] > 0:
            severity_color = get_severity_color(severity)
            severity_tr = get_severity_tr(severity)
            print(f"{severity_color}{severity_tr}{off}: {severity_stats[severity]} adet")
    
    print(f"{purple}{'-'*50}{off}")
    
    # Güvenlik önerileri 
    print(f"\n{cyan}Güvenlik Önerileri:{off}")
    print(f"{yellow}1. Kritik ve yüksek öncelikli açıkları hemen giderin{off}")
    print(f"{yellow}2. Paketleri güncel tutun: pip install --upgrade <paket>{off}")
else:
    print(f"{green}Hiçbir pakette güvenlik açığı tespit edilmedi!{off}")
