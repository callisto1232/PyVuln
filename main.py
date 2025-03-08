import pkg_resources
import requests 

installed_packages = pkg_resources.working_set

off='\033[0m'              
red = '\033[0;31m'          
green = '\033[0;32m'        
yellow = '\033[0;33m'       
blue = '\033[0;34m'         
purple = '\033[0;35m'         

print("\033c",end="")

for package in installed_packages:
    try:
        response = requests.get(f"https://pypi.org/pypi/{package.project_name}/{package.version}/json")
        result = response.json()
    except Exception as e:
        print("Bir hata oluştu! {e}")

    vulnerabilities = result.get("vulnerabilities")
    
    if vulnerabilities:
        print(red+"█"*150,off)
        print(f"\t\t\t{blue} {package.project_name} - {package.version} ")
        for vuln in vulnerabilities:
            print(f"{blue} {'-'*150} {off}")

            print(f"\t\t\t\t{green} Güvenlik açığı detayı \n {yellow} {vuln.get('details')} {off}")
            
            print(f"\t\t\tGüvenlik açığının düzeltildiği sürüm - {vuln.get('fixed_in')}")

            print(f"\t\t{purple} Daha fazla bilgi:{vuln.get('link')} {off}")
            
            print(red+"█"*150,off)

    else:
        print(f"{package.project_name} Paketinde herhangi bir güvenlik açığı bulunmadı {green}✔{off}")
