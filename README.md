# PyVuln

Python paketlerinizin güvenlik açıklarını otomatik olarak tarayan basit ve etkili bir araç. PyPI API'sini kullanarak CVE numaralarını, önem derecelerini ve çözüm önerilerini gösterir.

## Hızlı Başlangıç

### Gereksinimler
```bash
pip install requests
```

### Çalıştırma
Tek komutla tarama yapın:
```bash
curl -s https://raw.githubusercontent.com/isa-programmer/PyVuln/refs/heads/main/main.py | python3
```

## Özellikler
- Sistemdeki tüm Python paketlerini otomatik tarama
- CVE numaraları ve detaylı açıklamalar
- Güvenlik açığı önem dereceleri (Kritik/Yüksek/Orta/Düşük)
- Düzeltme için gerekli versiyon bilgisi
- Etkilenen sürümler listesi
- Referans bağlantıları
- Renkli terminal çıktısı
