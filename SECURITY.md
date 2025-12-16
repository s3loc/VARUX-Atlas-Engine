# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

E-posta: security@varux.io adresine CVE formatında veya ayrıntılı PoC içeren
raporlar iletin. İlk yanıt SLA'sı 3 iş günüdür; kritik bulgularda 24 saat
içinde aksiyon planı paylaşılır.

## Secret rotasyonu
- `OPENAI_API_KEY`, OAuth istemci gizli anahtarları ve `VARUX_SESSION_SECRET`
  değerlerini en az 90 günde bir değiştirin; değişim öncesi ve sonrası erişim
  loglarını denetleyin.
- Rotasyon sırasında eski anahtarları aynı anda geçerli tutmak gerekiyorsa
  en kısa süre için ikili anahtar desteği sağlayın ve geçiş tamamlanınca eski
  anahtarları derhal iptal edin.
- Gizli bilgileri `.env` dosyalarında saklamayın; üretimde bir gizli yönetim
  servisi kullanın ve erişimi en az ayrıcalık ilkesiyle sınırlandırın.

## Production hardening
- Dashboard örneklerini ters proxy arkasında TLS (1.2+) ile sunun ve IP/ASN
  kısıtlamaları uygulayın.
- `VARUX_DB_URL` ile bağlandığınız veritabanında salt-okunur roller ve audit
  logging etkin olsun; düzenli yedek alma ve şifreli aktarım gereklidir.
- Sunucu üzerinde gereksiz servisleri devre dışı bırakın, SSH için anahtar
  tabanlı kimlik doğrulama zorunlu kılın ve otomatik güvenlik yamalarını
  etkinleştirin.
