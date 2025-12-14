#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VARUX Security Framework - Elite Edition v1.0
© 2025 VARUX Security - Tüm hakları saklıdır.
Tek dosya ile tüm modülleri çalıştırır.
"""

import os
import sys
import asyncio
import importlib.util
from pathlib import Path

# varux klasörünü Python yoluna ekle (modülleri bulsun diye)
BASE_DIR = Path(__file__).resolve().parent
VARUX_DIR = BASE_DIR / "varux"
sys.path.insert(0, str(VARUX_DIR))

# Gerekli modül dizini var mı kontrol et
if not VARUX_DIR.exists():
    print(f"{VARUX_DIR} bulunamadı. Lütfen projenin kök dizininden çalıştırın.")
    sys.exit(1)

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    print("colorama yüklü değil, renkler devre dışı.")
    class Fore: RED = YELLOW = GREEN = CYAN = MAGENTA = WHITE = ""
    class Style: BRIGHT = RESET_ALL = ""

# ==========================================
# ASCII LOGO (isteğe bağlı, çok havalı duruyor)
# ==========================================
LOGO = f"""
{Fore.RED}██╗   ██╗{Fore.YELLOW} █████╗ {Fore.CYAN}██████╗ {Fore.GREEN}██╗   ██╗██╗  ██╗
{Fore.RED}╚██╗ ██╔╝{Fore.YELLOW}██╔══██╗{Fore.CYAN}██╔══██╗{Fore.GREEN}██║   ██║╚██╗██╔╝
{Fore.RED} ╚████╔╝ {Fore.YELLOW}███████║{Fore.CYAN}██████╔╝{Fore.GREEN}██║   ██║ ╚███╔╝ 
{Fore.RED}  ╚██╔╝  {Fore.YELLOW}██╔══██║{Fore.CYAN}██╔══██╗{Fore.GREEN}██║   ██║ ██╔██╗ 
{Fore.RED}   ██║   {Fore.YELLOW}██║  ██║{Fore.CYAN}██║  ██║{Fore.GREEN}╚██████╔╝██╔╝ ██╗
{Fore.RED}   ╚═╝   {Fore.YELLOW}╚═╝  ╚═╝{Fore.CYAN}╚═╝  ╚═╝ {Fore.GREEN}╚═════╝ ╚═╝  ╚═╝
{Fore.WHITE}{Style.BRIGHT}           ELITE EDITION v1.0 - 2025
"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def load_module(module_path):
    """Boşluklu dosya adları için güvenli modül yükleyici.

    ``spec_from_file_location`` nadiren de olsa ``None`` döndürebilir veya
    "loader" içermeyebilir. Bu durumda mevcut kod ``AttributeError`` ile
    kullanıcıyı yarı yolda bırakıyordu. Yükleyici bulunamazsa anlaşılır bir
    ``RuntimeError`` fırlatarak hangi dosyanın yüklenemediğini bildiriyoruz ve
    beklenmedik hataların önüne geçiyoruz.
    """

    spec = importlib.util.spec_from_file_location(
        module_path.stem.replace(" ", "_"),  # Boşlukları _ ile değiştir
        str(module_path)
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Modül yüklenemedi: {module_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_path.stem.replace(" ", "_")] = module
    spec.loader.exec_module(module)
    return module


def run_health_check():
    """Çekirdek bağımlılık ve ortam kontrollerini çalıştır."""

    try:
        from varux.core.diagnostics import run_diagnostics

        diagnostics_paths = [VARUX_DIR / "requirements.txt", Path.home() / ".varux"]
        report = run_diagnostics(paths=diagnostics_paths)
        print(report.format_as_table())
    except Exception as exc:  # pragma: no cover - sadece CLI çıktısı
        print(f"{Fore.RED}Tanılama çalıştırılamadı: {exc}")

def main_menu():
    while True:
        clear_screen()
        print(LOGO)
        print(f"{Fore.CYAN}┌{'─' * 58}┐")
        print(f"{Fore.CYAN}│{Fore.WHITE}                   ANA MENÜ                          {Fore.CYAN}│")
        print(f"{Fore.CYAN}└{'─' * 58}┘\n")
        print(f"{Fore.YELLOW}[1]{Fore.WHITE} Endüstriyel Ağ Keşfi (industrial_recon)       ")
        print(f"{Fore.YELLOW}[2]{Fore.WHITE} Web & SQL Injection Tarama (noxım)            ")
        print(f"{Fore.YELLOW}[3]{Fore.WHITE} Tam Otomatik Pentest (varuxctl)               ")
        print(f"{Fore.YELLOW}[4]{Fore.WHITE} ICS/SCADA Derin Keşif (VARUX OT Discovery Framework)")
        print(f"{Fore.YELLOW}[5]{Fore.WHITE} SQLMap Elite Wrapper (sqlmap_wrapper)         ")
        print(f"{Fore.YELLOW}[6]{Fore.WHITE} AI Kod Asistanı (OpenAI)                       ")
        print(f"{Fore.YELLOW}[D]{Fore.WHITE} Sistem Sağlık Kontrolü                          ")
        print(f"{Fore.YELLOW}[7]{Fore.WHITE} Çıkış                                         \n")

        secim = input(f"{Fore.CYAN}Seçiminiz (1-7): {Fore.WHITE}").strip()

        if secim == "1":
            try:
                industrial_path = VARUX_DIR / "industrial_recon.py"
                module = load_module(industrial_path)
                # Modülün ana fonksiyonunu çağır (koduna göre uyarla, örnek: module.main())
                if hasattr(module, 'main'):
                    module.main()
                else:
                    print(f"{Fore.YELLOW}Modül yüklendi ama 'main' fonksiyonu yok. Kodunu kontrol et.")
            except Exception as e:
                print(f"{Fore.RED}industrial_recon hatası: {e}")

        elif secim == "2":
            try:
                noxim_path = VARUX_DIR / "noxım.py"
                module = load_module(noxim_path)
                if hasattr(module, 'main'):
                    module.main()
                else:
                    print(f"{Fore.YELLOW}Modül yüklendi ama 'main' fonksiyonu yok.")
            except Exception as e:
                print(f"{Fore.RED}noxım hatası: {e}")

        elif secim == "3":
            try:
                varuxctl_path = VARUX_DIR / "varuxctl.py"
                module = load_module(varuxctl_path)
                if hasattr(module, 'main'):
                    asyncio.run(module.main())
                else:
                    print(f"{Fore.YELLOW}Modül yüklendi ama 'main' fonksiyonu yok.")
            except Exception as e:
                print(f"{Fore.RED}varuxctl hatası: {e}")

        elif secim == "4":
            try:
                ot_path = VARUX_DIR / "VARUX OT Discovery Framework.py"
                module = load_module(ot_path)
                if hasattr(module, 'main_enhanced'):
                    asyncio.run(module.main_enhanced())
                else:
                    print(f"{Fore.YELLOW}Modül yüklendi ama 'main_enhanced' fonksiyonu yok.")
            except Exception as e:
                print(f"{Fore.RED}OT Framework hatası: {e}")

        elif secim == "5":
            try:
                sqlmap_path = VARUX_DIR / "sqlmap_wrapper.py"
                module = load_module(sqlmap_path)
                if hasattr(module, 'SQLMapWrapper'):
                    target = input(f"{Fore.CYAN}Hedef URL (örnek: http://site.com/vuln.php?id=1): {Fore.WHITE}")
                    wrapper = module.SQLMapWrapper()
                    if wrapper.available():
                        wrapper.run_advanced_scan(target)
                    else:
                        print(f"{Fore.RED}SQLMap bulunamadı! Lütfen sqlmap kurun.")
                else:
                    print(f"{Fore.YELLOW}Modül yüklendi ama 'SQLMapWrapper' sınıfı yok.")
            except Exception as e:
                print(f"{Fore.RED}sqlmap_wrapper hatası: {e}")

        elif secim == "6":
            try:
                assistant_path = VARUX_DIR / "ai_assistant.py"
                module = load_module(assistant_path)
                if hasattr(module, 'AIAssistant'):
                    assistant = module.AIAssistant()
                    if not assistant.available():
                        print(f"{Fore.RED}OpenAI API anahtarı bulunamadı (OPENAI_API_KEY).")
                    else:
                        prompt = input(f"{Fore.CYAN}Asistan isteği: {Fore.WHITE}")
                        notes = input(f"{Fore.CYAN}Ek bağlam/özet (opsiyonel): {Fore.WHITE}")
                        result = assistant.generate_assistance(prompt, {'notes': notes})
                        if result.get('error'):
                            print(f"{Fore.RED}Asistan hatası: {result['error']}")
                        else:
                            print(f"\n{Fore.GREEN}Yanıt ({result.get('model', 'OpenAI')}):\n{Fore.WHITE}{result.get('assistant_response')}")
                else:
                    print(f"{Fore.YELLOW}Modül yüklendi ama 'AIAssistant' sınıfı yok.")
            except Exception as e:
                print(f"{Fore.RED}ai_assistant hatası: {e}")

        elif secim.lower() == "d":
            run_health_check()

        elif secim == "7":
            clear_screen()
            print(f"{Fore.GREEN}VARUX kapatılıyor... Güvenli kalın!\n")
            break
        else:
            print(f"{Fore.RED}Geçersiz seçim! 3 saniye içinde tekrar...")
            import time; time.sleep(3)
            continue

        input(f"\n{Fore.YELLOW}Devam etmek için ENTER'a basın...")


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        clear_screen()
        print(f"\n{Fore.RED}Ctrl+C ile çıkış yapıldı. Görüşürüz! ")
