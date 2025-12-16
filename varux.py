#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VARUX Security Framework - Elite Edition v1.0
© 2025 VARUX Security - Tüm hakları saklıdır.
Tek dosya ile tüm modülleri çalıştırır.
"""

import os
import sys
import argparse
from pathlib import Path
from time import sleep

import requests

# varux klasörünü Python yoluna ekle (modülleri bulsun diye)
BASE_DIR = Path(__file__).resolve().parent
VARUX_DIR = BASE_DIR / "varux"
sys.path.insert(0, str(VARUX_DIR))
ORCHESTRATOR_API = os.getenv("VARUX_ORCH_URL", "http://127.0.0.1:5001")

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

from varux.core.modules import MODULE_REGISTRY

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def _submit_task(module_key: str, payload: dict) -> tuple[bool, str | None]:
    try:
        response = requests.post(f"{ORCHESTRATOR_API}/api/tasks", json={"module": module_key, "payload": payload}, timeout=10)
        if response.status_code >= 300:
            print(f"{Fore.RED}Görev kuyruğuna eklenemedi: {response.text}")
            return False, None
        data = response.json()
        return True, data.get("job_id")
    except Exception as exc:
        print(f"{Fore.RED}Orkestratör API'ye ulaşılamadı ({ORCHESTRATOR_API}): {exc}")
        return False, None


def _poll_job(job_id: str):
    status = "PENDING"
    while status not in {"SUCCESS", "FAILED"}:
        try:
            resp = requests.get(f"{ORCHESTRATOR_API}/api/tasks/{job_id}", timeout=10)
            if resp.status_code >= 300:
                print(f"{Fore.RED}Durum sorgusu başarısız: {resp.text}")
                return
            job_info = resp.json()
            status = job_info.get("status", "UNKNOWN")
            print(f"{Fore.CYAN}Durum: {status} (Job: {job_id})")
            if status in {"SUCCESS", "FAILED"}:
                result = job_info.get("result")
                if result:
                    print(f"{Fore.GREEN if status == 'SUCCESS' else Fore.RED}{result}")
                break
        except Exception as exc:
            print(f"{Fore.RED}Durum okunamadı: {exc}")
            break
        sleep(2)


def run_health_check():
    try:
        resp = requests.get(f"{ORCHESTRATOR_API}/api/health", timeout=5)
        worker_resp = requests.get(f"{ORCHESTRATOR_API}/api/health/workers", timeout=5)
        print(f"{Fore.GREEN}Queue sağlığı: {resp.json()}")
        print(f"{Fore.GREEN}Worker durumu: {worker_resp.json()}")
    except Exception as exc:
        print(f"{Fore.RED}Sağlık sorgusu başarısız: {exc}")

def parse_cli_args():
    parser = argparse.ArgumentParser(
        description="VARUX Atlas Engine - etkileşimli veya doğrudan modül çalıştırma",
    )
    parser.add_argument(
        "--module",
        choices=MODULE_REGISTRY.keys(),
        help="Menüye girmeden belirli bir modülü hemen çalıştır",
    )
    parser.add_argument(
        "--target",
        help="Modülün ihtiyaç duyduğu hedef (örn. URL veya IP aralığı)",
    )
    parser.add_argument(
        "--prompt",
        help="AI asistanı için kullanıcı talebi",
    )
    parser.add_argument(
        "--context",
        type=Path,
        help="AI asistanı için JSON formatında bağlam dosyası",
    )
    parser.add_argument(
        "--notes",
        help="AI asistanına ek not/özet ilet",
    )
    parser.add_argument(
        "--api-key",
        help="AI asistanı için geçici OpenAI API anahtarı",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Tüm modülleri ve kısa açıklamalarını listele",
    )
    return parser.parse_args()

def _load_ai_context(path: Path):
    import json

    try:
        with path.expanduser().open("r", encoding="utf-8") as handle:
            data = json.load(handle)
            if not isinstance(data, dict):
                raise ValueError("JSON kökü bir sözlük olmalı")
            return data
    except Exception as exc:
        print(f"{Fore.RED}Bağlam dosyası okunamadı: {exc}")
        return None

def run_direct_module(args):
    module_key = args.module

    # SQLMap sarmalayıcısı için hedef kontrolü
    if module_key == "sqlmap_wrapper" and not args.target:
        print(f"{Fore.RED}SQLMap Wrapper doğrudan çalıştırmada --target zorunlu.")
        return 2

    if module_key == "ai_assistant" and not args.prompt:
        print(f"{Fore.RED}AI asistanı için --prompt parametresi zorunlu.")
        return 4

    payload = {}
    if args.target:
        payload["target"] = args.target
    if args.prompt:
        payload["prompt"] = args.prompt
    if args.notes:
        payload["notes"] = args.notes
    if args.context:
        context = _load_ai_context(args.context)
        if context is None:
            return 5
        payload["context"] = context
    if args.api_key:
        payload["api_key"] = args.api_key

    ok, job_id = _submit_task(module_key, payload)
    if not ok:
        return 9
    print(f"{Fore.GREEN}Görev kuyruğa eklendi: {job_id}")
    _poll_job(job_id)
    return 0

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
            ok, job_id = _submit_task("industrial_recon", {})
            if ok:
                _poll_job(job_id)

        elif secim == "2":
            ok, job_id = _submit_task("noxım", {})
            if ok:
                _poll_job(job_id)

        elif secim == "3":
            ok, job_id = _submit_task("varuxctl", {})
            if ok:
                _poll_job(job_id)

        elif secim == "4":
            ok, job_id = _submit_task("ot_discovery", {})
            if ok:
                _poll_job(job_id)

        elif secim == "5":
            target = input(f"{Fore.CYAN}Hedef URL (örnek: http://site.com/vuln.php?id=1): {Fore.WHITE}")
            if target:
                ok, job_id = _submit_task("sqlmap_wrapper", {"target": target})
                if ok:
                    _poll_job(job_id)
            else:
                print(f"{Fore.RED}Geçerli hedef girilmedi.")

        elif secim == "6":
            prompt = input(f"{Fore.CYAN}Asistan isteği: {Fore.WHITE}")
            notes = input(f"{Fore.CYAN}Ek bağlam/özet (opsiyonel): {Fore.WHITE}")
            if prompt:
                payload = {"prompt": prompt, "notes": notes}
                ok, job_id = _submit_task("ai_assistant", payload)
                if ok:
                    _poll_job(job_id)
            else:
                print(f"{Fore.RED}Geçerli prompt girilmedi.")

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
    args = parse_cli_args()

    if args.list:
        print(f"{Fore.CYAN}VARUX Atlas Engine modülleri:\n")
        for key, info in MODULE_REGISTRY.items():
            print(f" - {key} -> {info['description']} ({info['file']})")
        sys.exit(0)

    if args.module:
        sys.exit(run_direct_module(args))

    try:
        main_menu()
    except KeyboardInterrupt:
        clear_screen()
        print(f"\n{Fore.RED}Ctrl+C ile çıkış yapıldı. Görüşürüz! ")
