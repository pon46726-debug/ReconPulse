#!/usr/bin/env python3
"""
ReconPulse – быстрый OSINT-разведчик (учебные цели)
Версия 2.0 – расширенная база источников, автоочистка URL, улучшенный crt.sh
"""

import asyncio
import json
import re
import sys
import argparse
from urllib.parse import quote, urlparse

import httpx
import whois
from colorama import init, Fore, Style

init(autoreset=True)

BANNER = rf"""
{Fore.CYAN}  ____                       ____        _          
 |  _ \ ___  ___ ___  _ __   |  _ \ _   _| |___  ___ 
 | |_) / _ \/ __/ _ \| '_ \  | |_) | | | | / __|/ _ \
 |  _ <  __/ (_| (_) | | | | |  __/| |_| | \__ \  __/
 |_| \_\___|\___\___/|_| |_| |_|    \__,_|_|___/\___|
{Style.RESET_ALL}
          {Fore.YELLOW}ReconPulse v2.0 | OSINT tool | Educational use only{Style.RESET_ALL}
"""

def log_info(msg): print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def log_warn(msg): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def log_error(msg): print(f"{Fore.RED}[✘]{Style.RESET_ALL} {msg}")
def log_title(msg): print(f"\n{Fore.CYAN}{'─'*60}\n  {msg}\n{'─'*60}{Style.RESET_ALL}")

# ------------------------------------------------------------
# РАСШИРЕННАЯ БАЗА ИСТОЧНИКОВ для никнейма
# ------------------------------------------------------------
SOCIAL_SITES = {
    # Глобальные
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Bitbucket": "https://bitbucket.org/{}/",
    "Keybase": "https://keybase.io/{}",
    "Twitter": "https://twitter.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Reddit": "https://www.reddit.com/user/{}",
    "YouTube": "https://www.youtube.com/@{}",
    "Telegram": "https://t.me/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Steam": "https://steamcommunity.com/id/{}",
    "Spotify": "https://open.spotify.com/user/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Vimeo": "https://vimeo.com/{}",
    "Blogger": "https://{}.blogspot.com",
    "Medium": "https://medium.com/@{}",
    "Flickr": "https://www.flickr.com/people/{}",
    "About.me": "https://about.me/{}",
    "Patreon": "https://www.patreon.com/{}",
    "Behance": "https://www.behance.net/{}",
    "Dribbble": "https://dribbble.com/{}",
    "DeviantArt": "https://www.deviantart.com/{}",
    "ProductHunt": "https://www.producthunt.com/@{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "Lobsters": "https://lobste.rs/u/{}",
    "Pastebin": "https://pastebin.com/u/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Kaggle": "https://www.kaggle.com/{}",
    "Chess.com": "https://www.chess.com/member/{}",
    # Русскоязычные
    "VK": "https://vk.com/{}",
    "OK.ru": "https://ok.ru/{}",
    "Habr": "https://habr.com/ru/users/{}",
    "Pikabu": "https://pikabu.ru/@{}",
    "Яндекс.Дзен": "https://zen.yandex.ru/{}",
    "VC.ru": "https://vc.ru/u/{}",
    "LiveJournal": "https://{}.livejournal.com",
}

# ------------------------------------------------------------
# Утилиты очистки домена
# ------------------------------------------------------------
def clean_domain(raw: str) -> str:
    """Извлекает чистое доменное имя из URL или строки с www"""
    if not raw:
        return raw
    # Если передан URL с протоколом – парсим
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        domain = parsed.netloc or parsed.path  # на случай, если без схемы
    else:
        domain = raw
    # Убираем www, если есть
    if domain.startswith("www."):
        domain = domain[4:]
    # Убираем путь и слэш на конце
    domain = domain.split('/')[0]
    return domain

# ------------------------------------------------------------
# Асинхронные проверки
# ------------------------------------------------------------
async def check_site(client, name, url_template):
    url = url_template.format(quote(name))
    try:
        resp = await client.get(url, timeout=10)
        return (url, resp.status_code)
    except Exception:
        return (url, None)

async def scan_nickname(nickname):
    log_title(f"Поиск профилей для: {nickname}")
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        tasks = [check_site(client, nickname, url) for url in SOCIAL_SITES.values()]
        results = await asyncio.gather(*tasks)

    profiles = []
    for (url, status), (name, _) in zip(results, SOCIAL_SITES.items()):
        if status == 200:
            log_info(f"{name}: {url}")
            profiles.append({"site": name, "url": url, "status": status})
        elif status:
            log_warn(f"{name}: {url} (status {status})")
            profiles.append({"site": name, "url": url, "status": status})
        else:
            log_error(f"{name}: {url} (недоступен)")
    log_info(f"Итого найдено активных профилей: {len([p for p in profiles if p['status']==200])}")
    return profiles

# ------------------------------------------------------------
# Проверка email в Have I Been Pwned (уже было)
# ------------------------------------------------------------
async def check_haveibeenpwned(email):
    log_title(f"Проверка email в HIBP: {email}")
    import hashlib
    sha = hashlib.sha1(email.encode()).hexdigest().upper()
    prefix, suffix = sha[:5], sha[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "ReconPulse-Educational"}
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, headers=headers, timeout=10)
            if resp.status_code != 200:
                log_error(f"Ошибка HIBP API: {resp.status_code}")
                return None
            for line in resp.text.splitlines():
                hash_suffix, _, count = line.partition(':')
                if hash_suffix == suffix:
                    log_info(f"Email найден в утечках! Количество утечек: {count}")
                    return {"email": email, "breaches": int(count)}
            log_info("Email не найден в утечках (хорошо)")
            return {"email": email, "breaches": 0}
        except Exception as e:
            log_error(f"Ошибка запроса: {e}")
            return None

# ------------------------------------------------------------
# WHOIS (уже было)
# ------------------------------------------------------------
def get_whois_info(domain):
    log_title(f"WHOIS для домена: {domain}")
    try:
        w = whois.whois(domain)
        info = {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
        }
        if w.emails:
            info["email"] = list(w.emails)[0] if isinstance(w.emails, list) else w.emails
        log_info(f"Регистратор: {w.registrar}")
        log_info(f"Дата создания: {w.creation_date}")
        log_info(f"Дата окончания: {w.expiration_date}")
        log_info(f"Имена серверов: {w.name_servers}")
        if w.emails:
            log_info(f"Контактный email: {w.emails}")
        return info
    except Exception as e:
        log_error(f"Ошибка WHOIS: {e}")
        return {"error": str(e)}

# ------------------------------------------------------------
# Поиск поддоменов (исправлен + добавлен резервный источник)
# ------------------------------------------------------------
async def get_subdomains(domain):
    log_title(f"Поиск поддоменов (crt.sh): {domain}")
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        sub = sub.strip()
                        if sub and sub.endswith(f".{domain}"):
                            subdomains.add(sub)
            else:
                log_warn(f"crt.sh вернул {resp.status_code}, пробуем альтернативный источник")
        except Exception as e:
            log_error(f"Ошибка crt.sh: {e}")

    # Дополнительный источник: AlienVault OTX (бесплатно, без ключа)
    if not subdomains:
        log_info("Проверяем AlienVault OTX...")
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(otx_url, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data.get('passive_dns', []):
                        hostname = entry.get('hostname', '')
                        if hostname.endswith(f".{domain}") and hostname != domain:
                            subdomains.add(hostname)
        except Exception as e:
            log_error(f"Ошибка AlienVault: {e}")

    if subdomains:
        log_info(f"Найдено {len(subdomains)} поддоменов")
        for s in sorted(subdomains):
            print(f"  {Fore.GREEN}{s}{Style.RESET_ALL}")
    else:
        log_warn("Поддомены не найдены ни в одном источнике")
    return sorted(subdomains)

# ------------------------------------------------------------
# Сбор email с сайта (уже было)
# ------------------------------------------------------------
async def crawl_emails(url):
    log_title(f"Сбор email-адресов с: {url}")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=10)
            resp.raise_for_status()
            emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text))
            if emails:
                log_info(f"Найдено email: {len(emails)}")
                for e in emails:
                    print(f"  {Fore.GREEN}{e}{Style.RESET_ALL}")
            else:
                log_warn("Email-адреса не найдены на странице")
            return list(emails)
        except Exception as e:
            log_error(f"Ошибка при обходе: {e}")
            return []

# ------------------------------------------------------------
# Главная функция
# ------------------------------------------------------------
async def main():
    parser = argparse.ArgumentParser(description="ReconPulse – OSINT разведчик")
    subparsers = parser.add_subparsers(dest='command', help='Команды')

    # Сканирование никнейма
    nick_parser = subparsers.add_parser('nickname', help='Поиск профилей по никнейму')
    nick_parser.add_argument('nickname', help='Никнейм для поиска')
    nick_parser.add_argument('--json', type=str, help='Сохранить результаты в JSON файл')

    # Проверка email
    email_parser = subparsers.add_parser('email', help='Проверка email в HIBP')
    email_parser.add_argument('email', help='Email для проверки')
    email_parser.add_argument('--json', type=str, help='Сохранить в JSON')

    # Домен (whois + поддомены)
    domain_parser = subparsers.add_parser('domain', help='WHOIS и поддомены')
    domain_parser.add_argument('domain', help='Домен')
    domain_parser.add_argument('--json', type=str, help='Сохранить отчёт в JSON')

    # Сбор email с сайта
    crawler_parser = subparsers.add_parser('crawl', help='Сбор email с веб-страницы')
    crawler_parser.add_argument('url', help='URL сайта')
    crawler_parser.add_argument('--json', type=str, help='Сохранить в JSON')

    args = parser.parse_args()

    print(BANNER)
    report = {}

    if args.command == 'nickname':
        report['profiles'] = await scan_nickname(args.nickname)
        if args.json:
            with open(args.json, 'w') as f:
                json.dump(report, f, indent=2)
            log_info(f"Отчёт сохранён в {args.json}")

    elif args.command == 'email':
        report = await check_haveibeenpwned(args.email)
        if args.json and report:
            with open(args.json, 'w') as f:
                json.dump(report, f, indent=2)
            log_info(f"Отчёт сохранён в {args.json}")

    elif args.command == 'domain':
        # Очищаем домен перед использованием
        clean_dom = clean_domain(args.domain)
        log_info(f"Рабочий домен после очистки: {clean_dom}")
        whois_info = get_whois_info(clean_dom)
        subdomains = await get_subdomains(clean_dom)
        report = {'whois': whois_info, 'subdomains': subdomains}
        if args.json:
            with open(args.json, 'w') as f:
                json.dump(report, f, indent=2)
            log_info(f"Отчёт сохранён в {args.json}")

    elif args.command == 'crawl':
        emails = await crawl_emails(args.url)
        report = {'url': args.url, 'emails': emails}
        if args.json:
            with open(args.json, 'w') as f:
                json.dump(report, f, indent=2)
            log_info(f"Отчёт сохранён в {args.json}")

    else:
        parser.print_help()

if __name__ == '__main__':
    asyncio.run(main())