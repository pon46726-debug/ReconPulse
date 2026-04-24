<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=28&duration=2000&pause=1000&color=36BCF7&center=true&vCenter=true&width=600&lines=ReconPulse+v2.0+%F0%9F%8C%90;Fast+OSINT+Recon+Tool;40%2B+Social+%26+Professional+Sources" alt="Typing SVG" />
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-green"></a>
  <a href="#"><img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey"></a>
  <a href="#"><img src="https://img.shields.io/badge/Educational-Only-red"></a>
</p>

# 🌐 ReconPulse v2.0

> Быстрый OSINT-разведчик для сбора информации о никнеймах, email-адресах и доменах.
> Обновлённая версия с расширенной базой источников, автоочисткой URL и резервным поиском поддоменов.

ReconPulse поможет пентестерам, исследователям и студентам ИБ на этапе разведки:
- 🔎 Находит профили по никнейму в **40+** соцсетях, форумах и сервисах
- 🛡 Проверяет email в Have I Been Pwned (k-Anonymity, без передачи email)
- 🌍 Получает данные WHOIS по домену
- 🧩 Ищет поддомены через crt.sh и (если нужно) AlienVault OTX
- ✉️ Извлекает email-адреса с любой публичной веб-страницы

Всё работает асинхронно, с цветным CLI и возможностью сохранения результатов в JSON.

**⚠️ Только для этичного использования с явного разрешения владельца системы!**

---

## 🆕 Что нового в v2.0

- **Расширенная база источников**: добавлены GitLab, Keybase, ProductHunt, SoundCloud, VK, Habr, VC.ru и другие — теперь более 40 площадок.
- **Автоочистка ввода**: при указании домена можно передавать `https://www.deepseek.com/` — скрипт сам извлечёт `deepseek.com`.
- **Резервный источник поддоменов**: если crt.sh не дал результатов, автоматически пробуется AlienVault OTX.
- **Умный подсчёт**: после сканирования никнейма отображается итоговое число найденных активных профилей.

---

## 🚀 Быстрый старт

```bash
# Клонируйте репозиторий
git clone https://github.com/pon46726-debug/recon-pulse.git
cd recon-pulse

# Установите зависимости
pip install -r requirements.txt

# Запустите первый поиск
python recon.py nickname johndoe
