"""Rule-based red flags: explain *why* a message looks like fraud.

The ML model gives a probability; these rules give human-readable reasons
and a second, independent score. Each rule has a weight in [0, 1].
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

# Official domains of brands that scammers like to imitate.
OFFICIAL_DOMAINS = {
    "kaspi": "kaspi.kz",
    "halyk": "halykbank.kz",
    "jusan": "jusan.kz",
    "egov": "egov.kz",
    "kazpost": "post.kz",
    "beeline": "beeline.kz",
    "kcell": "kcell.kz",
}
SHORTENERS = {"bit.ly", "clck.ru", "tinyurl.com", "goo.su", "cutt.ly", "t.ly", "is.gd"}
SUSPICIOUS_TLDS = {"top", "xyz", "online", "site", "click", "info", "store", "live", "icu"}

URL_RE = re.compile(
    r"(?:https?://)?(?:www\.)?"
    r"((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})"
    r"(/[^\s]*)?",
    re.IGNORECASE,
)

# Asking the victim to *give away* a secret. Negated forms like
# "никому не сообщайте код" (normal in real bank SMS) must not match.
SECRET_REQUEST_RE = re.compile(
    r"(?<!не )\b(продиктуйте|назовите|сообщите|отправьте|перешлите|скажите|введите|укажите|айтыңыз|жіберіңіз)\b"
    r"[^.!?]{0,40}\b(код\w*|парол\w*|cvv|pin|пин\w*|данные карты|срок действия)",
    re.IGNORECASE,
)
URGENCY_RE = re.compile(
    r"срочно|немедленно|в течение \d+|до конца дня|последнее предупреждение|будет (заблокирован|удал[её]н|аннулирован)"
    r"|заблокирован|шұғыл|бұғатталды",
    re.IGNORECASE,
)
PRIZE_RE = re.compile(
    r"выиграли|победител|ваш приз|приз|в подарок|компенсаци|ұтып алдыңыз|жүлде|\bwinner\b|\bwon\b|\bprize\b|\bclaim\b",
    re.IGNORECASE,
)
PAYMENT_RE = re.compile(
    r"переведи|скинь|оплатите|предоплат|пошлин|аударып|төлеңіз|\bcall\b.*\b0\d{9,}",
    re.IGNORECASE,
)
IMPERSONATION_RE = re.compile(
    r"с нового номера|это я|служба безопасности|служб\w* поддержки|не звони",
    re.IGNORECASE,
)
TOO_GOOD_RE = re.compile(
    r"\d+\s?% в месяц|без риска|гарантия|без проверки|в день!",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Flag:
    code: str
    weight: float
    reason: str


def _domains(text: str) -> list[str]:
    found = []
    for match in URL_RE.finditer(text):
        host = match.group(1).lower()
        # skip plain numbers like "5.000" or amounts
        if re.fullmatch(r"[\d.]+", host) and host.count(".") != 3:
            continue
        found.append(host)
    return found


def _link_flags(text: str) -> list[Flag]:
    flags: list[Flag] = []
    for host in _domains(text):
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
            flags.append(Flag("ip_link", 0.6, f"Ссылка ведёт на IP-адрес ({host}), а не на сайт компании"))
            continue
        if host in SHORTENERS:
            flags.append(Flag("short_link", 0.4, f"Сокращённая ссылка ({host}) скрывает настоящий адрес"))
            continue
        for brand, official in OFFICIAL_DOMAINS.items():
            if brand in host and not (host == official or host.endswith("." + official)):
                flags.append(Flag("lookalike_domain", 0.7, f"Домен {host} похож на {brand}, но официальный сайт — {official}"))
                break
        else:
            tld = host.rsplit(".", 1)[-1]
            if tld in SUSPICIOUS_TLDS:
                flags.append(Flag("suspicious_tld", 0.4, f"Подозрительная доменная зона .{tld} ({host})"))
            else:
                flags.append(Flag("link", 0.15, f"В сообщении есть ссылка ({host})"))
    return flags


def find_red_flags(text: str) -> list[Flag]:
    """Return every red flag found in the message, strongest first."""
    flags = _link_flags(text)
    checks = [
        (SECRET_REQUEST_RE, Flag("secret_request", 0.8, "Просят сообщить код, пароль или данные карты — банки так никогда не делают")),
        (URGENCY_RE, Flag("urgency", 0.3, "Давят срочностью или угрозой блокировки")),
        (PRIZE_RE, Flag("prize", 0.35, "Обещают выигрыш, подарок или компенсацию")),
        (PAYMENT_RE, Flag("payment_request", 0.35, "Просят перевести или оплатить деньги")),
        (IMPERSONATION_RE, Flag("impersonation", 0.4, "Похоже на выдачу себя за родственника или сотрудника банка")),
        (TOO_GOOD_RE, Flag("too_good", 0.4, "Слишком выгодное предложение: гарантированный доход или кредит без проверки")),
    ]
    for pattern, flag in checks:
        if pattern.search(text):
            flags.append(flag)
    return sorted(flags, key=lambda f: f.weight, reverse=True)


def rules_score(flags: list[Flag]) -> float:
    """Combine flag weights like independent probabilities: 1 - prod(1 - w)."""
    remaining = 1.0
    for flag in flags:
        remaining *= 1.0 - flag.weight
    return round(1.0 - remaining, 4)
