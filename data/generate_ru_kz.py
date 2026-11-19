"""Generate a synthetic Russian/Kazakh SMS dataset of scam and legitimate messages.

Why synthetic: there is no open, labelled dataset of Kazakhstani scam SMS.
The templates below are modelled on common, publicly reported fraud schemes
(fake bank alerts, prize scams, "relative in trouble", fake delivery fees,
requests for one-time codes) and on ordinary legitimate messages.

Every row keeps a `template_id`, so the evaluation can split by template and
never test the model on a near-copy of a message it was trained on.

Usage:
    python data/generate_ru_kz.py            # writes data/ru_kz_synthetic.csv
"""

from __future__ import annotations

import csv
import random
from pathlib import Path

SEED = 42
PER_TEMPLATE = 14
OUT = Path(__file__).with_name("ru_kz_synthetic.csv")

SLOTS = {
    "bank": ["Kaspi", "Halyk", "Jusan", "Freedom", "Forte", "BCC", "Home Credit"],
    "fake_domain": [
        "kaspi-bonus.top", "halyk-secure.online", "kaspi-kz.site", "egov-shtraf.info",
        "jusan-verify.xyz", "kazpost-delivery.click", "beeline-bonus.store",
        "bit.ly/3kQx9Za", "clck.ru/36Hd2F", "tinyurl.com/kz-prize", "185.22.153.4/login",
    ],
    "amount": ["5 000", "15 000", "25 000", "50 000", "120 000", "250 000", "500 000"],
    "small_amount": ["350", "490", "700", "990", "1 200", "1 500"],
    "prize": ["iPhone 17", "автомобиль Chery", "500 000 тенге", "сертификат на 100 000 ₸", "PlayStation 5"],
    "hours": ["2 часов", "24 часов", "30 минут", "1 часа"],
    "relative": ["мама", "пап", "братан", "апа", "сестрёнка"],
    "name": ["Айгерим", "Данияр", "Асель", "Нурлан", "Мадина", "Ерлан", "Алия", "Тимур"],
    "code": ["4821", "739104", "5502", "118 342", "9073", "264519"],
    "time": ["10:30", "14:00", "16:45", "18:20", "09:15", "12:00"],
    "day": ["завтра", "в понедельник", "в пятницу", "25 ноября", "в субботу"],
    "shop": ["Magnum", "Small", "Technodom", "Sulpak", "Wildberries", "Ozon"],
    "track": ["KZ204551873", "RB118734KZ", "LP00981237", "KZ330912877"],
    "gb": ["5", "10", "20", "30"],
    "place": ["Mega", "Dostyk Plaza", "кофейне у дома", "универе", "Esentai"],
}

# (label, template_id, text). Labels: 1 = scam, 0 = legitimate.
SCAM = [
    "Ваша карта {bank} заблокирована. Для разблокировки перейдите: {fake_domain}",
    "{bank}: обнаружена подозрительная операция на {amount} тг. Если это не вы, срочно подтвердите данные на {fake_domain}",
    "Служба безопасности {bank}. С вашего счета пытаются списать {amount} ₸. Продиктуйте код из SMS, чтобы отменить операцию",
    "Поздравляем! Вы выиграли {prize} в розыгрыше {shop}. Для получения оплатите доставку {small_amount} тг: {fake_domain}",
    "Вы стали победителем акции! Ваш приз: {prize}. Заберите в течение {hours}: {fake_domain}",
    "{relative}, это я, пишу с нового номера. Попал в неприятность, срочно переведи {amount} на этот номер, потом всё объясню",
    "{relative}, я попал в аварию, нужны деньги на лечение. Скинь {amount} на Kaspi 8 707 {code}, не звони, не могу говорить",
    "Ваша посылка {track} задержана на таможне. Оплатите пошлину {small_amount} тг в течение {hours}: {fake_domain}",
    "Казпочта: не удалось доставить отправление {track}. Обновите адрес и оплатите {small_amount} тг: {fake_domain}",
    "eGov: на ваше имя выписан штраф. Оплатите со скидкой 50% до конца дня: {fake_domain}",
    "Ваш номер будет заблокирован через {hours} из-за окончания договора. Для продления назовите код, который придет в SMS",
    "Beeline: вам начислено {gb} ГБ в подарок! Активируйте до конца дня по ссылке {fake_domain}",
    "Уважаемый клиент! Ваш аккаунт {bank} будет удалён. Подтвердите личность: {fake_domain}",
    "Инвестируйте от {amount} ₸ и получайте доход 30% в месяц! Гарантия, без риска. Пишите в WhatsApp",
    "Работа на дому, 40 000 тг в день! Нужен только телефон. Предоплата за обучение {small_amount} тг",
    "Вам одобрен кредит {amount} тг без проверки. Для зачисления сообщите CVV и срок действия карты",
    "Ваш Kaspi Gold заблокирован за подозрительную активность. Перейдите по ссылке и введите пароль: {fake_domain}",
    "Это {name} из службы поддержки {bank}. Отправьте код из SMS, иначе деньги будут списаны",
    "Последнее предупреждение! Ваша ЭЦП будет аннулирована. Обновите данные: {fake_domain}",
    "Компенсация от государства {amount} тг! Получите выплату, указав данные карты: {fake_domain}",
    # Kazakh
    "Құттықтаймыз! Сіз {prize} ұтып алдыңыз. Жүлдені алу үшін сілтемеге өтіңіз: {fake_domain}",
    "{bank}: картаңыз бұғатталды. Бұғаттан шығару үшін SMS-кодты айтыңыз",
    "Шұғыл! {relative}, ақша керек, {amount} теңге аударып жібер, кейін түсіндіремін",
    "Сіздің сәлемдемеңіз {track} кеденде тұр. {small_amount} теңге төлеңіз: {fake_domain}",
]

LEGIT = [
    "{bank}: код подтверждения {code}. Никому не сообщайте этот код, даже сотрудникам банка",
    "{bank}: покупка {small_amount} тг, {shop}. Доступно {amount} тг",
    "{bank}: зачисление {amount} тг. Баланс обновлен",
    "Ваш код для входа: {code}. Если вы не запрашивали код, просто проигнорируйте это сообщение",
    "Привет! Встретимся {day} в {time} в {place}?",
    "{name}, скинь, пожалуйста, конспект по сетям, завтра коллоквиум",
    "Ок, буду через 10 минут",
    "{relative}, я дома, всё нормально, перезвоню вечером",
    "Ваш заказ в {shop} собран и будет доставлен {day} с {time}. Номер заказа {track}",
    "Казпочта: отправление {track} прибыло в отделение. Получите его до {day}, при себе иметь удостоверение",
    "Beeline: остаток трафика {gb} ГБ. Подробнее в приложении «Мой Beeline»",
    "Beeline: ваш баланс {small_amount} тг. Пополнить можно в приложении или в терминале",
    "Напоминаем: вы записаны к врачу {day} в {time}. Для отмены позвоните в регистратуру",
    "{name}, спасибо за помощь вчера! С меня кофе",
    "Пара по кибербезопасности переносится на {time}, аудитория та же",
    "Скидки до 30% в {shop} до конца недели. Подробности на официальном сайте магазина",
    "Ваш платёж за интернет на сумму {small_amount} тг прошёл успешно",
    "eGov: ваша заявка на справку принята. Результат будет в личном кабинете",
    "{name}, ты на тренировку {day} идёшь?",
    "Купи, пожалуйста, хлеб и молоко по дороге домой",
    # Kazakh
    "Сәлем! {day} {time}-да {place} кездесеміз бе?",
    "{bank}: растау коды {code}. Бұл кодты ешкімге айтпаңыз",
    "{relative}, үйге жеттім, бәрі жақсы",
    "Сіздің тапсырысыңыз {shop} дүкенінде дайын. Тапсырыс нөмірі {track}",
]


def fill(template: str, rng: random.Random) -> str:
    values = {k: rng.choice(v) for k, v in SLOTS.items()}
    return template.format(**values)


def generate() -> list[tuple[str, str, str]]:
    rng = random.Random(SEED)
    rows: list[tuple[str, str, str]] = []
    for label, templates, prefix in (("scam", SCAM, "S"), ("ham", LEGIT, "L")):
        for i, template in enumerate(templates):
            seen: set[str] = set()
            for _ in range(PER_TEMPLATE * 3):
                text = fill(template, rng)
                if text not in seen:
                    seen.add(text)
                    rows.append((label, f"{prefix}{i:02d}", text))
                if len(seen) >= PER_TEMPLATE:
                    break
    return rows


def main() -> None:
    rows = generate()
    with OUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["label", "template_id", "text"])
        writer.writerows(rows)
    scam = sum(1 for r in rows if r[0] == "scam")
    print(f"Wrote {len(rows)} rows ({scam} scam, {len(rows) - scam} legitimate) to {OUT}")


if __name__ == "__main__":
    main()
