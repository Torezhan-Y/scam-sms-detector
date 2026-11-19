import pytest

from src.detector.model import ScamDetector
from src.detector.red_flags import find_red_flags, rules_score


@pytest.fixture(scope="module")
def detector():
    return ScamDetector.load()


def codes(text):
    return {f.code for f in find_red_flags(text)}


def test_lookalike_domain_is_flagged():
    assert "lookalike_domain" in codes("Карта заблокирована: kaspi-secure.top")


def test_official_domain_is_not_lookalike():
    assert "lookalike_domain" not in codes("Подробнее на kaspi.kz")


def test_secret_request_is_flagged():
    assert "secret_request" in codes("Служба безопасности. Продиктуйте код из SMS")


def test_bank_warning_not_to_share_code_is_not_a_request():
    assert "secret_request" not in codes("Kaspi: код 4821. Никому не сообщайте этот код")


def test_rules_score_combines_weights():
    flags = find_red_flags("Срочно! Назовите код из SMS: kaspi-bonus.top")
    assert 0.9 < rules_score(flags) <= 1.0
    assert rules_score([]) == 0.0


@pytest.mark.parametrize(
    "text",
    [
        "Ваша карта Halyk заблокирована. Перейдите: halyk-verify.online",
        "Мам, это я с нового номера, срочно скинь 30 000",
        "Здравствуйте, служба безопасности банка, назовите код из смс",
        "Сіз iPhone ұтып алдыңыз! Сілтеме: egov-prize.xyz",
    ],
)
def test_scam_messages(detector, text):
    assert detector.check(text).is_scam


@pytest.mark.parametrize(
    "text",
    [
        "Kaspi: код подтверждения 4821. Никому не сообщайте этот код",
        "Привет, во сколько завтра пара?",
        "Ваш заказ Wildberries будет доставлен завтра с 10:00",
        "Сәлем! Ертең кездесеміз бе?",
    ],
)
def test_legit_messages(detector, text):
    assert not detector.check(text).is_scam
