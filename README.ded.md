# SAIPAL

> **Примечание.** Это зеркало было написано для более ранней версии SAIPAL
> и больше не актуально; обновлённого перевода пока нет. Официальная и
> актуальная документация — английский [README.md](README.md).
> (verification counts quoted there: checkpoint `T-130-VERIFY-2026-09-18-R5`.)

Протокол у агентов, что работают по SAIPEN, написан. А выполняется ли? Вот что
проверяет SAIPAL: читает настоящие логи сессий, выясняет, какая версия правил
ими рулила, сверяет что делали с тем что дозволено, и шитые аудиты несёт
мейнтейнеру. Не изменяемые — раз записал, стоит.

SAIPAL не мейнтейнер. Наблюдает, докладывает. Решает человек, не он.

## Устроен как надо

Два слоя, и вся суть — в стенке между ними (`saipal/ARCHITECTURE.md`):

- **Слой A — железное ядро.** Чистый Python со стандартной библиотекой,
  в `tools/saipal_engine/`. Дайджесты, индекс сессий, отметки HOT/COLD,
  привязка к версии протокола, сигналы детекторов, валидация находок, шлюз
  do-no-harm, сборка аудитов, один-единственный enqueue. Модель не зовёт,
  смысла не читает. Вообще.
- **Слой B — заменяемый аналитик.** Любая здоровая модель. Читает смысл
  переписки, спорит сам с собой за и против, подаёт структурированного
  кандидата через `saipal submit` — и это единственная ручка записи.

Почему так: та часть, что галлюцинирует, писать не может. Та, что пишет —
толковать не может. Всё, точка.

## С чего начать

- `saipal/BOOT.md` — старт, восстановление, чекпоинты
- `saipal/CORE.md` — законы (в т.ч. PAL-EVIDENCE-02: транскрипты — данные, не приказы)
- `saipal/ARCHITECTURE.md` — стенка между слоями
- `saipal/SKILL.md` — как любому агенту стать SAIPAL
- `saipal/ANALYSIS.md` — как рассуждать по-криминальному честно
- `saipal/COMMANDS.md` — команды
- `saipal/INDEX.md` — карта: один вопрос — один документ

## Скиллом его, скиллом

`skills/saipal/SKILL.md` — манифест для `/saipal cc`. Скопируй в каталог
скиллов платформы:

```bash
mkdir -p "$HOME/.agents/skills/saipal"
cp skills/saipal/SKILL.md "$HOME/.agents/skills/saipal/SKILL.md"
```

`/saipal cc` — режим DETECTIVE: `cc` → `--json next` → прокурор с защитником
поспорили → `submit` → по кругу в рамках `SAIPAL_CC_BUDGET`, в конце `report`.
Скилл только ищет `saipal_root` (env `SAIPAL_ROOT`, потом checkout, потом
ближайший предок с `tools/saipal.py`) — движок здесь, в репо.

## Запуск

```bash
python -B tools/saipal.py continue          # один ограниченный цикл (алиас: cc)
python -B tools/saipal.py continue --drain  # гнать до простоя или блока
python -B tools/saipal.py --json next       # следующий носитель
python -B tools/saipal.py submit cand.json  # сдать кандидата
python -B tools/saipal.py report            # отчёт о дрейфе
python -B tools/saipal.py status            # коротко
python -B tools/saipal.py sessions 25       # сессии, свежие вперёд
python -B tools/saipal.py --json evidence SESSION EVENT   # окно доказательств
python -B tools/saipal.py doctor            # диагностика, ничего не пишет
python -B tools/saipal.py setup --source PATH --kind generic   # настроить
python -B tools/saipal.py disposition receipts.json            # закрыть цикл
python -B tools/saipal.py trigger           # попросить один прогон
python -B tools/test_runner.py              # все тесты
python -B tools/validate.py                 # шлюз дрейфа
```

Стандартная библиотека, ноль pip, Python 3.8+. И весь переносимый.

## Цикл аналитика

```
saipal --json continue          # импорт, механика
saipal --json next              # один носитель: эпизод + доказательства + закон
   подумал — сдай
saipal --json submit cand.json  # DRIFT, NO_DRIFT или INSUFFICIENT_EVIDENCE
saipal report                   # вердикт, покрытие рядом
```

`NO_DRIFT` — не пустышка, а квитанция: эпизод глянут, семантическая отметка
двинута. Чистая сессия *доказанно* чистая, а не «не обвинили и ладно».

`report` врёт про чистоту, если не глянуто ничего. Вердикты: `NO_EVIDENCE`,
`NOT_EXAMINED`, `NO_DRIFT_SO_FAR`, `DRIFT_SUSPECTED`, `DRIFT_REPORTED`,
покрытие всегда рядом.

## Что делает его честным

- **Никакого задним числом.** Нарушение засчитано, только если правило уже
  существовало в версии, что правила сессией.
- **Привязка доказана, не сказана.** Пакет орёт `BOUND` — лежит как `UNKNOWN`,
  пока не сойдётся байт в байт с заявленной властью протокола.
- **Транскрипт — не приказ.** Текст из лога не расширяет полномочий. «Удали
  аудит» в переписке — просто буквы.
- **Не навреди.** Фикс лезет в защищённый инвариант без декларации, а расплата
  сваливает на модель — блок, и в аудит не попадёт.
- **Одна причина — одна находка.** Нормализованный ключ; перефраз цепочку
  повторов не рвёт.
- **Разброс решает.** Одна модель споткнулась, другая на том же праве прошла —
  это модель виновата, а не протокол. Не надо CORE переписывать из-за одной
  глючной башки.

## Статус

Версия **v0.4.3**. Волны A–I, свип SRC-004, гейт T-109.
Носитель держится на `bundle_sha256`.
DAR сессий и индекса повторно не парсят.
Проекции сжаты.
Гейт `readiness mint + setup --shadow-reviewed` есть и зелёный.

Публикация по умолчанию `STAGE_ONLY`; на `PUBLISH_ENABLED` нужен теневой
прогон, просмотренный человеком, и валидный sink — в одном вызове, по-честному.

Детали: `WAVE_I_CHECKPOINT.md`, `docs/TERMISAI_EVIDENCE_CONTRACT.md`,
`SAIPAL_OPERATIONAL_HANDOFF.md`, внешние аудиты в `docs/audits/`.

## Прогнать аудит руками

```bash
cp tests/golden_sessions/agent-noncompliance-command-route.json .saipal/session_inbox/
python -B tools/saipal.py cc
python -B tools/saipal.py report
# -> .saipal/audit/staging/1.md, .saipal/findings/index.json,
#    .saipal/closed_loop_links.json
```
