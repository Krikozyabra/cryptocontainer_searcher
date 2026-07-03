
# CryptoContainer Searcher

Кроссплатформенная консольная утилита на C++ (стандарт C++17) для автоматического
обнаружения и дешифрования криптографических контейнеров форматов **TrueCrypt**,
**VeraCrypt**, **PGP** (GnuPG), **LUKS** и **EncFS**.

Утилита выполняет рекурсивный обход дерева каталогов, определяет тип
криптоконтейнера по сигнатурным и статистическим признакам, а затем — при
наличии словаря паролей в формате JSON — пытается дешифровать каждый найденный
контейнер с помощью встроенных библиотек дешифрования.

## Поддерживаемые форматы и признаки обнаружения

| Формат | Метод обнаружения |
|---|---|
| **LUKS** | Сигнатурный анализ: первые 8 байта файла — ASCII-строка `LUKS` + пробел + номер версии (v1/v2) (`0x4C 0x55 0x4B 0x53 0xba 0xbe 0x00 0x01/0x02`) |
| **PGP / GnuPG** | Сигнатурный анализ: первые 6 байт — `0x8C 0x0D 0x04 0x09 0x03 0x0A` |
| **EncFS** | Поиск конфигурационного файла `.encfs6` / `.encfs6.xml` с валидацией XML-структуры (tinyxml2) |
| **TrueCrypt / VeraCrypt** | Эвристический анализ: размер кратен 512 байтам, энтропия Шеннона > 7.99 бит/байт, критерий хи-квадрат в диапазоне 200–310, отсев известных сигнатур через Tyfe |

## Архитектура

Проект состоит из трёх функциональных уровней:

```
main.cpp                    — CLI-парсер, валидация, оркестрация
├── crypto_search           — сигнатурный + энтропийный + статистический поиск
└── crypto_decrypt          — дешифрование через встроенные библиотеки
    ├── tcdecrypt           — TrueCrypt (нативная реализация на C++)
    ├── vcdecrypt           — VeraCrypt (нативная реализация на C++)
    ├── gpgdecrypt          — PGP/GnuPG (через GPGME)
    ├── encfsdecrypt        — EncFS (кроссплатформенная реализация без FUSE)
    └── luksdecrypt          — LUKS (через libcryptsetup C API, только Linux)
```

### Стек технологий

- **C++17** (`std::filesystem` для обхода каталогов)
- **nlohmann/json** — парсинг JSON-словаря паролей (FetchContent)
- **Catch2 v3** — модульное тестирование (FetchContent)
- **tinyxml2** — валидация конфигурационных файлов EncFS
- **Tyfe** — отсев файлов с известными сигнатурами при энтропийном анализе
- **entropy** (yuchdev/entropy_calculator) — расчёт энтропии Шеннона
- **libcryptsetup** — нативное дешифрование LUKS (только Linux)
- **GPGME** — нативное дешифрование PGP/GnuPG
- **CMake ≥ 3.24** — система сборки

## Сборка

### Linux

```bash
# Системные зависимости (Debian/Ubuntu)
sudo apt install build-essential cmake pkg-config libcryptsetup-dev libgpgme-dev

# Классическая сборка
cmake -B build

# Сборка с включенными логами
sudo apt install libspdlog-dev
cmake -B build -DLOG=ON 

# Сборка с тестами (файл unit_tests)
sudo add-apt-repository ppa:unit193/encryption
sudo apt update
sudo apt install encfs cryptsetup veracrypt gpg
cmake -B build -DTEST=ON

# Компиляция программы
cmake --build build
```

### Windows (MinGW)

```bash
cmake --toolchain mingw-toolchain.cmake -B build
cmake --build build
```

> **Примечание:** Дешифрование LUKS доступно только на Linux (зависит от
> `libcryptsetup`). На остальных платформах модуль LUKS отключается на этапе
> компиляции.

## Использование

```bash
# Справка
./build/crypto_search --help

# Версия
./build/crypto_search --version

# Поиск криптоконтейнеров в каталоге (без дешифрования)
./build/crypto_search --folder ~ --recursive

# Поиск + дешифрование со словарём паролей
./build/crypto_search --folder /mnt/disk --recursive \
    --decrypt passwords.json \
    --out-decrypted ./decrypted

# В случае, если логи пишутся в консоль (пока не знаю с чем связано)
./build/crypto_search --filder ~ --recursive > some_logs.txt
```

### Флаги

| Флаг | Описание |
|---|---|
| `--folder <путь>` | Каталог для поиска (по умолчанию `/`) |
| `--recursive` | Рекурсивный обход вложенных каталогов |
| `--decrypt <файл>` | JSON-файл со словарём паролей для дешифрования |
| `--out-decrypted <путь>` | Каталог для сохранения дешифрованных данных |
| `--help` | Вывести справку |
| `--version` | Вывести версию |

### Формат JSON-словаря паролей

```json
{
  "encfs":     ["pass1", "encfspass"],
  "luks":      ["lukskey123"],
  "pgp":       ["mygpgpassword"],
  "truecrypt": ["tcpass"],
  "veracrypt": ["vcpass"]
}
```

Для каждого найденного контейнера утилита поочерёдно перебирает пароли из
соответствующего раздела словаря до успешного дешифрования.

## Тесты

```bash
cd build && ctest
```

Модульные тесты (Catch2) проверяют сигнатурное обнаружение LUKS-контейнеров,
создаваемых на лету через `cryptsetup luksFormat`.

## Структура проекта

```
.
├── main.cpp                          # Главная точка входа, CLI-парсер
├── crypto_utils/
│   ├── include/crypto_utils/
│   │   ├── crypto_search.h           # API модуля поиска
│   │   ├── crypto_decrypt.h          # API модуля дешифрования
│   │   └── luksdecrypt.h             # API нативного LUKS-дешифрования
│   └── src/
│       ├── crypto_search.cpp         # Сигнатурный + энтропийный анализ
│       ├── crypto_decrypt.cpp        # Дешифрование через встроенные библиотеки
│       └── luksdecrypt.cpp           # LUKS через libcryptsetup C API
├── third_party/
│   ├── entropy/                      # Расчёт энтропии Шеннона
│   ├── Tyfe/                         # Отсев известных сигнатур файлов
│   ├── tcdecrypt/                    # Нативное дешифрование TrueCrypt
│   ├── vcdecrypt/                    # Нативное дешифрование VeraCrypt
│   ├── gpgdecrypt/                   # Дешифрование PGP/GnuPG (GPGME)
│   └── encfsdecrypt/                 # Кроссплатформенное дешифрование EncFS
├── tests/
│   └── test_search.cpp               # Модульные тесты (Catch2)
├── cmake/
│   ├── EncfsDecrypt.cmake            # Обёртка для сборки encfsdecrypt
│   └── mingw-toolchain.cmake         # Toolchain-файл для MinGW
└── CMakeLists.txt
```

## Безопасность

Пароли никогда не передаются через аргументы командной строки процессов — все
ключевые операции дешифрования выполняются **внутри процесса** через
нативные библиотеки C/C++, что исключает утечку паролей через дерево процессов
ОС (`ps aux`). Дешифрование LUKS выполняется в режиме read-only.
