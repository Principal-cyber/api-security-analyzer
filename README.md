 API Security Analyzer 🔒

Профессиональный инструмент для автоматического тестирования безопасности API. Специализирован для анализа банковских API и открытых банковских систем.

## 🚀 Возможности

- ✅ **Полное покрытие OWASP API Security Top 10**
- ✅ **Обнаружение уязвимостей**: SQL Injection, XSS, Command Injection
- ✅ **Тестирование аутентификации и авторизации**
- ✅ **Проверка security headers и конфигурации**
- ✅ **Генерация детальных HTML и JSON отчетов**
- ✅ **Поддержка OpenAPI/Swagger спецификаций**
- ✅ **Фаззинг-тестирование эндпоинтов**

## 📋 Содержание

- [Быстрый старт](#-быстрый-старт)
- [Установка](#-установка)
- [Использование](#-использование)
- [Примеры анализа банков](#-примеры-анализа-банков)
- [Структура проекта](#-структура-проекта)

## 🏁 Быстрый старт

### Требования
- **Java 17** или выше
- **Maven 3.8+**

### Установка

```bash
# Клонирование репозитория
git clone https://github.com/Principal-cyber/api-security-analyzer.git
cd api-security-analyzer

# Сборка проекта
mvn clean compile

# Создание исполняемого JAR
mvn package
🎯 Использование
Базовый синтаксис
bash
java -jar target/api-security-analyzer-1.0.0.jar <target-url> <openapi-spec-url>
Параметры запуска
<target-url> - базовый URL целевого API

<openapi-spec-url> - URL или путь к OpenAPI спецификации

🏦 Примеры анализа банков
Анализ VBank
bash
java -jar target/api-security-analyzer-1.0.0.jar \
    https://vbank.open.bankingapi.ru \
    https://vbank.open.bankingapi.ru/openapi.json
Анализ ABank
bash
java -jar target/api-security-analyzer-1.0.0.jar \
    https://abank.open.bankingapi.ru \
    https://abank.open.bankingapi.ru/openapi.json
Анализ SBank
bash
java -jar target/api-security-analyzer-1.0.0.jar \
    https://sbank.open.bankingapi.ru \
    https://sbank.open.bankingapi.ru/openapi.json
Дополнительные опции
bash
# С увеличенной памятью для больших API
java -Xmx512m -jar target/api-security-analyzer-1.0.0.jar \
    https://vbank.open.bankingapi.ru \
    https://vbank.open.bankingapi.ru/openapi.json

# С сохранением логов в файл
java -jar target/api-security-analyzer-1.0.0.jar \
    https://vbank.open.bankingapi.ru \
    https://vbank.open.bankingapi.ru/openapi.json \
    > scan.log 2>&1
📊 Результаты анализа
После успешного сканирования генерируются:

security-report.html - детальный визуальный отчет с графиками

security-report.json - машинно-читаемый отчет для интеграций

Пример вывода в консоли:
text
🚀 API SECURITY ANALYSIS REPORT
======================================================================
Target: https://vbank.open.bankingapi.ru
Scan Time: 2024-01-15T10:30:00
Execution Time: 15432 ms
Tested Endpoints: 15
----------------------------------------------------------------------
Security Score: 85.5/100
Compliance Score: 92.0/100
----------------------------------------------------------------------
VULNERABILITY SUMMARY:
Critical: 0
High: 2  
Medium: 3
Low: 5
Total: 10
======================================================================

📊 Reports generated:
• security-report.html (Detailed HTML report)
• security-report.json (Machine-readable JSON)
🏗️ Структура проекта
text
api-security-analyzer/
├── src/
│   └── main/
│       └── java/
│           └── com/security/analyzer/
│               ├── Application.java              # Точка входа
│               ├── cli/                          # CLI интерфейс
│               ├── config/                       # Конфигурация
│               ├── core/                         # Основная логика
│               │   ├── SecurityScanner.java
│               │   └── ReportGenerator.java
│               ├── analysis/                     # Анализаторы безопасности
│               │   ├── AuthenticationAnalyzer.java
│               │   ├── AuthorizationAnalyzer.java
│               │   ├── ComplianceValidator.java
│               │   ├── InjectionDetector.java
│               │   └── OWASPAnalyzer.java
│               ├── client/                       # HTTP клиенты
│               │   ├── APIClient.java
│               │   └── OpenAPIParser.java
│               ├── model/                        # Модели данных
│               │   ├── APISpecification.java
│               │   ├── Endpoint.java
│               │   ├── SecurityReport.java
│               │   ├── TestResult.java
│               │   └── Vulnerability.java
│               └── plugins/
│                   └── fuzzing/                  # Фаззинг-движок
│                       ├── FuzzingEngine.java
│                       └── PayloadGenerator.java
├── src/main/resources/                           # Ресурсы
├── src/test/java/                                # Тесты
├── config/                                       # Конфигурационные файлы
├── target/                                       # Собранные артефакты
├── pom.xml                                       # Maven конфигурация
└── README.md                                     # Документация
🛠️ Разработка
Сборка проекта
bash
# Переход в папку проекта
cd api-security-analyzer

# Очистка и компиляция
mvn clean compile

# Запуск тестов
mvn test

# Создание JAR файла
mvn package

# Полная пересборка
mvn clean package
Добавление новых анализаторов
Создайте класс в src/main/java/com/security/analyzer/analysis/


📈 Поддерживаемые тесты безопасности
OWASP API Security Top 10
API1:2023 - Broken Object Level Authorization

API2:2023 - Broken Authentication

API3:2023 - Broken Object Property Level Authorization

API4:2023 - Unrestricted Resource Consumption

API5:2023 - Broken Function Level Authorization

API6:2023 - Unrestricted Access to Sensitive Business Flows

API7:2023 - Server Side Request Forgery

API8:2023 - Security Misconfiguration

API9:2023 - Improper Inventory Management

API10:2023 - Unsafe Consumption of APIs

Инъекции и атаки
SQL Injection

NoSQL Injection

XSS (Cross-Site Scripting)

Command Injection

XXE (XML External Entity)

Path Traversal

Конфигурация и Headers
Security Headers (CSP, HSTS, X-Content-Type-Options)

CORS Configuration

Information Disclosure

Error Handling


📄 Лицензия
Этот проект распространяется под лицензией MIT - смотрите файл LICENSE для деталей.

⚠️ Ответственное использование
Этот инструмент предназначен для:

✅ Тестирования собственных API

✅ Авторизованного пентестинга

✅ Образовательных целей

✅ Исследований безопасности

Запрещено использовать для:

❌ Тестирования API без разрешения

❌ Нарушения законов

❌ Вредоносной деятельности
