# Анализатор сложности паролей (Java)

Консольный инструмент, который по строке-паролю выдаёт:
- оценку стойкости **LOW / MEDIUM / HIGH**;
- список сработавших факторов с весом и пояснением;
- понятную рекомендацию для сотрудника без ИТ-бэкграунда.

## Требования
- Java 17+ (используется `switch`-выражения/`record`-совместимый синтаксис не задействован,
  но код протестирован на 17 и 21).
- Внешние зависимости: **нет** (только `java.util`, `java.util.regex`).

## Запуск
```bash
javac PasswordStrengthAnalyzer.java

java PasswordStrengthAnalyzer                       # интерактивный ввод
java PasswordStrengthAnalyzer "MyP@ssw0rd2024"      # аргумент
java PasswordStrengthAnalyzer --json "MyP@ssw0rd"   # JSON
java PasswordStrengthAnalyzer --test                # прогон тестов
