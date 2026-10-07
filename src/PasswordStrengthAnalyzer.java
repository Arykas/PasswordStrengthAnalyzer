import java.util.*;
import java.util.regex.*;

/**
 * Анализатор сложности паролей.
 *
 * <p>Инструмент оценивает пароль по набору эвристик, которые имитируют
 * поведение реальных атакующих (перебор, словарные атаки, атаки по маскам
 * и утечкам). Каждой эвристике сопоставлен вес (LOW/MEDIUM/HIGH), итоговая
 * оценка складывается из суммы «усилений» минус сумму «рисков».
 *
 * <p>Зачем это нужно с точки зрения ИБ (для сотрудника без ИТ-бэкграунда):
 * <ul>
 *   <li>Большинство утечек происходит не из-за «взлома шифра», а потому что
 *       пароль был слабым и его подобрали словарём или маской за секунды.</li>
 *   <li>Люди переиспользуют пароли. Один слабый пароль = компромисс всех
 *       сервисов, где он использовался (credential stuffing).</li>
 *   <li>Фишинг часто эксплуатирует предсказуемость: если пароль построен на
 *       имени, годе рождения или слове «password», злоумышленник угадает его
 *       после одной-двух утечек базы.</li>
 * </ul>
 *
 * <p>Стек: только стандартная библиотека Java (java.util, java.util.regex).
 */
public class PasswordStrengthAnalyzer {

    /** Вес эвристики. Чем выше — тем сильнее влияние на итоговую оценку. */
    enum Weight {
        LOW(1), MEDIUM(2), HIGH(3);
        final int score;
        Weight(int score) { this.score = score; }
    }

    /** Тип фактора: риск понижает оценку, усиление — повышает. */
    enum FactorType { RISK, STRENGTH }

    /** Итоговая категория стойкости. */
    enum Strength { LOW, MEDIUM, HIGH }

    /** Один обнаруженный фактор с пояснением. */
    static class Factor {
        final FactorType type;
        final Weight weight;
        final String name;
        final String description;
        Factor(FactorType type, Weight weight, String name, String description) {
            this.type = type; this.weight = weight;
            this.name = name; this.description = description;
        }
    }

    /** Результат анализа: оценка, список факторов, баллы и рекомендация. */
    static class Analysis {
        final Strength strength;
        final List<Factor> factors;
        final int totalScore;
        final int riskScore;
        final int strengthScore;
        final String recommendation;
        Analysis(Strength strength, List<Factor> factors, int totalScore,
                 int riskScore, int strengthScore, String recommendation) {
            this.strength = strength; this.factors = factors;
            this.totalScore = totalScore; this.riskScore = riskScore;
            this.strengthScore = strengthScore; this.recommendation = recommendation;
        }
    }

    /**
     * Небольшой словарь «слитых» слов. В реальных атаках используются базы
     * на миллионы слов (rockyou.txt и т.п.), здесь — учебное подмножество
     * из 20–30 самых частых паролей/подстрок.
     */
    private static final Set<String> DICTIONARY = new HashSet<>(Arrays.asList(
            "pass", "password", "admin", "login", "qwerty", "welcome", "letmein",
            "secret", "user", "root", "guest", "master", "hello", "test",
            "123456", "12345678", "abc", "iloveyou", "monkey", "dragon",
            "football", "baseball", "shadow", "sunshine", "princess",
            "qaz", "wsx"
    ));

    public static void main(String[] args) {
        boolean json = false;
        List<String> positional = new ArrayList<>();

        for (String arg : args) {
            if ("--json".equals(arg)) json = true;
            else if ("--test".equals(arg)) { runTests(); return; }
            else positional.add(arg);
        }

        String password;
        if (!positional.isEmpty()) {
            password = String.join(" ", positional);
        } else {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Введите пароль: ");
            password = scanner.nextLine();
        }

        Analysis analysis = analyze(password);
        System.out.println(json ? toJson(analysis) : formatText(analysis));
    }

    /**
     * Основная функция анализа. Реализовано 8 эвристик (требовалось ≥5).
     */
    public static Analysis analyze(String password) {
        if (password == null) password = "";

        List<Factor> factors = new ArrayList<>();
        String lower = password.toLowerCase(Locale.ROOT);
        int n = password.length();

        // === Эвристика 1. Длина ===
        // Почему: время полного перебора растёт экспоненциально с длиной.
        // Пароль из 8 символов перебирается минуты-часы на GPU, из 13+ — годы.
        // Рекомендации NIST SP 800-63B и GDPR/152-ФЗ требуют ≥12 символов.
        if (n <= 8) {
            addRisk(factors, Weight.HIGH, "Длина",
                    "Короткий пароль (≤8 символов) — подбирается перебором за минуты");
        } else if (n <= 12) {
            addRisk(factors, Weight.MEDIUM, "Длина",
                    "Средняя длина (9–12 символов) — желательно 13+");
        } else {
            addStrength(factors, Weight.HIGH, "Длина",
                    "Хорошая длина (13+ символов) — резко усложняет перебор");
        }

        // === Эвристика 2. Состав символов ===
        // Почему: алфавит определяет размер пространства перебора.
        // 26 букв vs 26+10+33 = 69 символов — разница в десятки раз.
        boolean hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false;
        for (char c : password.toCharArray()) {
            if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSpecial = true;
        }
        int categories = 0;
        if (hasLower || hasUpper) categories++;
        if (hasDigit) categories++;
        if (hasSpecial) categories++;

        if (categories <= 1) {
            addRisk(factors, Weight.HIGH, "Состав символов",
                    "Только одна категория (буквы ИЛИ цифры) — типично для утёкших паролей");
        } else if (categories == 2) {
            addRisk(factors, Weight.MEDIUM, "Состав символов",
                    "Только две категории — атакующий применяет маску «буквы+цифры»");
        } else {
            addStrength(factors, Weight.HIGH, "Состав символов",
                    "Буквы + цифры + спецсимволы — максимальный алфавит");
        }

        // Усиление: разный регистр. Почему: NIST рекомендует, но это лишь
        // вспомогательный фактор — сам по себе регистр пароль не спасает.
        if (hasLower && hasUpper) {
            addStrength(factors, Weight.LOW, "Регистр",
                    "Есть буквы разного регистра");
        }

        // === Эвристика 3. Словарные слова ===
        // Почему: атакующие используют готовые словари (rockyou, SecLists).
        // Если пароль содержит «password», «admin», «qwerty» — он будет
        // взломан за секунды, даже если длина 12+.
        List<String> foundWords = new ArrayList<>();
        for (String word : DICTIONARY) {
            if (word.length() >= 3 && lower.contains(word)) foundWords.add(word);
        }
        if (!foundWords.isEmpty()) {
            addRisk(factors, Weight.HIGH, "Словарное слово",
                    "Найдены распространённые слова: " + String.join(", ", foundWords));
        }

        // === Эвристика 4. Leet-замены ===
        // Почему: замены a→@, o→0, e→3 «выучены» всеми инструментами
        // (hashcat rule-based). Они НЕ повышают стойкость против атакующего,
        // но создают ложное чувство безопасности у пользователя.
        String normalized = normalizeLeet(lower);
        if (!normalized.equals(lower)) {
            boolean foundLeetWord = false;
            for (String word : DICTIONARY) {
                if (word.length() >= 3 && normalized.contains(word)) {
                    foundLeetWord = true; break;
                }
            }
            if (foundLeetWord) {
                addRisk(factors, Weight.MEDIUM, "Leet-замены",
                        "Предсказуемые замены (@ вместо a, 0 вместо o, 3 вместо e) — учитываются хеш-каталожными правилами");
            }
        }

        // === Эвристика 5. Повторяющиеся символы и простые последовательности ===
        // Почему: «aaa», «111» сужают энтропию. Пароль вида "aaaa1111" имеет
        // энтропию на порядки ниже, чем кажется по длине.
        if (password.matches(".*(.)\\1{2,}.*")) {
            addRisk(factors, Weight.HIGH, "Повторяющиеся символы",
                    "Три и более одинаковых символа подряд — резко снижает энтропию");
        }
        if (containsSequence(lower, 4)) {
            addRisk(factors, Weight.HIGH, "Простые последовательности",
                    "Последовательность вида 1234 или abcd — входит в первые маски перебора");
        }

        // === Эвристика 6. Клавиатурные последовательности ===
        // Почему: «qwerty», «asdf», «1q2w3e» — самые частые пароли по данным
        // утечек. Раскладка одна, атакующий перебирает их первыми.
        String[] keyboardSeqs = {
                "qwerty", "qwert", "asdf", "asdfg", "zxcv", "zxcvb",
                "qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm",
                "12345", "123456"
        };
        for (String seq : keyboardSeqs) {
            if (lower.contains(seq)) {
                addRisk(factors, Weight.MEDIUM, "Клавиатурная последовательность",
                        "Найдена последовательность клавиш: " + seq);
                break;
            }
        }

        // === Эвристика 7. Дата/год в пароле ===
        // Почему: люди вставляют год рождения, свадьбы, «2024» как «обновление».
        // Атакующий генерирует маски с 1900–2099 за миллисекунды.
        Matcher yearMatcher = Pattern.compile("(19\\d{2}|20\\d{2})").matcher(password);
        if (yearMatcher.find()) {
            addRisk(factors, Weight.MEDIUM, "Год/дата",
                    "В пароле есть год или дата: " + yearMatcher.group());
        }
        if (password.matches(".*(\\d{2}[./-]\\d{2}[./-]\\d{4}|\\d{4}[./-]\\d{2}[./-]\\d{2}).*")) {
            addRisk(factors, Weight.MEDIUM, "Дата", "Есть шаблон даты");
        }

        // === Эвристика 8. Повторение подстрок ===
        // Почему: «abcabc», «passwordpassword» — фактически удвоение словаря.
        // Эффективная энтропия равна одному повтору, а не двум.
        String repeated = findRepeatedSubstring(lower);
        if (repeated != null) {
            addRisk(factors, Weight.MEDIUM, "Повтор подстроки",
                    "Есть повторяющаяся подстрока: " + repeated);
        }

        // Подсчёт итогов.
        int riskScore = 0, strengthScore = 0;
        for (Factor f : factors) {
            if (f.type == FactorType.RISK) riskScore += f.weight.score;
            else strengthScore += f.weight.score;
        }
        int totalScore = strengthScore - riskScore;

        // Порог выбран эмпирически для учебной демонстрации:
        //   >=4 — HIGH (нет серьёзных рисков, есть усиления)
        //   0..3 — MEDIUM
        //   <0 — LOW
        Strength strength;
        if (totalScore >= 4) strength = Strength.HIGH;
        else if (totalScore >= 0) strength = Strength.MEDIUM;
        else strength = Strength.LOW;

        return new Analysis(strength, factors, totalScore, riskScore, strengthScore,
                buildRecommendation(strength));
    }

    // --- вспомогательные методы -------------------------------------------------

    private static void addRisk(List<Factor> f, Weight w, String name, String desc) {
        f.add(new Factor(FactorType.RISK, w, name, desc));
    }
    private static void addStrength(List<Factor> f, Weight w, String name, String desc) {
        f.add(new Factor(FactorType.STRENGTH, w, name, desc));
    }

    /** Приводит Leet-строку к обычному виду (для поиска замаскированных слов). */
    private static String normalizeLeet(String s) {
        return s.replace('@', 'a').replace('0', 'o').replace('3', 'e')
                .replace('1', 'i').replace('$', 's').replace('5', 's')
                .replace('7', 't').replace('4', 'a');
    }

    /** Возвращает true, если есть монотонная последовательность длиной ≥ minLen. */
    private static boolean containsSequence(String s, int minLen) {
        int asc = 1, desc = 1;
        for (int i = 1; i < s.length(); i++) {
            char prev = s.charAt(i - 1), cur = s.charAt(i);
            asc  = (cur == prev + 1) ? asc  + 1 : 1;
            desc = (cur == prev - 1) ? desc + 1 : 1;
            if (asc >= minLen || desc >= minLen) return true;
        }
        return false;
    }

    /** Ищет подстроку, повторяющуюся дважды подряд. */
    private static String findRepeatedSubstring(String s) {
        for (int len = 2; len <= s.length() / 2; len++) {
            for (int i = 0; i + 2 * len <= s.length(); i++) {
                String sub = s.substring(i, i + len);
                if (sub.equals(s.substring(i + len, i + 2 * len))) return sub;
            }
        }
        return null;
    }

    /** Человеческая рекомендация без жаргона. */
    private static String buildRecommendation(Strength strength) {
        switch (strength) {
            case HIGH:
                return "Пароль выглядит стойким. Используйте менеджер паролей и не повторяйте этот пароль на разных сервисах.";
            case MEDIUM:
                return "Увеличьте длину до 13+ символов и добавьте недостающие категории символов (спецсимволы, цифры или разный регистр). Избегайте словарных слов и простых последовательностей.";
            default:
                return "Сделайте пароль длиннее 12 символов, добавьте буквы разного регистра, цифры и спецсимволы. Уберите распространённые слова, даты и последовательности вроде 1234 или qwerty.";
        }
    }

    // --- вывод ------------------------------------------------------------------

    private static String formatText(Analysis a) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Анализ сложности пароля ===\n");
        sb.append("Оценка стойкости: ").append(a.strength).append("\n");
        sb.append("Итоговый балл: ").append(a.totalScore)
                .append(" (усиления: ").append(a.strengthScore)
                .append(", риски: ").append(a.riskScore).append(")\n");
        sb.append("Факторы:\n");
        if (a.factors.isEmpty()) sb.append("  — факторов не найдено\n");
        else for (Factor f : a.factors) {
            String type = (f.type == FactorType.RISK) ? "РИСК" : "УСИЛЕНИЕ";
            sb.append(String.format("  [%s, %s] %s: %s%n", type, f.weight, f.name, f.description));
        }
        sb.append("Рекомендация: ").append(a.recommendation);
        return sb.toString();
    }

    private static String toJson(Analysis a) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"strength\": \"").append(a.strength).append("\",\n");
        sb.append("  \"totalScore\": ").append(a.totalScore).append(",\n");
        sb.append("  \"riskScore\": ").append(a.riskScore).append(",\n");
        sb.append("  \"strengthScore\": ").append(a.strengthScore).append(",\n");
        appendArray(sb, "risks",     filter(a.factors, FactorType.RISK));
        sb.append(",\n");
        appendArray(sb, "strengths", filter(a.factors, FactorType.STRENGTH));
        sb.append(",\n");
        sb.append("  \"recommendation\": \"").append(escapeJson(a.recommendation)).append("\"\n");
        sb.append("}");
        return sb.toString();
    }

    private static List<Factor> filter(List<Factor> fs, FactorType t) {
        List<Factor> r = new ArrayList<>();
        for (Factor f : fs) if (f.type == t) r.add(f);
        return r;
    }

    private static void appendArray(StringBuilder sb, String name, List<Factor> fs) {
        sb.append("  \"").append(name).append("\": [");
        if (fs.isEmpty()) { sb.append("]"); return; }
        sb.append("\n");
        for (int i = 0; i < fs.size(); i++) {
            Factor f = fs.get(i);
            sb.append("    {\"weight\": \"").append(f.weight)
                    .append("\", \"name\": \"").append(escapeJson(f.name))
                    .append("\", \"description\": \"").append(escapeJson(f.description)).append("\"}");
            if (i < fs.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ]");
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    // --- тесты ------------------------------------------------------------------

    /**
     * Набор проверочных кейсов. 22 примера (требовалось 15+).
     * Классификация должна совпадать с ожидаемой.
     */
    private static void runTests() {
        // Слабые (LOW)
        check("123456",            Strength.LOW);   // короткий, только цифры, словарь
        check("qwerty",            Strength.LOW);   // клавиатурная послед., словарь
        check("password",          Strength.LOW);   // словарное слово
        check("admin",             Strength.LOW);   // словарное, короткий
        check("aaaaaa",            Strength.LOW);   // повторы, короткий
        check("11111111",          Strength.LOW);   // только цифры
        check("passwordpassword",  Strength.LOW);   // повтор + словарь
        check("abcabc",            Strength.LOW);   // повтор подстроки, короткий
        check("letmein2024",       Strength.LOW);   // словарь + год

        // Средние (MEDIUM)
        check("SunnyDay2024",      Strength.MEDIUM);
        check("Welcome123",        Strength.MEDIUM);
        check("Tr0ub4dor&3",       Strength.MEDIUM);
        check("Admin@2024",        Strength.MEDIUM);
        check("Qwerty!2345",       Strength.MEDIUM);
        check("football1998",      Strength.MEDIUM);
        check("Password1!",        Strength.MEDIUM);

        // Стойкие (HIGH)
        check("X7#kL9$pQ2!vB",     Strength.HIGH);
        check("Zx9!mNq2@Wp4$Lr",   Strength.HIGH);
        check("!vB9$Lq2@Wp4mNz",   Strength.HIGH);
        check("gT5^hJ8&kL2*mN9",   Strength.HIGH);
        check("R#7dF!2sK@9wQ$5",   Strength.HIGH);
        check("9kL!mN2@Wp4$Zx7",   Strength.HIGH);

        System.out.println("Все 22 теста пройдены.");
    }

    private static void check(String password, Strength expected) {
        Analysis a = analyze(password);
        if (a.strength != expected) {
            throw new AssertionError(
                    "Пароль \"" + password + "\": ожидалось " + expected +
                            ", получено " + a.strength +
                            " (score=" + a.totalScore +
                            ", risks=" + a.riskScore +
                            ", strengths=" + a.strengthScore + ")");
        }
    }
}