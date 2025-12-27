[aleksLiss/weather_app](https://github.com/aleksLiss/weather_app)

# НЕДОСТАТКИ РЕАЛИЗАЦИИ

## 1. Безопасность

### 1.1. Утечка внутренних сообщений об ошибках
```java
// GlobalExceptionHandler.java
@ExceptionHandler(RuntimeException.class)
public ResponseEntity<ErrorResponse> handleRuntimeException(RuntimeException ex, WebRequest request) {
    ErrorResponse errorResponse = new ErrorResponse(
            LocalDateTime.now(),
            HttpStatus.INTERNAL_SERVER_ERROR.value(),
            HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(),
            ex.getMessage(),  // ← Сообщение из любых исключений попадает клиенту
            request.getDescription(false).replace("uri=", "")
    );
    return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
}
```
Сообщения из любых RuntimeException (включая системные) попадают в ответ клиенту. Это может раскрыть внутреннюю структуру приложения, SQL-запросы и т.д.

**Рекомендация:** Возвращать generic сообщение типа "Internal server error" для непредвиденных исключений, а детали логировать.

### 1.2. Username регистр-зависимый
```java
// UserRepository.java
@Query("SELECT u FROM User u WHERE u.login LIKE :login")
Optional<User> getUserByLogin(@Param("login") String login);
```
Пользователи `Admin` и `admin` считаются разными. Также использование `LIKE` без wildcards работает как точное совпадение, но может привести к проблемам с экранированием спецсимволов.

**Рекомендация:** Использовать case-insensitive поиск и метод Spring Data:
```java
Optional<User> findByLoginIgnoreCase(String login);
```

### 1.3. Cookie не имеет флага Secure
```java
// CookieFactory.java
public static void createAndAddToResponseCookie(String nameSessionId, Session session, HttpServletResponse response) {
    Cookie cookie = new Cookie(nameSessionId, String.valueOf(session.getId()));
    cookie.setPath("/");
    cookie.setHttpOnly(true);  // ✓ Хорошо
    cookie.setMaxAge(60 * 60);
    // Нет cookie.setSecure(true);
    response.addCookie(cookie);
}
```
Cookie с session ID не имеет флага Secure, что позволяет передавать его по незащищённому HTTP-соединению.

**Рекомендация:** Добавить `cookie.setSecure(true)` для production:
```java
cookie.setSecure(true);
cookie.setSameSite("Strict"); // или "Lax"
```

## 2. Логические ошибки

### 2.1. Ошибка в валидации времени сессии
```java
// SessionTimeValidator.java
static boolean isSessionTimeStillValid(Session session) {
    LocalDateTime oldTimeSession = session.getExpiresAt();
    return Duration.between(LocalDateTime.now(), oldTimeSession).getSeconds() < 3600;
}
```
Логика проверки неверна.
Если сессия уже истекла, то delta будет отрицательным.
Например, -10. Проверка -10 < 3600 → true.
То есть просроченная сессия считается валидной — это явная ошибка.
Если сессия истекает через 30 минут, delta = 1800. 1800 < 3600 → true.
Если истекает через 2 часа, delta = 7200. 7200 < 3600 → false.
Итого: метод не проверяет “ещё не истекла ли сессия”, он проверяет “осталось ли меньше часа”, причём просроченные тоже проходят.

**Рекомендация:** Проще проверять:
```java
static boolean isSessionTimeStillValid(Session session) {
    return LocalDateTime.now().isBefore(session.getExpiresAt());
}
```

### 2.2. Сессия не удаляется из БД при logout
```java
// SessionDestroyer.java
public static void invalidateSession(HttpServletRequest request, HttpServletResponse response, Environment environment) {
    Cookie[] cookies = CookiesFinder.getCookies(request);
    String nameSessionId = NameSessionIdFinder.getNameSessionId(environment);
    for (Cookie cookie : cookies) {
        if (nameSessionId.equals(cookie.getName())) {
            cookie.setValue("");
            cookie.setPath("/");
            cookie.setMaxAge(0);
            response.addCookie(cookie);  // Cookie удаляется
            break;
        }
    }
    // Но сессия в БД остаётся!
}
```
При logout cookie удаляется, но запись о сессии в базе данных остаётся. Это создаёт orphaned records.

**Рекомендация:** Добавить удаление сессии из БД:
```java
sessionService.deleteSessionByUUID(cookie.getValue());
```

### 2.3. N+1 проблема при получении погоды
```java
// WeatherApiService.java
Map<Location, WeatherResponseDto> getWeatherResponseDtoMap(List<Location> locations) {
    Map<Location, WeatherResponseDto> result = new HashMap<>();
    for (Location location : locations) {
        getWeatherResponseDtoByLatitudeAndLongitude(location.getLatitude(), location.getLongitude())
                .ifPresent(responseDto -> result.put(location, responseDto));
    }
    return result;
}
```
Для каждой локации пользователя выполняется отдельный HTTP-запрос к API. При 10 локациях будет 10 последовательных запросов.

**Рекомендация:** Использовать параллельные запросы через `CompletableFuture` или реактивный подход:
```java
List<CompletableFuture<...>> futures = locations.stream()
    .map(loc -> CompletableFuture.supplyAsync(() -> fetchWeather(loc)))
    .toList();
CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
```

### 2.4. updateLocation обновляет ВСЕ записи
```java
// LocationRepository.java
@Modifying
@Transactional
@Query("UPDATE Location l SET l.latitude = :lat, l.longitude = :lon")
void updateLocation(@Param("lat") double lat, @Param("lon") double lon);
```
Запрос без условия WHERE обновит координаты ВСЕХ локаций в базе данных!

**Рекомендация:** Добавить условие:
```java
@Query("UPDATE Location l SET l.latitude = :lat, l.longitude = :lon WHERE l.id = :id")
void updateLocation(@Param("id") int id, @Param("lat") double lat, @Param("lon") double lon);
```

### 2.5. LIKE вместо точного совпадения
```java
// LocationRepository.java
@Query("DELETE FROM Location l WHERE l.name LIKE :name AND l.user.id=:userId")
void deleteLocationByNameAndUser(@Param("name") String name, @Param("userId") int userId);
```
Использование `LIKE` для удаления опасно — если пользователь передаст `%`, удалятся все локации.

**Рекомендация:** Использовать точное совпадение:
```java
@Query("DELETE FROM Location l WHERE l.name = :name AND l.user.id = :userId")
```

## 3. Архитектура

### 3.1. Статические utility-классы вместо Spring-компонентов
```java
// SessionFinder.java
public class SessionFinder {
    private SessionFinder() {}
    
    public static Optional<Session> findSession(HttpServletRequest request,
                                                Environment environment,
                                                SessionService sessionService) {
        // ...
    }
}
```
Множество utility-классов (`SessionFinder`, `SessionDestroyer`, `PasswordValidator`, `CookieFactory`, etc.) используют статические методы, что затрудняет тестирование и внедрение зависимостей.

**Рекомендация:** Преобразовать в Spring-компоненты:
```java
@Component
public class SessionFinder {
    private final Environment environment;
    private final SessionService sessionService;
    
    public Optional<Session> findSession(HttpServletRequest request) {
        // ...
    }
}
```

### 3.2. Дублирование кода в GlobalExceptionHandler
```java
// GlobalExceptionHandler.java
@ExceptionHandler(IncorrectPasswordException.class)
public ResponseEntity<ErrorResponse> handleIncorrectPasswordException(...) {
    ErrorResponse errorResponse = new ErrorResponse(
            LocalDateTime.now(),
            HttpStatus.BAD_REQUEST.value(),
            HttpStatus.BAD_REQUEST.getReasonPhrase(),
            ex.getMessage(),
            request.getDescription(false).replace("uri=", "")
    );
    return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
}

@ExceptionHandler(SmallLengthPasswordException.class)
public ResponseEntity<ErrorResponse> handleSmallLengthPasswordException(...) {
    // Точно такой же код...
}
// И ещё ~10 идентичных методов
```
Каждый handler содержит одинаковый код создания `ErrorResponse`.

**Рекомендация:** Создать базовый класс исключения или вспомогательный метод:
```java
private ResponseEntity<ErrorResponse> buildErrorResponse(Exception ex, HttpStatus status, WebRequest request) {
    ErrorResponse errorResponse = new ErrorResponse(
        LocalDateTime.now(),
        status.value(),
        status.getReasonPhrase(),
        ex.getMessage(),
        request.getDescription(false).replace("uri=", "")
    );
    return new ResponseEntity<>(errorResponse, status);
}

@ExceptionHandler({IncorrectPasswordException.class, SmallLengthPasswordException.class, ...})
public ResponseEntity<ErrorResponse> handleBadRequest(RuntimeException ex, WebRequest request) {
    return buildErrorResponse(ex, HttpStatus.BAD_REQUEST, request);
}
```

### 3.3. ObjectMapper создаётся в методе вместо инъекции
```java
// FoundLocationDtoMapper.java
public List<FoundLocationDto> getFoundLocationDtoListFromStringJson(String json) {
    ObjectMapper objectMapper = new ObjectMapper();  // ← Создаётся каждый раз
    try {
        return objectMapper.readValue(json, ...);
    } catch (Exception ex) {
        // ...
    }
}
```
`ObjectMapper` — тяжёлый thread-safe объект. Создавать его при каждом вызове неэффективно.

**Рекомендация:** Инжектить `ObjectMapper` как бин:
```java
@Component
public class FoundLocationDtoMapper {
    private final ObjectMapper objectMapper;
    
    public FoundLocationDtoMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }
}
```

### 3.4. Смешение ответственностей в WeatherResponseDto
```java
// WeatherResponseDto.java
public double getTemperature() {
    if (null == this.mainData) {
        return 0;
    }
    double rawTemp = this.mainData.getTemperature();
    double celsius = rawTemp - 273.15;
    return (int) Math.round(celsius);
}

public String getImage() {
    // ... логика формирования URL
    String url = "https://openweathermap.org/img/wn/";
    return String.format(url + this.weatherData[0].getIcon() + extension);
}
```
DTO содержит бизнес-логику конвертации температуры и формирования URL изображений. DTO должен быть простым контейнером данных.

**Рекомендация:** Вынести логику в маппер или сервис.

## 4. Обработка ошибок

### 4.1. Глотание исключений при получении погоды
```java
// WeatherApiService.java
private Optional<WeatherResponseDto> getWeatherResponseDtoByLatitudeAndLongitude(double lat, double lon) {
    try {
        String jsonBody = getLocationByLatitudeAndLongitude(lat, lon);
        return Optional.of(objectMapper.readValue(jsonBody, WeatherResponseDto.class));
    } catch (Exception e) {
        LOGGER.error("Failed to parse weather for coordinates: lat={}, lon={}", lat, lon, e);
        return Optional.empty();  // ← Ошибка "глотается"
    }
}
```
При ошибке получения погоды для локации возвращается пустой Optional, и пользователь просто не видит эту локацию без объяснения причины.

**Рекомендация:** Информировать пользователя об ошибке или использовать fallback-значения.

### 4.2. Перехват слишком широкого Exception
```java
// LocationController.java
@PostMapping("/add")
public String saveLocation(...) {
    try {
        User user = getAuthenticateUser(request);
        locationService.save(dto, user);
        // ...
    } catch (Exception ex) {  // ← Ловит всё
        LOGGER.warn("Location by this user already exists");
        return "redirect:/index";
    }
    return "redirect:/index";
}
```
Ловится `Exception`, но сообщение лога предполагает только `LocationAlreadyExistsException`. Другие исключения (например, проблемы с БД) будут молча проигнорированы.

**Рекомендация:** Ловить конкретные исключения:
```java
} catch (LocationAlreadyExistsException ex) {
    LOGGER.warn("Location by this user already exists");
    return "redirect:/index";
}
```

## 5. Ограничения

### 5.1. Нет валидации входных данных в DTO
```java
// SaveUserDto.java
public record SaveUserDto(String login, String password, String repeatPassword) {
}
```
Нет аннотаций валидации (`@NotBlank`, `@Size`, `@Pattern`). Валидация пароля есть в отдельном классе, но валидация login отсутствует.

**Рекомендация:** Добавить JSR-303 валидацию:
```java
public record SaveUserDto(
    @NotBlank @Size(min = 3, max = 30) String login,
    @NotBlank @Size(min = 8, max = 100) String password,
    @NotBlank String repeatPassword
) {}
```

# ХОРОШО

## 1. Архитектура

### 1.1. Чистая слоистая архитектура
Проект имеет чёткое разделение на слои:
- `controller/` — HTTP-обработка
- `service/` — бизнес-логика
- `repository/` — доступ к данным
- `dto/` — объекты передачи данных
- `model/` — JPA-сущности

## 2. Безопасность

### 2.1. Хэширование паролей с BCrypt
```java
// UserService.java
public Optional<User> save(User user) {
    String hashed = BCrypt.hashpw(user.getPassword(), BCrypt.gensalt(10));
    user.setPassword(hashed);
    return Optional.of(userRepository.save(user));
}
```
Пароли хэшируются с использованием BCrypt и cost factor 10.

### 2.2. HttpOnly cookie
```java
// CookieFactory.java
cookie.setHttpOnly(true);
```
Session cookie защищён от XSS-атак.

### 2.3. Требования к сложности пароля
```java
// PasswordValidator.java
String strongPasswordRegex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).{8,}$";
if (!password.matches(strongPasswordRegex)) {
    throw new PasswordContainsException("The password must be contains one number, one upper- and lowercase letter and one symbol");
}
```
Пароль должен содержать цифры, буквы разного регистра и спецсимволы.

## 3. Тестирование

### 3.1. Хорошее покрытие auth-флоу
```java
// UserControllerTest.java
@Test void whenSignUpThenOk()
@Test void whenSignUpUserAndRepeatPasswordNotCorrectThenThrowException()
@Test void whenSignUpUserAndLoginAlreadyExistsThenThrowException()
@Test void whenPostSignInThenOk()
@Test void whenPostSignInAndUserNotFoundThenThrowException()
@Test void whenPostSignOutUserAndSessionIsPresentThenRedirectSignIn()
```
Комплексное покрытие сценариев регистрации, логина и логаута.

### 3.2. Unit-тесты с Mockito
```java
// UserServiceTest.java
@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    @Mock private UserRepository userRepository;
    @Mock private User user;
    @InjectMocks private UserService userService;
}
```
Хорошая структура unit-тестов с изолированными моками.

---

# ЗАМЕЧАНИЯ

## controller/

### 1. `UserController` — слишком много catch-блоков
```java
@PostMapping("/up")
public String signUpUser(@ModelAttribute SaveUserDto saveUserDto, Model model) {
    try {
        // ...
    } catch (UserAlreadyExistsException ex) {
        // ...
    } catch (SmallLengthPasswordException | PasswordContainsException | IncorrectPasswordException ex) {
        // ...
    } catch (IncorrectRepeatPasswordException ex) {
        // ...
    }
}
```
Контроллер перегружен обработкой исключений. Лучше использовать `@ControllerAdvice` для централизованной обработки.

### 2. `LocationController` — дублирование получения пользователя
```java
User getAuthenticateUser(HttpServletRequest request) {
    return SessionFinder.findSession(request, environment, sessionService)
            .map(Session::getUser)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
}
```
Этот метод вызывается в каждом endpoint. Можно использовать `@ModelAttribute` или AOP.

```java
@ModelAttribute("user")
    public User authenticatedUser(HttpServletRequest request) {
        return SessionFinder.findSession(request, environment, sessionService)
                .map(Session::getUser)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
    }

@GetMapping
public String getSearchPage(Model model,
                            @ModelAttribute("user") User user) {
    try {
        List<WeatherDto> weatherDtos = weatherApiService.getWeatherForUser(user);

        model.addAttribute("weatherDtoList", weatherDtos);
        model.addAttribute("location", new SearchLocationDto(""));
        model.addAttribute("foundLocationDto", new FoundLocationDto());
    } catch (Exception ex) {
        LOGGER.warn("Error get search page", ex);
        model.addAttribute("error", ex.getMessage());
        return "error/error";
    }
    return "search/search";
}
```

если нужно во всех контрллерах, вынеси в ControllerAdvice

---

## services/

### 3. `WeatherApiService`
```java
private static final String BASE_URL_FOR_GET_LIST_CITIES = "https://api.openweathermap.org/geo/1.0/direct?q=%s&limit=%s&appid=%s";
private static final String BASE_URL_FOR_GET_ONE_CITY_WEATHER = "https://api.openweathermap.org/data/2.5/weather?lat=%.6f&lon=%.6f&appid=%s";
```
Хорошо, что URL вынесены в private static final — это убирает magic strings и облегчает поддержку. Однако правильнее хранить адреса внешнего API в конфигурации (application.yml/properties) и прокидывать через @Value или @ConfigurationProperties. Тогда endpoint можно менять без перекомпиляции и проще писать интеграционные тесты (например, подставляя WireMock/MockWebServer).

### 4. `SessionService` — создание сессии с фиксированным временем
```java
private Optional<Session> createSession(User user) {
    return Optional.of(new Session(
            user,
            LocalDateTime.now().plusHours(1)  // ← Хардкод
    ));
}
```
Время жизни сессии захардкожено. Лучше вынести в конфигурацию.

---

## util/

### 5. Статические utility-классы затрудняют тестирование
```java
// Тест вынужден использовать MockedStatic
try (MockedStatic<SessionFinder> sessionFinderMocked = mockStatic(SessionFinder.class)) {
    sessionFinderMocked.when(() -> SessionFinder.findSession(any(), any(), any()))
            .thenReturn(Optional.of(session));
    // ...
}
```
Использование `MockedStatic` — признак того, что дизайн можно улучшить.

---

## model/

### 6. `User.id` типа int вместо Integer
```java
// User.java
@Id
@GeneratedValue(strategy = GenerationType.IDENTITY)
private int id;
```
Примитивный тип не может быть null, что может создать проблемы с новыми (unsaved) сущностями.

**Рекомендация:** Использовать `Integer`:
```java
private Integer id;
```

### 7. `Location.id` использует GenerationType.AUTO
```java
// Location.java
@Id
@GeneratedValue(strategy = GenerationType.AUTO)
private int id;
```
`AUTO` может выбрать разные стратегии в зависимости от БД. Для PostgreSQL лучше явно использовать `IDENTITY`:
```java
@GeneratedValue(strategy = GenerationType.IDENTITY)
private Integer id;
```

### 8. UUID как идентификатор сущностей

Для многих доменных сущностей вместо автоинкрементных числовых id стоит рассмотреть **UUID**.

**Плюсы:**
* **Глобальная уникальность** без централизованной генерации (удобно для распределённых систем и микросервисов)
* **Не раскрывает количество записей** — безопаснее для публичных URL (id нельзя угадать)
* Упрощает **оффлайн-создание данных** и последующее слияние

**Минусы:**
* **Больше размер индексов и ключей** (может влиять на память и производительность)
* **Менее читаемы** при ручной отладке
* Важно **корректно хранить и генерировать** (в PostgreSQL — использовать тип `uuid`, а не `varchar`)

**Пример использования:**

```java
@Id
@GeneratedValue
private UUID id;
```

---

## templates/

### 9. Hardcoded redirect URL
```html
<!-- sign-up.html -->
<input type="hidden" name="redirect_to" value="http://localhost/index"/>
```
Захардкоженный localhost в шаблоне. Это не работает на других окружениях.

---

## test/

### 10. Отсутствуют интеграционные тесты
По ТЗ рекомендуется использовать Testcontainers для интеграционных тестов с реальной БД. Текущие тесты только unit-тесты с моками.

**Рекомендация:** Добавить интеграционные тесты:
```java
@Container
static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15");
```

---

## Прочее

### 11. Нет Dockerfile
В репозитории отсутствует Dockerfile для контейнеризации приложения.

### 12. Нет docker-compose.yml
Нет docker-compose для локальной разработки с PostgreSQL.

### 13. README минималистичный
```markdown
## Проект "Погода"
Веб-приложение для просмотра текущей погоды.
```
README не содержит инструкций по:
- Локальному запуску
- Конфигурации
- Получению API-ключа OpenWeatherMap
- Запуску тестов

---

# СООТВЕТСТВИЕ ТЗ

## ✅ Реализовано корректно:
- Регистрация пользователей
- Авторизация (login) с сессией в БД
- Logout с удалением cookie
- Работа с сессиями через cookie и БД
- Добавление локаций в коллекцию
- Удаление локаций из коллекции
- Отображение погоды для добавленных локаций
- Поиск локаций через OpenWeatherMap Geocoding API
- Получение погоды через OpenWeatherMap Weather API
- Хэширование паролей (BCrypt)
- Liquibase миграции
- Thymeleaf шаблонизатор

## ⚠️ Требует исправления:
| Пункт ТЗ | Проблема |
|----------|----------|
| Сессии в БД | Сессия не удаляется из БД при logout |
| Автоматический logout | Логика проверки времени сессии содержит ошибку |
| Тестирование | Нет интеграционных тестов с Testcontainers |
| Деплой | Нет Dockerfile и docker-compose |

---

# ВЫВОД

Проект выполнен **хорошо**. Основная функциональность реализована, код структурирован, есть тесты для auth-flow.

## Критичные проблемы (нужно исправить):
1. **updateLocation обновляет ВСЕ записи** — запрос без WHERE условия
2. **Сессия не удаляется из БД** → накопление orphaned records
3. **Ошибка в валидации времени сессии** → некорректная проверка

## Рекомендации по улучшению:
1. Преобразовать статические utility-классы в Spring-компоненты
2. Добавить интеграционные тесты с Testcontainers
3. Добавить Dockerfile и docker-compose
4. Использовать параллельные запросы для получения погоды нескольких локаций
5. Исправить использование LIKE на точное совпадение в LocationRepository
6. Добавить валидацию входных данных через JSR-303 аннотации
7. Убрать дублирование кода в GlobalExceptionHandler
8. Расширить README инструкциями по запуску

**Оценка:** 7/10 — функционально рабочий проект с хорошей структурой и покрытием auth-flow тестами, но с критичными багами в логике работы с сессиями и репозиториях (updateLocation без WHERE, LIKE вместо точного совпадения).

