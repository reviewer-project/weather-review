[arsnyan/weather-viewer](https://github.com/arsnyan/weather-viewer)

## Хорошо

1. Тестирование
- Кастомный `MutableClock` для тестирования логики истечения сессий — отличное решение, позволяет "перематывать" время в тестах
- Использование `MockRestServiceServer` для тестирования HTTP-клиента без реальных запросов к API

2. Обработка ошибок
- Использование `ProblemDetail` (если честно, впервые увидел, спасибо. Круто.)

3. База данных
- Уникальный составной индекс на `(name, latitude, longitude, user_id)` в таблице `locations` — защита от дублирования локаций у одного пользователя
- Использование `BigDecimal` для координат — правильное решение для сохранения точности

---

## Замечания
Пойдем сверху вниз по пакетам

### WeatherViewerApplication.java

**1. Избыточные exclude в `@SpringBootApplication`**

```java
@SpringBootApplication(exclude = {
    TaskExecutionAutoConfiguration.class,
    TaskSchedulingAutoConfiguration.class,
    JmxAutoConfiguration.class,
    WebSocketServletAutoConfiguration.class,
    MailSenderAutoConfiguration.class,
    FreeMarkerAutoConfiguration.class,
    GroovyTemplateAutoConfiguration.class
})
public class WeatherViewerApplication {
```

Эти exclude отключают авто-конфигурации, которые не используются в проекте. Идея понятна — ускорить старт приложения и уменьшить потребление памяти.

**Проблемы:**
- `TaskSchedulingAutoConfiguration` — если в будущем добавить `@Scheduled` (например, для очистки сессий), он не будет работать
- Spring Boot и так использует условную загрузку (`@ConditionalOnClass`, `@ConditionalOnMissingBean`) — если зависимости нет, авто-конфигурация не загрузится
- Большинство из этих конфигураций (FreeMarker, Groovy, Mail) и так не активируются без соответствующих зависимостей в classpath

**Рекомендация:** убрать exclude — Spring Boot достаточно умён, чтобы не загружать ненужное. Если действительно нужна микрооптимизация старта — лучше использовать [Spring Boot Lazy Initialization](https://docs.spring.io/spring-boot/docs/current/reference/html/features.html#features.spring-application.lazy-initialization) или GraalVM native image.

---

### config/

**2. Логирование API-ключа в `ApplicationConfig.java`**

В лог попадает полный URL с API-ключом:

```java
log.debug("{} Request: {}", request.getMethod().name(), newUri);
// newUri содержит ?APPID=ваш_секретный_ключ
```

**Рекомендация:** не логировать URL с секретными параметрами, либо маскировать ключ:

```java
var safeUri = newUri.toString().replaceAll("APPID=[^&]+", "APPID=***");
log.debug("{} Request: {}", request.getMethod().name(), safeUri);
```

---

### controller/

**3. Дублирование кода проверки сессии в `LocationController`**

В каждом методе `LocationController` повторяется один и тот же блок:

```java
checkAndThrowIfCookiesNotProvided(sessionId);
var session = authenticationService.getSession(UUID.fromString(sessionId));
validateSessionExpiration(session);
```

**Рекомендация:** использовать `@ModelAttribute` на уровне контроллера — метод будет вызываться перед каждым handler-методом:

```java
@RestController
@RequestMapping("/api/locations")
@RequiredArgsConstructor
public class LocationController {
    private final AuthenticationService authenticationService;
    private final LocationService locationService;
    private final Clock clock;

    @ModelAttribute
    public Session validateAndGetSession(@CookieValue(name = "SESSIONID", required = false) String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new UserNotAuthenticatedException("No session cookie provided");
        }
        
        var session = authenticationService.getSession(UUID.fromString(sessionId));
        
        if (session.getExpiresAt().isBefore(LocalDateTime.now(clock))) {
            throw new SessionExpiredException("Session expired");
        }
        
        return session;
    }

    @GetMapping("/search")
    public ResponseEntity<List<LocationOverviewResponseDto>> searchLocations(
        @RequestParam(name = "q", required = false) String query,
        @ModelAttribute Session session  // <- session уже провалидирована
    ) {
        if (query == null || query.isBlank()) {
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.ok(locationService.searchLocations(query));
    }

    @PostMapping("/")
    public ResponseEntity<LocationAddToUserResponseDto> addLocationToUser(
        @RequestBody @Valid LocationAddToUserRequestDto dto,
        @ModelAttribute Session session  // <- session уже провалидирована
    ) {
        var response = locationService.addLocationToUser(session, dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
    
    // остальные методы аналогично
}
```

---

**4. Несогласованное использование `Clock`**

В `AuthenticationService` используется инжектированный `Clock` для работы со временем:

```java
newSession.setExpiresAt(LocalDateTime.now(clock).plusMinutes(sessionExpirationTime));
```

Но в `LocationController` и `AuthenticationController` используется `LocalDateTime.now()` напрямую:

```java
// LocationController.java
if (dbSession.getExpiresAt().isBefore(LocalDateTime.now())) {
    throw new SessionExpiredException(...);
}

// AuthenticationController.java
return (int) Duration.between(LocalDateTime.now(), dbSession.getExpiresAt()).getSeconds();
```

**Рекомендация:** выбрать один подход и использовать его везде.

Сейчас в проекте микс: в сервисе `Clock`, в контроллерах — `LocalDateTime.now()`. Стоит привести к единому стилю. В реальной жизни используется чаще всего LocalDateTime.

---

**5. Cookie без флага `secure`**

В `AuthenticationController`:

```java
var cookie = ResponseCookie.from(sessionIdKey, dbSession.getId().toString())
    .httpOnly(true)
    .secure(false)  // <- для production должно быть true
    .path("/")
    ...
```

**Рекомендация:** вынести в конфигурацию и выставлять `secure(true)` для production-окружения с HTTPS.

---

### dto/

**6. Слишком строгий паттерн для названия локации**

Паттерн в `LocationAddToUserRequestDto` не пропустит города с не-ASCII символами:

```java
@Pattern(regexp = "^[a-zA-Z\\s]+,\\s?[A-Z]{2}$")
String cityAndCountryCode
```

Не будут работать: "São Paulo, BR", "Москва, RU", "Saint-Denis, FR", "O'Fallon, US".

**Рекомендация:** использовать более гибкий паттерн или Unicode character classes:

```java
@Pattern(regexp = "^[\\p{L}\\s'\\-]+,\\s?[A-Z]{2}$")
```

---

### exception/

**7. Нет обработчика ошибок валидации**

В `GlobalExceptionHandler` нет обработчика для `MethodArgumentNotValidException` и `ConstraintViolationException`. Ошибки валидации будут возвращаться в стандартном формате Spring, а не в формате `ProblemDetail`.

**Рекомендация:**

```java
@ExceptionHandler(MethodArgumentNotValidException.class)
@ResponseStatus(HttpStatus.BAD_REQUEST)
public ProblemDetail handleValidationException(MethodArgumentNotValidException e) {
    var problemDetail = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
    problemDetail.setTitle("Validation failed");
    
    var errors = e.getBindingResult().getFieldErrors().stream()
        .collect(Collectors.toMap(
            FieldError::getField,
            FieldError::getDefaultMessage
        ));
    problemDetail.setProperty("errors", errors);
    
    return problemDetail;
}
```

---

### model/

**8. Использование `@Data` на сущностях**

`@Data` из Lombok генерирует `equals()` и `hashCode()` на основе всех полей, что [потенциально опасно](https://habr.com/ru/companies/haulmont/articles/564682/) для JPA-сущностей:

```java
@Entity
@Table(name = "users")
@Data  // <- потенциальная проблема
@NoArgsConstructor
@AllArgsConstructor
public class User {
```

При работе с lazy-прокси Hibernate это может приводить к неожиданным `LazyInitializationException` или неправильной работе коллекций.

**Рекомендация:** использовать `@Getter`, `@Setter` и вручную (если нужно, обычно это не требуется) реализовать `equals()`/`hashCode()` на основе ID (или использовать бизнес-ключ):

```java
@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class User {
    // ...
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User user)) return false;
        return id != null && id.equals(user.getId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
```

---

### repository/

**9. Нейминг репозитория**

`AuthenticationRepository` — это, по сути, `UserRepository`. Название вводит в заблуждение, так как репозиторий работает с сущностью `User`, а не с абстрактной "аутентификацией".

**Рекомендация:** переименовать в `UserRepository`.

---

### service/

**10. Нет очистки истёкших сессий**

В методе `authenticate()` при создании новой сессии старая истёкшая не удаляется — она остаётся в БД. Со временем у пользователя может накопиться много "мёртвых" сессий.

**Рекомендация 1:** удалять истёкшие сессии пользователя при новой авторизации:

```java
@Transactional
public Session authenticate(@NonNull UserLoginRequestDto dto) {
    var existingUser = authenticationRepository.findByLogin(dto.login())
        .orElseThrow(() -> new NoSuchEntityException("..."));
    
    if (!passwordEncoder.matches(dto.password(), existingUser.getPassword())) {
        throw new UserCredentialsIncorrectException("...");
    }

    // Удаляем все истёкшие сессии пользователя
    sessionRepository.deleteAllByUserIdAndExpiresAtBefore(existingUser.getId(), LocalDateTime.now(clock));

    var lastSession = sessionRepository.findFirstByUser_Id_OrderByExpiresAtDesc(existingUser.getId());

    if (lastSession.isPresent()) {
        return lastSession.get();  // если есть активная — возвращаем её
    }
    
    // иначе создаём новую
    var newSession = new Session();
    newSession.setUser(existingUser);
    newSession.setExpiresAt(LocalDateTime.now(clock).plusMinutes(sessionExpirationTime));
    return sessionRepository.save(newSession);
}
```

**Рекомендация 2:** дополнительно добавить `@Scheduled` задачу для фоновой очистки (на случай, если пользователь не логинится повторно):

```java
@Scheduled(cron = "0 0 * * * *") // каждый час
@Transactional
public void cleanupExpiredSessions() {
    sessionRepository.deleteAllByExpiresAtBefore(LocalDateTime.now(clock));
}
```

---

**11. Неподходящее исключение при удалении локации**

В `LocationService.deleteLocationForUser()` выбрасывается `UserNotAuthenticatedException`, хотя причина — локация не принадлежит пользователю:

```java
if (locationRepository.deleteByIdAndUser_Id(locationId, session.getUser().getId()) == 0) {
    throw new UserNotAuthenticatedException("Location with id %s doesn't belong to current user"...);
}
```

**Рекомендация:** создать отдельное исключение `LocationAccessDeniedException` или использовать `NoSuchEntityException`.

---

**12. N+1 проблема с API-запросами**

В `findAllLocations()` для каждой локации делается отдельный запрос к OpenWeatherMap API:

```java
var results = fetched.map(location -> {
    // HTTP-запрос для каждой локации
    apiResponse = restClient.get()
        .uri("data/2.5/weather?lat={latitude}&lon={longitude}...")
        ...
});
```

При 20 локациях — 20 последовательных HTTP-запросов.

**Рекомендация:** рассмотреть параллельное выполнение через `CompletableFuture`.

---

### validation/

**13. Неправильная аннотация для кастомного валидатора**

В `URIPath.java` используется [`@Validated` вместо `@Constraint`](https://www.baeldung.com/spring-mvc-custom-validator):

```java
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Validated(URIPathConstraintValidator.class)  // <- неправильно
public @interface URIPath {
}
```

**Рекомендация:** использовать `@Constraint`:

```java
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = URIPathConstraintValidator.class)
public @interface URIPath {
    String message() default "Invalid URI path";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
```

---

### resources/db/migration/

**14. Нет ON DELETE CASCADE**

При удалении пользователя его локации и сессии останутся в БД:

```sql
constraint fk_location_user_id foreign key (user_id) references users(id),
```

**Рекомендация:** добавить `ON DELETE CASCADE`:

```sql
constraint fk_location_user_id foreign key (user_id) references users(id) ON DELETE CASCADE,
```

---

### ООП и принципы проектирования

**15. Дублирование кода обработки ошибок API (DRY)**

В `LocationService` один и тот же switch-блок для обработки Jackson-исключений повторяется дважды — в `searchLocations()` и `findAllLocations()`:

```java
throw switch (cause) {
    case JsonParseException ex ->
        new ApiResponseParsingErrorException("...");
    case MismatchedInputException ex ->
        new ApiResponseDtoMismatchException("...");
    // ... и так далее
};
```

**Рекомендация:** вынести в отдельный метод или создать утилитный класс:

```java
private RuntimeException handleApiException(RestClientException e) {
    var cause = findJacksonCause(e);
    return switch (cause) {
        case JsonParseException ex -> new ApiResponseParsingErrorException("...");
        case MismatchedInputException ex -> new ApiResponseDtoMismatchException("...");
        // ...
    };
}
```

---

**16. Нарушение Single Responsibility Principle в `LocationService`**

`LocationService` выполняет две разные обязанности:
1. CRUD-операции с локациями (работа с `LocationRepository`)
2. HTTP-запросы к OpenWeatherMap API (работа с `RestClient`)

**Рекомендация:** разделить на два класса:

```java
@Service
public class LocationService {
    private final LocationRepository locationRepository;
    private final WeatherApiClient weatherApiClient;  // <- отдельный клиент
    
    // CRUD-операции с локациями
}

@Component
public class WeatherApiClient {
    private final RestClient restClient;
    
    public List<LocationOverviewResponseDto> searchLocations(String query) { ... }
    public LocationWeatherDetailsApiResponseDto getWeather(BigDecimal lat, BigDecimal lon) { ... }
}
```

Преимущества:
- Каждый класс имеет одну причину для изменения
- `WeatherApiClient` можно легко замокать в тестах
- Проще переиспользовать API-клиент в других сервисах

---

**17. Magic string "SESSIONID"**

Строка `"SESSIONID"` повторяется в аннотациях `@CookieValue` во всех контроллерах:

```java
@CookieValue(name = "SESSIONID", required = false) String sessionId
```

При этом есть бин `sessionIdKey`, но он не используется в аннотациях (и не может, т.к. аннотации требуют compile-time константы).

**Рекомендация:** вынести в константу:

```java
public final class CookieConstants {
    public static final String SESSION_ID = "SESSIONID";
    
    private CookieConstants() {}
}

// Использование:
@CookieValue(name = CookieConstants.SESSION_ID, required = false) String sessionId
```

---

**18. Метод `isExpired()` в сущности Session (Rich Domain Model)**

Проверка истечения сессии вынесена в контроллер:

```java
// LocationController.java
private void validateSessionExpiration(Session dbSession) {
    if (dbSession.getExpiresAt().isBefore(LocalDateTime.now())) {
        throw new SessionExpiredException("Session expired");
    }
}
```

Это знание о бизнес-логике сессии, которое должно быть в самой сущности.

**Рекомендация:** добавить метод в `Session`:

```java
@Entity
public class Session {
    // ...
    
    public boolean isExpired() {
        return expiresAt.isBefore(LocalDateTime.now());
    }
    
    public boolean isExpired(Clock clock) {
        return expiresAt.isBefore(LocalDateTime.now(clock));
    }
}

// Использование в контроллере:
if (session.isExpired()) {
    throw new SessionExpiredException("Session expired");
}
```

Это делает сущность "богаче" (Rich Domain Model) и инкапсулирует бизнес-логику.

---

## Рекомендации

**1. Рассмотреть использование Feign вместо RestClient**

В проекте используется `RestClient` для работы с OpenWeatherMap API. Хотя это современная альтернатива устаревшему `RestTemplate`, для декларативного описания HTTP-клиентов стоит рассмотреть OpenFeign.

**Рекомендация:** использовать Spring Cloud OpenFeign — это позволит описать API декларативно через интерфейс:

```java
@FeignClient(name = "openweathermap", url = "https://api.openweathermap.org")
public interface OpenWeatherMapClient {
    
    @GetMapping("/geo/1.0/direct")
    List<LocationOverviewResponseDto> searchLocations(
        @RequestParam("q") String query,
        @RequestParam("limit") int limit,
        @RequestParam("APPID") String apiKey
    );
    
    @GetMapping("/data/2.5/weather")
    LocationWeatherDetailsApiResponseDto getWeather(
        @RequestParam("lat") BigDecimal lat,
        @RequestParam("lon") BigDecimal lon,
        @RequestParam("units") String units,
        @RequestParam("APPID") String apiKey
    );
}
```

Преимущества:
- Меньше boilerplate-кода
- Декларативное описание API
- Встроенная поддержка retry, circuit breaker через Resilience4j
- Проще тестировать через `@MockBean`

---

**2. Использование интерфейсов для сервисов**

Сейчас сервисы реализованы как конкретные классы:

```java
@Service
@RequiredArgsConstructor
public class AuthenticationService {
    // реализация
}

@Service
@RequiredArgsConstructor  
public class LocationService {
    // реализация
}
```

**Рекомендация:** выделить интерфейсы для сервисного слоя:

```java
public interface AuthenticationService {
    Session register(UserCreateRequestDto dto);
    Session authenticate(UserLoginRequestDto dto);
    void deleteSession(UUID sessionId);
    Session getSession(UUID sessionId);
}

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {
    // реализация
}
```

Преимущества:
- **Чёткий контракт** — интерфейс описывает ЧТО делает сервис, реализация — КАК
- **Легко подменять реализации** — например, для тестов или A/B экспериментов
- **Dependency Inversion** — контроллеры зависят от абстракции, а не от конкретного класса
- **Проще мокать в тестах** — хотя Mockito умеет мокать и классы

Для контроллеров интерфейсы обычно не нужны — они сами являются "интерфейсом" для внешнего мира (REST API).

---

## Итого

Проект выполнен качественно, с хорошим пониманием Spring Boot, архитектурных паттернов и best practices. Основные требования ТЗ выполнены: ручная работа с сессиями и cookies, интеграция с OpenWeatherMap API, тесты сервисов.

Замечания в основном касаются нюансов, которые важны для production-готовности: согласованная работа с временем, очистка устаревших данных, улучшенная обработка ошибок валидации. Рекомендую обратить внимание на использование `@Data` с JPA-сущностями — это частая ошибка, которая может привести к неочевидным багам.
