# Technical TODOs

This document tracks technical improvements, refactoring tasks, and code quality enhancements that are not directly related to product features.


(cuz im sometimes lazy hehe)

## No Priority atm

- [ ] Implement `@Transactional` support for operations that span multiple tables
    - Reference: https://docs.spring.io/spring-framework/reference/data-access/transaction/declarative.html
- [ ] Add proper HTTP status codes in controller responses:
    - Change to: `return new ResponseEntity<>(someDto, HttpStatus.CREATED);` instead of `ResponseEntity.ok` (lol)
- [ ] Implement proper authorization with `@PreAuthorize` for future resource requests
  ```java
  @RestController
  @RequestMapping("/api/v1/admin")
  @PreAuthorize("hasRole('ADMIN')")
  public class SomeClass {
      @GetMapping
      @PreAuthorize("hasAuthority('admin:read')")
      public String get() {
          return "something";
      }
  }
  ```
- [ ] No need to wipe database after shutting server down, maybe stop u_U
  - ``ddl-auto: create-drop`` drop this in yml :)
- [ ] Think about scheduling tasks for secret key rotations & think about how to handle project/logs/application.log -> delete? backup? etc.
  ```java
  @Slf4j
  @AllArgsConstructor
  @Service
  public class ScheduleTasks {
   
  @Scheduled(fixedDelay = 60, timeUnit = TimeUnit.Minutes)
  public void backupOrClearLogs() {}  
  @Scheduled(fixedDelay = 60, timeUnit = TimeUnit.Minutes)
  public void rotateSecretKey() {}  
  }
  ```
- [ ] Global RequestLoggingFilter exists to monitor all incoming and outgoing HTTP-Methods
  - Insert useful and critical logs into the service
  - Insert useful and critical logs inside the remaining Filters (JWTAuthFilter & TokenRefreshFilter)

## Dependency Updates
- [ ] Update dependencies + code if needed post update: several vulnerabilities found. check github aswell for precise explanation (vulnerability "listener)

## Code Quality

- [ ] Refactor string and integer literals into constants
- [ ] Configure logback-spring.xml to display colored logs in console

## Completed

- [x] Example completed task (date completed)

## Planning ahead
- Plan database structure beforehand -> into -> creating backend endpoints before creating UI in React to avoid big changes later on
