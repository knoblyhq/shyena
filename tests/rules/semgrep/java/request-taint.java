package com.example.demo;

import java.io.File;
import java.io.FileInputStream;
import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.io.FilenameUtils;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.view.RedirectView;

@RestController
@RequestMapping("/api")
public class DemoController {

    private final JdbcTemplate jdbcTemplate;
    private final EntityManager em;
    private final RestTemplate restTemplate;
    private final WebClient webClient;

    DemoController(JdbcTemplate jdbcTemplate, EntityManager em, RestTemplate restTemplate, WebClient webClient) {
        this.jdbcTemplate = jdbcTemplate;
        this.em = em;
        this.restTemplate = restTemplate;
        this.webClient = webClient;
    }

    // ---------------------------------------------------------------- SQL injection

    @GetMapping("/users")
    public List<Map<String, Object>> byName(@RequestParam String name) {
        // ruleid: shyena.java.sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }

    @GetMapping("/users/sorted")
    public List<Map<String, Object>> sorted(@RequestParam("sort") String sort) {
        String sql = String.format("SELECT * FROM users ORDER BY %s", sort);
        // ruleid: shyena.java.sqli-taint
        return jdbcTemplate.queryForList(sql);
    }

    @PostMapping("/orders/search")
    public List<?> search(@RequestBody SearchRequest body) {
        // ruleid: shyena.java.sqli-taint
        return em.createQuery("from Order o where o.status = '" + body.getStatus() + "'").getResultList();
    }

    @GetMapping("/legacy")
    public Object legacy(HttpServletRequest request) {
        String id = request.getParameter("id");
        // ruleid: shyena.java.sqli-taint
        return em.createNativeQuery("select * from t where id = " + id).getResultList();
    }

    @GetMapping("/users/safe")
    public List<Map<String, Object>> safe(@RequestParam String name) {
        // ok: shyena.java.sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = ?", name);
    }

    @GetMapping("/users/{id}")
    public Map<String, Object> byId(@PathVariable Long id) {
        // ok: shyena.java.sqli-taint
        return jdbcTemplate.queryForMap("SELECT * FROM users WHERE id = " + id);
    }

    @GetMapping("/users/page")
    public List<Map<String, Object>> page(@RequestParam String limit) {
        int n = Integer.parseInt(limit);
        // ok: shyena.java.sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM users LIMIT " + n);
    }

    @GetMapping("/jpa/safe")
    public List<?> jpaSafe(@RequestParam String status) {
        // ok: shyena.java.sqli-taint
        return em.createQuery("from Order o where o.status = :s").setParameter("s", status).getResultList();
    }

    // ---------------------------------------------------------------- SpEL

    @PostMapping("/calc")
    public Object calc(@RequestParam String expr) {
        SpelExpressionParser parser = new SpelExpressionParser();
        // ruleid: shyena.java.spel-injection
        return parser.parseExpression(expr).getValue();
    }

    @GetMapping("/calc/fixed")
    public Object fixedCalc() {
        SpelExpressionParser parser = new SpelExpressionParser();
        // ok: shyena.java.spel-injection
        return parser.parseExpression("1 + 2").getValue();
    }

    // ---------------------------------------------------------------- command injection

    @PostMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        // ruleid: shyena.java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + host);
        // ruleid: shyena.java.command-injection
        new ProcessBuilder("sh", "-c", "nslookup " + host).start();
        return "ok";
    }

    @PostMapping("/uptime")
    public String uptime() throws Exception {
        // ok: shyena.java.command-injection
        new ProcessBuilder("uptime").start();
        return "ok";
    }

    // ---------------------------------------------------------------- SSRF

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) throws Exception {
        // ruleid: shyena.java.ssrf
        String body = restTemplate.getForObject(url, String.class);
        // ruleid: shyena.java.ssrf
        webClient.get().uri(url).retrieve();
        // ruleid: shyena.java.ssrf
        new URL(url).openStream();
        return body;
    }

    @GetMapping("/weather")
    public String weather(@RequestParam String city) {
        // ok: shyena.java.ssrf
        String a = restTemplate.getForObject("https://api.weather.example/v1/city/" + city, String.class);
        // ok: shyena.java.ssrf
        String b = restTemplate.getForObject("https://api.weather.example/v1/city/{c}", String.class, city);
        return a + b;
    }

    // ---------------------------------------------------------------- path traversal

    @GetMapping("/download")
    public byte[] download(@RequestParam String file) throws Exception {
        // ruleid: shyena.java.path-traversal
        return java.nio.file.Files.readAllBytes(Paths.get("/srv/files", file));
    }

    @PostMapping("/upload")
    public String upload(@RequestParam("file") MultipartFile upload) throws Exception {
        // ruleid: shyena.java.path-traversal
        upload.transferTo(new File("/srv/uploads/" + upload.getOriginalFilename()));
        return "ok";
    }

    @PostMapping("/upload/safe")
    public String uploadSafe(@RequestParam("file") MultipartFile upload) throws Exception {
        String name = FilenameUtils.getName(upload.getOriginalFilename());
        // ok: shyena.java.path-traversal
        upload.transferTo(new File("/srv/uploads/" + name));
        return "ok";
    }

    @GetMapping("/download/checked")
    public byte[] checked(@RequestParam String file) throws Exception {
        Path base = Paths.get("/srv/files");
        if (base.resolve(file).normalize().startsWith(base)) {
            // ok: shyena.java.path-traversal
            return java.nio.file.Files.readAllBytes(base.resolve(file).normalize());
        }
        return new byte[0];
    }

    // ---------------------------------------------------------------- open redirect

    @GetMapping("/go")
    public RedirectView go(@RequestParam String next) {
        // ruleid: shyena.java.open-redirect
        return new RedirectView(next);
    }

    @GetMapping("/login/done")
    public void done(@RequestParam String returnTo, HttpServletResponse response) throws Exception {
        // ruleid: shyena.java.open-redirect
        response.sendRedirect(returnTo);
    }

    @GetMapping("/items/back")
    public void back(@RequestParam String id, HttpServletResponse response) throws Exception {
        // ok: shyena.java.open-redirect
        response.sendRedirect("/items/" + id);
    }

    // A service method that is not a handler: its parameters are not request data.
    public List<Map<String, Object>> internal(String table) {
        // ok: shyena.java.sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM " + table);
    }
}
