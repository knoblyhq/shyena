package com.example.demo;

import org.springframework.jdbc.core.JdbcTemplate;

public class ReportJob {
    private static final String EXPORT_CSV =
        // ruleid: shyena.java.postgres-dangerous-function
        "COPY (SELECT * FROM orders) TO PROGRAM 'gzip > /tmp/orders.csv.gz' WITH (FORMAT csv)";

    private final JdbcTemplate jdbcTemplate;

    ReportJob(JdbcTemplate jdbcTemplate) { this.jdbcTemplate = jdbcTemplate; }

    void run() {
        jdbcTemplate.execute(EXPORT_CSV);
        // ruleid: shyena.java.postgres-dangerous-function
        jdbcTemplate.queryForObject("SELECT pg_read_file('/etc/passwd')", String.class);
        // ok: shyena.java.postgres-dangerous-function
        jdbcTemplate.queryForObject("SELECT count(*) FROM orders", Long.class);
        // ruleid: shyena.java.postgres-weak-sslmode
        String url = "jdbc:postgresql://reports-db.internal:5432/reports?sslmode=prefer";
    }
}
