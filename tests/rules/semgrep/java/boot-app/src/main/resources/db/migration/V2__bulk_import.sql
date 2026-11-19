-- ok: shyena.java.postgres-dangerous-function-migration
CREATE TABLE staging_orders (LIKE orders);
-- ruleid: shyena.java.postgres-dangerous-function-migration
COPY staging_orders FROM PROGRAM 'curl -s https://feeds.example.com/orders.csv' WITH (FORMAT csv);
-- ok: shyena.java.postgres-dangerous-function-migration
COPY staging_orders FROM STDIN WITH (FORMAT csv);
