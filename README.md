# pgsalt

pgsalt can generate and verify SCRAM password hashes as used by PostgreSQL 14
and newer versions

## Usage instructions

An example is worth a thousand words:

```
pgsalt verify 'SCRAM-SHA-256$4096:6XLbQHMPEcsKX2j7QGduHg==$pH3uW7XI+66Lwlz/CXCW07JwsryqhWL57jrK6Lk6P5c=:aNUS1WVrgG1ouU78jdjh0zHV/8lRF4eMoY5Vew2K9wI=' testpassword123
verification succeeded

pgsalt verify 'SCRAM-SHA-256$4096:81WODS+ZstEgpdNbnQqfvw==$PQFLz65Paw6MTnyzhg+k3ItjKfuFSrBNU+I/0/g7h6c=:KC6SF8NlghZbmRo9R7u5Kj7WUmqpwKnoC6zmqlhmXOQ=' testpassword123
verification failed: expected (same salt) SCRAM-SHA-256$4096:81WODS+ZstEgpdNbnQqfvw==$v1O+RJAG449EJ4tntARRmS+fVUDxZTOPJcnnbd2sP20=:NOx9GSVM0uC2xRnoBdhSsxJLdLEw6u2rQp12lddUO2U=
```

## References

This work is heavily influenced by
[scram-password](https://github.com/tv42/scram-password) and
[scram](github.com/xdg-go/scram)
