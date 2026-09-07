# Arquitectura

RAVENLOCK no usa servicios externos ni dependencias.

Componentes:

- baseline TSV local,
- canary files,
- scanner recursivo,
- comparador de drift,
- scoring local,
- reportes HTML/JSON.

Diseño:

```text
folders -> scanner -> current snapshot
baseline -> comparator -> findings -> reports
canaries -> priority alerts
```
