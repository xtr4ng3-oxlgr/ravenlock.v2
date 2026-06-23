# Arquitectura

RAVENLOCK v2 trabaja con una arquitectura local:

```text
folders
  -> scanner
  -> current snapshot
  -> comparator
  -> findings
  -> reports
```

Componentes:

- `ravenlock.toml`: configuración local.
- `baseline.tsv`: línea base.
- `baseline.seal`: sello local de baseline + canarios.
- `canaries.tsv`: índice de archivos canario.
- `reports/`: salida HTML, JSON y SARIF.

El sello local no pretende reemplazar criptografía fuerte. Sirve como control defensivo para detectar cambios accidentales o manipulación básica del estado de RAVENLOCK.
