# RAVENLOCK v2

<img width="1448" height="1086" alt="rav2" src="https://github.com/user-attachments/assets/f65c6d9c-c5f6-4a50-abd3-37cf7418e32e" />


**RAVENLOCK** es un centinela local de integridad para carpetas personales.  
Crea una línea base de archivos, coloca canarios defensivos, verifica un sello local de baseline y detecta modificaciones masivas, borrados, extensiones sospechosas y cambios sobre archivos canario.

Creado por **xtr4ng3**.

---

## Propósito

RAVENLOCK está diseñado para detectar desviaciones fuertes en carpetas personales antes de que el daño pase desapercibido.

No es antivirus.  
No reemplaza copias de seguridad.  
No elimina ni restaura archivos.  
Su función es vigilar integridad local, generar señales claras y documentar el estado de la máquina.

---

## Cambios de v2

- modo TUI vivo en terminal,
- archivo de configuración local,
- baseline con sello local,
- canarios por carpeta protegida,
- reportes HTML, JSON y SARIF,
- comando `refresh`,
- exclusiones configurables,
- huella ligera de archivos,
- score de riesgo,
- salida más profesional en terminal.

---

## Comandos

Crear configuración si no existe:

```bash
ravenlock config
```

Crear baseline:

```bash
ravenlock init
```

Escanear:

```bash
ravenlock scan
```

Modo TUI vivo:

```bash
ravenlock tui --seconds 5
```

Modo vigilancia clásico:

```bash
ravenlock watch --seconds 60
```

Actualizar baseline después de cambios intencionales:

```bash
ravenlock refresh
```

Ver estado:

```bash
ravenlock status
```

Usar carpetas concretas:

```bash
ravenlock init C:\Users\User\Documents C:\Users\User\Desktop
ravenlock scan C:\Users\User\Documents C:\Users\User\Desktop
```

---

## Estructura local

RAVENLOCK crea:

```text
.ravenlock/
├─ ravenlock.toml
├─ baseline.tsv
├─ baseline.seal
└─ canaries.tsv

reports/
├─ ravenlock_v2_report_<timestamp>.html
├─ ravenlock_v2_report_<timestamp>.json
└─ ravenlock_v2_report_<timestamp>.sarif
```

---

## Configuración

Ejemplo de `.ravenlock/ravenlock.toml`:

```toml
interval_seconds = 60
max_file_mb = 128

root = "C:\Users\User\Documents"
root = "C:\Users\User\Desktop"
root = "C:\Users\User\Downloads"

exclude = "\node_modules"
exclude = "\.git"
exclude = "\target"
```

---

## Interpretación

Un score alto puede aparecer por:

- canarios modificados,
- canarios eliminados,
- baseline alterada,
- muchos archivos modificados,
- muchos archivos borrados,
- extensiones sospechosas,
- creación masiva de archivos.

Un hallazgo alto significa: **detenerse, revisar y proteger copias sanas**.

---

## Compilar

Requiere Rust.

```bash
cargo build --release
```

En Windows:

```bat
build_windows\BUILD_RELEASE.bat
```

---
# Licencia

<img width="300" height="159" alt="giphy (25)" src="https://github.com/user-attachments/assets/021720ff-3aec-4916-9a93-25d47afd7d97" />

**xtr4ng3**

MIT.

