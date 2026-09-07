# RAVENLOCK

<img width="1448" height="1086" alt="raven" src="https://github.com/user-attachments/assets/5a801d77-a42c-480c-a2ae-a6fda12d43a5" />


**RAVENLOCK** es un centinela local de integridad para carpetas personales.  
Crea una línea base de archivos, coloca canarios defensivos y detecta alteraciones masivas, borrados, modificaciones, extensiones sospechosas y cambios sobre archivos canario.

Creado por **xtr4ng3**.

---

## Propósito

El daño real en una PC personal suele verse tarde: archivos renombrados, documentos alterados, extensiones desconocidas, carpetas modificadas en masa o archivos críticos desaparecidos.

RAVENLOCK está diseñado para observar ese cambio desde una perspectiva defensiva y local.  
No intenta ser antivirus, no promete detener amenazas por sí solo y no modifica archivos del usuario. Su valor está en crear una referencia confiable del estado de carpetas importantes y detectar desviaciones que merecen atención inmediata.

---

## Cómo funciona

RAVENLOCK trabaja con tres ideas:

1. **Baseline**  
   Guarda una línea base local de archivos, tamaños, fechas y huellas ligeras.

2. **Canary files**  
   Coloca archivos canario en las carpetas protegidas. Si un canario desaparece o cambia, la alerta sube de prioridad.

3. **Drift analysis**  
   Compara el estado actual contra la línea base y mide altas, bajas, modificaciones y extensiones sospechosas.

Todo queda local.

---

## Funciones

- línea base local,
- archivos canario,
- escaneo de carpetas,
- modo vigilancia por intervalos,
- detección de cambios masivos,
- detección de borrados,
- detección de modificaciones,
- detección de extensiones asociadas a eventos de cifrado o bloqueo,
- score de riesgo,
- reportes HTML,
- reportes JSON,
- estado local del baseline.

---

## Comandos

Crear baseline:

```bash
ravenlock init
```

Escanear:

```bash
ravenlock scan
```

Vigilar cada 60 segundos:

```bash
ravenlock watch --seconds 60
```

Ver estado:

```bash
ravenlock status
```

Usar carpetas específicas:

```bash
ravenlock init C:\Users\User\Documents C:\Users\User\Desktop
ravenlock scan C:\Users\User\Documents C:\Users\User\Desktop
```

---

## Carpetas por defecto

Si no se indican carpetas, RAVENLOCK intenta proteger carpetas comunes del usuario:

- Desktop / Escritorio
- Documents / Documentos
- Downloads / Descargas

---

## Reportes

Los reportes se guardan en:

```text
reports/
```

El estado local se guarda en:

```text
.ravenlock/
```

---

## Lo que RAVENLOCK no hace

RAVENLOCK no:

- elimina archivos,
- cifra archivos,
- restaura archivos,
- sube datos a internet,
- desactiva procesos,
- reemplaza antivirus,
- reemplaza backups.

Un hallazgo alto significa: **detenerse, revisar y proteger copias sanas**.

---

## Compilar

Requiere Rust.

```bash
cargo build --release
```

El binario queda en:

```text
target/release/ravenlock
```

En Windows:

```text
target\release\ravenlock.exe
```

---
# Licencia

<img width="300" height="159" alt="giphy (25)" src="https://github.com/user-attachments/assets/021720ff-3aec-4916-9a93-25d47afd7d97" />

**xtr4ng3**

MIT.

