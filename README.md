# Laboratorio 2: fuerza bruta en DVWA

Este repositorio reúne el informe, las capturas y el script del laboratorio. El script prueba combinaciones de los diccionarios incluidos contra una instancia **local** de DVWA configurada con seguridad **Low**. Úsalo únicamente en ese entorno de práctica.

## Requisitos

- Docker con Docker Compose
- Python 3 y el paquete `requests`
- Navegador para iniciar sesión en DVWA

## Preparar DVWA

Desde la raíz del repositorio:

```bash
docker compose up -d
```

Abre <http://127.0.0.1:4280>. Si es la primera vez, entra a **Create / Reset Database** y crea la base de datos. Inicia sesión con las credenciales iniciales de DVWA (`admin` / `password`), abre **DVWA Security** y selecciona **Low**. Mantén abierta esa sesión.

El puerto `4280` de `compose.yml` está enlazado a `127.0.0.1`, de modo que el laboratorio se ejecuta en tu propio equipo.

## Ejecutar el script

Instala la dependencia en un entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install requests
```

Busca la cookie `PHPSESSID` de la sesión abierta en las herramientas de desarrollo del navegador (Almacenamiento/Cookies para `127.0.0.1`). En la misma terminal:

```bash
read -rsp 'PHPSESSID de DVWA: ' DVWA_SESSION
echo
export DVWA_SESSION
python fuerza_bruta.py
unset DVWA_SESSION
```

El script usa `usuarios-reducidos.txt` y `contrasenas-reducidas.txt`, ambos incluidos aquí. Ejecuta primero un intento de control que debe fallar. Después recorre todas las combinaciones y escribe `intentos.csv`, `resumen.json` y las respuestas HTML en una carpeta nueva bajo `evidencias/python/`. La cookie no se guarda en el código ni en el repositorio.

Para detener el entorno al terminar:

```bash
docker compose down
```

## Material del informe

- [`Lab2_Criptoo.pdf`](Lab2_Criptoo.pdf): informe completo en PDF.
- [`Imagenes/`](Imagenes/): capturas citadas por el informe.
- [`fuerza_bruta.py`](fuerza_bruta.py): script reproducible.
- [`compose.yml`](compose.yml): DVWA y MariaDB para la práctica local.
- [`evidencias/trafico-dvwa-4280.pcapng`](evidencias/trafico-dvwa-4280.pcapng): tráfico TCP capturado en el puerto local 4280 de DVWA; se puede abrir con Wireshark.

La captura publicada conserva los 132.422 paquetes del puerto 4280 (62 MB). Se extrajo del archivo original de 704 MB, que también contenía tráfico ajeno a DVWA y supera el límite de tamaño de un archivo Git convencional.
