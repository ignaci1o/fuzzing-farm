#!/usr/bin/env python3
"""
triaje_ia.py - Script de Triaje Automático de Vulnerabilidades con Gemini AI
Analiza reportes de crash de AddressSanitizer/libFuzzer/ClusterFuzzLite
y determina si se trata de un bug explotable o ruido.
"""

import os
import sys
import json
import urllib.request
import urllib.error

API_KEY = os.getenv("GEMINI_API_KEY")
MODEL = "gemini-3.5-flash"

SYSTEM_PROMPT = """Eres un experto auditor de seguridad en memoria (Vulnerability Researcher).
Tu tarea es analizar el volcado de error (stack trace de AddressSanitizer/libFuzzer/AFL++)
de un crash generado durante fuzzing.

Analiza el reporte y responde con este formato estricto:

══════════════════════════════════════════════════════════════
RESULTADO DEL TRIAJE: [🔴 INTERESANTE / VULNERABILIDAD REAL | 🟡 RUIDO / BENIGNO]
══════════════════════════════════════════════════════════════
• Tipo de fallo: (ej. Stack Buffer Overflow, Heap Use After Free, Out of Memory, Assert Fail)
• CWE asociado: (ej. CWE-121, CWE-416, CWE-787)
• Función y línea culpable: (nombre de la función y archivo:línea)
• Severidad: [Crítica | Alta | Media | Baja / Nula]
• Análisis de Explotabilidad: (Explica en 2-3 líneas por qué es alcanzable/peligroso o si es solo un assert inofensivo)
• Recomendación de mitigación: (Cómo arreglar la línea vulnerable)
══════════════════════════════════════════════════════════════
"""

def analizar_crash(crash_text: str):
    if not API_KEY:
        print("[!] Error: No se encontró la variable GEMINI_API_KEY.")
        sys.exit(1)

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent?key={API_KEY}"
    headers = {"Content-Type": "application/json"}
    
    prompt = f"Analiza este volcado de error de AddressSanitizer:\n\n```text\n{crash_text}\n```"
    
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": SYSTEM_PROMPT + "\n\n" + prompt}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2
        }
    }

    try:
        req = urllib.request.Request(url, headers=headers, data=json.dumps(payload).encode("utf-8"))
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except urllib.error.HTTPError as e:
        error_msg = e.read().decode()
        return f"[!] Error de API ({e.code}): {error_msg}"
    except Exception as e:
        return f"[!] Error de conexión: {str(e)}"

def main():
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if os.path.isfile(target):
            with open(target, "r", encoding="utf-8", errors="ignore") as f:
                crash_text = f.read()
        else:
            crash_text = target
    else:
        print("[*] Leyendo volcado de error desde entrada estándar (o pega el log y presiona Ctrl+D / Ctrl+Z):")
        crash_text = sys.stdin.read()

    if not crash_text.strip():
        print("[!] No se proporcionó texto de crash para analizar.")
        sys.exit(1)

    print("\n🔍 Analizando crash con Gemini AI (gemini-3.5-flash)... Espera unos segundos.\n")
    resultado = analizar_crash(crash_text)
    print(resultado)

if __name__ == "__main__":
    main()
