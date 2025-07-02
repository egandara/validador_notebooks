#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
sys.stdout.reconfigure(encoding='utf-8')

import json
import os
import argparse
import re

def validar_sql_magic(codigo):
    """
    Valida la presencia del comando mágico %sql en el código.
    """
    hallazgos = []
    lineas = codigo.split('\n')
    for i, linea in enumerate(lineas, 1):
        if linea.strip().startswith('%sql'):
            hallazgos.append({
                "Tipo": "Uso de %sql",
                "Linea": i,
                "Contenido": linea.strip(),
                "Detalle": "El comando '%sql' debe ser reemplazado por spark.sql() o quitado."
            })
    return hallazgos

def validar_rutas_en_duro(codigo):
    """
    Valida que no existan rutas absolutas o relativas en duro en el código.
    """
    hallazgos = []
    regex_rutas = re.compile(r'("|\').*(\/|\\).*("|\')')
    
    lineas = codigo.split('\n')
    for i, linea in enumerate(lineas, 1):
        if linea.strip().startswith('#'):
            continue
        for match in regex_rutas.finditer(linea):
            ruta_encontrada = match.group(0)
            if '{' in ruta_encontrada and ':' in ruta_encontrada:
                continue
            if not re.search(r'https?:\/\/', ruta_encontrada):
                 hallazgos.append({
                     "Tipo": "Ruta en duro",
                     "Linea": i,
                     "Contenido": ruta_encontrada.strip(),
                     "Detalle": "Posible ruta en duro encontrada."
                 })
    return hallazgos

def validar_footer_notebook(celdas):
    """
    Valida la estructura del footer en un notebook .ipynb.
    """
    hallazgos = []
    indice_footer_markdown = -1
    
    # 1. Encontrar la celda "Mensaje Final"
    for i, celda in enumerate(celdas):
        if celda.get('cell_type') == 'markdown':
            contenido = "".join(celda.get('source', []))
            if "Mensaje Final" in contenido:
                indice_footer_markdown = i
                break
    
    if indice_footer_markdown == -1:
        hallazgos.append({"Tipo": "Footer Faltante", "Detalle": "No se encontró la celda Markdown con 'Mensaje Final'."})
        return hallazgos

    # 2. Validar la celda de exit
    indice_celda_exit = indice_footer_markdown + 1
    if indice_celda_exit >= len(celdas):
        hallazgos.append({"Tipo": "Footer Incorrecto", "Detalle": "Falta la celda de código con 'dbutils.notebook.exit' después del Mensaje Final."})
        return hallazgos

    celda_exit = celdas[indice_celda_exit]
    if celda_exit.get('cell_type') != 'code' or "dbutils.notebook.exit" not in "".join(celda_exit.get('source', [])):
        hallazgos.append({"Tipo": "Footer Incorrecto", "Detalle": "La celda siguiente al Mensaje Final no es una celda de código con 'dbutils.notebook.exit'."})
        return hallazgos

    # 3. Validar que no haya celdas posteriores
    if len(celdas) > (indice_celda_exit + 1):
        hallazgos.append({"Tipo": "Código posterior al final", "Detalle": f"Se encontró código o celdas después de la celda final en la celda número {indice_celda_exit + 2}."})

    return hallazgos

def analizar_notebook(file_path):
    """
    Analiza un único archivo de notebook y devuelve una lista de diccionarios de problemas.
    """
    hallazgos_totales = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            if file_path.endswith(('.ipynb', '.json')):
                notebook = json.load(f)
                celdas = notebook.get('cells', [])
            elif file_path.endswith('.py'):
                celdas = [{'cell_type': 'code', 'source': f.readlines()}]
            else:
                return [{"Tipo": "Error de Archivo", "Detalle": "Formato no soportado."}]
    except Exception as e:
        return [{"Tipo": "Error de Lectura", "Detalle": f"Error al leer o parsear el archivo: {e}"}]

    # --- Validaciones a nivel de celda ---
    for i, cell in enumerate(celdas):
        if cell.get('cell_type') == 'code':
            codigo = "".join(cell.get('source', []))
            validaciones = (
                validar_sql_magic(codigo) + 
                validar_rutas_en_duro(codigo)
            )
            for hallazgo in validaciones:
                hallazgo['Celda'] = i + 1
                hallazgos_totales.append(hallazgo)

    # --- Validaciones a nivel de notebook (.ipynb) ---
    if file_path.endswith('.ipynb'):
        hallazgos_notebook = validar_footer_notebook(celdas)
        for hallazgo in hallazgos_notebook:
            hallazgos_totales.append(hallazgo)

    return hallazgos_totales

def main():
    """
    Función principal para ejecutar el script.
    """
    parser = argparse.ArgumentParser(
        description="Valida notebooks de Databricks (.py, .ipynb, .json) en busca de malas prácticas.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("ruta", help="Ruta al archivo o directorio de notebooks a validar.")
    
    args = parser.parse_args()
    ruta_base = args.ruta
    archivos_a_validar = []

    if os.path.isfile(ruta_base):
        archivos_a_validar.append(ruta_base)
    elif os.path.isdir(ruta_base):
        for root, _, files in os.walk(ruta_base):
            for file in files:
                if file.endswith(('.py', '.ipynb', '.json')):
                    archivos_a_validar.append(os.path.join(root, file))
    else:
        print(f"Error: La ruta '{ruta_base}' no es un archivo o directorio válido.")
        sys.exit(1)

    if not archivos_a_validar:
        print("No se encontraron archivos de notebook para validar.")
        sys.exit(0)

    resultados_globales = []
    conteo_problemas_por_archivo = {}

    print("---")
    print(f"Analizando {len(archivos_a_validar)} archivos...")
    
    for file_path in archivos_a_validar:
        fn = os.path.basename(file_path)
        problemas = analizar_notebook(file_path)
        conteo_problemas_por_archivo[fn] = len(problemas)
        for p in problemas:
            p['Archivo'] = fn
            resultados_globales.append(p)

    print("\n---\n📁 Archivos:")
    print("❌ Con problemas:")
    for fn, c in sorted(conteo_problemas_por_archivo.items()):
        if c > 0:
            print(f"  ❌ {fn} ({c} problemas)")
    
    print("✅ Sin problemas:")
    for fn, c in sorted(conteo_problemas_por_archivo.items()):
        if c == 0:
            print(f"  ✅ {fn}")

    total_files = len(archivos_a_validar)
    total_problems = len(resultados_globales)
    print("\n---\n📊 Resumen:")
    print(f"  • Archivos escaneados: {total_files}")
    print(f"  • Problemas detectados: {total_problems}")
    
    if total_problems > 0:
        print("  • Desglose por tipo:")
        tipos = {}
        for r in resultados_globales:
            tipo = r.get("Tipo", "Desconocido")
            tipos[tipo] = tipos.get(tipo, 0) + 1
        for t, c in sorted(tipos.items()):
            print(f"    - {t}: {c}")

        # --- Guardado automático en archivo CSV ---
        output_filename = "hallazgos_validacion.csv"
        try:
            with open(output_filename, 'w', encoding='utf-8-sig') as f:
                f.write("archivo,celda,línea,tipo_problema,contenido_del_problema,detalle\n")
                for r in resultados_globales:
                    contenido = r.get("Contenido", "").replace('"', '""')
                    f.write(f'"{r.get("Archivo","N/A")}",'
                            f'"{r.get("Celda","N/A")}",'
                            f'"{r.get("Linea","N/A")}",'
                            f'"{r.get("Tipo","N/A")}",'
                            f'"{contenido}",'
                            f'"{r.get("Detalle","")}"\n')
            print(f"\nResultados detallados guardados en: {output_filename}")
        except Exception as e:
            print(f"\nError al guardar el archivo de salida: {e}")

if __name__ == "__main__":
    main()
