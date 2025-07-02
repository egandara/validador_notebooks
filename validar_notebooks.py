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
                "Detalle": "El comando '%sql' debe ser reemplazado por spark.sql() o eliminarlo."
            })
    return hallazgos

def validar_rutas_en_duro(codigo):
    """
    Valida que no existan rutas absolutas o relativas en duro en el código.
    Permite solo nombres de archivo sin ruta.
    """
    hallazgos = []
    # Regex para encontrar strings que contengan / o \.
    regex_rutas = re.compile(r'("|\').*(\/|\\).*("|\')')
    
    lineas = codigo.split('\n')
    for i, linea in enumerate(lineas, 1):
        if linea.strip().startswith('#'):
            continue

        # Usamos finditer para encontrar todas las posibles rutas en una línea
        for match in regex_rutas.finditer(linea):
            ruta_encontrada = match.group(0)
            
            # --- HEURÍSTICA PARA EVITAR FALSOS POSITIVOS ---
            # Si la cadena parece un JSON (contiene { y :), es probable que no sea una ruta.
            if '{' in ruta_encontrada and ':' in ruta_encontrada:
                continue

            # Excluimos URLs comunes para reducir falsos positivos
            if not re.search(r'https?:\/\/', ruta_encontrada):
                 hallazgos.append({
                     "Tipo": "Ruta en duro",
                     "Linea": i,
                     "Contenido": ruta_encontrada.strip(),
                     "Detalle": "Posible ruta en duro encontrada."
                 })
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

    for i, cell in enumerate(celdas):
        if cell.get('cell_type') == 'code':
            codigo = "".join(cell.get('source', []))
            
            # Recolectar hallazgos y agregar número de celda
            validaciones = validar_sql_magic(codigo) + validar_rutas_en_duro(codigo)
            for hallazgo in validaciones:
                hallazgo['Celda'] = i + 1
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
    parser.add_argument("--output-file", help="Archivo para guardar los hallazgos.", default=None)
    parser.add_argument("--output-format", help="Formato del archivo de salida.", choices=['txt', 'csv'], default='txt')
    
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

    # --- Recopilación de resultados ---
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

    # --- Impresión de resultados ---
    print("\n---\n📁 Archivos:")
    print("❌ Con problemas:")
    for fn, c in conteo_problemas_por_archivo.items():
        if c > 0:
            print(f"  ❌ {fn} ({c} problemas)")
    
    print("✅ Sin problemas:")
    for fn, c in conteo_problemas_por_archivo.items():
        if c == 0:
            print(f"  ✅ {fn}")

    # --- Impresión del resumen ---
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
        for t, c in tipos.items():
            print(f"    - {t}: {c}")

    # --- Guardado en archivo ---
    if args.output_file and total_problems > 0:
        try:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                if args.output_format == 'csv':
                    f.write("archivo,celda,linea,tipo_problema,contenido_del_problema,detalle\n")
                    for r in resultados_globales:
                        # Escapar comillas dobles en el contenido para formato CSV correcto
                        contenido = r.get("Contenido", "").replace('"', '""')
                        f.write(f'"{r.get("Archivo","")}",'
                                f'"{r.get("Celda","")}",'
                                f'"{r.get("Linea","")}",'
                                f'"{r.get("Tipo","")}",'
                                f'"{contenido}",'
                                f'"{r.get("Detalle","")}"\n')
                else: # txt
                    for r in resultados_globales:
                        f.write(f'Archivo: {r.get("Archivo","")} | Celda: {r.get("Celda","")} | Línea: {r.get("Linea","")} | Tipo: {r.get("Tipo","")} | Contenido: {r.get("Contenido","")}\n')
            print(f"\nResultados detallados guardados en: {args.output_file}")
        except Exception as e:
            print(f"\nError al guardar el archivo de salida: {e}")

if __name__ == "__main__":
    main()
