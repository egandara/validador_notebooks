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
                "Detalle": "El comando mágico '%sql' debe ser reemplazado por spark.sql()."
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

def validar_parametros_no_usados(celdas):
    """
    Valida que los parámetros de widgets declarados con .text() se usen con .get().
    """
    hallazgos = []
    codigo_completo = ""
    for celda in celdas:
        if celda.get('cell_type') == 'code':
            codigo_completo += "".join(celda.get('source', [])) + "\n"

    if not codigo_completo:
        return hallazgos

    # Extrae todos los parámetros declarados y usados
    regex_declaracion = re.compile(r'dbutils\.widgets\.text\s*\(\s*["\']([^"\']+)["\']')
    regex_uso = re.compile(r'dbutils\.widgets\.get\s*\(\s*["\']([^"\']+)["\']')
    
    declared_params = set(regex_declaracion.findall(codigo_completo))
    used_params = set(regex_uso.findall(codigo_completo))

    unused_params = declared_params - used_params

    # Si hay parámetros no usados, encuentra dónde se declararon
    if unused_params:
        for i, celda in enumerate(celdas):
            if celda.get('cell_type') == 'code':
                lineas = celda.get('source', [])
                for j, linea in enumerate(lineas, 1):
                    for param in unused_params:
                        # Comprueba si esta línea declara el parámetro no usado
                        if 'dbutils.widgets.text' in linea and (f'"{param}"' in linea or f"'{param}'" in linea):
                            hallazgos.append({
                                "Tipo": "Parámetro no usado",
                                "Celda": i + 1,
                                "Linea": j,
                                "Contenido": linea.strip(),
                                "Detalle": f"El parámetro de widget '{param}' se declara pero nunca se usa con dbutils.widgets.get()."
                            })
    return hallazgos

def validar_variables_widgets_no_usadas(celdas):
    """
    Valida que las variables creadas a partir de dbutils.widgets.get() se usen posteriormente.
    Ignora el uso en sentencias print() y spark.conf.set().
    """
    hallazgos = []
    
    # Regex para encontrar la asignación de variable desde un widget.get()
    regex_asignacion = re.compile(r'^\s*([\w\d_]+)\s*=\s*dbutils\.widgets\.get\s*\(')
    
    declaraciones = []
    codigo_completo_por_celda = {}

    # 1. Recolectar todas las declaraciones y todo el código
    for i, celda in enumerate(celdas):
        if celda.get('cell_type') == 'code':
            codigo_celda = "".join(celda.get('source', []))
            codigo_completo_por_celda[i] = codigo_celda
            lineas = codigo_celda.split('\n')
            for j, linea in enumerate(lineas, 1):
                match = regex_asignacion.search(linea)
                if match:
                    nombre_variable = match.group(1)
                    declaraciones.append({
                        "nombre": nombre_variable,
                        "celda_idx": i,
                        "linea_idx": j,
                        "contenido": linea.strip()
                    })

    # 2. Para cada declaración, buscar su uso en el resto del notebook
    for decl in declaraciones:
        variable_usada = False
        nombre_var = decl["nombre"]
        
        for i, codigo_celda in codigo_completo_por_celda.items():
            lineas = codigo_celda.split('\n')
            for j, linea in enumerate(lineas, 1):
                # Ignorar la línea de declaración original
                if i == decl["celda_idx"] and j == decl["linea_idx"]:
                    continue
                
                # Ignorar líneas que son solo un print o un spark.conf.set
                stripped_line = linea.strip()
                if stripped_line.startswith('print(') or stripped_line.startswith('spark.conf.set('):
                    continue

                # Buscar un uso válido de la variable (como palabra completa)
                if re.search(r'\b' + re.escape(nombre_var) + r'\b', linea):
                    variable_usada = True
                    break # Salir del bucle de líneas
            if variable_usada:
                break # Salir del bucle de celdas

        # 3. Si no se encontró uso, registrar el hallazgo
        if not variable_usada:
            hallazgos.append({
                "Tipo": "Variable de Widget no usada",
                "Celda": decl["celda_idx"] + 1,
                "Linea": decl["linea_idx"],
                "Contenido": decl["contenido"],
                "Detalle": f"La variable '{decl['nombre']}' se obtiene de un widget pero no se usa posteriormente (ignorando prints y spark.conf.set)."
            })
            
    return hallazgos

def validar_header_notebook(celdas, file_path):
    """
    Valida que la primera celda del notebook contenga el nombre del archivo.
    """
    hallazgos = []
    if not celdas:
        return hallazgos 

    nombre_base = os.path.splitext(os.path.basename(file_path))[0]
    primera_celda = celdas[0]
    contenido_primera_celda = "".join(primera_celda.get('source', []))

    if nombre_base not in contenido_primera_celda:
        hallazgos.append({
            "Tipo": "Header Incorrecto",
            "Celda": 1,
            "Detalle": f"La primera celda no contiene el nombre del archivo '{nombre_base}'."
        })
    return hallazgos

def validar_footer_notebook(celdas):
    """
    Valida la estructura del footer en un notebook .ipynb.
    """
    hallazgos = []
    indice_footer_markdown = -1
    
    for i, celda in enumerate(celdas):
        if celda.get('cell_type') == 'markdown':
            contenido = "".join(celda.get('source', []))
            if "Mensaje Final" in contenido:
                indice_footer_markdown = i
                break
    
    if indice_footer_markdown == -1:
        hallazgos.append({"Tipo": "Footer Faltante", "Detalle": "No se encontró la celda Markdown con 'Mensaje Final'."})
        return hallazgos

    indice_celda_exit = indice_footer_markdown + 1
    if indice_celda_exit >= len(celdas):
        hallazgos.append({"Tipo": "Footer Incorrecto", "Detalle": "Falta la celda de código con 'dbutils.notebook.exit' después del Mensaje Final."})
        return hallazgos

    celda_exit = celdas[indice_celda_exit]
    if celda_exit.get('cell_type') != 'code' or "dbutils.notebook.exit" not in "".join(celda_exit.get('source', [])):
        hallazgos.append({"Tipo": "Footer Incorrecto", "Detalle": "La celda siguiente al Mensaje Final no es una celda de código con 'dbutils.notebook.exit'."})
        return hallazgos

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
        hallazgos_notebook = (
            validar_header_notebook(celdas, file_path) +
            validar_footer_notebook(celdas) +
            validar_parametros_no_usados(celdas) +
            validar_variables_widgets_no_usadas(celdas)
        )
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
