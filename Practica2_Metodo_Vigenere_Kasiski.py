# Algoritmo Vigenere
"""
Pasos que se van a seguir
1. Se generará una llave extendida para cumplir con la longitud del mensaje a cifrar o descifrar
2. Una vez que se tiene una llave extendida y la cadena se deberá de hacer un loop para recorrer ambos y generar el encriptado siguiendo la lógica de Cesar
"""

def generar_llave(mensaje,llave):
  """
    Función para generar una llave extendida, es decir, que la longitud de la llave sea la misma que del mensaje realizando un padding
  """

  # La llave es del mismo tamaño que el mensaje
  if len(mensaje) == len(llave):
    return llave
  else:
    # Repetir la llave hasta que su longitud sea igual a la del mensaje
    for i in range(len(mensaje) - len(llave)):
      llave += llave[i]
    return llave

def cifrar(mensaje,llave):
  """
    Función que realiza el cifrado utilizando el algoritmo de Vigenere. Para esto se utilizó la expresión:
      Cifrar: C_1 = (P_i + K_i) mod 26

    Nota: Se consideró el valor numérico de cada letra en ASCII para obtener la conversión de A -> 0, B -> 1, etc...
  """
  resultado = ""
  # Generar la llave extendida
  llave = generar_llave(mensaje, llave)

  # Recorrer cada carácter en el texto
  for i, char in enumerate(mensaje):
      # Verificar si es una letra mayúscula
      if char.isupper():
          # Desplazar y ajustar al rango de letras mayúsculas
          resultado += chr((ord(char) + (ord(llave[i]) - 65) - 65) % 26 + 65)
      # Verificar si es una letra minúscula
      elif char.islower():
          # Desplazar y ajustar al rango de letras minúsculas
          resultado += chr((ord(char) + (ord(llave[i]) - 97) - 97) % 26 + 97)

  return resultado



def descifrar(mensaje,llave):
  """
    Función que realiza el descifrado utilizando el algoritmo de Vigenere. Para esto se utilizó la expresión:
      descifrar: D_1 = (C_i - K_i) mod 26

    Nota: Se consideró el valor numérico de cada letra en ASCII para obtener la conversión de A -> 0, B -> 1, etc...
  """
  resultado = ""
  # Generar la llave extendida
  llave = generar_llave(mensaje, llave)

  # Recorrer cada carácter en el texto
  for i, char in enumerate(mensaje):
      # Verificar si es una letra mayúscula
      if char.isupper():
          # Desplazar y ajustar al rango de letras mayúsculas
          resultado += chr((ord(char) - (ord(llave[i]) - 65) - 65) % 26 + 65)
      # Verificar si es una letra minúscula
      elif char.islower():
          # Desplazar y ajustar al rango de letras minúsculas
          resultado += chr((ord(char) - (ord(llave[i]) - 97) - 97) % 26 + 97)

  return resultado

#Método Kasiski
"""
Pasos:
  1. Buscar repeticiones de caracteres en el mensaje.
  2. Calcular distancias entre cada ocurrencia o repetición de caracteres
  3. Encontrar el Máximo Común Divisor (MCD) de dichas distancias
  4. Determinar la longitud de la llave
"""
def analizar_repeticiones_kasiski(criptograma, min_longitud_secuencia=3):

    repeticiones_encontradas = {}
    longitud_criptograma = len(criptograma)

    # Iterar sobre todas las posibles longitudes de secuencia
    for longitud_actual in range(min_longitud_secuencia, longitud_criptograma // 2 + 1):
        for i in range(longitud_criptograma - longitud_actual + 1):
            secuencia = criptograma[i : i + longitud_actual]

            # Buscar esta secuencia en el resto del criptograma
            # Empezamos la búsqueda desde la posición i + 1 para encontrar ocurrencias posteriores
            for j in range(i + 1, longitud_criptograma - longitud_actual + 1):
                if criptograma[j : j + longitud_actual] == secuencia:
                    # Si la secuencia ya está en el diccionario, añadir la nueva posición
                    if secuencia in repeticiones_encontradas:
                        if i not in repeticiones_encontradas[secuencia]: # Evitar añadir la misma posición
                            repeticiones_encontradas[secuencia].append(i)
                        if j not in repeticiones_encontradas[secuencia]:
                            repeticiones_encontradas[secuencia].append(j)
                    else:
                        # Si es la primera vez que encontramos esta repetición
                        repeticiones_encontradas[secuencia] = [i, j]

    # Filtrar solo las secuencias que realmente se repiten (tienen más de una posición)
    # y ordenar las posiciones para facilitar el cálculo de distancias
    repeticiones_filtradas = {}
    for seq, positions in repeticiones_encontradas.items():
        if len(positions) > 1:
            repeticiones_filtradas[seq] = sorted(list(set(positions))) # Eliminar duplicados y ordenar

    return repeticiones_filtradas

def calcular_distancias_y_mcd(repeticiones):

    from math import gcd # Importar la función MCD

    resultados_kasiski = {}
    todas_las_distancias = []

    for seq, positions in repeticiones.items():
        distancias_seq = []
        for i in range(1, len(positions)):
            dist = positions[i] - positions[i-1]
            distancias_seq.append(dist)
            todas_las_distancias.append(dist)

        resultados_kasiski[seq] = {
            "posiciones": positions,
            "distancias": distancias_seq
        }

    # Calcular el MCD de todas las distancias encontradas
    mcd_total = 0
    if todas_las_distancias:
        mcd_total = todas_las_distancias[0]
        for dist in todas_las_distancias[1:]:
            mcd_total = gcd(mcd_total, dist)

    return resultados_kasiski, mcd_total

def kasiski():
  criptograma = input("Ingresa el criptograma para aplicar el método Kasiski: ")
  reps = analizar_repeticiones_kasiski(criptograma)

  if reps:
    print("\nSecuencias repetidas encontradas:")
    for seq, positions in reps.items():
        print(f"- '{seq}' en posiciones: {positions}")

    resultados, mcd = calcular_distancias_y_mcd(reps)

    print("\nAnálisis de distancias y MCD:")

    for seq, data in resultados.items():
        print(f"  Secuencia '{seq}':")
        print(f"    Posiciones: {data['posiciones']}")
        print(f"    Distancias: {data['distancias']}")

    if mcd > 0:
        print(f"\nEl Máximo Común Divisor (MCD) de todas las distancias es: {mcd}")
        print(f"Posibles longitudes de clave (factores del MCD):")
        factores = [i for i in range(1, mcd + 1) if mcd % i == 0]
        print(f"  {factores}")
    else:
        print("\nNo se pudo calcular un MCD (quizás no hay distancias válidas).")
  else:
      print("No se encontraron secuencias repetidas de 3 o más caracteres.")


# Menú de selección de opciones
if __name__ == "__main__":
    while True:
        print("\n--- Algoritmo Vigenere ---")
        print("1. Cifrar mensaje")
        print("2. Descifrar mensaje")
        print("3. Método de Kasiski")
        print("4. Salir")
        opcion = input("Selecciona una opción (1/2/3/4): ")

        if opcion == "1":
            mensaje = input("Ingresa el mensaje a cifrar: ")
            llave = input("Ingresa la llave: ")
            mensaje_cifrado = cifrar(mensaje, llave)
            print(f"Mensaje cifrado: {mensaje_cifrado}")
        elif opcion == "2":
            mensaje = input("Ingresa el mensaje a descifrar: ")
            llave = input("Ingresa la llave: ")
            mensaje_descifrado = descifrar(mensaje, llave)
            print(f"Mensaje descifrado: {mensaje_descifrado}")
        elif opcion == "3":
            kasiski()
        elif opcion == "4":
            print("Saliendo...")
            break
        else:
            print("Opción no válida. Intenta de nuevo.")

