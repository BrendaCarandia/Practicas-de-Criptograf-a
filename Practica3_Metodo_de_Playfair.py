
def generar_matriz_playfair(llave):
    """
    Genera una matriz de 5x5 para el cifrado Playfair a partir de la llave.
    """
    alfabeto = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 'J' se combina con 'I'
    matriz = []
    llave = llave.upper()

    # Se llenan los primeros elementos de la matriz con caracteres únicos de la cadena
    # Se rellena por fila
    for char in llave:
        if char in alfabeto and char not in matriz:
            matriz.append(char)

    # Posteriormente se llena con los demás caracteres del abecedario
    for char in alfabeto:
        if char not in matriz:
            matriz.append(char)

    # Se retorna una matriz 5x5
    return [matriz[i:i + 5] for i in range(0, 25, 5)]

def generar_bloques_playfair(mensaje):
    """
    Genera bloques de 2 caracteres para el cifrado Playfair.
    Si el mensaje tiene un número impar de caracteres, se agrega una 'X' al final.
    """
    mensaje = mensaje.upper().replace("J", "I")  # 'J' se combina con 'I'
    mensaje = mensaje.replace(" ", "")  # Eliminar espacios
    bloques = []
    i = 0

    # Se recorre cada uno de los caracteres del mensaje para generar bloques
    while i < len(mensaje):
        # Si aun hay caracteres disponibles para generar un par, se genera un bloque con los dos caracteres
        if i + 1 < len(mensaje):
            bloques.append(mensaje[i] + mensaje[i + 1])
            i += 2
        else:
            # En otro caso se deberá de agregar un padding con la letra X
            bloques.append(mensaje[i] + 'X') # En nuestro caso estamos considerando el padding con X
            i += 1

    return bloques


def cifrar(mensaje, llave):
    """
    Cifra los bloques utilizando la matriz Playfair.
    """
    resultado = ""
    bloques = generar_bloques_playfair(mensaje)
    matriz = generar_matriz_playfair(llave)

    # Con base en estos elementos, los bloques y la matriz, deberemos de ir cifrando por bloques siguiendo
    # las reglas del algoritmo. Para esto se fácil identificar la posición de cada uno de los caracteres del bloque
    # en la matriz


    # Se analzia cada uno de los bloques obtenidos
    for bloque in bloques:
      pos_primer_caracter = []
      pos_segundo_caracter = []

      # En este primer loop lo que se busca es obtener las coordenadas de los caracteres del bloque en la matriz playfair
      # Esto será de utilidad para poder analizar las reglas y obtener el mensaje cifrado
      for i in range(0,5):
        for j in range(0,5):
          if matriz[i][j] == bloque[0]:
            pos_primer_caracter = [i,j]

          if matriz[i][j] == bloque[1]:
            pos_segundo_caracter = [i,j]

      # Primer caso, los caracteres están en la misma columna o son el mismo caracter
      if pos_primer_caracter[1] == pos_segundo_caracter[1]:
        # Se deberá de agregar el caracter que se encuentra en la fila inferior dentro de la misma columna
        resultado += matriz[(pos_primer_caracter[0] + 1) % 5][pos_primer_caracter[1]]
        resultado += matriz[(pos_segundo_caracter[0] + 1) % 5][pos_segundo_caracter[1]]
      # Segundo caso, los caracteres están en la misma fila
      elif pos_primer_caracter[0] == pos_segundo_caracter[0]:
        resultado += matriz[pos_primer_caracter[0]][(pos_primer_caracter[1] + 1) % 5]
        resultado += matriz[pos_segundo_caracter[0]][(pos_segundo_caracter[1] + 1) % 5]
        # Se deberá de realizar una rotación a la derecha
      # Tercer caso, los caracteres están en filas y columnas diferentes
      else:
        resultado += matriz[pos_segundo_caracter[0]][pos_primer_caracter[1]]
        resultado += matriz[pos_primer_caracter[0]][pos_segundo_caracter[1]]
        # Se deberá de realizar un "recuadro" y cada uno tendrá que tomar el valor de la esquina opuesta verticalmente


    return resultado

def descifrar(mensaje, llave):
    """
    Descifra los bloques utilizando la matriz Playfair.
    """
    resultado = ""
    bloques = generar_bloques_playfair(mensaje)
    matriz = generar_matriz_playfair(llave)

    # Con base en estos elementos, los bloques y la matriz, deberemos de ir cifrando por bloques siguiendo
    # las reglas del algoritmo. Para esto es fácil identificar la posición de cada uno de los caracteres del bloque
    # en la matriz

    for bloque in bloques:
      pos_primer_caracter = []
      pos_segundo_caracter = []
      for i in range(0,5):
        for j in range(0,5):
          if matriz[i][j] == bloque[0]:
            pos_primer_caracter = [i,j]

          if matriz[i][j] == bloque[1]:
            pos_segundo_caracter = [i,j]

      # Primer caso, los caracteres están en la misma columna o son el mismo caracter
      if pos_primer_caracter[1] == pos_segundo_caracter[1]:
        # Se deberá de agregar el caracter que se encuentra en la fila superior dentro de la misma columna
        if pos_primer_caracter[0] == 0:
          resultado += matriz[4][pos_primer_caracter[1]]
        else:
          resultado += matriz[pos_primer_caracter[0] - 1][pos_primer_caracter[1]]

        if pos_segundo_caracter[0] == 0:
          resultado += matriz[4][pos_segundo_caracter[1]]
        else:
          resultado += matriz[pos_segundo_caracter[0] - 1][pos_segundo_caracter[1]]

      # Segundo caso, los caracteres están en la misma fila, por ende, se moveran a la izquierda
      elif pos_primer_caracter[0] == pos_segundo_caracter[0]:
        if pos_primer_caracter[1] == 0:
          resultado += matriz[pos_primer_caracter[0]][4]
        else:
          resultado += matriz[pos_primer_caracter[0]][pos_primer_caracter[1] - 1]

        if pos_segundo_caracter[1] == 0:
          resultado += matriz[pos_segundo_caracter[0]][4]
        else:
          resultado += matriz[pos_segundo_caracter[0]][pos_segundo_caracter[1] - 1]
        # Se deberá de realizar una rotación a la derecha
      # Tercer caso, los caracteres están en filas y columnas diferentes
      else:
        resultado += matriz[pos_segundo_caracter[0]][pos_primer_caracter[1]]
        resultado += matriz[pos_primer_caracter[0]][pos_segundo_caracter[1]]
        # Se deberá de realizar un "recuadro" y cada uno tendrá que tomar el valor de la esquina opuesta verticalmente
        pass

    return resultado

if __name__ == "__main__":
    while True:
        print("\n--- Algoritmo Playfair ---")
        print("1. Cifrar mensaje")
        print("2. Descifrar mensaje")
        print("3. Salir")
        opcion = input("Selecciona una opción (1/2/3): ")

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
            print("Saliendo...")
            break
        else:
            print("Opción no válida. Intenta de nuevo.")
