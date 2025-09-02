import os
import random

def generar_llave_aleatoria(longitud):
    """
    Genera una llave aleatoria del mismo tamaño que el mensaje, solo letras mayúsculas
    """
    return ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(longitud))

def codificar_binario(texto):
    resultado = []
    for char in texto:
        binario = bin(ord(char.upper()) - ord('A'))[2:].zfill(5)
        for bit in binario:
            resultado.append(int(bit))
    return resultado

def cifrado_vernam(mensaje, llave):

    # Verificar que la llave tenga la misma longitud que el mensaje
    if len(llave) != len(mensaje):
        print("La llave debe tener la misma longitud que el mensaje")
        return None

    mensaje_binario = codificar_binario(mensaje)
    llave_binario = codificar_binario(llave)

    # Guardar la llave en archivo (como cadena de 1s y 0s)
    with open('llave_vernam.txt', 'w') as archivo:
        archivo.write("".join(map(str, llave_binario)))

    bits = []
    for i in range(len(mensaje_binario)):
        # Operación XOR
        bits.append((mensaje_binario[i] + llave_binario[i]) % 2)

    cifrado = ""
    mensaje_cifrado_binario = ""
    for i in range(0, len(bits), 5):
        binario = bits[i : i + 5]
        cadena_binaria = "".join(map(str, binario))
        mensaje_cifrado_binario += cadena_binaria
        cifrado += (chr(int(cadena_binaria, 2) % 26 + 65))

    # Guardar mensaje cifrado en archivo
    with open('mensaje_cifrado.txt', 'w') as archivo:
        archivo.write(mensaje_cifrado_binario)

    print(f"Llave guardada con exito en: {os.getcwd()}/llave_vernam.txt")
    print(f"Mensaje cifrado guardado con exito en: {os.getcwd()}/mensaje_cifrado.txt")

    return cifrado

def descifrado_vernam():
    try:
        # Verificar que existan los archivos
        if not os.path.exists('llave_vernam.txt') or not os.path.exists('mensaje_cifrado.txt'):
            print("No se encontraron los archivos de llave y mensaje cifrado. Intenta Nuevamente")
            return None

        # Leer llave del archivo
        with open('llave_vernam.txt', 'r') as archivo:
            llave_bin_str = archivo.read().strip()
            llave_binario = [int(bit) for bit in llave_bin_str]

        # Leer mensaje cifrado del archivo
        with open('mensaje_cifrado.txt', 'r') as archivo:
            mensaje_cifrado_str = archivo.read().strip()
            mensaje_cifrado_bin = [int(bit) for bit in mensaje_cifrado_str]


        bits_descifrado = []
        for i in range(len(mensaje_cifrado_bin)):
            # Operación XOR
            bits_descifrado.append((mensaje_cifrado_bin[i] + llave_binario[i]) % 2)

        mensaje_descifrado = ""
        for i in range(0, len(bits_descifrado), 5):
            if i + 5 <= len(bits_descifrado):
                binario = bits_descifrado[i : i + 5]
                cadena_binaria = "".join(map(str, binario))
                mensaje_descifrado += chr(int(cadena_binaria, 2) % 26 + 65)


        # Eliminar archivos
        os.remove('llave_vernam.txt')
        os.remove('mensaje_cifrado.txt')

        print("Archivos de llave y mensaje cifrado eliminados exitosamente")

        return mensaje_descifrado

    except FileNotFoundError:
        print("No se encontraron los archivos necesarios para el descifrado")
        return None
    except Exception as e:
        print(f"Error durante el descifrado: {e}")
        return None

if __name__ == "__main__":
    while True:
        print(" --- ALGORITMO VERNAM ---")
        print("1. Cifrar mensaje")
        print("2. Descifrar mensaje")
        print("3. Salir")
        opcion = input("Selecciona una opción (1/2/3): ")

        if opcion == "1":
            print("\n--- CIFRAR MENSAJE ---")
            mensaje = input("Ingresa el mensaje a cifrar (solo letras A-Z): ").upper()

              # Generar llave automáticamente del mismo tamaño
            llave = generar_llave_aleatoria(len(mensaje))
            print(f"Llave generada automáticamente: {llave}")

            mensaje_cifrado = cifrado_vernam(mensaje, llave)
            if mensaje_cifrado:
                print(f"Mensaje cifrado: {mensaje_cifrado}")

        elif opcion == "2":
            print("\n--- DESCIFRAR MENSAJE ---")
            print("Leyendo llave y mensaje cifrado desde archivos...")

            mensaje_descifrado = descifrado_vernam()
            if mensaje_descifrado:
                print(f"Mensaje descifrado: {mensaje_descifrado}")

        elif opcion == "3":
            # Limpiar archivos residuales antes de salir
            if os.path.exists('llave_vernam.txt'):
                os.remove('llave_vernam.txt')
            if os.path.exists('mensaje_cifrado.txt'):
                os.remove('mensaje_cifrado.txt')
            print("Saliendo... Archivos temporales eliminados.")
            break

        else:
            print("Opción no válida. Intenta de nuevo.")
