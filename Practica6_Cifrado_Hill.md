# Práctica 6 Cifrado de Hill en Python

### 1. Matriz Inversa
Código que calcula paso a paso, sin usar librerías, la matriz inversa de una matriz nxn

```bash
def get_submatrix(matrix, exclude_row, exclude_col):
    """
    Retorna una submatriz excluyendo una fila y una columna específicas.
    Esencial para calcular menores y cofactores.
    """
    return [
        [matrix[r][c] for c in range(len(matrix[0])) if c != exclude_col]
        for r in range(len(matrix)) if r != exclude_row
    ]

def determinant(matrix):
    """
    Calcula el determinante de una matriz cuadrada usando la expansión por cofactores.
    Esta función es recursiva.
    """
    n = len(matrix)

    if n == 1:
        return matrix[0][0]
    elif n == 2:
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]

    det_val = 0
    # Expansión por cofactores a lo largo de la primera fila
    for c in range(n):
        sub_matrix = get_submatrix(matrix, 0, c)
        cofactor_term = ((-1)**(0 + c)) * determinant(sub_matrix)
        det_val += matrix[0][c] * cofactor_term
    return det_val

def transpose_matrix(matrix):
    """
    Calcula la transpuesta de una matriz (intercambia filas por columnas).
    """
    rows = len(matrix)
    cols = len(matrix[0])
    transposed = [[0 for _ in range(rows)] for _ in range(cols)]
    for i in range(rows):
        for j in range(cols):
            transposed[j][i] = matrix[i][j]
    return transposed

def inverse_matrix(matrix):
    """
    Calcula la inversa de una matriz cuadrada de cualquier tamaño (N x N).
    """
    n = len(matrix)
    if not all(len(row) == n for row in matrix):
        raise ValueError("La matriz debe ser cuadrada.")

    det = determinant(matrix)
    if det == 0:
        raise ValueError("La matriz es singular (determinante es 0) y no tiene inversa.")

    # 1. Calcular la matriz de cofactores
    cofactors_matrix = [[0] * n for _ in range(n)]
    for r in range(n):
        for c in range(n):
            sub_matrix = get_submatrix(matrix, r, c)
            minor_det = determinant(sub_matrix)
            cofactor = ((-1)**(r + c)) * minor_det
            cofactors_matrix[r][c] = cofactor

    # 2. Calcular la matriz adjunta (transpuesta de la matriz de cofactores)
    adjugate_matrix = transpose_matrix(cofactors_matrix)

    # 3. Multiplicar la matriz adjunta por 1/determinante
    inverse = [[adjugate_matrix[r][c] / det for c in range(n)] for r in range(n)]
    return inverse

def get_matrix_from_user(n):
    """
    Solicita al usuario que introduzca los elementos para una matriz N x N.
    """
    matrix = []
    print(f"\nIntroduce los elementos de la matriz {n}x{n} fila por fila.")
    print("Separa los números de cada fila con espacios.")
    for i in range(n):
        while True:
            try:
                row_str = input(f"Fila {i+1} (separar con espacios): ")
                row = [float(x) for x in row_str.split()]
                if len(row) != n:
                    print(f"Error: Debes introducir exactamente {n} números para esta fila. Inténtalo de nuevo.")
                else:
                    matrix.append(row)
                    break
            except ValueError:
                print("Entrada inválida. Asegúrate de introducir solo números válidos. Inténtalo de nuevo.")
    return matrix

# --- Programa Principal ---
if __name__ == "__main__":
    while True:
        try:
            size_str = input("Introduce la dimensión de la matriz (N) [3-10], o 'salir' para terminar: ").lower()
            if size_str == 'salir':
                print("Saliendo del programa.")
                break

            n = int(size_str)
            if not (3 <= n <= 10):
                print("Error: La dimensión debe estar entre 3 y 10. Inténtalo de nuevo.")
                continue
            break
        except ValueError:
            print("Entrada inválida. Por favor, introduce un número entero o 'salir'.")

    if size_str != 'salir':
        user_matrix = get_matrix_from_user(n)

        print("\nMatriz introducida:")
        for row in user_matrix:
            print([f"{x:.2f}" for x in row]) # Muestra con 2 decimales para claridad

        try:
            print("\nCalculando la inversa...")
            if n >= 8:
                print("¡ADVERTENCIA! Para matrices de este tamaño (8x8 o más), el cálculo puede tardar MUCHO tiempo (minutos u horas).")
                print("Por favor, ten paciencia o considera usar una biblioteca optimizada como NumPy para cálculos reales.")
            inv_matrix = inverse_matrix(user_matrix)
            print("\nMatriz Inversa:")
            for row in inv_matrix:
                print([f"{x:.6f}" for x in row]) # Muestra con más decimales para precisión
        except ValueError as e:
            print(f"\nError: {e}")
        except Exception as e:
            print(f"\nOcurrió un error inesperado: {e}. Asegúrate de que los números sean válidos y la matriz no sea demasiado compleja.")
```
### 2. Función de Cifrado y Descifrado
Código que implementa la matriz inversa calculada anteriormente, para tener una función de cifrado y descifrado de acuerdo con algoritmo de Hill

```bash
def get_submatrix(matrix, exclude_row, exclude_col):
    """
    Retorna una submatriz excluyendo una fila y una columna específicas.
    Esencial para calcular menores y cofactores.
    """
    return [
        [matrix[r][c] for c in range(len(matrix[0])) if c != exclude_col]
        for r in range(len(matrix)) if r != exclude_row
    ]

def determinant(matrix):
    """
    Calcula el determinante de una matriz cuadrada usando la expansión por cofactores.
    Esta función es recursiva.
    """
    n = len(matrix)

    if n == 1:
        return matrix[0][0]
    elif n == 2:
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]

    det_val = 0
    for c in range(n):
        sub_matrix = get_submatrix(matrix, 0, c)
        cofactor_term = ((-1)**(c)) * determinant(sub_matrix)
        det_val += matrix[0][c] * cofactor_term
    return det_val

def transpose_matrix(matrix):
    """
    Calcula la transpuesta de una matriz (intercambia filas por columnas).
    """
    rows = len(matrix)
    cols = len(matrix[0])
    transposed = [[0 for _ in range(rows)] for _ in range(cols)]
    for i in range(rows):
        for j in range(cols):
            transposed[j][i] = matrix[i][j]
    return transposed

def extended_gcd(a, b):
    """Algoritmo extendido de Euclides."""
    if a == 0:
        return b, 0, 1
    else:
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

def mod_inverse(a, m=26):
    """Encuentra el inverso modular usando Euclides extendido."""
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        return None
    return x % m

def inverse_matrix_mod_26(matrix):
    """
    Calcula la inversa modular de una matriz para el cifrado de Hill (mod 26).
    """
    n = len(matrix)

    if not all(len(row) == n and all(isinstance(x, int) for x in row) for row in matrix):
        raise ValueError("La matriz debe ser cuadrada y contener solo números enteros.")

    det = determinant([[x % 26 for x in row] for row in matrix])
    det = det % 26

    det_inv = mod_inverse(det, 26)
    if det_inv is None:
        raise ValueError(f"La matriz es singular (determinante {det} no tiene inverso modular mod 26) y no tiene inversa.")

    cofactors_matrix = [[0] * n for _ in range(n)]
    for r in range(n):
        for c in range(n):
            sub_matrix = get_submatrix(matrix, r, c)
            minor_det = determinant(sub_matrix)
            cofactor = ((-1)**(r + c)) * minor_det
            cofactors_matrix[r][c] = cofactor % 26

    adjugate_matrix = transpose_matrix(cofactors_matrix)

    inverse_mod_26 = [[0] * n for _ in range(n)]
    for r in range(n):
        for c in range(n):
            inverse_mod_26[r][c] = (adjugate_matrix[r][c] * det_inv) % 26

    return inverse_mod_26

def text_to_numbers(text):
    """Convierte un texto a una lista de números (A=0, B=1...)."""
    text = text.upper().replace(" ", "")
    numbers = [ord(char) - ord('A') for char in text if 'A' <= char <= 'Z']
    return numbers

def numbers_to_text(numbers):
    """Convierte una lista de números a texto (0=A, 1=B...)."""
    text = "".join([chr(num + ord('A')) for num in numbers])
    return text

def matrix_multiplication_mod_26(matrix, vector):
    """Multiplica una matriz n x n por un vector de tamaño n (mod 26)."""
    n = len(matrix)
    result_vector = [0] * n
    for r in range(n):
        sum_val = 0
        for c in range(n):
            sum_val += matrix[r][c] * vector[c]
        result_vector[r] = sum_val % 26
    return result_vector

def hill_cipher(plain_text, key_matrix):
    """
    Cifra un texto plano usando el cifrado de Hill.
    """
    n = len(key_matrix)
    plain_numbers = text_to_numbers(plain_text)

    if len(plain_numbers) % n != 0:
        plain_numbers += [23] * (n - (len(plain_numbers) % n))

    cipher_numbers = []
    for i in range(0, len(plain_numbers), n):
        block = plain_numbers[i:i+n]
        encrypted_block = matrix_multiplication_mod_26(key_matrix, block)
        cipher_numbers.extend(encrypted_block)

    return numbers_to_text(cipher_numbers)

def hill_decipher(cipher_text, key_inverse_matrix):
    """
    Descifra un texto cifrado usando el cifrado de Hill.
    Ahora recibe la matriz inversa directamente.
    """
    n = len(key_inverse_matrix)
    cipher_numbers = text_to_numbers(cipher_text)

    deciphered_numbers = []
    for i in range(0, len(cipher_numbers), n):
        block = cipher_numbers[i:i+n]
        decrypted_block = matrix_multiplication_mod_26(key_inverse_matrix, block)
        deciphered_numbers.extend(decrypted_block)

    return numbers_to_text(deciphered_numbers)

def print_matrix(matrix, title):
    print(f"\n{title}:")
    for row in matrix:
        print(" ".join(map(str, row)))

def get_key_matrix(n):
    while True:
        try:
            matrix = []
            print(f"\nIntroduce los elementos de la matriz clave {n}x{n} fila por fila.")
            print("Separa los números de cada fila con espacios.")
            for i in range(n):
                row_str = input(f"Fila {i+1} (separar con espacios): ")
                row = [int(x) for x in row_str.split()]
                if len(row) != n:
                    raise ValueError(f"Debes introducir exactamente {n} números para esta fila.")
                matrix.append(row)
            inverse_matrix_mod_26(matrix)
            return matrix
        except ValueError as e:
            print(f"\nError: {e}")
            print("La matriz clave no es válida. Por favor, inténtalo de nuevo.")

# --- Programa Principal ---
if __name__ == "__main__":
    while True:
        print("\n--- ALGORITMO HILL ---")
        print("1. Cifrar mensaje")
        print("2. Descifrar mensaje")
        print("3. Salir")
        choice = input("Selecciona una opción (1/2/3): ")

        if choice in ['1', '2']:
            try:
                size_str = input("Introduce la dimensión de la matriz clave (N): ")
                n = int(size_str)
                if n < 2:
                    print("Error: La dimensión debe ser al menos 2.")
                    continue

                key_matrix = get_key_matrix(n)

                if choice == '1':
                    print_matrix(key_matrix, "Matriz Clave Ingresada")
                    plain_text = input("\nIntroduce el texto a cifrar: ")
                    cipher_text = hill_cipher(plain_text, key_matrix)
                    print(f"Texto cifrado: {cipher_text}")

                elif choice == '2':
                    # Calculamos la inversa una sola vez aquí
                    try:
                        key_inverse = inverse_matrix_mod_26(key_matrix)
                        print_matrix(key_matrix, "Matriz Clave Ingresada")
                        print_matrix(key_inverse, "Matriz Clave Inversa (mod 26)")
                    except ValueError as e:
                        print(f"Error: {e}")
                        continue

                    cipher_text = input("\nIntroduce el texto a descifrar: ")
                    # Pasamos la inversa, no la matriz original
                    plain_text = hill_decipher(cipher_text, key_inverse)
                    print(f"Texto descifrado: {plain_text}")

            except ValueError:
                print("Entrada inválida. Por favor, introduce un número entero para la dimensión.")

        elif choice == '3':
            print("Saliendo del programa.")
            break

        else:
            print("Opción no válida. Por favor, elige 1, 2 o 3.")
```
