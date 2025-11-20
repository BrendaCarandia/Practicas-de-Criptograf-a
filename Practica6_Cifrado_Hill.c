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
