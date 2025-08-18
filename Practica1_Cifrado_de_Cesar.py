
texto = str(input("Ingresa el texto a encriptar/desencriptar: "))
letras = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','Ñ','O','P','Q','R','S','T','U','V','W','X','Y','Z',
'a','b','c','d','e','f','g','h','i','j','k','l','m','n','ñ','o','p','q','e','s','t','u','v','w','x','y','z',' ']

n = int(input("Ingresa el número de espacios a mover al encriptar/descencriptar: "))

opcion = int(input("Ingresa opcion ENCRIPTAR (1)   DESENCRIPTAR (2): "))

if (opcion == 1):
    print("El texto encriptado es: ")
    i = 0
    encript = []
    textoEn = ""
    for i in range(len(texto)):
        k = 0
        while(texto[i] != letras[k]):
            k += 1
        if (k+n) > 55:
            k = abs(55-(k+n))
            encript.append(letras[k])
        else:
            encript.append(letras[((k + n) % 55)])
        textoEn += encript[i]

    print(textoEn)
else:
    print("El texto desencriptado es: ")
    i = 0
    desencript = []
    textoDn = ""
    for i in range(len(texto)):
        k = 0
        while(texto[i] != letras[k]):
            k += 1
        if (k-n) < 0:
            k = abs(55+(k-n))
            desencript.append(letras[k])
        else:
            desencript.append(letras[((k - n) % 55)])
        textoDn += desencript[i]

    print(textoDn)
