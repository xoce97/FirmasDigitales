from django.shortcuts import render,redirect
from django.template import Template,Context
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from Web2020.decoradores import login_requerido
#--------------------------------------------
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#-----------------------------------------------------------------------------
import os
from os import remove
import base64
import hashlib
from registroUsuario import models
import threading
import time
#https://pymotw.com/2/threading/

## Define a static Pomodoro timer.
def Countdown():
    p = 600.00
    alarm = time.time() + p
    while True: ## Loop infinitely
        n = time.time()
        if not n < alarm:
           revocar_llaves()
           break

def revocar_llaves():
    usuarios=models.Usuario.objects.all()
    for usuario in usuarios:
        usuario.Llave_publica=''
        usuario.Llave_privada=''
        usuario.Iv=''
        usuario.save()


#generamos las llaves privada
def generar_llave_privada():
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        return private_key

#convertir de bytes a PEM
def convertir_llave_privada_a_PEM(llave_privada): 
    """Convierte de bytes a PEM"""
    pem_private = llave_privada.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
    return pem_private

#convierte la llave PEM a objeto llave 
def convertir_bytes_llave_privada(llave_privada_pem):
    """
    Convierte de PEM a objeto llave 
    """
    resultado = serialization.load_pem_private_key(llave_privada_pem,backend=default_backend(),password=None)
    return resultado

#generamos la llave publica 
def generar_llave_publica(llave_privada):
        return llave_privada.public_key()

#convertimos la llave publica bytes a PEM 
def convertir_llave_publica_bytes(llave_publica):
    """Convierte de bytes a PEM"""
    resultado = llave_publica.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return resultado

#convertir llave publica PEM a objeto llave
def convertir_llave_publica_pem_a_bytes(contenido_pem):
    resultado = serialization.load_pem_public_key(contenido_pem,backend=default_backend())
    return resultado

#gerenerar las llaves aes por medio de las contraseña 
def generar_llave_aes_from_password(password):
    password = password.encode('utf-8')
    derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data ',backend=default_backend()).derive(password)
    return derived_key

def cifrar(llave_pem, llave_aes, iv):
    aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),backend=default_backend())
    cifrador = aesCipher.encryptor()
    cifrado = cifrador.update(llave_pem)
    cifrador.finalize()
    return cifrado

def descifrar(cifrado, llave_aes, iv):
    aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),backend=default_backend())
    descifrador = aesCipher.decryptor()
    plano = descifrador.update(cifrado)
    descifrador.finalize()
    return plano

def generar_iv():
    iv=os.urandom(16)
    return iv

def generar_hash_password(password_usuario):
    hasher=hashlib.sha512()
    hasher.update(password_usuario.encode('utf-8'))
    return hasher.hexdigest()

def generar_bytes_a_texto(contenido_cifrado_bytes):
    texto=base64.b64encode(contenido_cifrado_bytes)
    texto=texto.decode('utf-8')
    return texto

def generar_texto_a_bytes(contenido_cifrado_texto):
    texto=base64.b64decode(contenido_cifrado_texto)
    return texto

def remover_firmas():
    url='/Volumes/SSDMAC2/proyectosDjango/Web2020/media/'#url estatica donde se almacenan los archivos firma
    firmas=os.listdir(url)
    if firmas==[]:
       return True
    else:
        for x in firmas:
            #print('Se va a borrar :' + x)
            remove(url + x)
        return False
        
# Create your views here.
def registroUsuario(request):
    if request.method== 'GET':
        template='registroUsuario.html'
        return render(request,template)
    elif request.method=='POST':
        nombre_completo=request.POST.get('nombre','').strip()
        nick=request.POST.get('nickname','').strip()
        password=request.POST.get('contraseña','').strip()
        correo_electronico=request.POST.get('correo','').strip()
    #se genera el objeto de usuario para la base de datos 
    usuario=models.Usuario()

    #generacion de llave privada 
    private_key=generar_llave_privada()
    
    #conversion de object python a formato binario Y formato PEM
    pem_private=convertir_llave_privada_a_PEM(private_key)
    
    #generar vector de inicializacion (salt)
    vector_inicializacion=generar_iv()
    
    #se codifica el iv a texto plano para guardar en la base de datos 
    texto_iv=generar_bytes_a_texto(vector_inicializacion)
    
    #se guarda el iv ya en texto plano en la base de datos 
    usuario.Iv=texto_iv
    
    #generear llave aes a partir del password
    llave_aes=generar_llave_aes_from_password(password)
    
    #cifrar la llave privada con el vector el password y la llaveAES
    llave_privada_cifrada=cifrar(pem_private,llave_aes,vector_inicializacion)
    
    #decodifica a texto plano la llave cifrada 
    llave_privada_cifrada_texto=generar_bytes_a_texto(llave_privada_cifrada)
    
    # se ingresa ya en texto la llave privada cifrada
    usuario.Llave_privada=llave_privada_cifrada_texto 
    
    #se hace el hash de la contraseña para que no se vea en la base de datos
    hasher_password_user=generar_hash_password(password)
    
    # se ingresa en la base de datos 
    usuario.Password=hasher_password_user
    
    #generamos la llave publica a partir de la llave privada 
    public_key=generar_llave_publica(private_key)
    
    #formato pem llave publica 
    pem_public=convertir_llave_publica_bytes(public_key)
    
    #decodificamos la llave publica a base64 
    llave_publica_texto=generar_bytes_a_texto(pem_public)
    
    #ingresamos la llave publica a la base de datos 
    usuario.Llave_publica=llave_publica_texto
    usuario.Nombre_Completo=nombre_completo
    usuario.Nick=nick
    usuario.Correo_Electronico=correo_electronico
    usuario.save()
    return redirect('/login')
    
    
def index(request):
    template='index.html'
    return render(request,template)

@login_requerido
def usuario(request):
    template='usuario.html'
    return render(request,template)

@login_requerido
def firmar_archivo(request):
    nick=request.session.get('nombre')
    contexto={}
    template='firmar.html'
    if request.method=='GET':
        return render(request,template)
    elif request.method=='POST'and request.FILES['archivo']:
        password=request.POST.get('contraseña','').strip()
        archivo=request.FILES['archivo']
    
    try:
        hash_password=generar_hash_password(password)
        #generamos la consulta para optener un objeto del inicio de sesion
        usuario=models.Usuario.objects.get(Nick=nick,Password=hash_password)
        #mandar a traer la llave privada de la base datos
        llave_privada_cifrada_texto=usuario.Llave_privada
        #convertimos la llave privada de texto a bytes
        llave_privada_cifrada_bytes=generar_texto_a_bytes(llave_privada_cifrada_texto)
        #tambien optenemos el Iv en formato de texto
        iv_texto=usuario.Iv
        #convertimos el iv de texto a bytes 
        iv_bytes=generar_texto_a_bytes(iv_texto)
        #generamos la llave aes a partir de la contraseña
        llave_aes=generar_llave_aes_from_password(password)
        #deciframos la llave privada por medio de la contraseña 
        llave_privada=descifrar(llave_privada_cifrada_bytes,llave_aes,iv_bytes)
        #pasar la llave privada a object para que la pueda recibir la funcion sing
        private_key=convertir_bytes_llave_privada(llave_privada)
    except:
        errores={'Contraseña incorrecta'}
        return render(request,template,{'errores':errores})
    #guardamos temporalmente el archivo que el usuario envia 
    original=FileSystemStorage()
    try:
        archivo_original=original.save(archivo.name,archivo)
        archivo_binario=original.open(archivo_original,'rb')
        datos_a_firmar=archivo_binario.read()
        archivo_binario.close()
    except:
        errores={'Error al leer el archivo original'}
        return render(request,template,{'errores':errores})
    
    #firmamos los datos del usuario
    signature = private_key.sign(datos_a_firmar,ec.ECDSA(hashes.SHA256()))
    firma=FileSystemStorage()
    #aqui ponemos una exepcion para saber si algo sale mal 
    try:
        firmado=firma.save(archivo.name+'.sing',archivo)
        archivo_firmado=firma.open(firmado,'wb')
        archivo_firmado.write(signature)
        archivo_firmado.close()
        contexto['url']=firma.url(firmado)
    except:
        errores={'Error al crear el archivo a firmar'}
        return render(request,template,{'errores':errores})
    original.delete(archivo_original)
    return render(request,template,contexto)

@login_requerido
def verificar_firma_archivo(request):
    template='verificar.html'
    if request.method=='GET':
        return render(request,template)
    elif request.method=='POST' and request.FILES['archivoOriginal'] and request.FILES['archivoFirma'] :
        nickname=request.POST.get('nick','').strip()
        archivoOriginal=request.FILES['archivoOriginal']
        archivoFirma=request.FILES['archivoFirma']
    
    try:
        usuario=models.Usuario.objects.get(Nick=nickname)
        llave_publica_texto=usuario.Llave_publica
        llave_publica_pem=generar_texto_a_bytes(llave_publica_texto)
        public_key=convertir_llave_publica_pem_a_bytes(llave_publica_pem)
        validar=remover_firmas()
        #print(validar)
    except:
        errores={'Error el usuario que ingreso no existe o es incorrecto'}
        return render(request,template,{'errores':errores})
    
    archivo=FileSystemStorage()
    firma=FileSystemStorage()

    try:
        nombreOriginal=archivo.save(archivoOriginal.name,archivoOriginal)
        original=archivo.open(nombreOriginal,'rb')
        datos_a_firmar=original.read()
        original.close()
        archivo.delete(nombreOriginal)
    except:
        errores={'Error en el archivo original al leer'}
        return render(request,template,{'errores':errores})

    try:
        nombreFirma=firma.save(archivoFirma.name,archivoFirma)
        archivo_firma=firma.open(nombreFirma,'rb')
        signature=archivo_firma.read()
        archivo_firma.close()
        firma.delete(nombreFirma)
    except:
        errores={'Error en el archivo de la firma al leer'}
        return render(request,template,{'errores':errores})
    
    try:
        public_key.verify(signature, datos_a_firmar, ec.ECDSA(hashes.SHA256()))
        valido={'La firma es válida'}
        return render(request,template,{'valido':valido})
    except InvalidSignature:
        invalido={'La firma es inválida'}
        return render(request,template,{'invalido':invalido})

@login_requerido
def renovar_llaves(request):
    nick=request.session.get('nombre')
    template='renovar.html'
    if request.method=='GET':
        return render(request,template)
    elif  request.method=='POST':
        password=request.POST.get('password','').strip()
    
    try:
        password_hash=generar_hash_password(password)
        usuario=models.Usuario.objects.get(Nick=nick,Password=password_hash)
    except:
        errores={'Contraseña incorrecta'}
        return render(request,template,{'errores':errores})
    
    try:
        #generamos la llave privada de nuevo 
        new_private_key=generar_llave_privada()
    
        #convertimos la llave privada a pem
        new_llave_privada_pem=convertir_llave_privada_a_PEM(new_private_key)
    
        #genero el nuevo iv para la llave aes y lo pasamos a texto
        new_Iv=generar_iv()
        new_Iv_texto=generar_bytes_a_texto(new_Iv)
        llave_aes=generar_llave_aes_from_password(password)
        new_llave_privada_cifrada=cifrar(new_llave_privada_pem,llave_aes,new_Iv)
        new_llave_privada_cifrada_texto=generar_bytes_a_texto(new_llave_privada_cifrada)
    
        #genero la llave publica y la paso a pem tambien 
        new_public_key=generar_llave_publica(new_private_key)
        new_llave_publica_pem=convertir_llave_publica_bytes(new_public_key)
        llave_publica_pem_texto=generar_bytes_a_texto(new_llave_publica_pem)
    except:
        errores={'error en la asignacion de la llaves'}
        return render(request,template,{'errores':errores})
    
    usuario.Llave_privada=new_llave_privada_cifrada_texto
    usuario.Llave_publica=llave_publica_pem_texto
    usuario.Iv=new_Iv_texto
    usuario.save()
    cambio={'Las llaves privada y publica se han cambiado exitosamente'}
    return render(request,template,{'cambio':cambio})

def logIn(request):
    template='login.html'
    ingreso=request.session.get('ingreso',False)
    if request.method=='GET':
        if ingreso:
            return redirect('usuario/')
        return render(request,template) 
    elif request.method=='POST':
        nickname=request.POST.get('nickname','').strip()
        password=request.POST.get('contraseña','').strip()
        try:
            hash_password=generar_hash_password(password)
            models.Usuario.objects.get(Nick=nickname,Password=hash_password)
            request.session['ingreso']=True
            request.session['nombre']=nickname
            #t = threading.Thread(target=Countdown)
            #t.start()
            return redirect('usuario/')
        except:
            errores={'Usuario o Contraseña incorrecta'}
            return render(request,template,{'errores':errores})

def logOut(request):
    request.session.flush()
    return redirect('/login')