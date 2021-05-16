from django.db import models
# Create your models here.
class Usuario(models.Model):
    Nombre_Completo=models.CharField(max_length=100)
    Nick=models.CharField(max_length=20)
    Password=models.CharField(max_length=1024)
    Correo_Electronico=models.EmailField()
    Llave_publica=models.CharField(max_length=2048)
    Llave_privada=models.CharField(max_length=2048)
    Iv=models.CharField(max_length=1024)

