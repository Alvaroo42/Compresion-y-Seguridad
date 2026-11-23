@echo off
chcp 65001 >nul
setlocal
:: Compila y arranca el servidor HTTPS (TLS 1.3) en el puerto 8443 (o el que se pase: EjecutarServidor.bat 9443).
:: Pide la contrasena de servidor.p12, salvo que este en la variable CYS_CLAVE_ALMACEN.
cd /d "%~dp0.."

if not exist servidor_secretos\servidor.p12 (
  echo Falta el certificado del servidor. Ejecuta primero ejecutar\GenerarCertificado.bat
  pause
  exit /b 1
)

echo Compilando el servidor...
javac -encoding UTF-8 -sourcepath . -d out servidor\ServidorHTTPS.java
if errorlevel 1 (
  echo ERROR al compilar el servidor.
  pause
  exit /b 1
)
java -Dfile.encoding=UTF-8 -cp out servidor.ServidorHTTPS %*
pause
