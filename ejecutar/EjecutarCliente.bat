@echo off
chcp 65001 >nul
setlocal
:: Compila y abre el cliente. Necesita cliente_confianza.p12 en la carpeta del proyecto.
::   EjecutarCliente.bat                      servidor localhost:8443 (se puede cambiar en la ventana)
::   EjecutarCliente.bat 192.168.1.20:8443    otro servidor
:: No necesita librerias externas: SHA3, AES, RSA y TLS vienen en Java.
cd /d "%~dp0.."

echo Compilando el cliente...
javac -encoding UTF-8 -sourcepath . -d out cliente\interfaz\Interfaz.java
if errorlevel 1 (
  echo ERROR al compilar el cliente.
  pause
  exit /b 1
)
if "%~1"=="" (
  start "" javaw -Dfile.encoding=UTF-8 -cp out cliente.interfaz.Interfaz
) else (
  start "" javaw -Dfile.encoding=UTF-8 -Dcys.servidor=%~1 -cp out cliente.interfaz.Interfaz
)
