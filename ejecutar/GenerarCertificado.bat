@echo off
chcp 65001 >nul
setlocal
:: Crea el certificado autofirmado del servidor y el almacen de confianza del cliente con keytool
:: (viene con Java). Son los tres comandos del apartado 6.1 de la guia (opcion A).
::
::   GenerarCertificado.bat                     valido solo para localhost y 127.0.0.1 (mismo PC)
::   GenerarCertificado.bat 10.163.179.48       anade la IP del PC servidor (para clientes en otros PC)
::   GenerarCertificado.bat 10.0.0.5 miservidor varias IP o nombres, separados por espacios
:: Funciona igual desde cmd, PowerShell o doble clic (sin argumentos).
::
:: La contrasena del almacen del servidor la pide keytool (o se toma de la variable CYS_CLAVE_ALMACEN).
:: No se guarda en ningun fichero del proyecto.
::
:: Genera:
::   servidor_secretos\servidor.p12   certificado + clave privada TLS del servidor (NO se reparte)
::   servidor_secretos\servidor.crt   certificado publico (para comprobar su huella)
::   cliente_confianza.p12            lo unico en lo que confia el cliente: se copia junto a cada cliente
cd /d "%~dp0.."

set "SAN=dns:localhost,ip:127.0.0.1"
:argumentos
if "%~1"=="" goto fin_argumentos
set "ARG=%~1"
if /i "%ARG%"=="dns:localhost" goto siguiente
if /i "%ARG%"=="ip:127.0.0.1" goto siguiente
if /i "%ARG%"=="localhost" goto siguiente
if /i "%ARG%"=="127.0.0.1" goto siguiente
if /i "%ARG:~0,3%"=="ip:" (set "SAN=%SAN%,%ARG%" & goto siguiente)
if /i "%ARG:~0,4%"=="dns:" (set "SAN=%SAN%,%ARG%" & goto siguiente)
echo %ARG%| findstr /r "^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$" >nul
if errorlevel 1 (set "SAN=%SAN%,dns:%ARG%") else (set "SAN=%SAN%,ip:%ARG%")
:siguiente
shift
goto argumentos
:fin_argumentos
set "CLAVE_ALMACEN=-storepass:env CYS_CLAVE_ALMACEN"
if not defined CYS_CLAVE_ALMACEN set "CLAVE_ALMACEN="
if not defined CYS_CLAVE_CONFIANZA set "CYS_CLAVE_CONFIANZA=cys-confianza"

if not exist servidor_secretos mkdir servidor_secretos
if exist servidor_secretos\servidor.p12 del servidor_secretos\servidor.p12
if exist servidor_secretos\servidor.crt del servidor_secretos\servidor.crt
if exist cliente_confianza.p12 del cliente_confianza.p12

echo.
echo [1/3] Par de claves RSA-2048 y certificado del servidor (%SAN%)
keytool -genkeypair -alias servidor -keyalg RSA -keysize 2048 -validity 365 -storetype PKCS12 ^
  -keystore servidor_secretos\servidor.p12 %CLAVE_ALMACEN% ^
  -dname "CN=localhost, OU=CyS, O=Universidad de Alicante, C=ES" -ext "SAN=%SAN%"
if errorlevel 1 goto error

echo.
echo [2/3] Exportar el certificado publico
keytool -exportcert -alias servidor -keystore servidor_secretos\servidor.p12 %CLAVE_ALMACEN% -rfc -file servidor_secretos\servidor.crt
if errorlevel 1 goto error

echo.
echo [3/3] Almacen de confianza del cliente con ese certificado
keytool -importcert -alias servidor -file servidor_secretos\servidor.crt -noprompt -storetype PKCS12 ^
  -keystore cliente_confianza.p12 -storepass:env CYS_CLAVE_CONFIANZA
if errorlevel 1 goto error

echo.
echo Certificado creado para: %SAN%
echo Huella SHA-256 (comparala con la que veas en cada cliente):
keytool -printcert -file servidor_secretos\servidor.crt | findstr /C:"SHA256:"
echo.
echo Copia cliente_confianza.p12 a la carpeta del proyecto de cada equipo cliente.
pause
exit /b 0

:error
echo.
echo ERROR: no se ha podido generar el certificado. Esta instalado Java (JDK) y keytool en el PATH?
pause
exit /b 1
