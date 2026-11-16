@echo off
chcp 65001 >nul
setlocal
:: Pruebas automaticas: pasos 1-3 de la guia (sin red) y la prueba de extremo a extremo, que arranca su
:: propio servidor HTTPS y un proveedor de prueba que se comporta como Google, en carpetas temporales.
cd /d "%~dp0.."
javac -encoding UTF-8 -cp lib\bcprov.jar -sourcepath . -d out pruebas\*.java
if errorlevel 1 (
  echo ERROR al compilar las pruebas.
  pause
  exit /b 1
)
java -Dfile.encoding=UTF-8 -cp "out;lib\bcprov.jar" pruebas.PruebaPaso1Claves
java -Dfile.encoding=UTF-8 -cp "out;lib\bcprov.jar" pruebas.PruebaPaso2Almacen
java -Dfile.encoding=UTF-8 -cp "out;lib\bcprov.jar" pruebas.PruebaPaso3HashLogin
java -Dfile.encoding=UTF-8 -cp "out;lib\bcprov.jar" pruebas.PruebaExtremoAExtremo
pause
