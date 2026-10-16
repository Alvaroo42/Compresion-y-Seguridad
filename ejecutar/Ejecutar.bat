@echo off
chcp 65001 >nul

:: Retrocedemos una carpeta para ubicarnos en "Compresion-y-Seguridad"
cd ..

echo Compilando el código...
:: Usamos -sourcepath . para que encuentre las dependencias (como SesionLocal)
javac -encoding UTF-8 -sourcepath . -d out cliente\interfaz\Interfaz.java

echo Ejecutando la interfaz limpia...
java -Dfile.encoding=UTF-8 -cp out cliente.interfaz.Interfaz

pause