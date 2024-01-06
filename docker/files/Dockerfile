# Utilizar la imagen de Go como base
FROM golang:1.20.3-buster AS builder

# Configurar el directorio de trabajo en el contenedor
WORKDIR /app

# Copiar los archivos de dependencias de Go
COPY go.mod go.sum ./

# Descargar las dependencias de Go
RUN go mod download

# Copiar el resto del código fuente de la aplicación Go
COPY . .

# Compilar la aplicación Go, creando un binario
RUN go build -o main .

# Crear una nueva etapa de ejecución con una imagen base más ligera
FROM debian:buster

# Instalar dependencias de sistema necesarias
RUN apt-get update && apt-get install -y iptables openssh-server rsyslog fail2ban curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copiar el binario compilado de la etapa de construcción
COPY --from=builder /app/main /main

# Copiar los certificados y llaves, y configurar sus permisos
COPY certs /certs
COPY keys /keys
RUN chmod -R 644 /certs && \
    chmod -R 644 /keys

# Copiar y configurar permisos para el script de entrada
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Exponer el puerto 
EXPOSE 5000

CMD [ "/main" ]

# Configurar el punto de entrada para iniciar la aplicación
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
