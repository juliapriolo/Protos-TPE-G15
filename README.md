# Protos-TPE-G15

Trabajo Practico Especial de Protocolos de Comunicacion - 2026 1C.

El proyecto implementa un servidor proxy SOCKS5 en C con autenticacion
usuario/contrasena, conexiones salientes no bloqueantes, resolucion DNS,
metricas, registro de accesos y un protocolo simple de management consultable
desde un cliente propio.

## Autores

Grupo 15:

- Sofia Ines Ratto
- Olivia Rodrigue
- Julia Priolo
- Mateo Lopez Badias

## Requisitos

- Sistema POSIX con sockets BSD.
- `gcc`.
- `make`.
- `python3` y `nc` solo para las pruebas manuales propuestas.
- Libreria Check (`check.h`) solo para compilar los tests unitarios.

## Compilacion

Desde la raiz del repositorio:

```bash
make all
```

Para limpiar binarios y objetos:

```bash
make clean
```

Tambien se puede compilar solo el servidor o solo el cliente:

```bash
make server
make client
```

Los tests usan la libreria Check (`check.h`). Si no esta instalada, `make tests`
puede fallar aunque el servidor y el cliente compilen correctamente.

```bash
make tests
```

## Servidor

Uso:

```bash
./bin/server [opciones]
```

Opciones soportadas:

| Opcion | Descripcion | Default |
| --- | --- | --- |
| `-h` | Muestra ayuda y termina | - |
| `-v` | Muestra version y termina | - |
| `-l <addr>` | Direccion donde escucha el proxy SOCKS5 | `0.0.0.0` |
| `-p <port>` | Puerto SOCKS5 | `1080` |
| `-L <addr>` | Direccion donde escucha management | `127.0.0.1` |
| `-P <port>` | Puerto de management | `8080` |
| `-u <user>:<pass>` | Usuario SOCKS5 inicial. Se puede repetir hasta 10 veces | ninguno |

Ejemplo:

```bash
./bin/server -l 127.0.0.1 -p 1089 -L 127.0.0.1 -P 8089 -u alice:secret
```

Esto levanta:

```text
SOCKS5 listening on 127.0.0.1:1089
Management listening on 127.0.0.1:8089
```

Si no hay usuarios configurados, el proxy acepta el metodo SOCKS5 `NO AUTH`.
Si hay al menos un usuario configurado, exige autenticacion username/password
segun RFC1929.

Los cambios de usuarios realizados por management afectan a las nuevas
negociaciones SOCKS5. Las conexiones que ya superaron la negociacion y estan
autenticadas no se interrumpen por agregar o eliminar usuarios.

## SOCKS5

El servidor soporta:

- Version SOCKS5 (`0x05`).
- Metodo `NO AUTH` cuando no hay usuarios configurados.
- Metodo `USERNAME/PASSWORD` cuando hay usuarios configurados.
- Autenticacion RFC1929.
- Comando `CONNECT`.
- Destinos IPv4.
- Destinos IPv6.
- Destinos FQDN con `getaddrinfo`.
- Fallback cuando un FQDN resuelve multiples direcciones y una falla.
- Conexiones salientes no bloqueantes con `EINPROGRESS`, `OP_WRITE` y
  `getsockopt(SO_ERROR)`.

Codigos de respuesta relevantes:

| Respuesta | Significado |
| --- | --- |
| `0x00` | Exito |
| `0x01` | Falla general |
| `0x03` | Red inaccesible |
| `0x04` | Host inaccesible |
| `0x05` | Conexion rechazada |
| `0x06` | TTL expirado / timeout |
| `0x07` | Comando no soportado |
| `0x08` | Tipo de direccion no soportado |

## Cliente de management

Uso:

```bash
./bin/client [-L management_addr] [-P management_port] [comando]
```

Defaults:

```text
management_addr = 127.0.0.1
management_port = 8080
comando = STATS
```

Ejemplos:

```bash
./bin/client -P 8089
./bin/client -P 8089 HELP
./bin/client -P 8089 STATS
./bin/client -P 8089 USERS
./bin/client -P 8089 ADDUSER bob pass123
./bin/client -P 8089 DELUSER bob
./bin/client -P 8089 QUIT
```

## Protocolo de management

El protocolo de management es textual, orientado a lineas. Cada conexion envia
un comando terminado en `\n` y el servidor responde con texto `clave=valor`.

Comandos soportados:

| Comando | Descripcion |
| --- | --- |
| `STATS` | Devuelve metricas actuales |
| `METRICS` | Alias de `STATS` |
| `USERS` | Lista usuarios SOCKS5 configurados |
| `ADDUSER <user> <pass>` | Agrega usuario SOCKS5 |
| `DELUSER <user>` | Elimina usuario SOCKS5 |
| `HELP` | Lista comandos disponibles |
| `QUIT` | Responde `ok=bye` |

El canal de management no implementa autenticacion propia en esta version. Por
defecto escucha en `127.0.0.1`; si se expone en otra interfaz queda bajo
responsabilidad del operador.

Ejemplo de `STATS`:

```text
historical_connections=1
concurrent_connections=0
successful_connections=1
failed_connections=0
bytes_transferred=14
bytes_client_to_target=4
bytes_target_to_client=10
```

Ejemplo de `HELP`:

```text
commands=STATS,METRICS,USERS,ADDUSER,DELUSER,HELP,QUIT
```

Ejemplo de gestion de usuarios:

```bash
./bin/client -P 8089 ADDUSER alice secret
./bin/client -P 8089 USERS
./bin/client -P 8089 DELUSER alice
```

Salidas esperadas:

```text
adduser=ok
users_count=1
user=alice
deluser=ok
users_count=0
```

## Pruebas manuales

### 1. Compilar

```bash
make clean
make all
```

### 2. Levantar el servidor

```bash
./bin/server -l 127.0.0.1 -p 1089 -L 127.0.0.1 -P 8089
```

### 3. Agregar un usuario desde management

```bash
./bin/client -P 8089 ADDUSER alice secret
```

### 4. Levantar un destino TCP local

En otra terminal:

```bash
nc -l 29201
```

### 5. Probar SOCKS5 con autenticacion

En otra terminal:

```bash
python3 -c 'import socket
s=socket.create_connection(("127.0.0.1",1089))
s.sendall(bytes([5,1,2]))
print("method:", s.recv(2).hex())
s.sendall(bytes([1,5])+b"alice"+bytes([6])+b"secret")
print("auth:", s.recv(2).hex())
s.sendall(bytes([5,1,0,1,127,0,0,1,114,17]))
print("connect:", s.recv(10).hex())
s.sendall(b"hola\n")
s.close()'
```

Salida esperada:

```text
method: 0502
auth: 0100
connect: 05000001000000000000
```

En la terminal de `nc` deberia verse:

```text
hola
```

### 6. Consultar metricas en runtime

```bash
./bin/client -P 8089 STATS
```

### 7. Revisar access log

```bash
cat access.log
```

Ejemplo:

```text
2026-07-11T14:45:42Z user=alice dest=127.0.0.1 port=29201 status=OK
```

## Graceful shutdown

El servidor maneja `SIGINT` y `SIGTERM`.

Ante la primera señal:

- deja de aceptar conexiones nuevas;
- cierra los sockets pasivos;
- espera a que terminen las conexiones activas.

Ante una segunda señal puede forzar la finalizacion.

Ejemplo:

```bash
Ctrl+C
```

Salida esperada:

```text
shutdown requested: no longer accepting new connections, waiting for 0 active connection(s)
Metrics: historical_connections=...
```