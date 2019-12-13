import socket, base64, time

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 2525        # Port to listen on (non-privileged ports are > 1023)

server_conn=  socket.socket(socket.AF_INET, socket.SOCK_STREAM)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    server_conn.connect((HOST, 2225))
    with conn:
        print('Connected by', addr)
        str(server_conn.recv(1024),'utf-8')
        start = time.time()
        while True:
            data = conn.recv(1024),'utf-8'
            print(str(data))
            if not data:
                break
            server_conn.sendall(data)
            data_server=server_conn.recv(1024), 'utf-8'
            print(str(data_server))
            conn.send(data_server)
    end = time.time()
    print('tempo impiegato', (end-start)/60)

