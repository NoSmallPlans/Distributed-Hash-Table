
import socket
import sys

if __name__ == "__main__":
    HOST = ''

    # ./dht_client node nodePort get|put key [value]
    node_ip, node_port, method, key, value = None,None,None,None,None

    if len(sys.argv) < 4:
        sys.exit("Missing input argument. Host, port, method, and key required")

    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        node_port = int(sys.argv[2])
    if len(sys.argv) > 3:
        method = sys.argv[3]
    if len(sys.argv) > 4:
        key = sys.argv[4]
    if len(sys.argv) > 5:
        arg_list = sys.argv
        arg_list.pop(0)
        arg_list.pop(0)
        arg_list.pop(0)
        arg_list.pop(0)
        arg_list.pop(0)
        value = ""
        value = " ".join(arg_list)

    if host is not None:
        print("host is " + host)
    if node_port is not None:
        print("node_port is " + str(node_port))
    if method is not None:
        method = method.lower()
        if method != 'get' and method != 'put':
            sys.exit("Invalid method. Must be get or put")
        print("method is " + method)
    if key is not None:
        key = key.lower()
        print("key is " + key)
    if value is not None:
        value = value.lower()
        print("value is " + value)



    try:
        node_ip = socket.gethostbyname(host)
    except:
        sys.exit("Invalid host provided")

    if node_port < 0 or node_port > 65535:
        sys.exit("Invalid port provided")




    msg = node_ip + ' ' + str(node_port) + ' ' + method + ' ' + key
    if value is not None:
        msg = msg + ' ' + value
    
    HARDCODED_PORT = 11045
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', HARDCODED_PORT))

    s.sendto(msg.encode("utf-8"), (node_ip, node_port))
    s.settimeout(3)
    try:
        data, server = s.recvfrom(1024)
        print(data.decode("utf-8"))
    except socket.timeout:
        s.close()
        sys.exit("Receive timed out")