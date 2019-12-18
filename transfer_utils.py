import socket
import time

def G_socket_ping(tcp_tuple=None, host=None, port=None):
    if not tcp_tuple:
        tcp_tuple = (host, port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t_start = round(time.time() * 1000)
    try:
        s.settimeout(1)
        s.connect(tcp_tuple)
        s.shutdown(socket.SHUT_RD)
        t_end = round(time.time() * 1000)
        s.close()
        return t_end - t_start
    except Exception:
        s.close()
        return -1

def G_traffic_show(Traffic):
    if Traffic < 1024:
        return str(round((Traffic), 2)) + "B"

    if Traffic < 1024 * 1024:
        return str(round((Traffic / 1024), 2)) + "KB"

    if Traffic < 1024 * 1024 * 1024:
        return str(round((Traffic / 1024 / 1024), 2)) + "MB"

    return str(round((Traffic / 1024 / 1024 / 1024), 2)) + "GB"
