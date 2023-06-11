from security.connection import NodeServer

n = NodeServer(9050)
try:
    n.start()
finally:
    n.close()
