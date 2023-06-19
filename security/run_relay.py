from relay import NodeServer
import os

n = NodeServer(int(os.environ["PORT"]))
n.start()
