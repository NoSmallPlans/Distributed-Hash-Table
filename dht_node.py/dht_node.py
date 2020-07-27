import socket
import re
import math
import sys
import hashlib

class Finger:
    def __init__(self, node_addr, node_port):
        self.node_addr = node_addr
        self.port = int(node_port)
        self.pred = None
        self.successor = None
        self.addr_space = 160
        self.node_key = str(node_addr) + str(node_port)
        self.node_id = self.get_int_key_hash(self.node_key) % self.addr_space

    def get_int_key_hash(self, key):
        return int.from_bytes(hashlib.sha1(str(key).encode()).digest(), byteorder="big")

class Query:
    def __init__(self, sender_addr, query_bytes):
        query_str = query_bytes.decode("utf-8") 
        query_list = query_str.split()
        if len(query_list) < 4:
            self.error = True
        else:
            self.error = False
        if query_list[0] == 'FWD':
            self.fwd = True
            self.hop_count = int(query_list[1])
            self.return_host = query_list[2]
            self.return_port = int(query_list[3])
        else:
            query_list.pop(0)
            query_list.pop(0)
            self.fwd = False
            self.hop_count = 1
            self.return_host = sender_addr[0]
            self.return_port = int(sender_addr[1])
            query_list = ['FWD',self.hop_count,self.return_host,self.return_port] + query_list
        self.resp_addr = (self.return_host, self.return_port)
        self.method = query_list[4].lower()
        self.key = query_list[5].lower()
        self.hex_key = hashlib.sha1(self.key.encode()).hexdigest()
        self.value = ""
        if len(query_list) >= 7:
            query_list.pop(0)
            query_list.pop(0)
            query_list.pop(0)
            query_list.pop(0)
            query_list.pop(0)
            query_list.pop(0)
            self.value = " ".join(query_list)

    def prepare_to_hop(self):
            self.hop_count = self.hop_count + 1
            if not self.fwd:
                self.fwd = True

    def make_query_bstr(self):
        bstr = 'FWD'
        bstr = bstr +  ' ' + str(self.hop_count)
        bstr = bstr +  ' ' + self.return_host
        bstr = bstr +  ' ' + str(self.return_port)
        bstr = bstr +  ' ' + self.method
        bstr = bstr +  ' ' + self.key
        bstr = bstr +  ' ' + self.value
        return bstr.encode("utf-8")

class DHT_Node:
    def __init__(self, buffer_size, node_addr, node_port, old_successor_list, successor_list):
        self.keyMin = 'a'
        self.keyMax = 'm'
        self.buffer_size = buffer_size
        self.node_addr = node_addr
        self.node_port = int(node_port)
        self.old_successor_list = old_successor_list
        self.localStore = {}
        self.finger_table = {}
        self.mock_finger_table = []
        self.successor_list = []
        self.addr_space = 160
        self.node_key = str(node_addr) + str(node_port)
        self.node_id = self.get_int_key_hash(self.node_key) % self.addr_space
        self.hex_hash = hashlib.sha1(str(node_addr).encode()+str(node_port).encode()).hexdigest()
        self.sort_successors_by_increasing_id(successor_list)
        self.init_finger_table()
        self.config_socket()
        self.listen()


    def get_int_key_hash(self, key):
        return int.from_bytes(hashlib.sha1(str(key).encode()).digest(), byteorder="big")

    def KeyFit(self,key):
        return self.get_dest_id(self.node_key) == self.get_dest_id(key)

    def get_virtual_id(self, hashed_key):
        return hashed_key % self.addr_space

    def get_dest_id(self,key):
        hashed_key = int.from_bytes(hashlib.sha1(str(key).encode()).digest(), byteorder="big")
        virtual_id = self.get_virtual_id(hashed_key)
        return self.get_phys_node_id(virtual_id)

    def get_phys_node_id(self, virtual_id):
        #ensure phys_id_list sorted from small to large - init will call sort function
        #find smallest node_id >= virtual_id
        for i, node in enumerate(self.successor_list):
            if node.node_id >= virtual_id:
                return node.node_id
        return self.successor_list[0].node_id

    def sort_successors_by_increasing_id(self,raw_node_list):
        #sort_successors_by_increasing_id
        raw_node_list.sort(key=lambda x: x.node_id, reverse=False)
        sorted = raw_node_list
        self.successor_list = sorted
        
    def init_finger_table(self):
        for successor in self.successor_list:
            self.finger_table[successor.node_id] = (successor.node_addr, successor.port)

    def config_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.node_addr, self.node_port))

    def listen(self):
        while True:
            query, sender_addr = self.socket.recvfrom(self.buffer_size)
            print("Query: ", query.encode("utf-8"))
            self.handle_query(sender_addr, query)

    def send_resp(self, msg, addr):
        msg = msg.encode("utf-8")
        self.socket.sendto(msg, addr)

    def handle_query(self, sender_addr, query_bytes):
        query_obj = Query(sender_addr, query_bytes)
        if query_obj.error:
            print("Query Paremeter Error")
            return
        else:
            self.exec_query(query_obj)

    def exec_query(self, query_obj):
        if not self.KeyFit(query_obj.key):
            self.TrySuccessor(query_obj)
            return
        if query_obj.method == 'get':
            msg = self.process_get(query_obj.key)
        if query_obj.method == 'put':
            msg = self.process_put(query_obj.key, query_obj.value)
        msg = msg + ' | Number of Hops ' + str(query_obj.hop_count)
        msg = msg + ' | Hash of Node: ' + self.hex_hash
        msg = msg + ' | Hash of Key: ' + query_obj.hex_key
        self.send_resp(msg,query_obj.resp_addr)

    def process_get(self, key):
        response = ""
        if not self.HasKey(key):
            response = "Key not found."
        else:
            response = 'value is ' + self.GetVal(key)
        return response

    def process_put(self, key, value):
        if value == "":
            if self.HasKey(key):
                self.DeleteByKey(key)
                response = "Value deleted."
            else:
                response = "Key did not exist."
        elif self.HasKey(key):
            response = "Value updated."
            self.SetVal(key, value)
        else:
            response = "Value inserted."
            self.SetVal(key, value)
        return response

    def TrySuccessor(self, query_obj):
        id = self.get_dest_id(query_obj.key)
        next = self.finger_table[id]
        next_ip = next[0]
        next_port = next[1]
        query_obj.prepare_to_hop()
        query_string = query_obj.make_query_bstr()
        self.socket.sendto(query_string, (next_ip, next_port))

    def HasKey(self, key):
        return key in self.localStore

    def GetVal(self, key):
        return self.localStore[key]

    def SetVal(self, key, value):
        self.localStore[key] = value
        return

    def DeleteByKey(self, key):
        self.localStore.pop(key)
        return

if __name__ == "__main__":
    BUFFER_SIZE = 1024

    if len(sys.argv) > 2:
        file_name = sys.argv[1]
        tgt_index = int(sys.argv[2])
    else :
        sys.exit("Not enough command line args")

    try:
        f = open(file_name, "r")
        line_list = f.readlines()
        f.close()
    except:
        sys.exit("Error attempting to read file")

    if tgt_index < 0 or tgt_index+1 > len(line_list):
        sys.exit("Invalid index provided")

    node_list = []
    nex_node_list = []
    for line in line_list:
        host, node_port = line.split()
        node_addr = socket.gethostbyname(host)
        node_list.append((node_addr, int(node_port)))
        node_entry = Finger(node_addr, node_port)
        nex_node_list.append(node_entry)

    node_addr = node_list[tgt_index][0]
    node_port = node_list[tgt_index][1]
    del node_list[tgt_index]

    node = DHT_Node(BUFFER_SIZE, node_addr, node_port, node_list, nex_node_list)