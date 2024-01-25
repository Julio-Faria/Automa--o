import scapy.all as scapy

def scan(ip):
    # Criar um objeto ARP request para descobrir os endereços MAC na rede local
    arp_request = scapy.ARP(pdst=ip)

    # Criar um objeto Ether para definir o endereço MAC de destino como broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combinar o objeto Ether e o objeto ARP request
    arp_request_broadcast = broadcast/arp_request

    # Enviar o pacote e receber a resposta
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Criar uma lista para armazenar os resultados
    clients_list = []

    # Iterar sobre a lista de respostas
    for element in answered_list:
        # Obter o endereço IP e o endereço MAC do dispositivo
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}

        # Adicionar o dicionário à lista de clientes
        clients_list.append(client_dict)

    return clients_list

def print_result(results_list):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

# Obter o intervalo de IP a ser escaneado
target_ip = input("Enter the IP range to scan (e.g., 192.168.0.1/24): ")

# Chamar a função scan com o intervalo de IP fornecido
scan_result = scan(target_ip)

# Imprimir os resultados
print_result(scan_result)
