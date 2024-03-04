from fortiosapi import FortiOSAPI
import pandas as pd

class Fortinet():
    def __init__(self, ip_address:str, username:str, password:str, verify:bool, vdom:str, https:str):
        self.__fortigate = FortiOSAPI()

        self.__device = {
            "host": ip_address,
            "username": username,
            "password": password,
            "verify": verify, 
            "vdom": vdom,
        }
        self.__fortigate.https(https)

    def is_valid(self):
        self.__fortigate.login(**self.__device)
        return self.__fortigate.check_session()

    def get_all_services(self):
        all_services = self.__fortigate.get(path="firewall.service", name="custom", vdom="root")
        all_services = [s["q_origin_key"] for s in all_services["results"]]

    def cidr_to_netmask(self, cidr):
        temp_ip = []
        if("list" in str(type(cidr))):
            for ip in cidr:
                if("/" in ip):
                    ip = ip.split("/")
                    ip[1] = (0xffffffff >> (32 - int(ip[1]))) << (32 - int(ip[1]))
                    ip[1] = str( (0xff000000 & ip[1]) >> 24) + "." + str( (0x00ff0000 & ip[1]) >> 16) + "." + str( (0x0000ff00 & ip[1]) >> 8) + "." + str( (0x000000ff & ip[1]))
                    ip = f"{ip[0]} {ip[1]}"
                else:
                    ip = f"{ip} 255.255.255.255"
                temp_ip.append({"name": ip})
        else:
            if("/" in cidr):
                cidr = cidr.split("/")
                cidr[1] = (0xffffffff >> (32 - int(cidr[1]))) << (32 - int(cidr[1]))
                cidr[1] = str( (0xff000000 & cidr[1]) >> 24) + "." + str( (0x00ff0000 & cidr[1]) >> 16) + "." + str( (0x0000ff00 & cidr[1]) >> 8) + "." + str( (0x000000ff & cidr[1]))
                cidr = f"{cidr[0]} {cidr[1]}"
            else:
                cidr = f"{cidr} 255.255.255.255"
            temp_ip.append({"name": cidr})

        return temp_ip

    def create_acl(self, **kwargs):
        self.__fortigate.login(**self.__device)

        rules = self.read_acl()
        policyid = len(rules["results"]) + 1
        rule_name = kwargs.get("name", "")
        description = kwargs.get("description", "")

        service = kwargs.get("service", "")
        if("str" in str(type(service))):
            service = [service]
        service = list(dict.fromkeys(service))

        ports = pd.read_csv("./known_ports.csv")
        ports = ports.to_dict()
        ports = {ports["service"][ctr]: ports["port"][ctr] for ctr in range(len(ports["service"]))}

        valid_services = pd.read_csv("./known_ports.csv")
        valid_services = valid_services.to_dict()
        valid_ports = {}
        temp_service = []
        for ctr in range(len(valid_services["service"])):
            if(not "nan" in str(valid_services["service"][ctr])):
                if(not "nan" in str(valid_services["port"][ctr])):
                    valid_ports[valid_services["service"][ctr].lower()] = valid_services["port"][ctr]

                temp_service.append(valid_services["service"][ctr])

        valid_services = temp_service

        temp_service = []
        for svc in service:
            svc = svc.upper()

            all_services = self.__fortigate.get(path="firewall.service", name="custom", vdom="root")
            all_services = [s["q_origin_key"] for s in all_services["results"]]

            service_obj = {}

            service_name = ""

            if("/" in svc):
                svc = svc.split("/")
                protocol = svc[0].lower()
                port = svc[1].lower()

                service_name = f"{protocol.upper()}-{port}"
                if(service_name in all_services):
                    temp_service.append(service_name)
                    continue
                elif(service_name.lower() in all_services):
                    temp_service.append(service_name.upper())
                    continue
                elif(port.upper() in all_services):
                    temp_service.append(port.upper())
                    continue

                if(protocol == "tcp" or protocol == "udp" or protocol == "tcp-udp" or protocol == "icmp"):
                    if(port in all_services):
                        temp_service.append(port)

                    elif("-" in port):
                        port = port.split("-")
                        if(port[0].isdigit() and port[1].isdigit() and int(port[0]) > 0 and int(port[0]) < 65536 and int(port[1]) > 0 and int(port[1]) < 65536):
                            service_obj["name"] = f"{protocol.upper()}-{port[0]}-{port[1]}"
                            service_obj["type"] = f"{protocol}"
                            service_obj[f"{protocol}-portrange"] = f"{port[0]}-{port[1]}"
                            temp_service.append(service_obj["name"])
                            output = self.__fortigate.post(path="firewall.service", name="custom", mkey=f"{service_obj['name']}", vdom="root", data=service_obj)

                    elif(port.isdigit() and int(port) > 0 and int(port) < 65536):
                        service_obj["name"] = f"{protocol.upper()}-{port.upper()}"
                        service_obj["type"] = f"{protocol}"
                        service_obj[f"{protocol}-portrange"] = f"{port.upper()}"
                        temp_service.append(service_obj["name"])
                        output = self.__fortigate.post(path="firewall.service", name="custom", mkey=f"{service_obj['name']}", vdom="root", data=service_obj)
                    
                    elif(port.isalpha() and port.lower() in valid_services):
                        temp_port = ""
                        temp_port = valid_ports[port.lower()]
                        if("," in valid_ports):
                            temp_port = valid_ports.split(",")
                            service_obj["name"] = f"{protocol.upper()}-{port.upper()}"
                            service_obj["type"] = f"{protocol}"
                            temp_service.append(service_obj["name"])
                            service_obj[f"{protocol}-portrange"] = []
                            for tp in temp_port:
                                service_obj[f"{protocol}-portrange"].append(f"{tp.upper()}")
                            temp_service.append(service_obj["name"])
                            output = self.__fortigate.post(path="firewall.service", name="custom", mkey=f"{service_obj['name']}", vdom="root", data=service_obj)
                        else:
                            service_obj["name"] = f"{protocol.upper()}-{port.upper()}"
                            service_obj["type"] = f"{protocol}"
                            service_obj[f"{protocol}-portrange"] = f"{port.upper()}"
                            temp_service.append(service_obj["name"])
                            output = self.__fortigate.post(path="firewall.service", name="custom", mkey=f"{service_obj['name']}", vdom="root", data=service_obj)

            else:
                if(svc.lower() == "tcp-udp"):
                    temp_service.append("ALL_TCP")
                    temp_service.append("ALL_UDP")
                elif(svc.lower() == "icmp"):
                    temp_service.append("ALL_ICMP")
                elif(svc.lower() == "ip"):
                    temp_service.append("ALL_TCP")
                    temp_service.append("ALL_UDP")
                    temp_service.append("ALL_ICMP")


        temp_service = list(dict.fromkeys(temp_service))
        service = [{"name": svc} for svc in temp_service]

        if(len(description) > 0):
            rule_name = description[0]
            if(len(description) > 1):
                desc = ""
                for d in description:
                    desc = f"{desc} {d}"
                description = desc

        if(rule_name == ""):
            rule_name = f"rules-{policyid}"
        
        if("[" in rule_name):
            rule_name = rule_name.replace("[", "").replace("]", "")

        intf = kwargs.get("interface", "").lower()
        dest_intf = kwargs.get("dest_interface", "")

        ip_src = kwargs.get("source", "")
        ip_dest = kwargs.get("destination", "")

        ip_src = self.cidr_to_netmask(ip_src)
        ip_dest = self.cidr_to_netmask(ip_dest)

        action = kwargs.get("action", "deny")
        if(action.lower() == "permit"):
            action = "accept"
        else:
            action = action.lower()

        temp_addr = []
        for addr in ip_src:
            address_obj = {
                "name": addr["name"],
                "type": "subnet",
                "subnet": addr["name"],
                "port": intf
            }
            temp_addr.append(addr["name"])

            self.__fortigate.set(path="firewall", name="address", vdom="root", data=address_obj)
        ip_src = [{"name": t} for t in temp_addr]

        temp_addr = []
        for addr in ip_dest:
            address_obj = {
                "name": addr["name"],
                "type": "subnet",
                "subnet": addr["name"],
                "port": intf
            }
            temp_addr.append(addr["name"])

            self.__fortigate.set(path="firewall", name="address", vdom="root", data=address_obj)
        ip_dest = [{"name": t} for t in temp_addr]
        
        data = {
            "policyid": policyid,
            "name": rule_name,
            "srcintf": [{"name": intf}],
            "dstintf": dest_intf,
            "schedule": kwargs.get("schedule", "always"),
            "service": service,
            "action": action,
            "srcaddr": ip_src,
            "dstaddr": ip_dest,
            "inspection_mode": "flow-based",
            "profile-type": "single",
            "utm-status": "disable",
            "profile-protocol-options": "default",
            "ssl-ssh-profile": "no-inspection",
            "av-profile": "",
            "rtp-nat": "disable",
            "logtraffic": "all",
        }

        output = self.__fortigate.set(path="firewall", name="policy", vdom="root", data=data)
        try:
            if(output["error"] == -651):
                data["name"] = f"{data['name']}-duplicate{policyid}"
                output = self.__fortigate.set(path="firewall", name="policy", vdom="root", data=data)
        except KeyError:
            ''''''

    def read_acl(self):
        self.__fortigate.login(**self.__device)
        output = self.__fortigate.get(path="firewall", name="policy")
        return output

    def update_acl(self, data):
        self.__fortigate.login(**self.__device)
        output = ""
        for opt, val in data.items():
            for user_input in val:
                user_input_field = user_input["field"]
                user_input_input = user_input["input"]
                input_type = str(type(user_input["input"]))

                if("list" in input_type):
                    temp_result = {}
                    if("intf" in user_input_field):
                        temp_result[user_input_field] = [{"name": intf} for intf in user_input_input]

                    if("addr" in user_input_field):
                        temp_result[user_input_field] = self.cidr_to_netmask(user_input_input)

                    if("action" in user_input_field):
                        user_input_input = user_input_input.lower()
                        if("permit" in user_input_input):
                            user_input_input = "allow"
                        temp_result[user_input_field] = user_input_input

                    if("service" in user_input_field):
                        temp_result[user_input_field] = [{"name": svc} for svc in user_input_input]

                    output = self.__fortigate.set(path="firewall", name="policy", mkey=f"{opt}", data=temp_result)

                else:
                    temp_result = {}
                    if("intf" in user_input_field):
                        temp_result[user_input_field] = [{"name": user_input_input}]

                    if("addr" in user_input_field):
                        temp_result[user_input_field] = self.cidr_to_netmask([user_input_input])

                    if("action" in user_input_field):
                        user_input_input = user_input_input.lower()
                        if("permit" in user_input_input):
                            user_input_input = "allow"
                        temp_result[user_input_field] = user_input_input

                    if("service" in user_input_field):
                        temp_result[user_input_field] = [{"name": user_input_input}]

                    output = self.__fortigate.set(path="firewall", name="policy", mkey=f"{opt}", data=temp_result)

        self.__fortigate.logout()

    def delete_acl(self, options):
        self.__fortigate.login(**self.__device)
        for opt in options:
            output = self.__fortigate.delete(path="firewall", name="policy", mkey=f"{opt}")

    def logout(self):
        self.__fortigate.logout()

