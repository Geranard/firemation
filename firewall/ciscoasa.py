from netmiko import ConnectHandler
from textfsm.parser import TextFSMError

class CiscoASA():
    def __init__(self, ip_address:str, username:str, password:str):
        self.__device = { 
            "device_type": "cisco_asa",
            "host": ip_address,
            "username": username,
            "password": password,
            "secret": password,
            "disabled_algorithms": {
                "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]
            },
        }

    def is_valid(self):
        return self.send_enabled_command("sh run | i host").split()[1]

    def send_enabled_command(self, *commands):
        self.__net_connect = ConnectHandler(**self.__device)
        self.__net_connect.enable()

        output = ""

        for command in commands:
            try:
                output = self.__net_connect.send_command(
                    command,
                    use_textfsm=True,
                    expect_string=r"#"
                )
            except TextFSMError:
                output = self.__net_connect.send_command(
                    command,
                    expect_string=r"#"
                )

        self.__net_connect.disconnect()
        return output

    def read_acl(self):
        return self.send_enabled_command("show access-list")

    def read_specific_acl(self, acl_name):
        return self.send_enabled_command(f"show access-list {acl_name} | include ^access-list.+ line\ [0-9]+\ .+$")

    def commit_changes(self):
        return self.send_enabled_command("write")

    def get_object_group(self):
        commands = ["show object-group"]
        output = self.send_enabled_command(*commands)
        return output

    def extract_object_group(self, obj_grp):
        commands = ["conf t", f"show object-group id {obj_grp}"]
        output = self.send_enabled_command(*commands)
        output = output.split("\n")
        result = {}
        current_object = ""
        for o in output:
            temp_result = o.split(" ")
            temp_result = [t for t in temp_result if t != ""]

            if("object-group" in temp_result and "network" in temp_result):
                current_object = temp_result[2]
                result[current_object] = []

            if("network-object" in temp_result):
                result[current_object].append(f"{temp_result[-2]} {temp_result[-1]}")

            if("object-group" in temp_result and "service" in temp_result):
                current_object = temp_result[2]
                result[current_object] = []

            if("service-object" in temp_result and "eq" in temp_result):
                result[current_object].append(f"{temp_result[-4]}-{temp_result[-1]}")
            elif("service-object" in temp_result and not "eq" in temp_result):
                result[current_object].append(f"{temp_result[-1]}")

        return result

    def get_latest_object(self):
        result = self.get_object_group().split("\n")
        obj_group = {}
        obj_name = ""
        obj_ctr = {}
        latest_num = {}

        for res in result:
            temp_res = res.split(" ")

            if(temp_res[0] == ""):
                obj_group[obj_name]["objects"].append(" ".join(temp_res[2:]))

            elif(temp_res[0] == "object-group"):
                if(obj_name != "" and obj_name != "TCPUDP"):
                    if(len(obj_name.split("_")) > 2):
                        obj_ctr[obj_name.split("_")[-2]] = []
                        latest_num[obj_name.split("_")[-2]] = 0

                obj_name = temp_res[2]
                obj_group[obj_name] = {}
                obj_group[obj_name]["type"] = temp_res[1]
                obj_group[obj_name]["objects"] = []

        for obj_name, value in obj_group.items():
            temp_name = obj_name.split("_")
            if(len(temp_name) > 2):
                obj_type = temp_name[-2]
                obj_num = int(temp_name[-1])
                obj_ctr[obj_type].append(obj_num)

        for obj_name, nums in obj_ctr.items():
            nums.sort()
            intended_num = -1

            for ctr, num in zip(range(1, nums[-1]+1), nums):
                if(ctr != num):
                    intended_num = ctr
                    break

            if(intended_num == -1):
                intended_num = nums[-1] + 1

            latest_num[obj_name] = intended_num

        return latest_num
    
    def parsing_csv(self, element):
        if(element != ""):
            if("," in element):
                element = element.split(",")
            else:
                element = [f"{element}"]
        else:
            element = []

        element = [e.replace("'", "").replace("[", "").replace("]", "") for e in element]
        return element

    def find_netmask(self, ip_address):
        ip_address = ip_address.split("/")
        netmask = ip_address[1]
        ip_address = ip_address[0]

        mask_num = (0xffffffff >> (32 - int(netmask))) << (32 - int(netmask))
        netmask = str( (0xff000000 & mask_num) >> 24) + "." + str( (0x00ff0000 & mask_num) >> 16) + "." + str( (0x0000ff00 & mask_num) >> 8) + "." + str( (0x000000ff & mask_num))

        return ip_address, netmask

    def net_obj_commands(self, ip_address, latest_obj):
        # latest_obj = self.get_latest_object()
        commands = ["conf t"]
        commands.append(f"object-group network DM_INLINE_NETWORK_{latest_obj['NETWORK']}")

        for ip in ip_address:
            netmask = ""
            if("/" in ip):
                ip, netmask = self.find_netmask(ip)
                command = f"network-object {ip} {netmask}"
            else:
                command = f"network-object host {ip}"

            commands.append(command)

        commands.append("exit")
        commands.append("exit")

        return commands

    def create_acl(self, **kwargs):
        for ctr in range(len(kwargs.get("Interface", {0:"global"}))):
            interface = kwargs.get("Interface", {0:"global"})[ctr]
            action = kwargs.get("Action", {0:"Permit"})[ctr]
            source_ip = kwargs.get("Source", {0:"any"})[ctr]
            user = kwargs.get("User", {0:""})[ctr]
            source_security_group = kwargs.get("Security Group", {0:""})[ctr]
            dest_ip = kwargs.get("Destination", {0:"any"})[ctr]
            dest_security_group = kwargs.get("Security Group.1", {0:""})[ctr]
            service = kwargs.get("Service", {0:"any"})[ctr]
            logging_level = kwargs.get("Logging", {0:""})[ctr]
            description = kwargs.get("Description", {0:""})[ctr]

            source_ip = self.parsing_csv(source_ip)
            user = self.parsing_csv(user)
            source_security_group = self.parsing_csv(source_security_group)
            dest_ip = self.parsing_csv(dest_ip)
            dest_security_group = self.parsing_csv(dest_security_group)
            service = self.parsing_csv(service)

            latest_obj = self.get_latest_object()
            push_rule_command = ["conf t"]
            commands = ["conf t"]
            protocol = ""
            port = ""

            description = description
            description = self.parsing_csv(description)
            for desc in description:
                push_rule_command.append(f"access-list {interface}_access_in remark {desc}")

            push_rule_command.append(f"access-list {interface}_access_in extended {action}")

            # make service object if more than one service
            if(len(service) <= 1):
                service = service[0]
                if("/" in service):
                    service = service.split("/")
                    protocol = service[0]
                    port = service[1]
                push_rule_command[len(push_rule_command)-1] = f"{push_rule_command[len(push_rule_command)-1]} {protocol}"
            else:
                commands.append(f"object-group service DM_INLINE_SERVICE_{latest_obj['SERVICE']}")
                for svc in service:
                    if("/" in svc):
                        svc = svc.split("/")
                        protocol = svc[0]
                        svc = svc[1]
                        commands.append(f"service-object {protocol} destination eq {svc}")
                    else:
                        commands.append(f"service-object {svc}")
            
                commands.append("exit")
                commands.append("exit")
                push_rule_command[len(push_rule_command)-1] = f"{push_rule_command[len(push_rule_command)-1]} object-group DM_INLINE_SERVICE_{latest_obj['SERVICE']}"
                latest_obj["SERVICE"] = latest_obj["SERVICE"] + 1

            # make network object for source and dest ip
            if(len(source_ip) <= 1):
                source_ip = source_ip[0]
                if("/" in source_ip):
                    ip, netmask = self.find_netmask(source_ip)
                    push_rule_command[len(push_rule_command)-1] = f"{push_rule_command[len(push_rule_command)-1]} {ip} {netmask}"
                else:
                    push_rule_command[len(push_rule_command)-1] = f"{push_rule_command[len(push_rule_command)-1]} host {source_ip}"
            else:
                temp_commands = self.net_obj_commands(source_ip, latest_obj)
                for c in temp_commands:
                    commands.append(c)
                push_rule_command[len(push_rule_command)-1] = f"{push_rule_command[len(push_rule_command)-1]} object-group DM_INLINE_NETWORK_{latest_obj['NETWORK']}"
                latest_obj["NETWORK"] = latest_obj["NETWORK"] + 1

            if(len(dest_ip) <= 1):
                dest_ip = dest_ip[0]
                if("/" in dest_ip):
                    ip, netmask = self.find_netmask(dest_ip)
                    push_rule_command[len(push_rule_command)-1] = f"{push_rule_command[len(push_rule_command)-1]} {ip} {netmask}"
                else:
                    push_rule_command[len(push_rule_command)-1] = f"{push_rule_command[len(push_rule_command)-1]} host {dest_ip}"
            else:
                temp_commands = self.net_obj_commands(dest_ip, latest_obj)
                for c in temp_commands:
                    commands.append(c)
                push_rule_command[len(push_rule_command)-1] = f"{push_rule_command[len(push_rule_command)-1]} object-group DM_INLINE_NETWORK_{latest_obj['NETWORK']}"
                latest_obj["NETWORK"] = latest_obj["NETWORK"] + 1

            if(port != ""):
                push_rule_command[len(push_rule_command)-1] = f"{push_rule_command[len(push_rule_command)-1]} eq {port}"

            if(logging_level != ""):
                push_rule_command[len(push_rule_command)-1] = f"{push_rule_command[len(push_rule_command)-1]} log {logging_level}"
            
            push_rule_command.append(f"access-group {interface}_access_in in interface {interface}")
            push_rule_command.append("exit")
            push_rule_command.append("write")

            for c in push_rule_command:
                commands.append(c)
            
            self.send_enabled_command(*commands)

    