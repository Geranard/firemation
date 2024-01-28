from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule
from panos.objects import ServiceObject
import pandas as pd

class PaloAlto():
    def __init__(self, ip_address:str, username:str, password:str):
        self.__panfw = Firewall(ip_address, username, password)
        self.__rulebase = self.__panfw.add(Rulebase())

    def is_valid(self):
        return self.__panfw.refresh_system_info()

    def read_acl(self):
        result = SecurityRule.refreshall(self.__rulebase)
        rules = []
        for rule in result:
            rules.append(rule.about())

        return rules
    
    def create_service_obj(self, **kwargs):
        new_svc = {
            "name": kwargs.get("name", ""),
            "protocol": kwargs.get("protocol", ""),
            "destination_port": kwargs.get("destination_port", ""),
        }

        new_svc = ServiceObject(**new_svc)
        self.__panfw.add(new_svc).create()

    def create_acl(self, **kwargs):
        description = kwargs.get("description", [""])
        rule_name = ""

        if(len(description) > 0):
            rule_name = description[0]

        rule_name = rule_name.replace("'", "").replace("[", "").replace("]", "")

        rules = []
        rules = self.read_acl()
        names = [n["name"] for n in rules]
        if(rule_name == ""):
            rule_length = len(rules) + 1
            rule_name = f"rule-{rule_length}"
        if(rule_name in names):
            rule_length = len(rules) + 1
            rule_name = f"{rule_name}-duplicate-{rule_length}"

        ip_src = kwargs.get("source", ["any"])
        if("," in ip_src):
            ip_src = ip_src.split(",")

        ip_dest = kwargs.get("destination", ["any"])
        if("," in ip_dest):
            ip_dest = ip_dest.split(",")

        service = kwargs.get("service", ["any"])

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

        if("," in service):
            service = service.split(",")

        if("str" in str(type(service))):
            service = [service]

        temp_service = []
        for svc in service:
            temp_dict = {"name": "", "protocol": "", "destination_port": ""}

            if("/" in svc):
                svc = svc.split("/")
                protocol = svc[0].lower()
                port = svc[1].lower()

                if(protocol == "tcp" or protocol == "udp" or protocol == "tcp-udp" or protocol == "icmp"):
                    if("-" in port):
                        port = port.split("-")
                        if(port[0].isdigit() and port[1].isdigit() and int(port[0]) > 0 and int(port[0]) < 65536 and int(port[1]) > 0 and int(port[1]) < 65536):
                            temp_dict["name"] = f"{protocol.upper()}-{port[0]}-{port[1]}"
                            temp_dict["protocol"] = f"{protocol.lower()}"
                            temp_dict["destination_port"] = f"{port[0]}-{port[1]}"
                            temp_service.append(temp_dict["name"])
                            self.create_service_obj(**temp_dict)

                    elif(port.isdigit() and int(port) > 0 and int(port) < 65536):
                        temp_dict["name"] = f"{protocol.upper()}-{port.upper()}"
                        temp_dict["protocol"] = f"{protocol.lower()}"
                        temp_dict["destination_port"] = f"{port}"
                        temp_service.append(temp_dict["name"])
                        self.create_service_obj(**temp_dict)

                    elif(port.isalpha() and port.lower() in valid_services):
                        temp_port = ""
                        temp_port = valid_ports[port.lower()]
                        if("," in valid_ports):
                            temp_port = valid_ports.split(",")
                            temp_dict["name"] = f"{protocol.upper()}-{port.upper()}"
                            temp_dict["protocol"] = f"{protocol.lower()}"
                            temp_dict["destination_port"] = ""
                            for tp in temp_port:
                                temp_dict["destination_port"] = f"{temp_dict['destination_port']},{tp.upper()}"
                            temp_service.append(temp_dict["name"])
                            self.create_service_obj(**temp_dict)

                        else:
                            temp_dict["name"] = f"{protocol.upper()}-{port.upper()}"
                            temp_dict["protocol"] = f"{protocol.lower()}"
                            temp_dict["destination_port"] = f"{temp_port}"
                            temp_service.append(temp_dict["name"])
                            self.create_service_obj(**temp_dict)

            else:
                if(svc.lower() == "tcp-udp"):
                    temp_dict = {
                        "name": "ALL-TCP",
                        "protocol": "tcp",
                        "destination_port": "1-65535",
                    }
                    self.create_service_obj(**temp_dict)

                    temp_dict = {
                        "name": "ALL-UDP",
                        "protocol": "udp",
                        "destination_port": "1-65535",
                    }
                    self.create_service_obj(**temp_dict)

                    temp_service.append("ALL-TCP")
                    temp_service.append("ALL-UDP")

                # elif(svc.lower() == "icmp"):
                #     temp_dict = {
                #         "name": "ALL-ICMP",
                #         "protocol": "icmp",
                #         "destination_port": "1-65535",
                #     }
                #     self.create_service_obj(**temp_dict)

                #     temp_service.append("ALL-ICMP")

                elif(svc.lower() == "ip"):
                    temp_dict = {
                        "name": "ALL-TCP",
                        "protocol": "tcp",
                        "destination_port": "1-65535",
                    }
                    self.create_service_obj(**temp_dict)

                    temp_dict = {
                        "name": "ALL-UDP",
                        "protocol": "udp",
                        "destination_port": "1-65535",
                    }
                    self.create_service_obj(**temp_dict)

                    temp_dict = {
                        "name": "ALL-ICMP",
                        "protocol": "icmp",
                        "destination_port": "1-65535",
                    }
                    self.create_service_obj(**temp_dict)

                    # temp_dict = {
                    #     "name": "ALL-ICMP",
                    #     "protocol": "icmp",
                    #     "destination_port": "1-65535",
                    # }
                    # self.create_service_obj(**temp_dict)

                    temp_service.append("ALL-TCP")
                    temp_service.append("ALL-UDP")
                    # temp_service.append("ICMP")

        service = temp_service

        temp_desc = ""
        for desc in description:
            temp_desc = f"{temp_desc} {desc}"

        description = temp_desc

        new_rule = {
            "name": rule_name,
            "fromzone": kwargs.get("fromzone", ["any"]),
            "tozone": kwargs.get("tozone", ["any"]),
            "source": ip_src,
            "destination": ip_dest,
            "service": service,
            "action": kwargs.get("action", "deny"),
            "application": kwargs.get("application", ["any"]),
            "category": kwargs.get("category", []),
            "hip_profiles": kwargs.get("hip_profiles", "any"),
            "source_user": kwargs.get("source_user", "any"),
            "log_setting": kwargs.get("log_setting", None),
            "log_start": kwargs.get("log_start", False),
            "log_end": kwargs.get("log_end", False),
            "description": kwargs.get("description", "universal"),
            "tag": kwargs.get("tag", []),
            "negate_source": kwargs.get("negate_source", False),
            "negate_destination": kwargs.get("negate_destination", False),
            "disabled": kwargs.get("disabled", False),
            "schedule": kwargs.get("schedule", None),
            "icmp_unreachable": kwargs.get("icmp_unreachable", False),
            "disable_server_response_inspection": kwargs.get("disable_server_response_inspection", False),
            "group": kwargs.get("group", None),
            "negate_target": kwargs.get("negate_target", None),
            "target": kwargs.get("target", None),
            "virus": kwargs.get("virus", None),
            "spyware": kwargs.get("spyware", None),
            "vulnerability": kwargs.get("vulnerability", None),
            "url_filtering": kwargs.get("url_filtering", None),
            "file_blocking": kwargs.get("file_blocking", None),
            "wildfire_analysis": kwargs.get("wildfire_analysis", None),
            "data_filtering": kwargs.get("data_filtering", None),
            "source_devices": kwargs.get("source_devices", None),
            "destination_devices": kwargs.get("destination_devices", None),
            "group_tag": kwargs.get("group_tag", None),
        }

        new_rule = SecurityRule(**new_rule)

        self.__rulebase.add(new_rule)
        new_rule.create()

    def update_acl(self, data):
        result = SecurityRule.refreshall(self.__rulebase)
        num_before = 0
        flag = False

        for opt, val in data.items():
            if(flag == True): 
                opt = num_before

            flag = False
            num_before = opt

            for user_input in val:
                user_input_field = user_input["field"]
                user_input_input = user_input["input"]
                input_type = str(type(user_input["input"]))

                if(user_input_field == "name" and user_input_input != result[opt].name):
                    self.delete_acl([opt])
                    flag = True
                    opt = len(result) - 1

                if("list" in input_type):
                    temp_result = [u for u in user_input_input]
                    setattr(result[opt], user_input_field, temp_result)
                    result[opt].apply()

                else:
                    setattr(result[opt], user_input_field, user_input_input)
                    result[opt].apply()

    def delete_acl(self, options):
        result = SecurityRule.refreshall(self.__rulebase)
        for opt in options:
            result[opt].delete()

    def commit_changes(self):
        self.__panfw.commit()