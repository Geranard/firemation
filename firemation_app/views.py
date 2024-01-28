# import basic python
import os
import dotenv
import pandas as pd
import io
import ipaddress

# import django
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views.generic import TemplateView
from django.db import IntegrityError

# import firewalls, netbox, and DB
from firewall.paloaltonetworks import PaloAlto
from firewall.ciscoasa import CiscoASA
from firewall.fortinet import Fortinet
from firemation_app.models import User, Firewall
from cryptography.fernet import Fernet
import pynetbox

# import errors
from netmiko.exceptions import NetMikoAuthenticationException, NetMikoTimeoutException
from urllib3.exceptions import ConnectTimeoutError
from fortiosapi import NotLogged
from panos.errors import PanURLError
from django.utils.datastructures import MultiValueDictKeyError
from requests.exceptions import ConnectTimeout

# ==================== init var
dotenv.load_dotenv()
key = os.getenv("FIREMATION_FERNET_KEY").encode()
fernet = Fernet(key)
nb_ip = os.getenv("FIREMATION_NETBOX_IP")
nb_port = os.getenv("FIREMATION_NETBOX_PORT")
nb_secret = os.getenv("FIREMATION_NETBOX_SECRET_KEY")
nb = pynetbox.api(f"{nb_ip}:{nb_port}", f"{nb_secret}")

error_message_template = {
    "input_error": "Error on input. Please input mindfully.",
    "credential_error": "Error on credentials. Please go to Credential Management page.",
    "already_exists_error": "IP is already used. Please choose another options.",
    "authentication_error": "Error on authentication. Please go to Credential Management page, recheck the IP on the Netbox, or Check if Firewall is on.",
    "no_valid_ip": "There is no valid IP address or the IP is not correct. Please input mindfully",
    "no_valid_service": "There is no valid service or the service is not correct. Please check known_ports.csv or check the input.",
    "no_valid_action": "Only use Permit/Deny in the service column.",
}

# ==================== basic function

class CsvUploader(TemplateView):
    template_name = "create.html"
    def post(self, request):
        csv_file = request.FILES["csv"]
        result = pd.read_csv(
            io.StringIO(
                csv_file.read().decode("utf-8")
            )
        )

        for key, res in result.items():
            result[key] = result[key].fillna("")

        result = result.to_dict()

        checks = ["Source","Destination","Service","Action","Description"]
        key_to_checks = [key for key, value in result.items()]
        for ctr in range(len(checks)):
            if(not checks[ctr] in key_to_checks):
                return False

        return result


def encrypt_credentials(password):
    return fernet.encrypt(password).decode()


def decrypt_credentials(password):
    return fernet.decrypt(password.encode()).decode()


def access_firewall_details(fw_option):
    if("-" in fw_option):
        fw_option = str(fw_option.split("-")[1])

    fw_instance = Firewall.objects.get(firewall_ip=fw_option)
    fw_vendor = str(fw_instance.firewall_vendor)

    fw_user = User.objects.filter(firewall=fw_option, selected=True)
    username = str(fw_user[0].username)
    password = decrypt_credentials(str(fw_user[0].password))

    return fw_option, fw_vendor, username, password


# different version, different column name
def extracting_rules(fw_option, fw_vendor, username, password):
    result = {"column_name": [], "rules": [], "real_column_name": []}

    if(fw_vendor == "Cisco ASA"):
        asa = CiscoASA(fw_option, username, password)
        rules = asa.read_acl()
        result["column_name"] = []
        result["rules"] = []
        acl_name = [rule["acl_name"] for rule in rules]
        acl_name = list(dict.fromkeys(acl_name))

        for acl in acl_name:
            rule = asa.read_specific_acl(acl)
            remark = []
            temp_dict = {}

            for r in rule:
                if(len(r["remark"]) > 0):
                    remark.append(r["remark"])
                else:
                    temp_dict["ACL Name"] = r["acl_name"]

                    if(len(r["src_object_grp"]) > 0):
                        temp_host = asa.extract_object_group(r["src_object_grp"])
                        temp_dict["Source Host"] = [value for key, value in temp_host.items()][0]
                    elif(r['src_host'] == ""):
                        temp_dict["Source Host"] = f"{r['src_network']} {r['src_mask']}"
                    else:
                        temp_dict["Source Host"] = f"host {r['src_host']}"

                    if(len(r["dst_object_grp"]) > 0):
                        temp_host = asa.extract_object_group(r["dst_object_grp"])
                        temp_dict["Destination Host"] = [value for key, value in temp_host.items()][0]
                    elif(r['dst_host'] == ""):
                        temp_dict["Destination Host"] = f"{r['dst_network']} {r['dst_mask']}"
                    else:
                        temp_dict["Destination Host"] = f"host {r['dst_host']}"
                            
                    
                    if(len(r["svc_object_grp"]) > 0):
                        temp_service = asa.extract_object_group(r["svc_object_grp"])
                        temp_dict["Service"] = [value for key, value in temp_service.items()][0]
                    else:
                        temp_dict["Service"] = r["svc_object"]

                    if(len(r["action"]) > 0):
                        temp_dict["Action"] = r["action"]

                    temp_dict["Remark"] = remark
                    remark = []

                    result["rules"].append(temp_dict)
                    temp_dict = {}

        try:
            result["real_column_name"] = [key for key, value in result["rules"][0].items()]
        except IndexError:
            ''''''
        result["column_name"] = ["ACL Name", "Source Address", "Destination Address", "Service", "Action", "Remark"]

    elif(fw_vendor == "Fortinet"):
        fortinet = Fortinet(fw_option, username, password, False, "root", "off")
        rules = fortinet.read_acl()
        rules = rules["results"]
        fortinet.logout()
        for rule in rules:
            temp_dict = {
                "srcintf": [r["q_origin_key"] for r in rule["srcintf"]],
                "srcaddr": [r["q_origin_key"] for r in rule["srcaddr"]],
                "dstintf": [r["q_origin_key"] for r in rule["dstintf"]],
                "dstaddr": [r["q_origin_key"] for r in rule["dstaddr"]],
                "service": [r["q_origin_key"] for r in rule["service"]],
                "action": rule["action"],
                "name": rule["name"]
            }
            result["rules"].append(temp_dict)

        try:
            result["real_column_name"] = [key for key, value in result["rules"][0].items()]
        except IndexError:
            ''''''
        result["column_name"] = ["Source Interface", "Source Address", "Destination Interface", "Destination Address", "Service", "Action", "Name"]

    elif(fw_vendor == "Palo Alto Networks"):
        pan = PaloAlto(fw_option, username, password)
        rules = pan.read_acl()
        
        for rule in rules:
            temp_dict = {
                "fromzone": rule["fromzone"],
                "source": rule["source"],
                "tozone": rule["tozone"],
                "destination": rule["destination"],
                "service": rule["service"],
                "action": rule["action"],
                "name": rule["name"]
            }
            result["rules"].append(temp_dict)
        
        try:
            result["real_column_name"] = [key for key, value in result["rules"][0].items()]
        except IndexError:
            ''''''
        result["column_name"] = ["Source Zone", "Source Address", "Destination Zone", "Destination Address", "Service", "Action", "Name"]

    return result


def get_all_firewall_ip_from_db():
    fw_instance = Firewall.objects.all()
    fw_ip = [f.firewall_ip for f in fw_instance]
    return fw_ip


def get_all_firewall_ip_from_netbox():
    fw_ip = nb.ipam.ip_addresses.all()
    fw_ip = [f for f in fw_ip if dict(f)["custom_fields"]["Firewall"] == True]

    temp_f = []

    for f in fw_ip:
        f = str(f)
        if("/" in f):
            temp_f.append(f.split("/")[0])
        else:
            temp_f.append(f)

    return temp_f


def is_credential_valid(fw_option, fw_vendor, username, password):
    if(fw_vendor == "Cisco ASA"):
        try:
            asa = CiscoASA(fw_option, username, password)
            asa.is_valid()

        except NetMikoAuthenticationException:
            return False
        
        except NetMikoTimeoutException:
            return False

    elif(fw_vendor == "Fortinet"):
        try:
            fortinet = Fortinet(fw_option, username, password, False, "root", "off")
            fortinet.is_valid()
            fortinet.logout()
        except NotLogged:
            return False
        
        except ConnectTimeoutError:
            return False
        
        except ConnectTimeout:
            return False

    elif(fw_vendor == "Palo Alto Networks"):
        try:
            pan = PaloAlto(fw_option, username, password)
            pan.is_valid()
        
        except PanURLError:
            return False

    return True


def check_authentication():
    firewall_ip = get_all_firewall_ip_from_db()

    for ip in firewall_ip:
        try:
            fw_option, fw_vendor, username, password = access_firewall_details(ip)

            is_valid = is_credential_valid(fw_option, fw_vendor, username, password)
            if(is_valid == False):
                return False

        except IndexError:
            return False

    return True


def input_validation(page, **kwargs):
    all_fw_ip = get_all_firewall_ip_from_netbox()
    if(page == "register_firewall"):
        firewall_name = kwargs.get("firewall_name", "")
        firewall_vendor = kwargs.get("firewall_vendor", "")
        firewall_ip = kwargs.get("firewall_ip", "")

        if(firewall_name == "" or firewall_vendor == "" or firewall_ip == ""):
            return False
 
        if(not(firewall_vendor == "Cisco ASA" or firewall_vendor == "Fortinet" or firewall_vendor == "Palo Alto Networks")):
            return False

        if(not firewall_ip in all_fw_ip):
            return False

    if(page == "choose_credential"):
        user = User.objects.all()
        user = [u.id for u in user]
        checks = kwargs.get("checks", "")
        for c in checks:
            if(not c in user):
                return False

    if(page == "register_credential"):
        username = kwargs.get("username", "")
        password = kwargs.get("password", "")
        firewall_ip = kwargs.get("firewall_ip", "")

        if(username == "" or password == "" or firewall_ip == ""):
            return False
        
        if(not firewall_ip in all_fw_ip):
            return False
        
        fw_instance = Firewall.objects.get(firewall_ip=firewall_ip)
        fw_vendor = fw_instance.firewall_vendor

        is_valid = is_credential_valid(firewall_ip, fw_vendor, username, decrypt_credentials(password))
        
        if(is_valid == False):
            return False

    # if(page == "create_rule"):
    # if(page == "read_rule"):
    # if(page == "update_rule"):
    # if(page == "delete_rule"):

    return True


def rollback():
    pass


# ==================== views
def start_view(request):
    return redirect(reverse("firemation_app:menu"))


def firewall_management_view(request):
    fw_instance = Firewall.objects.all()
    fw_instance = [{"firewall_ip": fw.firewall_ip, "firewall_name": fw.firewall_name, "firewall_vendor": fw.firewall_vendor} for fw in fw_instance]
    context = {
        "firewall": fw_instance,
        "column_name": ["Firewall IP", "Firewall Vendor", "Firewall Name"]
    }

    if(request.POST):
        checks = list(request.POST.getlist("checks"))
        if(len(checks) > 0):
            checks = [str(c.split("-")[1]) for c in checks]
            for c in checks:
                fw_user = User.objects.filter(firewall=c)
                if(len(fw_user) > 0):
                    for u in fw_user:
                        u.delete()
                fw_instance = Firewall.objects.get(firewall_ip=c)
                fw_instance.delete()
            
            return redirect(reverse("firemation_app:firewall_management"))
        else:
            context["success"] = False
            context["error_message"] = "No firewall chosen."
            return render(request, "firewall_management.html", context=context)

    return render(request, "firewall_management.html", context=context)


def register_firewall_view(request):
    context = {}
    if request.POST:
        firewall_ip = request.POST["firewall-ip"]
        firewall_name = request.POST["firewall-name"]
        firewall_vendor = request.POST["firewall-vendor"]

        fw_ip = get_all_firewall_ip_from_netbox()

        context = {
            "firewall_ip": fw_ip
        }

        user_input = {
            "firewall_ip": firewall_ip,
            "firewall_name": firewall_name,
            "firewall_vendor": firewall_vendor
        }

        is_valid = input_validation("register_firewall", **user_input)
        if(is_valid == False):
            context["success"] = False
            context["error_message"] = error_message_template["input_error"]
            return render(request, "register_firewall.html", context=context)

        try:
            fw_ip = get_all_firewall_ip_from_netbox()
            if(not firewall_ip in fw_ip):
                context["success"] = False
                context["error_message"] = error_message_template["no_valid_ip"]
                return render(request, "register_firewall.html", context=context)

            response = list(nb.ipam.ip_addresses.filter(address=firewall_ip).response)
            response = [r["assigned_object"]["device"]["display"].lower() for r in response]
            for r in response:
                if(not (firewall_vendor.lower() in r or r in firewall_vendor.lower())):
                    context["success"] = False
                    context["error_message"] = error_message_template["input_error"]
                    return render(request, "register_firewall.html", context=context)

            Firewall(firewall_ip=firewall_ip, firewall_name=firewall_name, firewall_vendor=firewall_vendor).save()

        except IntegrityError:
            context["success"] = False
            context["error_message"] = error_message_template["already_exists_error"]
            return render(request, "register_firewall.html", context=context)

        context["success"] = True
        context["error_message"] = "Firewall added."
        return render(request, "register_firewall.html", context=context)

    else:
        fw_ip = get_all_firewall_ip_from_netbox()

        context = {
            "firewall_ip": fw_ip
        }

        return render(request, "register_firewall.html", context=context)


def credential_management_view(request):
    context = {
        "firewall": {
            "Cisco ASA": {},
            "Fortinet": {},
            "Palo Alto Networks": {},
        },
    }

    fw_user = User.objects.all()
    fw_instance = Firewall.objects.all()

    for fw in fw_instance:
        context["firewall"][f"{fw.firewall_vendor}"][f"{fw.firewall_ip}"] = []

    for u in fw_user:
        fw_instance = Firewall.objects.filter(firewall_ip=f"{u.firewall}")
        for f in fw_instance:
            context["firewall"][f"{f.firewall_vendor}"][f"{u.firewall}"].append({"id": u.id, "username": u.username, "selected": u.selected})

    if(request.POST):
        checks = request.POST.getlist("checks")
        checks = [int(c.split("-")[1]) for c in checks]

        user_input = {
            "checks": checks
        }

        is_valid = input_validation("choose_credential", **user_input)
        if(is_valid == False):
            context["success"] = False
            context["error_message"] = error_message_template["input_error"]
            return render(request, "credential_management.html", context=context)

        selected_user = User.objects.filter(selected=True)
        for u in selected_user:
            u.selected = False
            u.save()

        for c in checks:
            fw_user = User.objects.get(id=c)
            fw_user.selected = True
            fw_user.save()

        context["success"] = True
        context["error_message"] = "Credential chosen."
        return render(request, "credential_management.html", context=context)

    return render(request, "credential_management.html", context=context)


def register_credential_view(request):
    fw_instance = Firewall.objects.all()
    firewall_ip = [f.firewall_ip for f in fw_instance]

    context = {
        "firewall_ip": firewall_ip
    }

    if(request.POST):
        username = request.POST["username"]
        password = encrypt_credentials(request.POST["password"].encode())
        firewall_ip = ""
        try:
            firewall_ip = request.POST["firewall_ip"].split("-")[1]
        except IndexError:
            context["success"] = False
            context["error_message"] = error_message_template["input_error"]
            return render(request, "register_credential.html", context=context)

        user_input = {
            "username": username,
            "password": password,
            "firewall_ip": firewall_ip,
        }
        is_valid = input_validation("register_credential", **user_input)
        if(is_valid == False):
            context["success"] = False
            context["error_message"] = error_message_template["input_error"]
            return render(request, "register_credential.html", context=context)

        fw_instance = Firewall.objects.get(firewall_ip=firewall_ip)
        fw_user = User.objects.filter(firewall=firewall_ip)
        if(len(fw_user) <= 0):
            User(username=username, password=password, firewall=fw_instance, selected=True).save()
        else:
            User(username=username, password=password, firewall=fw_instance, selected=False).save()

        context["success"] = True
        context["error_message"] = "Credential added."
        return render(request, "register_credential.html", context=context)

    return render(request, "register_credential.html", context=context)


def delete_credential_view(request):
    fw_user = User.objects.all()
    user = [{"id": u.id, "username": u.username, "firewall_ip": u.firewall} for u in fw_user]

    context = {
        "column_name": ["Username", "Firewall IP"],
        "user": user,
    }

    if(request.POST):
        checks = list(request.POST.getlist("checks"))
        if(len(checks) > 0):
            checks = [int(c.split("-")[1]) for c in checks]
            for c in checks:
                fw_user = User.objects.get(id=c)

                if(fw_user.selected == True):
                    fw_instance = Firewall.objects.get(firewall_ip=fw_user.firewall)
                    fw_vendor = fw_instance.firewall_vendor

                    fw_instance = Firewall.objects.filter(firewall_vendor=fw_vendor)
                    temp_user = []
                    for f in fw_instance:
                        temp_user.append(User.objects.filter(firewall=f)[0])

                    for u in range(len(temp_user)):
                        if(temp_user[u].id == c and temp_user[u].selected == True):
                            if(len(temp_user) > 1):
                                temp_user[u+1].selected = True
                                break
                            elif(len(temp_user) == 1):
                                temp_user[0].selected = True

                fw_user.delete()
                return redirect(reverse("firemation_app:delete_credential"))
        else:
            context["success"] = False
            context["error_message"] = "No credential chosen."
            return render(request, "delete_credential.html", context=context)

    return render(request, "delete_credential.html", context=context)


def menu_view(request):
    request.session["firewall_ip"] = None
    return render(request, "menu.html")


def create_rule_view(request):
    context = {}
    is_valid = check_authentication()
    if(is_valid != True):
        context["success"] = False
        context["error_message"] = error_message_template["authentication_error"]
        return render(request, "menu.html", context=context)

    if(request.POST):
        is_valid = check_authentication()
        if(is_valid != True):
            context["success"] = False
            context["error_message"] = error_message_template["authentication_error"]
            return render(request, "menu.html", context=context)

        uploader = CsvUploader()
        rules = uploader.post(request)
        if(rules == False):
            context["success"] = False
            context["error_message"] = error_message_template["no_valid_ip"]
            return render(request, "create.html", context=context)

        ip_src = [rules["Source"][ctr].replace(" ", "") for ctr in range(len(rules["Source"]))]
        ip_dest = [rules["Destination"][ctr].replace(" ", "") for ctr in range(len(rules["Destination"]))]
        service = [rules["Service"][ctr].replace(" ", "") for ctr in range(len(rules["Service"]))]
        action = [rules["Action"][ctr].replace(" ", "") for ctr in range(len(rules["Action"]))]
        description = [rules["Description"][ctr] for ctr in range(len(rules["Description"]))]
        groups = []

        for item in ip_src:
            if(item == ""):
                context["success"] = False
                context["error_message"] = error_message_template["no_valid_ip"]
                return render(request, "create.html", context=context)

        for item in ip_dest:
            if(item == ""):
                context["success"] = False
                context["error_message"] = error_message_template["no_valid_ip"]
                return render(request, "create.html", context=context)

        for item in service:
            if(item == ""):
                context["success"] = False
                context["error_message"] = error_message_template["no_valid_service"]
                return render(request, "create.html", context=context)
        
        for item in action:
            if(item == "" or (not (item.lower() == "permit" or item.lower() == "deny"))):
                context["success"] = False
                context["error_message"] = error_message_template["no_valid_action"]
                return render(request, "create.html", context=context)

        for item in description:
            if(item == ""):
                context["success"] = False
                context["error_message"] = error_message_template["input_error"]
                return render(request, "create.html", context=context)
        
        all_prefixes = nb.ipam.prefixes.all()
        temp_prefixes = []
        for p in all_prefixes:
            try:
                if(dict(p)["custom_fields"]["FWIP"]["display"]):
                    temp_prefixes.append(p["prefix"])
            except TypeError:
                continue
            except ConnectionError:
                context["success"] = False
                context["error_message"] = "Please check if Netbox is on or API key is correct."
                return render(request, "create.html", context=context)
        all_prefixes = temp_prefixes

        valid_src_addr = []
        valid_dest_addr = []

        for src, dest in zip(ip_src, ip_dest):
            src = src.replace(" ", "").replace("'", "")
            dest = dest.replace(" ", "").replace("'", "")

            src = src.split(",")
            dest = dest.split(",")

            temp_valid = []
            for src_addr in src:
                for p in all_prefixes:
                    try:
                        temp_addr1 = ipaddress.ip_network(src_addr)
                        temp_addr2 = ipaddress.ip_network(p)
                        if(temp_addr1.subnet_of(temp_addr2)):
                            temp_valid.append(src_addr)
                            break
                    except ValueError:
                        context["success"] = False
                        context["error_message"] = error_message_template["no_valid_ip"]
                        return render(request, "create.html", context=context)

            valid_src_addr.append(temp_valid)
            temp_valid = []
            for dest_addr in dest:
                for p in all_prefixes:
                    try:
                        temp_addr1 = ipaddress.ip_network(dest_addr)
                        temp_addr2 = ipaddress.ip_network(p)
                        if(temp_addr1.subnet_of(temp_addr2)):
                            temp_valid.append(dest_addr)
                            break
                    except ValueError:
                        context["success"] = False
                        context["error_message"] = error_message_template["no_valid_ip"]
                        return render(request, "create.html", context=context)

            valid_dest_addr.append(temp_valid)

        ip_src = valid_src_addr
        ip_dest = valid_dest_addr
    
        if(len(ip_src) == 0):
            context["success"] = False
            context["error_message"] = error_message_template["no_valid_ip"]
            return render(request, "create.html", context=context)

        if(len(ip_dest) == 0):
            context["success"] = False
            context["error_message"] = error_message_template["no_valid_ip"]
            return render(request, "create.html", context=context)

        valid_services = pd.read_csv("./known_ports.csv")
        valid_services = valid_services.to_dict()
        temp_service = []
        for ctr in range(len(valid_services["service"])):
            if(str(type(valid_services["service"][ctr])) != "nan"):
                temp_service.append(valid_services["service"][ctr])

        valid_services = temp_service
        ctr = 0

        for src, dest in zip(ip_src, ip_dest):
            ip_groups = {}
            dest_groups = []

            for dest_addr in dest:
                dest_groups.append(dest_addr)

            for src_addr in src:
                response = list(nb.ipam.prefixes.filter(src_addr).response)
                for r in response:
                    firewall_ip = r["custom_fields"]["FWIP"]["display"]
                    firewall_src_name = list(nb.dcim.devices.filter(firewall_ip))[0]
                    firewall_src_int = ""

                    if(r["custom_fields"]["FWINT"]):
                        firewall_src_int = r["custom_fields"]["FWINT"]["name"]

                    if(not firewall_ip in ip_groups):
                        ip_groups[firewall_ip] = {}

                    if(not "name" in ip_groups[firewall_ip]):
                        ip_groups[firewall_ip]["name"] = firewall_src_name

                    if(not "ip_src" in ip_groups[firewall_ip]):
                        ip_groups[firewall_ip]["ip_src"] = {}

                    if(not firewall_src_int in ip_groups[firewall_ip]["ip_src"]):
                        ip_groups[firewall_ip]["ip_src"][firewall_src_int] = [src_addr]

                    if(not "ip_dest" in ip_groups[firewall_ip]):
                        ip_groups[firewall_ip]["ip_dest"] = dest_groups
                        ip_groups[firewall_ip]["ip_dest"] = list(dict.fromkeys(ip_groups[firewall_ip]["ip_dest"]))

                    if(not "action" in ip_groups[firewall_ip]):
                        ip_groups[firewall_ip]["action"] = action[ctr]

                    if(not "service" in ip_groups[firewall_ip]):
                        # if(not "," in service[ctr]):
                        #     service[ctr] = f"{service[ctr]},"
                        for svc in service[ctr].split(","):
                            svc = svc.replace(" ", "")
                            if("/" in svc):
                                svc = svc.split("/")
                                protocol = svc[0].lower()
                                port = svc[1].lower()

                                if(not(protocol == "tcp" or protocol == "udp" or protocol == "tcp-udp" or protocol == "icmp")):
                                    context["success"] = False
                                    context["error_message"] = error_message_template["no_valid_service"]
                                    return render(request, "create.html", context=context)

                                if("-" in port):
                                    port = port.split("-")
                                    if(port[0].isdigit() and port[1].isdigit() and not(int(port[0]) > 0 and int(port[0]) < 65536 and int(port[1]) > 0 and int(port[1]) < 65536)):
                                        context["success"] = False
                                        context["error_message"] = error_message_template["no_valid_service"]
                                        return render(request, "create.html", context=context)

                                elif(port.isdigit() and (not(int(port) > 0 and int(port) < 65536))):
                                    context["success"] = False
                                    context["error_message"] = error_message_template["no_valid_service"]
                                    return render(request, "create.html", context=context)

                                elif(port.isalpha() and (not port in valid_services)):
                                    context["success"] = False
                                    context["error_message"] = error_message_template["no_valid_service"]
                                    return render(request, "create.html", context=context)

                            else:
                                if(not(svc == "tcp-udp" or svc == "icmp" or svc == "ip")):
                                    context["success"] = False
                                    context["error_message"] = error_message_template["no_valid_service"]
                                    return render(request, "create.html", context=context)

                        ip_groups[firewall_ip]["service"] = service[ctr].split(",")
                        ip_groups[firewall_ip]["service"] = list(dict.fromkeys(ip_groups[firewall_ip]["service"]))

                    if(not "description" in ip_groups[firewall_ip]):
                        ip_groups[firewall_ip]["description"] = description[ctr].split(",")
                        ip_groups[firewall_ip]["description"] = list(dict.fromkeys(ip_groups[firewall_ip]["description"]))

                    ip_groups[firewall_ip]["ip_src"][firewall_src_int].append(src_addr)

                    ip_groups[firewall_ip]["ip_src"][firewall_src_int] = list(dict.fromkeys(ip_groups[firewall_ip]["ip_src"][firewall_src_int]))

            groups.append(ip_groups)
            ctr = ctr + 1

        # pushing one by one
        for g in groups:
            for firewall_ip, value in g.items():
                temp_dict = {}

                for interface, ip in value["ip_src"].items():
                    ip = list(dict.fromkeys(ip))
                    value["ip_dest"] = list(dict.fromkeys(value["ip_dest"]))
                    value["service"] = list(dict.fromkeys(value["service"]))
                    value["description"] = list(dict.fromkeys(value["description"]))

                    src = {0: str(ip).replace("'","").replace(" ", "").replace("[","").replace("]", "")}
                    dest = {0: str(value["ip_dest"])[1:-1].replace("'","").replace(" ", "")}
                    service = {0: str(value["service"])[1:-1].replace("'","").replace(" ", "")}
                    desc = {0: str(value["description"]).replace("'","")}

                    if("," in src[0]):
                        src[0] = src[0].split(",")
                    if("," in dest[0]):
                        dest[0] = dest[0].split(",")
                    if("," in service[0]):
                        service[0] = service[0].split(",")
                    if("," in desc[0]):
                        desc[0] = desc[0].split(",")
                    else:
                        desc[0] = [desc[0]]

                    if("/" in firewall_ip):
                        firewall_ip = firewall_ip.split("/")[0]

                    fw_option, fw_vendor, username, password = access_firewall_details(firewall_ip)

                    if(fw_vendor == "Cisco ASA"):
                        content = {
                            "Interface": {0: f"{interface}"},
                            "Action": {0: value["action"]},
                            "Source": {0: f"{src[0]}"},
                            "Destination": {0: f"{dest[0]}"},
                            "Service": {0: f"{service[0]}"},
                            "Description": {0: f"{desc[0]}"},
                        }
                        asa = CiscoASA(fw_option, username, password)
                        asa.create_acl(**content)

                    if(fw_vendor == "Fortinet"):
                        dest_interface = []
                        temp_dest = dest[0]
                        if("list" in str(type(temp_dest))):
                            for d in temp_dest:
                                resp = list(nb.ipam.prefixes.filter(f"{d}").response)
                                resp = resp[0]["custom_fields"]["FORTIPORT"]
                                try:
                                    for intf in resp:
                                        dest_interface.append(intf["name"].lower())
                                except TypeError:
                                    dest_interface.append(temp_dict["Interface"][0].lower())
                        else:
                            resp = list(nb.ipam.prefixes.filter(f"{temp_dest}").response)
                            resp = resp[0]["custom_fields"]["FORTIPORT"]
                            try:
                                for intf in resp:
                                    dest_interface.append(intf["name"].lower())
                            except TypeError:
                                dest_interface.append(temp_dict["Interface"][0].lower())
                        
                        dest_interface = list(dict.fromkeys(dest_interface))
                        dest_interface = [{"name": d} for d in dest_interface]

                        if(value["action"].lower() == "permit"):
                            forti_action = "accept"
                        else:
                            forti_action = value["action"].lower()

                        fortinet = Fortinet(fw_option, username, password, False, "root", "off")
                        content = {
                            "interface": interface,
                            "source": src[0],
                            "destination": dest[0],
                            "action": forti_action,
                            "service": service[0],
                            "description": desc[0],
                            "dest_interface": dest_interface,
                        }

                        fortinet.create_acl(**content)
                        fortinet.logout()

                    if(fw_vendor == "Palo Alto Networks"):
                        pan_action = ""
                        if(value["action"].lower() == "permit"):
                            pan_action = "allow"
                        else:
                            pan_action = value["action"].lower()
                        
                        src_zone = []
                        dest_zone = []

                        temp_src = src[0]
                        if("list" in str(type(temp_src))):
                            for s in temp_src:
                                resp = list(nb.ipam.prefixes.filter(f"{s}").response)
                                try:
                                    src_zone.append(resp[0]["role"]["name"])
                                except TypeError:
                                    src_zone.append("any")
                        else:
                            resp = list(nb.ipam.prefixes.filter(f"{temp_src}").response)
                            try:
                                resp = resp[0]["role"]["name"]
                            except IndexError:
                                resp = resp["role"]["name"]
                            try:
                                src_zone.append(resp)
                            except TypeError:
                                src_zone.append("any")

                        temp_dest = dest[0]
                        if("list" in str(type(temp_dest))):
                            for d in temp_dest:
                                resp = list(nb.ipam.prefixes.filter(f"{d}").response)
                                try:
                                    dest_zone.append(resp[0]["role"]["name"])
                                except TypeError:
                                    dest_zone.append("any")
                        else:
                            resp = list(nb.ipam.prefixes.filter(f"{temp_dest}").response)
                            try:
                                resp = resp[0]["role"]["name"]
                            except IndexError:
                                resp = resp["role"]["name"]
                            try:
                                dest_zone.append(resp)
                            except TypeError:
                                dest_zone.append("any")

                        src_zone = list(dict.fromkeys(src_zone))
                        dest_zone = list(dict.fromkeys(dest_zone))
                        pan = PaloAlto(fw_option, username, password)

                        content = {
                            "source": src[0],
                            "destination": dest[0],
                            "fromzone": src_zone,
                            "tozone": dest_zone,
                            "action": pan_action,
                            "service": service[0],
                            "description": desc[0],
                        }
                        if(content["description"][0] == "[" and content["description"][-1] == "]"):
                            content["description"] = content["description"][1:-1]

                        pan.create_acl(**content)
                        pan.commit_changes()

        # =============== destination to source ================== #

        groups = []
        service = [rules["Service"][ctr].replace(" ", "") for ctr in range(len(rules["Service"]))]
        ctr = 0
        for src, dest in zip(ip_src, ip_dest):
            ip_groups = {}
            src_groups = []

            for src_addr in src:
                src_groups.append(src_addr)

            for dest_addr in dest:
                response = list(nb.ipam.prefixes.filter(dest_addr).response)
                for r in response:
                    firewall_ip = r["custom_fields"]["FWIP"]["display"]
                    firewall_dest_name = list(nb.dcim.devices.filter(firewall_ip))[0]
                    firewall_dest_int = ""

                    if(r["custom_fields"]["FWINT"]):
                        firewall_dest_int = r["custom_fields"]["FWINT"]["name"]

                    if(not firewall_ip in ip_groups):
                        ip_groups[firewall_ip] = {}

                    if(not "name" in ip_groups[firewall_ip]):
                        ip_groups[firewall_ip]["name"] = firewall_dest_name

                    if(not "ip_dest" in ip_groups[firewall_ip]):
                        ip_groups[firewall_ip]["ip_dest"] = {}

                    if(not firewall_dest_int in ip_groups[firewall_ip]["ip_dest"]):
                        ip_groups[firewall_ip]["ip_dest"][firewall_dest_int] = [dest_addr]

                    if(not "ip_src" in ip_groups[firewall_ip]):
                        ip_groups[firewall_ip]["ip_src"] = src_groups
                        ip_groups[firewall_ip]["ip_src"] = list(dict.fromkeys(ip_groups[firewall_ip]["ip_src"]))

                    if(not "action" in ip_groups[firewall_ip]):
                        ip_groups[firewall_ip]["action"] = action[ctr]

                    if(not "service" in ip_groups[firewall_ip]):
                        for svc in service[ctr].split(","):
                            svc = svc.replace(" ", "")
                            if("/" in svc):
                                svc = svc.split("/")
                                protocol = svc[0].lower()
                                port = svc[1].lower()

                                if(not(protocol == "tcp" or protocol == "udp" or protocol == "tcp-udp" or protocol == "icmp")):
                                    context["success"] = False
                                    context["error_message"] = error_message_template["no_valid_service"]
                                    return render(request, "create.html", context=context)

                                if("-" in port):
                                    port = port.split("-")
                                    if(port[0].isdigit() and port[1].isdigit() and not(int(port[0]) > 0 and int(port[0]) < 65536 and int(port[1]) > 0 and int(port[1]) < 65536)):
                                        context["success"] = False
                                        context["error_message"] = error_message_template["no_valid_service"]
                                        return render(request, "create.html", context=context)

                                elif(port.isdigit() and (not(int(port) > 0 and int(port) < 65536))):
                                    context["success"] = False
                                    context["error_message"] = error_message_template["no_valid_service"]
                                    return render(request, "create.html", context=context)

                                elif(port.isalpha() and (not port in valid_services)):
                                    context["success"] = False
                                    context["error_message"] = error_message_template["no_valid_service"]
                                    return render(request, "create.html", context=context)

                            else:
                                if(not(svc == "tcp-udp" or svc == "icmp" or svc == "ip")):
                                    context["success"] = False
                                    context["error_message"] = error_message_template["no_valid_service"]
                                    return render(request, "create.html", context=context)

                        ip_groups[firewall_ip]["service"] = service[ctr].split(",")
                        ip_groups[firewall_ip]["service"] = list(dict.fromkeys(ip_groups[firewall_ip]["service"]))

                    if(not "description" in ip_groups[firewall_ip]):
                        ip_groups[firewall_ip]["description"] = description[ctr].split(",")
                        ip_groups[firewall_ip]["description"] = list(dict.fromkeys(ip_groups[firewall_ip]["description"]))

                    ip_groups[firewall_ip]["ip_dest"][firewall_dest_int].append(dest_addr)

                    ip_groups[firewall_ip]["ip_dest"][firewall_dest_int] = list(dict.fromkeys(ip_groups[firewall_ip]["ip_dest"][firewall_dest_int]))

            groups.append(ip_groups)
            ctr = ctr + 1

        # pushing one by one
        for g in groups:
            for firewall_ip, value in g.items():
                temp_dict = {}

                for interface, ip in value["ip_dest"].items():
                    ip = list(dict.fromkeys(ip))
                    value["ip_src"] = list(dict.fromkeys(value["ip_src"]))
                    value["service"] = list(dict.fromkeys(value["service"]))
                    value["description"] = list(dict.fromkeys(value["description"]))

                    dest = {0: str(ip).replace("'","").replace(" ", "").replace("[","").replace("]", "")}
                    src = {0: str(value["ip_src"])[1:-1].replace("'","").replace(" ", "")}
                    service = {0: str(value["service"])[1:-1].replace("'","").replace(" ", "")}
                    desc = {0: str(value["description"]).replace("'","")}

                    if("," in src[0]):
                        src[0] = src[0].split(",")
                    if("," in dest[0]):
                        dest[0] = dest[0].split(",")
                    if("," in service[0]):
                        service[0] = service[0].split(",")
                    if("," in desc[0]):
                        desc[0] = desc[0].split(",")
                    else:
                        desc[0] = [desc[0]]

                    if("/" in firewall_ip):
                        firewall_ip = firewall_ip.split("/")[0]

                    fw_option, fw_vendor, username, password = access_firewall_details(firewall_ip)

                    if(fw_vendor == "Cisco ASA"):
                        content = {
                            "Interface": {0: f"{interface}"},
                            "Action": {0: value["action"]},
                            "Source": {0: f"{src[0]}"},
                            "Destination": {0: f"{dest[0]}"},
                            "Service": {0: f"{service[0]}"},
                            "Description": {0: f"{desc[0]}"},
                        }
                        asa = CiscoASA(fw_option, username, password)
                        asa.create_acl(**content)

                    if(fw_vendor == "Fortinet"):
                        dest_interface = []
                        temp_dest = dest[0]
                        if("list" in str(type(temp_dest))):
                            for d in temp_dest:
                                resp = list(nb.ipam.prefixes.filter(f"{d}").response)
                                resp = resp[0]["custom_fields"]["FORTIPORT"]
                                try:
                                    for intf in resp:
                                        dest_interface.append(intf["name"].lower())
                                except TypeError:
                                    dest_interface.append(temp_dict["Interface"][0].lower())
                        else:
                            resp = list(nb.ipam.prefixes.filter(f"{temp_dest}").response)
                            resp = resp[0]["custom_fields"]["FORTIPORT"]
                            try:
                                for intf in resp:
                                    dest_interface.append(intf["name"].lower())
                            except TypeError:
                                dest_interface.append(temp_dict["Interface"][0].lower())
                        
                        dest_interface = list(dict.fromkeys(dest_interface))
                        dest_interface = [{"name": d} for d in dest_interface]

                        if(value["action"].lower() == "permit"):
                            forti_action = "accept"
                        else:
                            forti_action = value["action"].lower()

                        fortinet = Fortinet(fw_option, username, password, False, "root", "off")
                        content = {
                            "interface": interface,
                            "source": src[0],
                            "destination": dest[0],
                            "action": forti_action,
                            "service": service[0],
                            "description": desc[0],
                            "dest_interface": dest_interface,
                        }

                        fortinet.create_acl(**content)
                        fortinet.logout()

                    if(fw_vendor == "Palo Alto Networks"):
                        pan_action = ""
                        if(value["action"].lower() == "permit"):
                            pan_action = "allow"
                        else:
                            pan_action = value["action"].lower()

                        src_zone = []
                        dest_zone = []

                        temp_src = src[0]
                        if("list" in str(type(temp_src))):
                            for s in temp_src:
                                resp = list(nb.ipam.prefixes.filter(f"{s}").response)
                                try:
                                    src_zone.append(resp[0]["role"]["name"])
                                except TypeError:
                                    src_zone.append("any")
                        else:
                            resp = list(nb.ipam.prefixes.filter(f"{temp_src}").response)
                            try:
                                resp = resp[0]["role"]["name"]
                            except IndexError:
                                resp = resp["role"]["name"]
                            try:
                                src_zone.append(resp)
                            except TypeError:
                                src_zone.append("any")

                        temp_dest = dest[0]
                        if("list" in str(type(temp_dest))):
                            for d in temp_dest:
                                resp = list(nb.ipam.prefixes.filter(f"{d}").response)
                                try:
                                    dest_zone.append(resp[0]["role"]["name"])
                                except TypeError:
                                    dest_zone.append("any")
                        else:
                            resp = list(nb.ipam.prefixes.filter(f"{temp_dest}").response)
                            try:
                                resp = resp[0]["role"]["name"]
                            except IndexError:
                                resp = resp["role"]["name"]
                            try:
                                dest_zone.append(resp)
                            except TypeError:
                                dest_zone.append("any")

                        src_zone = list(dict.fromkeys(src_zone))
                        dest_zone = list(dict.fromkeys(dest_zone))
                        pan = PaloAlto(fw_option, username, password)

                        content = {
                            "source": src[0],
                            "destination": dest[0],
                            "fromzone": src_zone,
                            "tozone": dest_zone,
                            "action": pan_action,
                            "service": service[0],
                            "description": desc[0],
                        }
                        if(content["description"][0] == "[" and content["description"][-1] == "]"):
                            content["description"] = content["description"][1:-1]

                        pan.create_acl(**content)
                        pan.commit_changes()

        rules = {}
        context["success"] = True
        context["error_message"] = "Push rule suceeded."

    return render(request, "create.html", context=context)


def read_rule_view(request):
    is_valid = check_authentication()
    context = {}
    if(is_valid != True):
        context["success"] = False
        context["error_message"] = error_message_template["authentication_error"]
        return render(request, "menu.html", context=context)
    
    if(request.POST):
        is_valid = check_authentication()
        if(is_valid != True):
            context["success"] = False
            context["error_message"] = error_message_template["authentication_error"]
            return render(request, "menu.html", context=context)

        fw_option, fw_vendor, username, password = access_firewall_details(request.POST["firewall_ip"])
        context = extracting_rules(fw_option, fw_vendor, username, password)
        context["fw_chosen"] = True
        context["username"] = username
        context["fw_vendor"] = fw_vendor
        context["fw_option"] = fw_option
        return render(request, "read.html", context=context)

    context = {
        "firewall_ip": get_all_firewall_ip_from_db(),
        "fw_chosen": False
    }

    return render(request, "read.html", context=context)


def update_rule_view(request):
    context = {}
    is_valid = check_authentication()
    if(is_valid != True):
        context["success"] = False
        context["error_message"] = error_message_template["authentication_error"]
        return render(request, "menu.html", context=context)

    context = {}
    if(request.POST):
        is_valid = check_authentication()
        if(is_valid != True):
            context["success"] = False
            context["error_message"] = error_message_template["authentication_error"]
            return render(request, "menu.html", context=context)
    
        try:
            fw_option, fw_vendor, username, password = access_firewall_details(request.POST["firewall_ip"])
            request.session["firewall_ip"] = fw_option
            context = extracting_rules(fw_option, fw_vendor, username, password)
            context["fw_chosen"] = True
        except MultiValueDictKeyError:
            fw_option, fw_vendor, username, password = access_firewall_details(request.session["firewall_ip"])
        
        context["username"] = username
        context["fw_vendor"] = fw_vendor
        context["fw_option"] = fw_option

        if(request.POST.get("update_rule", None) != None and request.POST["update_rule"] == "Update Rules"):
            options = request.POST.getlist("checks-input")
            options_field = request.POST.getlist("checks")
            options_row_column = [(int(o.split('-')[1])-1, int(o.split('-')[2])-1) for o in options_field]

            fortinet = None
            pan = None

            chosen = []
            for idx in range(len(options)):
                if(options[idx] != ""):
                    chosen.append(idx)

            rules = extracting_rules(fw_option, fw_vendor, username, password)

            data = {}
            if(len(chosen) > 0):
                for c in chosen:
                    row = options_row_column[c][0]
                    if(fw_vendor == "Fortinet"):
                        row = row + 1
                    column = options_row_column[c][1]
                    chosen_field = rules["real_column_name"][column]
                    update_input = options[c]

                    if(chosen_field != "name"):
                        update_input = update_input.replace(" ", "")

                    if("," in update_input):
                        update_input = update_input.split(",")

                    if("addr" in chosen_field or "source" == chosen_field or "destination" == chosen_field):
                        if("list" in str(type(update_input))):
                            for uinp in update_input:
                                try:
                                    if("/" in uinp):
                                        ipaddress.ip_network(uinp)
                                    elif(not "/" in uinp):
                                        ipaddress.ip_address(uinp)
                                except ValueError:
                                    context = extracting_rules(fw_option, fw_vendor, username, password)
                                    context["fw_chosen"] = True
                                    context["username"] = username
                                    context["fw_vendor"] = fw_vendor
                                    context["fw_option"] = fw_option
                                    context["success"] = False
                                    context["error_message"] = error_message_template["no_valid_ip"]
                                    return render(request, "update.html", context=context)
                        else:
                            uinp = update_input
                            try:
                                if("/" in uinp):
                                    ipaddress.ip_network(uinp)
                                elif(not "/" in uinp):
                                    ipaddress.ip_address(uinp)
                            except ValueError:
                                context = extracting_rules(fw_option, fw_vendor, username, password)
                                context["fw_chosen"] = True
                                context["username"] = username
                                context["fw_vendor"] = fw_vendor
                                context["fw_option"] = fw_option
                                context["success"] = False
                                context["error_message"] = error_message_template["no_valid_ip"]
                                return render(request, "update.html", context=context)
                    
                    elif("service" in chosen_field):
                        valid_services = pd.read_csv("./known_ports.csv")
                        valid_services = valid_services.to_dict()
                        temp_service = []
                        for ctr in range(len(valid_services["service"])):
                            if(str(type(valid_services["service"][ctr])) != "nan"):
                                temp_service.append(valid_services["service"][ctr])

                        valid_services = temp_service
                        service = update_input

                        if("," in service):
                            service = update_input.split(",")

                        for svc in service:
                            svc = svc.replace(" ", "")
                            if("-" in svc):
                                svc = svc.split("-")
                                protocol = svc[0].lower()
                                port = svc[1].lower()

                                if(not(protocol == "tcp" or protocol == "udp" or protocol == "tcp-udp" or protocol == "icmp")):
                                    context = extracting_rules(fw_option, fw_vendor, username, password)
                                    context["fw_chosen"] = True
                                    context["username"] = username
                                    context["fw_vendor"] = fw_vendor
                                    context["fw_option"] = fw_option
                                    context["success"] = False
                                    context["error_message"] = error_message_template["no_valid_service"]
                                    return render(request, "update.html", context=context)

                                if("-" in port):
                                    port = port.split("-")
                                    if(port[0].isdigit() and port[1].isdigit() and not(int(port[0]) > 0 and int(port[0]) < 65536 and int(port[1]) > 0 and int(port[1]) < 65536)):
                                        context = extracting_rules(fw_option, fw_vendor, username, password)
                                        context["fw_chosen"] = True
                                        context["username"] = username
                                        context["fw_vendor"] = fw_vendor
                                        context["fw_option"] = fw_option
                                        context["success"] = False
                                        context["error_message"] = error_message_template["no_valid_service"]
                                        return render(request, "update.html", context=context)

                                    elif(port.isdigit() and (not (int(port) > 0 and int(port) < 65536))):
                                        context = extracting_rules(fw_option, fw_vendor, username, password)
                                        context["fw_chosen"] = True
                                        context["username"] = username
                                        context["fw_vendor"] = fw_vendor
                                        context["fw_option"] = fw_option
                                        context["success"] = False
                                        context["error_message"] = error_message_template["no_valid_service"]
                                        return render(request, "update.html", context=context)

                                elif(port.isalpha() and (not port in valid_services)):
                                    context = extracting_rules(fw_option, fw_vendor, username, password)
                                    context["fw_chosen"] = True
                                    context["username"] = username
                                    context["fw_vendor"] = fw_vendor
                                    context["fw_option"] = fw_option
                                    context["success"] = False
                                    context["error_message"] = error_message_template["no_valid_service"]
                                    return render(request, "update.html", context=context)

                            else:
                                if(not(svc.lower() in valid_services)):
                                    context = extracting_rules(fw_option, fw_vendor, username, password)
                                    context["fw_chosen"] = True
                                    context["username"] = username
                                    context["fw_vendor"] = fw_vendor
                                    context["fw_option"] = fw_option
                                    context["success"] = False
                                    context["error_message"] = error_message_template["no_valid_service"]
                                    return render(request, "update.html", context=context)

                    elif("action" in chosen_field):
                        if(not ("permit" == update_input.lower() or "deny" == update_input.lower())):
                            context = extracting_rules(fw_option, fw_vendor, username, password)
                            context["fw_chosen"] = True
                            context["username"] = username
                            context["fw_vendor"] = fw_vendor
                            context["fw_option"] = fw_option
                            context["success"] = False
                            context["error_message"] = error_message_template["no_valid_service"]
                            return render(request, "update.html", context=context)

                    temp_dict = {
                        "field": chosen_field,
                        "input": update_input
                    }

                    try: 
                        data[row].append(temp_dict)
                    except KeyError:
                        data[row] = []
                        data[row].append(temp_dict)

                if(fw_vendor == "Fortinet"):
                    fortinet = Fortinet(fw_option, username, password, False, "root", "off")
                    fortinet.update_acl(data)
                    fortinet.logout()

                elif(fw_vendor == "Palo Alto Networks"):
                    pan = PaloAlto(fw_option, username, password)
                    pan.update_acl(data)
                    pan.commit_changes()

                context = extracting_rules(fw_option, fw_vendor, username, password)
                context["success"] = True
                context["error_message"] = "Rule updated."
            else:
                context = extracting_rules(fw_option, fw_vendor, username, password)
                context["success"] = False
                context["error_message"] = "No input supplied."

            context["fw_chosen"] = True
            context["username"] = username
            context["fw_vendor"] = fw_vendor
            context["fw_option"] = fw_option
            return render(request, "update.html", context=context)

        return render(request, "update.html", context=context)

    if(request.session.get("firewall_ip", None) == None):
        context = {
            "firewall_ip": get_all_firewall_ip_from_db(),
            "fw_chosen": False
        }
    else:
        fw_option, fw_vendor, username, password = access_firewall_details(request.session["firewall_ip"])
        request.session["firewall_ip"] = fw_option
        context = extracting_rules(fw_option, fw_vendor, username, password)
        context["fw_chosen"] = True
        context["username"] = username
        context["fw_vendor"] = fw_vendor
        context["fw_option"] = fw_option

    return render(request, "update.html", context=context)


def delete_rule_view(request):
    context = {}
    is_valid = check_authentication()
    if(is_valid != True):
        context["success"] = False
        context["error_message"] = error_message_template["authentication_error"]
        return render(request, "menu.html", context=context)
    
    if(request.POST):
        is_valid = check_authentication()
        if(is_valid != True):
            context["success"] = False
            context["error_message"] = error_message_template["authentication_error"]
            return render(request, "menu.html", context=context)

        try:
            fw_option, fw_vendor, username, password = access_firewall_details(request.POST["firewall_ip"])
            request.session["firewall_ip"] = fw_option
            context = extracting_rules(fw_option, fw_vendor, username, password)
            context["fw_chosen"] = True
            context["username"] = username
            context["fw_vendor"] = fw_vendor
            context["fw_option"] = fw_option

        except MultiValueDictKeyError:
            fw_option, fw_vendor, username, password = access_firewall_details(request.session["firewall_ip"])

        if(request.POST.get("delete_rule", None) != None and request.POST["delete_rule"] == "Delete Rules"):
            options = request.POST.getlist("checks")
            options = [int(opt.split("-")[1])-1 for opt in options]
            options = list(dict.fromkeys(options))

            if(len(options) > 0):
                # if(fw_vendor == "Cisco ASA"):
                #     asa = CiscoASA(fw_option, username, password)
                #     asa.delete_acl()
                #     asa.commit_changes()

                if(fw_vendor == "Fortinet"):
                    fortinet = Fortinet(fw_option, username, password, False, "root", "off")
                    options = [opt+1 for opt in options]
                    fortinet.delete_acl(options)
                    fortinet.logout()

                elif(fw_vendor == "Palo Alto Networks"):
                    pan = PaloAlto(fw_option, username, password)
                    pan.delete_acl(options)
                    pan.commit_changes()

                options = []
                context = extracting_rules(fw_option, fw_vendor, username, password)
                context["success"] = True
                context["error_message"] = "Rule has been deleted."
            else:
                context = extracting_rules(fw_option, fw_vendor, username, password)
                context["success"] = False
                context["error_message"] = "No rule chosen."
            
            context["fw_chosen"] = True
            context["username"] = username
            context["fw_vendor"] = fw_vendor
            context["fw_option"] = fw_option
            return render(request, "delete.html", context=context)
        
        return render(request, "delete.html", context=context)

    if(request.session.get("firewall_ip", None) == None):
        is_valid = check_authentication()
        if(is_valid != True):
            context["success"] = False
            context["error_message"] = error_message_template["authentication_error"]
            return render(request, "menu.html", context=context)

        context = {
            "firewall_ip": get_all_firewall_ip_from_db(),
            "fw_chosen": False
        }

    else:
        fw_option, fw_vendor, username, password = access_firewall_details(request.session["firewall_ip"])

        is_valid = check_authentication()
        if(is_valid != True):
            context["success"] = False
            context["error_message"] = error_message_template["authentication_error"]
            return render(request, "menu.html", context=context)

        request.session["firewall_ip"] = fw_option
        context = extracting_rules(fw_option, fw_vendor, username, password)
        context["fw_chosen"] = True
        context["username"] = username
        context["fw_vendor"] = fw_vendor
        context["fw_option"] = fw_option

    return render(request, "delete.html", context=context)


def error_view(request):
    ctx = request.session["exception"]
    status = request.session["status"]
    ctx = {
        "error_message": ctx,
    }
    request.session["exception"] = "This is an error page."
    request.session["status"] = 200
    return render(request, "error.html", context=ctx, status=status)

