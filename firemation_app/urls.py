from django.urls import path
from . import views

app_name = "firemation_app"

urlpatterns = [
    path("", views.start_view, name="start"),
    path("firewall_management/", views.firewall_management_view, name="firewall_management"),
    path("register_firewall/", views.register_firewall_view, name="register_firewall"),
    path("credential_management/", views.credential_management_view, name="credential_management"),
    path("register_credential/", views.register_credential_view, name="register_credential"),
    path("delete_credential/", views.delete_credential_view, name="delete_credential"),
    path("menu/", views.menu_view, name="menu"),
    path("create_rule/", views.create_rule_view, name="create_rule"),
    path("read_rule/", views.read_rule_view, name="read_rule"),
    path("update_rule/", views.update_rule_view, name="update_rule"),
    path("delete_rule/", views.delete_rule_view, name="delete_rule"),
    path("error/", views.error_view, name="error"),
]
