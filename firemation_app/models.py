from django.db import models

# Create your models here.
class User(models.Model):
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    selected = models.BooleanField(default=False)
    firewall = models.ForeignKey("Firewall", on_delete=models.RESTRICT, null=True)

    def __str__(self):
        return self.username

class Firewall(models.Model):
    firewall_ip = models.CharField(max_length=255, unique=True, primary_key=True, default=uuid.uuid4)
    firewall_name = models.CharField(max_length=255)
    firewall_vendor = models.CharField(max_length=255, default="None")

    def __str__(self):
        return self.firewall_ip
