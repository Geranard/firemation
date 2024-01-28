# Generated by Django 4.2.7 on 2023-12-14 14:28

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('firemation_app', '0003_user_firewall_vendor'),
    ]

    operations = [
        migrations.CreateModel(
            name='Firewall',
            fields=[
                ('firewall_ip', models.CharField(default=uuid.uuid4, max_length=255, primary_key=True, serialize=False, unique=True)),
                ('firewall_name', models.CharField(max_length=255)),
                ('firewall_vendor', models.CharField(default='None', max_length=255)),
            ],
        ),
        migrations.RemoveField(
            model_name='user',
            name='firewall_ip',
        ),
        migrations.RemoveField(
            model_name='user',
            name='firewall_vendor',
        ),
        migrations.AddField(
            model_name='user',
            name='firewall',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.RESTRICT, to='firemation_app.firewall'),
        ),
    ]
