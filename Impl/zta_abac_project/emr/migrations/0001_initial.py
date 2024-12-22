# Generated by Django 5.1.4 on 2024-12-15 08:07

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Team',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('tag', models.CharField(choices=[('c', 'Call Center'), ('a', 'Ambulance'), ('h', 'Hospital')], max_length=10)),
            ],
        ),
        migrations.CreateModel(
            name='EMR',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('patient_id', models.CharField(max_length=50)),
                ('data', models.TextField()),
                ('owner_team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='emr.team')),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=100, unique=True)),
                ('role', models.CharField(choices=[('doctor', 'Doctor'), ('nurse', 'Nurse'), ('admin', 'Admin')], max_length=50)),
                ('active_shift', models.BooleanField(default=False)),
                ('last_device_id', models.CharField(blank=True, max_length=100, null=True)),
                ('last_known_location', models.CharField(blank=True, max_length=100, null=True)),
                ('team', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='emr.team')),
            ],
        ),
        migrations.CreateModel(
            name='AccessLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(max_length=50)),
                ('resource', models.CharField(max_length=100)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('location', models.CharField(max_length=100)),
                ('decision', models.CharField(max_length=10)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='emr.user')),
            ],
        ),
    ]