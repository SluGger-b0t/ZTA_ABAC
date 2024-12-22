# from django.db import models

# # Create your models here.

from django.db import models
from django.utils.timezone import now

class User(models.Model):
    username = models.CharField(max_length=100, unique=True)
    role = models.CharField(max_length=50, choices=[('doctor', 'Doctor'), ('nurse', 'Nurse'), ('admin', 'Admin')])
    active_shift = models.BooleanField(default=False)
    last_device_id = models.CharField(max_length=100, blank=True, null=True)
    last_known_location = models.CharField(max_length=100, blank=True, null=True)
    team = models.ForeignKey('Team', on_delete=models.SET_NULL, null=True)

class Team(models.Model):
    name = models.CharField(max_length=100)
    tag = models.CharField(max_length=10, choices=[('c', 'Call Center'), ('a', 'Ambulance'), ('h', 'Hospital')])

class EMR(models.Model):
    patient_id = models.CharField(max_length=50)
    data = models.TextField()
    owner_team = models.ForeignKey(Team, on_delete=models.CASCADE)

class AccessLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=50)
    resource = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)
    location = models.CharField(max_length=100)
    decision = models.CharField(max_length=10)
