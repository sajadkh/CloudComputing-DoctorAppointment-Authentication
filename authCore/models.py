from enum import Enum

from django.db import models
from django.contrib.auth.models import User


# Create your models here.

class Role(Enum):
    RESTAURANT = "DOCTOR"
    CUSTOMER = "PATIENT"
    INTERNAL = "INTERNAL"

    @classmethod
    def choices(cls):
        return tuple((i.name, i.value) for i in cls)


class User(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=255, default=None,
                                blank=True)  # make sure that no other user is available with the same username
    email = models.EmailField(default=None, blank=True)
    password = models.CharField(max_length=100, default="")
    role = models.CharField(max_length=255, choices=Role.choices())
    date_joined = models.DateField(blank=True)
    is_login = models.BooleanField(default=False)

    def __str__(self):
        return self.username
