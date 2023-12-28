from django.db import models
from django.conf import settings

class OIDCState(models.Model):
    state           =   models.CharField(max_length=128, unique=True)
    nonce           =   models.CharField(max_length=128, null=True)
    code_verifier   =   models.CharField(max_length=128, null=True)
    user            =   models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True)
    created_at      =   models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.state
