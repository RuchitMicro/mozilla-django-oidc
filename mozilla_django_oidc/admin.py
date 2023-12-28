from mozilla_django_oidc.models import OIDCState
from django.contrib import admin

class OIDCStateAdmin(admin.ModelAdmin):
    list_display = ('state', 'nonce', 'code_verifier', 'user', 'created_at')
    search_fields = ('state', 'nonce', 'code_verifier', 'user__username')
    

admin.site.register(OIDCState, OIDCStateAdmin)
