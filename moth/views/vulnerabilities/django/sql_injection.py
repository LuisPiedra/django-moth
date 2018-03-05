from django.contrib.auth.models import User
from django.db import DatabaseError
from django.shortcuts import render
from django.utils.html import escape

from moth.views.base.vulnerable_template_view import VulnerableTemplateView
try:
    from django.db.models.expressions import RawSQL
except ImportError:
    RawSQL = None


class DjangoSQLiView(VulnerableTemplateView):
    title = 'Django SQL injection'
    tags = ['GET', 'extra']
    description = 'https://docs.djangoproject.com/en/dev/topics/security/#sql-injection-protection'
    url_path = 'extra.py?select=&where='
    false_positive_check = False

    def get(self, request, *args, **kwds):
        context = self.get_context_data()

        query = User.objects.filter(username='admin')
        select = request.GET['select']
        where = request.GET['where']
        raw = request.GET.get('raw')

        if select:
            query = query.extra(select={'test': select})
        elif where:
            query = query.extra(where=[where])
        elif raw and RawSQL:
            User.objects.annotate(val=RawSQL(raw, []))

        context['html'] = 'Select: <pre>"username") AS "username", * FROM "auth_user" WHERE 1=1 OR "username"=? --</pre>'
        context['html'] += 'Where: <pre>1=1) OR 1=1 AND (1=1</pre>'
        context['html'] += 'Raw: <pre>"username") AS "val" FROM "auth_user" WHERE "username"="admin" --</pre>'
        context['html'] += '<h3>Admin</h3>'
        context['html'] += '<ul>'
        try:
            for user in query.all():
                context['html'] += '<li>{}</li>'.format(user.username)
        except DatabaseError as ex:
            context['html'] += '<li>!!Error injection</li>'
            context['html'] += '<li>{}</li>'.format(escape(ex.message))
        context['html'] += '</ul>'
        return render(request, self.template_name, context)

