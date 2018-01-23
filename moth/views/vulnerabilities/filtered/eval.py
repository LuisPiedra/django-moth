import subprocess
import re

from django.shortcuts import render

from moth.views.base.vulnerable_template_view import VulnerableTemplateView


WRONG_FILTER = re.compile('[\w\. ]+')
ARRAY_RE = re.compile('(\[|\()(\d,?)+(\]|\))')
VALID_COMMAND_RE = re.compile('(ls)|(pwd)')


class EvalView(VulnerableTemplateView):
    title = 'Python eval() vulnerability'
    tags = ['GET', 'eval']
    description = 'eval() the param query string with validation and returns the output.'
    url_path = 'eval_filter.py?eval=1'
    false_positive_check = True

    def get(self, request, *args, **kwds):
        context = self.get_context_data()

        eval_cmd = request.GET['eval']

        try:
            context['html'] = 'Filtered command, only array supported.'
            if ARRAY_RE.match(eval_cmd):
                context['html'] = eval(eval_cmd)
        except SyntaxError:
            context['html'] = 'Error on eval'
        return render(request, self.template_name, context)


class SubprocessView(VulnerableTemplateView):
    title = 'Python subprocess vulnerability'
    tags = ['GET', 'subprocess']
    description = 'Runs the provided input through subprocess and' \
                  ' returns the output. The command line argument is delimited' \
                  ' using single quotes.'
    url_path = 'subprocess_filter.py?cmd=1'
    false_positive_check = True

    def get(self, request, *args, **kwds):
        context = self.get_context_data()

        run_cmd = request.GET['cmd']

        try:
            output = 'Command filtered, only ls or pwd supported'
            if VALID_COMMAND_RE.match(run_cmd):
                output = subprocess.check_output(run_cmd, shell=True)
        except subprocess.CalledProcessError, cpe:
            context['html'] = 'Found execution error: %s' % cpe
        except:
            context['html'] = 'Generic crash!'
        else:
            context['html'] = output

        return render(request, self.template_name, context)

