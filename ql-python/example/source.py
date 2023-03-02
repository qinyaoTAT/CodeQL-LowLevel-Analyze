import os

def source():
    env = os.getenv('HOME')
    return env

def source2(request):
    if request.method == 'POST':
        action = request.POST.get('action', '')
        return action