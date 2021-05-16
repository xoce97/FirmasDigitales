from django.shortcuts import redirect
def login_requerido(vista):
    def interna(request,*args,**kwargs):
        if not request.session.get('ingreso',False):
            return redirect('login')
        return vista(request,*args,**kwargs)
    return interna
